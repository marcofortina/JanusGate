/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>

#include <jansson.h>
#include <sodium.h>

#include "daemon_runtime.h"
#include "database_internal.h"
#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/logging.h"

/** @brief Read the consistency reasons currently affecting management. */
uint32_t management_degraded_reasons(const struct jg_management *management)
{
    return management == NULL || management->health == NULL
               ? 0U
               : atomic_load_explicit(&management->health->degraded_reasons,
                                      memory_order_acquire);
}

/** @brief Record one consistency failure and emit its first occurrence. */
void mark_management_degraded(struct jg_management *management,
                              uint32_t reason,
                              const char *event_code,
                              const char *message)
{
    uint32_t previous = 0U;

    if (management == NULL || management->health == NULL || reason == 0U) {
        return;
    }
    previous = atomic_fetch_or_explicit(&management->health->degraded_reasons,
                                        reason, memory_order_acq_rel);
    if ((previous & reason) == 0U) {
        (void)jg_log_emit(JG_LOG_ERROR, "management", event_code, "", message,
                          NULL);
    }
}

/** @brief Clear one recovered consistency reason and report the transition. */
static void clear_management_degraded(struct jg_management *management,
                                      uint32_t reason,
                                      const char *event_code,
                                      const char *message)
{
    uint32_t previous = 0U;

    if (management == NULL || management->health == NULL || reason == 0U) {
        return;
    }
    previous = atomic_fetch_and_explicit(&management->health->degraded_reasons,
                                         ~reason, memory_order_acq_rel);
    if ((previous & reason) != 0U) {
        (void)jg_log_emit(JG_LOG_INFO, "management", event_code, "", message,
                          NULL);
    }
}

/** @brief Reconcile shared health with persistent policy publication state. */
void refresh_policy_sync_health(struct jg_management *management)
{
    struct jg_database_policy_sync sync;
    const int result =
        management == NULL
            ? -EINVAL
            : jg_database_policy_sync_load(management->database, &sync);

    if (result != 0 || sync.desired_revision != sync.applied_revision) {
        mark_management_degraded(
            management, MANAGEMENT_DEGRADED_POLICY_SYNC,
            "management.policy_unsynchronized",
            "Persistent policy is not synchronized with the runtime");
    } else {
        clear_management_degraded(
            management, MANAGEMENT_DEGRADED_POLICY_SYNC,
            "management.policy_synchronized",
            "Persistent policy synchronization was restored");
    }
}

/** @brief Return whether a degraded appliance may execute one maintenance path.
 */
static bool degraded_path_allowed(const char *path)
{
    static const char *const paths[] = {
        "/api/v1/auth/login",       "/api/v1/auth/logout",
        "/api/v1/config/reload",    "/api/v1/config/validate",
        "/api/v1/diagnostics",      "/api/v1/logging",
        "/api/v1/network/rollback", "/api/v1/network/validate",
        "/api/v1/service/restart",  "/api/v1/system/reboot",
        "/api/v1/system/shutdown",
    };

    for (size_t index = 0U; index < sizeof(paths) / sizeof(paths[0U]);
         ++index) {
        if (strcmp(path, paths[index]) == 0) {
            return true;
        }
    }
    return false;
}

/** @brief Begin one persistent mutation that must share its audit commit. */
int audited_mutation_begin(struct jg_management *management)
{
    return jg_database_transaction_begin(management->database);
}

/** @brief Abandon an audit scope when its persistent mutation fails. */
int audited_mutation_check(struct jg_management *management,
                           int operation_result)
{
    if (operation_result != 0) {
        const int rollback_result =
            jg_database_transaction_rollback(management->database);

        if (rollback_result != 0) {
            mark_management_degraded(
                management, MANAGEMENT_DEGRADED_DATABASE_ROLLBACK,
                "management.database_rollback",
                "A database mutation could not be rolled back");
            return -EIO;
        }
    }
    return operation_result;
}

/** @brief Commit a mutation with its audit event or restore prior state. */
int audited_mutation_finish(struct jg_management *management,
                            int operation_result,
                            bool reload_policy)
{
    bool refresh_policy_health = reload_policy;
    int result = operation_result;

    if (result == 0) {
        result = jg_database_transaction_commit(management->database);
    }
    if (result != 0) {
        const int rollback_result =
            jg_database_transaction_rollback(management->database);
        int reload_result = 0;

        if (reload_policy && management->runtime != NULL) {
            reload_result =
                jg_daemon_runtime_reload_policy(management->runtime);
        }
        if (rollback_result != 0) {
            mark_management_degraded(
                management, MANAGEMENT_DEGRADED_DATABASE_ROLLBACK,
                "management.database_rollback",
                "An audited database mutation could not be rolled back");
        }
        if (reload_result != 0) {
            refresh_policy_health = false;
            mark_management_degraded(
                management, MANAGEMENT_DEGRADED_POLICY_SYNC,
                "management.policy_rollback",
                "The runtime policy could not be synchronized after rollback");
        }
        if (rollback_result != 0 || reload_result != 0) {
            result = -EIO;
        }
    }
    if (refresh_policy_health) {
        refresh_policy_sync_health(management);
    }
    return result;
}

/** @brief Return the persistent audit kind for one authenticated actor. */
enum jg_audit_actor_type actor_audit_type(
    const struct authenticated_actor *actor)
{
    switch (actor->kind) {
    case AUTHENTICATED_ACTOR_USER:
        return JG_AUDIT_ACTOR_USER;
    case AUTHENTICATED_ACTOR_TOKEN:
        return JG_AUDIT_ACTOR_TOKEN;
    case AUTHENTICATED_ACTOR_LOCAL:
        return JG_AUDIT_ACTOR_LOCAL;
    default:
        return JG_AUDIT_ACTOR_SYSTEM;
    }
}

/** @brief Return whether one actor has a persistent database identifier. */
bool actor_has_identifier(const struct authenticated_actor *actor)
{
    return actor->kind == AUTHENTICATED_ACTOR_USER ||
           actor->kind == AUTHENTICATED_ACTOR_TOKEN;
}

/** @brief Return a bounded string length or one past the maximum. */
size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0U;

    if (text == NULL) {
        return maximum + 1U;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    return length;
}

/** @brief Validate one absolute key path without control characters. */
static bool key_path_valid(const char *path)
{
    size_t length = 0U;

    if (path == NULL || path[0U] != '/' || path[1U] == '\0') {
        return false;
    }
    while (length < PATH_MAX && path[length] != '\0') {
        const uint8_t character = (uint8_t)path[length];

        if (character < UINT8_C(0x20) || character == UINT8_C(0x7f)) {
            return false;
        }
        ++length;
    }
    return length > 1U && length < PATH_MAX;
}

/** @brief Create management state and load the appliance-local TOTP key. */
int jg_management_create(struct jg_database *database,
                         const char *totp_key_path,
                         const char *certificate_path,
                         const char *client_ca_path,
                         const char *backup_directory,
                         struct jg_daemon_runtime *runtime,
                         struct jg_management **management)
{
    struct jg_management *created = NULL;
    int result = 0;

    if (management == NULL) {
        return -EINVAL;
    }
    *management = NULL;
    if (database == NULL || !key_path_valid(totp_key_path) ||
        strlen(totp_key_path) > PATH_MAX - sizeof(MANAGEMENT_RECOVERY_SUFFIX) ||
        !key_path_valid(certificate_path) ||
        strlen(certificate_path) >
            PATH_MAX - sizeof(".pending-key" MANAGEMENT_RECOVERY_SUFFIX) ||
        !key_path_valid(client_ca_path) ||
        strlen(client_ca_path) >
            PATH_MAX - sizeof(MANAGEMENT_RECOVERY_SUFFIX) ||
        !key_path_valid(backup_directory)) {
        return -EINVAL;
    }
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    created->secrets = calloc(1U, sizeof(*created->secrets));
    if (created->secrets == NULL) {
        free(created);
        return -ENOMEM;
    }
    created->health = calloc(1U, sizeof(*created->health));
    if (created->health == NULL) {
        free(created->secrets);
        free(created);
        return -ENOMEM;
    }
    atomic_init(&created->health->degraded_reasons, 0U);
    created->database = database;
    created->runtime = runtime;
    (void)memcpy(created->totp_key_path, totp_key_path,
                 strlen(totp_key_path) + 1U);
    (void)memcpy(created->certificate_path, certificate_path,
                 strlen(certificate_path) + 1U);
    (void)memcpy(created->client_ca_path, client_ca_path,
                 strlen(client_ca_path) + 1U);
    (void)memcpy(created->backup_directory, backup_directory,
                 strlen(backup_directory) + 1U);
    jg_auth_password_policy_default(&created->password_policy);
    result = management_consistency_create(&created->consistency);
    if (result == 0) {
        result =
            management_totp_key_load(totp_key_path, created->secrets->totp_key);
    }
    if (result == 0) {
        result = recover_pending_operation(created);
        if (result != 0) {
            mark_management_degraded(
                created, MANAGEMENT_DEGRADED_EXTERNAL_RECOVERY,
                "management.startup_recovery",
                "Startup could not complete a pending management recovery");
            result = 0;
        }
    }
    if (result == 0) {
        refresh_policy_sync_health(created);
    }
    if (result == 0) {
        result = management_jobs_create(created, &created->jobs);
    }
    if (result != 0) {
        jg_management_destroy(created);
        return result;
    }
    *management = created;
    return 0;
}

/** @brief Validate text accepted as an internal request identifier. */
static bool request_id_valid(const char *request_id)
{
    const size_t length = bounded_length(request_id, MANAGEMENT_REQUEST_ID_MAX);

    if (length == 0U || length > MANAGEMENT_REQUEST_ID_MAX) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)request_id[index];

        if (!((character >= (uint8_t)'a' && character <= (uint8_t)'z') ||
              (character >= (uint8_t)'A' && character <= (uint8_t)'Z') ||
              (character >= (uint8_t)'0' && character <= (uint8_t)'9') ||
              character == (uint8_t)'-' || character == (uint8_t)'_')) {
            return false;
        }
    }
    return true;
}

/** @brief Validate a bounded HTTP Host value without delimiters or controls. */
static bool host_valid(const char *host)
{
    const size_t length = bounded_length(host, 128U);

    if (length == 0U || length > 128U) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)host[index];

        if (character <= UINT8_C(0x20) || character == UINT8_C(0x7f) ||
            character == (uint8_t)'/' || character == (uint8_t)'\\' ||
            character == (uint8_t)'@') {
            return false;
        }
    }
    return true;
}

/** @brief Accept only exact HTTPS same-origin state changes. */
static bool origin_valid(const char *origin, const char *host)
{
    static const char prefix[] = "https://";
    const size_t host_size = bounded_length(host, 128U);
    const size_t origin_size = bounded_length(origin, sizeof(prefix) + 128U);

    return host_valid(host) && origin != NULL &&
           origin_size == sizeof(prefix) - 1U + host_size &&
           memcmp(origin, prefix, sizeof(prefix) - 1U) == 0 &&
           memcmp(origin + sizeof(prefix) - 1U, host, host_size) == 0;
}

/** @brief Check whether one JSON object contains only allowlisted fields. */
bool fields_allowed(json_t *object,
                    const char *const *fields,
                    size_t field_count)
{
    const char *name = NULL;
    json_t *value = NULL;

    if (!json_is_object(object)) {
        return false;
    }
    json_object_foreach(object, name, value)
    {
        bool known = false;

        (void)value;
        for (size_t index = 0U; index < field_count; ++index) {
            if (strcmp(name, fields[index]) == 0) {
                known = true;
                break;
            }
        }
        if (!known) {
            return false;
        }
    }
    return true;
}

/** @brief Read a required bounded JSON string field. */
const char *required_string(const json_t *object,
                            const char *name,
                            size_t minimum,
                            size_t maximum)
{
    json_t *value = json_object_get(object, name);
    const char *text = json_is_string(value) ? json_string_value(value) : NULL;
    const size_t length = bounded_length(text, maximum);

    return length >= minimum && length <= maximum &&
                   json_string_length(value) == length
               ? text
               : NULL;
}

/** @brief Read an optional bounded JSON string field. */
const char *optional_string(const json_t *object,
                            const char *name,
                            size_t maximum)
{
    json_t *value = json_object_get(object, name);
    const char *text = NULL;

    if (value == NULL) {
        return "";
    }
    if (!json_is_string(value)) {
        return NULL;
    }
    text = json_string_value(value);
    return bounded_length(text, maximum) <= maximum &&
                   json_string_length(value) == strlen(text)
               ? text
               : NULL;
}

/** @brief Parse and validate one internal management request envelope. */
static int parse_request(const uint8_t *data,
                         size_t data_size,
                         json_t **root,
                         struct management_request *request)
{
    static const char *const fields[] = {
        "request_id",
        "method",
        "path",
        "query",
        "host",
        "origin",
        "remote_address",
        "session",
        "csrf",
        "bearer",
        "client_certificate",
        "body",
    };
    json_error_t error;
    json_t *parsed = NULL;
    int result = 0;

    *root = NULL;
    (void)memset(request, 0, sizeof(*request));
    if (data == NULL || data_size == 0U ||
        data_size > MANAGEMENT_REQUEST_SIZE_MAX) {
        return -EINVAL;
    }
    parsed = json_loadb((const char *)data, data_size, JSON_REJECT_DUPLICATES,
                        &error);
    if (!fields_allowed(parsed, fields, sizeof(fields) / sizeof(fields[0U]))) {
        result = -EINVAL;
    }
    if (result == 0) {
        request->request_id = required_string(parsed, "request_id", 1U,
                                              MANAGEMENT_REQUEST_ID_MAX);
        request->method = required_string(parsed, "method", 3U, 8U);
        request->path =
            required_string(parsed, "path", 1U, MANAGEMENT_PATH_MAX);
        request->query = optional_string(parsed, "query", MANAGEMENT_QUERY_MAX);
        request->host = required_string(parsed, "host", 1U, 128U);
        request->origin = optional_string(parsed, "origin", 256U);
        request->remote_address =
            required_string(parsed, "remote_address", 2U, 47U);
        request->session =
            optional_string(parsed, "session", JG_AUTH_SECRET_TEXT_SIZE - 1U);
        request->csrf =
            optional_string(parsed, "csrf", JG_AUTH_SECRET_TEXT_SIZE - 1U);
        request->bearer =
            optional_string(parsed, "bearer", JG_AUTH_SECRET_TEXT_SIZE - 1U);
        request->client_certificate =
            optional_string(parsed, "client_certificate", 64U);
        request->body = json_object_get(parsed, "body");
        if (!request_id_valid(request->request_id) || request->method == NULL ||
            request->path == NULL || request->query == NULL ||
            !host_valid(request->host) || request->origin == NULL ||
            request->remote_address == NULL || request->session == NULL ||
            request->csrf == NULL || request->bearer == NULL ||
            request->client_certificate == NULL ||
            !json_is_object(request->body)) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        *root = parsed;
    } else {
        if (parsed != NULL) {
            json_decref(parsed);
        }
    }
    return result;
}

/** @brief Validate one management envelope without dispatching it. */
int jg_management_request_validate(const uint8_t *request_data,
                                   size_t request_size)
{
    struct management_request request;
    json_t *root = NULL;
    const int result =
        parse_request(request_data, request_size, &root, &request);

    if (root != NULL) {
        json_decref(root);
    }
    return result;
}

/** @brief Parse an exact numeric IPv4 or IPv6 remote address. */
int parse_remote_address(const char *text, struct remote_address *remote)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    (void)memset(remote, 0, sizeof(*remote));
    if (inet_pton(AF_INET, text, &ipv4) == 1) {
        remote->family = JG_POLICY_ADDRESS_IPV4;
        (void)memcpy(remote->address, &ipv4, sizeof(ipv4));
        return 0;
    }
    if (inet_pton(AF_INET6, text, &ipv6) == 1) {
        remote->family = JG_POLICY_ADDRESS_IPV6;
        (void)memcpy(remote->address, &ipv6, sizeof(ipv6));
        return 0;
    }
    return -EINVAL;
}

/** @brief Decode one ASCII hexadecimal digit. */
int hexadecimal_value(char character, uint8_t *value)
{
    if (character >= '0' && character <= '9') {
        *value = (uint8_t)(character - '0');
        return 0;
    }
    if (character >= 'a' && character <= 'f') {
        *value = (uint8_t)(character - 'a' + 10);
        return 0;
    }
    if (character >= 'A' && character <= 'F') {
        *value = (uint8_t)(character - 'A' + 10);
        return 0;
    }
    return -EINVAL;
}

/** @brief Decode one exact SHA-256 client-certificate fingerprint. */
int parse_certificate_fingerprint(const char *text, uint8_t fingerprint[32U])
{
    if (text == NULL || strlen(text) != 64U) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < 32U; ++index) {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if (hexadecimal_value(text[index * 2U], &high) != 0 ||
            hexadecimal_value(text[index * 2U + 1U], &low) != 0) {
            (void)memset(fingerprint, 0, 32U);
            return -EINVAL;
        }
        fingerprint[index] = (uint8_t)((high << 4U) | low);
    }
    return 0;
}

/** @brief Read a trusted wall-clock timestamp for persistent operations. */
static int current_time(uint64_t *now)
{
    struct timespec value;

    if (clock_gettime(CLOCK_REALTIME, &value) != 0) {
        return -errno;
    }
    if (value.tv_sec <= 0) {
        return -EIO;
    }
    *now = (uint64_t)value.tv_sec;
    return 0;
}

/** @brief Create one consistent API error body. */
json_t *error_body(const char *code,
                   const char *message,
                   const char *request_id)
{
    json_t *body = json_object();
    json_t *error = json_object();

    if (body == NULL || error == NULL ||
        json_object_set_new(error, "code", json_string(code)) != 0 ||
        json_object_set_new(error, "message", json_string(message)) != 0 ||
        json_object_set_new(
            error, "request_id",
            json_string(request_id == NULL ? "" : request_id)) != 0 ||
        json_object_set(body, "error", error) != 0) {
        json_decref(error);
        json_decref(body);
        return NULL;
    }
    json_decref(error);
    return body;
}

/** @brief Serialize one complete internal response envelope. */
static int dump_response(json_t *response,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    const size_t required =
        json_dumpb(response, NULL, 0U, JSON_COMPACT | JSON_SORT_KEYS);

    if (required == 0U) {
        return -EIO;
    }
    if (required > output_size) {
        return -ENOSPC;
    }
    if (json_dumpb(response, (char *)output, output_size,
                   JSON_COMPACT | JSON_SORT_KEYS) != required) {
        return -EIO;
    }
    *written = required;
    return 0;
}

/** @brief Encode one complete JSON management response envelope. */
int encode_response(int status,
                    json_t *body,
                    const struct session_result *session,
                    uint8_t *output,
                    size_t output_size,
                    size_t *written)
{
    json_t *response = json_object();
    int result = 0;

    if (response == NULL || body == NULL ||
        json_object_set_new(response, "status", json_integer(status)) != 0 ||
        json_object_set(response, "body", body) != 0) {
        json_decref(response);
        json_decref(body);
        return -ENOMEM;
    }
    if (session != NULL && session->set_session != NULL &&
        json_object_set_new(response, "set_session",
                            json_string(session->set_session)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && session != NULL && session->clear_session &&
        json_object_set_new(response, "clear_session", json_true()) != 0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = dump_response(response, output, output_size, written);
    }
    json_decref(response);
    json_decref(body);
    return result;
}

/** @brief Encode one complete plain-text management response envelope. */
int encode_text_response(int status,
                         const char *content_type,
                         const char *text,
                         size_t text_size,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    json_t *response = json_object();
    int result = 0;

    if (response == NULL ||
        json_object_set_new(response, "status", json_integer(status)) != 0 ||
        json_object_set_new(response, "content_type",
                            json_string(content_type)) != 0 ||
        json_object_set_new(response, "text", json_stringn(text, text_size)) !=
            0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = dump_response(response, output, output_size, written);
    }
    json_decref(response);
    return result;
}

/** @brief Encode an HTTP-level error without exposing internal details. */
int respond_error(int status,
                  const char *code,
                  const char *message,
                  const char *request_id,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written)
{
    json_t *body = error_body(code, message, request_id);

    return body == NULL ? -ENOMEM
                        : encode_response(status, body, NULL, output,
                                          output_size, written);
}

/** @brief Read one required JSON boolean. */
bool required_boolean(const json_t *object, const char *name, bool *value)
{
    json_t *field = json_object_get(object, name);

    if (!json_is_boolean(field)) {
        return false;
    }
    *value = json_is_true(field);
    return true;
}

/** @brief Read one required positive JSON integer as an unsigned value. */
bool required_identifier(const json_t *object,
                         const char *name,
                         uint64_t *value)
{
    json_t *field = json_object_get(object, name);
    const json_int_t number =
        json_is_integer(field) ? json_integer_value(field) : 0;

    if (number <= 0) {
        return false;
    }
    *value = (uint64_t)number;
    return true;
}

/** @brief Read one required bounded nonnegative JSON integer. */
bool required_unsigned(const json_t *object,
                       const char *name,
                       uint64_t maximum,
                       uint64_t *value)
{
    json_t *field = json_object_get(object, name);
    const json_int_t number =
        json_is_integer(field) ? json_integer_value(field) : -1;

    if (number < 0 || (uint64_t)number > maximum) {
        return false;
    }
    *value = (uint64_t)number;
    return true;
}

/** @brief Read one required string-or-null JSON field. */
bool required_nullable_string(const json_t *object,
                              const char *name,
                              size_t maximum,
                              const char **value)
{
    json_t *field = json_object_get(object, name);
    const char *text = NULL;
    size_t length = 0U;

    if (json_is_null(field)) {
        *value = NULL;
        return true;
    }
    if (!json_is_string(field)) {
        return false;
    }
    text = json_string_value(field);
    length = bounded_length(text, maximum);
    if (length == 0U || length > maximum ||
        json_string_length(field) != length) {
        return false;
    }
    *value = text;
    return true;
}

/** @brief Add a timestamp or JSON null to one response object. */
int set_optional_timestamp(json_t *object, const char *name, uint64_t value)
{
    return json_object_set_new(object, name,
                               value == 0U ? json_null()
                                           : json_integer((json_int_t)value));
}

/** @brief Parse one bounded unsigned decimal text span. */
int parse_decimal(const char *text,
                  size_t size,
                  uint64_t maximum,
                  uint64_t *value)
{
    uint64_t parsed = 0U;

    if (text == NULL || size == 0U || value == NULL) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < size; ++index) {
        const uint8_t digit = (uint8_t)text[index];

        if (digit < (uint8_t)'0' || digit > (uint8_t)'9' ||
            parsed > (maximum - (uint64_t)(digit - (uint8_t)'0')) / 10U) {
            return -EINVAL;
        }
        parsed = parsed * 10U + (uint64_t)(digit - (uint8_t)'0');
    }
    *value = parsed;
    return 0;
}

/** @brief Decode one required nullable 32-byte hexadecimal field. */
bool required_optional_digest(const json_t *object,
                              const char *name,
                              uint8_t digest[32U],
                              bool *present)
{
    json_t *field = json_object_get(object, name);
    const char *text = NULL;
    size_t decoded_size = 0U;

    if (json_is_null(field)) {
        (void)memset(digest, 0, 32U);
        *present = false;
        return true;
    }
    if (!json_is_string(field) || json_string_length(field) != 64U) {
        return false;
    }
    text = json_string_value(field);
    if (sodium_hex2bin(digest, 32U, text, 64U, NULL, &decoded_size, NULL) !=
            0 ||
        decoded_size != 32U) {
        return false;
    }
    *present = true;
    return true;
}

/** @brief Parse one exact numeric cursor and limit query. */
int parse_page_query(const char *query,
                     const char *cursor_name,
                     size_t maximum_limit,
                     uint64_t *position,
                     size_t *limit)
{
    const char *cursor = query;
    const size_t cursor_name_size = strlen(cursor_name);
    bool have_position = false;
    bool have_limit = false;
    int result = 0;

    *position = 0U;
    *limit = maximum_limit < 50U ? maximum_limit : 50U;
    while (result == 0 && cursor != NULL && *cursor != '\0') {
        const char *end = strchr(cursor, '&');
        const char *equals = strchr(cursor, '=');
        const size_t field_size =
            end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        uint64_t parsed = 0U;

        if (equals == NULL || (size_t)(equals - cursor) >= field_size) {
            result = -EINVAL;
        } else if ((size_t)(equals - cursor) == cursor_name_size &&
                   memcmp(cursor, cursor_name, cursor_name_size) == 0 &&
                   !have_position) {
            result = parse_decimal(equals + 1,
                                   field_size - (size_t)(equals + 1 - cursor),
                                   (uint64_t)INT64_MAX, &parsed);
            if (result == 0) {
                *position = parsed;
                have_position = true;
            }
        } else if ((size_t)(equals - cursor) == sizeof("limit") - 1U &&
                   memcmp(cursor, "limit", sizeof("limit") - 1U) == 0 &&
                   !have_limit) {
            result = parse_decimal(equals + 1,
                                   field_size - (size_t)(equals + 1 - cursor),
                                   maximum_limit, &parsed);
            if (result == 0 && parsed > 0U) {
                *limit = (size_t)parsed;
                have_limit = true;
            } else {
                result = -EINVAL;
            }
        } else {
            result = -EINVAL;
        }
        cursor = end == NULL ? NULL : end + 1;
        if (end != NULL && end[1] == '\0') {
            result = -EINVAL;
        }
    }
    return result;
}

/** @brief Parse one identifier from an exact collection subpath. */
static bool collection_path_identifier(const char *path,
                                       const char *prefix,
                                       const char *suffix,
                                       uint64_t *identifier_value)
{
    const size_t prefix_size = strlen(prefix);
    const size_t suffix_size = strlen(suffix);
    const size_t path_size = strlen(path);
    const char *identifier = NULL;
    size_t identifier_size = 0U;

    if (path_size <= prefix_size + suffix_size ||
        memcmp(path, prefix, prefix_size) != 0 ||
        (suffix_size > 0U &&
         memcmp(path + path_size - suffix_size, suffix, suffix_size) != 0)) {
        return false;
    }
    identifier = path + prefix_size;
    identifier_size = path_size - prefix_size - suffix_size;
    return parse_decimal(identifier, identifier_size, (uint64_t)INT64_MAX,
                         identifier_value) == 0 &&
           *identifier_value > 0U;
}

/** @brief Add one nonnegative runtime counter to a JSON object. */
int set_counter(json_t *object, const char *name, uint64_t value)
{
    if (value > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    return json_object_set_new(object, name, json_integer((json_int_t)value)) ==
                   0
               ? 0
               : -ENOMEM;
}

/** @brief Return one accepted slow-operation reference. */
int respond_job_accepted(uint64_t job_id,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    json_t *body = json_object();
    json_t *job = json_object();

    if (body == NULL || job == NULL ||
        json_object_set_new(job, "id", json_integer((json_int_t)job_id)) != 0 ||
        json_object_set_new(job, "state", json_string("queued")) != 0 ||
        json_object_set(body, "job", job) != 0) {
        json_decref(job);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(job);
    return encode_response(202, body, NULL, output, output_size, written);
}

/** @brief Return one consistent slow-operation submission error. */
int respond_job_submission_error(int result,
                                 const struct management_request *request,
                                 const char *failure_message,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written)
{
    if (result == -EBUSY) {
        return respond_error(503, "job_queue_full",
                             "The slow-operation queue is currently full.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(
            429, "job_quota_exceeded",
            "Complete or inspect an existing job before submitting another.",
            request->request_id, output, output_size, written);
    }
    if (result == -EALREADY) {
        return respond_error(409, "job_conflict",
                             "A conflicting slow operation is already active.",
                             request->request_id, output, output_size, written);
    }
    return respond_error(500, "job_queue_failed", failure_message,
                         request->request_id, output, output_size, written);
}

/** @brief Execute or reject one reauthorized worker-owned operation. */
int execute_management_job(struct jg_management *management,
                           struct management_job *job,
                           int authorization_result,
                           size_t *response_size)
{
    bool mutation_active = false;
    int result = 0;

    if (authorization_result == 0 &&
        job->kind != MANAGEMENT_JOB_BACKUP_RESTORE) {
        result = management_mutation_begin(management);
        mutation_active = result == 0;
        if (result != 0 && !job->system_job) {
            (void)respond_error(
                result == -EBUSY ? 503 : 500,
                result == -EBUSY ? "restore_in_progress"
                                 : "consistency_unavailable",
                result == -EBUSY
                    ? "An applied restore temporarily prevents mutations."
                    : "The management consistency gate is unavailable.",
                job->request_id, job->response, sizeof(job->response),
                response_size);
        }
    }
    if (authorization_result != 0) {
        const bool denied =
            authorization_result == -EACCES || authorization_result == -EPERM;
        const bool degraded = authorization_result == -EROFS;

        result = respond_error(
            denied     ? 403
            : degraded ? 503
                       : 500,
            denied     ? "job_authorization_expired"
            : degraded ? "management_degraded"
                       : "job_authorization_failed",
            denied     ? "Authorization changed before the job could start."
            : degraded ? "The job was suspended because management is degraded."
                       : "The job authorization could not be rechecked.",
            job->request_id, job->response, sizeof(job->response),
            response_size);
    } else if (result == 0) {
        if (job->kind == MANAGEMENT_JOB_SOURCE_REFRESH) {
            result = execute_source_refresh_job(management, job, job->response,
                                                sizeof(job->response),
                                                response_size);
        } else if (job->kind == MANAGEMENT_JOB_SCHEDULED_SOURCES) {
            result =
                update_due_blocklists_now(management, job->submitted_at, NULL);
        } else if (job->kind == MANAGEMENT_JOB_BLOCKLIST_IMPORT) {
            result = execute_blocklist_import_job(
                management, job, job->response, sizeof(job->response),
                response_size);
        } else if (job->kind == MANAGEMENT_JOB_BACKUP_CREATE) {
            result =
                execute_backup_create_job(management, job, job->response,
                                          sizeof(job->response), response_size);
        } else if (job->kind == MANAGEMENT_JOB_BACKUP_RESTORE) {
            result = execute_backup_restore_job(management, job, job->response,
                                                sizeof(job->response),
                                                response_size);
        } else if (job->kind == MANAGEMENT_JOB_DIAGNOSTICS_CREATE) {
            result = execute_diagnostics_create_job(
                management, job, job->response, sizeof(job->response),
                response_size);
        } else if (job->kind == MANAGEMENT_JOB_CERTIFICATE_CSR) {
            result = execute_certificate_csr_job(management, job, job->response,
                                                 sizeof(job->response),
                                                 response_size);
        } else {
            result = -EINVAL;
        }
    }
    if (mutation_active) {
        management_mutation_end(management);
    }
    if (!job->system_job && result != 0 && *response_size == 0U) {
        (void)respond_error(500, "job_failed",
                            "The asynchronous operation failed.",
                            job->request_id, job->response,
                            sizeof(job->response), response_size);
    }
    return result;
}

/** @brief Return one authorized retained slow-operation state. */
static int handle_job_get(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t job_id,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    struct authenticated_actor actor;
    struct management_job snapshot;
    json_error_t error;
    json_t *body = NULL;
    json_t *job = NULL;
    json_t *response = NULL;
    const char *kind = NULL;
    const char *state = NULL;
    int result =
        authenticate_actor(management, request, remote, false, 0U, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "Job inspection accepts no query or body.",
                             request->request_id, output, output_size, written);
    }
    result =
        management_jobs_snapshot(management->jobs, job_id, &actor, &snapshot);
    if (result == -ENOENT) {
        return respond_error(404, "job_not_found",
                             "The requested job is no longer available.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return result;
    }
    if (!jg_access_grants(actor.identity.permissions,
                          snapshot.required_permission)) {
        sodium_memzero(&snapshot, sizeof(snapshot));
        return respond_actor_error(-EPERM, request, output, output_size,
                                   written);
    }
    state = management_job_state_name(snapshot.state);
    kind = management_job_kind_name(snapshot.kind);
    if (state == NULL || kind == NULL) {
        sodium_memzero(&snapshot, sizeof(snapshot));
        return -EILSEQ;
    }
    if (snapshot.state == MANAGEMENT_JOB_COMPLETED &&
        snapshot.response_size > 0U) {
        response =
            json_loadb((const char *)snapshot.response, snapshot.response_size,
                       JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(response)) {
            json_decref(response);
            sodium_memzero(&snapshot, sizeof(snapshot));
            return -EILSEQ;
        }
    } else {
        response = json_null();
    }
    body = json_object();
    job = json_object();
    if (body == NULL || job == NULL ||
        json_object_set_new(job, "id", json_integer((json_int_t)job_id)) != 0 ||
        json_object_set_new(job, "kind", json_string(kind)) != 0 ||
        json_object_set_new(job, "state", json_string(state)) != 0 ||
        json_object_set_new(job, "submitted_at",
                            json_integer((json_int_t)snapshot.submitted_at)) !=
            0 ||
        json_object_set_new(
            job, "started_at",
            snapshot.started_at == 0U
                ? json_null()
                : json_integer((json_int_t)snapshot.started_at)) != 0 ||
        json_object_set_new(
            job, "completed_at",
            snapshot.completed_at == 0U
                ? json_null()
                : json_integer((json_int_t)snapshot.completed_at)) != 0 ||
        json_object_set(job, "response", response) != 0 ||
        json_object_set(body, "job", job) != 0) {
        result = -ENOMEM;
    }
    json_decref(response);
    json_decref(job);
    if (result != 0) {
        sodium_memzero(&snapshot, sizeof(snapshot));
        json_decref(body);
        return result;
    }
    result = encode_response(200, body, NULL, output, output_size, written);
    if (result == 0 && snapshot.state == MANAGEMENT_JOB_COMPLETED) {
        result = management_jobs_observe(management->jobs, job_id);
    }
    sodium_memzero(&snapshot, sizeof(snapshot));
    return result;
}

/** @brief Return whether one path identifies an implemented API resource. */
static bool management_path_known(const char *path)
{
    static const char *const exact_paths[] = {
        "/api/v1/audit",
        "/api/v1/audit/verify",
        "/api/v1/auth/bootstrap",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/password",
        "/api/v1/auth/session",
        "/api/v1/auth/state",
        "/api/v1/auth/totp/confirm",
        "/api/v1/auth/totp/disable",
        "/api/v1/auth/totp/provision",
        "/api/v1/backups",
        "/api/v1/blocklists",
        "/api/v1/certificates",
        "/api/v1/certificates/csr",
        "/api/v1/certificates/install",
        "/api/v1/config/reload",
        "/api/v1/config/validate",
        "/api/v1/diagnostics",
        "/api/v1/domains",
        "/api/v1/events",
        "/api/v1/health",
        "/api/v1/logging",
        "/api/v1/logging/traces",
        "/api/v1/metrics",
        "/api/v1/mtls/authorities",
        "/api/v1/mtls/mappings",
        "/api/v1/network",
        "/api/v1/network/apply",
        "/api/v1/network/confirm",
        "/api/v1/network/rollback",
        "/api/v1/network/validate",
        "/api/v1/policies/destinations",
        "/api/v1/policies/groups",
        "/api/v1/policies/mode",
        "/api/v1/policies/scopes",
        "/api/v1/policies/simulate",
        "/api/v1/policies/statistics",
        "/api/v1/policies/statistics/cleanup",
        "/api/v1/service/restart",
        "/api/v1/sources",
        "/api/v1/status",
        "/api/v1/system/reboot",
        "/api/v1/system/shutdown",
        "/api/v1/tokens",
        "/api/v1/users",
    };
    uint64_t identifier = 0U;

    for (size_t index = 0U; index < sizeof(exact_paths) / sizeof(*exact_paths);
         ++index) {
        if (strcmp(path, exact_paths[index]) == 0) {
            return true;
        }
    }
    return collection_path_identifier(path, "/api/v1/backups/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/backups/", "/restore",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/domains/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/domains/", "/analysis",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/jobs/", "", &identifier) ||
           collection_path_identifier(path, "/api/v1/mtls/mappings/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/policies/destinations/",
                                      "", &identifier) ||
           collection_path_identifier(path, "/api/v1/policies/destinations/",
                                      "/analysis", &identifier) ||
           collection_path_identifier(path, "/api/v1/policies/groups/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/policies/scopes/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/sources/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/sources/", "/refresh",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/tokens/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/users/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/users/", "/password",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/users/", "/totp",
                                      &identifier);
}

/** @brief Dispatch one valid authentication management request. */
static int dispatch_request(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    const bool post = strcmp(request->method, "POST") == 0;
    const bool state_change = strcmp(request->method, "GET") != 0;
    const bool authentication_path = strncmp(request->path, "/api/v1/auth/",
                                             sizeof("/api/v1/auth/") - 1U) == 0;
    uint64_t backup_id = 0U;
    uint64_t destination_rule_id = 0U;
    uint64_t domain_rule_id = 0U;
    uint64_t group_id = 0U;
    uint64_t job_id = 0U;
    uint64_t mapping_id = 0U;
    uint64_t source_id = 0U;
    uint64_t scope_mode_id = 0U;
    uint64_t token_id = 0U;
    uint64_t user_id = 0U;

    if (request->client_certificate[0U] != '\0' && authentication_path) {
        return respond_error(404, "not_found",
                             "The requested API resource was not found.",
                             request->request_id, output, output_size, written);
    }
    if (!request->local_administrator && state_change &&
        (request->bearer[0U] == '\0' || authentication_path) &&
        !origin_valid(request->origin, request->host)) {
        return respond_error(403, "invalid_origin",
                             "The request origin is not permitted.",
                             request->request_id, output, output_size, written);
    }
    if (state_change && management_degraded_reasons(management) != 0U &&
        !degraded_path_allowed(request->path)) {
        return respond_error(
            503, "management_degraded",
            "Management mutations are suspended until consistency is "
            "restored.",
            request->request_id, output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/status") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_status(management, request, remote, now, output,
                             output_size, written);
    }
    if (strcmp(request->path, "/api/v1/health") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_health(management, request, remote, now, output,
                             output_size, written);
    }
    if (strcmp(request->path, "/api/v1/metrics") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_metrics(management, request, remote, now, output,
                              output_size, written);
    }
    if (strcmp(request->path, "/api/v1/config/validate") == 0 && post) {
        return handle_configuration(management, request, remote, now, false,
                                    output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/config/reload") == 0 && post) {
        return handle_configuration(management, request, remote, now, true,
                                    output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/logging") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_logging_get(management, request, remote, now, output,
                                  output_size, written);
    }
    if (strcmp(request->path, "/api/v1/logging") == 0 &&
        strcmp(request->method, "PUT") == 0) {
        return handle_logging_update(management, request, remote, now, output,
                                     output_size, written);
    }
    if (strcmp(request->path, "/api/v1/logging/traces") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_logging_traces(management, request, remote, now, output,
                                     output_size, written);
    }
    if (strcmp(request->path, "/api/v1/service/restart") == 0 && post) {
        return handle_system_action(management, request, remote, now,
                                    JG_SYSTEM_ACTION_RESTART, output,
                                    output_size, written);
    }
    if (strcmp(request->path, "/api/v1/system/reboot") == 0 && post) {
        return handle_system_action(management, request, remote, now,
                                    JG_SYSTEM_ACTION_REBOOT, output,
                                    output_size, written);
    }
    if (strcmp(request->path, "/api/v1/system/shutdown") == 0 && post) {
        return handle_system_action(management, request, remote, now,
                                    JG_SYSTEM_ACTION_POWEROFF, output,
                                    output_size, written);
    }
    if (strcmp(request->path, "/api/v1/diagnostics") == 0 && post) {
        return handle_diagnostics_create(management, request, remote, now,
                                         output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/network") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_network_get(management, request, remote, now, output,
                                  output_size, written);
    }
    if (strcmp(request->path, "/api/v1/network/validate") == 0 && post) {
        return handle_network_validate(management, request, remote, now, output,
                                       output_size, written);
    }
    if (strcmp(request->path, "/api/v1/network/apply") == 0 && post) {
        return handle_network_apply(management, request, remote, now, output,
                                    output_size, written);
    }
    if (strcmp(request->path, "/api/v1/network/confirm") == 0 && post) {
        return handle_network_confirm(management, request, remote, now, output,
                                      output_size, written);
    }
    if (strcmp(request->path, "/api/v1/network/rollback") == 0 && post) {
        return handle_network_rollback(management, request, remote, now, output,
                                       output_size, written);
    }
    if (strcmp(request->path, "/api/v1/blocklists") == 0 && post) {
        return handle_blocklist_import(management, request, remote, now, output,
                                       output_size, written);
    }
    if (strcmp(request->path, "/api/v1/sources") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_blocklist_sources_list(management, request, remote, now,
                                             output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/sources") == 0 && post) {
        return handle_blocklist_source_create(management, request, remote, now,
                                              output, output_size, written);
    }
    if (post && collection_path_identifier(request->path, "/api/v1/sources/",
                                           "/refresh", &source_id)) {
        return handle_blocklist_source_refresh(management, request, remote,
                                               source_id, now, output,
                                               output_size, written);
    }
    if (strcmp(request->method, "PATCH") == 0 &&
        collection_path_identifier(request->path, "/api/v1/sources/", "",
                                   &source_id)) {
        return handle_blocklist_source_update(management, request, remote,
                                              source_id, now, output,
                                              output_size, written);
    }
    if (strcmp(request->method, "DELETE") == 0 &&
        collection_path_identifier(request->path, "/api/v1/sources/", "",
                                   &source_id)) {
        return handle_blocklist_source_delete(management, request, remote,
                                              source_id, now, output,
                                              output_size, written);
    }
    if (strcmp(request->method, "GET") == 0 &&
        collection_path_identifier(request->path, "/api/v1/jobs/", "",
                                   &job_id)) {
        return handle_job_get(management, request, remote, job_id, now, output,
                              output_size, written);
    }
    if (strcmp(request->path, "/api/v1/domains") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_domain_rules_list(management, request, remote, now,
                                        output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/mode") == 0) {
        return handle_policy_global_mode(management, request, remote, now,
                                         output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/groups") == 0) {
        return handle_policy_groups(management, request, remote, now, output,
                                    output_size, written);
    }
    if (collection_path_identifier(request->path, "/api/v1/policies/groups/",
                                   "", &group_id)) {
        return handle_policy_group(management, request, remote, group_id, now,
                                   output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/scopes") == 0) {
        return handle_policy_scope_modes(management, request, remote, now,
                                         output, output_size, written);
    }
    if (collection_path_identifier(request->path, "/api/v1/policies/scopes/",
                                   "", &scope_mode_id)) {
        return handle_policy_scope_mode(management, request, remote,
                                        scope_mode_id, now, output, output_size,
                                        written);
    }
    if (strcmp(request->path, "/api/v1/policies/statistics") == 0) {
        return handle_policy_statistics(management, request, remote, now,
                                        output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/statistics/cleanup") == 0 &&
        post) {
        return handle_policy_statistics_cleanup(
            management, request, remote, now, output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/destinations") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_destination_rules_list(management, request, remote, now,
                                             output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/destinations") == 0 && post) {
        return handle_destination_rule_create(management, request, remote, now,
                                              output, output_size, written);
    }
    if (strcmp(request->method, "GET") == 0 &&
        collection_path_identifier(request->path,
                                   "/api/v1/policies/destinations/",
                                   "/analysis", &destination_rule_id)) {
        return handle_policy_rule_analysis(
            management, request, remote, JG_POLICY_STATS_DESTINATION,
            destination_rule_id, now, output, output_size, written);
    }
    if (strcmp(request->method, "PATCH") == 0 &&
        collection_path_identifier(request->path,
                                   "/api/v1/policies/destinations/", "",
                                   &destination_rule_id)) {
        return handle_destination_rule_update(management, request, remote,
                                              destination_rule_id, now, output,
                                              output_size, written);
    }
    if (strcmp(request->method, "DELETE") == 0 &&
        collection_path_identifier(request->path,
                                   "/api/v1/policies/destinations/", "",
                                   &destination_rule_id)) {
        return handle_destination_rule_delete(management, request, remote,
                                              destination_rule_id, now, output,
                                              output_size, written);
    }
    if (strcmp(request->path, "/api/v1/domains") == 0 && post) {
        return handle_domain_rule_create(management, request, remote, now,
                                         output, output_size, written);
    }
    if (strcmp(request->method, "GET") == 0 &&
        collection_path_identifier(request->path, "/api/v1/domains/",
                                   "/analysis", &domain_rule_id)) {
        return handle_policy_rule_analysis(
            management, request, remote, JG_POLICY_STATS_DOMAIN, domain_rule_id,
            now, output, output_size, written);
    }
    if (strcmp(request->method, "PATCH") == 0 &&
        collection_path_identifier(request->path, "/api/v1/domains/", "",
                                   &domain_rule_id)) {
        return handle_domain_rule_update(management, request, remote,
                                         domain_rule_id, now, output,
                                         output_size, written);
    }
    if (strcmp(request->method, "DELETE") == 0 &&
        collection_path_identifier(request->path, "/api/v1/domains/", "",
                                   &domain_rule_id)) {
        return handle_domain_rule_delete(management, request, remote,
                                         domain_rule_id, now, output,
                                         output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/simulate") == 0 && post) {
        return handle_policy_simulation(management, request, remote, now,
                                        output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/events") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_events_list(management, request, remote, now, output,
                                  output_size, written);
    }
    if (strcmp(request->path, "/api/v1/audit/verify") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_audit_verify(management, request, remote, now, output,
                                   output_size, written);
    }
    if (strcmp(request->path, "/api/v1/audit") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_audit_list(management, request, remote, now, output,
                                 output_size, written);
    }
    if (strcmp(request->path, "/api/v1/users") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_users_list(management, request, remote, now, output,
                                 output_size, written);
    }
    if (strcmp(request->path, "/api/v1/users") == 0 && post) {
        return handle_user_create(management, request, remote, now, output,
                                  output_size, written);
    }
    if (strcmp(request->path, "/api/v1/tokens") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_tokens_list(management, request, remote, now, output,
                                  output_size, written);
    }
    if (strcmp(request->path, "/api/v1/tokens") == 0 && post) {
        return handle_token_issue(management, request, remote, now, output,
                                  output_size, written);
    }
    if (strcmp(request->path, "/api/v1/certificates") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_certificate_show(management, request, remote, now, output,
                                       output_size, written);
    }
    if (strcmp(request->path, "/api/v1/certificates/install") == 0 && post) {
        return handle_certificate_install(management, request, remote, now,
                                          output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/certificates/csr") == 0 && post) {
        return handle_certificate_csr(management, request, remote, now, output,
                                      output_size, written);
    }
    if (strcmp(request->path, "/api/v1/mtls/authorities") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_mtls_authorities_show(management, request, remote, now,
                                            output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/mtls/authorities") == 0 &&
        strcmp(request->method, "PUT") == 0) {
        return handle_mtls_authorities_install(management, request, remote, now,
                                               output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/mtls/authorities") == 0 &&
        strcmp(request->method, "DELETE") == 0) {
        return handle_mtls_authorities_remove(management, request, remote, now,
                                              output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/mtls/mappings") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_mtls_mappings_list(management, request, remote, now,
                                         output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/mtls/mappings") == 0 && post) {
        return handle_mtls_mapping_create(management, request, remote, now,
                                          output, output_size, written);
    }
    if (strcmp(request->method, "DELETE") == 0 &&
        collection_path_identifier(request->path, "/api/v1/mtls/mappings/", "",
                                   &mapping_id)) {
        return handle_mtls_mapping_revoke(management, request, remote,
                                          mapping_id, now, output, output_size,
                                          written);
    }
    if (strcmp(request->path, "/api/v1/backups") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_backups_list(management, request, remote, now, output,
                                   output_size, written);
    }
    if (strcmp(request->path, "/api/v1/backups") == 0 && post) {
        return handle_backup_create(management, request, remote, now, output,
                                    output_size, written);
    }
    if (post && collection_path_identifier(request->path, "/api/v1/backups/",
                                           "/restore", &backup_id)) {
        return handle_backup_restore(management, request, remote, backup_id,
                                     now, output, output_size, written);
    }
    if (strcmp(request->method, "GET") == 0 &&
        collection_path_identifier(request->path, "/api/v1/backups/", "",
                                   &backup_id)) {
        return handle_backup_inspect(management, request, remote, backup_id,
                                     now, output, output_size, written);
    }
    if (strcmp(request->method, "DELETE") == 0 &&
        collection_path_identifier(request->path, "/api/v1/tokens/", "",
                                   &token_id)) {
        return handle_token_revoke(management, request, remote, token_id, now,
                                   output, output_size, written);
    }
    if (post && collection_path_identifier(request->path, "/api/v1/users/",
                                           "/password", &user_id)) {
        return handle_user_password_reset(management, request, remote, user_id,
                                          now, output, output_size, written);
    }
    if (strcmp(request->method, "DELETE") == 0 &&
        collection_path_identifier(request->path, "/api/v1/users/", "/totp",
                                   &user_id)) {
        return handle_user_totp_disable(management, request, remote, user_id,
                                        now, output, output_size, written);
    }
    if (strcmp(request->method, "PATCH") == 0 &&
        collection_path_identifier(request->path, "/api/v1/users/", "",
                                   &user_id)) {
        return handle_user_update(management, request, remote, user_id, now,
                                  output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/state") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_authentication_state(management, request, output,
                                           output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/bootstrap") == 0 && post) {
        return handle_bootstrap(management, request, remote, now, output,
                                output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/login") == 0 && post) {
        return handle_login(management, request, remote, now, output,
                            output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/password") == 0 && post) {
        return handle_password_change(management, request, remote, now, output,
                                      output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/session") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_session(management, request, remote, now, output,
                              output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/logout") == 0 && post) {
        return handle_logout(management, request, remote, now, output,
                             output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/totp/provision") == 0 && post) {
        return handle_totp_provision(management, request, remote, now, output,
                                     output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/totp/confirm") == 0 && post) {
        return handle_totp_confirm(management, request, remote, now, output,
                                   output_size, written);
    }
    if (strcmp(request->path, "/api/v1/auth/totp/disable") == 0 && post) {
        return handle_totp_disable(management, request, remote, now, output,
                                   output_size, written);
    }
    if (management_path_known(request->path)) {
        return respond_error(405, "method_not_allowed",
                             "The method is not allowed for this resource.",
                             request->request_id, output, output_size, written);
    }
    return respond_error(404, "not_found",
                         "The requested API resource was not found.",
                         request->request_id, output, output_size, written);
}

/** @brief Record one correlated management completion without request data. */
static void trace_management_completion(
    const struct management_request *request,
    const uint8_t *response,
    size_t response_size,
    int operation_result)
{
    enum jg_log_level level = JG_LOG_WARNING;
    json_error_t error;
    json_t *envelope = NULL;
    json_t *details = NULL;
    char *encoded = NULL;
    json_int_t status = 0;

    if (operation_result == 0) {
        envelope = json_loadb((const char *)response, response_size,
                              JSON_REJECT_DUPLICATES, &error);
        status = json_integer_value(json_object_get(envelope, "status"));
        level = status >= 500 ? JG_LOG_WARNING : JG_LOG_TRACE;
    }
    if (!jg_log_enabled("management", level)) {
        json_decref(envelope);
        return;
    }
    details = json_object();
    if (details != NULL &&
        (json_object_set_new(details, "method", json_string(request->method)) !=
             0 ||
         json_object_set_new(details, "path", json_string(request->path)) !=
             0 ||
         json_object_set_new(details, "status", json_integer(status)) != 0 ||
         json_object_set_new(details, "operation_result",
                             json_integer(operation_result)) != 0)) {
        json_decref(details);
        details = NULL;
    }
    if (details != NULL) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
    }
    if (encoded != NULL) {
        (void)jg_log_emit(level, "management", "management.request",
                          request->request_id, "Management request completed",
                          encoded);
    }
    free(encoded);
    json_decref(details);
    json_decref(envelope);
}

/** @brief Parse, authenticate, and dispatch one management JSON envelope. */
int jg_management_process(struct jg_management *management,
                          const uint8_t *request_data,
                          size_t request_size,
                          bool local_administrator,
                          uint8_t *response,
                          size_t response_size,
                          size_t *written)
{
    struct management_request request;
    struct remote_address remote;
    json_t *root = NULL;
    uint64_t now = 0U;
    bool mutation_active = false;
    bool mutation_blocked = false;
    int result = 0;

    if (management == NULL || request_data == NULL || response == NULL ||
        written == NULL) {
        return -EINVAL;
    }
    *written = 0U;
    result = parse_request(request_data, request_size, &root, &request);
    if (result != 0) {
        return respond_error(400, "invalid_request",
                             "The management request is not valid.", "",
                             response, response_size, written);
    }
    request.local_administrator = local_administrator;
    result = parse_remote_address(request.remote_address, &remote);
    if (result != 0) {
        result = respond_error(
            400, "invalid_request", "The remote address is not valid.",
            request.request_id, response, response_size, written);
    }
    if (result == 0) {
        result = current_time(&now);
    }
    if (result == 0 && strcmp(request.method, "GET") != 0) {
        const int consistency_result = management_mutation_begin(management);

        mutation_active = consistency_result == 0;
        mutation_blocked = consistency_result != 0;
        if (consistency_result != 0) {
            result = respond_error(
                consistency_result == -EBUSY ? 503 : 500,
                consistency_result == -EBUSY ? "restore_in_progress"
                                             : "consistency_unavailable",
                consistency_result == -EBUSY
                    ? "An applied restore temporarily prevents mutations."
                    : "The management consistency gate is unavailable.",
                request.request_id, response, response_size, written);
        }
    }
    if (result == 0 && !mutation_blocked) {
        result = dispatch_request(management, &request, &remote, now, response,
                                  response_size, written);
    }
    if (mutation_active) {
        management_mutation_end(management);
    }
    trace_management_completion(&request, response, *written, result);
    json_decref(root);
    return result;
}

/** @brief Consume one deferred lifecycle action. */
enum jg_system_action jg_management_take_system_action(
    struct jg_management *management)
{
    enum jg_system_action action = JG_SYSTEM_ACTION_NONE;

    if (management != NULL) {
        action = management->pending_system_action;
        management->pending_system_action = JG_SYSTEM_ACTION_NONE;
    }
    return action;
}

/** @brief Clear the TOTP key and release management state. */
void jg_management_destroy(struct jg_management *management)
{
    if (management == NULL) {
        return;
    }
    management_jobs_destroy(management->jobs);
    management->jobs = NULL;
    management_consistency_destroy(management->consistency);
    management->consistency = NULL;
    if (management->secrets != NULL) {
        sodium_memzero(management->secrets, sizeof(*management->secrets));
        free(management->secrets);
        management->secrets = NULL;
    }
    free(management->health);
    management->health = NULL;
    sodium_memzero(management, sizeof(*management));
    free(management);
}
