/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include <jansson.h>
#include <pthread.h>
#include <sodium.h>

#include "daemon_runtime.h"
#include "database_internal.h"
#include "diagnostic_bundle.h"
#include "janusgate/access.h"
#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/backup.h"
#include "janusgate/certificate.h"
#include "janusgate/diagnostic.h"
#include "janusgate/event.h"
#include "janusgate/ipc.h"
#include "janusgate/logging.h"
#include "metrics.h"
#include "netd_client.h"

/** @brief Execute one authenticated diagnostic archive job. */
static int execute_diagnostics_create_job(struct jg_management *management,
                                          const struct management_job *job,
                                          uint8_t *output,
                                          size_t output_size,
                                          size_t *written);

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

/** @brief Load one exact private key from a secure regular file. */
static int load_totp_key(const char *path, uint8_t key[JG_AUTH_TOTP_KEY_SIZE])
{
    struct stat metadata;
    uint8_t extra = 0U;
    size_t offset = 0U;
    int descriptor = -1;
    int result = 0;

    if (!key_path_valid(path)) {
        return -EINVAL;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) ||
               (metadata.st_mode & S_IRUSR) == 0U ||
               (metadata.st_mode & (S_IXUSR | S_IRWXG | S_IRWXO)) != 0U ||
               (geteuid() != 0U && metadata.st_uid != geteuid())) {
        result = -EACCES;
    }
    while (result == 0 && offset < JG_AUTH_TOTP_KEY_SIZE) {
        const ssize_t count =
            read(descriptor, key + offset, JG_AUTH_TOTP_KEY_SIZE - offset);

        if (count < 0) {
            result = errno == EINTR ? 0 : -errno;
        } else if (count == 0) {
            result = -EMSGSIZE;
        } else {
            offset += (size_t)count;
        }
    }
    if (result == 0) {
        ssize_t count = 0;

        do {
            count = read(descriptor, &extra, sizeof(extra));
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            result = -errno;
        } else if (count != 0) {
            result = -EMSGSIZE;
        }
    }
    (void)close(descriptor);
    if (result != 0) {
        sodium_memzero(key, JG_AUTH_TOTP_KEY_SIZE);
    }
    return result;
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
    if (database == NULL || totp_key_path == NULL ||
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
    created->health = calloc(1U, sizeof(*created->health));
    if (created->health == NULL) {
        free(created);
        return -ENOMEM;
    }
    atomic_init(&created->health->degraded_reasons, 0U);
    created->database = database;
    created->runtime = runtime;
    (void)memcpy(created->certificate_path, certificate_path,
                 strlen(certificate_path) + 1U);
    (void)memcpy(created->client_ca_path, client_ca_path,
                 strlen(client_ca_path) + 1U);
    (void)memcpy(created->backup_directory, backup_directory,
                 strlen(backup_directory) + 1U);
    jg_auth_password_policy_default(&created->password_policy);
    result = management_consistency_create(&created->consistency);
    if (result == 0) {
        result = load_totp_key(totp_key_path, created->totp_key);
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
static int encode_text_response(int status,
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

/** @brief Return the stable external name for one audit actor kind. */
static const char *audit_actor_name(enum jg_audit_actor_type actor)
{
    switch (actor) {
    case JG_AUDIT_ACTOR_SYSTEM:
        return "system";
    case JG_AUDIT_ACTOR_USER:
        return "user";
    case JG_AUDIT_ACTOR_TOKEN:
        return "token";
    case JG_AUDIT_ACTOR_LOCAL:
        return "local";
    default:
        return NULL;
    }
}

/** @brief Convert one immutable audit record to public JSON. */
static json_t *audit_json(const struct jg_audit_record *record)
{
    char previous_hash[JG_AUDIT_HASH_SIZE * 2U + 1U];
    char event_hash[JG_AUDIT_HASH_SIZE * 2U + 1U];
    const char *actor = audit_actor_name(record->actor_type);
    json_t *body = json_object();

    (void)memset(previous_hash, 0, sizeof(previous_hash));
    if (!record->first &&
        sodium_bin2hex(previous_hash, sizeof(previous_hash),
                       record->previous_hash, JG_AUDIT_HASH_SIZE) == NULL) {
        json_decref(body);
        return NULL;
    }
    if (actor == NULL ||
        sodium_bin2hex(event_hash, sizeof(event_hash), record->event_hash,
                       JG_AUDIT_HASH_SIZE) == NULL ||
        body == NULL ||
        json_object_set_new(body, "id",
                            json_integer((json_int_t)record->event_id)) != 0 ||
        json_object_set_new(body, "occurred_at",
                            json_integer((json_int_t)record->occurred_at)) !=
            0 ||
        json_object_set_new(body, "actor_type", json_string(actor)) != 0 ||
        json_object_set_new(body, "actor_id",
                            record->has_actor_id
                                ? json_integer((json_int_t)record->actor_id)
                                : json_null()) != 0 ||
        json_object_set_new(body, "source", json_string(record->source)) != 0 ||
        json_object_set_new(body, "action", json_string(record->action)) != 0 ||
        json_object_set_new(body, "object_type",
                            json_string(record->object_type)) != 0 ||
        json_object_set_new(body, "object_id",
                            record->object_id[0U] == '\0'
                                ? json_null()
                                : json_string(record->object_id)) != 0 ||
        json_object_set_new(body, "details", json_string(record->details)) !=
            0 ||
        json_object_set_new(
            body, "previous_revision",
            record->has_previous_revision
                ? json_integer((json_int_t)record->previous_revision)
                : json_null()) != 0 ||
        json_object_set_new(body, "new_revision",
                            record->has_new_revision
                                ? json_integer((json_int_t)record->new_revision)
                                : json_null()) != 0 ||
        json_object_set_new(body, "success", json_boolean(record->success)) !=
            0 ||
        json_object_set_new(body, "request_id",
                            json_string(record->request_id)) != 0 ||
        json_object_set_new(body, "previous_hash",
                            record->first ? json_null()
                                          : json_string(previous_hash)) != 0 ||
        json_object_set_new(body, "event_hash", json_string(event_hash)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Return the stable external name for one event severity. */
static const char *event_severity_name(enum jg_event_severity severity)
{
    switch (severity) {
    case JG_EVENT_SEVERITY_DEBUG:
        return "debug";
    case JG_EVENT_SEVERITY_INFO:
        return "info";
    case JG_EVENT_SEVERITY_WARNING:
        return "warning";
    case JG_EVENT_SEVERITY_ERROR:
        return "error";
    case JG_EVENT_SEVERITY_CRITICAL:
        return "critical";
    case JG_EVENT_SEVERITY_ANY:
    default:
        return NULL;
    }
}

/** @brief Parse one optional external event severity. */
static bool parse_event_severity(const char *text,
                                 size_t text_size,
                                 enum jg_event_severity *severity)
{
    static const struct {
        const char *name;
        enum jg_event_severity severity;
    } values[] = {
        {"debug", JG_EVENT_SEVERITY_DEBUG},
        {"info", JG_EVENT_SEVERITY_INFO},
        {"warning", JG_EVENT_SEVERITY_WARNING},
        {"error", JG_EVENT_SEVERITY_ERROR},
        {"critical", JG_EVENT_SEVERITY_CRITICAL},
    };

    for (size_t index = 0U; index < sizeof(values) / sizeof(values[0U]);
         ++index) {
        if (strlen(values[index].name) == text_size &&
            memcmp(values[index].name, text, text_size) == 0) {
            *severity = values[index].severity;
            return true;
        }
    }
    return false;
}

/** @brief Validate one bounded external event identifier. */
static bool event_identifier_valid(const char *text, size_t text_size)
{
    if (text == NULL || text_size == 0U || text_size > JG_EVENT_COMPONENT_MAX) {
        return false;
    }
    for (size_t index = 0U; index < text_size; ++index) {
        const char character = text[index];

        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_' ||
              character == '-' || character == '.')) {
            return false;
        }
    }
    return true;
}

/** @brief Convert one immutable operational event to public JSON. */
static json_t *event_json(const struct jg_event_record *record)
{
    const char *severity = event_severity_name(record->severity);
    json_error_t error;
    json_t *body = json_object();
    json_t *details =
        json_loads(record->details, JSON_REJECT_DUPLICATES, &error);

    if (severity == NULL || body == NULL || !json_is_object(details) ||
        json_object_set_new(body, "id", json_integer((json_int_t)record->id)) !=
            0 ||
        json_object_set_new(body, "occurred_at",
                            json_integer((json_int_t)record->occurred_at)) !=
            0 ||
        json_object_set_new(body, "severity", json_string(severity)) != 0 ||
        json_object_set_new(body, "component",
                            json_string(record->component)) != 0 ||
        json_object_set_new(body, "code", json_string(record->code)) != 0 ||
        json_object_set_new(body, "message", json_string(record->message)) !=
            0 ||
        json_object_set(body, "details", details) != 0) {
        json_decref(details);
        json_decref(body);
        return NULL;
    }
    json_decref(details);
    return body;
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

/** @brief Parse stable operational-event pagination and exact filters. */
static int parse_event_query(const char *query,
                             struct jg_event_filter *filter,
                             char component[JG_EVENT_COMPONENT_MAX + 1U],
                             size_t *limit)
{
    const char *cursor = query;
    bool have_after_id = false;
    bool have_limit = false;
    bool have_severity = false;
    bool have_component = false;
    int result = 0;

    *filter = (struct jg_event_filter){
        .severity = JG_EVENT_SEVERITY_ANY,
    };
    component[0U] = '\0';
    *limit = JG_EVENT_PAGE_MAX < 50U ? JG_EVENT_PAGE_MAX : 50U;
    while (result == 0 && cursor != NULL && *cursor != '\0') {
        const char *end = strchr(cursor, '&');
        const char *equals = strchr(cursor, '=');
        const size_t field_size =
            end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        const size_t name_size =
            equals == NULL ? field_size : (size_t)(equals - cursor);
        const char *value =
            equals == NULL || name_size >= field_size ? NULL : equals + 1;
        const size_t value_size =
            value == NULL ? 0U : field_size - name_size - 1U;
        uint64_t parsed = 0U;

        if (equals == NULL || name_size == 0U || value_size == 0U ||
            name_size >= field_size) {
            result = -EINVAL;
        } else if (name_size == sizeof("after_id") - 1U &&
                   memcmp(cursor, "after_id", name_size) == 0 &&
                   !have_after_id) {
            result = parse_decimal(value, value_size, (uint64_t)INT64_MAX,
                                   &filter->after_id);
            have_after_id = result == 0;
        } else if (name_size == sizeof("limit") - 1U &&
                   memcmp(cursor, "limit", name_size) == 0 && !have_limit) {
            result =
                parse_decimal(value, value_size, JG_EVENT_PAGE_MAX, &parsed);
            if (result == 0 && parsed > 0U) {
                *limit = (size_t)parsed;
                have_limit = true;
            } else {
                result = -EINVAL;
            }
        } else if (name_size == sizeof("severity") - 1U &&
                   memcmp(cursor, "severity", name_size) == 0 &&
                   !have_severity &&
                   parse_event_severity(value, value_size, &filter->severity)) {
            have_severity = true;
        } else if (name_size == sizeof("component") - 1U &&
                   memcmp(cursor, "component", name_size) == 0 &&
                   !have_component &&
                   event_identifier_valid(value, value_size)) {
            (void)memcpy(component, value, value_size);
            component[value_size] = '\0';
            filter->component = component;
            have_component = true;
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

/** @brief Append one authenticated configuration reload outcome. */
static int append_configuration_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    int operation_result,
    uint64_t previous_generation,
    const struct jg_daemon_configuration_status *status,
    uint64_t now)
{
    char source_address[INET6_ADDRSTRLEN];
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (details == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL) {
        result = details == NULL ? -ENOMEM : -EINVAL;
    }
    if (result == 0 &&
        (json_object_set_new(details, "operation_result",
                             json_integer(operation_result)) != 0 ||
         json_object_set_new(details, "restart_required",
                             json_boolean(operation_result == 0 &&
                                          status->restart_required)) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source_address,
            .action = "configuration.reload",
            .object_type = "runtime_configuration",
            .object_id = "active",
            .details = encoded,
            .has_previous_revision = true,
            .previous_revision = previous_generation,
            .has_new_revision = operation_result == 0,
            .new_revision =
                operation_result == 0 ? status->policy_generation : 0U,
            .success = operation_result == 0,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one successful diagnostic archive creation event. */
static int append_diagnostic_audit(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   const struct authenticated_actor *actor,
                                   const char *filename,
                                   const char *checksum,
                                   size_t archive_size,
                                   uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL) {
        result = -EINVAL;
    }
    if (result == 0 &&
        (details == NULL ||
         json_object_set_new(details, "checksum_sha256",
                             json_string(checksum)) != 0 ||
         json_object_set_new(details, "size_bytes",
                             json_integer((json_int_t)archive_size)) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source,
            .action = "diagnostics.create",
            .object_type = "diagnostic_archive",
            .object_id = filename,
            .details = encoded,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one accepted appliance lifecycle action. */
static int append_system_audit(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               const struct authenticated_actor *actor,
                               const char *action,
                               uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    const struct jg_audit_event event = {
        .occurred_at = now,
        .actor_type = actor_audit_type(actor),
        .has_actor_id = actor_has_identifier(actor),
        .actor_id = actor->actor_id,
        .source = source,
        .action = action,
        .object_type = "appliance",
        .object_id = NULL,
        .details = "{\"confirmed\":true}",
        .success = true,
        .request_id = request->request_id,
    };

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL) {
        return -EINVAL;
    }
    return jg_database_audit_append(management->database, &event, NULL);
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

/** @brief Attach one borrowed child object and preserve caller ownership. */
static int set_object(json_t *parent, const char *name, json_t *child)
{
    return json_object_set(parent, name, child) == 0 ? 0 : -ENOMEM;
}

/** @brief Serialize every current packet-runtime counter for the status API. */
static json_t *status_body(const struct jg_daemon_runtime_stats *stats)
{
    json_t *body = json_object();
    json_t *queues = json_object();
    json_t *dataplane = json_object();
    json_t *fragments = json_object();
    json_t *streams = json_object();
    json_t *output = json_object();
    int result = 0;

    if (body == NULL || queues == NULL || dataplane == NULL ||
        fragments == NULL || streams == NULL || output == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "ready", json_true()) != 0 ||
         set_counter(body, "policy_generation", stats->policy_generation) !=
             0 ||
         set_counter(queues, "packets", stats->queues.packets) != 0 ||
         set_counter(queues, "accepted", stats->queues.accepted) != 0 ||
         set_counter(queues, "dropped", stats->queues.dropped) != 0 ||
         set_counter(queues, "malformed", stats->queues.malformed) != 0 ||
         set_counter(queues, "overflows", stats->queues.overflows) != 0 ||
         set_counter(queues, "message_errors", stats->queues.message_errors) !=
             0 ||
         set_counter(queues, "verdict_errors", stats->queues.verdict_errors) !=
             0)) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        (set_counter(dataplane, "packets", stats->dataplane.packets) != 0 ||
         set_counter(dataplane, "accepted", stats->dataplane.accepted) != 0 ||
         set_counter(dataplane, "blocked", stats->dataplane.blocked) != 0 ||
         set_counter(dataplane, "malformed", stats->dataplane.malformed) != 0 ||
         set_counter(dataplane, "fragments", stats->dataplane.fragments) != 0 ||
         set_counter(dataplane, "streams", stats->dataplane.streams) != 0 ||
         set_counter(dataplane, "tcp_resets", stats->dataplane.tcp_resets) !=
             0 ||
         set_counter(dataplane, "internal_errors",
                     stats->dataplane.internal_errors) != 0 ||
         set_counter(dataplane, "sni_inspected",
                     stats->dataplane.sni_inspected) != 0 ||
         set_counter(dataplane, "sni_encrypted_or_unavailable",
                     stats->dataplane.sni_encrypted_or_unavailable) != 0 ||
         set_counter(dataplane, "dns_dropped", stats->dataplane.dns_dropped) !=
             0 ||
         set_counter(dataplane, "dns_refused", stats->dataplane.dns_refused) !=
             0 ||
         set_counter(dataplane, "dns_nxdomain",
                     stats->dataplane.dns_nxdomain) != 0 ||
         set_counter(dataplane, "dns_sinkholed",
                     stats->dataplane.dns_sinkholed) != 0)) {
        result = -EOVERFLOW;
    }
    if (result == 0 &&
        (set_counter(fragments, "stored", stats->fragments.stored) != 0 ||
         set_counter(fragments, "duplicates", stats->fragments.duplicates) !=
             0 ||
         set_counter(fragments, "completed", stats->fragments.completed) != 0 ||
         set_counter(fragments, "malformed", stats->fragments.malformed) != 0 ||
         set_counter(fragments, "overlaps", stats->fragments.overlaps) != 0 ||
         set_counter(fragments, "exhausted", stats->fragments.exhausted) != 0 ||
         set_counter(fragments, "timeouts", stats->fragments.timeouts) != 0 ||
         set_counter(streams, "buffered", stats->tcp_streams.buffered) != 0 ||
         set_counter(streams, "duplicates", stats->tcp_streams.duplicates) !=
             0 ||
         set_counter(streams, "messages", stats->tcp_streams.messages) != 0 ||
         set_counter(streams, "closed", stats->tcp_streams.closed) != 0 ||
         set_counter(streams, "malformed", stats->tcp_streams.malformed) != 0 ||
         set_counter(streams, "conflicts", stats->tcp_streams.conflicts) != 0 ||
         set_counter(streams, "exhausted", stats->tcp_streams.exhausted) != 0 ||
         set_counter(streams, "timeouts", stats->tcp_streams.timeouts) != 0 ||
         set_counter(output, "sent", stats->output.sent) != 0 ||
         set_counter(output, "errors", stats->output.errors) != 0)) {
        result = -EOVERFLOW;
    }
    if (result == 0 && (set_object(body, "queues", queues) != 0 ||
                        set_object(body, "dataplane", dataplane) != 0 ||
                        set_object(body, "fragments", fragments) != 0 ||
                        set_object(body, "tcp_streams", streams) != 0 ||
                        set_object(body, "output", output) != 0)) {
        result = -ENOMEM;
    }
    json_decref(output);
    json_decref(streams);
    json_decref(fragments);
    json_decref(dataplane);
    json_decref(queues);
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Return authenticated daemon readiness and packet counters. */
static int handle_status(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    struct jg_daemon_runtime_stats stats;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The status request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL ||
        jg_daemon_runtime_get_stats(management->runtime, &stats) != 0) {
        return respond_error(503, "status_unavailable",
                             "Runtime status is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    body = status_body(&stats);
    if (body == NULL) {
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Encode the persistent policy-publication relationship. */
static json_t *policy_sync_health_json(
    const struct jg_database_policy_sync *sync,
    bool available)
{
    json_t *body = json_object();
    int result = 0;

    if (body == NULL) {
        return NULL;
    }
    if (json_object_set_new(body, "available", json_boolean(available)) != 0 ||
        json_object_set_new(
            body, "synchronized",
            json_boolean(available && sync->desired_revision ==
                                          sync->applied_revision)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && available) {
        if (set_counter(body, "desired_revision", sync->desired_revision) !=
                0 ||
            set_counter(body, "applied_revision", sync->applied_revision) !=
                0 ||
            json_object_set_new(
                body, "last_attempt_at",
                sync->last_attempt_at == 0U
                    ? json_null()
                    : json_integer((json_int_t)sync->last_attempt_at)) != 0 ||
            json_object_set_new(body, "last_error",
                                sync->last_error[0U] == '\0'
                                    ? json_null()
                                    : json_string(sync->last_error)) != 0) {
            result = -ENOMEM;
        }
    } else if (result == 0 &&
               (json_object_set_new(body, "desired_revision", json_null()) !=
                    0 ||
                json_object_set_new(body, "applied_revision", json_null()) !=
                    0 ||
                json_object_set_new(body, "last_attempt_at", json_null()) !=
                    0 ||
                json_object_set_new(body, "last_error", json_null()) != 0)) {
        result = -ENOMEM;
    }
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Encode management consistency and mutation availability. */
static json_t *management_health_json(
    uint32_t reasons,
    const struct jg_database_policy_sync *sync,
    bool policy_available,
    bool restore_in_progress)
{
    json_t *body = json_object();
    json_t *items = json_array();
    json_t *policy = policy_sync_health_json(sync, policy_available);
    int result = 0;

    if (body == NULL || items == NULL || policy == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (reasons & MANAGEMENT_DEGRADED_DATABASE_ROLLBACK) != 0U &&
        json_array_append_new(items, json_string("database_rollback")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (reasons & MANAGEMENT_DEGRADED_EXTERNAL_RECOVERY) != 0U &&
        json_array_append_new(items, json_string("external_recovery")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && (reasons & MANAGEMENT_DEGRADED_POLICY_SYNC) != 0U &&
        json_array_append_new(items, json_string("policy_sync")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "available", json_true()) != 0 ||
         json_object_set_new(body, "degraded", json_boolean(reasons != 0U)) !=
             0 ||
         json_object_set_new(
             body, "mutations_allowed",
             json_boolean(reasons == 0U && !restore_in_progress)) != 0 ||
         json_object_set_new(body, "restore_in_progress",
                             json_boolean(restore_in_progress)) != 0 ||
         json_object_set(body, "reasons", items) != 0 ||
         set_object(body, "policy", policy) != 0)) {
        result = -ENOMEM;
    }
    json_decref(policy);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Return authenticated management, daemon, and helper health. */
static int handle_health(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    struct jg_daemon_runtime_stats stats;
    struct jg_database_policy_sync policy_sync = {0};
    struct jg_network_state network_state;
    json_t *body = NULL;
    json_t *management_state = NULL;
    json_t *daemon = NULL;
    json_t *network = NULL;
    uint32_t degraded_reasons = 0U;
    bool daemon_available = false;
    bool network_available = false;
    bool policy_available = false;
    bool restore_in_progress = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The health request is not valid.",
                             request->request_id, output, output_size, written);
    }
    daemon_available =
        management->runtime != NULL &&
        jg_daemon_runtime_get_stats(management->runtime, &stats) == 0;
    network_available = jg_netd_client_state(&network_state) == 0;
    policy_available =
        jg_database_policy_sync_load(management->database, &policy_sync) == 0;
    if (!policy_available ||
        policy_sync.desired_revision != policy_sync.applied_revision) {
        mark_management_degraded(
            management, MANAGEMENT_DEGRADED_POLICY_SYNC,
            "management.policy_unsynchronized",
            "Persistent policy is not synchronized with the runtime");
    }
    degraded_reasons = management_degraded_reasons(management);
    restore_in_progress = management_restore_in_progress(management);
    body = json_object();
    management_state = management_health_json(
        degraded_reasons, &policy_sync, policy_available, restore_in_progress);
    daemon = json_object();
    network = json_object();
    if (body == NULL || management_state == NULL || daemon == NULL ||
        network == NULL ||
        json_object_set_new(body, "healthy",
                            json_boolean(degraded_reasons == 0U &&
                                         daemon_available &&
                                         network_available)) != 0 ||
        json_object_set_new(daemon, "available",
                            json_boolean(daemon_available)) != 0 ||
        json_object_set_new(network, "available",
                            json_boolean(network_available)) != 0 ||
        (daemon_available && set_counter(daemon, "policy_generation",
                                         stats.policy_generation) != 0) ||
        (network_available &&
         (json_object_set_new(network, "configured",
                              json_boolean(network_state.has_confirmed)) != 0 ||
          json_object_set_new(network, "pending",
                              json_boolean(network_state.pending)) != 0)) ||
        set_object(body, "management", management_state) != 0 ||
        set_object(body, "daemon", daemon) != 0 ||
        set_object(body, "network", network) != 0) {
        result = -ENOMEM;
    }
    json_decref(network);
    json_decref(daemon);
    json_decref(management_state);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return authenticated Prometheus text for the current runtime. */
static int handle_metrics(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    static const char content_type[] =
        "text/plain; version=0.0.4; charset=utf-8";
    struct authenticated_actor actor;
    struct jg_daemon_runtime_stats stats;
    char placeholder = '\0';
    char *metrics = NULL;
    size_t metrics_size = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_METRICS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The metrics request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL ||
        jg_daemon_runtime_get_stats(management->runtime, &stats) != 0) {
        return respond_error(503, "metrics_unavailable",
                             "Runtime metrics are temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = jg_metrics_render(&stats, &placeholder, 0U, &metrics_size);
    if (result != -ENOSPC || metrics_size == 0U ||
        metrics_size >= JG_IPC_MAX_BODY_SIZE / 2U) {
        return respond_error(500, "metrics_failure",
                             "Runtime metrics could not be rendered.",
                             request->request_id, output, output_size, written);
    }
    metrics = malloc(metrics_size + 1U);
    if (metrics == NULL) {
        return -ENOMEM;
    }
    result =
        jg_metrics_render(&stats, metrics, metrics_size + 1U, &metrics_size);
    if (result == 0) {
        result = encode_text_response(200, content_type, metrics, metrics_size,
                                      output, output_size, written);
    }
    free(metrics);
    return result;
}

/** @brief Validate or atomically reload persistent runtime configuration. */
static int handle_configuration(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                uint64_t now,
                                bool reload,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written)
{
    struct authenticated_actor actor;
    struct jg_daemon_configuration_status status;
    json_t *body = NULL;
    uint64_t previous_generation = 0U;
    int audit_result = 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_OPERATE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The configuration request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "runtime_unavailable",
                             "Runtime configuration is unavailable while the "
                             "service is offline.",
                             request->request_id, output, output_size, written);
    }
    if (reload) {
        result = jg_daemon_runtime_get_policy_generation(management->runtime,
                                                         &previous_generation);
        if (result == 0) {
            result = jg_daemon_runtime_reload_configuration(management->runtime,
                                                            &status);
        }
        audit_result = append_configuration_audit(
            management, request, remote, &actor, result, previous_generation,
            &status, now);
        refresh_policy_sync_health(management);
        if (audit_result != 0) {
            return respond_error(
                500, "audit_failure",
                "The configuration reload could not be audited.",
                request->request_id, output, output_size, written);
        }
    } else {
        result = jg_daemon_runtime_validate_configuration(management->runtime,
                                                          &status);
    }
    if (result != 0) {
        if (result == -EOVERFLOW || result == -EBUSY) {
            return respond_error(
                409, "configuration_conflict",
                "The persistent configuration cannot be processed now.",
                request->request_id, output, output_size, written);
        }
        if (result == -EINVAL || result == -ERANGE || result == -EILSEQ ||
            result == -EPROTONOSUPPORT) {
            return respond_error(
                422, "configuration_invalid",
                "The persistent configuration did not pass validation.",
                request->request_id, output, output_size, written);
        }
        return respond_error(
            503, "configuration_unavailable",
            "The persistent configuration could not be validated.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "validated", json_true()) != 0 ||
        json_object_set_new(body, "reloaded", json_boolean(reload)) != 0 ||
        json_object_set_new(
            body, "network_revision",
            json_integer((json_int_t)status.network_revision)) != 0 ||
        json_object_set_new(
            body, "policy_generation",
            json_integer((json_int_t)status.policy_generation)) != 0 ||
        json_object_set_new(
            body, "domain_rule_count",
            json_integer((json_int_t)status.domain_rule_count)) != 0 ||
        json_object_set_new(
            body, "destination_rule_count",
            json_integer((json_int_t)status.destination_rule_count)) != 0 ||
        json_object_set_new(body, "restart_required",
                            json_boolean(status.restart_required)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Authorize, audit, and defer one appliance lifecycle action. */
static int handle_system_action(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                uint64_t now,
                                enum jg_system_action action,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written)
{
    static const char *const fields[] = {
        "confirm",
    };
    struct authenticated_actor actor;
    const char *action_name = NULL;
    json_t *body = NULL;
    bool confirmed = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SYSTEM_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        json_object_size(request->body) != 1U ||
        !required_boolean(request->body, "confirm", &confirmed) || !confirmed ||
        action < JG_SYSTEM_ACTION_RESTART ||
        action > JG_SYSTEM_ACTION_POWEROFF) {
        return respond_error(
            400, "confirmation_required",
            "The lifecycle action requires an exact explicit confirmation.",
            request->request_id, output, output_size, written);
    }
    if (management->pending_system_action != JG_SYSTEM_ACTION_NONE) {
        return respond_error(409, "system_action_pending",
                             "Another lifecycle action is already pending.",
                             request->request_id, output, output_size, written);
    }
    action_name = action == JG_SYSTEM_ACTION_RESTART
                      ? "service.restart"
                      : (action == JG_SYSTEM_ACTION_REBOOT ? "system.reboot"
                                                           : "system.shutdown");
    result = append_system_audit(management, request, remote, &actor,
                                 action_name, now);
    if (result != 0) {
        return respond_error(500, "audit_failure",
                             "The lifecycle action could not be audited.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "accepted", json_true()) != 0 ||
        json_object_set_new(body, "action", json_string(action_name)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    result = encode_response(202, body, NULL, output, output_size, written);
    if (result == 0) {
        management->pending_system_action = action;
    }
    return result;
}

/** @brief Format one UTC diagnostic archive filename. */
static int diagnostic_filename(
    uint64_t now,
    char filename[MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE])
{
    time_t timestamp = 0;
    struct tm utc;

    if (now > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    timestamp = (time_t)now;
    if ((uint64_t)timestamp != now || gmtime_r(&timestamp, &utc) == NULL ||
        strftime(filename, MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE,
                 "janusgate-diagnostics-%Y%m%dT%H%M%SZ.tar.gz", &utc) == 0U) {
        return -EOVERFLOW;
    }
    return 0;
}

/** @brief Create and return one authenticated diagnostic archive job. */
static int execute_diagnostics_create_job(struct jg_management *management,
                                          const struct management_job *job,
                                          uint8_t *output,
                                          size_t output_size,
                                          size_t *written)
{
    const struct management_request request_value = {
        .request_id = job->request_id,
    };
    const struct management_request *request = &request_value;
    const struct remote_address *remote = &job->remote;
    const struct authenticated_actor *actor = &job->actor;
    uint8_t checksum[crypto_hash_sha256_BYTES];
    char checksum_text[crypto_hash_sha256_BYTES * 2U + 1U];
    char filename[MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE];
    uint8_t *archive = NULL;
    char *encoded = NULL;
    json_t *body = NULL;
    size_t archive_size = 0U;
    size_t encoded_size = 0U;
    const uint64_t now = job->started_at;
    int result = 0;

    if (management->runtime == NULL) {
        return respond_error(
            503, "runtime_unavailable",
            "Diagnostics are unavailable while the service is offline.",
            request->request_id, output, output_size, written);
    }
    result =
        jg_diagnostic_bundle_create(management->database, management->runtime,
                                    now, &archive, &archive_size);
    if (result != 0) {
        return respond_error(
            result == -EMSGSIZE ? 413 : 500,
            result == -EMSGSIZE ? "diagnostic_too_large"
                                : "diagnostic_create_failed",
            result == -EMSGSIZE
                ? "The diagnostic archive exceeds its configured limit."
                : "The diagnostic archive could not be created.",
            request->request_id, output, output_size, written);
    }
    if (archive_size > MANAGEMENT_DIAGNOSTIC_ARCHIVE_SIZE_MAX) {
        jg_diagnostic_archive_destroy(archive);
        return respond_error(
            413, "diagnostic_too_large",
            "The diagnostic archive exceeds its management transfer limit.",
            request->request_id, output, output_size, written);
    }
    encoded_size =
        sodium_base64_encoded_len(archive_size, sodium_base64_VARIANT_ORIGINAL);
    if (diagnostic_filename(now, filename) != 0 || encoded_size == 0U ||
        encoded_size > JG_IPC_MAX_BODY_SIZE) {
        jg_diagnostic_archive_destroy(archive);
        return respond_error(500, "diagnostic_create_failed",
                             "The diagnostic archive could not be encoded.",
                             request->request_id, output, output_size, written);
    }
    encoded = malloc(encoded_size);
    if (encoded == NULL) {
        jg_diagnostic_archive_destroy(archive);
        return -ENOMEM;
    }
    (void)crypto_hash_sha256(checksum, archive, archive_size);
    (void)sodium_bin2hex(checksum_text, sizeof(checksum_text), checksum,
                         sizeof(checksum));
    if (sodium_bin2base64(encoded, encoded_size, archive, archive_size,
                          sodium_base64_VARIANT_ORIGINAL) == NULL) {
        sodium_memzero(checksum, sizeof(checksum));
        jg_diagnostic_archive_destroy(archive);
        free(encoded);
        return respond_error(500, "diagnostic_create_failed",
                             "The diagnostic archive could not be encoded.",
                             request->request_id, output, output_size, written);
    }
    result =
        append_diagnostic_audit(management, request, remote, actor, filename,
                                checksum_text, archive_size, now);
    if (result != 0) {
        sodium_memzero(checksum, sizeof(checksum));
        jg_diagnostic_archive_destroy(archive);
        free(encoded);
        return respond_error(500, "audit_failure",
                             "The diagnostic archive could not be audited.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "filename", json_string(filename)) != 0 ||
        json_object_set_new(body, "media_type",
                            json_string("application/gzip")) != 0 ||
        json_object_set_new(body, "size_bytes",
                            json_integer((json_int_t)archive_size)) != 0 ||
        json_object_set_new(body, "checksum_sha256",
                            json_string(checksum_text)) != 0 ||
        json_object_set_new(body, "data_base64", json_string(encoded)) != 0) {
        result = -ENOMEM;
    }
    sodium_memzero(checksum, sizeof(checksum));
    jg_diagnostic_archive_destroy(archive);
    free(encoded);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Queue one authenticated diagnostic archive creation. */
static int handle_diagnostics_create(struct jg_management *management,
                                     const struct management_request *request,
                                     const struct remote_address *remote,
                                     uint64_t now,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *written)
{
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_OPERATE,
        .kind = MANAGEMENT_JOB_DIAGNOSTICS_CREATE,
    };
    uint64_t job_id = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_OPERATE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The diagnostic request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(
            503, "runtime_unavailable",
            "Diagnostics are unavailable while the service is offline.",
            request->request_id, output, output_size, written);
    }
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The diagnostic archive could not be queued.",
            output, output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
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

/** @brief Return one authenticated filtered page of operational events. */
static int handle_events_list(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct jg_event_filter filter;
    struct jg_event_record *records = NULL;
    char component[JG_EVENT_COMPONENT_MAX + 1U];
    json_t *body = NULL;
    json_t *items = NULL;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_EVENTS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_event_query(request->query, &filter, component, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The event filters or pagination are not valid.",
                             request->request_id, output, output_size, written);
    }
    records = calloc(limit, sizeof(*records));
    if (records == NULL) {
        return -ENOMEM;
    }
    result = jg_database_event_list(management->database, &filter, records,
                                    limit, &count, &has_more);
    if (result != 0) {
        free(records);
        return respond_error(500, "events_unavailable",
                             "The operational events could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = event_json(&records[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)filter.after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set_new(
             body, "severity",
             filter.severity == JG_EVENT_SEVERITY_ANY
                 ? json_null()
                 : json_string(event_severity_name(filter.severity))) != 0 ||
         json_object_set_new(body, "component",
                             filter.component == NULL
                                 ? json_null()
                                 : json_string(filter.component)) != 0 ||
         json_object_set(body, "events", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)records[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(records);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return one authenticated page of immutable audit records. */
static int handle_audit_list(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    struct authenticated_actor actor;
    struct jg_audit_record *records = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t offset = 0U;
    uint64_t total = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_AUDIT_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "offset", JG_AUDIT_PAGE_MAX, &offset,
                         &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The audit pagination parameters are not valid.",
                             request->request_id, output, output_size, written);
    }
    records = calloc(limit, sizeof(*records));
    if (records == NULL) {
        return -ENOMEM;
    }
    result = jg_database_audit_list(management->database, offset, records,
                                    limit, &count, &total);
    if (result != 0) {
        free(records);
        return respond_error(500, "audit_unavailable",
                             "The audit records could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = audit_json(&records[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "offset",
                             json_integer((json_int_t)offset)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "total", json_integer((json_int_t)total)) !=
             0 ||
         json_object_set(body, "events", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        const uint64_t next = offset + (uint64_t)count;
        json_t *next_value = count > 0U && next < total
                                 ? json_integer((json_int_t)next)
                                 : json_null();

        if (json_object_set_new(body, "next_offset", next_value) != 0) {
            result = -ENOMEM;
        }
    }
    free(records);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Verify and report the complete authenticated audit chain. */
static int handle_audit_verify(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    struct authenticated_actor actor;
    struct jg_audit_verification verification;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_AUDIT_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The audit verification request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_audit_verify(management->database, &verification);
    if (result != 0) {
        return respond_error(500, "audit_verification_failed",
                             "The audit chain could not be verified.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "valid", json_boolean(verification.valid)) !=
            0 ||
        json_object_set_new(
            body, "records_inspected",
            json_integer((json_int_t)verification.records_inspected)) != 0 ||
        json_object_set_new(
            body, "first_invalid_id",
            verification.first_invalid_id == 0U
                ? json_null()
                : json_integer((json_int_t)verification.first_invalid_id)) !=
            0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
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
        "/api/v1/policies/simulate",
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
           collection_path_identifier(path, "/api/v1/jobs/", "", &identifier) ||
           collection_path_identifier(path, "/api/v1/mtls/mappings/", "",
                                      &identifier) ||
           collection_path_identifier(path, "/api/v1/policies/destinations/",
                                      "", &identifier) ||
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
    uint64_t job_id = 0U;
    uint64_t mapping_id = 0U;
    uint64_t source_id = 0U;
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
    if (strcmp(request->path, "/api/v1/policies/destinations") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_destination_rules_list(management, request, remote, now,
                                             output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/policies/destinations") == 0 && post) {
        return handle_destination_rule_create(management, request, remote, now,
                                              output, output_size, written);
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
    free(management->health);
    management->health = NULL;
    sodium_memzero(management, sizeof(*management));
    free(management);
}
