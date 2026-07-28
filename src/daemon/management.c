/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "management.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include <sodium.h>

#include "daemon_runtime.h"
#include "janusgate/access.h"
#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/ipc.h"
#include "metrics.h"

/** Absolute authenticated web-session lifetime. */
#define MANAGEMENT_SESSION_LIFETIME 43200U

/** Authenticated web-session inactivity timeout. */
#define MANAGEMENT_SESSION_INACTIVITY 1800U

/** Maximum internal management request bytes. */
#define MANAGEMENT_REQUEST_SIZE_MAX 65536U

/** Maximum request identifier bytes excluding its terminator. */
#define MANAGEMENT_REQUEST_ID_MAX 64U

/** Maximum management route bytes excluding its terminator. */
#define MANAGEMENT_PATH_MAX 256U

/** Maximum management query bytes excluding its terminator. */
#define MANAGEMENT_QUERY_MAX 256U

/** Maximum distinct API-token rate windows retained in memory. */
#define MANAGEMENT_TOKEN_RATE_SLOT_COUNT 256U

/** One bounded fixed-window token request counter. */
struct token_rate_slot {
    uint64_t token_id;
    uint64_t minute;
    uint64_t last_request;
    uint32_t requests;
};

/** Complete borrowed and secret state for serialized request processing. */
struct jg_management {
    struct jg_database *database;
    struct jg_daemon_runtime *runtime;
    struct jg_auth_password_policy password_policy;
    struct token_rate_slot token_rates[MANAGEMENT_TOKEN_RATE_SLOT_COUNT];
    uint8_t totp_key[JG_AUTH_TOTP_KEY_SIZE];
};

/** Validated borrowed view of one internal JSON request envelope. */
struct management_request {
    const char *request_id;
    const char *method;
    const char *path;
    const char *query;
    const char *host;
    const char *origin;
    const char *remote_address;
    const char *session;
    const char *csrf;
    const char *bearer;
    json_t *body;
};

/** Parsed network-order remote management address. */
struct remote_address {
    enum jg_policy_address_family family;
    uint8_t address[16U];
};

/** Optional session-cookie instructions returned to the HTTPS process. */
struct session_result {
    const char *set_session;
    bool clear_session;
};

/** Authenticated session or token actor used for backend authorization. */
struct authenticated_actor {
    struct jg_account_identity identity;
    uint64_t actor_id;
    bool token;
};

/** @brief Return a bounded string length or one past the maximum. */
static size_t bounded_length(const char *text, size_t maximum)
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
                         struct jg_daemon_runtime *runtime,
                         struct jg_management **management)
{
    struct jg_management *created = NULL;
    int result = 0;

    if (management == NULL) {
        return -EINVAL;
    }
    *management = NULL;
    if (database == NULL || totp_key_path == NULL) {
        return -EINVAL;
    }
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    created->database = database;
    created->runtime = runtime;
    jg_auth_password_policy_default(&created->password_policy);
    result = load_totp_key(totp_key_path, created->totp_key);
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
static bool fields_allowed(json_t *object,
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
static const char *required_string(const json_t *object,
                                   const char *name,
                                   size_t minimum,
                                   size_t maximum)
{
    json_t *value = json_object_get(object, name);
    const char *text = json_is_string(value) ? json_string_value(value) : NULL;
    const size_t length = bounded_length(text, maximum);

    return length >= minimum && length <= maximum ? text : NULL;
}

/** @brief Read an optional bounded JSON string field. */
static const char *optional_string(const json_t *object,
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
    return bounded_length(text, maximum) <= maximum ? text : NULL;
}

/** @brief Parse and validate one internal management request envelope. */
static int parse_request(const uint8_t *data,
                         size_t data_size,
                         json_t **root,
                         struct management_request *request)
{
    static const char *const fields[] = {
        "request_id",     "method",  "path", "query",  "host", "origin",
        "remote_address", "session", "csrf", "bearer", "body",
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
        request->body = json_object_get(parsed, "body");
        if (!request_id_valid(request->request_id) || request->method == NULL ||
            request->path == NULL || request->query == NULL ||
            !host_valid(request->host) || request->origin == NULL ||
            request->remote_address == NULL || request->session == NULL ||
            request->csrf == NULL || request->bearer == NULL ||
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

/** @brief Parse an exact numeric IPv4 or IPv6 remote address. */
static int parse_remote_address(const char *text, struct remote_address *remote)
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
static int hexadecimal_value(char character, uint8_t *value)
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

/** @brief Parse one exact colon-separated 48-bit MAC address. */
static int parse_mac_address(const char *text, uint8_t address[6U])
{
    uint8_t parsed[6U];

    if (text == NULL || strlen(text) != 17U) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < sizeof(parsed); ++index) {
        uint8_t high = 0U;
        uint8_t low = 0U;
        const size_t offset = index * 3U;

        if (hexadecimal_value(text[offset], &high) != 0 ||
            hexadecimal_value(text[offset + 1U], &low) != 0 ||
            (index + 1U < sizeof(parsed) && text[offset + 2U] != ':')) {
            return -EINVAL;
        }
        parsed[index] = (uint8_t)((high << 4U) | low);
    }
    (void)memcpy(address, parsed, sizeof(parsed));
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
static json_t *error_body(const char *code,
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
static int encode_response(int status,
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
static int respond_error(int status,
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

/** @brief Convert an authenticated identity to stable response fields. */
static json_t *identity_json(const struct jg_account_identity *identity)
{
    json_t *user = json_object();

    if (user == NULL ||
        json_object_set_new(user, "id",
                            json_integer((json_int_t)identity->user_id)) != 0 ||
        json_object_set_new(user, "username",
                            json_string(identity->username)) != 0 ||
        json_object_set_new(user, "permissions",
                            json_integer((json_int_t)identity->permissions)) !=
            0 ||
        json_object_set_new(user, "revision",
                            json_integer((json_int_t)identity->revision)) !=
            0 ||
        json_object_set_new(user, "force_password_change",
                            json_boolean(identity->force_password_change)) !=
            0 ||
        json_object_set_new(user, "totp_enabled",
                            json_boolean(identity->totp_enabled)) != 0) {
        json_decref(user);
        return NULL;
    }
    return user;
}

/** @brief Return the stable external name for one fixed backend role. */
static const char *role_name(enum jg_access_role role)
{
    switch (role) {
    case JG_ACCESS_ROLE_ADMINISTRATOR:
        return "administrator";
    case JG_ACCESS_ROLE_OPERATOR:
        return "operator";
    case JG_ACCESS_ROLE_AUDITOR:
        return "auditor";
    case JG_ACCESS_ROLE_NONE:
    default:
        return NULL;
    }
}

/** @brief Parse one exact fixed backend role name. */
static enum jg_access_role parse_role(const char *name)
{
    if (name == NULL) {
        return JG_ACCESS_ROLE_NONE;
    }
    if (strcmp(name, "administrator") == 0) {
        return JG_ACCESS_ROLE_ADMINISTRATOR;
    }
    if (strcmp(name, "operator") == 0) {
        return JG_ACCESS_ROLE_OPERATOR;
    }
    if (strcmp(name, "auditor") == 0) {
        return JG_ACCESS_ROLE_AUDITOR;
    }
    return JG_ACCESS_ROLE_NONE;
}

/** @brief Read one required JSON boolean. */
static bool required_boolean(const json_t *object,
                             const char *name,
                             bool *value)
{
    json_t *field = json_object_get(object, name);

    if (!json_is_boolean(field)) {
        return false;
    }
    *value = json_is_true(field);
    return true;
}

/** @brief Read one required positive JSON integer as an unsigned value. */
static bool required_identifier(const json_t *object,
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

/** @brief Add a timestamp or JSON null to one response object. */
static int set_optional_timestamp(json_t *object,
                                  const char *name,
                                  uint64_t value)
{
    return json_object_set_new(object, name,
                               value == 0U ? json_null()
                                           : json_integer((json_int_t)value));
}

/** @brief Convert one administrative user record to public JSON fields. */
static json_t *user_json(const struct jg_account_user *user)
{
    const char *role = role_name(user->role);
    json_t *body = json_object();

    if (role == NULL || body == NULL ||
        json_object_set_new(body, "id",
                            json_integer((json_int_t)user->user_id)) != 0 ||
        json_object_set_new(body, "username", json_string(user->username)) !=
            0 ||
        json_object_set_new(body, "role", json_string(role)) != 0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)user->revision)) != 0 ||
        json_object_set_new(body, "enabled", json_boolean(user->enabled)) !=
            0 ||
        json_object_set_new(body, "force_password_change",
                            json_boolean(user->force_password_change)) != 0 ||
        json_object_set_new(body, "totp_enabled",
                            json_boolean(user->totp_enabled)) != 0 ||
        json_object_set_new(body, "failed_logins",
                            json_integer((json_int_t)user->failed_logins)) !=
            0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)user->created_at)) != 0 ||
        json_object_set_new(
            body, "password_changed_at",
            json_integer((json_int_t)user->password_changed_at)) != 0 ||
        set_optional_timestamp(body, "last_login_at", user->last_login_at) !=
            0 ||
        set_optional_timestamp(body, "locked_until", user->locked_until) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Parse one bounded unsigned decimal text span. */
static int parse_decimal(const char *text,
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

/** @brief Read a required nullable nonnegative JSON timestamp. */
static bool required_optional_timestamp(const json_t *object,
                                        const char *name,
                                        uint64_t *value)
{
    json_t *field = json_object_get(object, name);
    const json_int_t number =
        json_is_integer(field) ? json_integer_value(field) : -1;

    if (json_is_null(field)) {
        *value = 0U;
        return true;
    }
    if (number <= 0) {
        return false;
    }
    *value = (uint64_t)number;
    return true;
}

/** @brief Parse one required nullable numeric IP prefix. */
static int parse_source_network(const json_t *object,
                                const char *name,
                                struct jg_account_token_config *config)
{
    json_t *field = json_object_get(object, name);
    const char *text = json_is_string(field) ? json_string_value(field) : NULL;
    char address[INET6_ADDRSTRLEN];
    const char *slash = text == NULL ? NULL : strrchr(text, '/');
    const size_t address_size =
        slash == NULL || text == NULL ? 0U : (size_t)(slash - text);
    uint64_t prefix = 0U;

    config->source_family = JG_POLICY_ADDRESS_NONE;
    config->source_prefix = 0U;
    (void)memset(config->source_address, 0, sizeof(config->source_address));
    if (json_is_null(field)) {
        return 0;
    }
    if (text == NULL || slash == NULL || address_size == 0U ||
        address_size >= sizeof(address) ||
        parse_decimal(slash + 1, strlen(slash + 1), 128U, &prefix) != 0) {
        return -EINVAL;
    }
    (void)memcpy(address, text, address_size);
    address[address_size] = '\0';
    if (prefix <= 32U &&
        inet_pton(AF_INET, address, config->source_address) == 1) {
        config->source_family = JG_POLICY_ADDRESS_IPV4;
    } else if (prefix <= 128U &&
               inet_pton(AF_INET6, address, config->source_address) == 1) {
        config->source_family = JG_POLICY_ADDRESS_IPV6;
    } else {
        return -EINVAL;
    }
    config->source_prefix = (uint8_t)prefix;
    return 0;
}

/** @brief Convert safe persistent API-token metadata to public JSON. */
static json_t *token_json(const struct jg_account_token_record *token)
{
    char scopes[JG_ACCESS_SCOPE_TEXT_MAX + 1U];
    char address[INET6_ADDRSTRLEN];
    char network[INET6_ADDRSTRLEN + 5U];
    json_t *body = json_object();
    int written = 0;
    int result =
        jg_access_scope_format(token->permissions, scopes, sizeof(scopes));

    network[0U] = '\0';
    if (result == 0 && token->source_family != JG_POLICY_ADDRESS_NONE) {
        const int family =
            token->source_family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6;

        if (inet_ntop(family, token->source_address, address,
                      sizeof(address)) == NULL) {
            result = -EINVAL;
        } else {
            written = snprintf(network, sizeof(network), "%s/%u", address,
                               token->source_prefix);
            if (written <= 0 || (size_t)written >= sizeof(network)) {
                result = -ENOSPC;
            }
        }
    }
    if (result != 0 || body == NULL ||
        json_object_set_new(body, "id",
                            json_integer((json_int_t)token->token_id)) != 0 ||
        json_object_set_new(body, "user_id",
                            json_integer((json_int_t)token->user_id)) != 0 ||
        json_object_set_new(body, "username", json_string(token->username)) !=
            0 ||
        json_object_set_new(body, "name", json_string(token->name)) != 0 ||
        json_object_set_new(body, "scopes", json_string(scopes)) != 0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)token->revision)) != 0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)token->created_at)) != 0 ||
        set_optional_timestamp(body, "expires_at", token->expires_at) != 0 ||
        set_optional_timestamp(body, "last_used_at", token->last_used_at) !=
            0 ||
        set_optional_timestamp(body, "revoked_at", token->revoked_at) != 0 ||
        json_object_set_new(body, "revoked",
                            json_boolean(token->revoked_at != 0U)) != 0 ||
        json_object_set_new(
            body, "requests_per_minute",
            json_integer((json_int_t)token->requests_per_minute)) != 0 ||
        json_object_set_new(body, "source_network",
                            network[0U] == '\0' ? json_null()
                                                : json_string(network)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
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

/** @brief Return the stable external name for one policy action. */
static const char *policy_effect_name(enum jg_policy_effect effect)
{
    switch (effect) {
    case JG_POLICY_ALLOW:
        return "allow";
    case JG_POLICY_BLOCK:
        return "block";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one policy source. */
static const char *policy_source_name(enum jg_policy_source source)
{
    switch (source) {
    case JG_POLICY_SOURCE_DEFAULT:
        return "default";
    case JG_POLICY_SOURCE_BLOCKLIST:
        return "blocklist";
    case JG_POLICY_SOURCE_EXPLICIT:
        return "explicit";
    case JG_POLICY_SOURCE_EMERGENCY:
        return "emergency";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one domain policy target. */
static const char *policy_target_name(enum jg_policy_domain_target target)
{
    switch (target) {
    case JG_POLICY_DOMAIN_DNS:
        return "dns";
    case JG_POLICY_DOMAIN_TLS_SNI:
        return "tls_sni";
    default:
        return NULL;
    }
}

/** @brief Return the stable external name for one policy scope. */
static const char *policy_scope_name(enum jg_policy_scope_type type)
{
    switch (type) {
    case JG_POLICY_SCOPE_GLOBAL:
        return "global";
    case JG_POLICY_SCOPE_MAC:
        return "mac";
    case JG_POLICY_SCOPE_IPV4:
        return "ipv4";
    case JG_POLICY_SCOPE_IPV6:
        return "ipv6";
    case JG_POLICY_SCOPE_VLAN:
        return "vlan";
    default:
        return NULL;
    }
}

/** @brief Convert one canonical client scope to public JSON. */
static json_t *policy_scope_json(const struct jg_policy_scope *scope)
{
    char address[INET6_ADDRSTRLEN];
    char mac[18U];
    const char *name = policy_scope_name(scope->type);
    json_t *body = json_object();
    int written = 0;
    int result = 0;

    if (name == NULL || body == NULL ||
        json_object_set_new(body, "type", json_string(name)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && scope->type == JG_POLICY_SCOPE_MAC) {
        written = snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                           scope->value.mac[0U], scope->value.mac[1U],
                           scope->value.mac[2U], scope->value.mac[3U],
                           scope->value.mac[4U], scope->value.mac[5U]);
        if (written != (int)(sizeof(mac) - 1U) ||
            json_object_set_new(body, "address", json_string(mac)) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && (scope->type == JG_POLICY_SCOPE_IPV4 ||
                        scope->type == JG_POLICY_SCOPE_IPV6)) {
        const int family =
            scope->type == JG_POLICY_SCOPE_IPV4 ? AF_INET : AF_INET6;

        if (inet_ntop(family, scope->value.network.address, address,
                      sizeof(address)) == NULL ||
            json_object_set_new(body, "address", json_string(address)) != 0 ||
            json_object_set_new(
                body, "prefix_length",
                json_integer((json_int_t)scope->value.network.prefix_length)) !=
                0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && scope->type == JG_POLICY_SCOPE_VLAN &&
        json_object_set_new(body, "vlan",
                            json_integer((json_int_t)scope->value.vlan_id)) !=
            0) {
        result = -ENOMEM;
    }
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert one persistent domain rule to public JSON. */
static json_t *domain_rule_json(const struct jg_database_domain_rule *rule)
{
    const char *effect = policy_effect_name(rule->effect);
    const char *source = policy_source_name(rule->source);
    const char *target = policy_target_name(rule->target);
    json_t *body = json_object();
    json_t *scope = policy_scope_json(&rule->scope);

    if (effect == NULL || source == NULL || target == NULL || body == NULL ||
        scope == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule->id)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)rule->revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)rule->updated_at)) != 0 ||
        json_object_set_new(body, "domain", json_string(rule->domain)) != 0 ||
        json_object_set_new(body, "include_subdomains",
                            json_boolean(rule->include_subdomains)) != 0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "target", json_string(target)) != 0 ||
        json_object_set_new(body, "attribution",
                            json_string(rule->attribution)) != 0 ||
        json_object_set_new(body, "category", json_string(rule->category)) !=
            0 ||
        json_object_set_new(body, "enabled", json_boolean(rule->enabled)) !=
            0 ||
        json_object_set(body, "scope", scope) != 0) {
        json_decref(scope);
        json_decref(body);
        return NULL;
    }
    json_decref(scope);
    return body;
}

/** @brief Return the stable external name for one transport selector. */
static const char *policy_transport_name(enum jg_policy_transport transport)
{
    switch (transport) {
    case JG_POLICY_TRANSPORT_ANY:
        return "any";
    case JG_POLICY_TRANSPORT_TCP:
        return "tcp";
    case JG_POLICY_TRANSPORT_UDP:
        return "udp";
    default:
        return NULL;
    }
}

/** @brief Convert one persistent destination rule to public JSON. */
static json_t *destination_rule_json(
    const struct jg_database_destination_rule *rule)
{
    char address[INET6_ADDRSTRLEN];
    const char *effect = policy_effect_name(rule->effect);
    const char *source = policy_source_name(rule->source);
    const char *transport = policy_transport_name(rule->transport);
    json_t *body = json_object();
    json_t *scope = policy_scope_json(&rule->scope);
    int result = 0;

    if (rule->has_address) {
        const int family =
            rule->address_family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6;

        if (inet_ntop(family, rule->address, address, sizeof(address)) ==
            NULL) {
            result = -EINVAL;
        }
    }
    if (result != 0 || effect == NULL || source == NULL || transport == NULL ||
        body == NULL || scope == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule->id)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)rule->revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)rule->updated_at)) != 0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "transport", json_string(transport)) != 0 ||
        json_object_set_new(body, "address",
                            rule->has_address ? json_string(address)
                                              : json_null()) != 0 ||
        json_object_set_new(body, "prefix_length",
                            rule->has_address
                                ? json_integer((json_int_t)rule->prefix_length)
                                : json_null()) != 0 ||
        json_object_set_new(body, "port",
                            rule->has_port
                                ? json_integer((json_int_t)rule->port)
                                : json_null()) != 0 ||
        json_object_set_new(body, "attribution",
                            json_string(rule->attribution)) != 0 ||
        json_object_set_new(body, "enabled", json_boolean(rule->enabled)) !=
            0 ||
        json_object_set(body, "scope", scope) != 0) {
        json_decref(scope);
        json_decref(body);
        return NULL;
    }
    json_decref(scope);
    return body;
}

/** @brief Parse one optional external domain policy target. */
static bool parse_policy_target(const char *text,
                                enum jg_policy_domain_target *target)
{
    if (text == NULL || target == NULL) {
        return false;
    }
    if (text[0U] == '\0' || strcmp(text, "dns") == 0) {
        *target = JG_POLICY_DOMAIN_DNS;
        return true;
    }
    if (strcmp(text, "tls_sni") == 0) {
        *target = JG_POLICY_DOMAIN_TLS_SNI;
        return true;
    }
    return false;
}

/** @brief Parse one external allow or block action. */
static bool parse_policy_effect(const char *text, enum jg_policy_effect *effect)
{
    if (text == NULL || effect == NULL) {
        return false;
    }
    if (strcmp(text, "allow") == 0) {
        *effect = JG_POLICY_ALLOW;
        return true;
    }
    if (strcmp(text, "block") == 0) {
        *effect = JG_POLICY_BLOCK;
        return true;
    }
    return false;
}

/** @brief Parse one strict domain-rule client scope object. */
static int parse_policy_scope(json_t *object, struct jg_policy_scope *scope)
{
    static const char *const global_fields[] = {"type"};
    static const char *const address_fields[] = {"type", "address"};
    static const char *const network_fields[] = {
        "type",
        "address",
        "prefix_length",
    };
    static const char *const vlan_fields[] = {"type", "vlan"};
    const char *type = NULL;
    const char *address = NULL;
    json_t *prefix_value = NULL;
    json_t *vlan_value = NULL;
    json_int_t number = -1;
    int family = AF_UNSPEC;

    (void)memset(scope, 0, sizeof(*scope));
    if (!json_is_object(object)) {
        return -EINVAL;
    }
    type = required_string(object, "type", 3U, 6U);
    if (type == NULL) {
        return -EINVAL;
    }
    if (strcmp(type, "global") == 0) {
        if (!fields_allowed(object, global_fields,
                            sizeof(global_fields) /
                                sizeof(global_fields[0U]))) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_GLOBAL;
        return 0;
    }
    if (strcmp(type, "mac") == 0) {
        address = required_string(object, "address", 17U, 17U);
        if (!fields_allowed(object, address_fields,
                            sizeof(address_fields) /
                                sizeof(address_fields[0U])) ||
            parse_mac_address(address, scope->value.mac) != 0) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_MAC;
        return 0;
    }
    if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv6") == 0) {
        address = required_string(object, "address", 2U, INET6_ADDRSTRLEN - 1U);
        prefix_value = json_object_get(object, "prefix_length");
        number = json_is_integer(prefix_value)
                     ? json_integer_value(prefix_value)
                     : -1;
        family = strcmp(type, "ipv4") == 0 ? AF_INET : AF_INET6;
        if (!fields_allowed(object, network_fields,
                            sizeof(network_fields) /
                                sizeof(network_fields[0U])) ||
            address == NULL || number < 0 ||
            number > (family == AF_INET ? 32 : 128) ||
            inet_pton(family, address, scope->value.network.address) != 1) {
            return -EINVAL;
        }
        scope->type =
            family == AF_INET ? JG_POLICY_SCOPE_IPV4 : JG_POLICY_SCOPE_IPV6;
        scope->value.network.prefix_length = (uint8_t)number;
        return 0;
    }
    if (strcmp(type, "vlan") == 0) {
        vlan_value = json_object_get(object, "vlan");
        number =
            json_is_integer(vlan_value) ? json_integer_value(vlan_value) : -1;
        if (!fields_allowed(object, vlan_fields,
                            sizeof(vlan_fields) / sizeof(vlan_fields[0U])) ||
            number < 0 || number > 4094) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_VLAN;
        scope->value.vlan_id = (uint16_t)number;
        return 0;
    }
    return -EINVAL;
}

/** @brief Parse one complete explicit domain-rule request body. */
static int parse_domain_rule_request(json_t *body,
                                     uint64_t rule_id,
                                     bool updating,
                                     struct jg_policy_rule_input *rule,
                                     bool *enabled,
                                     uint64_t *revision)
{
    static const char *const create_fields[] = {
        "domain", "include_subdomains", "action",  "target",
        "scope",  "attribution",        "enabled",
    };
    static const char *const update_fields[] = {
        "revision", "domain", "include_subdomains", "action",
        "target",   "scope",  "attribution",        "enabled",
    };
    const char *domain = required_string(body, "domain", 1U, 1024U);
    const char *action = required_string(body, "action", 5U, 5U);
    const char *target = required_string(body, "target", 3U, 7U);
    const char *attribution =
        required_string(body, "attribution", 1U, JG_POLICY_ATTRIBUTION_MAX);
    json_t *scope = json_object_get(body, "scope");
    int result = 0;

    (void)memset(rule, 0, sizeof(*rule));
    *revision = 0U;
    if ((updating &&
         !fields_allowed(body, update_fields,
                         sizeof(update_fields) / sizeof(update_fields[0U]))) ||
        (!updating &&
         !fields_allowed(body, create_fields,
                         sizeof(create_fields) / sizeof(create_fields[0U]))) ||
        domain == NULL || action == NULL || target == NULL ||
        attribution == NULL ||
        !required_boolean(body, "include_subdomains",
                          &rule->include_subdomains) ||
        !required_boolean(body, "enabled", enabled) ||
        !parse_policy_effect(action, &rule->effect) ||
        !parse_policy_target(target, &rule->target)) {
        return -EINVAL;
    }
    if (updating && !required_identifier(body, "revision", revision)) {
        return -EINVAL;
    }
    result = parse_policy_scope(scope, &rule->scope);
    if (result == 0) {
        rule->id = rule_id;
        rule->domain = domain;
        rule->source = JG_POLICY_SOURCE_EXPLICIT;
        rule->attribution = attribution;
    }
    return result;
}

/** @brief Parse one destination-rule transport selector. */
static bool parse_policy_transport_selector(const char *text,
                                            enum jg_policy_transport *transport)
{
    if (text == NULL || transport == NULL) {
        return false;
    }
    if (strcmp(text, "any") == 0) {
        *transport = JG_POLICY_TRANSPORT_ANY;
        return true;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = JG_POLICY_TRANSPORT_TCP;
        return true;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = JG_POLICY_TRANSPORT_UDP;
        return true;
    }
    return false;
}

/** @brief Parse one complete explicit destination-rule request body. */
static int parse_destination_rule_request(
    json_t *body,
    uint64_t rule_id,
    bool updating,
    struct jg_policy_destination_rule_input *rule,
    bool *enabled,
    uint64_t *revision)
{
    static const char *const create_fields[] = {
        "action", "transport", "address",     "prefix_length",
        "port",   "scope",     "attribution", "enabled",
    };
    static const char *const update_fields[] = {
        "revision", "action", "transport",   "address", "prefix_length",
        "port",     "scope",  "attribution", "enabled",
    };
    const char *action = required_string(body, "action", 5U, 5U);
    const char *transport = required_string(body, "transport", 3U, 3U);
    const char *attribution =
        required_string(body, "attribution", 1U, JG_POLICY_ATTRIBUTION_MAX);
    json_t *address_value = json_object_get(body, "address");
    json_t *prefix_value = json_object_get(body, "prefix_length");
    json_t *port_value = json_object_get(body, "port");
    json_t *scope = json_object_get(body, "scope");
    const char *address =
        json_is_string(address_value) ? json_string_value(address_value) : NULL;
    json_int_t prefix =
        json_is_integer(prefix_value) ? json_integer_value(prefix_value) : -1;
    json_int_t port =
        json_is_integer(port_value) ? json_integer_value(port_value) : -1;
    int result = 0;

    (void)memset(rule, 0, sizeof(*rule));
    *revision = 0U;
    if ((updating &&
         !fields_allowed(body, update_fields,
                         sizeof(update_fields) / sizeof(update_fields[0U]))) ||
        (!updating &&
         !fields_allowed(body, create_fields,
                         sizeof(create_fields) / sizeof(create_fields[0U]))) ||
        action == NULL || transport == NULL || attribution == NULL ||
        address_value == NULL || prefix_value == NULL || port_value == NULL ||
        !required_boolean(body, "enabled", enabled) ||
        !parse_policy_effect(action, &rule->effect) ||
        !parse_policy_transport_selector(transport, &rule->transport)) {
        return -EINVAL;
    }
    if (updating && !required_identifier(body, "revision", revision)) {
        return -EINVAL;
    }
    if (json_is_string(address_value)) {
        if (bounded_length(address, INET6_ADDRSTRLEN - 1U) >=
            INET6_ADDRSTRLEN) {
            return -EINVAL;
        }
        if (inet_pton(AF_INET, address, rule->address) == 1 && prefix >= 0 &&
            prefix <= 32) {
            rule->address_family = JG_POLICY_ADDRESS_IPV4;
        } else if (inet_pton(AF_INET6, address, rule->address) == 1 &&
                   prefix >= 0 && prefix <= 128) {
            rule->address_family = JG_POLICY_ADDRESS_IPV6;
        } else {
            return -EINVAL;
        }
        rule->has_address = true;
        rule->prefix_length = (uint8_t)prefix;
    } else if (!json_is_null(address_value) || !json_is_null(prefix_value)) {
        return -EINVAL;
    }
    if (json_is_integer(port_value)) {
        if (port <= 0 || port > 65535) {
            return -EINVAL;
        }
        rule->has_port = true;
        rule->port = (uint16_t)port;
    } else if (!json_is_null(port_value)) {
        return -EINVAL;
    }
    if (!rule->has_address && !rule->has_port) {
        return -EINVAL;
    }
    result = parse_policy_scope(scope, &rule->scope);
    if (result == 0) {
        rule->id = rule_id;
        rule->source = JG_POLICY_SOURCE_EXPLICIT;
        rule->attribution = attribution;
    }
    return result;
}

/** @brief Parse one external TCP or UDP policy transport. */
static bool parse_policy_transport(const char *text,
                                   enum jg_policy_transport *transport)
{
    if (text == NULL || transport == NULL) {
        return false;
    }
    if (strcmp(text, "tcp") == 0) {
        *transport = JG_POLICY_TRANSPORT_TCP;
        return true;
    }
    if (strcmp(text, "udp") == 0) {
        *transport = JG_POLICY_TRANSPORT_UDP;
        return true;
    }
    return false;
}

/** @brief Return the stable external name for a selected policy dimension. */
static const char *policy_dimension_name(
    enum jg_policy_match_dimension dimension)
{
    switch (dimension) {
    case JG_POLICY_MATCH_DEFAULT:
        return "default";
    case JG_POLICY_MATCH_DOMAIN:
        return "domain";
    case JG_POLICY_MATCH_DESTINATION:
        return "destination";
    default:
        return NULL;
    }
}

/** @brief Convert one self-contained simulated rule match to JSON. */
static json_t *policy_simulation_match_json(
    const struct jg_policy_simulation_match *match,
    enum jg_policy_match_dimension dimension)
{
    const char *effect = policy_effect_name(match->effect);
    const char *source = policy_source_name(match->source);
    const char *dimension_name = policy_dimension_name(dimension);
    json_t *body = json_object();

    if (effect == NULL || source == NULL || dimension_name == NULL ||
        body == NULL ||
        json_object_set_new(body, "dimension", json_string(dimension_name)) !=
            0 ||
        json_object_set_new(body, "matched", json_boolean(match->matched)) !=
            0 ||
        json_object_set_new(body, "action", json_string(effect)) != 0 ||
        json_object_set_new(body, "rule_id",
                            match->matched
                                ? json_integer((json_int_t)match->rule_id)
                                : json_null()) != 0 ||
        json_object_set_new(body, "source", json_string(source)) != 0 ||
        json_object_set_new(body, "domain",
                            match->domain[0U] == '\0'
                                ? json_null()
                                : json_string(match->domain)) != 0 ||
        json_object_set_new(body, "attribution",
                            match->attribution[0U] == '\0'
                                ? json_null()
                                : json_string(match->attribution)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Serialize one complete policy simulation explanation. */
static json_t *policy_simulation_json(
    const struct jg_policy_simulation *simulation)
{
    const char *effect = policy_effect_name(simulation->effect);
    const char *target = policy_target_name(simulation->target);
    const char *selected = policy_dimension_name(simulation->selected);
    const struct jg_policy_simulation_match *selected_match = NULL;
    json_t *body = json_object();
    json_t *domain = policy_simulation_match_json(&simulation->domain,
                                                  JG_POLICY_MATCH_DOMAIN);
    json_t *destination =
        simulation->destination_evaluated
            ? policy_simulation_match_json(&simulation->destination,
                                           JG_POLICY_MATCH_DESTINATION)
            : json_null();
    json_t *matching_rule = NULL;
    json_t *path = json_array();
    json_t *sources = json_array();
    int result = 0;

    if (simulation->selected == JG_POLICY_MATCH_DOMAIN) {
        selected_match = &simulation->domain;
    } else if (simulation->selected == JG_POLICY_MATCH_DESTINATION) {
        selected_match = &simulation->destination;
    }
    matching_rule = selected_match == NULL
                        ? json_null()
                        : policy_simulation_match_json(selected_match,
                                                       simulation->selected);
    if (effect == NULL || target == NULL || selected == NULL || body == NULL ||
        domain == NULL || destination == NULL || matching_rule == NULL ||
        path == NULL || sources == NULL ||
        simulation->generation > (uint64_t)INT64_MAX) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->destination_evaluated &&
        json_array_append_new(path, json_string("destination")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        !(simulation->selected == JG_POLICY_MATCH_DESTINATION &&
          simulation->effect == JG_POLICY_BLOCK) &&
        json_array_append_new(path, json_string("domain")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->selected == JG_POLICY_MATCH_DEFAULT &&
        json_array_append_new(path, json_string("default")) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->destination.attribution[0U] != '\0' &&
        json_array_append_new(
            sources, json_string(simulation->destination.attribution)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && simulation->domain.attribution[0U] != '\0' &&
        (simulation->destination.attribution[0U] == '\0' ||
         strcmp(simulation->domain.attribution,
                simulation->destination.attribution) != 0) &&
        json_array_append_new(
            sources, json_string(simulation->domain.attribution)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(body, "normalized_domain",
                             json_string(simulation->normalized_domain)) != 0 ||
         json_object_set_new(body, "target", json_string(target)) != 0 ||
         json_object_set_new(body, "action", json_string(effect)) != 0 ||
         json_object_set_new(body, "selected", json_string(selected)) != 0 ||
         json_object_set_new(
             body, "policy_generation",
             json_integer((json_int_t)simulation->generation)) != 0 ||
         json_object_set(body, "domain_match", domain) != 0 ||
         json_object_set(body, "destination_match", destination) != 0 ||
         json_object_set(body, "matching_rule", matching_rule) != 0 ||
         json_object_set(body, "precedence_path", path) != 0 ||
         json_object_set(body, "sources", sources) != 0)) {
        result = -ENOMEM;
    }
    json_decref(domain);
    json_decref(destination);
    json_decref(matching_rule);
    json_decref(path);
    json_decref(sources);
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Parse one exact numeric cursor and limit query. */
static int parse_page_query(const char *query,
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

/** @brief Append one domain-rule mutation and publication outcome. */
static int append_domain_rule_audit(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    const struct authenticated_actor *actor,
                                    const char *action,
                                    bool has_previous_revision,
                                    uint64_t previous_revision,
                                    bool has_new_revision,
                                    const struct jg_database_domain_rule *rule,
                                    bool published,
                                    uint64_t generation,
                                    uint64_t now)
{
    char object_id[32U];
    char source_address[INET6_ADDRSTRLEN];
    const char *effect = policy_effect_name(rule->effect);
    const char *target = policy_target_name(rule->target);
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)rule->id);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(object_id) ||
        effect == NULL || target == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "domain", json_string(rule->domain)) !=
            0 ||
        json_object_set_new(details, "action", json_string(effect)) != 0 ||
        json_object_set_new(details, "target", json_string(target)) != 0 ||
        json_object_set_new(details, "include_subdomains",
                            json_boolean(rule->include_subdomains)) != 0 ||
        json_object_set_new(details, "enabled", json_boolean(rule->enabled)) !=
            0 ||
        json_object_set_new(details, "published", json_boolean(published)) !=
            0 ||
        json_object_set_new(details, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
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
            .actor_type =
                actor->token ? JG_AUDIT_ACTOR_TOKEN : JG_AUDIT_ACTOR_USER,
            .has_actor_id = true,
            .actor_id = actor->actor_id,
            .source = source_address,
            .action = action,
            .object_type = "domain_rule",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = has_new_revision,
            .new_revision = rule->revision,
            .success = published,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one destination-rule mutation and publication outcome. */
static int append_destination_rule_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_destination_rule *rule,
    bool published,
    uint64_t generation,
    uint64_t now)
{
    char object_id[32U];
    char source_address[INET6_ADDRSTRLEN];
    json_t *details = destination_rule_json(rule);
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)rule->id);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(object_id) ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "published", json_boolean(published)) !=
            0 ||
        json_object_set_new(details, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
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
            .actor_type =
                actor->token ? JG_AUDIT_ACTOR_TOKEN : JG_AUDIT_ACTOR_USER,
            .has_actor_id = true,
            .actor_id = actor->actor_id,
            .source = source_address,
            .action = action,
            .object_type = "destination_rule",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = has_new_revision,
            .new_revision = rule->revision,
            .success = published,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one successful user lifecycle event without credentials. */
static int append_user_audit(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             const struct authenticated_actor *actor,
                             const char *action,
                             bool has_previous_revision,
                             uint64_t previous_revision,
                             const struct jg_account_user *user,
                             uint64_t now)
{
    char object_id[32U];
    char source[INET6_ADDRSTRLEN];
    const char *role = role_name(user->role);
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = 0;
    int result = 0;

    written = snprintf(object_id, sizeof(object_id), "%llu",
                       (unsigned long long)user->user_id);
    if (written <= 0 || (size_t)written >= sizeof(object_id) || role == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "username", json_string(user->username)) !=
            0 ||
        json_object_set_new(details, "role", json_string(role)) != 0 ||
        json_object_set_new(details, "enabled", json_boolean(user->enabled)) !=
            0 ||
        json_object_set_new(details, "force_password_change",
                            json_boolean(user->force_password_change)) != 0) {
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
            .actor_type =
                actor->token ? JG_AUDIT_ACTOR_TOKEN : JG_AUDIT_ACTOR_USER,
            .has_actor_id = true,
            .actor_id = actor->actor_id,
            .source = source,
            .action = action,
            .object_type = "user",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = true,
            .new_revision = user->revision,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one successful API-token lifecycle event. */
static int append_token_audit(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              const struct authenticated_actor *actor,
                              const char *action,
                              bool has_previous_revision,
                              uint64_t previous_revision,
                              const struct jg_account_token_record *token,
                              uint64_t now)
{
    char object_id[32U];
    char source[INET6_ADDRSTRLEN];
    char scopes[JG_ACCESS_SCOPE_TEXT_MAX + 1U];
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = 0;
    int result =
        jg_access_scope_format(token->permissions, scopes, sizeof(scopes));

    written = snprintf(object_id, sizeof(object_id), "%llu",
                       (unsigned long long)token->token_id);
    if (result != 0 || written <= 0 || (size_t)written >= sizeof(object_id) ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "user_id",
                            json_integer((json_int_t)token->user_id)) != 0 ||
        json_object_set_new(details, "name", json_string(token->name)) != 0 ||
        json_object_set_new(details, "scopes", json_string(scopes)) != 0) {
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
            .actor_type =
                actor->token ? JG_AUDIT_ACTOR_TOKEN : JG_AUDIT_ACTOR_USER,
            .has_actor_id = true,
            .actor_id = actor->actor_id,
            .source = source,
            .action = action,
            .object_type = "api_token",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = true,
            .new_revision = token->revision,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Issue a remote-address-bound session response. */
static int issue_session(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         const struct jg_account_identity *identity,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct jg_account_session_tokens tokens;
    struct session_result session;
    json_t *body = NULL;
    json_t *user = NULL;
    int result = jg_account_session_issue(
        management->database, identity, now, MANAGEMENT_SESSION_LIFETIME,
        remote->family, remote->address, &tokens);

    if (result != 0) {
        return respond_error(500, "session_failure",
                             "The authenticated session could not be created.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    user = identity_json(identity);
    if (body == NULL || user == NULL ||
        json_object_set(body, "user", user) != 0 ||
        json_object_set_new(body, "csrf", json_string(tokens.csrf)) != 0 ||
        json_object_set_new(body, "expires_at",
                            json_integer((json_int_t)tokens.expires_at)) != 0) {
        json_decref(user);
        json_decref(body);
        sodium_memzero(&tokens, sizeof(tokens));
        return -ENOMEM;
    }
    json_decref(user);
    session = (struct session_result){
        .set_session = tokens.session,
        .clear_session = false,
    };
    result = encode_response(200, body, &session, output, output_size, written);
    sodium_memzero(&tokens, sizeof(tokens));
    return result;
}

/** @brief Complete optional multifactor authentication after a password. */
static int complete_multifactor(
    struct jg_management *management,
    const struct management_request *request,
    const struct jg_account_identity *password_identity,
    uint64_t now,
    struct jg_account_identity *identity)
{
    static const char *const fields[] = {
        "username",
        "password",
        "totp",
        "recovery_code",
    };
    json_t *totp = json_object_get(request->body, "totp");
    const char *recovery = optional_string(request->body, "recovery_code",
                                           JG_AUTH_SECRET_TEXT_SIZE - 1U);

    if (!fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        recovery == NULL || (totp != NULL && !json_is_integer(totp)) ||
        (totp != NULL && recovery[0U] != '\0')) {
        return -EINVAL;
    }
    if (!password_identity->totp_enabled) {
        *identity = *password_identity;
        return totp == NULL && recovery[0U] == '\0' ? 0 : -EINVAL;
    }
    if (json_is_integer(totp)) {
        const json_int_t code = json_integer_value(totp);

        if (code < 0 || code >= 1000000) {
            return -EINVAL;
        }
        return jg_account_totp_authenticate(
            management->database, password_identity, management->totp_key,
            (uint32_t)code, now, identity);
    }
    if (recovery[0U] != '\0') {
        return jg_account_recovery_authenticate(
            management->database, password_identity, (const uint8_t *)recovery,
            strlen(recovery), now, identity);
    }
    return -ENOKEY;
}

/** @brief Authenticate a password and return one browser session. */
static int handle_login(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    const char *username =
        required_string(request->body, "username", 1U, JG_ACCOUNT_USERNAME_MAX);
    const char *password =
        required_string(request->body, "password", 1U, JG_AUTH_PASSWORD_MAX);
    struct jg_account_identity password_identity;
    struct jg_account_identity identity;
    int result = 0;

    if (username == NULL || password == NULL) {
        return respond_error(400, "invalid_body",
                             "The authentication request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_authenticate(
        management->database, username, (const uint8_t *)password,
        strlen(password), &management->password_policy, now,
        &password_identity);
    if (result == 0) {
        result = complete_multifactor(management, request, &password_identity,
                                      now, &identity);
    }
    if (result == -ENOKEY) {
        return respond_error(401, "mfa_required",
                             "A second authentication factor is required.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(429, "authentication_limited",
                             "Authentication is temporarily limited.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL) {
        return respond_error(400, "invalid_body",
                             "The authentication request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(401, "invalid_credentials",
                             "The supplied credentials are not valid.",
                             request->request_id, output, output_size, written);
    }
    return issue_session(management, request, remote, &identity, now, output,
                         output_size, written);
}

/** @brief Consume bootstrap access and create the first administrator. */
static int handle_bootstrap(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    static const char *const fields[] = {
        "token",
        "username",
        "password",
    };
    const char *token =
        required_string(request->body, "token", JG_AUTH_SECRET_TEXT_SIZE - 1U,
                        JG_AUTH_SECRET_TEXT_SIZE - 1U);
    const char *username =
        required_string(request->body, "username", 1U, JG_ACCOUNT_USERNAME_MAX);
    const char *password = required_string(
        request->body, "password", JG_AUTH_PASSWORD_MIN, JG_AUTH_PASSWORD_MAX);
    struct jg_account_identity identity;
    uint64_t user_id = 0U;
    int result = 0;

    if (!fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        token == NULL || username == NULL || password == NULL) {
        return respond_error(400, "invalid_body",
                             "The bootstrap request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_create_initial_administrator(
        management->database, (const uint8_t *)token, strlen(token), username,
        (const uint8_t *)password, strlen(password),
        &management->password_policy, now, &user_id);
    if (result == -EEXIST) {
        return respond_error(409, "setup_complete",
                             "The initial administrator already exists.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EACCES) {
        return respond_error(403, "invalid_bootstrap",
                             "The bootstrap credential is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "bootstrap_failure",
                             "The initial administrator could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_authenticate(
        management->database, username, (const uint8_t *)password,
        strlen(password), &management->password_policy, now, &identity);
    if (result != 0 || identity.user_id != user_id) {
        return respond_error(500, "session_failure",
                             "The administrator was created; sign in again.",
                             request->request_id, output, output_size, written);
    }
    return issue_session(management, request, remote, &identity, now, output,
                         output_size, written);
}

/** @brief Authenticate the current browser session and optional CSRF value. */
static int authenticate_session(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                bool require_csrf,
                                uint64_t now,
                                struct jg_account_identity *identity)
{
    const size_t session_size = strlen(request->session);
    const size_t csrf_size = strlen(request->csrf);

    if (session_size != JG_AUTH_SECRET_TEXT_SIZE - 1U ||
        (require_csrf && csrf_size != JG_AUTH_SECRET_TEXT_SIZE - 1U)) {
        return -EACCES;
    }
    return jg_account_session_validate(
        management->database, (const uint8_t *)request->session, session_size,
        require_csrf ? (const uint8_t *)request->csrf : NULL,
        require_csrf ? csrf_size : 0U, require_csrf, now,
        MANAGEMENT_SESSION_INACTIVITY, remote->family, remote->address,
        identity);
}

/** @brief Change the current user's password and rotate its web session. */
static int handle_password_change(struct jg_management *management,
                                  const struct management_request *request,
                                  const struct remote_address *remote,
                                  uint64_t now,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *written)
{
    static const char *const fields[] = {
        "current_password",
        "new_password",
    };
    struct jg_account_identity session_identity;
    struct jg_account_identity password_identity;
    struct jg_account_identity renewed_identity;
    struct jg_account_user user;
    struct authenticated_actor actor;
    const char *current_password = NULL;
    const char *new_password = NULL;
    int result = authenticate_session(management, request, remote, true, now,
                                      &session_identity);

    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "A valid authenticated session is required.",
                             request->request_id, output, output_size, written);
    }
    current_password = required_string(request->body, "current_password", 1U,
                                       JG_AUTH_PASSWORD_MAX);
    new_password = required_string(request->body, "new_password",
                                   JG_AUTH_PASSWORD_MIN, JG_AUTH_PASSWORD_MAX);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        current_password == NULL || new_password == NULL ||
        strcmp(current_password, new_password) == 0) {
        return respond_error(400, "invalid_body",
                             "The password-change request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_authenticate(
        management->database, session_identity.username,
        (const uint8_t *)current_password, strlen(current_password),
        &management->password_policy, now, &password_identity);
    if (result == -EAGAIN) {
        return respond_error(429, "authentication_limited",
                             "Authentication is temporarily limited.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(401, "invalid_credentials",
                             "The current password is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (password_identity.user_id != session_identity.user_id ||
        password_identity.revision != session_identity.revision ||
        password_identity.session_epoch != session_identity.session_epoch ||
        strcmp(password_identity.username, session_identity.username) != 0) {
        return respond_error(409, "session_changed",
                             "The account changed; sign in and try again.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_user_reset_password(
        management->database, session_identity.user_id,
        session_identity.revision, (const uint8_t *)new_password,
        strlen(new_password), &management->password_policy, false, now, &user);
    if (result == -ESTALE) {
        return respond_error(409, "session_changed",
                             "The account changed; sign in and try again.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE) {
        return respond_error(400, "invalid_password",
                             "The replacement password is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "password_change_failed",
                             "The password could not be changed.",
                             request->request_id, output, output_size, written);
    }
    actor = (struct authenticated_actor){
        .identity = session_identity,
        .actor_id = session_identity.user_id,
        .token = false,
    };
    result = append_user_audit(management, request, remote, &actor,
                               "user.password_change", true,
                               session_identity.revision, &user, now);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The password was changed, but its audit record could not be "
            "stored.",
            request->request_id, output, output_size, written);
    }
    result = jg_account_authenticate(
        management->database, session_identity.username,
        (const uint8_t *)new_password, strlen(new_password),
        &management->password_policy, now, &renewed_identity);
    if (result != 0 || renewed_identity.user_id != session_identity.user_id ||
        renewed_identity.revision != user.revision ||
        renewed_identity.totp_enabled != session_identity.totp_enabled) {
        return respond_error(500, "session_failure",
                             "The password was changed; sign in again.",
                             request->request_id, output, output_size, written);
    }
    renewed_identity.mfa_complete = session_identity.mfa_complete;
    return issue_session(management, request, remote, &renewed_identity, now,
                         output, output_size, written);
}

/** @brief Enforce one bounded fixed-window API-token request limit. */
static int token_rate_accept(struct jg_management *management,
                             uint64_t token_id,
                             uint32_t requests_per_minute,
                             uint64_t now)
{
    struct token_rate_slot *slot = NULL;
    struct token_rate_slot *oldest = &management->token_rates[0U];
    const uint64_t minute = now / 60U;

    for (size_t index = 0U; index < MANAGEMENT_TOKEN_RATE_SLOT_COUNT; ++index) {
        struct token_rate_slot *candidate = &management->token_rates[index];

        if (candidate->token_id == token_id || candidate->token_id == 0U) {
            slot = candidate;
            break;
        }
        if (candidate->last_request < oldest->last_request) {
            oldest = candidate;
        }
    }
    if (slot == NULL) {
        slot = oldest;
    }
    if (slot->token_id != token_id || slot->minute != minute) {
        *slot = (struct token_rate_slot){
            .token_id = token_id,
            .minute = minute,
            .last_request = now,
            .requests = 1U,
        };
        return 0;
    }
    slot->last_request = now;
    if (slot->requests >= requests_per_minute) {
        return -EAGAIN;
    }
    ++slot->requests;
    return 0;
}

/** @brief Authenticate a session or bearer token and enforce permissions. */
static int authenticate_actor(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              bool state_change,
                              uint32_t required_permissions,
                              uint64_t now,
                              struct authenticated_actor *actor)
{
    const bool has_session = request->session[0U] != '\0';
    const bool has_bearer = request->bearer[0U] != '\0';
    uint32_t requests_per_minute = 0U;
    uint64_t token_id = 0U;
    int result = 0;

    (void)memset(actor, 0, sizeof(*actor));
    if (has_session == has_bearer) {
        return -EACCES;
    }
    if (has_bearer) {
        if (strlen(request->bearer) != JG_AUTH_SECRET_TEXT_SIZE - 1U) {
            return -EACCES;
        }
        result = jg_account_token_validate(
            management->database, (const uint8_t *)request->bearer,
            strlen(request->bearer), now, remote->family, remote->address,
            &actor->identity, &token_id, &requests_per_minute);
        if (result == 0) {
            result = token_rate_accept(management, token_id,
                                       requests_per_minute, now);
        }
        actor->token = true;
        actor->actor_id = token_id;
    } else {
        result = authenticate_session(management, request, remote, state_change,
                                      now, &actor->identity);
        actor->actor_id = actor->identity.user_id;
    }
    if (result == 0 && actor->identity.force_password_change) {
        result = -EKEYEXPIRED;
    }
    if (result == 0 &&
        !jg_access_grants(actor->identity.permissions, required_permissions)) {
        result = -EPERM;
    }
    if (result != 0) {
        sodium_memzero(actor, sizeof(*actor));
    }
    return result;
}

/** @brief Convert one actor-authentication result to a public API error. */
static int respond_actor_error(int result,
                               const struct management_request *request,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    if (result == -EAGAIN) {
        return respond_error(429, "rate_limited",
                             "The API token request limit was exceeded.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EPERM || result == -EKEYEXPIRED) {
        return respond_error(403, "forbidden",
                             "The authenticated identity is not authorized.",
                             request->request_id, output, output_size, written);
    }
    return respond_error(401, "authentication_required",
                         "Valid authentication is required.",
                         request->request_id, output, output_size, written);
}

/** @brief Add one nonnegative runtime counter to a JSON object. */
static int set_counter(json_t *object, const char *name, uint64_t value)
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

    if (result == -EAGAIN) {
        return respond_error(429, "rate_limited",
                             "The API token request limit was exceeded.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EPERM || result == -EKEYEXPIRED) {
        return respond_error(403, "forbidden",
                             "The authenticated identity is not authorized.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "Valid authentication is required.",
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

/** @brief Simulate one authenticated decision on the active policy snapshot. */
static int handle_policy_simulation(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    uint64_t now,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *written)
{
    static const char *const fields[] = {
        "domain", "target",         "source_ip",        "source_mac",
        "vlan",   "destination_ip", "destination_port", "transport",
    };
    struct authenticated_actor actor;
    struct jg_policy_client client;
    struct jg_policy_destination destination;
    struct jg_policy_simulation simulation;
    struct remote_address parsed_address;
    const char *domain = NULL;
    const char *target_text = NULL;
    const char *source_ip = NULL;
    const char *source_mac = NULL;
    const char *destination_ip = NULL;
    const char *transport_text = NULL;
    json_t *target_value = json_object_get(request->body, "target");
    json_t *source_ip_value = json_object_get(request->body, "source_ip");
    json_t *source_mac_value = json_object_get(request->body, "source_mac");
    json_t *vlan_value = json_object_get(request->body, "vlan");
    json_t *destination_ip_value =
        json_object_get(request->body, "destination_ip");
    json_t *destination_port_value =
        json_object_get(request->body, "destination_port");
    json_t *transport_value = json_object_get(request->body, "transport");
    enum jg_policy_domain_target target = JG_POLICY_DOMAIN_DNS;
    bool has_client = false;
    bool has_destination = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    (void)memset(&client, 0, sizeof(client));
    (void)memset(&destination, 0, sizeof(destination));
    domain = required_string(request->body, "domain", 1U, 1024U);
    target_text = optional_string(request->body, "target", 7U);
    source_ip =
        optional_string(request->body, "source_ip", INET6_ADDRSTRLEN - 1U);
    source_mac = optional_string(request->body, "source_mac", 17U);
    destination_ip =
        optional_string(request->body, "destination_ip", INET6_ADDRSTRLEN - 1U);
    transport_text = optional_string(request->body, "transport", 3U);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        domain == NULL || target_text == NULL || source_ip == NULL ||
        source_mac == NULL || destination_ip == NULL ||
        transport_text == NULL ||
        (target_value != NULL && target_text[0U] == '\0') ||
        (source_ip_value != NULL && source_ip[0U] == '\0') ||
        (source_mac_value != NULL && source_mac[0U] == '\0') ||
        (destination_ip_value != NULL && destination_ip[0U] == '\0') ||
        (transport_value != NULL && transport_text[0U] == '\0') ||
        !parse_policy_target(target_text, &target)) {
        return respond_error(400, "invalid_body",
                             "The policy-simulation request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (source_ip[0U] != '\0') {
        result = parse_remote_address(source_ip, &parsed_address);
        if (result == 0) {
            client.address_family = parsed_address.family;
            (void)memcpy(client.address, parsed_address.address,
                         parsed_address.family == JG_POLICY_ADDRESS_IPV4 ? 4U
                                                                         : 16U);
            has_client = true;
        }
    }
    if (result == 0 && source_mac[0U] != '\0') {
        result = parse_mac_address(source_mac, client.mac);
        if (result == 0) {
            client.has_mac = true;
            has_client = true;
        }
    }
    if (result == 0 && vlan_value != NULL) {
        const json_int_t vlan =
            json_is_integer(vlan_value) ? json_integer_value(vlan_value) : -1;

        if (vlan < 0 || vlan > 4094) {
            result = -EINVAL;
        } else {
            client.has_vlan = true;
            client.vlan_id = (uint16_t)vlan;
            has_client = true;
        }
    }
    has_destination = destination_ip[0U] != '\0';
    if (result == 0 && has_destination) {
        const json_int_t port = json_is_integer(destination_port_value)
                                    ? json_integer_value(destination_port_value)
                                    : -1;

        result = parse_remote_address(destination_ip, &parsed_address);
        if (result == 0 &&
            (!parse_policy_transport(transport_text, &destination.transport) ||
             port <= 0 || port > 65535)) {
            result = -EINVAL;
        }
        if (result == 0) {
            destination.address_family = parsed_address.family;
            (void)memcpy(destination.address, parsed_address.address,
                         parsed_address.family == JG_POLICY_ADDRESS_IPV4 ? 4U
                                                                         : 16U);
            destination.port = (uint16_t)port;
        }
    } else if (result == 0 &&
               (destination_port_value != NULL || transport_value != NULL)) {
        result = -EINVAL;
    }
    if (result != 0) {
        return respond_error(400, "invalid_body",
                             "The policy-simulation request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = jg_daemon_runtime_simulate_policy(
        management->runtime, target, domain, has_client ? &client : NULL,
        has_destination ? &destination : NULL, &simulation);
    if (result == -EINVAL || result == -ENOSPC) {
        return respond_error(
            400, "invalid_simulation",
            "The simulation input is not a valid policy query.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    body = policy_simulation_json(&simulation);
    if (body == NULL) {
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return one authenticated stable page of domain rules. */
static int handle_domain_rules_list(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    uint64_t now,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_domain_rule *rules = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_POLICY_PAGE_MAX, &after_id, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The domain-rule pagination is not valid.",
                             request->request_id, output, output_size, written);
    }
    rules = calloc(limit, sizeof(*rules));
    if (rules == NULL) {
        return -ENOMEM;
    }
    result = jg_database_list_domain_rules(management->database, after_id,
                                           limit, rules, &count, &has_more);
    if (result != 0) {
        free(rules);
        return respond_error(500, "domains_unavailable",
                             "The domain rules could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = domain_rule_json(&rules[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "domains", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)rules[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(rules);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return one authenticated stable page of destination rules. */
static int handle_destination_rules_list(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    uint64_t now,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_destination_rule *rules = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_POLICY_PAGE_MAX, &after_id, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The destination-rule pagination is not valid.",
                             request->request_id, output, output_size, written);
    }
    rules = calloc(limit, sizeof(*rules));
    if (rules == NULL) {
        return -ENOMEM;
    }
    result = jg_database_list_destination_rules(
        management->database, after_id, limit, rules, &count, &has_more);
    if (result != 0) {
        free(rules);
        return respond_error(500, "destinations_unavailable",
                             "The destination rules could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = destination_rule_json(&rules[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "destination_rules", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)rules[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(rules);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Publish persistent policy and audit one domain-rule change. */
static int publish_domain_rule_change(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_domain_rule *rule,
    uint64_t now,
    bool *published,
    uint64_t *generation)
{
    int result = jg_daemon_runtime_reload_policy(management->runtime);
    int audit_result = 0;

    *published = result == 0;
    audit_result = jg_daemon_runtime_get_policy_generation(management->runtime,
                                                           generation);
    if (audit_result == 0) {
        audit_result = append_domain_rule_audit(
            management, request, remote, actor, action, has_previous_revision,
            previous_revision, has_new_revision, rule, *published, *generation,
            now);
    }
    return audit_result;
}

/** @brief Encode one created or updated domain-rule result. */
static int respond_domain_rule(int status,
                               const struct jg_database_domain_rule *rule,
                               bool published,
                               uint64_t generation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    json_t *body = json_object();
    json_t *item = domain_rule_json(rule);

    if (body == NULL || item == NULL ||
        json_object_set(body, "domain", item) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(item);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(item);
    return encode_response(status, body, NULL, output, output_size, written);
}

/** @brief Create one explicit domain rule and publish a new snapshot. */
static int handle_domain_rule_create(struct jg_management *management,
                                     const struct management_request *request,
                                     const struct remote_address *remote,
                                     uint64_t now,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_rule_input rule;
    struct jg_database_domain_rule created;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_domain_rule_request(request->body, 0U, false, &rule,
                                       &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The domain-rule request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_create_domain_rule(management->database, &rule,
                                            enabled, &created);
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_domain_rule",
                             "The domain-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "domain_create_failed",
                             "The domain rule could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = publish_domain_rule_change(management, request, remote, &actor,
                                        "policy.domain.create", false, 0U, true,
                                        &created, now, &published, &generation);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The domain rule changed, but its audit record was not stored.",
            request->request_id, output, output_size, written);
    }
    return respond_domain_rule(published ? 201 : 202, &created, published,
                               generation, output, output_size, written);
}

/** @brief Read one exact domain rule for guarded mutation. */
static int get_domain_rule(struct jg_database *database,
                           uint64_t rule_id,
                           struct jg_database_domain_rule *rule)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_domain_rules(database, rule_id - 1U, 1U, rule,
                                               &count, &has_more);

    (void)has_more;
    return result == 0 && (count != 1U || rule->id != rule_id) ? -ENOENT
                                                               : result;
}

/** @brief Update one explicit domain rule and publish a new snapshot. */
static int handle_domain_rule_update(struct jg_management *management,
                                     const struct management_request *request,
                                     const struct remote_address *remote,
                                     uint64_t rule_id,
                                     uint64_t now,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_rule_input rule;
    struct jg_database_domain_rule previous;
    struct jg_database_domain_rule updated;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_domain_rule_request(request->body, rule_id, true, &rule,
                                       &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The domain-rule update is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_domain_rule(management->database, rule_id, &previous);
    if (result == 0 && previous.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_domain_rule",
            "This rule is managed by its policy source and cannot be edited.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_update_domain_rule(management->database, &rule,
                                                enabled, revision, &updated);
    }
    if (result == -ENOENT) {
        return respond_error(404, "domain_not_found",
                             "The domain rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The domain rule has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_domain_rule",
                             "The domain-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "domain_update_failed",
                             "The domain rule could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = publish_domain_rule_change(
        management, request, remote, &actor, "policy.domain.update", true,
        revision, true, &updated, now, &published, &generation);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The domain rule changed, but its audit record was not stored.",
            request->request_id, output, output_size, written);
    }
    return respond_domain_rule(published ? 200 : 202, &updated, published,
                               generation, output, output_size, written);
}

/** @brief Delete one explicit domain rule and publish a new snapshot. */
static int handle_domain_rule_delete(struct jg_management *management,
                                     const struct management_request *request,
                                     const struct remote_address *remote,
                                     uint64_t rule_id,
                                     uint64_t now,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct jg_database_domain_rule removed;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The domain-rule deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_domain_rule(management->database, rule_id, &removed);
    if (result == 0 && removed.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_domain_rule",
            "This rule is managed by its policy source and cannot be deleted.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_delete_domain_rule(management->database, rule_id,
                                                revision);
    }
    if (result == -ENOENT) {
        return respond_error(404, "domain_not_found",
                             "The domain rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The domain rule has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "domain_delete_failed",
                             "The domain rule could not be deleted.",
                             request->request_id, output, output_size, written);
    }
    result = publish_domain_rule_change(
        management, request, remote, &actor, "policy.domain.delete", true,
        revision, false, &removed, now, &published, &generation);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The domain rule changed, but its audit record was not stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule_id)) !=
            0 ||
        json_object_set_new(body, "deleted", json_true()) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Publish policy and audit one destination-rule change. */
static int publish_destination_rule_change(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    bool has_new_revision,
    const struct jg_database_destination_rule *rule,
    uint64_t now,
    bool *published,
    uint64_t *generation)
{
    int result = jg_daemon_runtime_reload_policy(management->runtime);
    int audit_result = 0;

    *published = result == 0;
    audit_result = jg_daemon_runtime_get_policy_generation(management->runtime,
                                                           generation);
    if (audit_result == 0) {
        audit_result = append_destination_rule_audit(
            management, request, remote, actor, action, has_previous_revision,
            previous_revision, has_new_revision, rule, *published, *generation,
            now);
    }
    return audit_result;
}

/** @brief Encode one created or updated destination-rule result. */
static int respond_destination_rule(
    int status,
    const struct jg_database_destination_rule *rule,
    bool published,
    uint64_t generation,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    json_t *body = json_object();
    json_t *item = destination_rule_json(rule);

    if (body == NULL || item == NULL ||
        json_object_set(body, "destination_rule", item) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(item);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(item);
    return encode_response(status, body, NULL, output, output_size, written);
}

/** @brief Read one exact destination rule for guarded mutation. */
static int get_destination_rule(struct jg_database *database,
                                uint64_t rule_id,
                                struct jg_database_destination_rule *rule)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_destination_rules(database, rule_id - 1U, 1U,
                                                    rule, &count, &has_more);

    (void)has_more;
    return result == 0 && (count != 1U || rule->id != rule_id) ? -ENOENT
                                                               : result;
}

/** @brief Create one explicit destination rule and publish a snapshot. */
static int handle_destination_rule_create(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    uint64_t now,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_destination_rule_input rule;
    struct jg_database_destination_rule created;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_destination_rule_request(request->body, 0U, false, &rule,
                                            &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The destination-rule request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_create_destination_rule(management->database, &rule,
                                                 enabled, &created);
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_destination_rule",
                             "The destination-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "destination_create_failed",
                             "The destination rule could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = publish_destination_rule_change(
        management, request, remote, &actor, "policy.destination.create", false,
        0U, true, &created, now, &published, &generation);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The destination rule changed, but its audit record was not "
            "stored.",
            request->request_id, output, output_size, written);
    }
    return respond_destination_rule(published ? 201 : 202, &created, published,
                                    generation, output, output_size, written);
}

/** @brief Update one explicit destination rule and publish a snapshot. */
static int handle_destination_rule_update(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    uint64_t rule_id,
    uint64_t now,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    struct authenticated_actor actor;
    struct jg_policy_destination_rule_input rule;
    struct jg_database_destination_rule previous;
    struct jg_database_destination_rule updated;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool enabled = false;
    bool published = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = parse_destination_rule_request(request->body, rule_id, true, &rule,
                                            &enabled, &revision);
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The destination-rule update is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_destination_rule(management->database, rule_id, &previous);
    if (result == 0 && previous.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_destination_rule",
            "This rule is managed by its policy source and cannot be edited.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_update_destination_rule(
            management->database, &rule, enabled, revision, &updated);
    }
    if (result == -ENOENT) {
        return respond_error(404, "destination_not_found",
                             "The destination rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(
            409, "revision_conflict",
            "The destination rule has changed; reload and retry.",
            request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE || result == -ENOSPC) {
        return respond_error(400, "invalid_destination_rule",
                             "The destination-rule properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "destination_update_failed",
                             "The destination rule could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = publish_destination_rule_change(
        management, request, remote, &actor, "policy.destination.update", true,
        revision, true, &updated, now, &published, &generation);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The destination rule changed, but its audit record was not "
            "stored.",
            request->request_id, output, output_size, written);
    }
    return respond_destination_rule(published ? 200 : 202, &updated, published,
                                    generation, output, output_size, written);
}

/** @brief Delete one explicit destination rule and publish a snapshot. */
static int handle_destination_rule_delete(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    uint64_t rule_id,
    uint64_t now,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct authenticated_actor actor;
    struct jg_database_destination_rule removed;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    json_t *body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The destination-rule deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_destination_rule(management->database, rule_id, &removed);
    if (result == 0 && removed.source != JG_POLICY_SOURCE_EXPLICIT) {
        return respond_error(
            409, "managed_destination_rule",
            "This rule is managed by its policy source and cannot be deleted.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_database_delete_destination_rule(management->database,
                                                     rule_id, revision);
    }
    if (result == -ENOENT) {
        return respond_error(404, "destination_not_found",
                             "The destination rule was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(
            409, "revision_conflict",
            "The destination rule has changed; reload and retry.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "destination_delete_failed",
                             "The destination rule could not be deleted.",
                             request->request_id, output, output_size, written);
    }
    result = publish_destination_rule_change(
        management, request, remote, &actor, "policy.destination.delete", true,
        revision, false, &removed, now, &published, &generation);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The destination rule changed, but its audit record was not "
            "stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)rule_id)) !=
            0 ||
        json_object_set_new(body, "deleted", json_true()) != 0 ||
        json_object_set_new(body, "published", json_boolean(published)) != 0 ||
        json_object_set_new(body, "policy_generation",
                            json_integer((json_int_t)generation)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Return one authenticated stable page of local users. */
static int handle_users_list(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    struct authenticated_actor actor;
    struct jg_account_user *users = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t offset = 0U;
    uint64_t total = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "offset", JG_ACCOUNT_USER_PAGE_MAX,
                         &offset, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The user pagination parameters are not valid.",
                             request->request_id, output, output_size, written);
    }
    users = calloc(limit, sizeof(*users));
    if (users == NULL) {
        return -ENOMEM;
    }
    result = jg_account_user_list(management->database, offset, users, limit,
                                  &count, &total);
    if (result != 0) {
        free(users);
        return respond_error(500, "users_unavailable",
                             "The local users could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = user_json(&users[index]);

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
         json_object_set(body, "users", items) != 0)) {
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
    free(users);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Create one local user through an authorized API request. */
static int handle_user_create(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    static const char *const fields[] = {
        "username",
        "password",
        "role",
        "force_password_change",
    };
    struct authenticated_actor actor;
    struct jg_account_user user;
    const char *username = NULL;
    const char *password = NULL;
    const char *role_text = NULL;
    enum jg_access_role role = JG_ACCESS_ROLE_NONE;
    bool force_password_change = false;
    json_t *body = NULL;
    json_t *user_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    username =
        required_string(request->body, "username", 1U, JG_ACCOUNT_USERNAME_MAX);
    password = required_string(request->body, "password", JG_AUTH_PASSWORD_MIN,
                               JG_AUTH_PASSWORD_MAX);
    role_text = required_string(request->body, "role", 1U, 13U);
    role = parse_role(role_text);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        username == NULL || password == NULL || role == JG_ACCESS_ROLE_NONE ||
        !required_boolean(request->body, "force_password_change",
                          &force_password_change)) {
        return respond_error(400, "invalid_body",
                             "The local-user request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_user_create(management->database, username,
                                    (const uint8_t *)password, strlen(password),
                                    &management->password_policy, role,
                                    force_password_change, now, &user);
    if (result == -EEXIST) {
        return respond_error(409, "username_exists",
                             "The local username is already in use.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE) {
        return respond_error(400, "invalid_user",
                             "The local-user properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "user_create_failed",
                             "The local user could not be created.",
                             request->request_id, output, output_size, written);
    }
    result = append_user_audit(management, request, remote, &actor,
                               "user.create", false, 0U, &user, now);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The user was created, but its audit record could not be stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    user_body = user_json(&user);
    if (body == NULL || user_body == NULL ||
        json_object_set(body, "user", user_body) != 0) {
        json_decref(user_body);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(user_body);
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Replace one local user's mutable administration state. */
static int handle_user_update(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t user_id,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    static const char *const fields[] = {
        "revision",
        "role",
        "enabled",
        "force_password_change",
    };
    struct authenticated_actor actor;
    struct jg_account_user_update update;
    struct jg_account_user user;
    const char *role_text = NULL;
    uint64_t revision = 0U;
    json_t *body = NULL;
    json_t *user_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    (void)memset(&update, 0, sizeof(update));
    role_text = required_string(request->body, "role", 1U, 13U);
    update.role = parse_role(role_text);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision) ||
        update.role == JG_ACCESS_ROLE_NONE ||
        !required_boolean(request->body, "enabled", &update.enabled) ||
        !required_boolean(request->body, "force_password_change",
                          &update.force_password_change)) {
        return respond_error(400, "invalid_body",
                             "The local-user update is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_user_update(management->database, user_id, revision,
                                    &update, now, &user);
    if (result == -ENOENT) {
        return respond_error(404, "user_not_found",
                             "The local user was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -ESTALE) {
        return respond_error(409, "revision_conflict",
                             "The local user has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EPERM) {
        return respond_error(409, "administrator_required",
                             "At least one enabled administrator must remain.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "user_update_failed",
                             "The local user could not be updated.",
                             request->request_id, output, output_size, written);
    }
    result = append_user_audit(management, request, remote, &actor,
                               "user.update", true, revision, &user, now);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The user was updated, but its audit record could not be stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    user_body = user_json(&user);
    if (body == NULL || user_body == NULL ||
        json_object_set(body, "user", user_body) != 0) {
        json_decref(user_body);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(user_body);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Reset one local user's password without echoing credential data. */
static int handle_user_password_reset(struct jg_management *management,
                                      const struct management_request *request,
                                      const struct remote_address *remote,
                                      uint64_t user_id,
                                      uint64_t now,
                                      uint8_t *output,
                                      size_t output_size,
                                      size_t *written)
{
    static const char *const fields[] = {
        "revision",
        "password",
        "force_password_change",
    };
    struct authenticated_actor actor;
    struct jg_account_user user;
    const char *password = NULL;
    uint64_t revision = 0U;
    bool force_password_change = false;
    json_t *body = NULL;
    json_t *user_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    password = required_string(request->body, "password", JG_AUTH_PASSWORD_MIN,
                               JG_AUTH_PASSWORD_MAX);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision) ||
        password == NULL ||
        !required_boolean(request->body, "force_password_change",
                          &force_password_change)) {
        return respond_error(400, "invalid_body",
                             "The password-reset request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_user_reset_password(
        management->database, user_id, revision, (const uint8_t *)password,
        strlen(password), &management->password_policy, force_password_change,
        now, &user);
    if (result == -ENOENT) {
        return respond_error(404, "user_not_found",
                             "The local user was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -ESTALE) {
        return respond_error(409, "revision_conflict",
                             "The local user has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE) {
        return respond_error(400, "invalid_password",
                             "The replacement password is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "password_reset_failed",
                             "The password could not be replaced.",
                             request->request_id, output, output_size, written);
    }
    result =
        append_user_audit(management, request, remote, &actor,
                          "user.password_reset", true, revision, &user, now);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The password was replaced, but its audit record could not be "
            "stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    user_body = user_json(&user);
    if (body == NULL || user_body == NULL ||
        json_object_set(body, "user", user_body) != 0) {
        json_decref(user_body);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(user_body);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Return one authenticated stable page of API-token metadata. */
static int handle_tokens_list(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct jg_account_token_record *tokens = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t offset = 0U;
    uint64_t total = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "offset", JG_ACCOUNT_TOKEN_PAGE_MAX,
                         &offset, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The token pagination parameters are not valid.",
                             request->request_id, output, output_size, written);
    }
    tokens = calloc(limit, sizeof(*tokens));
    if (tokens == NULL) {
        return -ENOMEM;
    }
    result = jg_account_token_list(management->database, offset, tokens, limit,
                                   &count, &total);
    if (result != 0) {
        free(tokens);
        return respond_error(500, "tokens_unavailable",
                             "The API tokens could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = token_json(&tokens[index]);

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
         json_object_set(body, "tokens", items) != 0)) {
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
    free(tokens);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Issue and display one new scoped API token exactly once. */
static int handle_token_issue(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    static const char *const fields[] = {
        "user_id",    "name",           "scopes",
        "expires_at", "source_network", "requests_per_minute",
    };
    struct authenticated_actor actor;
    struct jg_account_token_config config;
    struct jg_account_api_token issued;
    struct jg_account_token_record token;
    const char *name = NULL;
    const char *scopes = NULL;
    uint64_t user_id = 0U;
    uint64_t rate = 0U;
    json_t *body = NULL;
    json_t *token_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    (void)memset(&config, 0, sizeof(config));
    (void)memset(&issued, 0, sizeof(issued));
    name =
        required_string(request->body, "name", 1U, JG_ACCOUNT_TOKEN_NAME_MAX);
    scopes =
        required_string(request->body, "scopes", 1U, JG_ACCESS_SCOPE_TEXT_MAX);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "user_id", &user_id) ||
        name == NULL || scopes == NULL ||
        jg_access_scope_parse(scopes, &config.permissions) != 0 ||
        !required_optional_timestamp(request->body, "expires_at",
                                     &config.expires_at) ||
        parse_source_network(request->body, "source_network", &config) != 0 ||
        !required_identifier(request->body, "requests_per_minute", &rate) ||
        rate > UINT32_MAX) {
        return respond_error(400, "invalid_body",
                             "The API-token request is not valid.",
                             request->request_id, output, output_size, written);
    }
    config.name = name;
    config.requests_per_minute = (uint32_t)rate;
    result = jg_account_token_issue(management->database, user_id, &config, now,
                                    &issued);
    if (result == -ENOENT) {
        return respond_error(404, "user_not_found",
                             "The token owner was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EACCES) {
        return respond_error(
            403, "invalid_scopes",
            "The token scopes exceed the owner's current permissions.",
            request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -ERANGE) {
        return respond_error(400, "invalid_token",
                             "The API-token properties are not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "token_issue_failed",
                             "The API token could not be issued.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_account_token_get(management->database, issued.token_id, &token);
    if (result == 0) {
        result = append_token_audit(management, request, remote, &actor,
                                    "token.create", false, 0U, &token, now);
    }
    if (result != 0) {
        sodium_memzero(&issued, sizeof(issued));
        return respond_error(
            500, "audit_failure",
            "The token was issued, but its audit record could not be stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    token_body = token_json(&token);
    if (body == NULL || token_body == NULL ||
        json_object_set_new(token_body, "secret", json_string(issued.secret)) !=
            0 ||
        json_object_set(body, "token", token_body) != 0) {
        json_decref(token_body);
        json_decref(body);
        sodium_memzero(&issued, sizeof(issued));
        return -ENOMEM;
    }
    json_decref(token_body);
    result = encode_response(201, body, NULL, output, output_size, written);
    sodium_memzero(&issued, sizeof(issued));
    return result;
}

/** @brief Revoke one API token idempotently and audit the action. */
static int handle_token_revoke(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t token_id,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    struct authenticated_actor actor;
    struct jg_account_token_record previous;
    struct jg_account_token_record token;
    json_t *body = NULL;
    json_t *token_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The token-revocation request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_token_get(management->database, token_id, &previous);
    if (result == -ENOENT) {
        return respond_error(404, "token_not_found",
                             "The API token was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = jg_account_token_revoke(management->database, token_id, now);
    }
    if (result == 0) {
        result = jg_account_token_get(management->database, token_id, &token);
    }
    if (result != 0) {
        return respond_error(500, "token_revoke_failed",
                             "The API token could not be revoked.",
                             request->request_id, output, output_size, written);
    }
    result =
        append_token_audit(management, request, remote, &actor, "token.revoke",
                           true, previous.revision, &token, now);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The token was revoked, but its audit record could not be stored.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    token_body = token_json(&token);
    if (body == NULL || token_body == NULL ||
        json_object_set(body, "token", token_body) != 0) {
        json_decref(token_body);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(token_body);
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

/** @brief Return the current authenticated browser identity. */
static int handle_session(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    struct jg_account_identity identity;
    json_t *body = NULL;
    json_t *user = NULL;
    int result = authenticate_session(management, request, remote, false, now,
                                      &identity);

    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "A valid authenticated session is required.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    user = identity_json(&identity);
    if (body == NULL || user == NULL ||
        json_object_set(body, "user", user) != 0) {
        json_decref(user);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(user);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Revoke the current authenticated browser session. */
static int handle_logout(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct jg_account_identity identity;
    const struct session_result session = {
        .set_session = NULL,
        .clear_session = true,
    };
    json_t *body = NULL;
    int result =
        authenticate_session(management, request, remote, true, now, &identity);

    (void)identity;
    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "A valid authenticated session is required.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_session_revoke(management->database,
                                       (const uint8_t *)request->session,
                                       strlen(request->session));
    if (result != 0) {
        return respond_error(500, "logout_failure",
                             "The session could not be revoked.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "logged_out", json_true()) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, &session, output, output_size, written);
}

/** @brief Begin TOTP enrollment for the authenticated user. */
static int handle_totp_provision(struct jg_management *management,
                                 const struct management_request *request,
                                 const struct remote_address *remote,
                                 uint64_t now,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written)
{
    struct jg_account_identity identity;
    struct jg_account_totp_provisioning provisioning;
    json_t *body = NULL;
    int result =
        authenticate_session(management, request, remote, true, now, &identity);

    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "A valid authenticated session is required.",
                             request->request_id, output, output_size, written);
    }
    if (json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_body",
                             "The enrollment request must be empty.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_account_totp_provision(management->database, identity.user_id,
                                  management->totp_key, now, &provisioning);
    if (result == -EEXIST) {
        return respond_error(409, "totp_enabled",
                             "TOTP is already enabled for this user.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "totp_failure",
                             "TOTP enrollment could not be started.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "secret", json_string(provisioning.secret)) !=
            0) {
        json_decref(body);
        sodium_memzero(&provisioning, sizeof(provisioning));
        return -ENOMEM;
    }
    result = encode_response(200, body, NULL, output, output_size, written);
    sodium_memzero(&provisioning, sizeof(provisioning));
    return result;
}

/** @brief Read one required six-digit JSON TOTP value. */
static int request_totp_code(json_t *body, uint32_t *code)
{
    static const char *const fields[] = {
        "code",
    };
    json_t *value = json_object_get(body, "code");
    json_int_t number = 0;

    if (!fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) ||
        !json_is_integer(value)) {
        return -EINVAL;
    }
    number = json_integer_value(value);
    if (number < 0 || number >= 1000000) {
        return -EINVAL;
    }
    *code = (uint32_t)number;
    return 0;
}

/** @brief Confirm TOTP and return newly issued recovery codes once. */
static int handle_totp_confirm(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    struct jg_account_identity identity;
    struct jg_account_recovery_codes recovery;
    const struct session_result session = {
        .set_session = NULL,
        .clear_session = true,
    };
    uint32_t code = 0U;
    json_t *body = NULL;
    json_t *codes = NULL;
    int result =
        authenticate_session(management, request, remote, true, now, &identity);

    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "A valid authenticated session is required.",
                             request->request_id, output, output_size, written);
    }
    result = request_totp_code(request->body, &code);
    if (result != 0) {
        return respond_error(400, "invalid_body",
                             "A six-digit TOTP code is required.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_account_totp_confirm(management->database, identity.user_id,
                                management->totp_key, code, now, &recovery);
    if (result == -EACCES) {
        return respond_error(401, "invalid_totp",
                             "The supplied TOTP code is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(409, "totp_failure",
                             "TOTP enrollment could not be confirmed.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    codes = json_array();
    for (size_t index = 0U; body != NULL && codes != NULL &&
                            index < JG_ACCOUNT_RECOVERY_CODE_COUNT;
         ++index) {
        if (json_array_append_new(codes, json_string(recovery.codes[index])) !=
            0) {
            json_decref(codes);
            codes = NULL;
        }
    }
    if (body == NULL || codes == NULL ||
        json_object_set(body, "recovery_codes", codes) != 0) {
        json_decref(codes);
        json_decref(body);
        sodium_memzero(&recovery, sizeof(recovery));
        return -ENOMEM;
    }
    json_decref(codes);
    result = encode_response(200, body, &session, output, output_size, written);
    sodium_memzero(&recovery, sizeof(recovery));
    return result;
}

/** @brief Verify current TOTP and disable multifactor authentication. */
static int handle_totp_disable(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    struct jg_account_identity identity;
    struct jg_account_identity verified;
    const struct session_result session = {
        .set_session = NULL,
        .clear_session = true,
    };
    uint32_t code = 0U;
    json_t *body = NULL;
    int result =
        authenticate_session(management, request, remote, true, now, &identity);

    if (result != 0) {
        return respond_error(401, "authentication_required",
                             "A valid authenticated session is required.",
                             request->request_id, output, output_size, written);
    }
    result = request_totp_code(request->body, &code);
    if (result == 0) {
        identity.mfa_complete = false;
        result = jg_account_totp_authenticate(management->database, &identity,
                                              management->totp_key, code, now,
                                              &verified);
    }
    if (result != 0) {
        return respond_error(
            result == -EINVAL ? 400 : 401,
            result == -EINVAL ? "invalid_body" : "invalid_totp",
            result == -EINVAL ? "A six-digit TOTP code is required."
                              : "The supplied TOTP code is not valid.",
            request->request_id, output, output_size, written);
    }
    result = jg_account_totp_disable(management->database, verified.user_id);
    if (result != 0) {
        return respond_error(500, "totp_failure", "TOTP could not be disabled.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "totp_enabled", json_false()) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, &session, output, output_size, written);
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
    uint64_t destination_rule_id = 0U;
    uint64_t domain_rule_id = 0U;
    uint64_t token_id = 0U;
    uint64_t user_id = 0U;

    if (state_change && (request->bearer[0U] == '\0' || authentication_path) &&
        !origin_valid(request->origin, request->host)) {
        return respond_error(403, "invalid_origin",
                             "The request origin is not permitted.",
                             request->request_id, output, output_size, written);
    }
    if (strcmp(request->path, "/api/v1/status") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_status(management, request, remote, now, output,
                             output_size, written);
    }
    if (strcmp(request->path, "/api/v1/metrics") == 0 &&
        strcmp(request->method, "GET") == 0) {
        return handle_metrics(management, request, remote, now, output,
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
    if (strcmp(request->method, "PATCH") == 0 &&
        collection_path_identifier(request->path, "/api/v1/users/", "",
                                   &user_id)) {
        return handle_user_update(management, request, remote, user_id, now,
                                  output, output_size, written);
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
    return respond_error(404, "not_found",
                         "The requested API resource was not found.",
                         request->request_id, output, output_size, written);
}

/** @brief Parse, authenticate, and dispatch one management JSON envelope. */
int jg_management_process(struct jg_management *management,
                          const uint8_t *request_data,
                          size_t request_size,
                          uint8_t *response,
                          size_t response_size,
                          size_t *written)
{
    struct management_request request;
    struct remote_address remote;
    json_t *root = NULL;
    uint64_t now = 0U;
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
    result = parse_remote_address(request.remote_address, &remote);
    if (result != 0) {
        result = respond_error(
            400, "invalid_request", "The remote address is not valid.",
            request.request_id, response, response_size, written);
    }
    if (result == 0) {
        result = current_time(&now);
    }
    if (result == 0) {
        result = dispatch_request(management, &request, &remote, now, response,
                                  response_size, written);
    }
    json_decref(root);
    return result;
}

/** @brief Clear the TOTP key and release management state. */
void jg_management_destroy(struct jg_management *management)
{
    if (management == NULL) {
        return;
    }
    sodium_memzero(management, sizeof(*management));
    free(management);
}
