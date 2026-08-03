/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_identity.c
 * @brief Identity, authentication, and account management.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "database_internal.h"
#include "janusgate/access.h"
#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/auth.h"
#include "janusgate/database.h"

/** @brief Resolve the one fixed role represented by an identity mask. */
static const char *identity_role_name(uint32_t permissions)
{
    static const enum jg_access_role roles[] = {
        JG_ACCESS_ROLE_ADMINISTRATOR,
        JG_ACCESS_ROLE_OPERATOR,
        JG_ACCESS_ROLE_AUDITOR,
    };

    for (size_t index = 0U; index < sizeof(roles) / sizeof(roles[0U]);
         ++index) {
        if (permissions == jg_access_role_permissions(roles[index])) {
            return management_role_name(roles[index]);
        }
    }
    return NULL;
}

/** @brief Convert an authenticated identity to stable response fields. */
static json_t *identity_json(const struct jg_account_identity *identity)
{
    const char *role = identity_role_name(identity->permissions);
    json_t *user = json_object();

    if (role == NULL || user == NULL ||
        json_object_set_new(user, "id",
                            json_integer((json_int_t)identity->user_id)) != 0 ||
        json_object_set_new(user, "username",
                            json_string(identity->username)) != 0 ||
        json_object_set_new(user, "role", json_string(role)) != 0 ||
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
const char *management_role_name(enum jg_access_role role)
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
enum jg_access_role management_parse_role(const char *name)
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

/** @brief Convert one administrative user record to public JSON fields. */
static json_t *user_json(const struct jg_account_user *user)
{
    const char *role = management_role_name(user->role);
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
    const char *role = management_role_name(user->role);
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
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
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
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
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
            management->database, password_identity,
            management->secrets->totp_key, (uint32_t)code, now, identity);
    }
    if (recovery[0U] != '\0') {
        return jg_account_recovery_authenticate(
            management->database, password_identity, (const uint8_t *)recovery,
            strlen(recovery), now, identity);
    }
    return -ENOMSG;
}

/** @brief Build one exact IPv4 or bounded IPv6 login source key. */
static int login_source_key(const struct remote_address *remote,
                            uint8_t source[16U])
{
    (void)memset(source, 0, 16U);
    if (remote->family == JG_POLICY_ADDRESS_IPV4) {
        (void)memcpy(source, remote->address, 4U);
        return 0;
    }
    if (remote->family == JG_POLICY_ADDRESS_IPV6) {
        (void)memcpy(source, remote->address, 8U);
        return 0;
    }
    return -EINVAL;
}

/** @brief Enforce bounded source and appliance-wide login windows. */
static int login_rate_accept(struct jg_management *management,
                             const struct remote_address *remote,
                             uint64_t now)
{
    struct login_rate_slot *slot = NULL;
    struct login_rate_slot *oldest = &management->login_rates[0U];
    uint8_t source[16U];
    int result = login_source_key(remote, source);

    if (result != 0) {
        return result;
    }
    for (size_t index = 0U; index < MANAGEMENT_LOGIN_RATE_SLOT_COUNT; ++index) {
        struct login_rate_slot *candidate = &management->login_rates[index];

        if ((candidate->family == remote->family &&
             memcmp(candidate->source, source, sizeof(source)) == 0) ||
            candidate->last_request == 0U) {
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
    if (slot->family != remote->family ||
        memcmp(slot->source, source, sizeof(source)) != 0 ||
        now < slot->window_started_at || now - slot->window_started_at >= 60U) {
        *slot = (struct login_rate_slot){
            .family = remote->family,
            .window_started_at = now,
        };
        (void)memcpy(slot->source, source, sizeof(source));
    }
    slot->last_request = now;
    if (slot->requests >= MANAGEMENT_LOGIN_SOURCE_RATE) {
        return -EAGAIN;
    }
    if (now < management->login_global_window_started_at ||
        now - management->login_global_window_started_at >= 60U) {
        management->login_global_window_started_at = now;
        management->login_global_requests = 0U;
    }
    if (management->login_global_requests >= MANAGEMENT_LOGIN_GLOBAL_RATE) {
        return -EAGAIN;
    }
    ++slot->requests;
    ++management->login_global_requests;
    return 0;
}

/** @brief Authenticate a password and return one browser session. */
int handle_login(struct jg_management *management,
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
    result = login_rate_accept(management, remote, now);
    if (result == -EAGAIN) {
        (void)jg_log_emit(JG_LOG_WARNING, "authentication",
                          "authentication.rate_limited", request->request_id,
                          "Browser login rate limit reached", NULL);
        return respond_error(429, "authentication_limited",
                             "Authentication is temporarily limited.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(400, "invalid_request",
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
    if (result == -ENOMSG) {
        return respond_error(401, "mfa_required",
                             "A second authentication factor is required.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        (void)jg_log_emit(JG_LOG_WARNING, "authentication",
                          "authentication.retry_limited", request->request_id,
                          "Account password retry delay is active", NULL);
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
        management_alert_authentication_failed(management);
        return respond_error(401, "invalid_credentials",
                             "The supplied credentials are not valid.",
                             request->request_id, output, output_size, written);
    }
    return issue_session(management, request, remote, &identity, now, output,
                         output_size, written);
}

/** @brief Report whether the appliance still requires initial setup. */
int handle_authentication_state(struct jg_management *management,
                                const struct management_request *request,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written)
{
    struct jg_account_user user;
    size_t count = 0U;
    uint64_t total = 0U;
    json_t *body = NULL;
    int result = 0;

    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The authentication-state request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_user_list(management->database, 0U, &user, 1U, &count,
                                  &total);
    if (result != 0) {
        return respond_error(
            503, "authentication_state_unavailable",
            "The appliance setup state could not be determined.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL || json_object_set_new(body, "setup_required",
                                            json_boolean(total == 0U)) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Consume bootstrap access and create the first administrator. */
int handle_bootstrap(struct jg_management *management,
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

/** @brief Persist authenticated activity without competing with a restore. */
static int record_actor_activity(struct jg_management *management,
                                 const struct management_request *request,
                                 const char *session,
                                 uint64_t token_id,
                                 uint64_t now)
{
    const bool best_effort = strcmp(request->method, "GET") == 0;
    bool mutation_active = false;
    int result = 0;

    if (best_effort) {
        if (management_degraded_reasons(management) != 0U ||
            management_mutation_begin(management) != 0) {
            return 0;
        }
        mutation_active = true;
    }
    if (session != NULL) {
        result = jg_account_session_touch(management->database,
                                          (const uint8_t *)session,
                                          strlen(session), now);
    } else {
        result = jg_account_token_touch(management->database, token_id, now);
    }
    if (mutation_active) {
        management_mutation_end(management);
    }
    return best_effort ? 0 : result;
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
    int result = 0;

    if (session_size != JG_AUTH_SECRET_TEXT_SIZE - 1U ||
        (require_csrf && csrf_size != JG_AUTH_SECRET_TEXT_SIZE - 1U)) {
        return -EACCES;
    }
    result = jg_account_session_validate(
        management->database, (const uint8_t *)request->session, session_size,
        require_csrf ? (const uint8_t *)request->csrf : NULL,
        require_csrf ? csrf_size : 0U, require_csrf, now,
        MANAGEMENT_SESSION_INACTIVITY, remote->family, remote->address,
        identity);
    if (result == 0) {
        result = record_actor_activity(management, request, request->session,
                                       0U, now);
    }
    return result;
}

/** @brief Change the current user's password and rotate its web session. */
int handle_password_change(struct jg_management *management,
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
    struct jg_account_user user = {0};
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
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_user_reset_password(
            management->database, session_identity.user_id,
            session_identity.revision, (const uint8_t *)new_password,
            strlen(new_password), &management->password_policy, false, now,
            &user);
    }
    result = audited_mutation_check(management, result);
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
        .kind = AUTHENTICATED_ACTOR_USER,
    };
    result = append_user_audit(management, request, remote, &actor,
                               "user.password_change", true,
                               session_identity.revision, &user, now);
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The password change and its audit record were not committed.",
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
int authenticate_actor(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       bool state_change,
                       uint32_t required_permissions,
                       uint64_t now,
                       struct authenticated_actor *actor)
{
    const bool has_session = request->session[0U] != '\0';
    const bool has_bearer = request->bearer[0U] != '\0';
    const bool has_certificate = request->client_certificate[0U] != '\0';
    uint8_t certificate_fingerprint[32U];
    uint32_t requests_per_minute = 0U;
    uint64_t token_id = 0U;
    int result = 0;

    (void)memset(actor, 0, sizeof(*actor));
    (void)memset(certificate_fingerprint, 0, sizeof(certificate_fingerprint));
    if (request->local_administrator) {
        if (has_session || has_bearer || has_certificate) {
            return -EACCES;
        }
        actor->identity.permissions = JG_ACCESS_PERMISSION_ALL;
        actor->identity.mfa_complete = true;
        actor->kind = AUTHENTICATED_ACTOR_LOCAL;
        return 0;
    }
    if (has_session == has_bearer || has_certificate != has_bearer) {
        management_alert_authentication_failed(management);
        return -EACCES;
    }
    if (has_bearer) {
        if (strlen(request->bearer) != JG_AUTH_SECRET_TEXT_SIZE - 1U ||
            parse_certificate_fingerprint(request->client_certificate,
                                          certificate_fingerprint) != 0) {
            management_alert_authentication_failed(management);
            return -EACCES;
        }
        result = jg_account_token_validate(
            management->database, (const uint8_t *)request->bearer,
            strlen(request->bearer), now, remote->family, remote->address,
            &actor->identity, &token_id, &requests_per_minute);
        if (result == 0) {
            result = jg_account_mtls_mapping_authorize(
                management->database, certificate_fingerprint,
                actor->identity.user_id, now);
        }
        if (result == 0) {
            result = token_rate_accept(management, token_id,
                                       requests_per_minute, now);
        }
        if (result == 0) {
            result =
                record_actor_activity(management, request, NULL, token_id, now);
        }
        actor->kind = AUTHENTICATED_ACTOR_TOKEN;
        actor->actor_id = token_id;
    } else {
        result = authenticate_session(management, request, remote, state_change,
                                      now, &actor->identity);
        actor->actor_id = actor->identity.user_id;
        actor->kind = AUTHENTICATED_ACTOR_USER;
    }
    if (result == 0 && actor->identity.force_password_change) {
        result = -EPERM;
    }
    if (result == 0 && required_permissions != 0U &&
        !jg_access_grants(actor->identity.permissions, required_permissions)) {
        result = -EPERM;
    }
    if (result == -EACCES || result == -ENOENT || result == -EBADMSG) {
        management_alert_authentication_failed(management);
    }
    if (result != 0) {
        sodium_memzero(actor, sizeof(*actor));
    }
    sodium_memzero(certificate_fingerprint, sizeof(certificate_fingerprint));
    return result;
}

/** @brief Convert one actor-authentication result to a public API error. */
int respond_actor_error(int result,
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
    if (result == -EPERM) {
        return respond_error(403, "forbidden",
                             "The authenticated identity is not authorized.",
                             request->request_id, output, output_size, written);
    }
    return respond_error(401, "authentication_required",
                         "Valid authentication is required.",
                         request->request_id, output, output_size, written);
}

/** @brief Return one authenticated stable page of local users. */
int handle_users_list(struct jg_management *management,
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
int handle_user_create(struct jg_management *management,
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
    struct jg_account_user user = {0};
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
    role = management_parse_role(role_text);
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
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_user_create(
            management->database, username, (const uint8_t *)password,
            strlen(password), &management->password_policy, role,
            force_password_change, now, &user);
    }
    result = audited_mutation_check(management, result);
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
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The user creation and its audit record were not committed.",
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
int handle_user_update(struct jg_management *management,
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
    struct jg_account_user user = {0};
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
    update.role = management_parse_role(role_text);
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
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_user_update(management->database, user_id, revision,
                                        &update, now, &user);
    }
    result = audited_mutation_check(management, result);
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
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The user update and its audit record were not committed.",
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
int handle_user_password_reset(struct jg_management *management,
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
    struct jg_account_user user = {0};
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
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_user_reset_password(
            management->database, user_id, revision, (const uint8_t *)password,
            strlen(password), &management->password_policy,
            force_password_change, now, &user);
    }
    result = audited_mutation_check(management, result);
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
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The password replacement and its audit were not committed.",
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

/** @brief Administratively remove one local user's TOTP credentials. */
int handle_user_totp_disable(struct jg_management *management,
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
    };
    struct authenticated_actor actor;
    struct jg_account_user user = {0};
    uint64_t revision = 0U;
    json_t *body = NULL;
    json_t *user_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_ACCESS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The TOTP-reset request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_user_disable_totp(management->database, user_id,
                                              revision, &user);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "totp_not_found",
                             "The user has no active TOTP credential.",
                             request->request_id, output, output_size, written);
    }
    if (result == -ESTALE) {
        return respond_error(409, "revision_conflict",
                             "The local user has changed; reload and retry.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "totp_reset_failed",
                             "The TOTP credential could not be removed.",
                             request->request_id, output, output_size, written);
    }
    result = append_user_audit(management, request, remote, &actor,
                               "user.totp_disable", true, revision, &user, now);
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The TOTP removal and its audit record were not committed.",
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
int handle_tokens_list(struct jg_management *management,
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
int handle_token_issue(struct jg_management *management,
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
    struct jg_account_token_record token = {0};
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
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_token_issue(management->database, user_id, &config,
                                        now, &issued);
    }
    result = audited_mutation_check(management, result);
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
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        sodium_memzero(&issued, sizeof(issued));
        return respond_error(
            500, "audit_failure",
            "The token issuance and its audit record were not committed.",
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
int handle_token_revoke(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t token_id,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    struct authenticated_actor actor;
    struct jg_account_token_record previous = {0};
    struct jg_account_token_record token = {0};
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
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_account_token_revoke(management->database, token_id, now);
    }
    result = audited_mutation_check(management, result);
    if (result == 0) {
        result = jg_account_token_get(management->database, token_id, &token);
    }
    result = audited_mutation_check(management, result);
    if (result != 0) {
        return respond_error(500, "token_revoke_failed",
                             "The API token could not be revoked.",
                             request->request_id, output, output_size, written);
    }
    result =
        append_token_audit(management, request, remote, &actor, "token.revoke",
                           true, previous.revision, &token, now);
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The token revocation and its audit record were not committed.",
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

/** @brief Return the current authenticated browser identity. */
int handle_session(struct jg_management *management,
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
int handle_logout(struct jg_management *management,
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
int handle_totp_provision(struct jg_management *management,
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
    result = jg_account_totp_provision(management->database, identity.user_id,
                                       management->secrets->totp_key, now,
                                       &provisioning);
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
int handle_totp_confirm(struct jg_management *management,
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
    result = jg_account_totp_confirm(management->database, identity.user_id,
                                     management->secrets->totp_key, code, now,
                                     &recovery);
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
int handle_totp_disable(struct jg_management *management,
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
                                              management->secrets->totp_key,
                                              code, now, &verified);
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
