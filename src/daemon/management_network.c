/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_network.c
 * @brief Transactional inline-network configuration management.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "database_internal.h"
#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/database.h"
#include "janusgate/network.h"
#include "netd_client.h"

/** @brief Return the stable external name for one network failure mode. */
static const char *network_failure_mode_name(
    enum jg_network_failure_mode failure_mode)
{
    if (failure_mode == JG_NETWORK_FAIL_OPEN) {
        return "fail_open";
    }
    if (failure_mode == JG_NETWORK_FAIL_CLOSED) {
        return "fail_closed";
    }
    return NULL;
}

/** @brief Parse one stable external network failure mode. */
static enum jg_network_failure_mode parse_network_failure_mode(const char *name)
{
    if (name != NULL && strcmp(name, "fail_open") == 0) {
        return JG_NETWORK_FAIL_OPEN;
    }
    if (name != NULL && strcmp(name, "fail_closed") == 0) {
        return JG_NETWORK_FAIL_CLOSED;
    }
    return 0;
}

/** @brief Compare every semantic field of two network configurations. */
bool network_configs_equal(const struct jg_network_config *left,
                           const struct jg_network_config *right)
{
    return strcmp(left->bridge, right->bridge) == 0 &&
           strcmp(left->ingress, right->ingress) == 0 &&
           strcmp(left->egress, right->egress) == 0 &&
           strcmp(left->management, right->management) == 0 &&
           left->bridge_mtu == right->bridge_mtu &&
           left->queue_first == right->queue_first &&
           left->queue_count == right->queue_count &&
           left->queue_length == right->queue_length &&
           left->failure_mode == right->failure_mode &&
           left->stp == right->stp &&
           left->multicast_snooping == right->multicast_snooping &&
           left->queue_cpu_fanout == right->queue_cpu_fanout;
}

/** @brief Convert one validated network configuration to public JSON. */
static json_t *network_config_json(const struct jg_network_config *config)
{
    const char *failure_mode = network_failure_mode_name(config->failure_mode);
    json_t *body = json_object();

    if (failure_mode == NULL || body == NULL ||
        json_object_set_new(body, "bridge", json_string(config->bridge)) != 0 ||
        json_object_set_new(body, "ingress", json_string(config->ingress)) !=
            0 ||
        json_object_set_new(body, "egress", json_string(config->egress)) != 0 ||
        json_object_set_new(body, "management",
                            json_string(config->management)) != 0 ||
        json_object_set_new(body, "bridge_mtu",
                            json_integer((json_int_t)config->bridge_mtu)) !=
            0 ||
        json_object_set_new(body, "queue_first",
                            json_integer((json_int_t)config->queue_first)) !=
            0 ||
        json_object_set_new(body, "queue_count",
                            json_integer((json_int_t)config->queue_count)) !=
            0 ||
        json_object_set_new(body, "queue_length",
                            json_integer((json_int_t)config->queue_length)) !=
            0 ||
        json_object_set_new(body, "failure_mode", json_string(failure_mode)) !=
            0 ||
        json_object_set_new(body, "stp", json_boolean(config->stp)) != 0 ||
        json_object_set_new(body, "multicast_snooping",
                            json_boolean(config->multicast_snooping)) != 0 ||
        json_object_set_new(body, "queue_cpu_fanout",
                            json_boolean(config->queue_cpu_fanout)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert one helper transaction snapshot to public JSON. */
static json_t *network_state_json(const struct jg_network_state *state)
{
    json_t *body = json_object();
    json_t *confirmed = state->has_confirmed
                            ? network_config_json(&state->confirmed)
                            : json_null();
    json_t *pending = state->pending
                          ? network_config_json(&state->pending_config)
                          : json_null();
    int result = 0;

    if (body == NULL || confirmed == NULL || pending == NULL ||
        json_object_set(body, "confirmed", confirmed) != 0 ||
        json_object_set(body, "pending", pending) != 0 ||
        json_object_set_new(
            body, "confirmation_seconds_remaining",
            json_integer((json_int_t)state->confirmation_seconds_remaining)) !=
            0) {
        result = -ENOMEM;
    }
    json_decref(pending);
    json_decref(confirmed);
    if (result != 0) {
        json_decref(body);
        body = NULL;
    }
    return body;
}

/** @brief Parse one complete proposed inline-network configuration. */
static int parse_network_config_request(json_t *body,
                                        struct jg_network_config *config)
{
    static const char *const fields[] = {
        "bridge",
        "ingress",
        "egress",
        "management",
        "bridge_mtu",
        "queue_first",
        "queue_count",
        "queue_length",
        "failure_mode",
        "stp",
        "multicast_snooping",
        "queue_cpu_fanout",
    };
    const char *bridge =
        required_string(body, "bridge", 1U, JG_INTERFACE_NAME_MAX);
    const char *ingress =
        required_string(body, "ingress", 1U, JG_INTERFACE_NAME_MAX);
    const char *egress =
        required_string(body, "egress", 1U, JG_INTERFACE_NAME_MAX);
    const char *management =
        required_string(body, "management", 1U, JG_INTERFACE_NAME_MAX);
    const char *failure_mode = required_string(body, "failure_mode", 1U, 11U);
    uint64_t bridge_mtu = 0U;
    uint64_t queue_first = 0U;
    uint64_t queue_count = 0U;
    uint64_t queue_length = 0U;

    (void)memset(config, 0, sizeof(*config));
    if (!fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) ||
        bridge == NULL || ingress == NULL || egress == NULL ||
        management == NULL ||
        !required_unsigned(body, "bridge_mtu", UINT32_MAX, &bridge_mtu) ||
        !required_unsigned(body, "queue_first", UINT16_MAX, &queue_first) ||
        !required_unsigned(body, "queue_count", UINT16_MAX, &queue_count) ||
        !required_unsigned(body, "queue_length", UINT32_MAX, &queue_length) ||
        failure_mode == NULL || !required_boolean(body, "stp", &config->stp) ||
        !required_boolean(body, "multicast_snooping",
                          &config->multicast_snooping) ||
        !required_boolean(body, "queue_cpu_fanout",
                          &config->queue_cpu_fanout)) {
        return -EINVAL;
    }
    (void)snprintf(config->bridge, sizeof(config->bridge), "%s", bridge);
    (void)snprintf(config->ingress, sizeof(config->ingress), "%s", ingress);
    (void)snprintf(config->egress, sizeof(config->egress), "%s", egress);
    (void)snprintf(config->management, sizeof(config->management), "%s",
                   management);
    config->bridge_mtu = (uint32_t)bridge_mtu;
    config->queue_first = (uint16_t)queue_first;
    config->queue_count = (uint16_t)queue_count;
    config->queue_length = (uint32_t)queue_length;
    config->failure_mode = parse_network_failure_mode(failure_mode);
    return jg_network_config_validate(config);
}

/** @brief Parse one revision-bound network staging request. */
static int parse_network_apply_request(json_t *body,
                                       uint64_t *revision,
                                       struct jg_network_config *config)
{
    static const char *const fields[] = {
        "revision",
        "configuration",
    };
    json_t *configuration = json_object_get(body, "configuration");

    if (!fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) ||
        !required_identifier(body, "revision", revision) ||
        !json_is_object(configuration)) {
        return -EINVAL;
    }
    return parse_network_config_request(configuration, config);
}

/** @brief Parse one exact revision-bound network operation request. */
static int parse_network_revision_request(json_t *body, uint64_t *revision)
{
    static const char *const fields[] = {
        "revision",
    };

    return fields_allowed(body, fields, sizeof(fields) / sizeof(fields[0U])) &&
                   required_identifier(body, "revision", revision)
               ? 0
               : -EINVAL;
}

/** @brief Append one authenticated network transaction outcome. */
static int append_network_audit(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                const struct authenticated_actor *actor,
                                const char *action,
                                const struct jg_network_config *config,
                                int operation_result,
                                uint64_t previous_revision,
                                bool has_new_revision,
                                uint64_t new_revision,
                                uint64_t now)
{
    char source_address[INET6_ADDRSTRLEN];
    json_t *details = network_config_json(config);
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL) {
        result = -EINVAL;
    }
    if (result == 0 &&
        (details == NULL ||
         json_object_set_new(details, "operation_result",
                             json_integer(operation_result)) != 0)) {
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
            .action = action,
            .object_type = "network_configuration",
            .object_id = "active",
            .details = encoded,
            .has_previous_revision = true,
            .previous_revision = previous_revision,
            .has_new_revision = has_new_revision,
            .new_revision = new_revision,
            .success = operation_result == 0,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Return the persistent inline-network configuration. */
int handle_network_get(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_network_config record;
    struct jg_network_state state;
    json_t *body = NULL;
    json_t *configuration = NULL;
    json_t *runtime = NULL;
    int state_result = 0;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_STATUS_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The network request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_database_load_network_config_record(management->database, &record);
    if (result == -ENOENT) {
        return respond_error(404, "network_unconfigured",
                             "Network configuration has not been initialized.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "network_unavailable",
                             "Network configuration could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    configuration = network_config_json(&record.config);
    state_result = jg_netd_client_state(&state);
    runtime = state_result == 0 ? network_state_json(&state) : json_null();
    if (body == NULL || configuration == NULL || runtime == NULL ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)record.revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)record.updated_at)) != 0 ||
        json_object_set_new(body, "runtime_available",
                            json_boolean(state_result == 0)) != 0 ||
        json_object_set(body, "configuration", configuration) != 0 ||
        json_object_set(body, "runtime", runtime) != 0) {
        result = -ENOMEM;
    }
    json_decref(runtime);
    json_decref(configuration);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Validate a proposed network configuration without applying it. */
int handle_network_validate(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    struct authenticated_actor actor;
    struct jg_network_config config;
    json_t *body = NULL;
    json_t *configuration = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_NETWORK_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = request->query[0U] == '\0'
                 ? parse_network_config_request(request->body, &config)
                 : -EINVAL;
    if (result != 0) {
        return respond_error(400, "invalid_network",
                             "The proposed network configuration is invalid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_netd_client_validate(&config);
    if (result == -EINVAL) {
        return respond_error(
            422, "network_validation_failed",
            "The proposed configuration is not valid on this system.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(
            503, "network_validation_unavailable",
            "Live network validation is temporarily unavailable.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    configuration = network_config_json(&config);
    if (body == NULL || configuration == NULL ||
        json_object_set_new(body, "valid", json_true()) != 0 ||
        json_object_set(body, "configuration", configuration) != 0) {
        json_decref(configuration);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(configuration);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Stage one revision-bound network change for confirmation. */
int handle_network_apply(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_network_config record;
    struct jg_network_config config;
    struct jg_network_state state;
    json_t *body = NULL;
    json_t *runtime = NULL;
    uint64_t revision = 0U;
    int audit_result = 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_NETWORK_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result =
        request->query[0U] == '\0'
            ? parse_network_apply_request(request->body, &revision, &config)
            : -EINVAL;
    if (result != 0) {
        return respond_error(400, "invalid_network",
                             "The network staging request is invalid.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_database_load_network_config_record(management->database, &record);
    if (result != 0) {
        return respond_error(
            result == -ENOENT ? 404 : 500,
            result == -ENOENT ? "network_unconfigured" : "network_unavailable",
            result == -ENOENT
                ? "Network configuration has not been initialized."
                : "Network configuration could not be read.",
            request->request_id, output, output_size, written);
    }
    if (record.revision != revision) {
        audit_result = append_network_audit(management, request, remote, &actor,
                                            "network.apply", &config, -EAGAIN,
                                            record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(409, "revision_conflict",
                             "The network configuration revision has changed.",
                             request->request_id, output, output_size, written);
    }
    result = jg_netd_client_apply(&config);
    if (result != 0) {
        audit_result = append_network_audit(management, request, remote, &actor,
                                            "network.apply", &config, result,
                                            record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        if (result == -EBUSY) {
            return respond_error(
                409, "network_transaction_pending",
                "Another network transaction is awaiting confirmation.",
                request->request_id, output, output_size, written);
        }
        if (result == -EINVAL || result == -ERANGE) {
            return respond_error(
                422, "network_apply_rejected",
                "The proposed configuration is not valid on this system.",
                request->request_id, output, output_size, written);
        }
        return respond_error(503, "network_apply_unavailable",
                             "The network change could not be staged.",
                             request->request_id, output, output_size, written);
    }
    result = jg_netd_client_state(&state);
    if (result != 0 || !state.pending) {
        (void)jg_netd_client_rollback();
        if (result == 0) {
            result = -EPROTO;
        }
        audit_result = append_network_audit(management, request, remote, &actor,
                                            "network.apply", &config, result,
                                            record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(503, "network_state_unavailable",
                             "The pending network state could not be verified.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    runtime = network_state_json(&state);
    if (body == NULL || runtime == NULL ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)record.revision)) != 0 ||
        json_object_set(body, "runtime", runtime) != 0) {
        result = -ENOMEM;
    }
    json_decref(runtime);
    if (result == 0) {
        audit_result = append_network_audit(management, request, remote, &actor,
                                            "network.apply", &config, 0,
                                            record.revision, false, 0U, now);
        if (audit_result != 0) {
            (void)jg_netd_client_rollback();
            result = audit_result;
        }
    }
    if (result != 0) {
        if (result == -ENOMEM) {
            (void)jg_netd_client_rollback();
        }
        json_decref(body);
        return respond_error(
            500, result == -ENOMEM ? "serialization_failure" : "audit_failure",
            result == -ENOMEM
                ? "The pending network state could not be encoded."
                : "The network change could not be audited.",
            request->request_id, output, output_size, written);
    }
    return encode_response(202, body, NULL, output, output_size, written);
}

/** @brief Confirm one pending network change and persist its revision. */
int handle_network_confirm(struct jg_management *management,
                           const struct management_request *request,
                           const struct remote_address *remote,
                           uint64_t now,
                           uint8_t *output,
                           size_t output_size,
                           size_t *written)
{
    struct authenticated_actor actor;
    const struct management_operation_origin operation_origin = {
        .request = request,
        .remote = remote,
        .actor = &actor,
        .action = "network.confirm",
    };
    struct jg_database_network_config record;
    struct jg_database_network_config updated;
    struct jg_database_network_config recovered;
    struct jg_network_state state;
    json_t *body = NULL;
    json_t *configuration = NULL;
    json_t *runtime = NULL;
    uint64_t revision = 0U;
    int audit_result = 0;
    int recovery_result = 0;
    int state_result = 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_NETWORK_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = request->query[0U] == '\0'
                 ? parse_network_revision_request(request->body, &revision)
                 : -EINVAL;
    if (result != 0) {
        return respond_error(400, "invalid_request",
                             "The network confirmation request is invalid.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_database_load_network_config_record(management->database, &record);
    if (result != 0) {
        return respond_error(
            result == -ENOENT ? 404 : 500,
            result == -ENOENT ? "network_unconfigured" : "network_unavailable",
            result == -ENOENT
                ? "Network configuration has not been initialized."
                : "Network configuration could not be read.",
            request->request_id, output, output_size, written);
    }
    if (record.revision != revision) {
        audit_result = append_network_audit(
            management, request, remote, &actor, "network.confirm",
            &record.config, -EAGAIN, record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(409, "revision_conflict",
                             "The network configuration revision has changed.",
                             request->request_id, output, output_size, written);
    }
    result = jg_netd_client_state(&state);
    if (result != 0 || !state.pending) {
        if (result == 0) {
            result = -EBUSY;
        }
        audit_result = append_network_audit(
            management, request, remote, &actor, "network.confirm",
            &record.config, result, record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(
            result == -EBUSY ? 409 : 503,
            result == -EBUSY ? "network_transaction_absent"
                             : "network_state_unavailable",
            result == -EBUSY
                ? "No network transaction is awaiting confirmation."
                : "The pending network state could not be read.",
            request->request_id, output, output_size, written);
    }
    result =
        start_network_recovery(management, &record.config,
                               &state.pending_config, &operation_origin, now);
    if (result == -EBUSY) {
        return respond_error(
            409, "operation_conflict",
            "Another recoverable management operation is in progress.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(503, "recovery_unavailable",
                             "Durable network recovery could not be prepared.",
                             request->request_id, output, output_size, written);
    }
    result = jg_database_replace_network_config(
        management->database, &state.pending_config, record.revision, &updated);
    if (result != 0) {
        const int operation_result = result;

        recovery_result =
            abort_recovery_operation(management, operation_result);

        audit_result = append_network_audit(
            management, request, remote, &actor, "network.confirm",
            &state.pending_config,
            recovery_result == -EIO ? -EIO : operation_result, record.revision,
            false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(
            recovery_result == -EIO       ? 503
            : operation_result == -EAGAIN ? 409
                                          : 500,
            recovery_result == -EIO       ? "network_recovery_failure"
            : operation_result == -EAGAIN ? "revision_conflict"
                                          : "network_store_failure",
            recovery_result == -EIO
                ? "The failed network confirmation could not be recovered."
            : operation_result == -EAGAIN
                ? "The network configuration revision has changed."
                : "The pending network configuration could not be "
                  "persisted.",
            request->request_id, output, output_size, written);
    }
    result = jg_netd_client_confirm();
    if (result != 0) {
        const int operation_result = result;

        recovery_result =
            abort_recovery_operation(management, operation_result);
        state_result = jg_database_load_network_config_record(
            management->database, &recovered);
        audit_result = append_network_audit(
            management, request, remote, &actor, "network.confirm",
            &state.pending_config,
            recovery_result == -EIO ? -EIO : operation_result, record.revision,
            state_result == 0,
            state_result == 0 ? recovered.revision : updated.revision, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network recovery could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(
            recovery_result == -EIO ? 503 : 500,
            recovery_result == -EIO ? "network_recovery_failure"
                                    : "network_confirm_failure",
            recovery_result == -EIO
                ? "The network change could not be restored consistently."
                : "The network change was not confirmed and was restored.",
            request->request_id, output, output_size, written);
    }
    audit_result = jg_database_transaction_begin(management->database);
    if (audit_result == 0) {
        audit_result = append_network_audit(
            management, request, remote, &actor, "network.confirm",
            &updated.config, 0, record.revision, true, updated.revision, now);
    }
    audit_result = finish_recovery_operation(management, audit_result);
    if (audit_result != 0) {
        return respond_error(500, "audit_failure",
                             "The network confirmation was not committed.",
                             request->request_id, output, output_size, written);
    }
    state_result = jg_netd_client_state(&state);
    body = json_object();
    configuration = network_config_json(&updated.config);
    runtime = state_result == 0 ? network_state_json(&state) : json_null();
    if (body == NULL || configuration == NULL || runtime == NULL ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)updated.revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)updated.updated_at)) !=
            0 ||
        json_object_set_new(body, "runtime_available",
                            json_boolean(state_result == 0)) != 0 ||
        json_object_set(body, "configuration", configuration) != 0 ||
        json_object_set(body, "runtime", runtime) != 0) {
        result = -ENOMEM;
    }
    json_decref(runtime);
    json_decref(configuration);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Roll back one pending network change without persistence. */
int handle_network_rollback(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_network_config record;
    struct jg_network_state state;
    json_t *body = NULL;
    json_t *runtime = NULL;
    uint64_t revision = 0U;
    int audit_result = 0;
    int state_result = 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_NETWORK_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    result = request->query[0U] == '\0'
                 ? parse_network_revision_request(request->body, &revision)
                 : -EINVAL;
    if (result != 0) {
        return respond_error(400, "invalid_request",
                             "The network rollback request is invalid.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_database_load_network_config_record(management->database, &record);
    if (result != 0) {
        return respond_error(
            result == -ENOENT ? 404 : 500,
            result == -ENOENT ? "network_unconfigured" : "network_unavailable",
            result == -ENOENT
                ? "Network configuration has not been initialized."
                : "Network configuration could not be read.",
            request->request_id, output, output_size, written);
    }
    if (record.revision != revision) {
        audit_result = append_network_audit(
            management, request, remote, &actor, "network.rollback",
            &record.config, -EAGAIN, record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(409, "revision_conflict",
                             "The network configuration revision has changed.",
                             request->request_id, output, output_size, written);
    }
    result = jg_netd_client_state(&state);
    if (result != 0 || !state.pending) {
        if (result == 0) {
            result = -EBUSY;
        }
        audit_result = append_network_audit(
            management, request, remote, &actor, "network.rollback",
            &record.config, result, record.revision, false, 0U, now);
        if (audit_result != 0) {
            return respond_error(500, "audit_failure",
                                 "The network attempt could not be audited.",
                                 request->request_id, output, output_size,
                                 written);
        }
        return respond_error(
            result == -EBUSY ? 409 : 503,
            result == -EBUSY ? "network_transaction_absent"
                             : "network_state_unavailable",
            result == -EBUSY ? "No network transaction is awaiting rollback."
                             : "The pending network state could not be read.",
            request->request_id, output, output_size, written);
    }
    result = jg_netd_client_rollback();
    audit_result = append_network_audit(
        management, request, remote, &actor, "network.rollback",
        &state.pending_config, result, record.revision, false, 0U, now);
    if (audit_result != 0) {
        return respond_error(500, "audit_failure",
                             "The network rollback could not be audited.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(
            result == -EBUSY ? 409 : 500,
            result == -EBUSY ? "network_transaction_absent"
                             : "network_recovery_failure",
            result == -EBUSY
                ? "No network transaction is awaiting rollback."
                : "The network change could not be restored consistently.",
            request->request_id, output, output_size, written);
    }
    state_result = jg_netd_client_state(&state);
    body = json_object();
    runtime = state_result == 0 ? network_state_json(&state) : json_null();
    if (body == NULL || runtime == NULL ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)record.revision)) != 0 ||
        json_object_set_new(body, "rolled_back", json_true()) != 0 ||
        json_object_set_new(body, "runtime_available",
                            json_boolean(state_result == 0)) != 0 ||
        json_object_set(body, "runtime", runtime) != 0) {
        result = -ENOMEM;
    }
    json_decref(runtime);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}
