/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_policy_modes.c
 * @brief Global, group, and client-scoped policy enforcement management.
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

#include "janusgate/access.h"
#include "janusgate/audit.h"
#include "janusgate/database.h"
#include "janusgate/policy.h"

/** @brief Return the public spelling for one enforcement mode. */
static const char *enforcement_name(enum jg_policy_enforcement enforcement)
{
    return enforcement == JG_POLICY_ENFORCE
               ? "enforce"
               : (enforcement == JG_POLICY_OBSERVE ? "observe" : NULL);
}

/** @brief Parse one required enforcement mode. */
static bool parse_enforcement(const char *text,
                              enum jg_policy_enforcement *enforcement)
{
    if (text == NULL || enforcement == NULL) {
        return false;
    }
    if (strcmp(text, "enforce") == 0) {
        *enforcement = JG_POLICY_ENFORCE;
        return true;
    }
    if (strcmp(text, "observe") == 0) {
        *enforcement = JG_POLICY_OBSERVE;
        return true;
    }
    return false;
}

/** @brief Parse one exact colon-separated MAC address. */
static int parse_mac(const char *text, uint8_t address[6U])
{
    if (text == NULL || strlen(text) != 17U) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < 6U; ++index) {
        const size_t offset = index * 3U;
        uint8_t high = 0U;
        uint8_t low = 0U;

        if (hexadecimal_value(text[offset], &high) != 0 ||
            hexadecimal_value(text[offset + 1U], &low) != 0 ||
            (index < 5U && text[offset + 2U] != ':')) {
            return -EINVAL;
        }
        address[index] = (uint8_t)((high << 4U) | low);
    }
    return 0;
}

/** @brief Parse one client, network, or VLAN policy selector. */
static int parse_scope(json_t *object, struct jg_policy_scope *scope)
{
    static const char *const address_fields[] = {"type", "address"};
    static const char *const network_fields[] = {
        "type",
        "address",
        "prefix_length",
    };
    static const char *const vlan_fields[] = {"type", "vlan"};
    const char *type = required_string(object, "type", 3U, 4U);
    const char *address = NULL;
    uint64_t number = 0U;
    int family = AF_UNSPEC;

    (void)memset(scope, 0, sizeof(*scope));
    if (!json_is_object(object) || type == NULL) {
        return -EINVAL;
    }
    if (strcmp(type, "mac") == 0) {
        address = required_string(object, "address", 17U, 17U);
        if (!fields_allowed(object, address_fields, 2U) ||
            parse_mac(address, scope->value.mac) != 0) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_MAC;
        return 0;
    }
    if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv6") == 0) {
        address = required_string(object, "address", 2U, INET6_ADDRSTRLEN - 1U);
        family = strcmp(type, "ipv4") == 0 ? AF_INET : AF_INET6;
        if (!fields_allowed(object, network_fields, 3U) || address == NULL ||
            !required_unsigned(object, "prefix_length",
                               family == AF_INET ? 32U : 128U, &number) ||
            inet_pton(family, address, scope->value.network.address) != 1) {
            return -EINVAL;
        }
        scope->type =
            family == AF_INET ? JG_POLICY_SCOPE_IPV4 : JG_POLICY_SCOPE_IPV6;
        scope->value.network.prefix_length = (uint8_t)number;
        return 0;
    }
    if (strcmp(type, "vlan") == 0) {
        if (!fields_allowed(object, vlan_fields, 2U) ||
            !required_unsigned(object, "vlan", 4094U, &number)) {
            return -EINVAL;
        }
        scope->type = JG_POLICY_SCOPE_VLAN;
        scope->value.vlan_id = (uint16_t)number;
        return 0;
    }
    return -EINVAL;
}

/** @brief Serialize one client-scoped selector. */
static json_t *scope_json(const struct jg_policy_scope *scope)
{
    char address[INET6_ADDRSTRLEN];
    char mac[18U];
    const char *type = NULL;
    json_t *body = json_object();
    int result = 0;

    if (scope->type == JG_POLICY_SCOPE_MAC) {
        type = "mac";
    } else if (scope->type == JG_POLICY_SCOPE_IPV4) {
        type = "ipv4";
    } else if (scope->type == JG_POLICY_SCOPE_IPV6) {
        type = "ipv6";
    } else if (scope->type == JG_POLICY_SCOPE_VLAN) {
        type = "vlan";
    }
    if (type == NULL || body == NULL ||
        json_object_set_new(body, "type", json_string(type)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0 && scope->type == JG_POLICY_SCOPE_MAC) {
        const int written = snprintf(
            mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
            scope->value.mac[0U], scope->value.mac[1U], scope->value.mac[2U],
            scope->value.mac[3U], scope->value.mac[4U], scope->value.mac[5U]);

        if (written != 17 ||
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
        json_object_set_new(body, "vlan", json_integer(scope->value.vlan_id)) !=
            0) {
        result = -ENOMEM;
    }
    if (result != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Append one policy-mode mutation to the tamper-evident audit. */
static int append_mode_audit(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             const struct authenticated_actor *actor,
                             const char *action,
                             const char *object_type,
                             const char *object_id,
                             bool has_previous_revision,
                             uint64_t previous_revision,
                             bool has_new_revision,
                             uint64_t new_revision,
                             json_t *details,
                             uint64_t now)
{
    char source_address[INET6_ADDRSTRLEN];
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source_address,
                  sizeof(source_address)) == NULL ||
        details == NULL) {
        return -EINVAL;
    }
    encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
    if (encoded == NULL) {
        return -ENOMEM;
    }
    event = (struct jg_audit_event){
        .occurred_at = now,
        .actor_type = actor_audit_type(actor),
        .has_actor_id = actor_has_identifier(actor),
        .actor_id = actor->actor_id,
        .source = source_address,
        .action = action,
        .object_type = object_type,
        .object_id = object_id,
        .details = encoded,
        .has_previous_revision = has_previous_revision,
        .previous_revision = previous_revision,
        .has_new_revision = has_new_revision,
        .new_revision = new_revision,
        .success = true,
        .request_id = request->request_id,
    };
    result = jg_database_audit_append(management->database, &event, NULL);
    free(encoded);
    return result;
}

/** @brief Publish a mode mutation and complete its audit transaction. */
static int finish_mode_mutation(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                const struct authenticated_actor *actor,
                                const char *action,
                                const char *object_type,
                                const char *object_id,
                                bool has_previous_revision,
                                uint64_t previous_revision,
                                bool has_new_revision,
                                uint64_t new_revision,
                                json_t *details,
                                uint64_t now,
                                bool *published,
                                uint64_t *generation)
{
    int result = management_publish_policy_change(management, now, published,
                                                  generation);

    if (result == 0 &&
        (json_object_set_new(details, "published", json_boolean(*published)) !=
             0 ||
         json_object_set_new(details, "policy_generation",
                             json_integer((json_int_t)*generation)) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = append_mode_audit(
            management, request, remote, actor, action, object_type, object_id,
            has_previous_revision, previous_revision, has_new_revision,
            new_revision, details, now);
    }
    return audited_mutation_finish(management, result, true);
}

/** @brief Serialize snapshot-wide policy enforcement. */
static json_t *global_mode_json(const struct jg_database_policy_config *config)
{
    const char *enforcement = enforcement_name(config->enforcement);
    json_t *body = json_object();

    if (enforcement == NULL || body == NULL ||
        json_object_set_new(body, "enforcement", json_string(enforcement)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)config->revision)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)config->updated_at)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Return or replace snapshot-wide policy enforcement. */
int handle_policy_global_mode(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    static const char *const fields[] = {"revision", "enforcement"};
    struct authenticated_actor actor;
    struct jg_database_policy_config config = {0};
    enum jg_policy_enforcement enforcement = JG_POLICY_ENFORCE;
    const bool updating = strcmp(request->method, "PUT") == 0;
    const char *mode = NULL;
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    json_t *body = NULL;
    int result = authenticate_actor(
        management, request, remote, updating,
        updating ? JG_ACCESS_POLICY_WRITE : JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' ||
        (!updating && strcmp(request->method, "GET") != 0)) {
        return respond_error(400, "invalid_request",
                             "The global policy-mode request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (!updating) {
        result = jg_database_load_policy_config(management->database, &config);
    } else {
        mode = required_string(request->body, "enforcement", 7U, 7U);
        if (!fields_allowed(request->body, fields, 2U) ||
            !required_identifier(request->body, "revision", &revision) ||
            !parse_enforcement(mode, &enforcement)) {
            return respond_error(
                400, "invalid_body", "The global policy mode is not valid.",
                request->request_id, output, output_size, written);
        }
        if (management->runtime == NULL) {
            return respond_error(
                503, "policy_unavailable",
                "The active policy is temporarily unavailable.",
                request->request_id, output, output_size, written);
        }
        result = audited_mutation_begin(management);
        if (result == 0) {
            mutation_open = true;
            result = jg_database_replace_policy_config(
                management->database, enforcement, revision, &config);
        }
        if (result != 0 && mutation_open) {
            result = audited_mutation_check(management, result);
            mutation_open = false;
        }
        if (result == 0) {
            body = global_mode_json(&config);
            if (body == NULL) {
                result = -ENOMEM;
            }
        }
        if (result == 0) {
            result = finish_mode_mutation(
                management, request, remote, &actor, "policy.mode.update",
                "policy_mode", "global", true, revision, true, config.revision,
                body, now, &published, &generation);
        } else if (mutation_open) {
            result = audited_mutation_finish(management, result, true);
        }
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The global policy mode has changed.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_mode_failed",
                             "The global policy mode could not be processed.",
                             request->request_id, output, output_size, written);
    }
    if (body == NULL) {
        body = global_mode_json(&config);
    }
    if (body == NULL ||
        (updating &&
         (json_object_set_new(body, "published", json_boolean(published)) !=
              0 ||
          json_object_set_new(body, "policy_generation",
                              json_integer((json_int_t)generation)) != 0))) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(updating && !published ? 202 : 200, body, NULL,
                           output, output_size, written);
}

/** @brief Serialize one persistent policy group. */
static json_t *group_json(const struct jg_database_policy_group *group)
{
    const char *enforcement = enforcement_name(group->enforcement);
    json_t *body = json_object();

    if (enforcement == NULL || body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)group->id)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)group->revision)) != 0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)group->created_at)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)group->updated_at)) != 0 ||
        json_object_set_new(body, "name", json_string(group->name)) != 0 ||
        json_object_set_new(body, "description",
                            json_string(group->description)) != 0 ||
        json_object_set_new(body, "enforcement", json_string(enforcement)) !=
            0 ||
        json_object_set_new(body, "enabled", json_boolean(group->enabled)) !=
            0 ||
        json_object_set_new(
            body, "domain_rule_count",
            json_integer((json_int_t)group->domain_rule_count)) != 0 ||
        json_object_set_new(
            body, "destination_rule_count",
            json_integer((json_int_t)group->destination_rule_count)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Parse one complete policy-group request. */
static int parse_group_config(json_t *body,
                              bool updating,
                              struct jg_database_policy_group_config *config,
                              uint64_t *revision)
{
    static const char *const create_fields[] = {
        "name",
        "description",
        "enforcement",
        "enabled",
    };
    static const char *const update_fields[] = {
        "revision", "name", "description", "enforcement", "enabled",
    };
    const char *enforcement = NULL;

    (void)memset(config, 0, sizeof(*config));
    *revision = 0U;
    config->name =
        required_string(body, "name", 1U, JG_DATABASE_POLICY_NAME_MAX);
    config->description = optional_string(body, "description",
                                          JG_DATABASE_POLICY_DESCRIPTION_MAX);
    enforcement = required_string(body, "enforcement", 7U, 7U);
    if ((updating && !fields_allowed(body, update_fields, 5U)) ||
        (!updating && !fields_allowed(body, create_fields, 4U)) ||
        config->name == NULL || config->description == NULL ||
        !parse_enforcement(enforcement, &config->enforcement) ||
        !required_boolean(body, "enabled", &config->enabled) ||
        (updating && !required_identifier(body, "revision", revision))) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Read one exact policy group. */
static int get_group(struct jg_database *database,
                     uint64_t group_id,
                     struct jg_database_policy_group *group)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_policy_groups(database, group_id - 1U, 1U,
                                                group, &count, &has_more);

    (void)has_more;
    return result == 0 && (count != 1U || group->id != group_id) ? -ENOENT
                                                                 : result;
}

/** @brief Return one stable page of policy groups. */
static int list_groups(struct jg_management *management,
                       const struct management_request *request,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written)
{
    struct jg_database_policy_group *groups = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    json_t *body = NULL;
    json_t *items = NULL;
    int result =
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_POLICY_PAGE_MAX, &after_id, &limit);

    if (result != 0) {
        return respond_error(400, "invalid_query",
                             "The policy-group query is not valid.",
                             request->request_id, output, output_size, written);
    }
    groups = calloc(limit, sizeof(*groups));
    body = json_object();
    items = json_array();
    if (groups == NULL || body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = jg_database_list_policy_groups(
            management->database, after_id, limit, groups, &count, &has_more);
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = group_json(&groups[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            json_decref(item);
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "groups", items) != 0 ||
         json_object_set_new(
             body, "next_after_id",
             has_more && count > 0U
                 ? json_integer((json_int_t)groups[count - 1U].id)
                 : json_null()) != 0)) {
        result = -ENOMEM;
    }
    free(groups);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_groups_failed",
                             "Policy groups could not be listed.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Create one policy group and publish its mode. */
static int create_group(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        const struct authenticated_actor *actor,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    struct jg_database_policy_group_config config;
    struct jg_database_policy_group created = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    char object_id[32U];
    json_t *body = NULL;
    int result = parse_group_config(request->body, false, &config, &revision);

    (void)revision;
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The policy-group request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        mutation_open = true;
        result = jg_database_create_policy_group(management->database, &config,
                                                 &created);
    }
    if (result != 0 && mutation_open) {
        result = audited_mutation_check(management, result);
        mutation_open = false;
    }
    if (result == 0) {
        body = group_json(&created);
        if (body == NULL || snprintf(object_id, sizeof(object_id), "%llu",
                                     (unsigned long long)created.id) <= 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = finish_mode_mutation(
            management, request, remote, actor, "policy.group.create",
            "policy_group", object_id, false, 0U, true, created.revision, body,
            now, &published, &generation);
    } else if (mutation_open) {
        result = audited_mutation_finish(management, result, true);
    }
    if (result == -EEXIST || result == -EINVAL) {
        json_decref(body);
        return respond_error(409, "policy_group_conflict",
                             "The policy group conflicts with existing state.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_group_create_failed",
                             "The policy group could not be created.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(published ? 201 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief List or create policy rule groups. */
int handle_policy_groups(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    const bool creating = strcmp(request->method, "POST") == 0;
    int result = authenticate_actor(
        management, request, remote, creating,
        creating ? JG_ACCESS_POLICY_WRITE : JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (!creating && strcmp(request->method, "GET") != 0) {
        return respond_error(400, "invalid_request",
                             "The policy-group request is not valid.",
                             request->request_id, output, output_size, written);
    }
    return creating
               ? create_group(management, request, remote, &actor, now, output,
                              output_size, written)
               : list_groups(management, request, output, output_size, written);
}

/** @brief Replace one policy group at its exact revision. */
static int update_group(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        const struct authenticated_actor *actor,
                        uint64_t group_id,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    struct jg_database_policy_group_config config;
    struct jg_database_policy_group updated = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    char object_id[32U];
    json_t *body = NULL;
    int result = parse_group_config(request->body, true, &config, &revision);

    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The policy-group update is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        mutation_open = true;
        result = jg_database_update_policy_group(management->database, group_id,
                                                 &config, revision, &updated);
    }
    if (result != 0 && mutation_open) {
        result = audited_mutation_check(management, result);
        mutation_open = false;
    }
    if (result == 0) {
        body = group_json(&updated);
        if (body == NULL || snprintf(object_id, sizeof(object_id), "%llu",
                                     (unsigned long long)group_id) <= 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = finish_mode_mutation(
            management, request, remote, actor, "policy.group.update",
            "policy_group", object_id, true, revision, true, updated.revision,
            body, now, &published, &generation);
    } else if (mutation_open) {
        result = audited_mutation_finish(management, result, true);
    }
    if (result == -ENOENT) {
        return respond_error(404, "policy_group_not_found",
                             "The policy group was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN || result == -EEXIST) {
        return respond_error(409, "policy_group_conflict",
                             "The policy group has changed or conflicts.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_group_update_failed",
                             "The policy group could not be updated.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Remove one policy group and its assigned rules. */
static int delete_group(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        const struct authenticated_actor *actor,
                        uint64_t group_id,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct jg_database_policy_group removed = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    char object_id[32U];
    json_t *body = NULL;
    int result = 0;

    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields, 1U) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The policy-group deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_group(management->database, group_id, &removed);
    if (result == 0) {
        result = audited_mutation_begin(management);
        mutation_open = result == 0;
    }
    if (result == 0) {
        result = jg_database_delete_policy_group(management->database, group_id,
                                                 revision);
    }
    if (result != 0 && mutation_open) {
        result = audited_mutation_check(management, result);
        mutation_open = false;
    }
    if (result == 0) {
        body = group_json(&removed);
        if (body == NULL || snprintf(object_id, sizeof(object_id), "%llu",
                                     (unsigned long long)group_id) <= 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = finish_mode_mutation(management, request, remote, actor,
                                      "policy.group.delete", "policy_group",
                                      object_id, true, revision, false, 0U,
                                      body, now, &published, &generation);
    } else if (mutation_open) {
        result = audited_mutation_finish(management, result, true);
    }
    if (result == -ENOENT) {
        return respond_error(404, "policy_group_not_found",
                             "The policy group was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The policy group has changed.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_group_delete_failed",
                             "The policy group could not be removed.",
                             request->request_id, output, output_size, written);
    }
    if (json_object_set_new(body, "deleted", json_true()) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Replace or remove one policy rule group. */
int handle_policy_group(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t group_id,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    struct authenticated_actor actor;
    const bool updating = strcmp(request->method, "PATCH") == 0;
    const bool deleting = strcmp(request->method, "DELETE") == 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (!updating && !deleting) {
        return respond_error(400, "invalid_request",
                             "The policy-group request is not valid.",
                             request->request_id, output, output_size, written);
    }
    return updating ? update_group(management, request, remote, &actor,
                                   group_id, now, output, output_size, written)
                    : delete_group(management, request, remote, &actor,
                                   group_id, now, output, output_size, written);
}

/** @brief Serialize one persistent client-scoped policy mode. */
static json_t *scope_mode_json(const struct jg_database_policy_scope_mode *mode)
{
    const char *enforcement = enforcement_name(mode->enforcement);
    json_t *body = json_object();
    json_t *scope = scope_json(&mode->scope);

    if (enforcement == NULL || body == NULL || scope == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)mode->id)) !=
            0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)mode->revision)) != 0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)mode->created_at)) != 0 ||
        json_object_set_new(body, "updated_at",
                            json_integer((json_int_t)mode->updated_at)) != 0 ||
        json_object_set_new(body, "name", json_string(mode->name)) != 0 ||
        json_object_set_new(body, "enforcement", json_string(enforcement)) !=
            0 ||
        json_object_set_new(body, "enabled", json_boolean(mode->enabled)) !=
            0 ||
        json_object_set(body, "scope", scope) != 0) {
        json_decref(scope);
        json_decref(body);
        return NULL;
    }
    json_decref(scope);
    return body;
}

/** @brief Parse one complete client-scoped policy-mode request. */
static int parse_scope_mode_config(
    json_t *body,
    bool updating,
    struct jg_database_policy_scope_mode_config *config,
    uint64_t *revision)
{
    static const char *const create_fields[] = {
        "name",
        "enforcement",
        "scope",
        "enabled",
    };
    static const char *const update_fields[] = {
        "revision", "name", "enforcement", "scope", "enabled",
    };
    const char *enforcement = NULL;
    int result = 0;

    (void)memset(config, 0, sizeof(*config));
    *revision = 0U;
    config->name =
        required_string(body, "name", 1U, JG_DATABASE_POLICY_NAME_MAX);
    enforcement = required_string(body, "enforcement", 7U, 7U);
    if ((updating && !fields_allowed(body, update_fields, 5U)) ||
        (!updating && !fields_allowed(body, create_fields, 4U)) ||
        config->name == NULL ||
        !parse_enforcement(enforcement, &config->enforcement) ||
        !required_boolean(body, "enabled", &config->enabled) ||
        (updating && !required_identifier(body, "revision", revision))) {
        return -EINVAL;
    }
    result = parse_scope(json_object_get(body, "scope"), &config->scope);
    return result;
}

/** @brief Read one exact client-scoped policy mode. */
static int get_scope_mode(struct jg_database *database,
                          uint64_t mode_id,
                          struct jg_database_policy_scope_mode *mode)
{
    size_t count = 0U;
    bool has_more = false;
    int result = jg_database_list_policy_scope_modes(database, mode_id - 1U, 1U,
                                                     mode, &count, &has_more);

    (void)has_more;
    return result == 0 && (count != 1U || mode->id != mode_id) ? -ENOENT
                                                               : result;
}

/** @brief Return one stable page of client-scoped policy modes. */
static int list_scope_modes(struct jg_management *management,
                            const struct management_request *request,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    struct jg_database_policy_scope_mode *modes = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    json_t *body = NULL;
    json_t *items = NULL;
    int result =
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_POLICY_PAGE_MAX, &after_id, &limit);

    if (result != 0) {
        return respond_error(400, "invalid_query",
                             "The policy-scope query is not valid.",
                             request->request_id, output, output_size, written);
    }
    modes = calloc(limit, sizeof(*modes));
    body = json_object();
    items = json_array();
    if (modes == NULL || body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = jg_database_list_policy_scope_modes(
            management->database, after_id, limit, modes, &count, &has_more);
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = scope_mode_json(&modes[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            json_decref(item);
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "scope_modes", items) != 0 ||
         json_object_set_new(
             body, "next_after_id",
             has_more && count > 0U
                 ? json_integer((json_int_t)modes[count - 1U].id)
                 : json_null()) != 0)) {
        result = -ENOMEM;
    }
    free(modes);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_scopes_failed",
                             "Policy scopes could not be listed.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Create one client-scoped mode and publish it. */
static int create_scope_mode(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             const struct authenticated_actor *actor,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    struct jg_database_policy_scope_mode_config config;
    struct jg_database_policy_scope_mode created = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    char object_id[32U];
    json_t *body = NULL;
    int result =
        parse_scope_mode_config(request->body, false, &config, &revision);

    (void)revision;
    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The policy-scope request is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        mutation_open = true;
        result = jg_database_create_policy_scope_mode(management->database,
                                                      &config, &created);
    }
    if (result != 0 && mutation_open) {
        result = audited_mutation_check(management, result);
        mutation_open = false;
    }
    if (result == 0) {
        body = scope_mode_json(&created);
        if (body == NULL || snprintf(object_id, sizeof(object_id), "%llu",
                                     (unsigned long long)created.id) <= 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = finish_mode_mutation(
            management, request, remote, actor, "policy.scope.create",
            "policy_scope", object_id, false, 0U, true, created.revision, body,
            now, &published, &generation);
    } else if (mutation_open) {
        result = audited_mutation_finish(management, result, true);
    }
    if (result == -EEXIST || result == -EINVAL) {
        json_decref(body);
        return respond_error(409, "policy_scope_conflict",
                             "The policy scope conflicts with existing state.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_scope_create_failed",
                             "The policy scope could not be created.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(published ? 201 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief List or create client-scoped policy modes. */
int handle_policy_scope_modes(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    const bool creating = strcmp(request->method, "POST") == 0;
    int result = authenticate_actor(
        management, request, remote, creating,
        creating ? JG_ACCESS_POLICY_WRITE : JG_ACCESS_POLICY_READ, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (!creating && strcmp(request->method, "GET") != 0) {
        return respond_error(400, "invalid_request",
                             "The policy-scope request is not valid.",
                             request->request_id, output, output_size, written);
    }
    return creating ? create_scope_mode(management, request, remote, &actor,
                                        now, output, output_size, written)
                    : list_scope_modes(management, request, output, output_size,
                                       written);
}

/** @brief Replace one client-scoped policy mode. */
static int update_scope_mode(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             const struct authenticated_actor *actor,
                             uint64_t mode_id,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    struct jg_database_policy_scope_mode_config config;
    struct jg_database_policy_scope_mode updated = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    char object_id[32U];
    json_t *body = NULL;
    int result =
        parse_scope_mode_config(request->body, true, &config, &revision);

    if (request->query[0U] != '\0' || result != 0) {
        return respond_error(400, "invalid_body",
                             "The policy-scope update is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = audited_mutation_begin(management);
    if (result == 0) {
        mutation_open = true;
        result = jg_database_update_policy_scope_mode(
            management->database, mode_id, &config, revision, &updated);
    }
    if (result != 0 && mutation_open) {
        result = audited_mutation_check(management, result);
        mutation_open = false;
    }
    if (result == 0) {
        body = scope_mode_json(&updated);
        if (body == NULL || snprintf(object_id, sizeof(object_id), "%llu",
                                     (unsigned long long)mode_id) <= 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = finish_mode_mutation(
            management, request, remote, actor, "policy.scope.update",
            "policy_scope", object_id, true, revision, true, updated.revision,
            body, now, &published, &generation);
    } else if (mutation_open) {
        result = audited_mutation_finish(management, result, true);
    }
    if (result == -ENOENT) {
        return respond_error(404, "policy_scope_not_found",
                             "The policy scope was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN || result == -EEXIST) {
        return respond_error(409, "policy_scope_conflict",
                             "The policy scope has changed or conflicts.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_scope_update_failed",
                             "The policy scope could not be updated.",
                             request->request_id, output, output_size, written);
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Remove one client-scoped policy mode. */
static int delete_scope_mode(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             const struct authenticated_actor *actor,
                             uint64_t mode_id,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    static const char *const fields[] = {"revision"};
    struct jg_database_policy_scope_mode removed = {0};
    uint64_t revision = 0U;
    uint64_t generation = 0U;
    bool published = false;
    bool mutation_open = false;
    char object_id[32U];
    json_t *body = NULL;
    int result = 0;

    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields, 1U) ||
        !required_identifier(request->body, "revision", &revision)) {
        return respond_error(400, "invalid_body",
                             "The policy-scope deletion is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (management->runtime == NULL) {
        return respond_error(503, "policy_unavailable",
                             "The active policy is temporarily unavailable.",
                             request->request_id, output, output_size, written);
    }
    result = get_scope_mode(management->database, mode_id, &removed);
    if (result == 0) {
        result = audited_mutation_begin(management);
        mutation_open = result == 0;
    }
    if (result == 0) {
        result = jg_database_delete_policy_scope_mode(management->database,
                                                      mode_id, revision);
    }
    if (result != 0 && mutation_open) {
        result = audited_mutation_check(management, result);
        mutation_open = false;
    }
    if (result == 0) {
        body = scope_mode_json(&removed);
        if (body == NULL || snprintf(object_id, sizeof(object_id), "%llu",
                                     (unsigned long long)mode_id) <= 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = finish_mode_mutation(management, request, remote, actor,
                                      "policy.scope.delete", "policy_scope",
                                      object_id, true, revision, false, 0U,
                                      body, now, &published, &generation);
    } else if (mutation_open) {
        result = audited_mutation_finish(management, result, true);
    }
    if (result == -ENOENT) {
        return respond_error(404, "policy_scope_not_found",
                             "The policy scope was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EAGAIN) {
        return respond_error(409, "revision_conflict",
                             "The policy scope has changed.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        json_decref(body);
        return respond_error(500, "policy_scope_delete_failed",
                             "The policy scope could not be removed.",
                             request->request_id, output, output_size, written);
    }
    if (json_object_set_new(body, "deleted", json_true()) != 0) {
        json_decref(body);
        return -ENOMEM;
    }
    return encode_response(published ? 200 : 202, body, NULL, output,
                           output_size, written);
}

/** @brief Replace or remove one client-scoped policy mode. */
int handle_policy_scope_mode(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t mode_id,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written)
{
    struct authenticated_actor actor;
    const bool updating = strcmp(request->method, "PATCH") == 0;
    const bool deleting = strcmp(request->method, "DELETE") == 0;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_POLICY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (!updating && !deleting) {
        return respond_error(400, "invalid_request",
                             "The policy-scope request is not valid.",
                             request->request_id, output, output_size, written);
    }
    return updating
               ? update_scope_mode(management, request, remote, &actor, mode_id,
                                   now, output, output_size, written)
               : delete_scope_mode(management, request, remote, &actor, mode_id,
                                   now, output, output_size, written);
}
