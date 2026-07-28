/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/access.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** One canonical scope name and its permission bit. */
struct scope_definition {
    const char *name;
    uint32_t permission;
};

/** Canonically ordered token-scope vocabulary. */
static const struct scope_definition scope_definitions[] = {
    {"status:read", JG_ACCESS_STATUS_READ},
    {"policy:read", JG_ACCESS_POLICY_READ},
    {"policy:write", JG_ACCESS_POLICY_WRITE},
    {"events:read", JG_ACCESS_EVENTS_READ},
    {"audit:read", JG_ACCESS_AUDIT_READ},
    {"operate", JG_ACCESS_OPERATE},
    {"network:write", JG_ACCESS_NETWORK_WRITE},
    {"access:write", JG_ACCESS_ACCESS_WRITE},
    {"security:write", JG_ACCESS_SECURITY_WRITE},
    {"backups:write", JG_ACCESS_BACKUPS_WRITE},
    {"system:write", JG_ACCESS_SYSTEM_WRITE},
    {"metrics:read", JG_ACCESS_METRICS_READ},
};

/** @brief Return the fixed permission mask for one backend role. */
uint32_t jg_access_role_permissions(enum jg_access_role role)
{
    switch (role) {
    case JG_ACCESS_ROLE_ADMINISTRATOR:
        return JG_ACCESS_PERMISSION_ALL;
    case JG_ACCESS_ROLE_OPERATOR:
        return JG_ACCESS_STATUS_READ | JG_ACCESS_POLICY_READ |
               JG_ACCESS_POLICY_WRITE | JG_ACCESS_EVENTS_READ |
               JG_ACCESS_OPERATE | JG_ACCESS_METRICS_READ;
    case JG_ACCESS_ROLE_AUDITOR:
        return JG_ACCESS_STATUS_READ | JG_ACCESS_POLICY_READ |
               JG_ACCESS_EVENTS_READ | JG_ACCESS_AUDIT_READ |
               JG_ACCESS_METRICS_READ;
    case JG_ACCESS_ROLE_NONE:
    default:
        return 0U;
    }
}

/** @brief Find one exact scope name in the fixed vocabulary. */
static uint32_t find_scope(const char *name, size_t name_size)
{
    for (size_t index = 0U;
         index < sizeof(scope_definitions) / sizeof(scope_definitions[0U]);
         ++index) {
        if (strlen(scope_definitions[index].name) == name_size &&
            memcmp(scope_definitions[index].name, name, name_size) == 0) {
            return scope_definitions[index].permission;
        }
    }
    return 0U;
}

/** @brief Parse one bounded comma-separated token-scope list. */
int jg_access_scope_parse(const char *text, uint32_t *permissions)
{
    size_t text_size = 0U;
    size_t offset = 0U;
    uint32_t parsed = 0U;

    if (text == NULL || permissions == NULL) {
        return -EINVAL;
    }
    *permissions = 0U;
    while (text_size <= JG_ACCESS_SCOPE_TEXT_MAX && text[text_size] != '\0') {
        ++text_size;
    }
    if (text_size == 0U || text_size > JG_ACCESS_SCOPE_TEXT_MAX) {
        return -EINVAL;
    }
    while (offset < text_size) {
        size_t scope_size = 0U;
        uint32_t permission = 0U;

        while (offset + scope_size < text_size &&
               text[offset + scope_size] != ',') {
            ++scope_size;
        }
        permission = find_scope(text + offset, scope_size);
        if (permission == 0U || (parsed & permission) != 0U) {
            return -EINVAL;
        }
        parsed |= permission;
        offset += scope_size;
        if (offset < text_size) {
            ++offset;
            if (offset == text_size) {
                return -EINVAL;
            }
        }
    }
    *permissions = parsed;
    return 0;
}

/** @brief Append one exact byte range to a bounded text output. */
static int append_text(char *output,
                       size_t output_size,
                       size_t *offset,
                       const char *text,
                       size_t text_size)
{
    if (text_size >= output_size || *offset > output_size - text_size - 1U) {
        return -ENOSPC;
    }
    (void)memcpy(output + *offset, text, text_size);
    *offset += text_size;
    output[*offset] = '\0';
    return 0;
}

/** @brief Format one permission mask in canonical scope order. */
int jg_access_scope_format(uint32_t permissions,
                           char *output,
                           size_t output_size)
{
    size_t offset = 0U;
    int result = 0;

    if (output == NULL || output_size == 0U || permissions == 0U ||
        (permissions & ~JG_ACCESS_PERMISSION_ALL) != 0U) {
        return -EINVAL;
    }
    output[0U] = '\0';
    for (size_t index = 0U;
         result == 0 &&
         index < sizeof(scope_definitions) / sizeof(scope_definitions[0U]);
         ++index) {
        if ((permissions & scope_definitions[index].permission) == 0U) {
            continue;
        }
        if (offset != 0U) {
            result = append_text(output, output_size, &offset, ",", 1U);
        }
        if (result == 0) {
            result = append_text(output, output_size, &offset,
                                 scope_definitions[index].name,
                                 strlen(scope_definitions[index].name));
        }
    }
    if (result != 0) {
        output[0U] = '\0';
    }
    return result;
}

/** @brief Check that every required permission is present and defined. */
bool jg_access_grants(uint32_t granted, uint32_t required)
{
    return required != 0U &&
           ((granted | required) & ~JG_ACCESS_PERMISSION_ALL) == 0U &&
           (granted & required) == required;
}
