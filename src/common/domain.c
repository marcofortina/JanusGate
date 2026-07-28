/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/domain.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <idn2.h>

/**
 * @brief Validate and lowercase an IDNA A-label domain.
 *
 * @param[in] input ASCII input.
 * @param[in] input_length Input bytes excluding a terminator.
 * @param[out] output Destination buffer.
 * @param[in] output_size Destination size.
 *
 * @return Zero or a negative errno-style value.
 */
static int normalize_ascii(const char *input,
                           size_t input_length,
                           char *output,
                           size_t output_size)
{
    size_t label_length = 0U;
    size_t index = 0U;

    if (input_length == 0U || input_length > JG_DOMAIN_NAME_MAX) {
        return -EINVAL;
    }
    if (output_size <= input_length) {
        return -ENOSPC;
    }

    for (index = 0U; index < input_length; ++index) {
        uint8_t value = (uint8_t)input[index];

        if (value == (uint8_t)'.') {
            if (label_length == 0U || label_length > JG_DOMAIN_LABEL_MAX) {
                return -EINVAL;
            }
            label_length = 0U;
            output[index] = '.';
            continue;
        }
        if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') {
            value = (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
        }
        if (!((value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
              (value >= (uint8_t)'0' && value <= (uint8_t)'9') ||
              value == (uint8_t)'-')) {
            return -EINVAL;
        }
        if ((label_length == 0U && value == (uint8_t)'-') ||
            (value == (uint8_t)'-' &&
             (index + 1U == input_length || input[index + 1U] == '.'))) {
            return -EINVAL;
        }
        ++label_length;
        if (label_length > JG_DOMAIN_LABEL_MAX) {
            return -EINVAL;
        }
        output[index] = (char)value;
    }
    if (label_length == 0U) {
        return -EINVAL;
    }
    output[input_length] = '\0';
    return 0;
}

/** @brief Normalize administrator-provided UTF-8 into a policy A-label. */
int jg_domain_normalize(const char *input, char *output, size_t output_size)
{
    uint8_t *alabel = NULL;
    char *trimmed = NULL;
    size_t input_length = 0U;
    size_t index = 0U;
    bool ascii_only = true;
    int idn_result = IDN2_OK;
    int result = -EINVAL;

    if (output == NULL || output_size == 0U) {
        return -EINVAL;
    }
    output[0] = '\0';
    if (input == NULL) {
        return -EINVAL;
    }

    input_length = strlen(input);
    if (input_length == 0U || input_length > JG_DOMAIN_NAME_MAX * 4U) {
        return -EINVAL;
    }
    if (input[input_length - 1U] == '.') {
        --input_length;
    }
    if (input_length == 0U) {
        return -EINVAL;
    }
    for (index = 0U; index < input_length; ++index) {
        if ((uint8_t)input[index] > UINT8_C(0x7f)) {
            ascii_only = false;
            break;
        }
    }
    if (ascii_only) {
        result = normalize_ascii(input, input_length, output, output_size);
        if (result != 0) {
            output[0] = '\0';
        }
        return result;
    }

    trimmed = malloc(input_length + 1U);
    if (trimmed == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(trimmed, input, input_length);
    trimmed[input_length] = '\0';

    idn_result = idn2_lookup_u8((const uint8_t *)trimmed, &alabel,
                                IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL |
                                    IDN2_USE_STD3_ASCII_RULES);
    free(trimmed);
    if (idn_result != IDN2_OK || alabel == NULL) {
        idn2_free(alabel);
        return -EINVAL;
    }
    result = normalize_ascii((const char *)alabel, strlen((const char *)alabel),
                             output, output_size);
    idn2_free(alabel);
    if (result != 0) {
        output[0] = '\0';
    }
    return result;
}

/** @brief Validate a lowercase normalized ASCII policy domain. */
bool jg_domain_is_normalized(const char *domain)
{
    char normalized[JG_DOMAIN_NAME_MAX + 1U];
    size_t length = 0U;

    if (domain == NULL) {
        return false;
    }
    length = strlen(domain);
    return normalize_ascii(domain, length, normalized, sizeof(normalized)) ==
               0 &&
           memcmp(domain, normalized, length + 1U) == 0;
}

/** @brief Match a policy domain exactly or at a DNS label boundary. */
bool jg_domain_matches(const char *name,
                       const char *rule,
                       bool include_subdomains)
{
    size_t name_length = 0U;
    size_t rule_length = 0U;

    if (!jg_domain_is_normalized(name) || !jg_domain_is_normalized(rule)) {
        return false;
    }
    if (strcmp(name, rule) == 0) {
        return true;
    }
    if (!include_subdomains) {
        return false;
    }

    name_length = strlen(name);
    rule_length = strlen(rule);
    return name_length > rule_length &&
           name[name_length - rule_length - 1U] == '.' &&
           memcmp(name + name_length - rule_length, rule, rule_length) == 0;
}
