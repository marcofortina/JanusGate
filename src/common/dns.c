/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/dns.h"

#include <string.h>

#include "janusgate/checked.h"

#define JG_DNS_HEADER_SIZE 12U
#define JG_DNS_POINTER_LIMIT 16U
#define JG_DNS_TYPE_OPT UINT16_C(41)

/**
 * @brief Validate one wire-label byte for policy representation.
 *
 * @param[in] value Wire byte.
 *
 * @return `true` for unambiguous printable ASCII other than dot and backslash.
 */
static bool is_policy_label_byte(uint8_t value)
{
    return value >= UINT8_C(0x21) && value <= UINT8_C(0x7e) &&
           value != (uint8_t)'.' && value != (uint8_t)'\\';
}

/** @brief Decode and normalize one bounded DNS wire-format name. */
enum jg_dns_result jg_dns_decode_name(const uint8_t *message,
                                      size_t message_size,
                                      size_t offset,
                                      char *output,
                                      size_t output_size,
                                      size_t *next_offset)
{
    size_t cursor = offset;
    size_t end_offset = 0U;
    size_t output_length = 0U;
    size_t pointer_depth = 0U;
    bool jumped = false;

    if (output == NULL || output_size == 0U || next_offset == NULL) {
        return JG_DNS_MALFORMED;
    }
    output[0] = '\0';
    *next_offset = 0U;
    if (message == NULL || offset >= message_size) {
        return JG_DNS_TRUNCATED;
    }

    for (;;) {
        uint8_t label_length = 0U;
        size_t label_index = 0U;

        if (cursor >= message_size) {
            return JG_DNS_TRUNCATED;
        }
        label_length = message[cursor];
        if ((label_length & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
            uint16_t pointer_value = 0U;
            size_t target = 0U;

            if (!jg_read_u16_be(message, message_size, cursor,
                                &pointer_value)) {
                return JG_DNS_TRUNCATED;
            }
            target = (size_t)(pointer_value & UINT16_C(0x3fff));
            if (target >= cursor || target >= message_size) {
                return JG_DNS_MALFORMED;
            }
            if (!jumped) {
                end_offset = cursor + 2U;
                jumped = true;
            }
            ++pointer_depth;
            if (pointer_depth > JG_DNS_POINTER_LIMIT) {
                return JG_DNS_LIMIT_EXCEEDED;
            }
            cursor = target;
            continue;
        }
        if ((label_length & UINT8_C(0xc0)) != 0U) {
            return JG_DNS_MALFORMED;
        }
        ++cursor;
        if (label_length == 0U) {
            if (!jumped) {
                end_offset = cursor;
            }
            break;
        }
        if (label_length > JG_DOMAIN_LABEL_MAX ||
            !jg_range_valid(cursor, (size_t)label_length, message_size)) {
            return label_length > JG_DOMAIN_LABEL_MAX ? JG_DNS_MALFORMED
                                                      : JG_DNS_TRUNCATED;
        }
        if (output_length != 0U) {
            if (output_length + 1U >= output_size ||
                output_length + 1U > JG_DOMAIN_NAME_MAX) {
                return JG_DNS_LIMIT_EXCEEDED;
            }
            output[output_length] = '.';
            ++output_length;
        }
        if ((size_t)label_length > JG_DOMAIN_NAME_MAX - output_length ||
            output_length + (size_t)label_length >= output_size) {
            return JG_DNS_LIMIT_EXCEEDED;
        }
        for (label_index = 0U; label_index < (size_t)label_length;
             ++label_index) {
            uint8_t value = message[cursor + label_index];

            if (!is_policy_label_byte(value)) {
                return JG_DNS_MALFORMED;
            }
            if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') {
                value = (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
            }
            output[output_length + label_index] = (char)value;
        }
        output_length += (size_t)label_length;
        cursor += (size_t)label_length;
    }

    output[output_length] = '\0';
    *next_offset = end_offset;
    return JG_DNS_OK;
}

/**
 * @brief Skip and validate resource records of one DNS section.
 *
 * @param[in] message Complete wire message.
 * @param[in] message_size Wire message size.
 * @param[in,out] cursor Current section offset, advanced on success.
 * @param[in] count Number of records to parse.
 * @param[in] detect_opt Whether OPT records update @p parsed.
 * @param[in,out] parsed Destination message metadata.
 *
 * @return A DNS parser result.
 */
static enum jg_dns_result skip_records(const uint8_t *message,
                                       size_t message_size,
                                       size_t *cursor,
                                       uint16_t count,
                                       bool detect_opt,
                                       struct jg_dns_message *parsed)
{
    uint16_t index = 0U;

    for (index = 0U; index < count; ++index) {
        char owner[JG_DOMAIN_NAME_MAX + 1U];
        size_t record_cursor = 0U;
        uint16_t type = 0U;
        uint16_t data_length = 0U;
        enum jg_dns_result result =
            jg_dns_decode_name(message, message_size, *cursor, owner,
                               sizeof(owner), &record_cursor);

        if (result != JG_DNS_OK) {
            return result;
        }
        if (!jg_range_valid(record_cursor, 10U, message_size) ||
            !jg_read_u16_be(message, message_size, record_cursor, &type) ||
            !jg_read_u16_be(message, message_size, record_cursor + 8U,
                            &data_length)) {
            return JG_DNS_TRUNCATED;
        }
        record_cursor += 10U;
        if (!jg_range_valid(record_cursor, (size_t)data_length, message_size)) {
            return JG_DNS_TRUNCATED;
        }
        if (detect_opt && type == JG_DNS_TYPE_OPT) {
            if (parsed->has_edns0) {
                return JG_DNS_MALFORMED;
            }
            parsed->has_edns0 = true;
        }
        *cursor = record_cursor + (size_t)data_length;
    }
    return JG_DNS_OK;
}

/** @brief Parse and validate every section of a classic DNS query. */
enum jg_dns_result jg_dns_parse_query(const uint8_t *message,
                                      size_t message_size,
                                      struct jg_dns_message *parsed)
{
    size_t cursor = JG_DNS_HEADER_SIZE;
    size_t index = 0U;
    enum jg_dns_result result = JG_DNS_MALFORMED;

    if (parsed == NULL) {
        return JG_DNS_MALFORMED;
    }
    (void)memset(parsed, 0, sizeof(*parsed));
    if (message == NULL || message_size < JG_DNS_HEADER_SIZE) {
        return JG_DNS_TRUNCATED;
    }
    if (!jg_read_u16_be(message, message_size, 0U, &parsed->id) ||
        !jg_read_u16_be(message, message_size, 2U, &parsed->flags) ||
        !jg_read_u16_be(message, message_size, 4U,
                        &parsed->wire_question_count) ||
        !jg_read_u16_be(message, message_size, 6U, &parsed->answer_count) ||
        !jg_read_u16_be(message, message_size, 8U, &parsed->authority_count) ||
        !jg_read_u16_be(message, message_size, 10U,
                        &parsed->additional_count)) {
        return JG_DNS_TRUNCATED;
    }
    if ((parsed->flags & UINT16_C(0x8000)) != 0U) {
        return JG_DNS_MALFORMED;
    }
    if ((parsed->flags & UINT16_C(0x7800)) != 0U) {
        return JG_DNS_BAD_OPCODE;
    }
    if (parsed->wire_question_count == 0U) {
        return JG_DNS_MALFORMED;
    }
    if (parsed->wire_question_count > JG_DNS_QUESTION_LIMIT) {
        return JG_DNS_LIMIT_EXCEEDED;
    }

    for (index = 0U; index < (size_t)parsed->wire_question_count; ++index) {
        struct jg_dns_question *question = &parsed->questions[index];

        result =
            jg_dns_decode_name(message, message_size, cursor, question->name,
                               sizeof(question->name), &cursor);
        if (result != JG_DNS_OK) {
            return result;
        }
        if (question->name[0] == '\0') {
            return JG_DNS_MALFORMED;
        }
        if (!jg_read_u16_be(message, message_size, cursor, &question->type) ||
            !jg_read_u16_be(message, message_size, cursor + 2U,
                            &question->class_code)) {
            return JG_DNS_TRUNCATED;
        }
        cursor += 4U;
        ++parsed->question_count;
    }

    result = skip_records(message, message_size, &cursor, parsed->answer_count,
                          false, parsed);
    if (result == JG_DNS_OK) {
        result = skip_records(message, message_size, &cursor,
                              parsed->authority_count, false, parsed);
    }
    if (result == JG_DNS_OK) {
        result = skip_records(message, message_size, &cursor,
                              parsed->additional_count, true, parsed);
    }
    if (result != JG_DNS_OK) {
        return result;
    }
    return cursor == message_size ? JG_DNS_OK : JG_DNS_MALFORMED;
}
