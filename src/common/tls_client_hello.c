/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/tls_client_hello.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "janusgate/checked.h"

/** TLS record content type for handshake messages. */
#define TLS_CONTENT_HANDSHAKE 22U

/** TLS handshake type for ClientHello. */
#define TLS_HANDSHAKE_CLIENT_HELLO 1U

/** TLS extension type for server_name. */
#define TLS_EXTENSION_SERVER_NAME 0U

/** TLS extension type for encrypted_client_hello. */
#define TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO UINT16_C(0xfe0d)

/** Fixed bytes before the legacy ClientHello session identifier. */
#define CLIENT_HELLO_PREFIX_SIZE 34U

/** @brief Read one byte after a strict bounds check. */
static bool read_byte(const uint8_t *data,
                      size_t data_size,
                      size_t offset,
                      uint8_t *value)
{
    if (data == NULL || value == NULL || offset >= data_size) {
        return false;
    }
    *value = data[offset];
    return true;
}

/** @brief Set and return one permanent parser result. */
static enum jg_tls_client_hello_result terminal_result(
    struct jg_tls_client_hello_parser *parser,
    enum jg_tls_client_hello_result result)
{
    parser->terminal = result;
    return result;
}

/** @brief Copy and validate a visible ASCII SNI as a normalized domain. */
static bool normalize_server_name(const uint8_t *name,
                                  size_t name_size,
                                  char output[JG_DOMAIN_NAME_MAX + 1U])
{
    size_t index = 0U;

    if (name == NULL || name_size == 0U || name_size > JG_DOMAIN_NAME_MAX) {
        return false;
    }
    for (index = 0U; index < name_size; ++index) {
        uint8_t value = name[index];

        if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') {
            value = (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
        }
        if (value > UINT8_C(0x7f) || value == 0U) {
            return false;
        }
        output[index] = (char)value;
    }
    output[name_size] = '\0';
    if (!jg_domain_is_normalized(output)) {
        output[0] = '\0';
        return false;
    }
    return true;
}

/** @brief Parse one complete server_name extension. */
static bool parse_server_name_extension(const uint8_t *data,
                                        size_t data_size,
                                        struct jg_tls_client_hello *hello)
{
    uint16_t list_size = 0U;
    size_t offset = 2U;

    if (data_size < 2U || !jg_read_u16_be(data, data_size, 0U, &list_size) ||
        (size_t)list_size != data_size - 2U || list_size == 0U) {
        return false;
    }
    while (offset < data_size) {
        uint16_t name_size = 0U;
        uint8_t name_type = 0U;

        if (!read_byte(data, data_size, offset, &name_type) ||
            !jg_read_u16_be(data, data_size, offset + 1U, &name_size) ||
            name_size == 0U || (size_t)name_size > data_size - offset - 3U) {
            return false;
        }
        if (name_type == 0U) {
            if (hello->has_server_name ||
                !normalize_server_name(data + offset + 3U, name_size,
                                       hello->server_name)) {
                return false;
            }
            hello->has_server_name = true;
        }
        offset += 3U + (size_t)name_size;
    }
    return offset == data_size;
}

/** @brief Parse the bounded ClientHello extension vector. */
static bool parse_extensions(const uint8_t *data,
                             size_t data_size,
                             struct jg_tls_client_hello *hello)
{
    size_t offset = 0U;
    bool saw_server_name = false;

    while (offset < data_size) {
        uint16_t extension_type = 0U;
        uint16_t extension_size = 0U;

        if (!jg_read_u16_be(data, data_size, offset, &extension_type) ||
            !jg_read_u16_be(data, data_size, offset + 2U, &extension_size) ||
            (size_t)extension_size > data_size - offset - 4U) {
            return false;
        }
        if (extension_type == TLS_EXTENSION_SERVER_NAME) {
            if (saw_server_name ||
                !parse_server_name_extension(data + offset + 4U, extension_size,
                                             hello)) {
                return false;
            }
            saw_server_name = true;
        } else if (extension_type == TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO) {
            hello->encrypted_client_hello = true;
        }
        offset += 4U + (size_t)extension_size;
    }
    return offset == data_size;
}

/** @brief Parse one complete TLS 1.2 or TLS 1.3 ClientHello body. */
static bool parse_client_hello(const uint8_t *body,
                               size_t body_size,
                               struct jg_tls_client_hello *hello)
{
    uint16_t cipher_suites_size = 0U;
    uint16_t extensions_size = 0U;
    uint8_t compression_size = 0U;
    uint8_t session_size = 0U;
    size_t offset = CLIENT_HELLO_PREFIX_SIZE;

    (void)memset(hello, 0, sizeof(*hello));
    if (body_size < CLIENT_HELLO_PREFIX_SIZE + 1U ||
        body[0U] != UINT8_C(0x03) || body[1U] != UINT8_C(0x03) ||
        !read_byte(body, body_size, offset, &session_size) ||
        session_size > 32U || (size_t)session_size > body_size - offset - 1U) {
        return false;
    }
    offset += 1U + (size_t)session_size;
    if (!jg_read_u16_be(body, body_size, offset, &cipher_suites_size) ||
        cipher_suites_size < 2U || (cipher_suites_size & 1U) != 0U ||
        (size_t)cipher_suites_size > body_size - offset - 2U) {
        return false;
    }
    offset += 2U + (size_t)cipher_suites_size;
    if (!read_byte(body, body_size, offset, &compression_size) ||
        compression_size == 0U ||
        (size_t)compression_size > body_size - offset - 1U) {
        return false;
    }
    offset += 1U + (size_t)compression_size;
    if (offset == body_size) {
        return true;
    }
    if (!jg_read_u16_be(body, body_size, offset, &extensions_size) ||
        (size_t)extensions_size != body_size - offset - 2U) {
        return false;
    }
    return parse_extensions(body + offset + 2U, extensions_size, hello);
}

/** @brief Validate and activate one complete TLS record header. */
static enum jg_tls_client_hello_result activate_record(
    struct jg_tls_client_hello_parser *parser)
{
    uint16_t record_size = 0U;

    if (parser->record_count >= JG_TLS_RECORD_COUNT_MAX) {
        return terminal_result(parser, JG_TLS_CLIENT_HELLO_TOO_LARGE);
    }
    if (parser->record_header[0U] != TLS_CONTENT_HANDSHAKE ||
        parser->record_header[1U] != UINT8_C(0x03) ||
        parser->record_header[2U] < UINT8_C(0x01) ||
        parser->record_header[2U] > UINT8_C(0x03) ||
        !jg_read_u16_be(parser->record_header, sizeof(parser->record_header),
                        3U, &record_size) ||
        record_size == 0U || record_size > JG_TLS_RECORD_PAYLOAD_MAX) {
        return terminal_result(parser, JG_TLS_CLIENT_HELLO_MALFORMED);
    }
    parser->record_header_size = 0U;
    parser->record_remaining = record_size;
    ++parser->record_count;
    return JG_TLS_CLIENT_HELLO_MORE;
}

/** @brief Validate and activate one complete TLS handshake header. */
static enum jg_tls_client_hello_result activate_handshake(
    struct jg_tls_client_hello_parser *parser)
{
    const uint32_t body_size = (uint32_t)parser->handshake_header[1U] << 16U |
                               (uint32_t)parser->handshake_header[2U] << 8U |
                               (uint32_t)parser->handshake_header[3U];

    if (parser->handshake_header[0U] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return terminal_result(parser, JG_TLS_CLIENT_HELLO_NOT_CLIENT_HELLO);
    }
    if (body_size == 0U) {
        return terminal_result(parser, JG_TLS_CLIENT_HELLO_MALFORMED);
    }
    if (body_size > JG_TLS_CLIENT_HELLO_MAX) {
        return terminal_result(parser, JG_TLS_CLIENT_HELLO_TOO_LARGE);
    }
    parser->body_size = body_size;
    return JG_TLS_CLIENT_HELLO_MORE;
}

/** @brief Copy available bytes into one bounded parser field. */
static size_t copy_available(uint8_t *destination,
                             size_t received,
                             size_t required,
                             const uint8_t *data,
                             size_t available)
{
    const size_t remaining = required - received;
    const size_t copied = available < remaining ? available : remaining;

    (void)memcpy(destination + received, data, copied);
    return copied;
}

/** @brief Initialize one empty incremental ClientHello parser. */
void jg_tls_client_hello_parser_init(struct jg_tls_client_hello_parser *parser)
{
    if (parser != NULL) {
        (void)memset(parser, 0, sizeof(*parser));
        parser->terminal = JG_TLS_CLIENT_HELLO_MORE;
    }
}

/** @brief Feed ordered TLS records until the first ClientHello is complete. */
enum jg_tls_client_hello_result jg_tls_client_hello_parser_feed(
    struct jg_tls_client_hello_parser *parser,
    const uint8_t *data,
    size_t data_size,
    struct jg_tls_client_hello *hello)
{
    size_t offset = 0U;

    if (hello != NULL) {
        (void)memset(hello, 0, sizeof(*hello));
    }
    if (parser == NULL || hello == NULL || (data == NULL && data_size != 0U)) {
        return JG_TLS_CLIENT_HELLO_MALFORMED;
    }
    if (parser->terminal != JG_TLS_CLIENT_HELLO_MORE) {
        *hello = parser->hello;
        return parser->terminal;
    }
    while (offset < data_size && parser->terminal == JG_TLS_CLIENT_HELLO_MORE) {
        size_t copied;

        if (parser->record_remaining == 0U) {
            copied = copy_available(parser->record_header,
                                    parser->record_header_size,
                                    sizeof(parser->record_header),
                                    data + offset, data_size - offset);
            parser->record_header_size += copied;
            offset += copied;
            if (parser->record_header_size < sizeof(parser->record_header)) {
                break;
            }
            if (activate_record(parser) != JG_TLS_CLIENT_HELLO_MORE) {
                break;
            }
        }
        if (parser->handshake_header_size < sizeof(parser->handshake_header)) {
            size_t available = data_size - offset;

            if (available > parser->record_remaining) {
                available = parser->record_remaining;
            }
            copied = copy_available(
                parser->handshake_header, parser->handshake_header_size,
                sizeof(parser->handshake_header), data + offset, available);
            parser->handshake_header_size += copied;
            parser->record_remaining -= copied;
            offset += copied;
            if (parser->handshake_header_size <
                sizeof(parser->handshake_header)) {
                continue;
            }
            if (activate_handshake(parser) != JG_TLS_CLIENT_HELLO_MORE) {
                break;
            }
        }
        if (parser->body_received < parser->body_size) {
            size_t available = data_size - offset;

            if (available > parser->record_remaining) {
                available = parser->record_remaining;
            }
            copied =
                copy_available(parser->body, parser->body_received,
                               parser->body_size, data + offset, available);
            parser->body_received += copied;
            parser->record_remaining -= copied;
            offset += copied;
        }
        if (parser->body_received == parser->body_size) {
            parser->terminal =
                parse_client_hello(parser->body, parser->body_size,
                                   &parser->hello)
                    ? JG_TLS_CLIENT_HELLO_COMPLETE
                    : JG_TLS_CLIENT_HELLO_MALFORMED;
        }
    }
    *hello = parser->hello;
    return parser->terminal;
}
