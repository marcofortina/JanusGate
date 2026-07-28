/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "janusgate/tls_client_hello.h"

int jg_test_tls_client_hello(void);

/** Bounded byte builder used for valid TLS test messages. */
struct byte_builder {
    uint8_t data[2048U];
    size_t size;
};

/** @brief Append one byte to a bounded test message. */
static void append_u8(struct byte_builder *builder, uint8_t value)
{
    assert_true(builder->size < sizeof(builder->data));
    builder->data[builder->size] = value;
    ++builder->size;
}

/** @brief Append one big-endian 16-bit value to a test message. */
static void append_u16(struct byte_builder *builder, uint16_t value)
{
    append_u8(builder, (uint8_t)(value >> 8U));
    append_u8(builder, (uint8_t)value);
}

/** @brief Append one big-endian 24-bit value to a test message. */
static void append_u24(struct byte_builder *builder, size_t value)
{
    assert_true(value <= UINT32_C(0x00ffffff));
    append_u8(builder, (uint8_t)(value >> 16U));
    append_u8(builder, (uint8_t)(value >> 8U));
    append_u8(builder, (uint8_t)value);
}

/** @brief Append raw bytes to a bounded test message. */
static void append_bytes(struct byte_builder *builder,
                         const uint8_t *data,
                         size_t size)
{
    assert_true(size <= sizeof(builder->data) - builder->size);
    (void)memcpy(builder->data + builder->size, data, size);
    builder->size += size;
}

/** @brief Append one TLS extension with a complete bounded body. */
static void append_extension(struct byte_builder *extensions,
                             uint16_t type,
                             const uint8_t *body,
                             size_t body_size)
{
    assert_true(body_size <= UINT16_MAX);
    append_u16(extensions, type);
    append_u16(extensions, (uint16_t)body_size);
    append_bytes(extensions, body, body_size);
}

/** @brief Build a valid ClientHello handshake with optional SNI and ECH. */
static struct byte_builder build_handshake(const char *server_name, bool ech)
{
    struct byte_builder extensions = {0};
    struct byte_builder body = {0};
    struct byte_builder handshake = {0};
    static const uint8_t supported_versions[] = {2U, 3U, 4U};
    uint8_t random[32U] = {0};

    if (server_name != NULL) {
        struct byte_builder names = {0};
        struct byte_builder extension = {0};
        const size_t name_size = strlen(server_name);

        assert_true(name_size <= UINT16_MAX);
        append_u8(&names, 0U);
        append_u16(&names, (uint16_t)name_size);
        append_bytes(&names, (const uint8_t *)server_name, name_size);
        append_u16(&extension, (uint16_t)names.size);
        append_bytes(&extension, names.data, names.size);
        append_extension(&extensions, 0U, extension.data, extension.size);
    }
    append_extension(&extensions, 43U, supported_versions,
                     sizeof(supported_versions));
    if (ech) {
        const uint8_t encrypted_client_hello[] = {0U};

        append_extension(&extensions, UINT16_C(0xfe0d), encrypted_client_hello,
                         sizeof(encrypted_client_hello));
    }

    append_u16(&body, UINT16_C(0x0303));
    append_bytes(&body, random, sizeof(random));
    append_u8(&body, 0U);
    append_u16(&body, 2U);
    append_u16(&body, UINT16_C(0x1301));
    append_u8(&body, 1U);
    append_u8(&body, 0U);
    append_u16(&body, (uint16_t)extensions.size);
    append_bytes(&body, extensions.data, extensions.size);

    append_u8(&handshake, 1U);
    append_u24(&handshake, body.size);
    append_bytes(&handshake, body.data, body.size);
    return handshake;
}

/** @brief Append one handshake record containing a selected byte range. */
static void append_record(struct byte_builder *wire,
                          const struct byte_builder *handshake,
                          size_t offset,
                          size_t size)
{
    assert_true(offset <= handshake->size);
    assert_true(size <= handshake->size - offset);
    assert_true(size <= UINT16_MAX);
    append_u8(wire, 22U);
    append_u16(wire, UINT16_C(0x0303));
    append_u16(wire, (uint16_t)size);
    append_bytes(wire, handshake->data + offset, size);
}

/** @brief Verify one complete TLS 1.2 record with visible SNI. */
static void test_single_record(void **state)
{
    const struct byte_builder handshake = build_handshake("Example.COM", false);
    struct byte_builder wire = {0};
    struct jg_tls_client_hello_parser parser;
    struct jg_tls_client_hello hello;

    (void)state;
    append_record(&wire, &handshake, 0U, handshake.size);
    jg_tls_client_hello_parser_init(&parser);
    assert_int_equal(
        jg_tls_client_hello_parser_feed(&parser, wire.data, wire.size, &hello),
        JG_TLS_CLIENT_HELLO_COMPLETE);
    assert_true(hello.has_server_name);
    assert_string_equal(hello.server_name, "example.com");
    assert_false(hello.encrypted_client_hello);
}

/** @brief Verify bytewise TCP fragmentation across multiple TLS records. */
static void test_fragmented_records(void **state)
{
    const struct byte_builder handshake =
        build_handshake("public.example", true);
    struct byte_builder wire = {0};
    struct jg_tls_client_hello_parser parser;
    struct jg_tls_client_hello hello;
    enum jg_tls_client_hello_result result = JG_TLS_CLIENT_HELLO_MORE;
    size_t index = 0U;

    (void)state;
    append_record(&wire, &handshake, 0U, 11U);
    append_record(&wire, &handshake, 11U, handshake.size - 11U);
    jg_tls_client_hello_parser_init(&parser);
    for (index = 0U; index < wire.size; ++index) {
        result = jg_tls_client_hello_parser_feed(&parser, wire.data + index, 1U,
                                                 &hello);
        if (index + 1U < wire.size) {
            assert_int_equal(result, JG_TLS_CLIENT_HELLO_MORE);
        }
    }
    assert_int_equal(result, JG_TLS_CLIENT_HELLO_COMPLETE);
    assert_true(hello.has_server_name);
    assert_string_equal(hello.server_name, "public.example");
    assert_true(hello.encrypted_client_hello);
    assert_int_equal(jg_tls_client_hello_parser_feed(&parser, NULL, 0U, &hello),
                     JG_TLS_CLIENT_HELLO_COMPLETE);
}

/** @brief Verify a valid ClientHello without visible SNI. */
static void test_no_server_name(void **state)
{
    const struct byte_builder handshake = build_handshake(NULL, false);
    struct byte_builder wire = {0};
    struct jg_tls_client_hello_parser parser;
    struct jg_tls_client_hello hello;

    (void)state;
    append_record(&wire, &handshake, 0U, handshake.size);
    jg_tls_client_hello_parser_init(&parser);
    assert_int_equal(
        jg_tls_client_hello_parser_feed(&parser, wire.data, wire.size, &hello),
        JG_TLS_CLIENT_HELLO_COMPLETE);
    assert_false(hello.has_server_name);
    assert_string_equal(hello.server_name, "");
    assert_false(hello.encrypted_client_hello);
}

/** @brief Verify malformed, unsupported, and oversized framing outcomes. */
static void test_rejections(void **state)
{
    const struct byte_builder handshake = build_handshake("example.org", false);
    struct byte_builder wire = {0};
    struct jg_tls_client_hello_parser parser;
    struct jg_tls_client_hello hello;
    uint8_t oversized[] = {22U, 3U, 3U, 0U, 4U, 1U, 0U, 64U, 1U};

    (void)state;
    append_record(&wire, &handshake, 0U, handshake.size);
    wire.data[5U + 4U + 34U] = 33U;
    jg_tls_client_hello_parser_init(&parser);
    assert_int_equal(
        jg_tls_client_hello_parser_feed(&parser, wire.data, wire.size, &hello),
        JG_TLS_CLIENT_HELLO_MALFORMED);

    wire.data[5U] = 2U;
    jg_tls_client_hello_parser_init(&parser);
    assert_int_equal(
        jg_tls_client_hello_parser_feed(&parser, wire.data, wire.size, &hello),
        JG_TLS_CLIENT_HELLO_NOT_CLIENT_HELLO);

    jg_tls_client_hello_parser_init(&parser);
    assert_int_equal(jg_tls_client_hello_parser_feed(&parser, oversized,
                                                     sizeof(oversized), &hello),
                     JG_TLS_CLIENT_HELLO_TOO_LARGE);
    assert_int_equal(
        jg_tls_client_hello_parser_feed(NULL, wire.data, wire.size, &hello),
        JG_TLS_CLIENT_HELLO_MALFORMED);
}

/** @brief Run the incremental TLS ClientHello parser test group. */
int jg_test_tls_client_hello(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_single_record),
        cmocka_unit_test(test_fragmented_records),
        cmocka_unit_test(test_no_server_name),
        cmocka_unit_test(test_rejections),
    };

    return cmocka_run_group_tests_name("tls_client_hello", tests, NULL, NULL);
}
