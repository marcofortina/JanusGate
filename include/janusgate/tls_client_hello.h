/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file tls_client_hello.h
 * @brief Incremental bounded TLS ClientHello and visible-SNI parser.
 *
 * The parser accepts client-to-server TLS record bytes across any number of
 * TCP segments. It reconstructs only the first ClientHello and never decrypts
 * TLS content.
 *
 * @thread_safety Each parser belongs to one flow and one packet thread.
 */

#ifndef JANUSGATE_TLS_CLIENT_HELLO_H
#define JANUSGATE_TLS_CLIENT_HELLO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/domain.h"
#include "janusgate/version.h"

/** Largest ClientHello body retained by one parser. */
#define JG_TLS_CLIENT_HELLO_MAX 16384U

/** Largest accepted encrypted TLS record payload. */
#define JG_TLS_RECORD_PAYLOAD_MAX 18432U

/** Largest number of TLS records accepted for one ClientHello. */
#define JG_TLS_RECORD_COUNT_MAX 64U

/** Semantic outcome of incremental ClientHello parsing. */
enum jg_tls_client_hello_result {
    /** More client-to-server record bytes are required. */
    JG_TLS_CLIENT_HELLO_MORE = 1,
    /** A complete, structurally valid ClientHello was parsed. */
    JG_TLS_CLIENT_HELLO_COMPLETE = 2,
    /** The first TLS handshake message is not a ClientHello. */
    JG_TLS_CLIENT_HELLO_NOT_CLIENT_HELLO = 3,
    /** Record or ClientHello framing is malformed. */
    JG_TLS_CLIENT_HELLO_MALFORMED = 4,
    /** The declared ClientHello exceeds the fixed parser bound. */
    JG_TLS_CLIENT_HELLO_TOO_LARGE = 5
};

/** Visible information extracted from one complete ClientHello. */
struct jg_tls_client_hello {
    /** Whether a valid visible host_name SNI entry was present. */
    bool has_server_name;
    /** Whether the encrypted-client-hello extension was present. */
    bool encrypted_client_hello;
    /** Lowercase A-label SNI, empty when unavailable. */
    char server_name[JG_DOMAIN_NAME_MAX + 1U];
};

/**
 * @brief Caller-owned bounded state for one TLS flow.
 *
 * Members are public only to permit allocation inside a preallocated flow
 * table. Callers must initialize the complete object and otherwise treat its
 * contents as private.
 */
struct jg_tls_client_hello_parser {
    /** Partial TLS record header. */
    uint8_t record_header[5U];
    /** Partial TLS handshake header. */
    uint8_t handshake_header[4U];
    /** Retained ClientHello body. */
    uint8_t body[JG_TLS_CLIENT_HELLO_MAX];
    /** Bytes collected in record_header. */
    size_t record_header_size;
    /** Payload bytes remaining in the current record. */
    size_t record_remaining;
    /** TLS records activated for this ClientHello. */
    size_t record_count;
    /** Bytes collected in handshake_header. */
    size_t handshake_header_size;
    /** Declared ClientHello body bytes. */
    size_t body_size;
    /** Retained ClientHello body bytes. */
    size_t body_received;
    /** Terminal result, or MORE while parsing. */
    enum jg_tls_client_hello_result terminal;
    /** Terminal extracted fields. */
    struct jg_tls_client_hello hello;
};

/**
 * @brief Initialize an empty incremental ClientHello parser.
 *
 * @param[out] parser Parser state to clear; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_tls_client_hello_parser_init(
    struct jg_tls_client_hello_parser *parser);

/**
 * @brief Feed ordered client-to-server TLS record bytes.
 *
 * Multiple TLS records and arbitrary TCP segmentation are supported. Once a
 * terminal result is reached, later calls return the same result and fields.
 * Bytes following the completed ClientHello in the final input are ignored.
 *
 * @param[in,out] parser Initialized flow parser.
 * @param[in] data Next ordered TLS bytes; null is accepted only when
 * @p data_size is zero.
 * @param[in] data_size Available bytes.
 * @param[out] hello Receives visible fields on COMPLETE and is otherwise
 * cleared.
 *
 * @return Incremental or terminal parser result.
 *
 * @thread_safety Exactly one packet thread may feed a parser.
 */
JG_PUBLIC enum jg_tls_client_hello_result jg_tls_client_hello_parser_feed(
    struct jg_tls_client_hello_parser *parser,
    const uint8_t *data,
    size_t data_size,
    struct jg_tls_client_hello *hello);

#endif
