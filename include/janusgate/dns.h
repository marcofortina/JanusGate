/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file dns.h
 * @brief Strict DNS query parsing and bounded name decompression.
 *
 * Parsed messages own their normalized question strings. The input wire
 * message need only remain valid during the parsing call.
 *
 * @thread_safety All functions are reentrant and access caller-owned storage.
 *
 * @error_handling Results distinguish truncation, invalid wire syntax,
 * unsupported operation codes, and configured resource limits.
 */

#ifndef JANUSGATE_DNS_H
#define JANUSGATE_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/domain.h"
#include "janusgate/version.h"

/** Maximum questions retained from one policy query. */
#define JG_DNS_QUESTION_LIMIT 16U

/**
 * @brief DNS parser result.
 */
enum jg_dns_result {
    /** The message is a valid DNS query. */
    JG_DNS_OK = 0,
    /** The message ends before a declared field. */
    JG_DNS_TRUNCATED,
    /** The message contains invalid DNS syntax. */
    JG_DNS_MALFORMED,
    /** The message uses a non-query operation code. */
    JG_DNS_BAD_OPCODE,
    /** A configured parser resource bound was exceeded. */
    JG_DNS_LIMIT_EXCEEDED
};

/**
 * @brief One normalized DNS question.
 */
struct jg_dns_question {
    /** Lowercase owner name without the trailing root dot. */
    char name[JG_DOMAIN_NAME_MAX + 1U];
    /** Offset of the encoded owner name in the original DNS message. */
    size_t wire_offset;
    /** Host-order DNS resource record type. */
    uint16_t type;
    /** Host-order DNS class. */
    uint16_t class_code;
};

/**
 * @brief Validated DNS query metadata.
 */
struct jg_dns_message {
    /** Host-order transaction identifier. */
    uint16_t id;
    /** Host-order DNS flags. */
    uint16_t flags;
    /** Question count from the wire header. */
    uint16_t wire_question_count;
    /** Answer record count from the wire header. */
    uint16_t answer_count;
    /** Authority record count from the wire header. */
    uint16_t authority_count;
    /** Additional record count from the wire header. */
    uint16_t additional_count;
    /** Number of entries populated in @ref questions. */
    size_t question_count;
    /** Bytes occupied by the complete wire-format question section. */
    size_t question_wire_size;
    /** Whether an EDNS OPT record was present in additional data. */
    bool has_edns0;
    /** Normalized questions in wire order. */
    struct jg_dns_question questions[JG_DNS_QUESTION_LIMIT];
};

/**
 * @brief Decode one possibly compressed DNS name.
 *
 * Compression pointers must refer to an earlier wire offset. Pointer loops,
 * reserved label encodings, oversized labels, and non-ASCII label bytes are
 * rejected. ASCII letters are converted to lowercase.
 *
 * @param[in] message Complete DNS message.
 * @param[in] message_size Number of available message bytes.
 * @param[in] offset Offset of the encoded name.
 * @param[out] output Destination for the normalized textual name.
 * @param[in] output_size Destination size including the null terminator.
 * @param[out] next_offset First byte after the name at its original location.
 *
 * @return A DNS parser result.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC enum jg_dns_result jg_dns_decode_name(const uint8_t *message,
                                                size_t message_size,
                                                size_t offset,
                                                char *output,
                                                size_t output_size,
                                                size_t *next_offset);

/**
 * @brief Parse and validate a complete DNS query message.
 *
 * The parser validates every declared question and resource record, including
 * generic handling for record types unknown to this release.
 *
 * @param[in] message DNS wire bytes without a TCP length prefix.
 * @param[in] message_size Number of available bytes.
 * @param[out] parsed Caller-owned destination.
 *
 * @return A DNS parser result.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects @p parsed is cleared before every return.
 */
JG_PUBLIC enum jg_dns_result jg_dns_parse_query(const uint8_t *message,
                                                size_t message_size,
                                                struct jg_dns_message *parsed);

#endif
