/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file blocklist.h
 * @brief Bounded blocklist parsing, normalization, and deduplication.
 *
 * An imported blocklist owns packed normalized domains, optional categories,
 * source attribution, and a canonical checksum. Entry views borrow that
 * storage and remain valid until the blocklist is destroyed.
 *
 * @thread_safety Import functions are reentrant. An immutable blocklist may be
 * read concurrently; destruction requires exclusive ownership.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values on failure. Strict mode rejects the complete input at its first bad
 * record. Tolerant mode reports and skips malformed records.
 */

#ifndef JANUSGATE_BLOCKLIST_H
#define JANUSGATE_BLOCKLIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Number of bytes in a canonical blocklist SHA-256 checksum. */
#define JG_BLOCKLIST_CHECKSUM_SIZE 32U

/** Largest retained category in bytes, excluding its terminator. */
#define JG_BLOCKLIST_CATEGORY_MAX 128U

/** Largest source attribution in bytes, excluding its terminator. */
#define JG_BLOCKLIST_ATTRIBUTION_MAX 255U

/**
 * @brief Supported blocklist input syntax.
 */
enum jg_blocklist_format {
    /** One domain per non-comment line. */
    JG_BLOCKLIST_FORMAT_DOMAIN = 1,
    /** Hosts-file address followed by one or more domains. */
    JG_BLOCKLIST_FORMAT_HOSTS = 2,
    /** Domain followed by an optional comma- or tab-separated category. */
    JG_BLOCKLIST_FORMAT_CATEGORY = 3,
    /** RPZ CNAME records selecting a blocking policy action. */
    JG_BLOCKLIST_FORMAT_RPZ = 4,
    /** Versioned JanusGate JSON object containing an entries array. */
    JG_BLOCKLIST_FORMAT_JSON = 5
};

/**
 * @brief Import error policy.
 */
enum jg_blocklist_mode {
    /** Reject the complete import when any record is invalid. */
    JG_BLOCKLIST_STRICT = 1,
    /** Skip invalid records and retain valid records. */
    JG_BLOCKLIST_TOLERANT = 2
};

/**
 * @brief Resource limits applied before and during import.
 */
struct jg_blocklist_limits {
    /** Maximum complete input bytes. */
    size_t max_file_bytes;
    /** Maximum bytes in one text-format line. */
    size_t max_line_bytes;
    /** Maximum parsed entries before deduplication. */
    size_t max_entries;
};

/**
 * @brief Import statistics and first rejected record.
 */
struct jg_blocklist_report {
    /** Physical text lines or JSON entries examined. */
    size_t records_seen;
    /** Valid entries parsed before deduplication. */
    size_t entries_parsed;
    /** Malformed records skipped in tolerant mode. */
    size_t records_rejected;
    /** Valid duplicate domains removed. */
    size_t duplicates_removed;
    /** One-based first rejected line or JSON entry; zero when none. */
    size_t first_error_record;
    /** Negative errno-style first rejection reason; zero when none. */
    int first_error;
};

/**
 * @brief Stable metadata for an imported blocklist.
 */
struct jg_blocklist_info {
    /** Number of unique normalized domains. */
    size_t entry_count;
    /** Caller-supplied source attribution copied during import. */
    const char *attribution;
    /** Canonical digest of ordered domains and categories. */
    uint8_t checksum[JG_BLOCKLIST_CHECKSUM_SIZE];
};

/**
 * @brief Borrowed view of one imported entry.
 */
struct jg_blocklist_entry {
    /** Normalized lowercase IDNA2008 A-label domain. */
    const char *domain;
    /** UTF-8 category, or an empty string when absent. */
    const char *category;
};

/** Opaque immutable imported blocklist. */
struct jg_blocklist;

/**
 * @brief Initialize conservative import limits.
 *
 * Defaults permit 64 MiB input, 4096 bytes per line, and one million parsed
 * entries.
 *
 * @param[out] limits Limits structure to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_blocklist_limits_default(struct jg_blocklist_limits *limits);

/**
 * @brief Import one complete bounded blocklist buffer.
 *
 * Embedded null bytes are always rejected. Text formats accept blank lines
 * and comments. JSON must contain `{"version":1,"entries":[...]}`, with each
 * entry providing `domain` and an optional `category`.
 *
 * @param[in] data Complete immutable input buffer.
 * @param[in] data_size Number of bytes in @p data.
 * @param[in] format Input syntax.
 * @param[in] mode Strict or tolerant record handling.
 * @param[in] attribution Nonempty UTF-8 source description.
 * @param[in] limits Resource bounds, or null for conservative defaults.
 * @param[out] blocklist Receives the owned immutable result.
 * @param[out] report Receives import statistics; null discards them.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments, structure, or record syntax.
 * @return -EILSEQ for invalid UTF-8 or embedded null bytes.
 * @return -EFBIG when the input exceeds its file bound.
 * @return -EMSGSIZE when a strict text record exceeds its line bound.
 * @return -E2BIG when the entry bound is exceeded.
 * @return -ENOMEM when allocation fails.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Normalizes Unicode domains through libidn2.
 */
JG_PUBLIC int jg_blocklist_import(const uint8_t *data,
                                  size_t data_size,
                                  enum jg_blocklist_format format,
                                  enum jg_blocklist_mode mode,
                                  const char *attribution,
                                  const struct jg_blocklist_limits *limits,
                                  struct jg_blocklist **blocklist,
                                  struct jg_blocklist_report *report);

/**
 * @brief Destroy an imported blocklist.
 *
 * @param[in,out] blocklist Owned blocklist, or null.
 *
 * @thread_safety Safe after callers have excluded concurrent readers.
 */
JG_PUBLIC void jg_blocklist_destroy(struct jg_blocklist *blocklist);

/**
 * @brief Copy metadata from an immutable blocklist.
 *
 * @param[in] blocklist Imported blocklist.
 * @param[out] info Receives stable metadata and borrowed attribution.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe for concurrent calls on the same blocklist.
 */
JG_PUBLIC int jg_blocklist_get_info(const struct jg_blocklist *blocklist,
                                    struct jg_blocklist_info *info);

/**
 * @brief Borrow one entry by canonical order.
 *
 * @param[in] blocklist Imported blocklist.
 * @param[in] index Zero-based entry index below the reported entry count.
 * @param[out] entry Receives borrowed domain and category pointers.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument or out-of-range index.
 *
 * @thread_safety Safe for concurrent calls on the same blocklist.
 */
JG_PUBLIC int jg_blocklist_get_entry(const struct jg_blocklist *blocklist,
                                     size_t index,
                                     struct jg_blocklist_entry *entry);

#endif
