/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file event.h
 * @brief Bounded persistent operational and security events.
 *
 * Events contain administrative-safe UTF-8 text and a canonical JSON details
 * object. Listing is stable by ascending identifier and supports exact
 * severity and component filters.
 *
 * @thread_safety The caller must serialize access to each database object.
 *
 * @error_handling Functions return zero on success and negative errno-style
 * values on validation, allocation, or storage failure.
 */

#ifndef JANUSGATE_EVENT_H
#define JANUSGATE_EVENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Largest event component excluding its terminator. */
#define JG_EVENT_COMPONENT_MAX 128U

/** Largest stable event code excluding its terminator. */
#define JG_EVENT_CODE_MAX 128U

/** Largest event message excluding its terminator. */
#define JG_EVENT_MESSAGE_MAX 2048U

/** Largest canonical event details object excluding its terminator. */
#define JG_EVENT_DETAILS_MAX 4096U

/** Largest event page returned by one query. */
#define JG_EVENT_PAGE_MAX 100U

/** Opaque database connection declared by database.h. */
struct jg_database;

/**
 * @brief Stable operational-event severity.
 */
enum jg_event_severity {
    /** No filter; invalid for a stored event. */
    JG_EVENT_SEVERITY_ANY = 0,
    /** Verbose diagnostic event. */
    JG_EVENT_SEVERITY_DEBUG = 1,
    /** Normal operational event. */
    JG_EVENT_SEVERITY_INFO = 2,
    /** Recoverable degraded condition. */
    JG_EVENT_SEVERITY_WARNING = 3,
    /** Failed operation requiring attention. */
    JG_EVENT_SEVERITY_ERROR = 4,
    /** Appliance integrity or enforcement failure. */
    JG_EVENT_SEVERITY_CRITICAL = 5
};

/**
 * @brief Caller-owned content for one new operational event.
 */
struct jg_event {
    /** Unix timestamp in seconds. */
    uint64_t occurred_at;
    /** Stored event severity. */
    enum jg_event_severity severity;
    /** Stable lowercase component identifier. */
    const char *component;
    /** Stable lowercase event code. */
    const char *code;
    /** Human-readable UTF-8 message without control characters. */
    const char *message;
    /** JSON object serialized canonically before persistence. */
    const char *details;
};

/**
 * @brief Self-contained immutable operational-event record.
 */
struct jg_event_record {
    /** Persistent positive event identifier. */
    uint64_t id;
    /** Unix timestamp in seconds. */
    uint64_t occurred_at;
    /** Stored event severity. */
    enum jg_event_severity severity;
    /** Stable component identifier. */
    char component[JG_EVENT_COMPONENT_MAX + 1U];
    /** Stable event code. */
    char code[JG_EVENT_CODE_MAX + 1U];
    /** Human-readable event message. */
    char message[JG_EVENT_MESSAGE_MAX + 1U];
    /** Canonical JSON details object. */
    char details[JG_EVENT_DETAILS_MAX + 1U];
};

/**
 * @brief Stable filters for one event page.
 */
struct jg_event_filter {
    /** Exclusive identifier cursor, or zero for the first page. */
    uint64_t after_id;
    /** Exact severity, or @ref JG_EVENT_SEVERITY_ANY. */
    enum jg_event_severity severity;
    /** Exact component identifier, or null for every component. */
    const char *component;
};

/**
 * @brief Append one validated operational event.
 *
 * @param[in,out] database Open database.
 * @param[in] event Complete event content.
 * @param[out] event_id Receives the assigned positive identifier; null
 * discards it.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid bounds, identifiers, severity, or JSON.
 * @return -EILSEQ for invalid UTF-8.
 * @return -EOVERFLOW when values cannot be represented persistently.
 * @return A negative errno-style allocation or SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 *
 * @side_effects Canonicalizes details and inserts one persistent row.
 */
JG_PUBLIC int jg_database_event_append(struct jg_database *database,
                                       const struct jg_event *event,
                                       uint64_t *event_id);

/**
 * @brief List one stable ascending page of operational events.
 *
 * @param[in,out] database Open database.
 * @param[in] filter Stable cursor and optional exact filters.
 * @param[out] records Array with room for at least @p capacity records.
 * @param[in] capacity Requested page size from one through
 * @ref JG_EVENT_PAGE_MAX.
 * @param[out] count Number of records written.
 * @param[out] has_more Whether another matching record follows the page.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or filters.
 * @return -EILSEQ for invalid persistent data.
 * @return A negative errno-style SQLite error otherwise.
 *
 * @thread_safety The caller must serialize access to @p database.
 */
JG_PUBLIC int jg_database_event_list(struct jg_database *database,
                                     const struct jg_event_filter *filter,
                                     struct jg_event_record *records,
                                     size_t capacity,
                                     size_t *count,
                                     bool *has_more);

#endif
