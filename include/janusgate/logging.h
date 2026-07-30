/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file logging.h
 * @brief Bounded structured operational logging and diagnostic trace capture.
 *
 * Log records are JSON objects written to stderr, syslog, or both. Secret
 * detail fields are always redacted. Client and domain identifiers are
 * redacted unless an administrator explicitly enables their inclusion.
 *
 * @thread_safety Every function is safe to call concurrently.
 *
 * @error_handling Fallible functions return zero on success and negative
 * errno-style values for invalid input, encoding, clocks, or output failures.
 */

#ifndef JANUSGATE_LOGGING_H
#define JANUSGATE_LOGGING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Largest stable logging component excluding its terminator. */
#define JG_LOG_COMPONENT_MAX 63U

/** Largest stable logging event code excluding its terminator. */
#define JG_LOG_EVENT_CODE_MAX 63U

/** Largest correlation identifier excluding its terminator. */
#define JG_LOG_CORRELATION_MAX 64U

/** Largest human-readable log message excluding its terminator. */
#define JG_LOG_MESSAGE_MAX 384U

/** Largest input detail object excluding its terminator. */
#define JG_LOG_DETAILS_MAX 768U

/** Largest complete structured record excluding its terminator. */
#define JG_LOG_RECORD_MAX 1536U

/** Largest canonical logging configuration excluding its terminator. */
#define JG_LOG_CONFIG_JSON_MAX 4096U

/** Maximum number of component-level overrides. */
#define JG_LOG_OVERRIDE_COUNT_MAX 16U

/** Maximum number of in-memory diagnostic trace records. */
#define JG_LOG_TRACE_CAPACITY_MAX 32U

/** Maximum accepted emitted records in one second. */
#define JG_LOG_RATE_LIMIT_MAX 1000U

/**
 * @brief Ordered operational logging severity.
 */
enum jg_log_level {
    /** Failed operation requiring attention. */
    JG_LOG_ERROR = 0,
    /** Recoverable degraded condition. */
    JG_LOG_WARNING = 1,
    /** Normal lifecycle or configuration information. */
    JG_LOG_INFO = 2,
    /** Detailed diagnostic state. */
    JG_LOG_DEBUG = 3,
    /** Fine-grained execution tracing. */
    JG_LOG_TRACE = 4
};

/**
 * @brief Selectable structured-log destinations.
 */
enum jg_log_destination {
    /** Write one JSON line to standard error. */
    JG_LOG_DESTINATION_STDERR = 1U << 0U,
    /** Submit one JSON record to the system logger. */
    JG_LOG_DESTINATION_SYSLOG = 1U << 1U
};

/**
 * @brief One exact component-level override.
 */
struct jg_log_override {
    /** Stable lowercase component identifier. */
    char component[JG_LOG_COMPONENT_MAX + 1U];
    /** Maximum emitted severity for this component. */
    enum jg_log_level level;
};

/**
 * @brief Complete bounded process logging configuration.
 */
struct jg_logging_config {
    /** Maximum emitted severity when no component override matches. */
    enum jg_log_level global_level;
    /** Bitwise combination of @ref jg_log_destination values. */
    uint32_t destinations;
    /** Maximum emitted records per one-second fixed window. */
    uint32_t rate_limit_per_second;
    /** Number of recent redacted records retained in memory. */
    uint32_t trace_capacity;
    /** Unix expiration for debug and trace levels, or zero to disable them. */
    uint64_t diagnostic_until;
    /** Whether client and domain identifiers may appear in detail objects. */
    bool include_identifiers;
    /** Number of populated component overrides. */
    size_t override_count;
    /** Exact per-component maximum levels. */
    struct jg_log_override overrides[JG_LOG_OVERRIDE_COUNT_MAX];
};

/**
 * @brief One caller-owned diagnostic trace record.
 */
struct jg_log_trace_record {
    /** Complete redacted structured JSON record. */
    char json[JG_LOG_RECORD_MAX + 1U];
};

/**
 * @brief Current bounded logger counters.
 */
struct jg_logging_stats {
    /** Records delivered to at least one configured destination. */
    uint64_t emitted;
    /** Records discarded by the fixed-window rate limit. */
    uint64_t suppressed;
    /** Records currently retained in the trace buffer. */
    size_t buffered;
    /** Whether diagnostic levels have not reached their expiration. */
    bool diagnostic_active;
};

/**
 * @brief Initialize conservative production logging defaults.
 *
 * @param[out] config Configuration to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_logging_config_default(struct jg_logging_config *config);

/**
 * @brief Validate one complete logging configuration.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid levels, destinations, component names, duplicate
 * overrides, or inconsistent diagnostic expiration.
 * @return -ERANGE for unsupported rate or buffer bounds.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_logging_config_validate(
    const struct jg_logging_config *config);

/**
 * @brief Encode one validated configuration as canonical JSON.
 *
 * @param[in] config Configuration to encode.
 * @param[out] output Destination buffer.
 * @param[in] output_size Available destination bytes.
 * @param[out] written Receives bytes excluding the terminator.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or configuration.
 * @return -ENOSPC when @p output is too small.
 * @return -ENOMEM on allocation failure.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_logging_config_encode(const struct jg_logging_config *config,
                                       char *output,
                                       size_t output_size,
                                       size_t *written);

/**
 * @brief Decode one exact canonical configuration object.
 *
 * @param[in] input JSON object bytes.
 * @param[in] input_size Exact input bytes excluding any terminator.
 * @param[out] config Receives the validated configuration.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed, duplicate, unknown, or invalid fields.
 * @return -ERANGE for unsupported bounds.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_logging_config_decode(const char *input,
                                       size_t input_size,
                                       struct jg_logging_config *config);

/**
 * @brief Return the stable lowercase name for one level.
 *
 * @param[in] level Logging severity.
 *
 * @return Static name, or null for an invalid level.
 */
JG_PUBLIC const char *jg_log_level_name(enum jg_log_level level);

/**
 * @brief Parse one exact lowercase logging level.
 *
 * @param[in] name Null-terminated level name.
 * @param[out] level Receives the parsed level.
 *
 * @return 0 on success, or -EINVAL for invalid arguments or value.
 */
JG_PUBLIC int jg_log_level_parse(const char *name, enum jg_log_level *level);

/**
 * @brief Initialize process identity and apply one logger configuration.
 *
 * Reinitialization is supported for isolated tests and clears retained trace
 * records.
 *
 * @param[in] process Stable process identifier.
 * @param[in] config Validated configuration.
 *
 * @return 0 on success or a negative validation error.
 */
JG_PUBLIC int jg_logging_initialize(const char *process,
                                    const struct jg_logging_config *config);

/**
 * @brief Atomically replace process logging configuration.
 *
 * Retained records are cleared so reducing identifier disclosure or capacity
 * cannot leave older data reachable.
 *
 * @param[in] config Validated configuration.
 *
 * @return 0 on success or a negative validation error.
 */
JG_PUBLIC int jg_logging_configure(const struct jg_logging_config *config);

/**
 * @brief Copy current configuration and counters.
 *
 * @param[out] config Receives configuration; null discards it.
 * @param[out] stats Receives counters; null discards them.
 *
 * @return 0 on success.
 */
JG_PUBLIC int jg_logging_get(struct jg_logging_config *config,
                             struct jg_logging_stats *stats);

/**
 * @brief Determine whether one level is currently enabled for a component.
 *
 * Expired debug and trace settings are conservatively clamped to info.
 *
 * @param[in] component Stable component identifier.
 * @param[in] level Proposed record level.
 *
 * @return `true` only when the record would pass severity selection.
 */
JG_PUBLIC bool jg_log_enabled(const char *component, enum jg_log_level level);

/**
 * @brief Emit one bounded structured operational record.
 *
 * Detail fields with secret names are always replaced with `[redacted]`.
 * Identifying fields are also replaced unless explicitly enabled. Callers
 * must keep the human-readable message generic and place variable values only
 * in the detail object.
 *
 * @param[in] level Record severity.
 * @param[in] component Stable component identifier.
 * @param[in] event_code Stable event identifier.
 * @param[in] correlation_id Request or flow identifier; null omits it.
 * @param[in] message Constant operator-facing message.
 * @param[in] details JSON object text; null omits it.
 *
 * @return 0 when emitted or filtered by configuration.
 * @return A negative validation, clock, allocation, or write error otherwise.
 */
JG_PUBLIC int jg_log_emit(enum jg_log_level level,
                          const char *component,
                          const char *event_code,
                          const char *correlation_id,
                          const char *message,
                          const char *details);

/**
 * @brief Copy the newest retained records in chronological order.
 *
 * @param[out] records Array with room for @p capacity records.
 * @param[in] capacity Requested count from one through
 * @ref JG_LOG_TRACE_CAPACITY_MAX.
 * @param[out] count Number of copied records.
 * @param[out] stats Receives current counters; null discards them.
 *
 * @return 0 on success or -EINVAL for invalid arguments.
 */
JG_PUBLIC int jg_logging_trace_snapshot(struct jg_log_trace_record *records,
                                        size_t capacity,
                                        size_t *count,
                                        struct jg_logging_stats *stats);

/**
 * @brief Close syslog state and clear all retained records.
 */
JG_PUBLIC void jg_logging_shutdown(void);

#endif
