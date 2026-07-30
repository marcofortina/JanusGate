/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "janusgate/logging.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <syslog.h>
#include <unistd.h>

#include <jansson.h>

/** Conservative fixed default record rate. */
#define JG_LOG_RATE_LIMIT_DEFAULT 100U

/** Default retained diagnostic record count. */
#define JG_LOG_TRACE_CAPACITY_DEFAULT 16U

/** Stable process identifier bound. */
#define JG_LOG_PROCESS_MAX 63U

/** Supported destination bits. */
#define JG_LOG_DESTINATION_ALL                                                 \
    (JG_LOG_DESTINATION_STDERR | JG_LOG_DESTINATION_SYSLOG)

/** Process-global bounded logger state. */
static struct {
    pthread_mutex_t lock;
    atomic_uint_fast32_t maximum_level;
    atomic_uint_fast64_t diagnostic_until;
    struct jg_logging_config config;
    struct jg_log_trace_record records[JG_LOG_TRACE_CAPACITY_MAX];
    char process[JG_LOG_PROCESS_MAX + 1U];
    uint64_t emitted;
    uint64_t suppressed;
    uint64_t window_second;
    uint64_t pending_suppressed;
    uint32_t window_records;
    size_t record_start;
    size_t record_count;
    bool initialized;
    bool syslog_open;
} logger = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .maximum_level = JG_LOG_ERROR,
    .diagnostic_until = 0U,
};

/** @brief Return one bounded string length or one past the maximum. */
static size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0U;

    if (text == NULL) {
        return maximum + 1U;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    return length;
}

/** @brief Validate one stable lowercase identifier. */
static bool identifier_valid(const char *text, size_t maximum)
{
    const size_t length = bounded_length(text, maximum);

    if (length == 0U || length > maximum) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)text[index];

        if (!((character >= (uint8_t)'a' && character <= (uint8_t)'z') ||
              (character >= (uint8_t)'0' && character <= (uint8_t)'9') ||
              character == (uint8_t)'-' || character == (uint8_t)'_' ||
              character == (uint8_t)'.')) {
            return false;
        }
    }
    return true;
}

/** @brief Validate one opaque visible correlation identifier. */
static bool correlation_valid(const char *text)
{
    const size_t length = bounded_length(text, JG_LOG_CORRELATION_MAX);

    if (text == NULL) {
        return true;
    }
    if (length == 0U || length > JG_LOG_CORRELATION_MAX) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)text[index];

        if (!((character >= (uint8_t)'a' && character <= (uint8_t)'z') ||
              (character >= (uint8_t)'A' && character <= (uint8_t)'Z') ||
              (character >= (uint8_t)'0' && character <= (uint8_t)'9') ||
              character == (uint8_t)'-' || character == (uint8_t)'_' ||
              character == (uint8_t)'.' || character == (uint8_t)':')) {
            return false;
        }
    }
    return true;
}

/** @brief Return the stable lowercase name for one level. */
const char *jg_log_level_name(enum jg_log_level level)
{
    switch (level) {
    case JG_LOG_ERROR:
        return "error";
    case JG_LOG_WARNING:
        return "warning";
    case JG_LOG_INFO:
        return "info";
    case JG_LOG_DEBUG:
        return "debug";
    case JG_LOG_TRACE:
        return "trace";
    default:
        return NULL;
    }
}

/** @brief Parse one exact lowercase logging level. */
int jg_log_level_parse(const char *name, enum jg_log_level *level)
{
    static const struct {
        const char *name;
        enum jg_log_level level;
    } values[] = {
        {"error", JG_LOG_ERROR}, {"warning", JG_LOG_WARNING},
        {"info", JG_LOG_INFO},   {"debug", JG_LOG_DEBUG},
        {"trace", JG_LOG_TRACE},
    };

    if (name == NULL || level == NULL) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < sizeof(values) / sizeof(values[0U]);
         ++index) {
        if (strcmp(name, values[index].name) == 0) {
            *level = values[index].level;
            return 0;
        }
    }
    return -EINVAL;
}

/** @brief Initialize conservative production logging defaults. */
void jg_logging_config_default(struct jg_logging_config *config)
{
    if (config == NULL) {
        return;
    }
    (void)memset(config, 0, sizeof(*config));
    config->global_level = JG_LOG_INFO;
    config->destinations =
        JG_LOG_DESTINATION_STDERR | JG_LOG_DESTINATION_SYSLOG;
    config->rate_limit_per_second = JG_LOG_RATE_LIMIT_DEFAULT;
    config->trace_capacity = JG_LOG_TRACE_CAPACITY_DEFAULT;
}

/** @brief Report whether a configuration selects diagnostic verbosity. */
static bool diagnostic_levels_configured(const struct jg_logging_config *config)
{
    if (config->global_level > JG_LOG_INFO) {
        return true;
    }
    for (size_t index = 0U; index < config->override_count; ++index) {
        if (config->overrides[index].level > JG_LOG_INFO) {
            return true;
        }
    }
    return false;
}

/** @brief Validate one complete logging configuration. */
int jg_logging_config_validate(const struct jg_logging_config *config)
{
    if (config == NULL || jg_log_level_name(config->global_level) == NULL ||
        config->destinations == 0U ||
        (config->destinations & ~((uint32_t)JG_LOG_DESTINATION_ALL)) != 0U ||
        config->override_count > JG_LOG_OVERRIDE_COUNT_MAX) {
        return -EINVAL;
    }
    if (config->rate_limit_per_second == 0U ||
        config->rate_limit_per_second > JG_LOG_RATE_LIMIT_MAX ||
        config->trace_capacity > JG_LOG_TRACE_CAPACITY_MAX) {
        return -ERANGE;
    }
    if (diagnostic_levels_configured(config) &&
        config->diagnostic_until == 0U) {
        return -EINVAL;
    }
    if (!diagnostic_levels_configured(config) &&
        config->diagnostic_until != 0U) {
        return -EINVAL;
    }
    if (config->include_identifiers && !diagnostic_levels_configured(config)) {
        return -EINVAL;
    }
    if (config->diagnostic_until > (uint64_t)INT64_MAX) {
        return -ERANGE;
    }
    for (size_t index = 0U; index < config->override_count; ++index) {
        if (!identifier_valid(config->overrides[index].component,
                              JG_LOG_COMPONENT_MAX) ||
            jg_log_level_name(config->overrides[index].level) == NULL) {
            return -EINVAL;
        }
        for (size_t previous = 0U; previous < index; ++previous) {
            if (strcmp(config->overrides[index].component,
                       config->overrides[previous].component) == 0) {
                return -EINVAL;
            }
        }
    }
    return 0;
}

/** @brief Append configured destinations to one JSON array. */
static int encode_destinations(uint32_t destinations, json_t *values)
{
    if ((destinations & JG_LOG_DESTINATION_STDERR) != 0U &&
        json_array_append_new(values, json_string("stderr")) != 0) {
        return -ENOMEM;
    }
    if ((destinations & JG_LOG_DESTINATION_SYSLOG) != 0U &&
        json_array_append_new(values, json_string("syslog")) != 0) {
        return -ENOMEM;
    }
    return 0;
}

/** @brief Build one canonical configuration JSON object. */
static json_t *config_json(const struct jg_logging_config *config)
{
    json_t *object = json_object();
    json_t *destinations = json_array();
    json_t *overrides = json_array();
    int result = object == NULL || destinations == NULL || overrides == NULL
                     ? -ENOMEM
                     : 0;

    if (result == 0) {
        result = encode_destinations(config->destinations, destinations);
    }
    for (size_t index = 0U; result == 0 && index < config->override_count;
         ++index) {
        json_t *override = json_object();

        if (override == NULL ||
            json_object_set_new(
                override, "component",
                json_string(config->overrides[index].component)) != 0 ||
            json_object_set_new(override, "level",
                                json_string(jg_log_level_name(
                                    config->overrides[index].level))) != 0 ||
            json_array_append_new(overrides, override) != 0) {
            json_decref(override);
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(
             object, "global_level",
             json_string(jg_log_level_name(config->global_level))) != 0 ||
         json_object_set(object, "destinations", destinations) != 0 ||
         json_object_set_new(
             object, "rate_limit_per_second",
             json_integer((json_int_t)config->rate_limit_per_second)) != 0 ||
         json_object_set_new(
             object, "trace_capacity",
             json_integer((json_int_t)config->trace_capacity)) != 0 ||
         json_object_set_new(
             object, "diagnostic_until",
             json_integer((json_int_t)config->diagnostic_until)) != 0 ||
         json_object_set_new(object, "include_identifiers",
                             json_boolean(config->include_identifiers)) != 0 ||
         json_object_set(object, "overrides", overrides) != 0)) {
        result = -ENOMEM;
    }
    json_decref(overrides);
    json_decref(destinations);
    if (result != 0) {
        json_decref(object);
        return NULL;
    }
    return object;
}

/** @brief Encode one validated configuration as canonical JSON. */
int jg_logging_config_encode(const struct jg_logging_config *config,
                             char *output,
                             size_t output_size,
                             size_t *written)
{
    json_t *object = NULL;
    char *encoded = NULL;
    size_t encoded_size = 0U;
    int result = jg_logging_config_validate(config);

    if (output == NULL || output_size == 0U || written == NULL) {
        return -EINVAL;
    }
    *written = 0U;
    if (result == 0) {
        object = config_json(config);
        if (object == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        encoded = json_dumps(object, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        encoded_size = strlen(encoded);
        if (encoded_size >= output_size) {
            result = -ENOSPC;
        } else {
            (void)memcpy(output, encoded, encoded_size + 1U);
            *written = encoded_size;
        }
    }
    free(encoded);
    json_decref(object);
    return result;
}

/** @brief Check that a JSON object contains only exact allowed fields. */
static bool fields_allowed(json_t *object,
                           const char *const *fields,
                           size_t field_count)
{
    const char *name = NULL;
    json_t *value = NULL;

    if (!json_is_object(object)) {
        return false;
    }
    json_object_foreach(object, name, value)
    {
        bool allowed = false;

        (void)value;
        for (size_t index = 0U; index < field_count; ++index) {
            if (strcmp(name, fields[index]) == 0) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return false;
        }
    }
    return true;
}

/** @brief Decode an exact destination array. */
static int decode_destinations(json_t *values, uint32_t *destinations)
{
    size_t index = 0U;
    json_t *value = NULL;

    *destinations = 0U;
    if (!json_is_array(values) || json_array_size(values) == 0U ||
        json_array_size(values) > 2U) {
        return -EINVAL;
    }
    json_array_foreach(values, index, value)
    {
        const char *name = json_string_value(value);
        uint32_t destination = 0U;

        if (name == NULL) {
            return -EINVAL;
        }
        if (strcmp(name, "stderr") == 0) {
            destination = JG_LOG_DESTINATION_STDERR;
        } else if (strcmp(name, "syslog") == 0) {
            destination = JG_LOG_DESTINATION_SYSLOG;
        } else {
            return -EINVAL;
        }
        if ((*destinations & destination) != 0U) {
            return -EINVAL;
        }
        *destinations |= destination;
    }
    return 0;
}

/** @brief Decode exact component override objects. */
static int decode_overrides(json_t *values, struct jg_logging_config *config)
{
    static const char *const fields[] = {
        "component",
        "level",
    };
    size_t index = 0U;
    json_t *value = NULL;

    if (!json_is_array(values) ||
        json_array_size(values) > JG_LOG_OVERRIDE_COUNT_MAX) {
        return -EINVAL;
    }
    config->override_count = json_array_size(values);
    json_array_foreach(values, index, value)
    {
        json_t *component = json_object_get(value, "component");
        json_t *level = json_object_get(value, "level");
        const char *component_name = json_string_value(component);
        const char *level_name = json_string_value(level);
        size_t component_size =
            json_is_string(component) ? json_string_length(component) : 0U;

        if (!fields_allowed(value, fields,
                            sizeof(fields) / sizeof(fields[0U])) ||
            json_object_size(value) != 2U || component_name == NULL ||
            component_size == 0U || component_size > JG_LOG_COMPONENT_MAX ||
            jg_log_level_parse(level_name, &config->overrides[index].level) !=
                0) {
            return -EINVAL;
        }
        (void)memcpy(config->overrides[index].component, component_name,
                     component_size + 1U);
    }
    return 0;
}

/** @brief Decode one exact canonical configuration object. */
int jg_logging_config_decode(const char *input,
                             size_t input_size,
                             struct jg_logging_config *config)
{
    static const char *const fields[] = {
        "global_level",   "destinations",     "rate_limit_per_second",
        "trace_capacity", "diagnostic_until", "include_identifiers",
        "overrides",
    };
    json_error_t error;
    json_t *object = NULL;
    json_t *global_level = NULL;
    json_t *rate_limit = NULL;
    json_t *trace_capacity = NULL;
    json_t *diagnostic_until = NULL;
    json_t *include_identifiers = NULL;
    json_int_t number = 0;
    int result = 0;

    if (input == NULL || input_size == 0U || config == NULL) {
        return -EINVAL;
    }
    (void)memset(config, 0, sizeof(*config));
    object = json_loadb(input, input_size, JSON_REJECT_DUPLICATES, &error);
    if (!fields_allowed(object, fields, sizeof(fields) / sizeof(fields[0U])) ||
        json_object_size(object) != sizeof(fields) / sizeof(fields[0U])) {
        result = -EINVAL;
    }
    if (result == 0) {
        global_level = json_object_get(object, "global_level");
        rate_limit = json_object_get(object, "rate_limit_per_second");
        trace_capacity = json_object_get(object, "trace_capacity");
        diagnostic_until = json_object_get(object, "diagnostic_until");
        include_identifiers = json_object_get(object, "include_identifiers");
        if (jg_log_level_parse(json_string_value(global_level),
                               &config->global_level) != 0 ||
            !json_is_integer(rate_limit) || !json_is_integer(trace_capacity) ||
            !json_is_integer(diagnostic_until) ||
            (!json_is_true(include_identifiers) &&
             !json_is_false(include_identifiers))) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        number = json_integer_value(rate_limit);
        if (number <= 0 || (uint64_t)number > UINT32_MAX) {
            result = -ERANGE;
        } else {
            config->rate_limit_per_second = (uint32_t)number;
        }
    }
    if (result == 0) {
        number = json_integer_value(trace_capacity);
        if (number < 0 || (uint64_t)number > UINT32_MAX) {
            result = -ERANGE;
        } else {
            config->trace_capacity = (uint32_t)number;
        }
    }
    if (result == 0) {
        number = json_integer_value(diagnostic_until);
        if (number < 0) {
            result = -ERANGE;
        } else {
            config->diagnostic_until = (uint64_t)number;
        }
    }
    if (result == 0) {
        config->include_identifiers = json_is_true(include_identifiers);
        result = decode_destinations(json_object_get(object, "destinations"),
                                     &config->destinations);
    }
    if (result == 0) {
        result = decode_overrides(json_object_get(object, "overrides"), config);
    }
    if (result == 0) {
        result = jg_logging_config_validate(config);
    }
    json_decref(object);
    if (result != 0) {
        (void)memset(config, 0, sizeof(*config));
    }
    return result;
}

/** @brief Read current whole real-time seconds. */
static int realtime_seconds(uint64_t *seconds)
{
    struct timespec value;

    if (clock_gettime(CLOCK_REALTIME, &value) != 0) {
        return -errno;
    }
    if (value.tv_sec < 0) {
        return -EIO;
    }
    *seconds = (uint64_t)value.tv_sec;
    return 0;
}

/** @brief Determine whether diagnostic levels are currently active. */
static bool diagnostic_active_locked(uint64_t now)
{
    return logger.config.diagnostic_until != 0U &&
           now < logger.config.diagnostic_until;
}

/** @brief Select one configured level while holding the logger lock. */
static enum jg_log_level configured_level_locked(const char *component,
                                                 uint64_t now)
{
    enum jg_log_level selected = logger.config.global_level;

    for (size_t index = 0U; index < logger.config.override_count; ++index) {
        if (strcmp(component, logger.config.overrides[index].component) == 0) {
            selected = logger.config.overrides[index].level;
            break;
        }
    }
    if (selected > JG_LOG_INFO && !diagnostic_active_locked(now)) {
        selected = JG_LOG_INFO;
    }
    return selected;
}

/** @brief Return the greatest configured severity for fast-path filtering. */
static enum jg_log_level maximum_configured_level(
    const struct jg_logging_config *config)
{
    enum jg_log_level maximum = config->global_level;

    for (size_t index = 0U; index < config->override_count; ++index) {
        if (config->overrides[index].level > maximum) {
            maximum = config->overrides[index].level;
        }
    }
    return maximum;
}

/** @brief Configure syslog ownership while holding the logger lock. */
static void configure_syslog_locked(void)
{
    const bool requested =
        (logger.config.destinations & JG_LOG_DESTINATION_SYSLOG) != 0U;

    if (requested && !logger.syslog_open) {
        openlog(logger.process, LOG_NDELAY | LOG_PID, LOG_DAEMON);
        logger.syslog_open = true;
    } else if (!requested && logger.syslog_open) {
        closelog();
        logger.syslog_open = false;
    }
}

/** @brief Reset bounded records and rate counters while holding the lock. */
static void reset_runtime_locked(void)
{
    (void)memset(logger.records, 0, sizeof(logger.records));
    logger.emitted = 0U;
    logger.suppressed = 0U;
    logger.window_second = 0U;
    logger.pending_suppressed = 0U;
    logger.window_records = 0U;
    logger.record_start = 0U;
    logger.record_count = 0U;
}

/** @brief Initialize process identity and apply one logger configuration. */
int jg_logging_initialize(const char *process,
                          const struct jg_logging_config *config)
{
    const size_t process_size = bounded_length(process, JG_LOG_PROCESS_MAX);
    int result = jg_logging_config_validate(config);

    if (result != 0 || !identifier_valid(process, JG_LOG_PROCESS_MAX)) {
        return result != 0 ? result : -EINVAL;
    }
    result = pthread_mutex_lock(&logger.lock);
    if (result != 0) {
        return -result;
    }
    if (logger.syslog_open) {
        closelog();
        logger.syslog_open = false;
    }
    (void)memcpy(logger.process, process, process_size + 1U);
    logger.config = *config;
    atomic_store(&logger.maximum_level, maximum_configured_level(config));
    atomic_store(&logger.diagnostic_until, config->diagnostic_until);
    logger.initialized = true;
    reset_runtime_locked();
    configure_syslog_locked();
    result = pthread_mutex_unlock(&logger.lock);
    return result == 0 ? 0 : -result;
}

/** @brief Atomically replace process logging configuration. */
int jg_logging_configure(const struct jg_logging_config *config)
{
    int result = jg_logging_config_validate(config);

    if (result != 0) {
        return result;
    }
    result = pthread_mutex_lock(&logger.lock);
    if (result != 0) {
        return -result;
    }
    if (!logger.initialized) {
        (void)memcpy(logger.process, "janusgate", sizeof("janusgate"));
        logger.initialized = true;
    }
    logger.config = *config;
    atomic_store(&logger.maximum_level, maximum_configured_level(config));
    atomic_store(&logger.diagnostic_until, config->diagnostic_until);
    reset_runtime_locked();
    configure_syslog_locked();
    result = pthread_mutex_unlock(&logger.lock);
    return result == 0 ? 0 : -result;
}

/** @brief Copy current configuration and counters while holding the lock. */
static int get_locked(struct jg_logging_config *config,
                      struct jg_logging_stats *stats)
{
    uint64_t now = 0U;
    int result = realtime_seconds(&now);

    if (result != 0) {
        return result;
    }
    if (config != NULL) {
        *config = logger.config;
    }
    if (stats != NULL) {
        *stats = (struct jg_logging_stats){
            .emitted = logger.emitted,
            .suppressed = logger.suppressed,
            .buffered = logger.record_count,
            .diagnostic_active = diagnostic_active_locked(now),
        };
    }
    return 0;
}

/** @brief Copy current configuration and counters. */
int jg_logging_get(struct jg_logging_config *config,
                   struct jg_logging_stats *stats)
{
    int result = pthread_mutex_lock(&logger.lock);

    if (result != 0) {
        return -result;
    }
    result = get_locked(config, stats);
    {
        const int unlock_result = pthread_mutex_unlock(&logger.lock);

        if (result == 0 && unlock_result != 0) {
            result = -unlock_result;
        }
    }
    return result;
}

/** @brief Determine whether one level is enabled for a component. */
bool jg_log_enabled(const char *component, enum jg_log_level level)
{
    uint64_t now = 0U;
    bool enabled = false;
    int result = 0;

    if (!identifier_valid(component, JG_LOG_COMPONENT_MAX) ||
        jg_log_level_name(level) == NULL ||
        level > (enum jg_log_level)atomic_load(&logger.maximum_level) ||
        realtime_seconds(&now) != 0 ||
        (level > JG_LOG_INFO && now >= atomic_load(&logger.diagnostic_until))) {
        return false;
    }
    result = pthread_mutex_lock(&logger.lock);
    if (result != 0) {
        return false;
    }
    enabled =
        logger.initialized && level <= configured_level_locked(component, now);
    (void)pthread_mutex_unlock(&logger.lock);
    return enabled;
}

/** @brief Compare a detail name with one exact case-insensitive value. */
static bool key_equal(const char *key, const char *expected)
{
    size_t index = 0U;

    while (key[index] != '\0' && expected[index] != '\0') {
        uint8_t left = (uint8_t)key[index];
        uint8_t right = (uint8_t)expected[index];

        if (left >= (uint8_t)'A' && left <= (uint8_t)'Z') {
            left = (uint8_t)(left - (uint8_t)'A' + (uint8_t)'a');
        }
        if (right >= (uint8_t)'A' && right <= (uint8_t)'Z') {
            right = (uint8_t)(right - (uint8_t)'A' + (uint8_t)'a');
        }
        if (left != right) {
            return false;
        }
        ++index;
    }
    return key[index] == '\0' && expected[index] == '\0';
}

/** @brief Identify fields whose values must never enter logs. */
static bool secret_key(const char *key)
{
    static const char *const names[] = {
        "password",          "password_hash", "token",       "api_token",
        "session",           "session_id",    "cookie",      "authorization",
        "private_key",       "secret",        "totp_secret", "recovery_code",
        "backup_passphrase",
    };

    for (size_t index = 0U; index < sizeof(names) / sizeof(names[0U]);
         ++index) {
        if (key_equal(key, names[index])) {
            return true;
        }
    }
    return false;
}

/** @brief Identify client and domain fields controlled by privacy settings. */
static bool identifier_key(const char *key)
{
    static const char *const names[] = {
        "domain",         "qname",          "hostname",       "server_name",
        "source_address", "client_address", "remote_address", "mac_address",
    };

    for (size_t index = 0U; index < sizeof(names) / sizeof(names[0U]);
         ++index) {
        if (key_equal(key, names[index])) {
            return true;
        }
    }
    return false;
}

/** @brief Recursively redact one owned JSON value in place. */
static int redact_json(json_t *value, bool include_identifiers)
{
    if (json_is_object(value)) {
        const char *key = NULL;
        json_t *member = NULL;

        json_object_foreach(value, key, member)
        {
            if (secret_key(key) ||
                (!include_identifiers && identifier_key(key))) {
                if (json_object_set_new(value, key,
                                        json_string("[redacted]")) != 0) {
                    return -ENOMEM;
                }
            } else if (redact_json(member, include_identifiers) != 0) {
                return -ENOMEM;
            }
        }
    } else if (json_is_array(value)) {
        size_t index = 0U;
        json_t *member = NULL;

        json_array_foreach(value, index, member)
        {
            if (redact_json(member, include_identifiers) != 0) {
                return -ENOMEM;
            }
        }
    }
    return 0;
}

/** @brief Decode and redact one bounded optional detail object. */
static int safe_details(const char *details,
                        bool include_identifiers,
                        json_t **value)
{
    const size_t details_size =
        details == NULL ? 0U : bounded_length(details, JG_LOG_DETAILS_MAX);
    json_error_t error;
    int result = 0;

    *value = NULL;
    if (details == NULL) {
        return 0;
    }
    if (details_size == 0U || details_size > JG_LOG_DETAILS_MAX) {
        return -EINVAL;
    }
    *value = json_loadb(details, details_size, JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(*value)) {
        json_decref(*value);
        *value = NULL;
        return -EINVAL;
    }
    result = redact_json(*value, include_identifiers);
    if (result != 0) {
        json_decref(*value);
        *value = NULL;
    }
    return result;
}

/** @brief Format one real-time timestamp with millisecond precision. */
static int timestamp_now(char output[25U],
                         uint64_t *seconds,
                         uint32_t *milliseconds)
{
    struct timespec value;
    struct tm utc;
    time_t time_value = 0;

    if (clock_gettime(CLOCK_REALTIME, &value) != 0) {
        return -errno;
    }
    if (value.tv_sec < 0) {
        return -EIO;
    }
    time_value = value.tv_sec;
    if ((uint64_t)time_value != (uint64_t)value.tv_sec ||
        gmtime_r(&time_value, &utc) == NULL) {
        return -EOVERFLOW;
    }
    if (strftime(output, 21U, "%Y-%m-%dT%H:%M:%S", &utc) != 19U) {
        return -EOVERFLOW;
    }
    *milliseconds = (uint32_t)(value.tv_nsec / 1000000L);
    if (snprintf(output + 19U, 6U, ".%03uZ", *milliseconds) != 5) {
        return -EOVERFLOW;
    }
    *seconds = (uint64_t)value.tv_sec;
    return 0;
}

/** @brief Map one internal level to a syslog priority. */
static int syslog_priority(enum jg_log_level level)
{
    switch (level) {
    case JG_LOG_ERROR:
        return LOG_ERR;
    case JG_LOG_WARNING:
        return LOG_WARNING;
    case JG_LOG_INFO:
        return LOG_INFO;
    case JG_LOG_DEBUG:
    case JG_LOG_TRACE:
    default:
        return LOG_DEBUG;
    }
}

/** @brief Write every byte to standard error despite interruptions. */
static int write_stderr(const char *data, size_t size)
{
    size_t offset = 0U;

    while (offset < size) {
        const ssize_t written =
            write(STDERR_FILENO, data + offset, size - offset);

        if (written < 0) {
            if (errno != EINTR) {
                return -errno;
            }
        } else if (written == 0) {
            return -EIO;
        } else {
            offset += (size_t)written;
        }
    }
    return 0;
}

/** @brief Retain one emitted record in the configured circular buffer. */
static void retain_locked(const char *encoded)
{
    size_t index = 0U;

    if (logger.config.trace_capacity == 0U) {
        return;
    }
    if (logger.record_count < logger.config.trace_capacity) {
        index = (logger.record_start + logger.record_count) %
                logger.config.trace_capacity;
        ++logger.record_count;
    } else {
        index = logger.record_start;
        logger.record_start =
            (logger.record_start + 1U) % logger.config.trace_capacity;
    }
    (void)memcpy(logger.records[index].json, encoded, strlen(encoded) + 1U);
}

/** @brief Apply one fixed-window rate decision while holding the lock. */
static bool rate_accept_locked(uint64_t now)
{
    if (logger.window_second != now) {
        logger.window_second = now;
        logger.window_records = 0U;
    }
    if (logger.window_records >= logger.config.rate_limit_per_second) {
        if (logger.suppressed != UINT64_MAX) {
            ++logger.suppressed;
        }
        if (logger.pending_suppressed != UINT64_MAX) {
            ++logger.pending_suppressed;
        }
        return false;
    }
    ++logger.window_records;
    return true;
}

/** @brief Build one final structured record while holding the lock. */
static int encode_record_locked(enum jg_log_level level,
                                const char *component,
                                const char *event_code,
                                const char *correlation_id,
                                const char *message,
                                const char *timestamp,
                                json_t *details,
                                char output[JG_LOG_RECORD_MAX + 1U])
{
    json_t *record = json_object();
    char *encoded = NULL;
    size_t encoded_size = 0U;
    int result = 0;

    if (record == NULL ||
        json_object_set_new(record, "timestamp", json_string(timestamp)) != 0 ||
        json_object_set_new(record, "severity",
                            json_string(jg_log_level_name(level))) != 0 ||
        json_object_set_new(record, "process", json_string(logger.process)) !=
            0 ||
        json_object_set_new(record, "component", json_string(component)) != 0 ||
        json_object_set_new(record, "event", json_string(event_code)) != 0 ||
        json_object_set_new(record, "message", json_string(message)) != 0 ||
        (correlation_id != NULL &&
         json_object_set_new(record, "correlation_id",
                             json_string(correlation_id)) != 0) ||
        (details != NULL && json_object_set(record, "details", details) != 0) ||
        (logger.pending_suppressed != 0U &&
         json_object_set_new(
             record, "suppressed_since_last",
             json_integer((json_int_t)logger.pending_suppressed)) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(record, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        encoded_size = strlen(encoded);
        if (encoded_size > JG_LOG_RECORD_MAX) {
            result = -EMSGSIZE;
        } else {
            (void)memcpy(output, encoded, encoded_size + 1U);
            logger.pending_suppressed = 0U;
        }
    }
    free(encoded);
    json_decref(record);
    return result;
}

/** @brief Emit one bounded structured operational record. */
int jg_log_emit(enum jg_log_level level,
                const char *component,
                const char *event_code,
                const char *correlation_id,
                const char *message,
                const char *details)
{
    const size_t message_size = bounded_length(message, JG_LOG_MESSAGE_MAX);
    char timestamp[25U];
    char encoded[JG_LOG_RECORD_MAX + 1U];
    json_t *safe = NULL;
    uint64_t now = 0U;
    uint32_t milliseconds = 0U;
    size_t encoded_size = 0U;
    int result = 0;
    int unlock_result = 0;

    if (jg_log_level_name(level) == NULL ||
        !identifier_valid(component, JG_LOG_COMPONENT_MAX) ||
        !identifier_valid(event_code, JG_LOG_EVENT_CODE_MAX) ||
        !correlation_valid(correlation_id) || message_size == 0U ||
        message_size > JG_LOG_MESSAGE_MAX) {
        return -EINVAL;
    }
    if (level > (enum jg_log_level)atomic_load(&logger.maximum_level)) {
        return 0;
    }
    result = timestamp_now(timestamp, &now, &milliseconds);
    (void)milliseconds;
    if (result != 0) {
        return result;
    }
    if (level > JG_LOG_INFO && now >= atomic_load(&logger.diagnostic_until)) {
        return 0;
    }
    result = pthread_mutex_lock(&logger.lock);
    if (result != 0) {
        return -result;
    }
    if (!logger.initialized ||
        level > configured_level_locked(component, now)) {
        (void)pthread_mutex_unlock(&logger.lock);
        return 0;
    }
    result = safe_details(details,
                          logger.config.include_identifiers &&
                              diagnostic_active_locked(now),
                          &safe);
    if (result == 0 && !rate_accept_locked(now)) {
        json_decref(safe);
        (void)pthread_mutex_unlock(&logger.lock);
        return 0;
    }
    if (result == 0) {
        result =
            encode_record_locked(level, component, event_code, correlation_id,
                                 message, timestamp, safe, encoded);
    }
    json_decref(safe);
    if (result == 0) {
        encoded_size = strlen(encoded);
        if ((logger.config.destinations & JG_LOG_DESTINATION_STDERR) != 0U) {
            result = write_stderr(encoded, encoded_size);
            if (result == 0) {
                result = write_stderr("\n", 1U);
            }
        }
        if ((logger.config.destinations & JG_LOG_DESTINATION_SYSLOG) != 0U) {
            syslog(syslog_priority(level), "%s", encoded);
        }
        if (result == 0) {
            if (logger.emitted != UINT64_MAX) {
                ++logger.emitted;
            }
            retain_locked(encoded);
        }
    }
    unlock_result = pthread_mutex_unlock(&logger.lock);
    if (result == 0 && unlock_result != 0) {
        result = -unlock_result;
    }
    return result;
}

/** @brief Copy the newest retained records in chronological order. */
int jg_logging_trace_snapshot(struct jg_log_trace_record *records,
                              size_t capacity,
                              size_t *count,
                              struct jg_logging_stats *stats)
{
    size_t copied = 0U;
    size_t skip = 0U;
    int result = 0;

    if (records == NULL || capacity == 0U ||
        capacity > JG_LOG_TRACE_CAPACITY_MAX || count == NULL) {
        return -EINVAL;
    }
    *count = 0U;
    result = pthread_mutex_lock(&logger.lock);
    if (result != 0) {
        return -result;
    }
    skip = logger.record_count > capacity ? logger.record_count - capacity : 0U;
    copied = logger.record_count - skip;
    for (size_t index = 0U; index < copied; ++index) {
        const size_t source =
            (logger.record_start + skip + index) %
            (logger.config.trace_capacity == 0U ? 1U
                                                : logger.config.trace_capacity);

        records[index] = logger.records[source];
    }
    result = get_locked(NULL, stats);
    if (result == 0) {
        *count = copied;
    }
    {
        const int unlock_result = pthread_mutex_unlock(&logger.lock);

        if (result == 0 && unlock_result != 0) {
            result = -unlock_result;
        }
    }
    return result;
}

/** @brief Close syslog state and clear all retained records. */
void jg_logging_shutdown(void)
{
    if (pthread_mutex_lock(&logger.lock) != 0) {
        return;
    }
    if (logger.syslog_open) {
        closelog();
    }
    (void)memset(&logger.config, 0, sizeof(logger.config));
    atomic_store(&logger.maximum_level, JG_LOG_ERROR);
    atomic_store(&logger.diagnostic_until, 0U);
    (void)memset(logger.records, 0, sizeof(logger.records));
    (void)memset(logger.process, 0, sizeof(logger.process));
    logger.emitted = 0U;
    logger.suppressed = 0U;
    logger.window_second = 0U;
    logger.pending_suppressed = 0U;
    logger.window_records = 0U;
    logger.record_start = 0U;
    logger.record_count = 0U;
    logger.initialized = false;
    logger.syslog_open = false;
    (void)pthread_mutex_unlock(&logger.lock);
}
