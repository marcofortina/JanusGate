/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file alert.h
 * @brief Persistent native alert configuration and incident lifecycle.
 *
 * Alert conditions are reconciled into durable open or resolved incidents.
 * Optional HTTPS delivery uses an independently generated HMAC secret which
 * is encrypted by the appliance protection key before persistence.
 *
 * @thread_safety The caller must serialize access to each database object.
 * Distinct database objects follow SQLite's normal locking rules.
 */

#ifndef JANUSGATE_ALERT_H
#define JANUSGATE_ALERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/certificate.h"
#include "janusgate/version.h"

/** Largest HTTPS webhook URL excluding its terminator. */
#define JG_ALERT_WEBHOOK_URL_MAX 2048U

/** Largest optional webhook CA bundle excluding its terminator. */
#define JG_ALERT_WEBHOOK_CA_MAX JG_CERTIFICATE_PEM_MAX

/** Raw bytes in one generated webhook HMAC secret. */
#define JG_ALERT_WEBHOOK_SECRET_SIZE 32U

/** Lowercase hexadecimal webhook secret bytes including its terminator. */
#define JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE                                      \
    (JG_ALERT_WEBHOOK_SECRET_SIZE * 2U + 1U)

/** Smallest periodic alert evaluation interval. */
#define JG_ALERT_EVALUATION_INTERVAL_MIN 30U

/** Largest periodic alert evaluation interval. */
#define JG_ALERT_EVALUATION_INTERVAL_MAX 3600U

/** Number of fixed alert types exposed as bounded metric labels. */
#define JG_ALERT_TYPE_COUNT 8U

/** Largest alert resource identity excluding its terminator. */
#define JG_ALERT_RESOURCE_MAX 128U

/** Largest human-readable alert summary excluding its terminator. */
#define JG_ALERT_SUMMARY_MAX 512U

/** Largest canonical alert detail object excluding its terminator. */
#define JG_ALERT_DETAILS_MAX 4096U

/** Largest incident page returned by one query. */
#define JG_ALERT_PAGE_MAX 100U

/** Largest stable notification event code excluding its terminator. */
#define JG_ALERT_EVENT_CODE_MAX 128U

/** Largest canonical webhook payload excluding its terminator. */
#define JG_ALERT_PAYLOAD_MAX 8192U

/** Largest retained webhook delivery error excluding its terminator. */
#define JG_ALERT_DELIVERY_ERROR_MAX 512U

/** Lowercase hexadecimal webhook event identity including its terminator. */
#define JG_ALERT_EVENT_ID_SIZE 33U

/** Raw bytes in one transient webhook delivery claim. */
#define JG_ALERT_DELIVERY_CLAIM_SIZE 16U

/** Opaque database connection declared by database.h. */
struct jg_database;

/**
 * @brief Fixed native condition types.
 */
enum jg_alert_type {
    /** Invalid type and list-filter wildcard. */
    JG_ALERT_TYPE_ANY = 0,
    /** Management consistency is degraded. */
    JG_ALERT_TYPE_APPLIANCE_DEGRADED = 1,
    /** Desired and applied policy revisions differ. */
    JG_ALERT_TYPE_POLICY_UNSYNCHRONIZED = 2,
    /** Audit-chain verification failed. */
    JG_ALERT_TYPE_AUDIT_UNVERIFIABLE = 3,
    /** An appliance certificate approaches expiry. */
    JG_ALERT_TYPE_CERTIFICATE_EXPIRING = 4,
    /** An enabled blocklist source is unhealthy or stale. */
    JG_ALERT_TYPE_SOURCE_UNHEALTHY = 5,
    /** A JanusGate filesystem has insufficient free space. */
    JG_ALERT_TYPE_FILESYSTEM_LOW_SPACE = 6,
    /** Packet queues dropped traffic during one observation window. */
    JG_ALERT_TYPE_QUEUE_DROPS = 7,
    /** Authentication failures crossed the configured threshold. */
    JG_ALERT_TYPE_AUTHENTICATION_FAILURES = 8
};

/**
 * @brief Native alert severity.
 */
enum jg_alert_severity {
    /** Recoverable condition needing attention. */
    JG_ALERT_SEVERITY_WARNING = 1,
    /** Failed subsystem operation. */
    JG_ALERT_SEVERITY_ERROR = 2,
    /** Enforcement or integrity failure. */
    JG_ALERT_SEVERITY_CRITICAL = 3
};

/**
 * @brief Persistent incident lifecycle state.
 */
enum jg_alert_state {
    /** List-filter wildcard; invalid for a stored incident. */
    JG_ALERT_STATE_ANY = 0,
    /** Condition is currently present. */
    JG_ALERT_STATE_OPEN = 1,
    /** Condition is no longer present. */
    JG_ALERT_STATE_RESOLVED = 2
};

/**
 * @brief Result of reconciling one evaluated condition.
 */
enum jg_alert_transition {
    /** No persistent state transition occurred. */
    JG_ALERT_TRANSITION_NONE = 0,
    /** A new incident was opened. */
    JG_ALERT_TRANSITION_OPEN = 1,
    /** An existing incident was resolved. */
    JG_ALERT_TRANSITION_RESOLVED = 2
};

/**
 * @brief Evaluated native alert content.
 */
struct jg_alert_condition {
    /** Fixed condition type. */
    enum jg_alert_type type;
    /** Stable bounded resource identity. */
    const char *resource;
    /** Current condition severity. */
    enum jg_alert_severity severity;
    /** Human-readable administrative summary. */
    const char *summary;
    /** JSON object canonicalized before persistence. */
    const char *details;
};

/**
 * @brief Self-contained immutable incident record.
 */
struct jg_alert_incident {
    /** Persistent positive incident identifier. */
    uint64_t id;
    /** Fixed native condition type. */
    enum jg_alert_type type;
    /** Stable resource identity. */
    char resource[JG_ALERT_RESOURCE_MAX + 1U];
    /** Incident severity. */
    enum jg_alert_severity severity;
    /** Current lifecycle state. */
    enum jg_alert_state state;
    /** Human-readable summary. */
    char summary[JG_ALERT_SUMMARY_MAX + 1U];
    /** Canonical JSON detail object. */
    char details[JG_ALERT_DETAILS_MAX + 1U];
    /** Unix timestamp at which the incident opened. */
    uint64_t opened_at;
    /** Unix timestamp of the last material update. */
    uint64_t updated_at;
    /** Unix timestamp at resolution, or zero while open. */
    uint64_t resolved_at;
    /** Number of times the same condition key has opened. */
    uint64_t occurrences;
};

/**
 * @brief Stable filters for a newest-first incident page.
 */
struct jg_alert_filter {
    /** Exclusive descending identifier cursor, or zero for the newest page. */
    uint64_t before_id;
    /** Exact state or @ref JG_ALERT_STATE_ANY. */
    enum jg_alert_state state;
    /** Exact type or @ref JG_ALERT_TYPE_ANY. */
    enum jg_alert_type type;
};

/**
 * @brief One due webhook delivery copied from the durable outbox.
 */
struct jg_alert_delivery {
    /** Internal persistent outbox identifier. */
    uint64_t id;
    /** Globally unique event identity exposed to webhook receivers. */
    char event_id[JG_ALERT_EVENT_ID_SIZE];
    /** Opaque ownership token for this delivery attempt. */
    uint8_t claim[JG_ALERT_DELIVERY_CLAIM_SIZE];
    /** Canonical webhook JSON body. */
    char payload[JG_ALERT_PAYLOAD_MAX + 1U];
    /** Number of prior failed delivery attempts. */
    uint32_t attempts;
};

/**
 * @brief Bounded monitoring aggregates derived from alert storage.
 */
struct jg_alert_storage_metrics {
    /** Open incidents indexed by enum value minus one. */
    uint64_t open_by_type[JG_ALERT_TYPE_COUNT];
    /** Total incident-opening transitions retained. */
    uint64_t opened_total;
    /** Total incident-resolution transitions retained. */
    uint64_t resolved_total;
    /** Pending webhook deliveries. */
    uint64_t deliveries_pending;
    /** Successfully delivered webhook notifications retained. */
    uint64_t deliveries_succeeded;
    /** Permanently abandoned webhook notifications retained. */
    uint64_t deliveries_failed;
};

/** @brief Return the stable persistent name for one alert type. */
JG_PUBLIC const char *jg_alert_type_name(enum jg_alert_type type);

/** @brief Return the stable persistent name for one alert severity. */
JG_PUBLIC const char *jg_alert_severity_name(enum jg_alert_severity severity);

/** @brief Return the stable persistent name for one alert state. */
JG_PUBLIC const char *jg_alert_state_name(enum jg_alert_state state);

/**
 * @brief Borrowed replacement values for native alerting.
 */
struct jg_alert_configuration_update {
    /** Whether native condition evaluation is enabled. */
    bool enabled;
    /** Seconds between condition evaluations. */
    uint32_t evaluation_interval_seconds;
    /** Remaining certificate lifetime which opens a warning. */
    uint32_t certificate_warning_days;
    /** Consecutive source failures which open an incident. */
    uint32_t source_failure_threshold;
    /** Maximum age of a successful enabled source refresh. */
    uint32_t source_stale_seconds;
    /** Minimum filesystem space percentage before an incident opens. */
    uint32_t filesystem_minimum_percent;
    /** Minimum filesystem bytes before an incident opens. */
    uint64_t filesystem_minimum_bytes;
    /** Fixed queue-drop observation window in seconds. */
    uint32_t queue_window_seconds;
    /** Queue drops in one window which open an incident. */
    uint64_t queue_drop_threshold;
    /** Fixed authentication-failure window in seconds. */
    uint32_t authentication_window_seconds;
    /** Authentication failures in one window which open an incident. */
    uint64_t authentication_failure_threshold;
    /** Whether incident transitions are delivered to the webhook. */
    bool webhook_enabled;
    /** Absolute HTTPS webhook URL, or null when unconfigured. */
    const char *webhook_url;
    /** Optional CA-only PEM bundle for a private webhook PKI. */
    const char *webhook_ca_pem;
    /** Complete webhook request timeout in seconds. */
    uint32_t webhook_timeout_seconds;
};

/**
 * @brief Owned persistent alert configuration and concurrency metadata.
 */
struct jg_alert_configuration {
    /** Validated configuration values; strings point into owned storage. */
    struct jg_alert_configuration_update values;
    /** Whether an encrypted webhook secret is available. */
    bool webhook_secret_configured;
    /** Optimistic concurrency revision. */
    uint64_t revision;
    /** Unix timestamp of the last configuration or secret update. */
    uint64_t updated_at;
    /** Owned webhook URL storage; null when absent. */
    char *webhook_url_storage;
    /** Owned webhook CA storage; null when absent. */
    char *webhook_ca_storage;
};

/**
 * @brief Populate safe default alert settings.
 *
 * @param[out] update Receives defaults with webhook delivery disabled.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_alert_configuration_default(
    struct jg_alert_configuration_update *update);

/**
 * @brief Validate one complete alert configuration replacement.
 *
 * A webhook URL must use HTTPS and must not contain user information or a
 * fragment. A custom CA bundle must contain only valid CA certificates.
 * Webhook enablement additionally requires a secret and is enforced by the
 * persistent replacement operation.
 *
 * @return 0 when valid.
 * @return -EINVAL for invalid bounds, URL syntax, or PEM material.
 * @return -EILSEQ for invalid UTF-8.
 * @return A negative allocation or cryptographic error otherwise.
 */
JG_PUBLIC int jg_alert_configuration_validate(
    const struct jg_alert_configuration_update *update);

/**
 * @brief Release strings owned by a loaded alert configuration.
 *
 * @param[in,out] configuration Record to clear; null is accepted.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC void jg_alert_configuration_clear(
    struct jg_alert_configuration *configuration);

/**
 * @brief Load and validate the singleton persistent alert configuration.
 *
 * @param[in,out] database Open database.
 * @param[out] configuration Zero-initialized destination record.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return -EILSEQ for invalid persistent data.
 * @return A negative allocation or SQLite error otherwise.
 *
 * @side_effects Allocates optional URL and CA strings. The caller must invoke
 * jg_alert_configuration_clear() after success.
 */
JG_PUBLIC int jg_database_alert_configuration_load(
    struct jg_database *database,
    struct jg_alert_configuration *configuration);

/**
 * @brief Replace alert settings at one expected revision.
 *
 * Existing webhook secret material is retained and must already exist when
 * webhook delivery is enabled.
 *
 * @param[in,out] database Open database.
 * @param[in] update Complete validated replacement.
 * @param[in] expected_revision Exact current revision.
 * @param[in] updated_at Current Unix timestamp in seconds.
 * @param[out] updated Receives the new owned record.
 *
 * @return 0 on success.
 * @return -EAGAIN for a revision conflict.
 * @return -ENOENT when webhook enablement lacks a generated secret.
 * @return -EOVERFLOW when the revision cannot advance.
 * @return Another validation, allocation, or SQLite error otherwise.
 */
JG_PUBLIC int jg_database_alert_configuration_replace(
    struct jg_database *database,
    const struct jg_alert_configuration_update *update,
    uint64_t expected_revision,
    uint64_t updated_at,
    struct jg_alert_configuration *updated);

/**
 * @brief Generate and atomically replace the webhook HMAC secret.
 *
 * The plaintext secret is returned exactly once as lowercase hexadecimal and
 * is otherwise retained only as authenticated ciphertext.
 *
 * @param[in,out] database Open database.
 * @param[in] protection_key Exact appliance-local protection key.
 * @param[in] expected_revision Exact current configuration revision.
 * @param[in] updated_at Current Unix timestamp in seconds.
 * @param[out] secret_text Receives the new one-time secret.
 * @param[out] updated Receives the updated owned configuration.
 *
 * @return 0 on success, with the secret available to the caller.
 * @return -EAGAIN for a revision conflict.
 * @return A negative validation, cryptographic, allocation, or SQLite error
 * otherwise.
 *
 * @side_effects Obtains cryptographically secure randomness.
 */
JG_PUBLIC int jg_database_alert_webhook_secret_rotate(
    struct jg_database *database,
    const uint8_t protection_key[JG_ALERT_WEBHOOK_SECRET_SIZE],
    uint64_t expected_revision,
    uint64_t updated_at,
    char secret_text[JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE],
    struct jg_alert_configuration *updated);

/**
 * @brief Authenticate and decrypt the persistent webhook HMAC secret.
 *
 * @param[in,out] database Open database.
 * @param[in] protection_key Exact appliance-local protection key.
 * @param[out] secret Receives plaintext only after authentication.
 *
 * @return 0 on success.
 * @return -ENOENT when no webhook secret is configured.
 * @return -EBADMSG when persistent ciphertext authentication fails.
 * @return Another negative validation, cryptographic, or SQLite error.
 *
 * @side_effects The caller must securely clear @p secret after use.
 */
JG_PUBLIC int jg_database_alert_webhook_secret_load(
    struct jg_database *database,
    const uint8_t protection_key[JG_ALERT_WEBHOOK_SECRET_SIZE],
    uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE]);

/**
 * @brief Reconcile one evaluated condition with persistent incident state.
 *
 * Repeated active evaluations are deduplicated. Only an opening, resolution,
 * or material content change writes storage. Opening and resolution enqueue a
 * webhook notification atomically when delivery is enabled.
 *
 * @param[in,out] database Open database.
 * @param[in] condition Complete evaluated condition content.
 * @param[in] active Whether the condition is currently present.
 * @param[in] notify Whether a state transition enters the webhook outbox.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] incident Receives the current or changed incident; zero when an
 * absent condition had no open incident.
 * @param[out] transition Receives the resulting lifecycle transition.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid content or arguments.
 * @return -EILSEQ for invalid UTF-8 or persistent data.
 * @return A negative allocation or SQLite error otherwise.
 */
JG_PUBLIC int jg_database_alert_reconcile(
    struct jg_database *database,
    const struct jg_alert_condition *condition,
    bool active,
    bool notify,
    uint64_t now,
    struct jg_alert_incident *incident,
    enum jg_alert_transition *transition);

/**
 * @brief List one stable newest-first page of alert incidents.
 *
 * @param[in,out] database Open database.
 * @param[in] filter Stable cursor and optional exact filters.
 * @param[out] incidents Array with room for at least @p capacity records.
 * @param[in] capacity Requested count from one through @ref JG_ALERT_PAGE_MAX.
 * @param[out] count Number of records written.
 * @param[out] has_more Whether another matching record follows the page.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments or filters.
 * @return -EILSEQ for invalid persistent data.
 * @return A negative SQLite error otherwise.
 */
JG_PUBLIC int jg_database_alert_list(struct jg_database *database,
                                     const struct jg_alert_filter *filter,
                                     struct jg_alert_incident *incidents,
                                     size_t capacity,
                                     size_t *count,
                                     bool *has_more);

/**
 * @brief Enqueue one bounded operational notification event.
 *
 * Events are distinct from persistent condition incidents and therefore have
 * no artificial open or resolved state.
 *
 * @param[in,out] database Open database.
 * @param[in] event_code Stable lowercase event identifier.
 * @param[in] severity Event severity.
 * @param[in] summary Human-readable event summary.
 * @param[in] details JSON object canonicalized before persistence.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] event_id Receives the globally unique event identity; null
 * discards it.
 *
 * @return 0 on success or a negative validation, allocation, or SQLite error.
 */
JG_PUBLIC int jg_database_alert_event_enqueue(
    struct jg_database *database,
    const char *event_code,
    enum jg_alert_severity severity,
    const char *summary,
    const char *details,
    uint64_t now,
    char event_id[JG_ALERT_EVENT_ID_SIZE]);

/**
 * @brief Atomically claim the oldest due pending webhook delivery.
 *
 * @return 0 when one delivery was loaded.
 * @return -ENOENT when no pending delivery is currently due.
 * @return A negative validation or SQLite error otherwise.
 */
JG_PUBLIC int jg_database_alert_delivery_next(
    struct jg_database *database,
    uint64_t now,
    struct jg_alert_delivery *delivery);

/**
 * @brief Atomically snapshot webhook transport and claim one due delivery.
 *
 * Configuration, secret material, and the outbox claim are read or changed in
 * one transaction. A transport update committed after this function returns
 * does not alter the claimed attempt.
 *
 * @param[in,out] database Open database.
 * @param[in] protection_key Exact appliance-local protection key.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[out] configuration Receives the owned transport snapshot.
 * @param[out] secret Receives the authenticated plaintext HMAC secret.
 * @param[out] delivery Receives the claimed delivery.
 *
 * @return 0 when one delivery and its transport were loaded.
 * @return -ENOENT when delivery is disabled or no event is currently due.
 * @return A negative validation, cryptographic, allocation, or SQLite error.
 *
 * @side_effects The caller must clear @p configuration and securely erase
 * @p secret after every successful call.
 */
JG_PUBLIC int jg_database_alert_delivery_claim(
    struct jg_database *database,
    const uint8_t protection_key[JG_ALERT_WEBHOOK_SECRET_SIZE],
    uint64_t now,
    struct jg_alert_configuration *configuration,
    uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE],
    struct jg_alert_delivery *delivery);

/**
 * @brief Complete one webhook delivery attempt.
 *
 * Successful attempts become delivered. Failures use bounded exponential
 * backoff and become permanently abandoned after ten attempts.
 *
 * @param[in,out] database Open database.
 * @param[in] delivery Delivery and opaque claim returned by
 * @ref jg_database_alert_delivery_claim or
 * @ref jg_database_alert_delivery_next.
 * @param[in] delivered Whether the remote endpoint accepted the payload.
 * @param[in] now Current Unix timestamp in seconds.
 * @param[in] error Administrative-safe failure text when not delivered.
 *
 * @return 0 on success.
 * @return -ENOENT when the pending identifier no longer exists.
 * @return A negative validation or SQLite error otherwise.
 */
JG_PUBLIC int jg_database_alert_delivery_complete(
    struct jg_database *database,
    const struct jg_alert_delivery *delivery,
    bool delivered,
    uint64_t now,
    const char *error);

/**
 * @brief Collect bounded incident and delivery aggregates for monitoring.
 *
 * @param[in,out] database Open database.
 * @param[out] metrics Receives a complete snapshot.
 *
 * @return 0 on success or a negative validation or SQLite error.
 */
JG_PUBLIC int jg_database_alert_storage_metrics(
    struct jg_database *database,
    struct jg_alert_storage_metrics *metrics);

/**
 * @brief Prune terminal alert history beyond fixed retention bounds.
 *
 * All open incidents and pending deliveries are retained. The newest 10,000
 * resolved incidents and newest 1,000 terminal deliveries are retained.
 *
 * @return 0 on success or a negative validation or SQLite error.
 */
JG_PUBLIC int jg_database_alert_prune(struct jg_database *database);

#endif
