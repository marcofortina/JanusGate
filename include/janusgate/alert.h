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

/** Opaque database connection declared by database.h. */
struct jg_database;

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

#endif
