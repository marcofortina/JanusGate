/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file alert_webhook.h
 * @brief Signed bounded HTTPS alert delivery.
 */

#ifndef JANUSGATE_DAEMON_ALERT_WEBHOOK_H
#define JANUSGATE_DAEMON_ALERT_WEBHOOK_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/alert.h"

/** Lowercase SHA-256 signature bytes including the sha256 prefix and null. */
#define ALERT_WEBHOOK_SIGNATURE_SIZE 72U

/**
 * @brief Create the canonical timestamp-bound webhook signature.
 *
 * The HMAC input is the decimal Unix timestamp, one period, then the exact
 * request body. This allows receivers to reject stale deliveries.
 *
 * @return 0 on success or a negative validation or cryptographic error.
 */
int alert_webhook_signature(const uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE],
                            uint64_t timestamp,
                            const char *payload,
                            size_t payload_size,
                            char signature[ALERT_WEBHOOK_SIGNATURE_SIZE]);

/**
 * @brief Deliver one signed JSON payload to an exact HTTPS endpoint.
 *
 * Redirects and environment proxies are disabled. Server certificates and
 * hostnames are always verified, optionally against a configured private CA.
 *
 * @return 0 for an HTTP 2xx response or a negative transport/status error.
 */
int alert_webhook_deliver(const char *url,
                          const char *ca_pem,
                          uint32_t timeout_seconds,
                          const uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE],
                          uint64_t delivery_id,
                          uint64_t timestamp,
                          const char *payload,
                          char error[JG_ALERT_DELIVERY_ERROR_MAX + 1U]);

#endif
