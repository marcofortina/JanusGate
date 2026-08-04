/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "alert_webhook.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <sodium.h>

#include "http_client.h"

/** Maximum ignored response body bytes. */
#define ALERT_WEBHOOK_RESPONSE_MAX 4096U

/** Counter for bounded response-body discard. */
struct response_counter {
    size_t received;
};

/** @brief Encode fixed bytes as lowercase hexadecimal text. */
static void encode_hex(const uint8_t *bytes, size_t size, char *text)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t index = 0U; index < size; ++index) {
        text[index * 2U] = digits[bytes[index] >> 4U];
        text[index * 2U + 1U] = digits[bytes[index] & UINT8_C(0x0f)];
    }
    text[size * 2U] = '\0';
}

/** @brief Discard one bounded webhook response body. */
static size_t discard_response(char *data,
                               size_t element_size,
                               size_t element_count,
                               void *context)
{
    struct response_counter *counter = context;
    size_t transferred = 0U;

    (void)data;
    if (element_size != 0U && element_count > SIZE_MAX / element_size) {
        return 0U;
    }
    transferred = element_size * element_count;
    if (transferred > ALERT_WEBHOOK_RESPONSE_MAX - counter->received) {
        return 0U;
    }
    counter->received += transferred;
    return transferred;
}

/** @brief Map one CURL operation result to an errno-style value. */
static int curl_result(CURLcode status)
{
    switch (status) {
    case CURLE_OK:
        return 0;
    case CURLE_OUT_OF_MEMORY:
        return -ENOMEM;
    case CURLE_OPERATION_TIMEDOUT:
        return -ETIMEDOUT;
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_CONNECT:
        return -EHOSTUNREACH;
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CACERT_BADFILE:
    case CURLE_SSL_CERTPROBLEM:
        return -EACCES;
    default:
        return -EIO;
    }
}

/** @brief Append one fixed header or release an incomplete list. */
static int append_header(struct curl_slist **headers, const char *header)
{
    struct curl_slist *updated = curl_slist_append(*headers, header);

    if (updated == NULL) {
        curl_slist_free_all(*headers);
        *headers = NULL;
        return -ENOMEM;
    }
    *headers = updated;
    return 0;
}

/** @brief Create the canonical timestamp-bound webhook signature. */
int alert_webhook_signature(const uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE],
                            uint64_t timestamp,
                            const char *payload,
                            size_t payload_size,
                            char signature[ALERT_WEBHOOK_SIGNATURE_SIZE])
{
    crypto_auth_hmacsha256_state state;
    uint8_t digest[crypto_auth_hmacsha256_BYTES];
    char timestamp_text[32U];
    int written = 0;
    int result = 0;

    if (secret == NULL || payload == NULL || payload_size == 0U ||
        payload_size > JG_ALERT_PAYLOAD_MAX || signature == NULL) {
        return -EINVAL;
    }
    signature[0U] = '\0';
    written =
        snprintf(timestamp_text, sizeof(timestamp_text), "%" PRIu64, timestamp);
    if (written <= 0 || (size_t)written >= sizeof(timestamp_text) ||
        sodium_init() < 0) {
        return -EIO;
    }
    if (crypto_auth_hmacsha256_init(&state, secret,
                                    JG_ALERT_WEBHOOK_SECRET_SIZE) != 0 ||
        crypto_auth_hmacsha256_update(
            &state, (const unsigned char *)timestamp_text,
            (unsigned long long)(size_t)written) != 0 ||
        crypto_auth_hmacsha256_update(&state, (const unsigned char *)".", 1U) !=
            0 ||
        crypto_auth_hmacsha256_update(&state, (const unsigned char *)payload,
                                      (unsigned long long)payload_size) != 0 ||
        crypto_auth_hmacsha256_final(&state, digest) != 0) {
        result = -EIO;
    }
    if (result == 0) {
        (void)memcpy(signature, "sha256=", 7U);
        encode_hex(digest, sizeof(digest), signature + 7U);
    }
    sodium_memzero(&state, sizeof(state));
    sodium_memzero(digest, sizeof(digest));
    return result;
}

/** @brief Build all fixed headers for one signed webhook request. */
static int create_headers(const char event_id[JG_ALERT_EVENT_ID_SIZE],
                          uint64_t timestamp,
                          const char signature[ALERT_WEBHOOK_SIGNATURE_SIZE],
                          struct curl_slist **headers)
{
    char identifier_header[64U];
    char timestamp_header[64U];
    char signature_header[128U];
    int written = snprintf(identifier_header, sizeof(identifier_header),
                           "X-JanusGate-Event-ID: %s", event_id);
    int result = 0;

    *headers = NULL;
    if (written <= 0 || (size_t)written >= sizeof(identifier_header)) {
        return -EOVERFLOW;
    }
    written = snprintf(timestamp_header, sizeof(timestamp_header),
                       "X-JanusGate-Timestamp: %" PRIu64, timestamp);
    if (written <= 0 || (size_t)written >= sizeof(timestamp_header)) {
        return -EOVERFLOW;
    }
    written = snprintf(signature_header, sizeof(signature_header),
                       "X-JanusGate-Signature: %s", signature);
    if (written <= 0 || (size_t)written >= sizeof(signature_header)) {
        return -EOVERFLOW;
    }
    result = append_header(headers, "Content-Type: application/json");
    if (result == 0) {
        result = append_header(headers, identifier_header);
    }
    if (result == 0) {
        result = append_header(headers, timestamp_header);
    }
    if (result == 0) {
        result = append_header(headers, signature_header);
    }
    return result;
}

/** @brief Store one bounded administrative-safe delivery error. */
static void store_error(char output[JG_ALERT_DELIVERY_ERROR_MAX + 1U],
                        const char *message,
                        long status)
{
    int written =
        status == 0L
            ? snprintf(output, JG_ALERT_DELIVERY_ERROR_MAX + 1U, "%s", message)
            : snprintf(output, JG_ALERT_DELIVERY_ERROR_MAX + 1U,
                       "HTTP status %ld", status);

    if (written < 0) {
        (void)snprintf(output, JG_ALERT_DELIVERY_ERROR_MAX + 1U,
                       "Webhook delivery failed");
    } else {
        output[JG_ALERT_DELIVERY_ERROR_MAX] = '\0';
    }
}

/** @brief Deliver one signed JSON payload to an exact HTTPS endpoint. */
int alert_webhook_deliver(const char *url,
                          const char *ca_pem,
                          uint32_t timeout_seconds,
                          const uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE],
                          const char event_id[JG_ALERT_EVENT_ID_SIZE],
                          uint64_t timestamp,
                          const char *payload,
                          char error[JG_ALERT_DELIVERY_ERROR_MAX + 1U])
{
    const size_t payload_size = payload == NULL ? 0U : strlen(payload);
    struct response_counter response = {0};
    struct curl_slist *headers = NULL;
    struct curl_blob ca_blob;
    char signature[ALERT_WEBHOOK_SIGNATURE_SIZE];
    char *ca_copy = NULL;
    CURL *curl = NULL;
    CURLcode status = CURLE_OK;
    long http_status = 0L;
    bool http_failure = false;
    int result = 0;

    if (url == NULL || secret == NULL || event_id == NULL || timestamp == 0U ||
        payload_size == 0U || payload_size > JG_ALERT_PAYLOAD_MAX ||
        timeout_seconds == 0U || timeout_seconds > 30U || error == NULL) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < JG_ALERT_EVENT_ID_SIZE - 1U; ++index) {
        const char character = event_id[index];

        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return -EINVAL;
        }
    }
    if (event_id[JG_ALERT_EVENT_ID_SIZE - 1U] != '\0') {
        return -EINVAL;
    }
    error[0U] = '\0';
    result = alert_webhook_signature(secret, timestamp, payload, payload_size,
                                     signature);
    if (result == 0) {
        result = create_headers(event_id, timestamp, signature, &headers);
    }
    if (result == 0 && ca_pem != NULL) {
        ca_copy = strdup(ca_pem);
        if (ca_copy == NULL) {
            result = -ENOMEM;
        } else {
            ca_blob = (struct curl_blob){
                .data = ca_copy,
                .len = strlen(ca_copy),
                .flags = CURL_BLOB_COPY,
            };
        }
    }
    if (result == 0) {
        result = jg_http_client_initialize();
    }
    if (result == 0) {
        curl = curl_easy_init();
        if (curl == NULL) {
            result = -ENOMEM;
        }
    }

#define ALERT_CURL_SETOPT(option, value)                                       \
    do {                                                                       \
        if (result == 0) {                                                     \
            status = curl_easy_setopt(curl, (option), (value));                \
            result = curl_result(status);                                      \
        }                                                                      \
    } while (false)

    ALERT_CURL_SETOPT(CURLOPT_URL, url);
    ALERT_CURL_SETOPT(CURLOPT_PROTOCOLS_STR, "https");
    ALERT_CURL_SETOPT(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    ALERT_CURL_SETOPT(CURLOPT_FOLLOWLOCATION, 0L);
    ALERT_CURL_SETOPT(CURLOPT_MAXREDIRS, 0L);
    ALERT_CURL_SETOPT(CURLOPT_PROXY, "");
    ALERT_CURL_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    ALERT_CURL_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    ALERT_CURL_SETOPT(CURLOPT_NOSIGNAL, 1L);
    ALERT_CURL_SETOPT(CURLOPT_CONNECTTIMEOUT, (long)timeout_seconds);
    ALERT_CURL_SETOPT(CURLOPT_TIMEOUT, (long)timeout_seconds);
    ALERT_CURL_SETOPT(CURLOPT_USERAGENT, "JanusGate alerting");
    ALERT_CURL_SETOPT(CURLOPT_HTTPHEADER, headers);
    ALERT_CURL_SETOPT(CURLOPT_POST, 1L);
    ALERT_CURL_SETOPT(CURLOPT_POSTFIELDS, payload);
    ALERT_CURL_SETOPT(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)payload_size);
    ALERT_CURL_SETOPT(CURLOPT_WRITEFUNCTION, discard_response);
    ALERT_CURL_SETOPT(CURLOPT_WRITEDATA, &response);
    if (ca_copy != NULL) {
        ALERT_CURL_SETOPT(CURLOPT_CAINFO_BLOB, &ca_blob);
    }
#undef ALERT_CURL_SETOPT

    if (result == 0) {
        status = curl_easy_perform(curl);
        result = curl_result(status);
    }
    if (result == 0) {
        status = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
        result = curl_result(status);
    }
    if (result == 0 && (http_status < 200L || http_status >= 300L)) {
        result = -EIO;
        http_failure = true;
    }
    if (result != 0) {
        store_error(error,
                    status == CURLE_OK ? "Webhook transport failed"
                                       : curl_easy_strerror(status),
                    http_failure ? http_status : 0L);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }
    curl_slist_free_all(headers);
    free(ca_copy);
    sodium_memzero(signature, sizeof(signature));
    return result;
}
