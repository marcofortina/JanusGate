/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/blocklist_remote.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <curl/curl.h>
#include <sodium.h>

#include "janusgate/checked.h"

#include "http_client.h"

/** Complete bounded HTTP response assembled by libcurl callbacks. */
struct download_response {
    uint8_t *body;
    size_t body_size;
    size_t body_capacity;
    size_t body_limit;
    char etag[JG_BLOCKLIST_ETAG_MAX + 1U];
    char last_modified[JG_BLOCKLIST_LAST_MODIFIED_MAX + 1U];
    int callback_error;
    long status;
};

/** Per-transfer record of an address rejected before socket creation. */
struct socket_policy {
    bool rejected;
};

/** @brief Return whether one IPv4 address is public unicast. */
static bool ipv4_public(const uint8_t address[4U])
{
    return address[0U] != 0U && address[0U] != 10U && address[0U] != 127U &&
           !(address[0U] == 100U && (address[1U] & UINT8_C(0xc0)) == 64U) &&
           !(address[0U] == 169U && address[1U] == 254U) &&
           !(address[0U] == 172U && (address[1U] & UINT8_C(0xf0)) == 16U) &&
           !(address[0U] == 192U && address[1U] == 0U && address[2U] == 0U) &&
           !(address[0U] == 192U && address[1U] == 0U && address[2U] == 2U) &&
           !(address[0U] == 192U && address[1U] == 88U && address[2U] == 99U) &&
           !(address[0U] == 192U && address[1U] == 168U) &&
           !(address[0U] == 198U &&
             (address[1U] == 18U || address[1U] == 19U)) &&
           !(address[0U] == 198U && address[1U] == 51U &&
             address[2U] == 100U) &&
           !(address[0U] == 203U && address[1U] == 0U && address[2U] == 113U) &&
           address[0U] < 224U;
}

/** @brief Return whether one IPv6 address is public unicast. */
static bool ipv6_public(const uint8_t address[16U])
{
    const bool protocol_assignment = address[0U] == UINT8_C(0x20) &&
                                     address[1U] == UINT8_C(0x01) &&
                                     (address[2U] & UINT8_C(0xfe)) == 0U;
    const bool documentation =
        address[0U] == UINT8_C(0x20) && address[1U] == UINT8_C(0x01) &&
        address[2U] == UINT8_C(0x0d) && address[3U] == UINT8_C(0xb8);
    const bool six_to_four =
        address[0U] == UINT8_C(0x20) && address[1U] == UINT8_C(0x02);
    const bool extended_documentation = address[0U] == UINT8_C(0x3f) &&
                                        address[1U] == UINT8_C(0xff) &&
                                        (address[2U] & UINT8_C(0xf0)) == 0U;

    return (address[0U] & UINT8_C(0xe0)) == UINT8_C(0x20) &&
           !protocol_assignment && !documentation && !six_to_four &&
           !extended_documentation;
}

/** @brief Open only sockets whose resolved destination is public unicast. */
static curl_socket_t open_public_socket(void *user_data,
                                        curlsocktype purpose,
                                        struct curl_sockaddr *address)
{
    struct socket_policy *policy = user_data;
    bool permitted = false;

    if (purpose == CURLSOCKTYPE_IPCXN && address != NULL &&
        address->family == AF_INET &&
        address->addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
        struct sockaddr_in ipv4;

        (void)memcpy(&ipv4, &address->addr, sizeof(ipv4));
        permitted = ipv4_public((const uint8_t *)&ipv4.sin_addr);
    } else if (purpose == CURLSOCKTYPE_IPCXN && address != NULL &&
               address->family == AF_INET6 &&
               address->addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 ipv6;

        (void)memcpy(&ipv6, &address->addr, sizeof(ipv6));
        permitted = ipv6_public((const uint8_t *)&ipv6.sin6_addr);
    }
    if (!permitted) {
        policy->rejected = true;
        errno = EACCES;
        return CURL_SOCKET_BAD;
    }
    return socket(address->family, address->socktype, address->protocol);
}

/** @brief Validate that a URL explicitly selects HTTPS. */
static bool is_https_url(const char *url)
{
    return url != NULL && strncasecmp(url, "https://", 8U) == 0 &&
           url[8] != '\0';
}

/** @brief Validate a retained HTTP validator against header injection. */
static bool http_validator_valid(const char *value, size_t maximum)
{
    size_t length = 0U;

    if (value == NULL) {
        return false;
    }
    while (length <= maximum && value[length] != '\0') {
        const uint8_t byte = (uint8_t)value[length];

        if (byte < UINT8_C(0x20) || byte > UINT8_C(0x7e)) {
            return false;
        }
        ++length;
    }
    return length <= maximum;
}

/** @brief Validate all remote-source bounds and required relationships. */
static bool config_valid(const struct jg_blocklist_remote_config *config)
{
    if (config == NULL || !is_https_url(config->url) ||
        config->format < JG_BLOCKLIST_FORMAT_DOMAIN ||
        config->format > JG_BLOCKLIST_FORMAT_JSON ||
        (config->mode != JG_BLOCKLIST_STRICT &&
         config->mode != JG_BLOCKLIST_TOLERANT) ||
        config->attribution == NULL ||
        config->import_limits.max_file_bytes == 0U ||
        config->import_limits.max_line_bytes == 0U ||
        config->import_limits.max_entries == 0U ||
        config->max_download_bytes == 0U ||
        config->max_download_bytes > (size_t)INT64_MAX ||
        config->connect_timeout_ms == 0U ||
        config->connect_timeout_ms > JG_BLOCKLIST_CONNECT_TIMEOUT_MAX ||
        config->transfer_timeout_ms == 0U ||
        config->transfer_timeout_ms > JG_BLOCKLIST_TRANSFER_TIMEOUT_MAX ||
        config->redirect_limit > 20U || config->update_interval_seconds == 0U ||
        config->retry_base_seconds == 0U ||
        config->retry_base_seconds > config->retry_max_seconds) {
        return false;
    }
    if (config->has_signature) {
        return is_https_url(config->signature_url);
    }
    return config->signature_url == NULL;
}

/** @brief Grow a response body without exceeding its configured limit. */
static int reserve_body(struct download_response *response, size_t required)
{
    uint8_t *resized = NULL;
    size_t capacity =
        response->body_capacity == 0U ? 16384U : response->body_capacity;

    if (required > response->body_limit) {
        return -EFBIG;
    }
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2U) {
            return -EOVERFLOW;
        }
        capacity *= 2U;
    }
    if (capacity > response->body_limit) {
        capacity = response->body_limit;
    }
    if (capacity == response->body_capacity) {
        return 0;
    }
    resized = realloc(response->body, capacity);
    if (resized == NULL) {
        return -ENOMEM;
    }
    response->body = resized;
    response->body_capacity = capacity;
    return 0;
}

/** @brief Receive decompressed body bytes from libcurl. */
static size_t receive_body(char *data,
                           size_t element_size,
                           size_t element_count,
                           void *user_data)
{
    struct download_response *response = user_data;
    size_t chunk_size = 0U;
    size_t required = 0U;

    if (!jg_size_multiply(element_size, element_count, &chunk_size) ||
        !jg_size_add(response->body_size, chunk_size, &required)) {
        response->callback_error = -EOVERFLOW;
        return 0U;
    }
    response->callback_error = reserve_body(response, required);
    if (response->callback_error != 0) {
        return 0U;
    }
    if (chunk_size != 0U) {
        (void)memcpy(response->body + response->body_size, data, chunk_size);
        response->body_size = required;
    }
    return chunk_size;
}

/** @brief Copy one bounded final-response validator header. */
static int copy_header_value(char *destination,
                             size_t destination_size,
                             const char *value,
                             size_t value_size)
{
    while (value_size > 0U &&
           (value[value_size - 1U] == '\r' || value[value_size - 1U] == '\n' ||
            value[value_size - 1U] == ' ' || value[value_size - 1U] == '\t')) {
        --value_size;
    }
    while (value_size > 0U && (*value == ' ' || *value == '\t')) {
        ++value;
        --value_size;
    }
    if (value_size >= destination_size) {
        return -EOVERFLOW;
    }
    for (size_t index = 0U; index < value_size; ++index) {
        const uint8_t byte = (uint8_t)value[index];

        if (byte < UINT8_C(0x20) || byte > UINT8_C(0x7e)) {
            return -EPROTO;
        }
    }
    (void)memcpy(destination, value, value_size);
    destination[value_size] = '\0';
    return 0;
}

/** @brief Receive response headers and retain bounded HTTP validators. */
static size_t receive_header(char *data,
                             size_t element_size,
                             size_t element_count,
                             void *user_data)
{
    struct download_response *response = user_data;
    size_t header_size = 0U;

    if (!jg_size_multiply(element_size, element_count, &header_size)) {
        response->callback_error = -EOVERFLOW;
        return 0U;
    }
    if (header_size >= 5U && strncasecmp(data, "HTTP/", 5U) == 0) {
        response->etag[0] = '\0';
        response->last_modified[0] = '\0';
    } else if (header_size >= 5U && strncasecmp(data, "ETag:", 5U) == 0) {
        response->callback_error =
            copy_header_value(response->etag, sizeof(response->etag), data + 5U,
                              header_size - 5U);
    } else if (header_size >= 14U &&
               strncasecmp(data, "Last-Modified:", 14U) == 0) {
        response->callback_error = copy_header_value(
            response->last_modified, sizeof(response->last_modified),
            data + 14U, header_size - 14U);
    }
    return response->callback_error == 0 ? header_size : 0U;
}

/** @brief Append one conditional request header to a curl list. */
static int append_validator(struct curl_slist **headers,
                            const char *name,
                            const char *value)
{
    struct curl_slist *updated = NULL;
    char *header = NULL;
    size_t header_size = 0U;
    const size_t name_size = strlen(name);
    const size_t value_size = strlen(value);

    if (!jg_size_add(name_size, value_size, &header_size) ||
        !jg_size_add(header_size, 3U, &header_size)) {
        return -EOVERFLOW;
    }
    header = malloc(header_size);
    if (header == NULL) {
        return -ENOMEM;
    }
    (void)snprintf(header, header_size, "%s: %s", name, value);
    updated = curl_slist_append(*headers, header);
    free(header);
    if (updated == NULL) {
        return -ENOMEM;
    }
    *headers = updated;
    return 0;
}

/** @brief Map a libcurl transport result to an errno-style value. */
static int curl_result(CURLcode status)
{
    switch (status) {
    case CURLE_OK:
        return 0;
    case CURLE_OPERATION_TIMEDOUT:
        return -ETIMEDOUT;
    case CURLE_FILESIZE_EXCEEDED:
    case CURLE_WRITE_ERROR:
        return -EFBIG;
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CIPHER:
    case CURLE_SSL_CONNECT_ERROR:
        return -EACCES;
    case CURLE_UNSUPPORTED_PROTOCOL:
    case CURLE_URL_MALFORMAT:
        return -EINVAL;
    default:
        return -EIO;
    }
}

/** @brief Perform one bounded verified HTTPS retrieval. */
static int fetch_https(const char *url,
                       const struct jg_blocklist_remote_state *validators,
                       size_t advertised_limit,
                       size_t body_limit,
                       uint32_t connect_timeout_ms,
                       uint32_t transfer_timeout_ms,
                       uint32_t redirect_limit,
                       struct download_response *response)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    struct socket_policy socket_policy = {0};
    CURLcode status = CURLE_OK;
    int result = 0;

    response->body_limit = body_limit;
    if (validators != NULL && validators->etag[0] != '\0') {
        result = append_validator(&headers, "If-None-Match", validators->etag);
    }
    if (result == 0 && validators != NULL &&
        validators->last_modified[0] != '\0') {
        result = append_validator(&headers, "If-Modified-Since",
                                  validators->last_modified);
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
#define JG_CURL_SETOPT(option, value)                                          \
    do {                                                                       \
        if (result == 0) {                                                     \
            status = curl_easy_setopt(curl, (option), (value));                \
            result = curl_result(status);                                      \
        }                                                                      \
    } while (false)
    JG_CURL_SETOPT(CURLOPT_URL, url);
    JG_CURL_SETOPT(CURLOPT_PROTOCOLS_STR, "https");
    JG_CURL_SETOPT(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    JG_CURL_SETOPT(CURLOPT_FOLLOWLOCATION, 1L);
    JG_CURL_SETOPT(CURLOPT_MAXREDIRS, (long)redirect_limit);
    JG_CURL_SETOPT(CURLOPT_CONNECTTIMEOUT_MS, (long)connect_timeout_ms);
    JG_CURL_SETOPT(CURLOPT_TIMEOUT_MS, (long)transfer_timeout_ms);
    JG_CURL_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    JG_CURL_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    JG_CURL_SETOPT(CURLOPT_PROXY, "");
    JG_CURL_SETOPT(CURLOPT_ACCEPT_ENCODING, "");
    JG_CURL_SETOPT(CURLOPT_NOSIGNAL, 1L);
    JG_CURL_SETOPT(CURLOPT_USERAGENT, "JanusGate/0.1");
    JG_CURL_SETOPT(CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)advertised_limit);
    JG_CURL_SETOPT(CURLOPT_WRITEFUNCTION, receive_body);
    JG_CURL_SETOPT(CURLOPT_WRITEDATA, response);
    JG_CURL_SETOPT(CURLOPT_HEADERFUNCTION, receive_header);
    JG_CURL_SETOPT(CURLOPT_HEADERDATA, response);
    JG_CURL_SETOPT(CURLOPT_OPENSOCKETFUNCTION, open_public_socket);
    JG_CURL_SETOPT(CURLOPT_OPENSOCKETDATA, &socket_policy);
    if (headers != NULL) {
        JG_CURL_SETOPT(CURLOPT_HTTPHEADER, headers);
    }
#undef JG_CURL_SETOPT

    if (result == 0) {
        status = curl_easy_perform(curl);
        result = response->callback_error != 0
                     ? response->callback_error
                     : (status != CURLE_OK && socket_policy.rejected
                            ? -EACCES
                            : curl_result(status));
    }
    if (result == 0) {
        status =
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status);
        result = curl_result(status);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }
    curl_slist_free_all(headers);
    return result;
}

/** @brief Verify configured body digest and detached signature. */
static int verify_body(const struct jg_blocklist_remote_config *config,
                       const struct download_response *body)
{
    static const uint8_t empty_body = 0U;
    uint8_t digest[crypto_hash_sha256_BYTES];
    struct download_response signature = {0};
    const uint8_t *message = body->body_size == 0U ? &empty_body : body->body;
    int result = 0;

    if (config->has_sha256_pin) {
        (void)crypto_hash_sha256(digest, message,
                                 (unsigned long long)body->body_size);
        if (sodium_memcmp(digest, config->sha256_pin,
                          sizeof(config->sha256_pin)) != 0) {
            result = -EACCES;
        }
    }
    if (result == 0 && config->has_signature) {
        result = fetch_https(config->signature_url, NULL, crypto_sign_BYTES,
                             crypto_sign_BYTES, config->connect_timeout_ms,
                             config->transfer_timeout_ms,
                             config->redirect_limit, &signature);
        if (result == 0 &&
            (signature.status != 200L ||
             signature.body_size != crypto_sign_BYTES ||
             crypto_sign_verify_detached(signature.body, message,
                                         (unsigned long long)body->body_size,
                                         config->ed25519_public_key) != 0)) {
            result = -EACCES;
        }
    }
    free(signature.body);
    return result;
}

/** @brief Add a bounded delay to a Unix timestamp without wrapping. */
static uint64_t schedule_after(uint64_t now, uint64_t delay)
{
    return delay > UINT64_MAX - now ? UINT64_MAX : now + delay;
}

/** @brief Compute a capped exponential retry delay with positive jitter. */
static uint64_t retry_delay(const struct jg_blocklist_remote_config *config,
                            uint32_t failures)
{
    uint64_t delay = config->retry_base_seconds;
    uint32_t exponent = failures > 0U ? failures - 1U : 0U;
    uint64_t jitter_limit = 0U;
    uint64_t jitter = 0U;

    while (exponent > 0U && delay < config->retry_max_seconds) {
        delay = delay > config->retry_max_seconds / 2U
                    ? config->retry_max_seconds
                    : delay * 2U;
        --exponent;
    }
    if (delay > config->retry_max_seconds) {
        delay = config->retry_max_seconds;
    }
    jitter_limit = delay / 4U;
    if (jitter_limit != 0U) {
        jitter = (uint64_t)randombytes_random() % (jitter_limit + 1U);
    }
    return delay > UINT64_MAX - jitter ? UINT64_MAX : delay + jitter;
}

/** @brief Record one failed attempt and schedule its bounded retry. */
static void record_failure(const struct jg_blocklist_remote_config *config,
                           struct jg_blocklist_remote_state *state,
                           uint64_t now)
{
    if (state->consecutive_failures < UINT32_MAX) {
        ++state->consecutive_failures;
    }
    state->next_attempt_at =
        schedule_after(now, retry_delay(config, state->consecutive_failures));
}

/** @brief Commit successful validators and normal update scheduling. */
static void record_success(const struct jg_blocklist_remote_config *config,
                           struct jg_blocklist_remote_state *state,
                           const struct download_response *response,
                           uint64_t now,
                           bool replace_validators)
{
    if (replace_validators || response->etag[0] != '\0') {
        (void)snprintf(state->etag, sizeof(state->etag), "%s", response->etag);
    }
    if (replace_validators || response->last_modified[0] != '\0') {
        (void)snprintf(state->last_modified, sizeof(state->last_modified), "%s",
                       response->last_modified);
    }
    state->last_success_at = now;
    state->next_attempt_at =
        schedule_after(now, config->update_interval_seconds);
    state->consecutive_failures = 0U;
}

/** @brief Clear persistent remote-source validators and scheduling. */
void jg_blocklist_remote_state_init(struct jg_blocklist_remote_state *state)
{
    if (state != NULL) {
        (void)memset(state, 0, sizeof(*state));
    }
}

/** @brief Determine whether a remote source has reached its next attempt. */
bool jg_blocklist_remote_due(const struct jg_blocklist_remote_state *state,
                             uint64_t now)
{
    return state != NULL && now >= state->next_attempt_at;
}

/** @brief Fetch and atomically validate one scheduled remote blocklist. */
int jg_blocklist_remote_update(const struct jg_blocklist_remote_config *config,
                               struct jg_blocklist_remote_state *state,
                               uint64_t now,
                               enum jg_blocklist_remote_status *status,
                               struct jg_blocklist **blocklist,
                               struct jg_blocklist_remote_report *report)
{
    struct download_response response = {0};
    struct jg_blocklist_remote_report local_report = {0};
    struct jg_blocklist *imported = NULL;
    int result = 0;

    if (state == NULL || status == NULL || blocklist == NULL) {
        return -EINVAL;
    }
    *blocklist = NULL;
    if (report != NULL) {
        (void)memset(report, 0, sizeof(*report));
    }
    if (!config_valid(config) ||
        !http_validator_valid(state->etag, JG_BLOCKLIST_ETAG_MAX) ||
        !http_validator_valid(state->last_modified,
                              JG_BLOCKLIST_LAST_MODIFIED_MAX)) {
        return -EINVAL;
    }
    if (sodium_init() < 0) {
        return -EIO;
    }
    state->last_attempt_at = now;
    result = fetch_https(
        config->url, state, config->max_download_bytes,
        config->import_limits.max_file_bytes, config->connect_timeout_ms,
        config->transfer_timeout_ms, config->redirect_limit, &response);
    local_report.http_status = response.status;
    local_report.body_size = response.body_size;
    if (result == 0 && response.status == 304L) {
        *status = JG_BLOCKLIST_REMOTE_NOT_MODIFIED;
        record_success(config, state, &response, now, false);
    } else if (result == 0 && response.status != 200L) {
        result = -EPROTO;
    }
    if (result == 0 && response.status == 200L) {
        result = verify_body(config, &response);
        if (result == 0) {
            result = jg_blocklist_import(
                response.body, response.body_size, config->format, config->mode,
                config->attribution, &config->import_limits, &imported,
                &local_report.import);
        }
        if (result == 0) {
            *status = JG_BLOCKLIST_REMOTE_UPDATED;
            *blocklist = imported;
            imported = NULL;
            record_success(config, state, &response, now, true);
        }
    }
    if (result != 0) {
        record_failure(config, state, now);
    }
    jg_blocklist_destroy(imported);
    free(response.body);
    if (report != NULL) {
        *report = local_report;
    }
    return result;
}
