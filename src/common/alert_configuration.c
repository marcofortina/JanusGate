/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/alert.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <sodium.h>
#include <sqlite3.h>

#include "database_internal.h"
#include "janusgate/checked.h"

/** Largest signed value accepted by the alert schema. */
#define ALERT_VALUE_MAX UINT64_C(9223372036854775807)

/** Authenticated ciphertext bytes for one webhook secret. */
#define ALERT_SECRET_CIPHERTEXT_SIZE                                           \
    (JG_ALERT_WEBHOOK_SECRET_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES)

/** Public nonce bytes for one encrypted webhook secret. */
#define ALERT_SECRET_NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

/** @brief Return one bounded string length or one past the limit. */
static size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0U;

    if (text == NULL) {
        return 0U;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    return length;
}

/** @brief Validate one absolute HTTPS webhook URL. */
static int validate_webhook_url(const char *url)
{
    CURLU *parsed = NULL;
    char *scheme = NULL;
    char *host = NULL;
    char *user = NULL;
    char *password = NULL;
    char *fragment = NULL;
    const size_t length = bounded_length(url, JG_ALERT_WEBHOOK_URL_MAX);
    int result = 0;

    if (url == NULL) {
        return 0;
    }
    if (length == 0U || length > JG_ALERT_WEBHOOK_URL_MAX ||
        !jg_utf8_text_valid((const uint8_t *)url, length, false)) {
        return -EINVAL;
    }
    parsed = curl_url();
    if (parsed == NULL) {
        return -ENOMEM;
    }
    if (curl_url_set(parsed, CURLUPART_URL, url, CURLU_NON_SUPPORT_SCHEME) !=
            CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_SCHEME, &scheme, 0U) != CURLUE_OK ||
        curl_url_get(parsed, CURLUPART_HOST, &host, 0U) != CURLUE_OK ||
        strcmp(scheme, "https") != 0 || host[0U] == '\0') {
        result = -EINVAL;
    }
    if (result == 0 &&
        (curl_url_get(parsed, CURLUPART_USER, &user, 0U) == CURLUE_OK ||
         curl_url_get(parsed, CURLUPART_PASSWORD, &password, 0U) == CURLUE_OK ||
         curl_url_get(parsed, CURLUPART_FRAGMENT, &fragment, 0U) ==
             CURLUE_OK)) {
        result = -EINVAL;
    }
    curl_free(fragment);
    curl_free(password);
    curl_free(user);
    curl_free(host);
    curl_free(scheme);
    curl_url_cleanup(parsed);
    return result;
}

/** @brief Validate one optional private-CA trust bundle. */
static int validate_webhook_ca(const char *pem)
{
    struct jg_certificate_info *authorities = NULL;
    size_t authority_count = 0U;
    const size_t length = bounded_length(pem, JG_ALERT_WEBHOOK_CA_MAX);
    int result = 0;

    if (pem == NULL) {
        return 0;
    }
    if (length == 0U || length > JG_ALERT_WEBHOOK_CA_MAX) {
        return -EINVAL;
    }
    authorities = calloc(JG_CERTIFICATE_AUTHORITY_MAX, sizeof(*authorities));
    if (authorities == NULL) {
        return -ENOMEM;
    }
    result = jg_certificate_trust_store_inspect(pem, length, authorities,
                                                JG_CERTIFICATE_AUTHORITY_MAX,
                                                &authority_count);
    free(authorities);
    return result == 0 && authority_count == 0U ? -EINVAL : result;
}

/** @brief Copy one optional bounded SQLite text column. */
static int copy_optional_text(sqlite3_stmt *statement,
                              int column,
                              size_t maximum,
                              bool multiline,
                              char **output)
{
    const char *text = NULL;
    const int bytes = sqlite3_column_bytes(statement, column);

    *output = NULL;
    if (sqlite3_column_type(statement, column) == SQLITE_NULL) {
        return 0;
    }
    text = (const char *)sqlite3_column_text(statement, column);
    if (sqlite3_column_type(statement, column) != SQLITE_TEXT || text == NULL ||
        bytes <= 0 || (size_t)bytes > maximum ||
        memchr(text, '\0', (size_t)bytes) != NULL ||
        (!multiline &&
         !jg_utf8_text_valid((const uint8_t *)text, (size_t)bytes, false))) {
        return -EILSEQ;
    }
    *output = malloc((size_t)bytes + 1U);
    if (*output == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(*output, text, (size_t)bytes);
    (*output)[bytes] = '\0';
    return 0;
}

/** @brief Decode and validate one persistent configuration row. */
static int decode_configuration(sqlite3_stmt *statement,
                                struct jg_alert_configuration *configuration)
{
    struct jg_alert_configuration loaded = {0};
    uint64_t values[11U];
    int result = 0;

    loaded.values.enabled = sqlite3_column_int(statement, 0) != 0;
    for (size_t index = 0U; result == 0 && index < 10U; ++index) {
        result = jg_database_column_unsigned(statement, (int)index + 1,
                                             &values[index]);
    }
    if (result == 0) {
        loaded.values.webhook_enabled = sqlite3_column_int(statement, 11) != 0;
        result = copy_optional_text(statement, 12, JG_ALERT_WEBHOOK_URL_MAX,
                                    false, &loaded.webhook_url_storage);
    }
    if (result == 0) {
        result = copy_optional_text(statement, 13, JG_ALERT_WEBHOOK_CA_MAX,
                                    true, &loaded.webhook_ca_storage);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 14, &values[10U]);
    }
    if (result == 0) {
        const int ciphertext_type = sqlite3_column_type(statement, 15);
        const int nonce_type = sqlite3_column_type(statement, 16);

        if ((ciphertext_type == SQLITE_NULL) != (nonce_type == SQLITE_NULL) ||
            (ciphertext_type != SQLITE_NULL &&
             (ciphertext_type != SQLITE_BLOB || nonce_type != SQLITE_BLOB ||
              sqlite3_column_bytes(statement, 15) !=
                  (int)ALERT_SECRET_CIPHERTEXT_SIZE ||
              sqlite3_column_bytes(statement, 16) !=
                  (int)ALERT_SECRET_NONCE_SIZE))) {
            result = -EILSEQ;
        } else {
            loaded.webhook_secret_configured = ciphertext_type != SQLITE_NULL;
        }
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 17, &loaded.revision);
    }
    if (result == 0) {
        result = jg_database_column_unsigned(statement, 18, &loaded.updated_at);
    }
    if (result == 0) {
        loaded.values.evaluation_interval_seconds = (uint32_t)values[0U];
        loaded.values.certificate_warning_days = (uint32_t)values[1U];
        loaded.values.source_failure_threshold = (uint32_t)values[2U];
        loaded.values.source_stale_seconds = (uint32_t)values[3U];
        loaded.values.filesystem_minimum_percent = (uint32_t)values[4U];
        loaded.values.filesystem_minimum_bytes = values[5U];
        loaded.values.queue_window_seconds = (uint32_t)values[6U];
        loaded.values.queue_drop_threshold = values[7U];
        loaded.values.authentication_window_seconds = (uint32_t)values[8U];
        loaded.values.authentication_failure_threshold = values[9U];
        loaded.values.webhook_timeout_seconds = (uint32_t)values[10U];
        loaded.values.webhook_url = loaded.webhook_url_storage;
        loaded.values.webhook_ca_pem = loaded.webhook_ca_storage;
        result = jg_alert_configuration_validate(&loaded.values);
    }
    if (result == 0 &&
        (loaded.revision == 0U || (loaded.values.webhook_enabled &&
                                   !loaded.webhook_secret_configured))) {
        result = -EILSEQ;
    }
    if (result == 0) {
        *configuration = loaded;
    } else {
        jg_alert_configuration_clear(&loaded);
    }
    return result;
}

/** @brief Populate safe default alert settings. */
void jg_alert_configuration_default(
    struct jg_alert_configuration_update *update)
{
    if (update == NULL) {
        return;
    }
    *update = (struct jg_alert_configuration_update){
        .enabled = true,
        .evaluation_interval_seconds = 60U,
        .certificate_warning_days = 30U,
        .source_failure_threshold = 3U,
        .source_stale_seconds = 3600U,
        .filesystem_minimum_percent = 10U,
        .filesystem_minimum_bytes = UINT64_C(268435456),
        .queue_window_seconds = 300U,
        .queue_drop_threshold = 1U,
        .authentication_window_seconds = 300U,
        .authentication_failure_threshold = 20U,
        .webhook_timeout_seconds = 10U,
    };
}

/** @brief Validate one complete alert configuration replacement. */
int jg_alert_configuration_validate(
    const struct jg_alert_configuration_update *update)
{
    int result = 0;

    if (update == NULL ||
        update->evaluation_interval_seconds <
            JG_ALERT_EVALUATION_INTERVAL_MIN ||
        update->evaluation_interval_seconds >
            JG_ALERT_EVALUATION_INTERVAL_MAX ||
        update->certificate_warning_days < 1U ||
        update->certificate_warning_days > 365U ||
        update->source_failure_threshold < 1U ||
        update->source_failure_threshold > 100U ||
        update->source_stale_seconds < 300U ||
        update->source_stale_seconds > 2592000U ||
        update->filesystem_minimum_percent < 1U ||
        update->filesystem_minimum_percent > 50U ||
        update->filesystem_minimum_bytes > UINT64_C(1099511627776) ||
        update->queue_window_seconds < 60U ||
        update->queue_window_seconds > 3600U ||
        update->queue_drop_threshold < 1U ||
        update->queue_drop_threshold > UINT64_C(1000000000) ||
        update->authentication_window_seconds < 60U ||
        update->authentication_window_seconds > 3600U ||
        update->authentication_failure_threshold < 1U ||
        update->authentication_failure_threshold > UINT64_C(1000000000) ||
        update->webhook_timeout_seconds < 1U ||
        update->webhook_timeout_seconds > 30U ||
        (update->webhook_enabled && update->webhook_url == NULL)) {
        return -EINVAL;
    }
    result = validate_webhook_url(update->webhook_url);
    if (result == 0) {
        result = validate_webhook_ca(update->webhook_ca_pem);
    }
    return result;
}

/** @brief Release strings owned by a loaded alert configuration. */
void jg_alert_configuration_clear(struct jg_alert_configuration *configuration)
{
    if (configuration != NULL) {
        free(configuration->webhook_ca_storage);
        free(configuration->webhook_url_storage);
        (void)memset(configuration, 0, sizeof(*configuration));
    }
}

/** @brief Load and validate the singleton persistent alert configuration. */
int jg_database_alert_configuration_load(
    struct jg_database *database,
    struct jg_alert_configuration *configuration)
{
    static const char query[] =
        "SELECT enabled,evaluation_interval_seconds,certificate_warning_days,"
        "source_failure_threshold,source_stale_seconds,"
        "filesystem_minimum_percent,filesystem_minimum_bytes,"
        "queue_window_seconds,queue_drop_threshold,"
        "authentication_window_seconds,authentication_failure_threshold,"
        "webhook_enabled,webhook_url,webhook_ca_pem,"
        "webhook_timeout_seconds,webhook_secret_ciphertext,"
        "webhook_secret_nonce,revision,updated_at FROM alert_configuration "
        "WHERE id=1;";
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || configuration == NULL) {
        return -EINVAL;
    }
    (void)memset(configuration, 0, sizeof(*configuration));
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        result =
            status == SQLITE_ROW
                ? decode_configuration(statement, configuration)
                : (status == SQLITE_DONE ? -EILSEQ
                                         : jg_database_sqlite_result(status));
    }
    if (result == 0 && sqlite3_step(statement) != SQLITE_DONE) {
        result = -EIO;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result != 0) {
        jg_alert_configuration_clear(configuration);
    }
    return result;
}

/** @brief Bind complete alert replacement values to one update statement. */
static int bind_update(sqlite3_stmt *statement,
                       const struct jg_alert_configuration_update *update,
                       uint64_t updated_at,
                       uint64_t expected_revision)
{
    int status = sqlite3_bind_int(statement, 1, update->enabled ? 1 : 0);

#define BIND_INTEGER(index, value)                                             \
    do {                                                                       \
        if (status == SQLITE_OK) {                                             \
            status = sqlite3_bind_int64(statement, (index),                    \
                                        (sqlite3_int64)(value));               \
        }                                                                      \
    } while (false)

    BIND_INTEGER(2, update->evaluation_interval_seconds);
    BIND_INTEGER(3, update->certificate_warning_days);
    BIND_INTEGER(4, update->source_failure_threshold);
    BIND_INTEGER(5, update->source_stale_seconds);
    BIND_INTEGER(6, update->filesystem_minimum_percent);
    BIND_INTEGER(7, update->filesystem_minimum_bytes);
    BIND_INTEGER(8, update->queue_window_seconds);
    BIND_INTEGER(9, update->queue_drop_threshold);
    BIND_INTEGER(10, update->authentication_window_seconds);
    BIND_INTEGER(11, update->authentication_failure_threshold);
    BIND_INTEGER(12, update->webhook_enabled ? 1 : 0);
    if (status == SQLITE_OK) {
        status = update->webhook_url == NULL
                     ? sqlite3_bind_null(statement, 13)
                     : sqlite3_bind_text(statement, 13, update->webhook_url, -1,
                                         SQLITE_TRANSIENT);
    }
    if (status == SQLITE_OK) {
        status = update->webhook_ca_pem == NULL
                     ? sqlite3_bind_null(statement, 14)
                     : sqlite3_bind_text(statement, 14, update->webhook_ca_pem,
                                         -1, SQLITE_TRANSIENT);
    }
    BIND_INTEGER(15, update->webhook_timeout_seconds);
    BIND_INTEGER(16, updated_at);
    BIND_INTEGER(17, expected_revision);
#undef BIND_INTEGER
    return jg_database_sqlite_result(status);
}

/** @brief Replace alert settings at one expected revision. */
int jg_database_alert_configuration_replace(
    struct jg_database *database,
    const struct jg_alert_configuration_update *update,
    uint64_t expected_revision,
    uint64_t updated_at,
    struct jg_alert_configuration *updated)
{
    static const char update_sql[] =
        "UPDATE alert_configuration SET enabled=?1,"
        "evaluation_interval_seconds=?2,certificate_warning_days=?3,"
        "source_failure_threshold=?4,source_stale_seconds=?5,"
        "filesystem_minimum_percent=?6,filesystem_minimum_bytes=?7,"
        "queue_window_seconds=?8,queue_drop_threshold=?9,"
        "authentication_window_seconds=?10,"
        "authentication_failure_threshold=?11,webhook_enabled=?12,"
        "webhook_url=?13,webhook_ca_pem=?14,webhook_timeout_seconds=?15,"
        "updated_at=?16,revision=revision+1 WHERE id=1 AND revision=?17 "
        "AND revision<9223372036854775807;";
    static const char revision_query[] =
        "SELECT revision FROM alert_configuration WHERE id=?1;";
    struct jg_alert_configuration current = {0};
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || updated == NULL || expected_revision == 0U ||
        expected_revision > ALERT_VALUE_MAX || updated_at > ALERT_VALUE_MAX) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = jg_alert_configuration_validate(update);
    if (result == 0) {
        result = jg_database_alert_configuration_load(database, &current);
    }
    if (result == 0 && update->webhook_enabled &&
        !current.webhook_secret_configured) {
        result = -ENOENT;
    }
    jg_alert_configuration_clear(&current);
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update_sql, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        result = bind_update(statement, update, updated_at, expected_revision);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            1U, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_alert_configuration_load(database, updated);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
        jg_alert_configuration_clear(updated);
    }
    return result;
}

/** @brief Encode fixed bytes as lowercase hexadecimal. */
static void encode_hex(const uint8_t *bytes, size_t size, char *text)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t index = 0U; index < size; ++index) {
        text[index * 2U] = digits[bytes[index] >> 4U];
        text[index * 2U + 1U] = digits[bytes[index] & UINT8_C(0x0f)];
    }
    text[size * 2U] = '\0';
}

/** @brief Generate and atomically replace the webhook HMAC secret. */
int jg_database_alert_webhook_secret_rotate(
    struct jg_database *database,
    const uint8_t protection_key[JG_ALERT_WEBHOOK_SECRET_SIZE],
    uint64_t expected_revision,
    uint64_t updated_at,
    char secret_text[JG_ALERT_WEBHOOK_SECRET_TEXT_SIZE],
    struct jg_alert_configuration *updated)
{
    static const char update[] =
        "UPDATE alert_configuration SET webhook_secret_ciphertext=?1,"
        "webhook_secret_nonce=?2,revision=revision+1,updated_at=?3 "
        "WHERE id=1 AND revision=?4 AND revision<9223372036854775807;";
    static const char revision_query[] =
        "SELECT revision FROM alert_configuration WHERE id=?1;";
    uint8_t ciphertext[ALERT_SECRET_CIPHERTEXT_SIZE];
    uint8_t nonce[ALERT_SECRET_NONCE_SIZE];
    uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE];
    unsigned long long ciphertext_size = 0U;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (secret_text != NULL) {
        secret_text[0U] = '\0';
    }
    if (database == NULL || protection_key == NULL || secret_text == NULL ||
        updated == NULL || expected_revision == 0U ||
        expected_revision > ALERT_VALUE_MAX || updated_at > ALERT_VALUE_MAX) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    if (sodium_init() < 0) {
        return -EIO;
    }
    randombytes_buf(secret, sizeof(secret));
    randombytes_buf(nonce, sizeof(nonce));
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &ciphertext_size, secret, sizeof(secret), NULL, 0U,
            NULL, nonce, protection_key) != 0 ||
        ciphertext_size != sizeof(ciphertext)) {
        result = -EIO;
    }
    if (result == 0) {
        result = jg_database_transaction_begin(database);
    }
    if (result == 0) {
        status =
            sqlite3_prepare_v3(database->handle, update, -1,
                               SQLITE_PREPARE_PERSISTENT, &statement, NULL);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_bind_blob(statement, 1, ciphertext,
                                   (int)sizeof(ciphertext), SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_blob(statement, 2, nonce, (int)sizeof(nonce),
                                       SQLITE_TRANSIENT);
        }
        if (status == SQLITE_OK) {
            status =
                sqlite3_bind_int64(statement, 3, (sqlite3_int64)updated_at);
        }
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 4,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_write_conflict(database->handle, revision_query,
                                            1U, expected_revision, true);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        statement = NULL;
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result = jg_database_alert_configuration_load(database, updated);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(database);
    } else {
        (void)jg_database_transaction_rollback(database);
        jg_alert_configuration_clear(updated);
    }
    if (result == 0) {
        encode_hex(secret, sizeof(secret), secret_text);
    }
    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(ciphertext, sizeof(ciphertext));
    return result;
}

/** @brief Authenticate and decrypt the persistent webhook HMAC secret. */
int jg_database_alert_webhook_secret_load(
    struct jg_database *database,
    const uint8_t protection_key[JG_ALERT_WEBHOOK_SECRET_SIZE],
    uint8_t secret[JG_ALERT_WEBHOOK_SECRET_SIZE])
{
    static const char query[] =
        "SELECT webhook_secret_ciphertext,webhook_secret_nonce FROM "
        "alert_configuration WHERE id=1;";
    const uint8_t *ciphertext = NULL;
    const uint8_t *nonce = NULL;
    unsigned long long secret_size = 0U;
    sqlite3_stmt *statement = NULL;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || protection_key == NULL || secret == NULL) {
        return -EINVAL;
    }
    (void)memset(secret, 0, JG_ALERT_WEBHOOK_SECRET_SIZE);
    if (sodium_init() < 0) {
        return -EIO;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status != SQLITE_ROW) {
            result = status == SQLITE_DONE ? -EILSEQ
                                           : jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && (sqlite3_column_type(statement, 0) == SQLITE_NULL ||
                        sqlite3_column_type(statement, 1) == SQLITE_NULL)) {
        result = -ENOENT;
    }
    if (result == 0 &&
        (sqlite3_column_type(statement, 0) != SQLITE_BLOB ||
         sqlite3_column_bytes(statement, 0) !=
             (int)ALERT_SECRET_CIPHERTEXT_SIZE ||
         sqlite3_column_type(statement, 1) != SQLITE_BLOB ||
         sqlite3_column_bytes(statement, 1) != (int)ALERT_SECRET_NONCE_SIZE)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        ciphertext = sqlite3_column_blob(statement, 0);
        nonce = sqlite3_column_blob(statement, 1);
        if (ciphertext == NULL || nonce == NULL) {
            result = -EILSEQ;
        }
    }
    if (result == 0 && crypto_aead_xchacha20poly1305_ietf_decrypt(
                           secret, &secret_size, NULL, ciphertext,
                           ALERT_SECRET_CIPHERTEXT_SIZE, NULL, 0U, nonce,
                           protection_key) != 0) {
        result = -EBADMSG;
    }
    if (result == 0 && secret_size != JG_ALERT_WEBHOOK_SECRET_SIZE) {
        result = -EIO;
    }
    if (result == 0 && sqlite3_step(statement) != SQLITE_DONE) {
        result = -EIO;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result != 0) {
        sodium_memzero(secret, JG_ALERT_WEBHOOK_SECRET_SIZE);
    }
    return result;
}
