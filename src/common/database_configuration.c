/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/database.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sqlite3.h>

#include "database_internal.h"

/** @brief Return one lowercase hexadecimal digit. */
static char hex_digit(uint8_t value)
{
    static const char digits[] = "0123456789abcdef";

    return digits[value & UINT8_C(0x0f)];
}

/** @brief Encode fixed-size bytes as canonical lowercase hexadecimal text. */
static void encode_hex(const uint8_t *wire, size_t wire_size, char *text)
{
    size_t index = 0U;

    for (index = 0U; index < wire_size; ++index) {
        text[index * 2U] = hex_digit((uint8_t)(wire[index] >> 4U));
        text[index * 2U + 1U] = hex_digit(wire[index]);
    }
    text[wire_size * 2U] = '\0';
}

/** @brief Decode one lowercase hexadecimal digit. */
static bool decode_hex_digit(char digit, uint8_t *value)
{
    if (digit >= '0' && digit <= '9') {
        *value = (uint8_t)(digit - '0');
        return true;
    }
    if (digit >= 'a' && digit <= 'f') {
        *value = (uint8_t)(digit - 'a') + 10U;
        return true;
    }
    return false;
}

/** @brief Decode canonical lowercase hexadecimal text into fixed-size bytes. */
static int decode_hex(const char *text,
                      size_t text_size,
                      uint8_t *wire,
                      size_t wire_size)
{
    size_t index = 0U;

    if (text_size != wire_size * 2U) {
        return -EILSEQ;
    }
    for (index = 0U; index < wire_size; ++index) {
        uint8_t high = 0U;
        uint8_t low = 0U;

        if (!decode_hex_digit(text[index * 2U], &high) ||
            !decode_hex_digit(text[index * 2U + 1U], &low)) {
            return -EILSEQ;
        }
        wire[index] = (uint8_t)((uint8_t)(high << 4U) | low);
    }
    return 0;
}

/** @brief Atomically persist one validated network configuration. */
int jg_database_store_network_config(struct jg_database *database,
                                     const struct jg_network_config *config)
{
    static const char statement_text[] =
        "INSERT INTO network_configuration(id,value,revision,updated_at)"
        " VALUES(1,?1,1,unixepoch())"
        " ON CONFLICT(id) DO UPDATE SET"
        " value=excluded.value,updated_at=excluded.updated_at,"
        " revision=revision+1 WHERE revision<9223372036854775807;";
    char text[JG_NETWORK_CONFIG_WIRE_SIZE * 2U + 1U];
    uint8_t wire[JG_NETWORK_CONFIG_WIRE_SIZE];
    sqlite3_stmt *statement = NULL;
    size_t encoded_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result =
        jg_network_config_encode(config, wire, sizeof(wire), &encoded_size);
    if (result != 0) {
        return result;
    }
    if (encoded_size != sizeof(wire)) {
        return -EIO;
    }
    encode_hex(wire, sizeof(wire), text);
    status = sqlite3_prepare_v3(database->handle, statement_text, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, text, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = -EOVERFLOW;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Load one validated network record and its concurrency metadata. */
int jg_database_load_network_config_record(
    struct jg_database *database,
    struct jg_database_network_config *record)
{
    static const char query[] =
        "SELECT value,updated_at,revision FROM network_configuration"
        " WHERE id=1;";
    uint8_t wire[JG_NETWORK_CONFIG_WIRE_SIZE];
    struct jg_database_network_config loaded;
    sqlite3_stmt *statement = NULL;
    const char *text = NULL;
    size_t text_size = 0U;
    sqlite3_int64 updated_at = 0;
    sqlite3_int64 revision = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || record == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 0, &text, &text_size);
    }
    if (result == 0) {
        result = decode_hex(text, text_size, wire, sizeof(wire));
    }
    if (result == 0 &&
        jg_network_config_decode(wire, sizeof(wire), &loaded.config) != 0) {
        result = -EILSEQ;
    }
    if (result == 0) {
        updated_at = sqlite3_column_int64(statement, 1);
        revision = sqlite3_column_int64(statement, 2);
        if (sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER ||
            updated_at < 0 || revision <= 0) {
            result = -EILSEQ;
        } else {
            loaded.updated_at = (uint64_t)updated_at;
            loaded.revision = (uint64_t)revision;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *record = loaded;
    }
    return result;
}

/** @brief Load only the validated persistent network configuration. */
int jg_database_load_network_config(struct jg_database *database,
                                    struct jg_network_config *config)
{
    struct jg_database_network_config record;
    int result = 0;

    if (config == NULL) {
        return -EINVAL;
    }
    result = jg_database_load_network_config_record(database, &record);
    if (result == 0) {
        *config = record.config;
    }
    return result;
}

/** @brief Replace one network configuration at its expected revision. */
int jg_database_replace_network_config(
    struct jg_database *database,
    const struct jg_network_config *config,
    uint64_t expected_revision,
    struct jg_database_network_config *updated)
{
    static const char update[] =
        "UPDATE network_configuration SET value=?1,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=1"
        " AND revision=?2 AND revision<9223372036854775807;";
    char text[JG_NETWORK_CONFIG_WIRE_SIZE * 2U + 1U];
    uint8_t wire[JG_NETWORK_CONFIG_WIRE_SIZE];
    struct jg_database_network_config current;
    sqlite3_stmt *statement = NULL;
    size_t encoded_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result =
        jg_network_config_encode(config, wire, sizeof(wire), &encoded_size);
    if (result != 0) {
        return result;
    }
    if (encoded_size != sizeof(wire)) {
        return -EIO;
    }
    encode_hex(wire, sizeof(wire), text);
    status = sqlite3_prepare_v3(database->handle, update, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, text, -1, SQLITE_TRANSIENT);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_load_network_config_record(database, &current);
        if (result == 0 && current.revision != expected_revision) {
            result = -EAGAIN;
        } else if (result == 0 && current.revision == (uint64_t)INT64_MAX) {
            result = -EOVERFLOW;
        } else if (result == 0) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = jg_database_load_network_config_record(database, &current);
    }
    if (result == 0) {
        *updated = current;
    }
    return result;
}

/** @brief Load validated logging configuration and concurrency metadata. */
int jg_database_load_logging_config(struct jg_database *database,
                                    struct jg_database_logging_config *record)
{
    static const char query[] =
        "SELECT value,updated_at,revision FROM logging_configuration"
        " WHERE id=1;";
    struct jg_database_logging_config loaded;
    sqlite3_stmt *statement = NULL;
    const char *text = NULL;
    size_t text_size = 0U;
    sqlite3_int64 updated_at = 0;
    sqlite3_int64 revision = 0;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || record == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 0, &text, &text_size);
    }
    if (result == 0 &&
        jg_logging_config_decode(text, text_size, &loaded.config) != 0) {
        result = -EILSEQ;
    }
    if (result == 0) {
        updated_at = sqlite3_column_int64(statement, 1);
        revision = sqlite3_column_int64(statement, 2);
        if (sqlite3_column_type(statement, 1) != SQLITE_INTEGER ||
            sqlite3_column_type(statement, 2) != SQLITE_INTEGER ||
            updated_at < 0 || revision <= 0) {
            result = -EILSEQ;
        } else {
            loaded.updated_at = (uint64_t)updated_at;
            loaded.revision = (uint64_t)revision;
        }
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *record = loaded;
    }
    return result;
}

/** @brief Replace logging configuration at its expected revision. */
int jg_database_replace_logging_config(
    struct jg_database *database,
    const struct jg_logging_config *config,
    uint64_t expected_revision,
    struct jg_database_logging_config *updated)
{
    static const char update[] =
        "UPDATE logging_configuration SET value=?1,updated_at=unixepoch(),"
        "revision=revision+1 WHERE id=1"
        " AND revision=?2 AND revision<9223372036854775807;";
    char encoded[JG_LOG_CONFIG_JSON_MAX + 1U];
    struct jg_database_logging_config current;
    sqlite3_stmt *statement = NULL;
    size_t encoded_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || expected_revision == 0U ||
        expected_revision > (uint64_t)INT64_MAX || updated == NULL) {
        return -EINVAL;
    }
    (void)memset(updated, 0, sizeof(*updated));
    result = jg_logging_config_encode(config, encoded, sizeof(encoded),
                                      &encoded_size);
    if (result != 0) {
        return result;
    }
    status = sqlite3_prepare_v3(database->handle, update, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text64(statement, 1, encoded,
                                     (sqlite3_uint64)encoded_size,
                                     SQLITE_TRANSIENT, SQLITE_UTF8);
        if (status == SQLITE_OK) {
            status = sqlite3_bind_int64(statement, 2,
                                        (sqlite3_int64)expected_revision);
        }
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0 && sqlite3_changes(database->handle) != 1) {
        result = jg_database_load_logging_config(database, &current);
        if (result == 0 && current.revision != expected_revision) {
            result = -EAGAIN;
        } else if (result == 0 && current.revision == (uint64_t)INT64_MAX) {
            result = -EOVERFLOW;
        } else if (result == 0) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = jg_database_load_logging_config(database, &current);
    }
    if (result == 0) {
        *updated = current;
    }
    return result;
}

/** @brief Atomically persist one validated DNS response configuration. */
int jg_database_store_dns_response_config(
    struct jg_database *database,
    const struct jg_dns_response_config *config)
{
    static const char statement_text[] =
        "INSERT INTO system_settings(key,value,updated_at)"
        " VALUES('dns.response',?1,unixepoch())"
        " ON CONFLICT(key) DO UPDATE SET"
        " value=excluded.value,updated_at=excluded.updated_at;";
    char text[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE * 2U + 1U];
    uint8_t wire[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE];
    sqlite3_stmt *statement = NULL;
    size_t encoded_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL) {
        return -EINVAL;
    }
    result = jg_dns_response_config_encode(config, wire, sizeof(wire),
                                           &encoded_size);
    if (result != 0) {
        return result;
    }
    if (encoded_size != sizeof(wire)) {
        return -EIO;
    }
    encode_hex(wire, sizeof(wire), text);
    status = sqlite3_prepare_v3(database->handle, statement_text, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_bind_text(statement, 1, text, -1, SQLITE_TRANSIENT);
        result = jg_database_sqlite_result(status);
    }
    if (result == 0) {
        status = sqlite3_step(statement);
        result = status == SQLITE_DONE ? 0 : jg_database_sqlite_result(status);
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    return result;
}

/** @brief Load one validated persistent DNS response configuration. */
int jg_database_load_dns_response_config(struct jg_database *database,
                                         struct jg_dns_response_config *config)
{
    static const char query[] = "SELECT value FROM system_settings"
                                " WHERE key='dns.response';";
    uint8_t wire[JG_DNS_RESPONSE_CONFIG_WIRE_SIZE];
    struct jg_dns_response_config loaded;
    sqlite3_stmt *statement = NULL;
    const char *text = NULL;
    size_t text_size = 0U;
    int status = SQLITE_OK;
    int result = 0;

    if (database == NULL || config == NULL) {
        return -EINVAL;
    }
    status = sqlite3_prepare_v3(database->handle, query, -1,
                                SQLITE_PREPARE_PERSISTENT, &statement, NULL);
    result = jg_database_sqlite_result(status);
    if (result == 0) {
        status = sqlite3_step(statement);
        if (status == SQLITE_DONE) {
            result = -ENOENT;
        } else if (status != SQLITE_ROW) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        result =
            jg_database_column_required_text(statement, 0, &text, &text_size);
    }
    if (result == 0) {
        result = decode_hex(text, text_size, wire, sizeof(wire));
    }
    if (result == 0 &&
        jg_dns_response_config_decode(wire, sizeof(wire), &loaded) != 0) {
        result = -EILSEQ;
    }
    if (statement != NULL) {
        status = sqlite3_finalize(statement);
        if (result == 0) {
            result = jg_database_sqlite_result(status);
        }
    }
    if (result == 0) {
        *config = loaded;
    }
    return result;
}
