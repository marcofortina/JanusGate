/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file database_internal.h
 * @brief Internal SQLite connection shared by storage modules.
 */

#ifndef JANUSGATE_DATABASE_INTERNAL_H
#define JANUSGATE_DATABASE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

/** Private database connection and path ownership. */
struct jg_database {
    /** Open SQLite connection owned by this object. */
    sqlite3 *handle;
    /** Absolute database path owned by this object. */
    char *path;
    /** Number of cooperating transaction scopes on this connection. */
    unsigned int transaction_depth;
    /** Whether an active transaction could not be rolled back safely. */
    bool transaction_failed;
    /** Configured busy timeout reused by private peer connections. */
    uint32_t busy_timeout_ms;
};

/** @brief Translate a SQLite result to the common errno-style contract. */
int jg_database_sqlite_result(int status);

/** @brief Execute one fixed SQL statement without returning rows. */
int jg_database_execute_sql(sqlite3 *handle, const char *sql);

/** @brief Parse a required SQLite text column without embedded null bytes. */
int jg_database_column_required_text(sqlite3_stmt *statement,
                                     int column,
                                     const char **text,
                                     size_t *length);

/** @brief Copy one nullable text column into bounded record storage. */
int jg_database_column_optional_text(sqlite3_stmt *statement,
                                     int column,
                                     char *destination,
                                     size_t capacity);

/** @brief Decode one required nonnegative integer column. */
int jg_database_column_unsigned(sqlite3_stmt *statement,
                                int column,
                                uint64_t *value);

/** @brief Decode a nullable nonnegative integer as zero when absent. */
int jg_database_column_optional_unsigned(sqlite3_stmt *statement,
                                         int column,
                                         uint64_t *value);

/** @brief Decode one optional fixed-size binary column. */
int jg_database_column_optional_blob(sqlite3_stmt *statement,
                                     int column,
                                     uint8_t *destination,
                                     size_t expected_size,
                                     bool *present);

/** @brief Read one record revision or report an absent identifier. */
int jg_database_read_revision(sqlite3 *handle,
                              const char *query,
                              uint64_t identifier,
                              uint64_t *revision);

/** @brief Classify a failed optimistic record write. */
int jg_database_write_conflict(sqlite3 *handle,
                               const char *query,
                               uint64_t identifier,
                               uint64_t expected_revision,
                               bool revision_must_advance);

/** @brief Enter a transaction scope, nesting within an existing scope. */
int jg_database_transaction_begin(struct jg_database *database);

/** @brief Enter a read transaction scope, nesting within an existing scope. */
int jg_database_transaction_begin_read(struct jg_database *database);

/**
 * @brief Commit one transaction scope and recover the outermost scope on
 * failure.
 */
int jg_database_transaction_commit(struct jg_database *database);

/** @brief Roll back every active transaction scope. */
int jg_database_transaction_rollback(struct jg_database *database);

/** @brief Open an independent connection to the same database file. */
int jg_database_open_peer(const struct jg_database *database,
                          struct jg_database **peer);

/** @brief Create and synchronize the fixed durable recovery checkpoint. */
int jg_database_recovery_checkpoint_create(const struct jg_database *database);

/** @brief Replace the current database from its recovery checkpoint. */
int jg_database_recovery_checkpoint_restore(struct jg_database *database);

/** @brief Remove and synchronize the fixed recovery checkpoint. */
int jg_database_recovery_checkpoint_remove(const struct jg_database *database);

#endif
