/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file database_internal.h
 * @brief Internal SQLite connection shared by storage modules.
 */

#ifndef JANUSGATE_DATABASE_INTERNAL_H
#define JANUSGATE_DATABASE_INTERNAL_H

#include <sqlite3.h>

/** Private database connection and path ownership. */
struct jg_database {
    sqlite3 *handle;
    char *path;
};

/** @brief Translate a SQLite result to the common errno-style contract. */
int jg_database_sqlite_result(int status);

#endif
