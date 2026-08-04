/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file http_client.h
 * @brief Process-wide HTTP client initialization.
 */

#ifndef JANUSGATE_COMMON_HTTP_CLIENT_H
#define JANUSGATE_COMMON_HTTP_CLIENT_H

/**
 * @brief Initialize the shared libcurl runtime exactly once.
 *
 * The initialized runtime remains available until process termination so
 * concurrent transfers cannot race with global cleanup.
 *
 * @return 0 on success or -EIO when libcurl initialization failed.
 *
 * @thread_safety Safe to call concurrently from any thread.
 */
int jg_http_client_initialize(void);

#endif
