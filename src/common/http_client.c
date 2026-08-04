/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file http_client.c
 * @brief Process-wide HTTP client initialization.
 */

#include "http_client.h"

#include <errno.h>
#include <pthread.h>

#include <curl/curl.h>

/** One-time initialization guard shared by all HTTP consumers. */
static pthread_once_t http_client_once = PTHREAD_ONCE_INIT;

/** Cached global initialization result. */
static int http_client_result = -EIO;

/** @brief Perform the process-wide libcurl initialization. */
static void initialize_http_client(void)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {
        http_client_result = 0;
    }
}

/** @brief Initialize the shared libcurl runtime exactly once. */
int jg_http_client_initialize(void)
{
    return pthread_once(&http_client_once, initialize_http_client) == 0
               ? http_client_result
               : -EIO;
}
