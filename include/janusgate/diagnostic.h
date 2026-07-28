/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file diagnostic.h
 * @brief Bounded gzip-compressed diagnostic archives.
 *
 * Archives use POSIX ustar with deterministic ownership and permissions.
 * Callers select every included file explicitly; the archive writer never
 * reads the filesystem.
 *
 * @thread_safety Every function is reentrant and accesses caller-owned data.
 *
 * @error_handling Fallible functions return zero on success and a negative
 * errno-style value otherwise.
 */

#ifndef JANUSGATE_DIAGNOSTIC_H
#define JANUSGATE_DIAGNOSTIC_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Maximum number of files in one diagnostic archive. */
#define JG_DIAGNOSTIC_ENTRY_COUNT_MAX 16U

/** Maximum combined uncompressed diagnostic file content. */
#define JG_DIAGNOSTIC_CONTENT_SIZE_MAX (256U * 1024U)

/** Maximum compressed diagnostic archive size. */
#define JG_DIAGNOSTIC_ARCHIVE_SIZE_MAX (256U * 1024U)

/** Maximum archive filename bytes excluding the terminator. */
#define JG_DIAGNOSTIC_NAME_MAX 99U

/**
 * @brief One caller-owned regular file included in an archive.
 */
struct jg_diagnostic_entry {
    /** Safe root-level archive filename. */
    const char *name;
    /** Immutable file content, or null only when @ref size is zero. */
    const uint8_t *data;
    /** Exact file content size. */
    size_t size;
};

/**
 * @brief Create one gzip-compressed POSIX ustar diagnostic archive.
 *
 * Entry names may contain ASCII letters, digits, `.`, `_`, and `-`. Duplicate
 * names and path separators are rejected. Archive files use mode 0600 and
 * root ownership without platform-specific metadata.
 *
 * @param[in] entries Nonempty array of explicitly selected files.
 * @param[in] entry_count Number of entries.
 * @param[in] created_at Nonzero Unix creation time.
 * @param[out] archive Receives the owned compressed archive.
 * @param[out] archive_size Receives the compressed byte count.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid arguments, names, or duplicate entries.
 * @return -EOVERFLOW when an intermediate size cannot be represented.
 * @return -EMSGSIZE when configured archive limits are exceeded.
 * @return -ENOMEM when allocation fails.
 * @return -EIO when compression fails.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Allocates @p archive, which must be released with
 * @ref jg_diagnostic_archive_destroy.
 */
JG_PUBLIC int jg_diagnostic_archive_create(
    const struct jg_diagnostic_entry *entries,
    size_t entry_count,
    uint64_t created_at,
    uint8_t **archive,
    size_t *archive_size);

/**
 * @brief Release one diagnostic archive allocation.
 *
 * @param[in,out] archive Archive returned by
 * @ref jg_diagnostic_archive_create, or null.
 *
 * @thread_safety The allocation must not be used concurrently.
 */
JG_PUBLIC void jg_diagnostic_archive_destroy(uint8_t *archive);

#endif
