/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/diagnostic.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "janusgate/checked.h"

/** Bytes in one POSIX tar record. */
#define TAR_BLOCK_SIZE 512U

/** POSIX tar end marker record count. */
#define TAR_END_BLOCK_COUNT 2U

/** @brief Determine whether one root-level archive name is safe. */
static bool entry_name_valid(const char *name)
{
    size_t length = 0U;

    if (name == NULL || name[0U] == '\0') {
        return false;
    }
    while (length <= JG_DIAGNOSTIC_NAME_MAX && name[length] != '\0') {
        const unsigned char character = (unsigned char)name[length];

        if (!((character >= (unsigned char)'a' &&
               character <= (unsigned char)'z') ||
              (character >= (unsigned char)'A' &&
               character <= (unsigned char)'Z') ||
              (character >= (unsigned char)'0' &&
               character <= (unsigned char)'9') ||
              character == (unsigned char)'.' ||
              character == (unsigned char)'_' ||
              character == (unsigned char)'-')) {
            return false;
        }
        ++length;
    }
    return length > 0U && length <= JG_DIAGNOSTIC_NAME_MAX;
}

/** @brief Reject duplicate archive entry names. */
static bool entry_names_unique(const struct jg_diagnostic_entry *entries,
                               size_t entry_count)
{
    for (size_t left = 0U; left < entry_count; ++left) {
        for (size_t right = left + 1U; right < entry_count; ++right) {
            if (strcmp(entries[left].name, entries[right].name) == 0) {
                return false;
            }
        }
    }
    return true;
}

/** @brief Write one unsigned value into a null-terminated tar octal field. */
static int write_octal(uint8_t *field, size_t field_size, uint64_t value)
{
    char digits[32U];
    int written =
        snprintf(digits, sizeof(digits), "%llo", (unsigned long long)value);
    size_t digit_count = 0U;

    if (written <= 0) {
        return -EIO;
    }
    digit_count = (size_t)written;
    if (field_size < 2U || digit_count > field_size - 1U) {
        return -EOVERFLOW;
    }
    (void)memset(field, '0', field_size);
    (void)memcpy(field + field_size - 1U - digit_count, digits, digit_count);
    field[field_size - 1U] = '\0';
    return 0;
}

/** @brief Encode one portable regular-file ustar header. */
static int write_header(uint8_t header[TAR_BLOCK_SIZE],
                        const struct jg_diagnostic_entry *entry,
                        uint64_t created_at)
{
    uint64_t checksum = 0U;
    int result = 0;

    (void)memset(header, 0, TAR_BLOCK_SIZE);
    (void)memcpy(header, entry->name, strlen(entry->name));
    result = write_octal(header + 100U, 8U, UINT64_C(0600));
    if (result == 0) {
        result = write_octal(header + 108U, 8U, 0U);
    }
    if (result == 0) {
        result = write_octal(header + 116U, 8U, 0U);
    }
    if (result == 0) {
        result = write_octal(header + 124U, 12U, (uint64_t)entry->size);
    }
    if (result == 0) {
        result = write_octal(header + 136U, 12U, created_at);
    }
    if (result != 0) {
        return result;
    }
    (void)memset(header + 148U, ' ', 8U);
    header[156U] = (uint8_t)'0';
    (void)memcpy(header + 257U, "ustar", 5U);
    (void)memcpy(header + 263U, "00", 2U);
    (void)memcpy(header + 265U, "root", 4U);
    (void)memcpy(header + 297U, "root", 4U);
    for (size_t index = 0U; index < TAR_BLOCK_SIZE; ++index) {
        checksum += header[index];
    }
    result = write_octal(header + 148U, 7U, checksum);
    header[155U] = (uint8_t)' ';
    return result;
}

/** @brief Calculate the complete padded tar representation size. */
static int tar_size(const struct jg_diagnostic_entry *entries,
                    size_t entry_count,
                    size_t *size)
{
    size_t content_size = 0U;
    size_t total = TAR_END_BLOCK_COUNT * TAR_BLOCK_SIZE;

    for (size_t index = 0U; index < entry_count; ++index) {
        size_t padded = 0U;

        if (!entry_name_valid(entries[index].name) ||
            (entries[index].data == NULL && entries[index].size != 0U)) {
            return -EINVAL;
        }
        if (!jg_size_add(content_size, entries[index].size, &content_size) ||
            !jg_size_add(entries[index].size, TAR_BLOCK_SIZE - 1U, &padded)) {
            return -EOVERFLOW;
        }
        if (content_size > JG_DIAGNOSTIC_CONTENT_SIZE_MAX) {
            return -EMSGSIZE;
        }
        padded = padded / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;
        if (!jg_size_add(total, TAR_BLOCK_SIZE, &total) ||
            !jg_size_add(total, padded, &total)) {
            return -EOVERFLOW;
        }
    }
    *size = total;
    return 0;
}

/** @brief Serialize every selected file into one zero-padded tar buffer. */
static int create_tar(const struct jg_diagnostic_entry *entries,
                      size_t entry_count,
                      uint64_t created_at,
                      uint8_t **tar,
                      size_t *size)
{
    size_t offset = 0U;
    int result = tar_size(entries, entry_count, size);

    if (result != 0) {
        return result;
    }
    if (!entry_names_unique(entries, entry_count)) {
        return -EINVAL;
    }
    *tar = calloc(1U, *size);
    if (*tar == NULL) {
        return -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < entry_count; ++index) {
        result = write_header(*tar + offset, &entries[index], created_at);
        offset += TAR_BLOCK_SIZE;
        if (result == 0 && entries[index].size != 0U) {
            (void)memcpy(*tar + offset, entries[index].data,
                         entries[index].size);
        }
        offset += (entries[index].size + TAR_BLOCK_SIZE - 1U) / TAR_BLOCK_SIZE *
                  TAR_BLOCK_SIZE;
    }
    if (result != 0) {
        free(*tar);
        *tar = NULL;
    }
    return result;
}

/** @brief Compress one complete tar buffer with a portable gzip wrapper. */
static int compress_tar(uint8_t *tar,
                        size_t tar_size_value,
                        uint64_t created_at,
                        uint8_t **archive,
                        size_t *archive_size)
{
    gz_header header;
    z_stream stream;
    uLong bound = 0UL;
    int status = Z_OK;
    int result = 0;

    (void)memset(&header, 0, sizeof(header));
    (void)memset(&stream, 0, sizeof(stream));
    status = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16,
                          8, Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        return status == Z_MEM_ERROR ? -ENOMEM : -EIO;
    }
    header.time = created_at > (uint64_t)UINT32_MAX ? (uLong)UINT32_MAX
                                                    : (uLong)created_at;
    header.os = 3;
    status = deflateSetHeader(&stream, &header);
    bound = deflateBound(&stream, (uLong)tar_size_value);
    if (status != Z_OK || bound == 0UL ||
        bound > (uLong)JG_DIAGNOSTIC_ARCHIVE_SIZE_MAX ||
        bound > (uLong)UINT_MAX) {
        result = status == Z_OK ? -EMSGSIZE : -EIO;
    }
    if (result == 0) {
        *archive = malloc((size_t)bound);
        if (*archive == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        stream.next_in = tar;
        stream.avail_in = (uInt)tar_size_value;
        stream.next_out = *archive;
        stream.avail_out = (uInt)bound;
        status = deflate(&stream, Z_FINISH);
        if (status != Z_STREAM_END) {
            result = status == Z_MEM_ERROR ? -ENOMEM : -EIO;
        } else {
            *archive_size = (size_t)stream.total_out;
        }
    }
    if (deflateEnd(&stream) != Z_OK && result == 0) {
        result = -EIO;
    }
    if (result != 0) {
        free(*archive);
        *archive = NULL;
        *archive_size = 0U;
    }
    return result;
}

/** @brief Create one validated gzip-compressed ustar archive. */
int jg_diagnostic_archive_create(const struct jg_diagnostic_entry *entries,
                                 size_t entry_count,
                                 uint64_t created_at,
                                 uint8_t **archive,
                                 size_t *archive_size)
{
    uint8_t *tar = NULL;
    size_t size = 0U;
    int result = 0;

    if (archive == NULL || archive_size == NULL) {
        return -EINVAL;
    }
    *archive = NULL;
    *archive_size = 0U;
    if (entries == NULL || entry_count == 0U ||
        entry_count > JG_DIAGNOSTIC_ENTRY_COUNT_MAX || created_at == 0U) {
        return -EINVAL;
    }
    result = create_tar(entries, entry_count, created_at, &tar, &size);
    if (result == 0) {
        result = compress_tar(tar, size, created_at, archive, archive_size);
    }
    free(tar);
    return result;
}

/** @brief Release one owned diagnostic archive. */
void jg_diagnostic_archive_destroy(uint8_t *archive)
{
    free(archive);
}
