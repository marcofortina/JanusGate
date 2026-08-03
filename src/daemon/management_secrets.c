/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_secrets.c
 * @brief Secure appliance-local management secret storage.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

/** @brief Split one absolute key path into its parent and leaf. */
static int split_key_path(const char *path,
                          char directory[PATH_MAX],
                          char leaf[NAME_MAX + 1U])
{
    const char *separator = path == NULL ? NULL : strrchr(path, '/');
    size_t directory_size = 0U;
    size_t leaf_size = 0U;

    if (separator == NULL || path[0U] != '/' || separator[1U] == '\0') {
        return -EINVAL;
    }
    directory_size = separator == path ? 1U : (size_t)(separator - path);
    leaf_size = strlen(separator + 1U);
    if (directory_size >= PATH_MAX || leaf_size == 0U || leaf_size > NAME_MAX ||
        (leaf_size == 1U && separator[1U] == '.') ||
        (leaf_size == 2U && separator[1U] == '.' && separator[2U] == '.')) {
        return -EINVAL;
    }
    (void)memcpy(directory, path, directory_size);
    directory[directory_size] = '\0';
    (void)memcpy(leaf, separator + 1U, leaf_size + 1U);
    return 0;
}

/** @brief Validate exact private key-file metadata. */
static int validate_key_file(int descriptor)
{
    struct stat metadata;
    const uid_t effective_user = geteuid();

    if (fstat(descriptor, &metadata) != 0) {
        return -errno;
    }
    return S_ISREG(metadata.st_mode) &&
                   (effective_user == 0U ||
                    metadata.st_uid == effective_user) &&
                   (metadata.st_mode & 0777U) == (S_IRUSR | S_IWUSR) &&
                   metadata.st_nlink == 1U &&
                   metadata.st_size == (off_t)JG_AUTH_TOTP_KEY_SIZE
               ? 0
               : -EACCES;
}

/** @brief Read one exact key buffer without short I/O. */
static int read_key(int descriptor, uint8_t key[JG_AUTH_TOTP_KEY_SIZE])
{
    size_t offset = 0U;

    while (offset < JG_AUTH_TOTP_KEY_SIZE) {
        const ssize_t transferred =
            read(descriptor, key + offset, JG_AUTH_TOTP_KEY_SIZE - offset);

        if (transferred > 0) {
            offset += (size_t)transferred;
        } else if (transferred == 0) {
            return -EIO;
        } else if (errno != EINTR) {
            return -errno;
        }
    }
    return 0;
}

/** @brief Write one exact key buffer without short I/O. */
static int write_key(int descriptor, const uint8_t key[JG_AUTH_TOTP_KEY_SIZE])
{
    size_t offset = 0U;

    while (offset < JG_AUTH_TOTP_KEY_SIZE) {
        const ssize_t transferred =
            write(descriptor, key + offset, JG_AUTH_TOTP_KEY_SIZE - offset);

        if (transferred > 0) {
            offset += (size_t)transferred;
        } else if (transferred == 0) {
            return -EIO;
        } else if (errno != EINTR) {
            return -errno;
        }
    }
    return 0;
}

/** @brief Load one exact owner-private TOTP protection key. */
int management_totp_key_load(const char *path,
                             uint8_t key[JG_AUTH_TOTP_KEY_SIZE])
{
    int descriptor = -1;
    int result = 0;

    if (path == NULL || key == NULL) {
        return -EINVAL;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    result = validate_key_file(descriptor);
    if (result == 0) {
        result = read_key(descriptor, key);
    }
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result != 0) {
        sodium_memzero(key, JG_AUTH_TOTP_KEY_SIZE);
    }
    return result;
}

/** @brief Atomically replace one owner-private TOTP protection key. */
int management_totp_key_store(const char *path,
                              const uint8_t key[JG_AUTH_TOTP_KEY_SIZE])
{
    char directory_path[PATH_MAX];
    char leaf[NAME_MAX + 1U];
    char temporary[64U] = {0};
    struct stat directory_metadata;
    uint64_t random = 0U;
    int directory = -1;
    int descriptor = -1;
    int result = split_key_path(path, directory_path, leaf);

    if (result != 0 || key == NULL) {
        return result != 0 ? result : -EINVAL;
    }
    directory =
        open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        return -errno;
    }
    if (fstat(directory, &directory_metadata) != 0) {
        result = -errno;
    }
    if (result == 0) {
        descriptor = openat(directory, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor >= 0) {
            result = validate_key_file(descriptor);
            if (close(descriptor) != 0 && result == 0) {
                result = -errno;
            }
            descriptor = -1;
        } else if (errno != ENOENT) {
            result = -errno;
        }
    }
    if (result == 0) {
        randombytes_buf(&random, sizeof(random));
        const int written = snprintf(temporary, sizeof(temporary),
                                     ".janusgate-totp-%016" PRIx64, random);

        if (written <= 0 || (size_t)written >= sizeof(temporary)) {
            result = -EOVERFLOW;
        }
    }
    if (result == 0) {
        descriptor =
            openat(directory, temporary,
                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   S_IRUSR | S_IWUSR);
        if (descriptor < 0) {
            result = -errno;
        }
    }
    if (result == 0 && geteuid() == 0U &&
        fchown(descriptor, directory_metadata.st_uid,
               directory_metadata.st_gid) != 0) {
        result = -errno;
    }
    if (result == 0) {
        result = write_key(descriptor, key);
    }
    if (result == 0 && fsync(descriptor) != 0) {
        result = -errno;
    }
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0 && renameat(directory, temporary, directory, leaf) != 0) {
        result = -errno;
    } else if (result == 0) {
        temporary[0U] = '\0';
    }
    if (result == 0 && fsync(directory) != 0) {
        result = -errno;
    }
    if (temporary[0U] != '\0') {
        (void)unlinkat(directory, temporary, 0);
    }
    if (close(directory) != 0 && result == 0) {
        result = -errno;
    }
    sodium_memzero(&random, sizeof(random));
    return result;
}

/** @brief Atomically copy one validated TOTP protection key. */
int management_totp_key_copy(const char *source, const char *destination)
{
    uint8_t key[JG_AUTH_TOTP_KEY_SIZE];
    int result = 0;

    if (source == NULL || destination == NULL ||
        strcmp(source, destination) == 0) {
        return -EINVAL;
    }
    result = management_totp_key_load(source, key);
    if (result == 0) {
        result = management_totp_key_store(destination, key);
    }
    sodium_memzero(key, sizeof(key));
    return result;
}
