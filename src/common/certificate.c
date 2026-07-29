/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _GNU_SOURCE

#include "janusgate/certificate.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sodium.h>

#include "janusgate/domain.h"

/** Maximum common-name bytes accepted before UTF-8 validation by OpenSSL. */
#define CERTIFICATE_COMMON_NAME_MAX 253U

/** RSA strength used for locally created long-lived identities. */
#define CERTIFICATE_RSA_BITS 3072

/** @brief Return one bounded string length or one past the maximum. */
static size_t bounded_length(const char *text, size_t maximum)
{
    size_t length = 0U;

    if (text == NULL) {
        return maximum + 1U;
    }
    while (length <= maximum && text[length] != '\0') {
        ++length;
    }
    return length;
}

/** @brief Convert one ASN.1 UTC time to a nonnegative Unix timestamp. */
static int certificate_time(const ASN1_TIME *value, uint64_t *timestamp)
{
    struct tm decoded = {0};
    time_t converted = 0;

    if (value == NULL || timestamp == NULL ||
        ASN1_TIME_to_tm(value, &decoded) != 1) {
        return -EINVAL;
    }
    errno = 0;
    converted = timegm(&decoded);
    if (converted < 0 || (converted == (time_t)-1 && errno != 0)) {
        return -ERANGE;
    }
    *timestamp = (uint64_t)converted;
    return 0;
}

/** @brief Render one distinguished name in stable RFC 2253 form. */
static int render_name(const X509_NAME *name,
                       char output[JG_CERTIFICATE_NAME_MAX + 1U])
{
    BIO *memory = BIO_new(BIO_s_mem());
    char *data = NULL;
    int result = 0;

    if (memory == NULL) {
        return -ENOMEM;
    }
    if (X509_NAME_print_ex(memory, name, 0, XN_FLAG_RFC2253) < 0) {
        result = -EINVAL;
    }
    if (result == 0) {
        const long size = BIO_get_mem_data(memory, &data);

        if (size <= 0L || size > (long)JG_CERTIFICATE_NAME_MAX) {
            result = -ENOSPC;
        } else {
            (void)memcpy(output, data, (size_t)size);
            output[size] = '\0';
        }
    }
    BIO_free(memory);
    return result;
}

/** @brief Decode one bounded PEM leaf certificate. */
static X509 *read_certificate(const char *pem, size_t pem_size)
{
    BIO *memory = NULL;
    X509 *certificate = NULL;

    if (pem == NULL || pem_size == 0U || pem_size > JG_CERTIFICATE_PEM_MAX ||
        pem_size > (size_t)INT_MAX) {
        return NULL;
    }
    memory = BIO_new_mem_buf(pem, (int)pem_size);
    if (memory != NULL) {
        certificate = PEM_read_bio_X509(memory, NULL, NULL, NULL);
    }
    BIO_free(memory);
    return certificate;
}

/** @brief Decode one bounded unencrypted PEM private key. */
static EVP_PKEY *read_private_key(const char *pem, size_t pem_size)
{
    BIO *memory = NULL;
    EVP_PKEY *private_key = NULL;

    if (pem == NULL || pem_size == 0U || pem_size > JG_CERTIFICATE_PEM_MAX ||
        pem_size > (size_t)INT_MAX) {
        return NULL;
    }
    memory = BIO_new_mem_buf(pem, (int)pem_size);
    if (memory != NULL) {
        private_key = PEM_read_bio_PrivateKey(memory, NULL, NULL, NULL);
    }
    BIO_free(memory);
    return private_key;
}

/** @brief Inspect one parsed leaf and optional private key. */
static int inspect_certificate(X509 *certificate,
                               EVP_PKEY *private_key,
                               struct jg_certificate_info *info)
{
    EVP_PKEY *public_key = NULL;
    unsigned int fingerprint_size = 0U;
    int result = render_name(X509_get_subject_name(certificate), info->subject);

    if (result == 0) {
        result = render_name(X509_get_issuer_name(certificate), info->issuer);
    }
    if (result == 0 &&
        X509_digest(certificate, EVP_sha256(), info->fingerprint_sha256,
                    &fingerprint_size) != 1) {
        result = -EINVAL;
    }
    if (result == 0 && fingerprint_size != sizeof(info->fingerprint_sha256)) {
        result = -EILSEQ;
    }
    if (result == 0) {
        result = certificate_time(X509_get0_notBefore(certificate),
                                  &info->not_before);
    }
    if (result == 0) {
        result =
            certificate_time(X509_get0_notAfter(certificate), &info->not_after);
    }
    if (result == 0 && info->not_after <= info->not_before) {
        result = -EINVAL;
    }
    if (result == 0) {
        public_key = X509_get_pubkey(certificate);
        if (public_key == NULL) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        info->self_signed =
            X509_NAME_cmp(X509_get_subject_name(certificate),
                          X509_get_issuer_name(certificate)) == 0 &&
            X509_verify(certificate, public_key) == 1;
        info->private_key_matches =
            private_key != NULL &&
            X509_check_private_key(certificate, private_key) == 1;
        if (private_key != NULL && !info->private_key_matches) {
            result = -EKEYREJECTED;
        }
    }
    EVP_PKEY_free(public_key);
    return result;
}

/** @brief Inspect one PEM certificate and optional matching private key. */
int jg_certificate_inspect(const char *certificate,
                           size_t certificate_size,
                           const char *private_key,
                           size_t private_key_size,
                           struct jg_certificate_info *info)
{
    X509 *parsed_certificate = NULL;
    EVP_PKEY *parsed_key = NULL;
    int result = 0;

    if (info == NULL || ((private_key == NULL) != (private_key_size == 0U))) {
        return -EINVAL;
    }
    (void)memset(info, 0, sizeof(*info));
    parsed_certificate = read_certificate(certificate, certificate_size);
    if (parsed_certificate == NULL) {
        result = -EINVAL;
    }
    if (result == 0 && private_key != NULL) {
        parsed_key = read_private_key(private_key, private_key_size);
        if (parsed_key == NULL) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        result = inspect_certificate(parsed_certificate, parsed_key, info);
    }
    EVP_PKEY_free(parsed_key);
    X509_free(parsed_certificate);
    if (result != 0) {
        (void)memset(info, 0, sizeof(*info));
    }
    return result;
}

/** @brief Split one safe absolute path into directory and leaf components. */
static int split_path(const char *path,
                      char directory[PATH_MAX],
                      char leaf[NAME_MAX + 1U])
{
    const size_t path_size = bounded_length(path, PATH_MAX - 1U);
    const char *separator = NULL;
    size_t directory_size = 0U;
    size_t leaf_size = 0U;

    if (path_size < 2U || path_size >= PATH_MAX || path[0U] != '/') {
        return -EINVAL;
    }
    for (size_t index = 0U; index < path_size; ++index) {
        const uint8_t character = (uint8_t)path[index];

        if (character < UINT8_C(0x20) || character == UINT8_C(0x7f)) {
            return -EINVAL;
        }
    }
    separator = strrchr(path, '/');
    leaf_size = strlen(separator + 1);
    if (leaf_size == 0U || leaf_size > NAME_MAX ||
        (leaf_size == 1U && separator[1U] == '.') ||
        (leaf_size == 2U && separator[1U] == '.' && separator[2U] == '.')) {
        return -EINVAL;
    }
    directory_size = separator == path ? 1U : (size_t)(separator - path);
    (void)memcpy(directory, path, directory_size);
    directory[directory_size] = '\0';
    (void)memcpy(leaf, separator + 1, leaf_size + 1U);
    return 0;
}

/** @brief Read an exact byte count while retrying interrupted operations. */
static int read_exact(int descriptor, uint8_t *data, size_t data_size)
{
    size_t offset = 0U;

    while (offset < data_size) {
        const ssize_t count =
            read(descriptor, data + offset, data_size - offset);

        if (count < 0 && errno != EINTR) {
            return -errno;
        }
        if (count == 0) {
            return -EMSGSIZE;
        }
        if (count > 0) {
            offset += (size_t)count;
        }
    }
    return 0;
}

/** @brief Write an exact byte count while retrying interrupted operations. */
static int write_exact(int descriptor, const char *data, size_t data_size)
{
    size_t offset = 0U;

    while (offset < data_size) {
        const ssize_t count =
            write(descriptor, data + offset, data_size - offset);

        if (count < 0 && errno != EINTR) {
            return -errno;
        }
        if (count == 0) {
            return -EIO;
        }
        if (count > 0) {
            offset += (size_t)count;
        }
    }
    return 0;
}

/** Preserved ownership attributes for one secure destination. */
struct secure_file_attributes {
    gid_t group;
    mode_t mode;
    bool exists;
};

/** @brief Determine whether the process belongs to one service group. */
static bool process_has_group(gid_t group)
{
    gid_t *groups = NULL;
    int count = 0;
    bool present = group == getegid();

    if (present) {
        return true;
    }
    count = getgroups(0, NULL);
    if (count <= 0) {
        return false;
    }
    groups = calloc((size_t)count, sizeof(*groups));
    if (groups == NULL || getgroups(count, groups) != count) {
        free(groups);
        return false;
    }
    for (int index = 0; index < count && !present; ++index) {
        present = groups[index] == group;
    }
    free(groups);
    return present;
}

/** @brief Validate private owner or read-only service-group access. */
static bool secure_file_valid(const struct stat *metadata, bool require_owner)
{
    const mode_t permissions = metadata->st_mode & 0777;
    const bool owner = metadata->st_uid == geteuid();
    const bool group_reader = permissions == 0640;

    return S_ISREG(metadata->st_mode) &&
           ((owner && (permissions == 0600 || group_reader)) ||
            (!require_owner && group_reader &&
             process_has_group(metadata->st_gid)));
}

/** @brief Check and capture one destination without following its final link.
 */
static int validate_destination(int directory,
                                const char *leaf,
                                struct secure_file_attributes *attributes)
{
    struct stat metadata;

    *attributes = (struct secure_file_attributes){
        .group = getegid(),
        .mode = 0600,
        .exists = false,
    };
    if (fstatat(directory, leaf, &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? 0 : -errno;
    }
    if (!secure_file_valid(&metadata, true)) {
        return -EACCES;
    }
    attributes->group = metadata.st_gid;
    attributes->mode = metadata.st_mode & 0777;
    attributes->exists = true;
    return 0;
}

/** @brief Load one bounded secure regular file without following symlinks. */
static int read_secure_file(const char *path, uint8_t **data, size_t *data_size)
{
    char directory_path[PATH_MAX];
    char leaf[NAME_MAX + 1U];
    struct stat metadata;
    int directory = -1;
    int descriptor = -1;
    int result = 0;

    if (data == NULL || data_size == NULL) {
        return -EINVAL;
    }
    *data = NULL;
    *data_size = 0U;
    result = split_path(path, directory_path, leaf);
    if (result != 0) {
        return result;
    }
    directory =
        open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        return -errno;
    }
    descriptor = openat(directory, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        result = -errno;
    }
    if (close(directory) != 0 && result == 0) {
        result = -errno;
    }
    if (result != 0) {
        return result;
    }
    if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!secure_file_valid(&metadata, false)) {
        result = -EACCES;
    } else if (metadata.st_size <= 0 ||
               metadata.st_size > (off_t)JG_CERTIFICATE_PEM_MAX) {
        result = -EMSGSIZE;
    }
    if (result == 0) {
        *data = malloc((size_t)metadata.st_size + 1U);
        if (*data == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = read_exact(descriptor, *data, (size_t)metadata.st_size);
    }
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0) {
        (*data)[metadata.st_size] = '\0';
        *data_size = (size_t)metadata.st_size;
    } else if (*data != NULL) {
        sodium_memzero(*data, (size_t)metadata.st_size);
        free(*data);
        *data = NULL;
    }
    return result;
}

/** @brief Inspect one securely installed combined certificate PEM. */
int jg_certificate_inspect_file(const char *path,
                                struct jg_certificate_info *info)
{
    uint8_t *data = NULL;
    size_t data_size = 0U;
    int result = 0;

    if (info == NULL) {
        return -EINVAL;
    }
    (void)memset(info, 0, sizeof(*info));
    result = read_secure_file(path, &data, &data_size);
    if (result == 0) {
        result = jg_certificate_inspect((const char *)data, data_size,
                                        (const char *)data, data_size, info);
    }
    if (data != NULL) {
        sodium_memzero(data, data_size);
        free(data);
    }
    return result;
}

/** @brief Return the first private-key PEM marker in canonical identity data.
 */
static uint8_t *find_private_key(uint8_t *data)
{
    static const char *const markers[] = {
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    };
    uint8_t *first = NULL;
    size_t index = 0U;

    for (index = 0U; index < sizeof(markers) / sizeof(markers[0U]); ++index) {
        uint8_t *candidate = (uint8_t *)strstr((char *)data, markers[index]);

        if (candidate != NULL && (first == NULL || candidate < first)) {
            first = candidate;
        }
    }
    return first;
}

/** @brief Export one installed identity with optional private material. */
int jg_certificate_export_file(const char *path,
                               bool include_private_key,
                               char **pem,
                               size_t *pem_size)
{
    struct jg_certificate_info info;
    uint8_t *data = NULL;
    const uint8_t *private_key = NULL;
    size_t data_size = 0U;
    size_t public_size = 0U;
    int result = 0;

    if (pem == NULL || pem_size == NULL) {
        return -EINVAL;
    }
    *pem = NULL;
    *pem_size = 0U;
    result = read_secure_file(path, &data, &data_size);
    if (result == 0) {
        result = jg_certificate_inspect((const char *)data, data_size,
                                        (const char *)data, data_size, &info);
    }
    if (result == 0 && include_private_key) {
        *pem = (char *)data;
        *pem_size = data_size;
        data = NULL;
    }
    if (result == 0 && !include_private_key) {
        private_key = find_private_key(data);
        if (private_key == NULL) {
            result = -EILSEQ;
        } else {
            public_size = (size_t)(private_key - data);
            *pem = malloc(public_size + 1U);
            if (*pem == NULL) {
                result = -ENOMEM;
            }
        }
    }
    if (result == 0 && !include_private_key) {
        (void)memcpy(*pem, data, public_size);
        (*pem)[public_size] = '\0';
        *pem_size = public_size;
    }
    if (data != NULL) {
        sodium_memzero(data, data_size);
        free(data);
    }
    if (result != 0) {
        jg_certificate_pem_clear(*pem, *pem_size);
        *pem = NULL;
        *pem_size = 0U;
    }
    return result;
}

/** @brief Securely erase and release exported PEM data. */
void jg_certificate_pem_clear(char *pem, size_t pem_size)
{
    if (pem != NULL) {
        sodium_memzero(pem, pem_size);
        free(pem);
    }
}

/** @brief Create one exclusive random temporary name in an open directory. */
static int create_temporary_file(int directory, char name[64U], int *descriptor)
{
    uint8_t random[12U];
    int result = -EEXIST;

    *descriptor = -1;
    for (size_t attempt = 0U; attempt < 8U && result == -EEXIST; ++attempt) {
        if (RAND_bytes(random, sizeof(random)) != 1) {
            result = -EIO;
        } else {
            int written = snprintf(
                name, 64U,
                ".janusgate-certificate-%02x%02x%02x%02x%02x%02x%02x%02x"
                "%02x%02x%02x%02x",
                random[0U], random[1U], random[2U], random[3U], random[4U],
                random[5U], random[6U], random[7U], random[8U], random[9U],
                random[10U], random[11U]);

            if (written <= 0 || written >= 64) {
                result = -EOVERFLOW;
            } else {
                *descriptor =
                    openat(directory, name,
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                           S_IRUSR | S_IWUSR);
                result = *descriptor < 0 ? -errno : 0;
            }
        }
    }
    sodium_memzero(random, sizeof(random));
    return result;
}

/** @brief Atomically replace one secure file with up to two byte spans. */
static int atomic_write(const char *path,
                        const char *first,
                        size_t first_size,
                        const char *second,
                        size_t second_size)
{
    char directory_path[PATH_MAX];
    char leaf[NAME_MAX + 1U];
    char temporary[64U] = {0};
    struct secure_file_attributes attributes;
    int directory = -1;
    int descriptor = -1;
    bool temporary_exists = false;
    int result = 0;

    if (first == NULL || first_size == 0U ||
        ((second == NULL) != (second_size == 0U)) ||
        second_size > JG_CERTIFICATE_PEM_MAX ||
        first_size > JG_CERTIFICATE_PEM_MAX - second_size) {
        return -EINVAL;
    }
    result = split_path(path, directory_path, leaf);
    if (result == 0) {
        directory = open(directory_path,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        result = validate_destination(directory, leaf, &attributes);
    }
    if (result == 0) {
        result = create_temporary_file(directory, temporary, &descriptor);
        temporary_exists = result == 0;
    }
    if (result == 0 && attributes.exists &&
        (fchown(descriptor, (uid_t)-1, attributes.group) != 0 ||
         fchmod(descriptor, attributes.mode) != 0)) {
        result = -errno;
    }
    if (result == 0) {
        result = write_exact(descriptor, first, first_size);
    }
    if (result == 0) {
        result = write_exact(descriptor, second, second_size);
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
        temporary_exists = false;
    }
    if (result == 0 && fsync(directory) != 0) {
        result = -errno;
    }
    if (temporary_exists) {
        (void)unlinkat(directory, temporary, 0);
    }
    if (directory >= 0) {
        (void)close(directory);
    }
    return result;
}

/** @brief Atomically install one matching certificate and private key. */
int jg_certificate_install(const char *path,
                           const char *certificate,
                           size_t certificate_size,
                           const char *private_key,
                           size_t private_key_size,
                           struct jg_certificate_info *info)
{
    int result = 0;

    if (info == NULL || private_key_size > JG_CERTIFICATE_PEM_MAX ||
        certificate_size > JG_CERTIFICATE_PEM_MAX - private_key_size) {
        return -EINVAL;
    }
    result = jg_certificate_inspect(certificate, certificate_size, private_key,
                                    private_key_size, info);
    if (result == 0) {
        result = atomic_write(path, certificate, certificate_size, private_key,
                              private_key_size);
    }
    if (result != 0) {
        (void)memset(info, 0, sizeof(*info));
    }
    return result;
}

/** @brief Atomically store one validated pending private key. */
int jg_certificate_private_key_store(const char *path,
                                     const char *private_key,
                                     size_t private_key_size)
{
    EVP_PKEY *parsed = read_private_key(private_key, private_key_size);
    int result = 0;

    if (parsed == NULL) {
        return -EINVAL;
    }
    result = atomic_write(path, private_key, private_key_size, NULL, 0U);
    EVP_PKEY_free(parsed);
    return result;
}

/** @brief Load one securely stored pending private key. */
int jg_certificate_private_key_load(const char *path,
                                    char **private_key,
                                    size_t *private_key_size)
{
    uint8_t *data = NULL;
    EVP_PKEY *parsed = NULL;
    int result = 0;

    if (private_key == NULL || private_key_size == NULL) {
        return -EINVAL;
    }
    *private_key = NULL;
    *private_key_size = 0U;
    result = read_secure_file(path, &data, private_key_size);
    if (result == 0) {
        parsed = read_private_key((const char *)data, *private_key_size);
        if (parsed == NULL) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        *private_key = (char *)data;
        data = NULL;
    }
    EVP_PKEY_free(parsed);
    if (data != NULL) {
        sodium_memzero(data, *private_key_size);
        free(data);
        *private_key_size = 0U;
    }
    return result;
}

/** @brief Securely remove one pending private-key file. */
int jg_certificate_private_key_remove(const char *path)
{
    char directory_path[PATH_MAX];
    char leaf[NAME_MAX + 1U];
    struct secure_file_attributes attributes;
    int directory = -1;
    int result = split_path(path, directory_path, leaf);

    if (result == 0) {
        directory = open(directory_path,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (directory < 0) {
            result = -errno;
        }
    }
    if (result == 0) {
        result = validate_destination(directory, leaf, &attributes);
    }
    if (result == 0 && unlinkat(directory, leaf, 0) != 0) {
        result = -errno;
    }
    if (result == 0 && fsync(directory) != 0) {
        result = -errno;
    }
    if (directory >= 0) {
        (void)close(directory);
    }
    return result;
}

/** @brief Validate a common name accepted by X.509 generation. */
static bool common_name_valid(const char *common_name)
{
    const size_t length =
        bounded_length(common_name, CERTIFICATE_COMMON_NAME_MAX);

    if (length == 0U || length > CERTIFICATE_COMMON_NAME_MAX) {
        return false;
    }
    for (size_t index = 0U; index < length; ++index) {
        const uint8_t character = (uint8_t)common_name[index];

        if (character < UINT8_C(0x20) || character == UINT8_C(0x7f)) {
            return false;
        }
    }
    return true;
}

/** @brief Append validated subject alternative names to OpenSSL syntax. */
static int build_alternative_names(const char *const *names,
                                   size_t count,
                                   char **encoded)
{
    char normalized[JG_DOMAIN_NAME_MAX + 1U];
    size_t capacity = count * (JG_DOMAIN_NAME_MAX + sizeof("DNS:,"));
    size_t offset = 0U;
    int result = 0;

    *encoded = NULL;
    if (count == 0U) {
        return 0;
    }
    if (names == NULL || count > JG_CERTIFICATE_SAN_MAX) {
        return -EINVAL;
    }
    *encoded = calloc(capacity + 1U, 1U);
    if (*encoded == NULL) {
        return -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        uint8_t address[16U];
        const char *kind = NULL;
        const char *value = names[index];

        if (value != NULL && (inet_pton(AF_INET, value, address) == 1 ||
                              inet_pton(AF_INET6, value, address) == 1)) {
            kind = "IP";
        } else if (jg_domain_normalize(value, normalized, sizeof(normalized)) ==
                   0) {
            kind = "DNS";
            value = normalized;
        } else {
            result = -EINVAL;
        }
        if (result == 0) {
            const int written =
                snprintf(*encoded + offset, capacity + 1U - offset, "%s%s:%s",
                         index == 0U ? "" : ",", kind, value);

            if (written <= 0 || (size_t)written >= capacity + 1U - offset) {
                result = -EOVERFLOW;
            } else {
                offset += (size_t)written;
            }
        }
        sodium_memzero(address, sizeof(address));
        sodium_memzero(normalized, sizeof(normalized));
    }
    if (result != 0) {
        free(*encoded);
        *encoded = NULL;
    }
    return result;
}

/** @brief Generate one RSA private key with the fixed project strength. */
static int generate_private_key(EVP_PKEY **private_key)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    int result = 0;

    *private_key = NULL;
    if (context == NULL) {
        return -ENOMEM;
    }
    if (EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context, CERTIFICATE_RSA_BITS) <= 0 ||
        EVP_PKEY_keygen(context, private_key) <= 0) {
        result = -EIO;
    }
    EVP_PKEY_CTX_free(context);
    return result;
}

/** @brief Populate one X.509 subject containing only the requested CN. */
static int set_common_name(X509_NAME *subject, const char *common_name)
{
    return X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
                                      (const unsigned char *)common_name, -1,
                                      -1, 0) == 1
               ? 0
               : -EINVAL;
}

/** @brief Add one subject-alternative-name extension to a request. */
static int add_request_alternative_names(X509_REQ *request, const char *encoded)
{
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    X509_EXTENSION *extension = NULL;
    char *configuration = NULL;
    int result = 0;

    if (encoded == NULL) {
        return 0;
    }
    extensions = sk_X509_EXTENSION_new_null();
    configuration = strdup(encoded);
    if (configuration != NULL) {
        extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                                        configuration);
    }
    if (extensions == NULL || configuration == NULL || extension == NULL ||
        sk_X509_EXTENSION_push(extensions, extension) == 0) {
        result = -ENOMEM;
    } else {
        extension = NULL;
    }
    if (result == 0 && X509_REQ_add_extensions(request, extensions) != 1) {
        result = -EIO;
    }
    X509_EXTENSION_free(extension);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    free(configuration);
    return result;
}

/** @brief Copy one memory BIO into an owned null-terminated PEM buffer. */
static int copy_bio(BIO *memory, char **output, size_t *output_size)
{
    char *data = NULL;
    const long size = BIO_get_mem_data(memory, &data);

    if (size <= 0L || size > (long)JG_CERTIFICATE_PEM_MAX) {
        return -EOVERFLOW;
    }
    *output = malloc((size_t)size + 1U);
    if (*output == NULL) {
        return -ENOMEM;
    }
    (void)memcpy(*output, data, (size_t)size);
    (*output)[size] = '\0';
    *output_size = (size_t)size;
    return 0;
}

/** @brief Serialize one private key into owned PKCS#8 PEM. */
static int serialize_private_key(EVP_PKEY *private_key,
                                 struct jg_certificate_material *material)
{
    BIO *memory = BIO_new(BIO_s_mem());
    int result = 0;

    if (memory == NULL) {
        return -ENOMEM;
    }
    if (PEM_write_bio_PrivateKey(memory, private_key, NULL, NULL, 0, NULL,
                                 NULL) != 1) {
        result = -EIO;
    }
    if (result == 0) {
        result = copy_bio(memory, &material->private_key,
                          &material->private_key_size);
    }
    BIO_free(memory);
    return result;
}

/** @brief Generate a private key and signed PKCS#10 request. */
int jg_certificate_create_csr(const char *common_name,
                              const char *const *alternative_names,
                              size_t alternative_name_count,
                              struct jg_certificate_material *material)
{
    EVP_PKEY *private_key = NULL;
    X509_REQ *request = NULL;
    X509_NAME *subject = NULL;
    BIO *memory = NULL;
    char *encoded_names = NULL;
    int result = 0;

    if (material == NULL || !common_name_valid(common_name)) {
        return -EINVAL;
    }
    (void)memset(material, 0, sizeof(*material));
    result = build_alternative_names(alternative_names, alternative_name_count,
                                     &encoded_names);
    if (result == 0) {
        result = generate_private_key(&private_key);
    }
    if (result == 0) {
        request = X509_REQ_new();
        subject = X509_NAME_new();
        if (request == NULL || subject == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = set_common_name(subject, common_name);
    }
    if (result == 0 && (X509_REQ_set_version(request, 0L) != 1 ||
                        X509_REQ_set_subject_name(request, subject) != 1 ||
                        X509_REQ_set_pubkey(request, private_key) != 1)) {
        result = -EIO;
    }
    if (result == 0) {
        result = add_request_alternative_names(request, encoded_names);
    }
    if (result == 0 && X509_REQ_sign(request, private_key, EVP_sha256()) <= 0) {
        result = -EIO;
    }
    if (result == 0) {
        memory = BIO_new(BIO_s_mem());
        if (memory == NULL) {
            result = -ENOMEM;
        } else if (PEM_write_bio_X509_REQ(memory, request) != 1) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = copy_bio(memory, &material->request, &material->request_size);
    }
    if (result == 0) {
        result = serialize_private_key(private_key, material);
    }
    BIO_free(memory);
    X509_NAME_free(subject);
    X509_REQ_free(request);
    EVP_PKEY_free(private_key);
    free(encoded_names);
    if (result != 0) {
        jg_certificate_material_clear(material);
    }
    return result;
}

/** @brief Add one configured X.509 v3 extension to a certificate. */
static int add_certificate_extension(X509 *certificate,
                                     int identifier,
                                     const char *value)
{
    char *configuration = strdup(value);
    X509_EXTENSION *extension =
        configuration == NULL
            ? NULL
            : X509V3_EXT_conf_nid(NULL, NULL, identifier, configuration);
    int result = 0;

    if (extension == NULL) {
        free(configuration);
        return -EINVAL;
    }
    if (X509_add_ext(certificate, extension, -1) != 1) {
        result = -EIO;
    }
    X509_EXTENSION_free(extension);
    free(configuration);
    return result;
}

/** @brief Assign one nonzero random positive certificate serial. */
static int set_random_serial(X509 *certificate)
{
    uint8_t bytes[16U];
    BIGNUM *number = NULL;
    ASN1_INTEGER *serial = NULL;
    int result = 0;

    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        return -EIO;
    }
    bytes[0U] &= UINT8_C(0x7f);
    bytes[sizeof(bytes) - 1U] |= UINT8_C(0x01);
    number = BN_bin2bn(bytes, (int)sizeof(bytes), NULL);
    serial = number == NULL ? NULL : BN_to_ASN1_INTEGER(number, NULL);
    if (serial == NULL || X509_set_serialNumber(certificate, serial) != 1) {
        result = -EIO;
    }
    ASN1_INTEGER_free(serial);
    BN_free(number);
    sodium_memzero(bytes, sizeof(bytes));
    return result;
}

/** @brief Generate a private key and self-signed server certificate. */
int jg_certificate_create_self_signed(const char *common_name,
                                      const char *const *alternative_names,
                                      size_t alternative_name_count,
                                      uint32_t validity_days,
                                      struct jg_certificate_material *material)
{
    EVP_PKEY *private_key = NULL;
    X509 *certificate = NULL;
    X509_NAME *subject = NULL;
    BIO *memory = NULL;
    char *encoded_names = NULL;
    int result = 0;

    if (material == NULL || !common_name_valid(common_name) ||
        validity_days == 0U ||
        validity_days > JG_CERTIFICATE_VALIDITY_DAYS_MAX) {
        return -EINVAL;
    }
    (void)memset(material, 0, sizeof(*material));
    result = build_alternative_names(alternative_names, alternative_name_count,
                                     &encoded_names);
    if (result == 0) {
        result = generate_private_key(&private_key);
    }
    if (result == 0) {
        certificate = X509_new();
        subject = X509_NAME_new();
        if (certificate == NULL || subject == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = set_common_name(subject, common_name);
    }
    if (result == 0) {
        result = set_random_serial(certificate);
    }
    if (result == 0 &&
        (X509_set_version(certificate, 2L) != 1 ||
         X509_set_subject_name(certificate, subject) != 1 ||
         X509_set_issuer_name(certificate, subject) != 1 ||
         X509_set_pubkey(certificate, private_key) != 1 ||
         X509_gmtime_adj(X509_getm_notBefore(certificate), 0L) == NULL ||
         X509_gmtime_adj(X509_getm_notAfter(certificate),
                         (long)validity_days * 86400L) == NULL)) {
        result = -EIO;
    }
    if (result == 0) {
        result = add_certificate_extension(certificate, NID_basic_constraints,
                                           "critical,CA:FALSE");
    }
    if (result == 0) {
        result = add_certificate_extension(
            certificate, NID_key_usage,
            "critical,digitalSignature,keyEncipherment");
    }
    if (result == 0) {
        result = add_certificate_extension(certificate, NID_ext_key_usage,
                                           "serverAuth");
    }
    if (result == 0 && encoded_names != NULL) {
        result = add_certificate_extension(certificate, NID_subject_alt_name,
                                           encoded_names);
    }
    if (result == 0 && X509_sign(certificate, private_key, EVP_sha256()) <= 0) {
        result = -EIO;
    }
    if (result == 0) {
        memory = BIO_new(BIO_s_mem());
        if (memory == NULL) {
            result = -ENOMEM;
        } else if (PEM_write_bio_X509(memory, certificate) != 1) {
            result = -EIO;
        }
    }
    if (result == 0) {
        result = copy_bio(memory, &material->certificate,
                          &material->certificate_size);
    }
    if (result == 0) {
        result = serialize_private_key(private_key, material);
    }
    BIO_free(memory);
    X509_NAME_free(subject);
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    free(encoded_names);
    if (result != 0) {
        jg_certificate_material_clear(material);
    }
    return result;
}

/** @brief Erase private material and release created PEM buffers. */
void jg_certificate_material_clear(struct jg_certificate_material *material)
{
    if (material == NULL) {
        return;
    }
    free(material->certificate);
    free(material->request);
    if (material->private_key != NULL) {
        sodium_memzero(material->private_key, material->private_key_size);
        free(material->private_key);
    }
    (void)memset(material, 0, sizeof(*material));
}
