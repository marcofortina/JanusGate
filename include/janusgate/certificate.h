/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file certificate.h
 * @brief X.509 inspection and local key-generation primitives.
 */

#ifndef JANUSGATE_CERTIFICATE_H
#define JANUSGATE_CERTIFICATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Maximum accepted certificate or private-key PEM bytes. */
#define JG_CERTIFICATE_PEM_MAX (64U * 1024U)

/** Maximum rendered X.509 distinguished-name bytes excluding the terminator. */
#define JG_CERTIFICATE_NAME_MAX 1023U

/** Maximum requested subject alternative names. */
#define JG_CERTIFICATE_SAN_MAX 32U

/** Maximum CA certificates accepted in one client trust store. */
#define JG_CERTIFICATE_AUTHORITY_MAX 64U

/** Maximum certificate validity accepted for local generation. */
#define JG_CERTIFICATE_VALIDITY_DAYS_MAX 3650U

/** Default combined server certificate and private-key PEM path. */
#define JG_CERTIFICATE_DEFAULT_PATH "/etc/janusgate/certs/server.pem"

/** Public metadata extracted from one leaf certificate. */
struct jg_certificate_info {
    /** RFC 2253 subject distinguished name. */
    char subject[JG_CERTIFICATE_NAME_MAX + 1U];
    /** RFC 2253 issuer distinguished name. */
    char issuer[JG_CERTIFICATE_NAME_MAX + 1U];
    /** SHA-256 certificate fingerprint. */
    uint8_t fingerprint_sha256[32U];
    /** Inclusive UTC validity start as a Unix timestamp. */
    uint64_t not_before;
    /** Inclusive UTC validity end as a Unix timestamp. */
    uint64_t not_after;
    /** Whether the leaf is cryptographically self-signed. */
    bool self_signed;
    /** Whether the supplied private key matches the leaf public key. */
    bool private_key_matches;
};

/** Owned PEM material produced by local certificate operations. */
struct jg_certificate_material {
    /** Null-terminated leaf certificate PEM, when created. */
    char *certificate;
    /** Certificate bytes excluding the terminator. */
    size_t certificate_size;
    /** Null-terminated private-key PEM. */
    char *private_key;
    /** Private-key bytes excluding the terminator. */
    size_t private_key_size;
    /** Null-terminated certificate-signing request PEM, when created. */
    char *request;
    /** Request bytes excluding the terminator. */
    size_t request_size;
};

/**
 * @brief Inspect one PEM leaf certificate and optional private key.
 *
 * @param[in] certificate Certificate or chain PEM beginning with the leaf.
 * @param[in] certificate_size Exact certificate bytes.
 * @param[in] private_key Optional unencrypted private-key PEM.
 * @param[in] private_key_size Exact key bytes, or zero when absent.
 * @param[out] info Receives validated public metadata.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or PEM.
 * @return -EACCES when the supplied private key does not match.
 * @return A negative errno-style allocation or conversion error otherwise.
 *
 * @thread_safety OpenSSL initialization must be process-wide and complete.
 */
JG_PUBLIC int jg_certificate_inspect(const char *certificate,
                                     size_t certificate_size,
                                     const char *private_key,
                                     size_t private_key_size,
                                     struct jg_certificate_info *info);

/**
 * @brief Inspect one PEM trust store containing only CA certificates.
 *
 * Public, private, and self-hosted authorities are handled identically. Every
 * certificate must assert the CA basic constraint; private keys, leaf
 * certificates, CRLs, malformed trailing data, and duplicate certificates
 * are rejected.
 *
 * @param[in] pem Exact PEM trust-store bytes.
 * @param[in] pem_size PEM byte count.
 * @param[out] authorities Receives authority metadata in PEM order.
 * @param[in] capacity Available metadata records from one through
 * JG_CERTIFICATE_AUTHORITY_MAX.
 * @param[out] authority_count Receives the number of authorities.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or trust material.
 * @return -ENOSPC when @p capacity is insufficient.
 * @return A negative errno-style allocation or conversion error otherwise.
 *
 * @thread_safety OpenSSL initialization must be process-wide and complete.
 */
JG_PUBLIC int jg_certificate_trust_store_inspect(
    const char *pem,
    size_t pem_size,
    struct jg_certificate_info *authorities,
    size_t capacity,
    size_t *authority_count);

/**
 * @brief Inspect one securely installed client-certificate trust store.
 *
 * @param[in] path Absolute regular-file path.
 * @param[out] authorities Receives authority metadata in PEM order.
 * @param[in] capacity Available metadata records.
 * @param[out] authority_count Receives the number of authorities.
 *
 * @return 0 on success.
 * @return -ENOENT when no trust store is installed.
 * @return -EACCES unless the file is securely owned and permissioned.
 * @return Another result from jg_certificate_trust_store_inspect().
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_certificate_trust_store_inspect_file(
    const char *path,
    struct jg_certificate_info *authorities,
    size_t capacity,
    size_t *authority_count);

/**
 * @brief Validate and atomically install a shared client trust store.
 *
 * A newly created file inherits the containing directory group and is stored
 * with mode 0640 so the unprivileged HTTPS service can read public CA data.
 * Existing secure ownership and permissions are preserved.
 *
 * @param[in] path Absolute destination path.
 * @param[in] pem Exact PEM trust-store bytes.
 * @param[in] pem_size PEM byte count.
 * @param[out] authorities Receives installed authority metadata.
 * @param[in] capacity Available metadata records.
 * @param[out] authority_count Receives the number of authorities.
 *
 * @return 0 on success.
 * @return A result from jg_certificate_trust_store_inspect() or a negative
 * errno-style filesystem error.
 *
 * @thread_safety Concurrent writers to the same path require serialization.
 *
 * @side_effects Atomically creates or replaces @p path.
 */
JG_PUBLIC int jg_certificate_trust_store_install(
    const char *path,
    const char *pem,
    size_t pem_size,
    struct jg_certificate_info *authorities,
    size_t capacity,
    size_t *authority_count);

/**
 * @brief Securely remove an installed client trust store.
 *
 * @param[in] path Absolute regular-file path.
 *
 * @return 0 when absent or removed.
 * @return -EACCES for an unsafe target.
 * @return A negative errno-style filesystem error otherwise.
 *
 * @thread_safety Concurrent access to the same path requires serialization.
 *
 * @side_effects Removes the trust-store file when present.
 */
JG_PUBLIC int jg_certificate_trust_store_remove(const char *path);

/**
 * @brief Inspect one securely installed combined certificate PEM.
 *
 * @param[in] path Absolute regular-file path.
 * @param[out] info Receives validated public metadata.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or PEM.
 * @return -EACCES unless the file is owned by the effective user with mode
 * 0600, or uses mode 0640 with a read-only group available to the process.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Opens and reads one bounded file without following a symlink.
 */
JG_PUBLIC int jg_certificate_inspect_file(const char *path,
                                          struct jg_certificate_info *info);

/**
 * @brief Export an installed identity with or without its private key.
 *
 * @param[in] path Absolute combined server identity path.
 * @param[in] include_private_key Whether to retain private-key PEM.
 * @param[out] pem Receives owned null-terminated PEM.
 * @param[out] pem_size Receives exact PEM bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or PEM.
 * @return -EACCES unless the file is owned by the effective user with mode
 * 0600, or uses mode 0640 with a read-only group available to the process.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety This function is reentrant.
 *
 * @side_effects Opens and reads one bounded file without following a symlink.
 * Release @p pem with jg_certificate_pem_clear().
 */
JG_PUBLIC int jg_certificate_export_file(const char *path,
                                         bool include_private_key,
                                         char **pem,
                                         size_t *pem_size);

/**
 * @brief Securely erase and release exported PEM.
 *
 * @param[in,out] pem Exported PEM, or null.
 * @param[in] pem_size Exact PEM bytes.
 */
JG_PUBLIC void jg_certificate_pem_clear(char *pem, size_t pem_size);

/**
 * @brief Atomically install one matching certificate and private key.
 *
 * The destination directory must already exist. An existing destination must
 * be a secure regular file owned by the effective user.
 *
 * @param[in] path Absolute destination path.
 * @param[in] certificate Certificate or chain PEM beginning with the leaf.
 * @param[in] certificate_size Exact certificate bytes.
 * @param[in] private_key Matching unencrypted private-key PEM.
 * @param[in] private_key_size Exact private-key bytes.
 * @param[out] info Receives installed public metadata.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or PEM.
 * @return -EACCES when the private key does not match.
 * @return -EACCES for an insecure existing destination. A secure 0640
 * destination owned by the effective user retains its service group.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety Concurrent installation to the same path is unsupported.
 *
 * @side_effects Creates a private temporary file, synchronizes it, and
 * atomically replaces the destination.
 */
JG_PUBLIC int jg_certificate_install(const char *path,
                                     const char *certificate,
                                     size_t certificate_size,
                                     const char *private_key,
                                     size_t private_key_size,
                                     struct jg_certificate_info *info);

/**
 * @brief Atomically store one validated pending private key.
 *
 * @param[in] path Absolute private destination path.
 * @param[in] private_key Unencrypted private-key PEM.
 * @param[in] private_key_size Exact private-key bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or PEM.
 * @return -EACCES for an insecure existing destination. A secure 0640
 * destination owned by the effective user retains its service group.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety Concurrent replacement of the same path is unsupported.
 */
JG_PUBLIC int jg_certificate_private_key_store(const char *path,
                                               const char *private_key,
                                               size_t private_key_size);

/**
 * @brief Load one securely stored pending private key.
 *
 * @param[in] path Absolute private source path.
 * @param[out] private_key Receives an owned null-terminated PEM.
 * @param[out] private_key_size Receives exact PEM bytes.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed arguments or PEM.
 * @return -EACCES for an insecure source.
 * @return A negative errno-style file or allocation error otherwise.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_certificate_private_key_load(const char *path,
                                              char **private_key,
                                              size_t *private_key_size);

/**
 * @brief Securely remove one pending private-key file.
 *
 * @param[in] path Absolute private-key path.
 *
 * @return 0 on success.
 * @return -EINVAL for a malformed path.
 * @return -EACCES for an insecure source.
 * @return A negative errno-style file error otherwise.
 *
 * @thread_safety Concurrent replacement of the same path is unsupported.
 */
JG_PUBLIC int jg_certificate_private_key_remove(const char *path);

/**
 * @brief Generate a private key and PKCS#10 certificate-signing request.
 *
 * Subject alternative names accept normalized DNS names and IPv4 or IPv6
 * literals. Private-key material is returned only to the trusted caller.
 *
 * @param[in] common_name Nonempty certificate common name.
 * @param[in] alternative_names Optional array of subject alternative names.
 * @param[in] alternative_name_count Number of names in the array.
 * @param[out] material Receives owned private-key and request PEM.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed names or arguments.
 * @return A negative errno-style OpenSSL or allocation error otherwise.
 *
 * @thread_safety OpenSSL key generation is thread-safe after initialization.
 */
JG_PUBLIC int jg_certificate_create_csr(
    const char *common_name,
    const char *const *alternative_names,
    size_t alternative_name_count,
    struct jg_certificate_material *material);

/**
 * @brief Generate a private key and self-signed server certificate.
 *
 * @param[in] common_name Nonempty certificate common name.
 * @param[in] alternative_names Optional array of subject alternative names.
 * @param[in] alternative_name_count Number of names in the array.
 * @param[in] validity_days Validity in whole days.
 * @param[out] material Receives owned private-key and certificate PEM.
 *
 * @return 0 on success.
 * @return -EINVAL for malformed names, validity, or arguments.
 * @return A negative errno-style OpenSSL or allocation error otherwise.
 *
 * @thread_safety OpenSSL key generation is thread-safe after initialization.
 */
JG_PUBLIC int jg_certificate_create_self_signed(
    const char *common_name,
    const char *const *alternative_names,
    size_t alternative_name_count,
    uint32_t validity_days,
    struct jg_certificate_material *material);

/**
 * @brief Erase private material and release created PEM buffers.
 *
 * @param[in,out] material Owned material to clear; null is accepted.
 *
 * @thread_safety The material must not be used concurrently.
 */
JG_PUBLIC void jg_certificate_material_clear(
    struct jg_certificate_material *material);

#endif
