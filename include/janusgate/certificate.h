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

/** Maximum certificate validity accepted for local generation. */
#define JG_CERTIFICATE_VALIDITY_DAYS_MAX 3650U

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
 * @return -EKEYREJECTED when the supplied private key does not match.
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
