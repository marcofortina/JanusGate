/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sodium.h>

#include "janusgate/certificate.h"

int jg_test_certificate(void);

/** @brief Verify self-signed generation, metadata, and key matching. */
static void test_self_signed_certificate(void **state)
{
    static const char *const names[] = {
        "janusgate.local",
        "192.168.77.1",
        "2001:db8::1",
    };
    struct jg_certificate_material material;
    struct jg_certificate_info info;
    bool fingerprint_present = false;

    (void)state;
    assert_int_equal(jg_certificate_create_self_signed(
                         "janusgate.local", names,
                         sizeof(names) / sizeof(names[0U]), 365U, &material),
                     0);
    assert_non_null(material.certificate);
    assert_non_null(material.private_key);
    assert_null(material.request);
    assert_true(material.certificate_size > 0U);
    assert_true(material.private_key_size > 0U);
    assert_int_equal(jg_certificate_inspect(material.certificate,
                                            material.certificate_size,
                                            material.private_key,
                                            material.private_key_size, &info),
                     0);
    assert_string_equal(info.subject, "CN=janusgate.local");
    assert_string_equal(info.issuer, info.subject);
    assert_true(info.self_signed);
    assert_true(info.private_key_matches);
    assert_true(info.not_after > info.not_before);
    for (size_t index = 0U; index < sizeof(info.fingerprint_sha256); ++index) {
        fingerprint_present =
            fingerprint_present || info.fingerprint_sha256[index] != 0U;
    }
    assert_true(fingerprint_present);
    jg_certificate_material_clear(&material);
    assert_null(material.certificate);
    assert_null(material.private_key);
}

/** @brief Verify a signed CSR and rejection of a mismatched private key. */
static void test_certificate_request(void **state)
{
    static const char *const names[] = {
        "gateway.example",
    };
    struct jg_certificate_material certificate;
    struct jg_certificate_material request;
    struct jg_certificate_info info;
    BIO *memory = NULL;
    X509_REQ *parsed = NULL;
    EVP_PKEY *public_key = NULL;

    (void)state;
    assert_int_equal(
        jg_certificate_create_csr("gateway.example", names,
                                  sizeof(names) / sizeof(names[0U]), &request),
        0);
    assert_non_null(request.request);
    assert_non_null(request.private_key);
    assert_null(request.certificate);
    memory = BIO_new_mem_buf(request.request, (int)request.request_size);
    assert_non_null(memory);
    parsed = PEM_read_bio_X509_REQ(memory, NULL, NULL, NULL);
    assert_non_null(parsed);
    public_key = X509_REQ_get_pubkey(parsed);
    assert_non_null(public_key);
    assert_int_equal(X509_REQ_verify(parsed, public_key), 1);

    assert_int_equal(jg_certificate_create_self_signed("other.example", NULL,
                                                       0U, 30U, &certificate),
                     0);
    assert_int_equal(jg_certificate_inspect(
                         certificate.certificate, certificate.certificate_size,
                         request.private_key, request.private_key_size, &info),
                     -EKEYREJECTED);

    EVP_PKEY_free(public_key);
    X509_REQ_free(parsed);
    BIO_free(memory);
    jg_certificate_material_clear(&certificate);
    jg_certificate_material_clear(&request);
}

/** @brief Verify strict input bounds for certificate generation. */
static void test_certificate_validation(void **state)
{
    struct jg_certificate_material material;
    struct jg_certificate_info info;

    (void)state;
    assert_int_equal(jg_certificate_create_csr("", NULL, 0U, &material),
                     -EINVAL);
    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 0U, &material),
                     -EINVAL);
    assert_int_equal(
        jg_certificate_inspect("invalid", strlen("invalid"), NULL, 0U, &info),
        -EINVAL);
}

/** @brief Verify atomic private installation and secure file inspection. */
static void test_certificate_installation(void **state)
{
    static const char template[] = "/tmp/janusgate-certificate-XXXXXX";
    char directory[sizeof(template)];
    char path[256U];
    char link[256U];
    char pending[256U];
    char *exported = NULL;
    size_t exported_size = 0U;
    char *loaded_key = NULL;
    size_t loaded_key_size = 0U;
    struct stat metadata;
    struct jg_certificate_material material;
    struct jg_certificate_info installed;
    struct jg_certificate_info inspected;
    int written = 0;

    (void)state;
    (void)memcpy(directory, template, sizeof(template));
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, sizeof(path), "%s/server.pem", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(path));
    written = snprintf(link, sizeof(link), "%s/server-link.pem", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(link));
    written =
        snprintf(pending, sizeof(pending), "%s/server.pending", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(pending));

    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 30U, &material),
                     0);
    assert_int_equal(
        jg_certificate_install(path, material.certificate,
                               material.certificate_size, material.private_key,
                               material.private_key_size, &installed),
        0);
    assert_int_equal(stat(path, &metadata), 0);
    assert_int_equal(metadata.st_mode & 0777U, S_IRUSR | S_IWUSR);
    assert_int_equal(jg_certificate_inspect_file(path, &inspected), 0);
    assert_memory_equal(inspected.fingerprint_sha256,
                        installed.fingerprint_sha256,
                        sizeof(installed.fingerprint_sha256));
    assert_int_equal(
        jg_certificate_export_file(path, false, &exported, &exported_size), 0);
    assert_int_equal(exported_size, material.certificate_size);
    assert_memory_equal(exported, material.certificate, exported_size);
    assert_null(strstr(exported, "PRIVATE KEY"));
    jg_certificate_pem_clear(exported, exported_size);
    exported = NULL;
    exported_size = 0U;
    assert_int_equal(
        jg_certificate_export_file(path, true, &exported, &exported_size), 0);
    assert_true(exported_size > material.certificate_size);
    assert_non_null(strstr(exported, "PRIVATE KEY"));
    jg_certificate_pem_clear(exported, exported_size);
    exported = NULL;
    exported_size = 0U;

    assert_int_equal(chmod(path, 0644), 0);
    assert_int_equal(jg_certificate_inspect_file(path, &inspected), -EACCES);
    assert_int_equal(chmod(path, 0600), 0);
    assert_int_equal(symlink(path, link), 0);
    assert_int_equal(
        jg_certificate_install(link, material.certificate,
                               material.certificate_size, material.private_key,
                               material.private_key_size, &installed),
        -EACCES);

    assert_int_equal(
        jg_certificate_private_key_store(pending, material.private_key,
                                         material.private_key_size),
        0);
    assert_int_equal(
        jg_certificate_private_key_load(pending, &loaded_key, &loaded_key_size),
        0);
    assert_int_equal(loaded_key_size, material.private_key_size);
    assert_memory_equal(loaded_key, material.private_key, loaded_key_size);
    sodium_memzero(loaded_key, loaded_key_size);
    free(loaded_key);
    assert_int_equal(jg_certificate_private_key_remove(pending), 0);
    assert_int_equal(
        jg_certificate_private_key_load(pending, &loaded_key, &loaded_key_size),
        -ENOENT);

    assert_int_equal(unlink(link), 0);
    assert_int_equal(unlink(path), 0);
    assert_int_equal(rmdir(directory), 0);
    jg_certificate_material_clear(&material);
}

/** @brief Run the certificate-management unit-test group. */
int jg_test_certificate(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_self_signed_certificate),
        cmocka_unit_test(test_certificate_request),
        cmocka_unit_test(test_certificate_validation),
        cmocka_unit_test(test_certificate_installation),
    };

    return cmocka_run_group_tests_name("certificate", tests, NULL, NULL);
}
