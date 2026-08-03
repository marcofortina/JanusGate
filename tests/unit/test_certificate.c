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
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sodium.h>

#include "janusgate/certificate.h"

int jg_test_certificate(void);

/** @brief Create one private self-signed CA fixture in memory. */
static void create_test_authority(char **pem,
                                  size_t *pem_size,
                                  EVP_PKEY **authority_key,
                                  X509 **authority_certificate)
{
    char constraints_text[] = "critical,CA:TRUE,pathlen:1";
    char usage_text[] = "critical,keyCertSign,cRLSign";
    EVP_PKEY_CTX *key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *private_key = NULL;
    X509 *certificate = X509_new();
    X509_NAME *subject = X509_NAME_new();
    X509_EXTENSION *constraints = NULL;
    X509_EXTENSION *usage = NULL;
    BIO *memory = BIO_new(BIO_s_mem());
    BUF_MEM *contents = NULL;

    *pem = NULL;
    *pem_size = 0U;
    *authority_key = NULL;
    *authority_certificate = NULL;
    assert_non_null(key_context);
    assert_non_null(certificate);
    assert_non_null(subject);
    assert_non_null(memory);
    assert_int_equal(EVP_PKEY_keygen_init(key_context), 1);
    assert_int_equal(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context, 2048), 1);
    assert_int_equal(EVP_PKEY_keygen(key_context, &private_key), 1);
    assert_non_null(private_key);
    assert_int_equal(X509_NAME_add_entry_by_txt(
                         subject, "CN", MBSTRING_ASC,
                         (const unsigned char *)"JanusGate home lab CA", -1, -1,
                         0),
                     1);
    assert_int_equal(X509_set_version(certificate, 2L), 1);
    assert_int_equal(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1L),
                     1);
    assert_int_equal(X509_set_subject_name(certificate, subject), 1);
    assert_int_equal(X509_set_issuer_name(certificate, subject), 1);
    assert_int_equal(X509_set_pubkey(certificate, private_key), 1);
    assert_non_null(X509_gmtime_adj(X509_getm_notBefore(certificate), -60L));
    assert_non_null(X509_gmtime_adj(X509_getm_notAfter(certificate), 86400L));
    constraints = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                      constraints_text);
    usage = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, usage_text);
    assert_non_null(constraints);
    assert_non_null(usage);
    assert_int_equal(X509_add_ext(certificate, constraints, -1), 1);
    assert_int_equal(X509_add_ext(certificate, usage, -1), 1);
    assert_true(X509_sign(certificate, private_key, EVP_sha256()) > 0);
    assert_int_equal(PEM_write_bio_X509(memory, certificate), 1);
    BIO_get_mem_ptr(memory, &contents);
    assert_non_null(contents);
    assert_true(contents->length > 0U);
    *pem = malloc(contents->length + 1U);
    assert_non_null(*pem);
    (void)memcpy(*pem, contents->data, contents->length);
    (*pem)[contents->length] = '\0';
    *pem_size = contents->length;

    X509_EXTENSION_free(usage);
    X509_EXTENSION_free(constraints);
    BIO_free(memory);
    X509_NAME_free(subject);
    *authority_certificate = certificate;
    *authority_key = private_key;
    EVP_PKEY_CTX_free(key_context);
}

/** @brief Create one CA-signed leaf with a selected extended key usage. */
static void create_test_leaf(EVP_PKEY *authority_key,
                             X509 *authority,
                             const char *extended_usage,
                             char **pem,
                             size_t *pem_size,
                             char **key_pem,
                             size_t *key_pem_size)
{
    char constraints_text[] = "critical,CA:FALSE";
    char usage_text[] = "critical,digitalSignature";
    char extended_usage_text[32U];
    EVP_PKEY_CTX *key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *private_key = NULL;
    X509 *certificate = X509_new();
    X509_NAME *subject = X509_NAME_new();
    X509_EXTENSION *constraints = NULL;
    X509_EXTENSION *usage = NULL;
    X509_EXTENSION *extended = NULL;
    BIO *memory = BIO_new(BIO_s_mem());
    BIO *key_memory = NULL;
    BUF_MEM *contents = NULL;
    BUF_MEM *key_contents = NULL;

    *pem = NULL;
    *pem_size = 0U;
    assert_true((key_pem == NULL) == (key_pem_size == NULL));
    if (key_pem != NULL) {
        *key_pem = NULL;
        *key_pem_size = 0U;
        key_memory = BIO_new(BIO_s_mem());
    }
    assert_non_null(authority_key);
    assert_non_null(authority);
    assert_non_null(key_context);
    assert_non_null(certificate);
    assert_non_null(subject);
    assert_non_null(memory);
    assert_true(key_pem == NULL || key_memory != NULL);
    assert_true(snprintf(extended_usage_text, sizeof(extended_usage_text), "%s",
                         extended_usage) > 0);
    assert_int_equal(EVP_PKEY_keygen_init(key_context), 1);
    assert_int_equal(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context, 2048), 1);
    assert_int_equal(EVP_PKEY_keygen(key_context, &private_key), 1);
    assert_non_null(private_key);
    assert_int_equal(X509_NAME_add_entry_by_txt(
                         subject, "CN", MBSTRING_ASC,
                         (const unsigned char *)"JanusGate test client", -1, -1,
                         0),
                     1);
    assert_int_equal(X509_set_version(certificate, 2L), 1);
    assert_int_equal(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 2L),
                     1);
    assert_int_equal(X509_set_subject_name(certificate, subject), 1);
    assert_int_equal(
        X509_set_issuer_name(certificate, X509_get_subject_name(authority)), 1);
    assert_int_equal(X509_set_pubkey(certificate, private_key), 1);
    assert_non_null(X509_gmtime_adj(X509_getm_notBefore(certificate), -60L));
    assert_non_null(X509_gmtime_adj(X509_getm_notAfter(certificate), 86400L));
    constraints = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                      constraints_text);
    usage = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, usage_text);
    extended =
        X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, extended_usage_text);
    assert_non_null(constraints);
    assert_non_null(usage);
    assert_non_null(extended);
    assert_int_equal(X509_add_ext(certificate, constraints, -1), 1);
    assert_int_equal(X509_add_ext(certificate, usage, -1), 1);
    assert_int_equal(X509_add_ext(certificate, extended, -1), 1);
    assert_true(X509_sign(certificate, authority_key, EVP_sha256()) > 0);
    assert_int_equal(PEM_write_bio_X509(memory, certificate), 1);
    BIO_get_mem_ptr(memory, &contents);
    assert_non_null(contents);
    assert_true(contents->length > 0U);
    *pem = malloc(contents->length + 1U);
    assert_non_null(*pem);
    (void)memcpy(*pem, contents->data, contents->length);
    (*pem)[contents->length] = '\0';
    *pem_size = contents->length;
    if (key_pem != NULL) {
        assert_int_equal(PEM_write_bio_PrivateKey(key_memory, private_key, NULL,
                                                  NULL, 0, NULL, NULL),
                         1);
        BIO_get_mem_ptr(key_memory, &key_contents);
        assert_non_null(key_contents);
        assert_true(key_contents->length > 0U);
        *key_pem = malloc(key_contents->length + 1U);
        assert_non_null(*key_pem);
        (void)memcpy(*key_pem, key_contents->data, key_contents->length);
        (*key_pem)[key_contents->length] = '\0';
        *key_pem_size = key_contents->length;
    }

    X509_EXTENSION_free(extended);
    X509_EXTENSION_free(usage);
    X509_EXTENSION_free(constraints);
    BIO_free(key_memory);
    BIO_free(memory);
    X509_NAME_free(subject);
    X509_free(certificate);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(key_context);
}

/** @brief Re-sign generated self-signed material with selected validity. */
static void rewrite_test_validity(struct jg_certificate_material *material,
                                  long not_before,
                                  long not_after)
{
    BIO *certificate_memory =
        BIO_new_mem_buf(material->certificate, (int)material->certificate_size);
    BIO *key_memory =
        BIO_new_mem_buf(material->private_key, (int)material->private_key_size);
    BIO *output = BIO_new(BIO_s_mem());
    X509 *certificate = NULL;
    EVP_PKEY *private_key = NULL;
    BUF_MEM *contents = NULL;
    char *rewritten = NULL;

    assert_non_null(certificate_memory);
    assert_non_null(key_memory);
    assert_non_null(output);
    certificate = PEM_read_bio_X509(certificate_memory, NULL, NULL, NULL);
    private_key = PEM_read_bio_PrivateKey(key_memory, NULL, NULL, NULL);
    assert_non_null(certificate);
    assert_non_null(private_key);
    assert_non_null(
        X509_gmtime_adj(X509_getm_notBefore(certificate), not_before));
    assert_non_null(
        X509_gmtime_adj(X509_getm_notAfter(certificate), not_after));
    assert_true(X509_sign(certificate, private_key, EVP_sha256()) > 0);
    assert_int_equal(PEM_write_bio_X509(output, certificate), 1);
    BIO_get_mem_ptr(output, &contents);
    assert_non_null(contents);
    assert_true(contents->length > 0U);
    rewritten = malloc(contents->length + 1U);
    assert_non_null(rewritten);
    (void)memcpy(rewritten, contents->data, contents->length);
    rewritten[contents->length] = '\0';
    sodium_memzero(material->certificate, material->certificate_size);
    free(material->certificate);
    material->certificate = rewritten;
    material->certificate_size = contents->length;

    EVP_PKEY_free(private_key);
    X509_free(certificate);
    BIO_free(output);
    BIO_free(key_memory);
    BIO_free(certificate_memory);
}

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
                     -EACCES);

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
    char *certificate = NULL;
    char *private_key = NULL;
    size_t certificate_size = 0U;
    size_t private_key_size = 0U;

    (void)state;
    assert_int_equal(jg_certificate_create_csr("", NULL, 0U, &material),
                     -EINVAL);
    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 0U, &material),
                     -EINVAL);
    assert_int_equal(
        jg_certificate_inspect("invalid", strlen("invalid"), NULL, 0U, &info),
        -EINVAL);
    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 30U, &material),
                     0);
    certificate_size = material.certificate_size + strlen("trailing data");
    certificate = malloc(certificate_size);
    assert_non_null(certificate);
    (void)memcpy(certificate, material.certificate, material.certificate_size);
    (void)memcpy(certificate + material.certificate_size, "trailing data",
                 strlen("trailing data"));
    assert_int_equal(
        jg_certificate_inspect(certificate, certificate_size, NULL, 0U, &info),
        -EINVAL);
    private_key_size = material.private_key_size + strlen("trailing data");
    private_key = malloc(private_key_size);
    assert_non_null(private_key);
    (void)memcpy(private_key, material.private_key, material.private_key_size);
    (void)memcpy(private_key + material.private_key_size, "trailing data",
                 strlen("trailing data"));
    assert_int_equal(
        jg_certificate_inspect(material.certificate, material.certificate_size,
                               private_key, private_key_size, &info),
        -EINVAL);
    sodium_memzero(private_key, private_key_size);
    free(private_key);
    sodium_memzero(certificate, certificate_size);
    free(certificate);
    jg_certificate_material_clear(&material);
}

/** @brief Verify current validity and TLS-server purpose enforcement. */
static void test_server_certificate_validation(void **state)
{
    struct jg_certificate_material material;
    struct jg_certificate_info info;
    EVP_PKEY *authority_key = NULL;
    X509 *authority_certificate = NULL;
    char *authority = NULL;
    char *client_certificate = NULL;
    char *client_key = NULL;
    char *server_certificate = NULL;
    char *server_key = NULL;
    size_t authority_size = 0U;
    size_t client_certificate_size = 0U;
    size_t client_key_size = 0U;
    size_t server_certificate_size = 0U;
    size_t server_key_size = 0U;

    (void)state;
    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 30U, &material),
                     0);
    assert_int_equal(jg_certificate_server_validate(
                         material.certificate, material.certificate_size,
                         material.private_key, material.private_key_size,
                         &info),
                     0);
    jg_certificate_material_clear(&material);

    assert_int_equal(jg_certificate_create_self_signed("future.example", NULL,
                                                       0U, 30U, &material),
                     0);
    rewrite_test_validity(&material, 3600L, 86400L);
    assert_int_equal(jg_certificate_server_validate(
                         material.certificate, material.certificate_size,
                         material.private_key, material.private_key_size,
                         &info),
                     -EACCES);
    jg_certificate_material_clear(&material);

    assert_int_equal(jg_certificate_create_self_signed("expired.example", NULL,
                                                       0U, 30U, &material),
                     0);
    rewrite_test_validity(&material, -86400L, -3600L);
    assert_int_equal(jg_certificate_server_validate(
                         material.certificate, material.certificate_size,
                         material.private_key, material.private_key_size,
                         &info),
                     -EACCES);
    jg_certificate_material_clear(&material);

    create_test_authority(&authority, &authority_size, &authority_key,
                          &authority_certificate);
    create_test_leaf(authority_key, authority_certificate, "clientAuth",
                     &client_certificate, &client_certificate_size, &client_key,
                     &client_key_size);
    create_test_leaf(authority_key, authority_certificate, "serverAuth",
                     &server_certificate, &server_certificate_size, &server_key,
                     &server_key_size);
    assert_int_equal(jg_certificate_server_validate(
                         client_certificate, client_certificate_size,
                         client_key, client_key_size, &info),
                     -EACCES);
    assert_int_equal(jg_certificate_server_validate(
                         server_certificate, server_certificate_size,
                         server_key, server_key_size, &info),
                     0);
    assert_int_equal(jg_certificate_server_validate(server_certificate,
                                                    server_certificate_size,
                                                    NULL, 0U, &info),
                     -EINVAL);

    sodium_memzero(server_key, server_key_size);
    free(server_key);
    sodium_memzero(server_certificate, server_certificate_size);
    free(server_certificate);
    sodium_memzero(client_key, client_key_size);
    free(client_key);
    sodium_memzero(client_certificate, client_certificate_size);
    free(client_certificate);
    X509_free(authority_certificate);
    EVP_PKEY_free(authority_key);
    sodium_memzero(authority, authority_size);
    free(authority);
}

/** @brief Verify atomic private installation and secure file inspection. */
static void test_certificate_installation(void **state)
{
    static const char template[] = "/tmp/janusgate-certificate-XXXXXX";
    char directory[sizeof(template)];
    char path[256U];
    char copy[256U];
    char link[256U];
    char pending[256U];
    char *exported = NULL;
    size_t exported_size = 0U;
    char *loaded_key = NULL;
    size_t loaded_key_size = 0U;
    struct stat metadata;
    struct jg_certificate_material future;
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
    written = snprintf(copy, sizeof(copy), "%s/server-copy.pem", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(copy));
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
    assert_int_equal(jg_certificate_server_validate_file(path, &inspected), 0);
    assert_memory_equal(inspected.fingerprint_sha256,
                        installed.fingerprint_sha256,
                        sizeof(installed.fingerprint_sha256));
    assert_int_equal(jg_certificate_create_self_signed("future.example", NULL,
                                                       0U, 30U, &future),
                     0);
    rewrite_test_validity(&future, 3600L, 86400L);
    assert_int_equal(
        jg_certificate_install(path, future.certificate,
                               future.certificate_size, future.private_key,
                               future.private_key_size, &inspected),
        -EACCES);
    assert_int_equal(jg_certificate_server_validate_file(path, &inspected), 0);
    assert_memory_equal(inspected.fingerprint_sha256,
                        installed.fingerprint_sha256,
                        sizeof(installed.fingerprint_sha256));
    jg_certificate_material_clear(&future);
    assert_int_equal(jg_certificate_identity_copy(path, copy), 0);
    assert_int_equal(jg_certificate_inspect_file(copy, &inspected), 0);
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

    assert_int_equal(chmod(path, 0640), 0);
    assert_int_equal(jg_certificate_inspect_file(path, &inspected), 0);
    assert_int_equal(
        jg_certificate_install(path, material.certificate,
                               material.certificate_size, material.private_key,
                               material.private_key_size, &installed),
        0);
    assert_int_equal(stat(path, &metadata), 0);
    assert_int_equal(metadata.st_mode & 0777U, S_IRUSR | S_IWUSR | S_IRGRP);

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
    assert_int_equal(unlink(copy), 0);
    assert_int_equal(unlink(path), 0);
    assert_int_equal(rmdir(directory), 0);
    jg_certificate_material_clear(&material);
}

/** @brief Verify private CA-bundle validation, installation, and removal. */
static void test_client_trust_store(void **state)
{
    static const char template[] = "/tmp/janusgate-client-ca-XXXXXX";
    char directory[sizeof(template)];
    char path[256U];
    char copy[256U];
    char *authority = NULL;
    char *duplicate = NULL;
    char *exported = NULL;
    char *client = NULL;
    char *client_chain = NULL;
    char *server_client = NULL;
    char *trailing = NULL;
    size_t authority_size = 0U;
    size_t client_size = 0U;
    size_t exported_size = 0U;
    size_t server_client_size = 0U;
    size_t authority_count = 0U;
    EVP_PKEY *authority_key = NULL;
    X509 *authority_certificate = NULL;
    struct stat metadata;
    struct jg_certificate_info authorities[2U];
    struct jg_certificate_material server;
    int written = 0;

    (void)state;
    (void)memcpy(directory, template, sizeof(template));
    assert_non_null(mkdtemp(directory));
    written = snprintf(path, sizeof(path), "%s/client-ca.pem", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(path));
    written = snprintf(copy, sizeof(copy), "%s/client-ca-copy.pem", directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(copy));
    create_test_authority(&authority, &authority_size, &authority_key,
                          &authority_certificate);
    assert_int_equal(
        jg_certificate_trust_store_inspect(authority, authority_size,
                                           authorities, 2U, &authority_count),
        0);
    assert_int_equal(authority_count, 1U);
    assert_string_equal(authorities[0U].subject, "CN=JanusGate home lab CA");
    assert_true(authorities[0U].self_signed);

    duplicate = malloc(authority_size * 2U);
    assert_non_null(duplicate);
    (void)memcpy(duplicate, authority, authority_size);
    (void)memcpy(duplicate + authority_size, authority, authority_size);
    assert_int_equal(
        jg_certificate_trust_store_inspect(duplicate, authority_size * 2U,
                                           authorities, 2U, &authority_count),
        -EINVAL);
    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 30U, &server),
                     0);
    assert_int_equal(jg_certificate_trust_store_inspect(
                         server.certificate, server.certificate_size,
                         authorities, 2U, &authority_count),
                     -EINVAL);

    trailing = malloc(authority_size + sizeof("trailing data"));
    assert_non_null(trailing);
    (void)memcpy(trailing, authority, authority_size);
    (void)memcpy(trailing + authority_size, "trailing data",
                 sizeof("trailing data"));
    assert_int_equal(jg_certificate_trust_store_inspect(
                         trailing, authority_size + strlen("trailing data"),
                         authorities, 2U, &authority_count),
                     -EINVAL);

    assert_int_equal(
        jg_certificate_trust_store_install(path, authority, authority_size,
                                           authorities, 2U, &authority_count),
        0);
    assert_int_equal(stat(path, &metadata), 0);
    assert_int_equal(metadata.st_mode & 0777U, S_IRUSR | S_IWUSR | S_IRGRP);
    assert_int_equal(jg_certificate_trust_store_inspect_file(
                         path, authorities, 2U, &authority_count),
                     0);
    assert_int_equal(authority_count, 1U);
    assert_int_equal(
        jg_certificate_trust_store_export_file(path, &exported, &exported_size),
        0);
    assert_int_equal(exported_size, authority_size);
    assert_memory_equal(exported, authority, authority_size);
    jg_certificate_pem_clear(exported, exported_size);
    exported = NULL;
    exported_size = 0U;
    assert_int_equal(jg_certificate_trust_store_copy(path, copy), 0);
    assert_int_equal(jg_certificate_trust_store_inspect_file(
                         copy, authorities, 2U, &authority_count),
                     0);
    create_test_leaf(authority_key, authority_certificate, "clientAuth",
                     &client, &client_size, NULL, NULL);
    create_test_leaf(authority_key, authority_certificate, "serverAuth",
                     &server_client, &server_client_size, NULL, NULL);
    assert_int_equal(jg_certificate_client_validate(client, client_size, path,
                                                    &authorities[0U]),
                     0);
    assert_string_equal(authorities[0U].subject, "CN=JanusGate test client");
    client_chain = malloc(client_size + authority_size);
    assert_non_null(client_chain);
    (void)memcpy(client_chain, client, client_size);
    (void)memcpy(client_chain + client_size, authority, authority_size);
    assert_int_equal(
        jg_certificate_client_validate(
            client_chain, client_size + authority_size, path, &authorities[0U]),
        0);
    assert_int_equal(jg_certificate_client_validate(server_client,
                                                    server_client_size, path,
                                                    &authorities[0U]),
                     -EACCES);
    assert_int_equal(jg_certificate_client_validate(authority, authority_size,
                                                    path, &authorities[0U]),
                     -EACCES);
    assert_int_equal(jg_certificate_client_validate(server.certificate,
                                                    server.certificate_size,
                                                    path, &authorities[0U]),
                     -EACCES);
    assert_int_equal(jg_certificate_trust_store_remove(path), 0);
    assert_int_equal(jg_certificate_trust_store_remove(copy), 0);
    assert_int_equal(jg_certificate_client_validate(client, client_size, path,
                                                    &authorities[0U]),
                     -ENOENT);
    assert_int_equal(jg_certificate_trust_store_remove(path), 0);

    X509_free(authority_certificate);
    EVP_PKEY_free(authority_key);
    jg_certificate_material_clear(&server);
    sodium_memzero(trailing, authority_size + sizeof("trailing data"));
    free(trailing);
    sodium_memzero(server_client, server_client_size);
    free(server_client);
    sodium_memzero(client_chain, client_size + authority_size);
    free(client_chain);
    sodium_memzero(client, client_size);
    free(client);
    sodium_memzero(duplicate, authority_size * 2U);
    free(duplicate);
    sodium_memzero(authority, authority_size);
    free(authority);
    assert_int_equal(rmdir(directory), 0);
}

/** @brief Run the certificate-management unit-test group. */
int jg_test_certificate(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_self_signed_certificate),
        cmocka_unit_test(test_certificate_request),
        cmocka_unit_test(test_certificate_validation),
        cmocka_unit_test(test_server_certificate_validation),
        cmocka_unit_test(test_certificate_installation),
        cmocka_unit_test(test_client_trust_store),
    };

    return cmocka_run_group_tests_name("certificate", tests, NULL, NULL);
}
