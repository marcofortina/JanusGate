/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <jansson.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sodium.h>
#include <sqlite3.h>

#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/backup.h"
#include "janusgate/certificate.h"
#include "janusgate/event.h"
#include "janusgate/ipc.h"
#include "janusgate/logging.h"
#include "management.h"
#include "management_internal.h"

int jg_test_management(void);

/** Stable certificate fingerprint injected into remote-API test envelopes. */
static const char management_client_fingerprint[] =
    "1111111111111111111111111111111111111111111111111111111111111111";

/** Complete private filesystem and database fixture for management tests. */
struct management_fixture {
    char directory[64U];
    char database_path[128U];
    char key_path[128U];
    char certificate_path[128U];
    char client_ca_path[128U];
    struct jg_database *database;
    struct jg_management *management;
};

/** Result storage for one restore gate acquisition thread. */
struct restore_gate_thread {
    struct jg_management *management;
    int result;
};

/** @brief Wait for exclusive restore ownership in a helper thread. */
static void *enter_restore_gate(void *context)
{
    struct restore_gate_thread *thread = context;

    thread->result = management_restore_begin(thread->management);
    return NULL;
}

/** @brief Verify restores drain mutations and reject new ones
 * deterministically.
 */
static void test_management_consistency(void **state)
{
    struct jg_management management = {0};
    struct restore_gate_thread context = {.management = &management};
    pthread_t thread;
    size_t attempts = 0U;

    (void)state;
    assert_int_equal(management_consistency_create(&management.consistency), 0);
    assert_int_equal(management_mutation_begin(&management), 0);
    assert_int_equal(
        pthread_create(&thread, NULL, enter_restore_gate, &context), 0);
    while (!management_restore_in_progress(&management) && attempts < 100000U) {
        ++attempts;
        (void)sched_yield();
    }
    assert_true(management_restore_in_progress(&management));
    assert_int_equal(management_mutation_begin(&management), -EBUSY);
    management_mutation_end(&management);
    assert_int_equal(pthread_join(thread, NULL), 0);
    assert_int_equal(context.result, 0);
    management_restore_end(&management);
    assert_false(management_restore_in_progress(&management));
    assert_int_equal(management_mutation_begin(&management), 0);
    management_mutation_end(&management);
    management_consistency_destroy(management.consistency);
}

/** @brief Write one exact buffer to a newly created private file. */
static void write_private_file(const char *path,
                               const uint8_t *data,
                               size_t data_size)
{
    size_t offset = 0U;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    assert_true(descriptor >= 0);
    while (offset < data_size) {
        const ssize_t count =
            write(descriptor, data + offset, data_size - offset);

        assert_true(count > 0);
        offset += (size_t)count;
    }
    assert_int_equal(close(descriptor), 0);
}

/** @brief Create one private CA and a signed TLS client for management tests.
 */
static void create_management_test_identity(char **pem,
                                            size_t *pem_size,
                                            char **client_pem,
                                            size_t *client_pem_size)
{
    char constraints_text[] = "critical,CA:TRUE,pathlen:1";
    char usage_text[] = "critical,keyCertSign,cRLSign";
    char client_constraints_text[] = "critical,CA:FALSE";
    char client_usage_text[] = "critical,digitalSignature";
    char client_extended_usage_text[] = "clientAuth";
    EVP_PKEY_CTX *key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_CTX *client_key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *client_private_key = NULL;
    X509 *certificate = X509_new();
    X509 *client_certificate = X509_new();
    X509_NAME *subject = X509_NAME_new();
    X509_NAME *client_subject = X509_NAME_new();
    X509_EXTENSION *constraints = NULL;
    X509_EXTENSION *usage = NULL;
    X509_EXTENSION *client_constraints = NULL;
    X509_EXTENSION *client_usage = NULL;
    X509_EXTENSION *client_extended_usage = NULL;
    BIO *memory = BIO_new(BIO_s_mem());
    BUF_MEM *contents = NULL;

    *pem = NULL;
    *pem_size = 0U;
    *client_pem = NULL;
    *client_pem_size = 0U;
    assert_non_null(key_context);
    assert_non_null(client_key_context);
    assert_non_null(certificate);
    assert_non_null(client_certificate);
    assert_non_null(subject);
    assert_non_null(client_subject);
    assert_non_null(memory);
    assert_int_equal(EVP_PKEY_keygen_init(key_context), 1);
    assert_int_equal(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context, 2048), 1);
    assert_int_equal(EVP_PKEY_keygen(key_context, &private_key), 1);
    assert_non_null(private_key);
    assert_int_equal(X509_NAME_add_entry_by_txt(
                         subject, "CN", MBSTRING_ASC,
                         (const unsigned char *)"JanusGate private CA", -1, -1,
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

    assert_int_equal(EVP_PKEY_keygen_init(client_key_context), 1);
    assert_int_equal(EVP_PKEY_CTX_set_rsa_keygen_bits(client_key_context, 2048),
                     1);
    assert_int_equal(EVP_PKEY_keygen(client_key_context, &client_private_key),
                     1);
    assert_non_null(client_private_key);
    assert_int_equal(X509_NAME_add_entry_by_txt(
                         client_subject, "CN", MBSTRING_ASC,
                         (const unsigned char *)"JanusGate remote client", -1,
                         -1, 0),
                     1);
    assert_int_equal(X509_set_version(client_certificate, 2L), 1);
    assert_int_equal(
        ASN1_INTEGER_set(X509_get_serialNumber(client_certificate), 2L), 1);
    assert_int_equal(X509_set_subject_name(client_certificate, client_subject),
                     1);
    assert_int_equal(X509_set_issuer_name(client_certificate, subject), 1);
    assert_int_equal(X509_set_pubkey(client_certificate, client_private_key),
                     1);
    assert_non_null(
        X509_gmtime_adj(X509_getm_notBefore(client_certificate), -60L));
    assert_non_null(
        X509_gmtime_adj(X509_getm_notAfter(client_certificate), 86400L));
    client_constraints = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                             client_constraints_text);
    client_usage =
        X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, client_usage_text);
    client_extended_usage = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage,
                                                client_extended_usage_text);
    assert_non_null(client_constraints);
    assert_non_null(client_usage);
    assert_non_null(client_extended_usage);
    assert_int_equal(X509_add_ext(client_certificate, client_constraints, -1),
                     1);
    assert_int_equal(X509_add_ext(client_certificate, client_usage, -1), 1);
    assert_int_equal(
        X509_add_ext(client_certificate, client_extended_usage, -1), 1);
    assert_true(X509_sign(client_certificate, private_key, EVP_sha256()) > 0);
    assert_int_equal(BIO_reset(memory), 1);
    assert_int_equal(PEM_write_bio_X509(memory, client_certificate), 1);
    BIO_get_mem_ptr(memory, &contents);
    assert_non_null(contents);
    assert_true(contents->length > 0U);
    *client_pem = malloc(contents->length + 1U);
    assert_non_null(*client_pem);
    (void)memcpy(*client_pem, contents->data, contents->length);
    (*client_pem)[contents->length] = '\0';
    *client_pem_size = contents->length;

    X509_EXTENSION_free(client_extended_usage);
    X509_EXTENSION_free(client_usage);
    X509_EXTENSION_free(client_constraints);
    X509_EXTENSION_free(usage);
    X509_EXTENSION_free(constraints);
    BIO_free(memory);
    X509_NAME_free(client_subject);
    X509_NAME_free(subject);
    X509_free(client_certificate);
    X509_free(certificate);
    EVP_PKEY_free(client_private_key);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(client_key_context);
    EVP_PKEY_CTX_free(key_context);
}

/** @brief Create private storage and management state around a fresh schema. */
static int setup_management(void **state)
{
    static const char template[] = "/tmp/janusgate-management-XXXXXX";
    uint8_t key[JG_AUTH_TOTP_KEY_SIZE];
    struct jg_account_mtls_mapping_config mapping_config = {
        .subject = "CN=management-test-client",
        .issuer = "CN=management-test-ca",
        .role = JG_ACCESS_ROLE_ADMINISTRATOR,
    };
    struct jg_account_mtls_mapping mapping;
    struct management_fixture *fixture = calloc(1U, sizeof(*fixture));
    const time_t now = time(NULL);
    int written = 0;

    assert_non_null(fixture);
    assert_true(now > 1);
    (void)snprintf(fixture->directory, sizeof(fixture->directory), "%s",
                   template);
    assert_non_null(mkdtemp(fixture->directory));
    written = snprintf(fixture->database_path, sizeof(fixture->database_path),
                       "%s/janusgate.db", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->database_path));
    written = snprintf(fixture->key_path, sizeof(fixture->key_path),
                       "%s/totp.key", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->key_path));
    written =
        snprintf(fixture->certificate_path, sizeof(fixture->certificate_path),
                 "%s/server.pem", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->certificate_path));
    written = snprintf(fixture->client_ca_path, sizeof(fixture->client_ca_path),
                       "%s/client-ca.pem", fixture->directory);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(fixture->client_ca_path));
    for (size_t index = 0U; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(index + 1U);
    }
    write_private_file(fixture->key_path, key, sizeof(key));
    assert_int_equal(
        jg_database_open(fixture->database_path, 1000U, &fixture->database), 0);
    (void)memset(mapping_config.fingerprint_sha256, 0x11,
                 sizeof(mapping_config.fingerprint_sha256));
    mapping_config.not_before = (uint64_t)now - 1U;
    mapping_config.not_after = (uint64_t)now + 86400U;
    assert_int_equal(jg_account_mtls_mapping_create(fixture->database,
                                                    &mapping_config,
                                                    (uint64_t)now, &mapping),
                     0);
    assert_int_equal(
        jg_management_create(fixture->database, fixture->key_path,
                             fixture->certificate_path, fixture->client_ca_path,
                             fixture->directory, NULL, &fixture->management),
        0);
    *state = fixture;
    return 0;
}

/** @brief Add one initial server identity to a fresh management fixture. */
static int setup_certificate_management(void **state)
{
    struct management_fixture *fixture = NULL;
    struct jg_certificate_material material;
    struct jg_certificate_info info;
    int result = setup_management(state);

    assert_int_equal(result, 0);
    fixture = *state;
    assert_int_equal(jg_certificate_create_self_signed("janusgate.local", NULL,
                                                       0U, 365U, &material),
                     0);
    assert_int_equal(
        jg_certificate_install(fixture->certificate_path, material.certificate,
                               material.certificate_size, material.private_key,
                               material.private_key_size, &info),
        0);
    jg_certificate_material_clear(&material);
    return 0;
}

/** @brief Remove SQLite side files and every private fixture resource. */
static int teardown_management(void **state)
{
    struct management_fixture *fixture = *state;
    char auxiliary[160U];
    int written = 0;

    jg_management_destroy(fixture->management);
    jg_database_close(fixture->database);
    written = snprintf(auxiliary, sizeof(auxiliary), "%s-wal",
                       fixture->database_path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    written = snprintf(auxiliary, sizeof(auxiliary), "%s-shm",
                       fixture->database_path);
    if (written > 0 && (size_t)written < sizeof(auxiliary)) {
        (void)unlink(auxiliary);
    }
    (void)unlink(fixture->database_path);
    (void)unlink(fixture->key_path);
    (void)unlink(fixture->certificate_path);
    (void)unlink(fixture->client_ca_path);
    (void)rmdir(fixture->directory);
    free(fixture);
    return 0;
}

/** @brief Process one textual envelope and parse its exact JSON response. */
static json_t *process_request(struct management_fixture *fixture,
                               const char *request)
{
    uint8_t response[JG_IPC_MAX_BODY_SIZE];
    json_error_t error;
    json_t *envelope = NULL;
    json_t *parsed = NULL;
    char *encoded = NULL;
    size_t response_size = 0U;

    envelope = json_loads(request, JSON_REJECT_DUPLICATES, &error);
    if (json_is_object(envelope) &&
        json_object_get(envelope, "bearer") != NULL &&
        json_object_get(envelope, "client_certificate") == NULL) {
        assert_int_equal(
            json_object_set_new(envelope, "client_certificate",
                                json_string(management_client_fingerprint)),
            0);
    }
    encoded = envelope == NULL
                  ? strdup(request)
                  : json_dumps(envelope, JSON_COMPACT | JSON_SORT_KEYS);
    assert_non_null(encoded);
    assert_int_equal(jg_management_process(fixture->management,
                                           (const uint8_t *)encoded,
                                           strlen(encoded), false, response,
                                           sizeof(response), &response_size),
                     0);
    free(encoded);
    json_decref(envelope);
    parsed = json_loadb((const char *)response, response_size,
                        JSON_REJECT_DUPLICATES, &error);
    assert_non_null(parsed);
    assert_true(json_is_object(parsed));
    return parsed;
}

/** @brief Process one envelope as the trusted local Unix-socket actor. */
static json_t *process_local_request(struct management_fixture *fixture,
                                     const char *request)
{
    uint8_t response[JG_IPC_MAX_BODY_SIZE];
    json_error_t error;
    json_t *parsed = NULL;
    size_t response_size = 0U;

    assert_int_equal(jg_management_process(fixture->management,
                                           (const uint8_t *)request,
                                           strlen(request), true, response,
                                           sizeof(response), &response_size),
                     0);
    parsed = json_loadb((const char *)response, response_size,
                        JSON_REJECT_DUPLICATES, &error);
    assert_non_null(parsed);
    assert_true(json_is_object(parsed));
    return parsed;
}

/** @brief Verify reads continue while an applied restore rejects mutations. */
static void test_restore_request_exclusion(void **state)
{
    static const char read_request[] =
        "{\"request_id\":\"restore-read\",\"method\":\"GET\","
        "\"path\":\"/api/v1/auth/state\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    static const char mutation_request[] =
        "{\"request_id\":\"restore-mutation\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    struct management_fixture *fixture = *state;
    json_t *response = NULL;

    assert_int_equal(management_restore_begin(fixture->management), 0);
    response = process_local_request(fixture, read_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    json_decref(response);
    response = process_local_request(fixture, mutation_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "restore_in_progress");
    json_decref(response);
    management_restore_end(fixture->management);
    response = process_local_request(fixture, mutation_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);
    assert_int_equal(management_restore_begin(fixture->management), 0);
    management_restore_end(fixture->management);
}

/** @brief Simulate successful runtime publication in a runtime-free fixture. */
static void synchronize_policy(struct management_fixture *fixture)
{
    struct jg_database_policy_sync sync;
    const time_t now = time(NULL);

    assert_true(now > 0);
    assert_int_equal(jg_database_policy_sync_load(fixture->database, &sync), 0);
    assert_int_equal(jg_database_policy_sync_record(fixture->database,
                                                    sync.desired_revision, true,
                                                    NULL, (uint64_t)now, &sync),
                     0);
    jg_management_refresh_policy_health(fixture->management);
}

/** @brief Wait for one accepted API job and return its final envelope. */
static json_t *wait_for_job(struct management_fixture *fixture,
                            uint64_t job_id,
                            const char *bearer)
{
    const struct timespec interval = {
        .tv_nsec = 10000000L,
    };
    char request[1024U];

    for (size_t attempt = 0U; attempt < 500U; ++attempt) {
        json_t *response = NULL;
        json_t *job = NULL;
        json_t *completed = NULL;
        int written =
            snprintf(request, sizeof(request),
                     "{\"request_id\":\"job-poll-%zu\",\"method\":\"GET\","
                     "\"path\":\"/api/v1/jobs/%llu\",\"host\":\"192.168.77.1\","
                     "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                     "\"body\":{}}",
                     attempt, (unsigned long long)job_id, bearer);

        assert_true(written > 0);
        assert_true((size_t)written < sizeof(request));
        response = process_request(fixture, request);
        assert_int_equal(
            json_integer_value(json_object_get(response, "status")), 200);
        job = json_object_get(json_object_get(response, "body"), "job");
        assert_true(json_is_object(job));
        if (strcmp(json_string_value(json_object_get(job, "state")),
                   "completed") == 0) {
            completed = json_object_get(job, "response");
            assert_true(json_is_object(completed));
            json_incref(completed);
            json_decref(response);
            return completed;
        }
        json_decref(response);
        assert_int_equal(nanosleep(&interval, NULL), 0);
    }
    fail_msg("management job did not complete within five seconds");
    return NULL;
}

/** @brief Consume one accepted response and wait for its final envelope. */
static json_t *complete_accepted_job(struct management_fixture *fixture,
                                     json_t *accepted,
                                     const char *bearer)
{
    json_t *job = NULL;
    json_t *completed = NULL;
    uint64_t job_id = 0U;

    assert_int_equal(json_integer_value(json_object_get(accepted, "status")),
                     202);
    job = json_object_get(json_object_get(accepted, "body"), "job");
    assert_true(json_is_object(job));
    assert_string_equal(json_string_value(json_object_get(job, "state")),
                        "queued");
    job_id = (uint64_t)json_integer_value(json_object_get(job, "id"));
    assert_true(job_id > 0U);
    completed = wait_for_job(fixture, job_id, bearer);
    json_decref(accepted);
    return completed;
}

/** @brief Wait until the scheduled worker records one source attempt. */
static void wait_for_source_attempt(struct management_fixture *fixture,
                                    uint64_t source_id,
                                    uint64_t attempted_at,
                                    struct jg_database_blocklist_source *source)
{
    const struct timespec interval = {
        .tv_nsec = 10000000L,
    };

    for (size_t attempt = 0U; attempt < 500U; ++attempt) {
        size_t count = 0U;
        bool has_more = false;

        assert_int_equal(jg_database_list_blocklist_sources(
                             fixture->database, source_id - 1U, 1U, source,
                             &count, &has_more),
                         0);
        assert_int_equal(count, 1U);
        assert_int_equal(source->id, source_id);
        if (source->last_attempt_at == attempted_at) {
            return;
        }
        assert_int_equal(nanosleep(&interval, NULL), 0);
    }
    fail_msg("scheduled source update did not complete within five seconds");
}

/** @brief Verify token-free local authorization and audit provenance. */
static void test_local_administration(void **state)
{
    static const char show_request[] =
        "{\"request_id\":\"local-show\",\"method\":\"GET\","
        "\"path\":\"/api/v1/logging\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    static const char update_request[] =
        "{\"request_id\":\"local-update\",\"method\":\"PUT\","
        "\"path\":\"/api/v1/logging\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{"
        "\"revision\":1,\"global_level\":\"debug\","
        "\"destinations\":[\"syslog\"],\"rate_limit_per_second\":100,"
        "\"trace_capacity\":4,\"diagnostic_duration_seconds\":120,"
        "\"include_identifiers\":false,\"overrides\":[]}}";
    struct management_fixture *fixture = *state;
    struct jg_audit_record audit;
    struct jg_logging_config logging;
    json_t *response = NULL;
    size_t count = 0U;
    uint64_t total = 0U;

    jg_logging_config_default(&logging);
    logging.destinations = JG_LOG_DESTINATION_SYSLOG;
    assert_int_equal(jg_logging_initialize("local-management-test", &logging),
                     0);
    response = process_local_request(fixture, show_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    json_decref(response);
    response = process_local_request(fixture, update_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    json_decref(response);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, &audit, 1U,
                                            &count, &total),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(audit.actor_type, JG_AUDIT_ACTOR_LOCAL);
    assert_false(audit.has_actor_id);
    assert_string_equal(audit.action, "logging.update");
    jg_logging_shutdown();
}

/** @brief Verify an audit write failure rolls back its user mutation. */
static void test_atomic_user_audit(void **state)
{
    static const char create_request[] =
        "{\"request_id\":\"atomic-user\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{"
        "\"username\":\"rollback-test\","
        "\"password\":\"correct horse battery staple\","
        "\"role\":\"auditor\",\"force_password_change\":false}}";
    static const char reject_audit[] =
        "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events "
        "BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;";
    struct management_fixture *fixture = *state;
    struct jg_account_user user;
    sqlite3 *injection = NULL;
    json_t *response = NULL;
    json_t *error = NULL;
    size_t count = 0U;
    uint64_t total = 0U;

    assert_int_equal(sqlite3_open_v2(fixture->database_path, &injection,
                                     SQLITE_OPEN_READWRITE, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_exec(injection, reject_audit, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(injection), SQLITE_OK);

    response = process_local_request(fixture, create_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     500);
    error = json_object_get(json_object_get(response, "body"), "error");
    assert_string_equal(json_string_value(json_object_get(error, "code")),
                        "audit_failure");
    assert_string_equal(
        json_string_value(json_object_get(error, "message")),
        "The user creation and its audit record were not committed.");
    json_decref(response);

    assert_int_equal(
        jg_account_user_list(fixture->database, 0U, &user, 1U, &count, &total),
        0);
    assert_int_equal(count, 0U);
    assert_int_equal(total, 0U);
}

/** @brief Verify remote tokens require one current mapped mTLS identity. */
static void test_remote_api_authentication(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    const struct jg_account_token_config token_config = {
        .name = "remote API authentication",
        .permissions = JG_ACCESS_STATUS_READ,
        .requests_per_minute = 20U,
    };
    struct management_fixture *fixture = *state;
    struct jg_account_mtls_mapping mapping;
    struct jg_account_api_token token;
    struct jg_auth_password_policy password_policy;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[1024U];
    json_t *response = NULL;
    const time_t now = time(NULL);
    uint64_t total = 0U;
    uint64_t user_id = 0U;
    size_t count = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator", password,
                         sizeof(password) - 1U, &password_policy, (uint64_t)now,
                         &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"remote-mapped\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{}}",
                       token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"remote-no-cert\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"client_certificate\":\"\",\"body\":{}}",
                       token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"remote-unmapped\",\"method\":\"GET\","
        "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"client_certificate\":"
        "\"2222222222222222222222222222222222222222222222222222222222222222\","
        "\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"remote-auth-hidden\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/state\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     404);
    json_decref(response);

    assert_int_equal(jg_account_mtls_mapping_list(fixture->database, 0U,
                                                  &mapping, 1U, &count, &total),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(jg_account_mtls_mapping_revoke(fixture->database,
                                                    mapping.mapping_id,
                                                    (uint64_t)now + 1U),
                     0);
    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"remote-revoked\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{}}",
                       token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);
    sodium_memzero(&token, sizeof(token));
    sodium_memzero(bootstrap, sizeof(bootstrap));
}

/** @brief Verify bootstrap, login session validation, CSRF, and logout. */
static void test_browser_authentication(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    char token[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_account_token_config token_config = {
        .name = "status test",
        .permissions = JG_ACCESS_STATUS_READ,
        .requests_per_minute = 1U,
    };
    const struct jg_account_token_config health_token_config = {
        .name = "health test",
        .permissions = JG_ACCESS_STATUS_READ,
        .requests_per_minute = 10U,
    };
    struct jg_account_api_token api_token;
    struct jg_account_api_token health_token;
    struct jg_policy_rule_input domain_rules[2U];
    struct jg_policy_destination_rule_input destination_rules[2U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    int written = 0;

    assert_true(now > 0);
    response = process_request(
        fixture, "{\"request_id\":\"auth-state-new\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/state\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"body\":{}}");
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "setup_required")));
    json_decref(response);

    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, token),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"bootstrap-1\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        token, password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    assert_int_equal(json_string_length(value), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    (void)snprintf(session, sizeof(session), "%s", json_string_value(value));
    body = json_object_get(response, "body");
    user_id = (uint64_t)json_integer_value(
        json_object_get(json_object_get(body, "user"), "id"));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    response = process_request(
        fixture, "{\"request_id\":\"auth-state-ready\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/state\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"body\":{}}");
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "setup_required")));
    json_decref(response);

    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &api_token),
                     0);
    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"status-token-1\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{}}",
                       api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     429);
    json_decref(response);

    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &health_token_config, (uint64_t)now,
                                            &health_token),
                     0);
    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"health-token\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/health\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{}}",
                       health_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "healthy")));
    assert_false(json_is_true(
        json_object_get(json_object_get(body, "management"), "degraded")));
    assert_true(json_is_true(json_object_get(
        json_object_get(body, "management"), "mutations_allowed")));
    assert_false(json_is_true(
        json_object_get(json_object_get(body, "daemon"), "available")));
    assert_false(json_is_true(
        json_object_get(json_object_get(body, "network"), "available")));
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"status-invalid\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"query\":\"extra=true\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{}}",
                       health_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"session-1\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    value = json_object_get(json_object_get(body, "user"), "username");
    assert_string_equal(json_string_value(value), "administrator");
    value = json_object_get(json_object_get(body, "user"), "role");
    assert_string_equal(json_string_value(value), "administrator");
    json_decref(response);

    (void)memset(domain_rules, 0, sizeof(domain_rules));
    domain_rules[0U].id = 2U;
    domain_rules[0U].domain = "Blocked.Example.";
    domain_rules[0U].include_subdomains = true;
    domain_rules[0U].effect = JG_POLICY_BLOCK;
    domain_rules[0U].enforcement = JG_POLICY_OBSERVE;
    domain_rules[0U].source = JG_POLICY_SOURCE_EXPLICIT;
    domain_rules[0U].scope.type = JG_POLICY_SCOPE_GLOBAL;
    domain_rules[0U].attribution = "management test";
    domain_rules[1U].id = 1U;
    domain_rules[1U].domain = "safe.example";
    domain_rules[1U].effect = JG_POLICY_ALLOW;
    domain_rules[1U].source = JG_POLICY_SOURCE_EXPLICIT;
    domain_rules[1U].scope.type = JG_POLICY_SCOPE_VLAN;
    domain_rules[1U].scope.value.vlan_id = 20U;
    domain_rules[1U].attribution = "local exception";
    assert_int_equal(jg_database_replace_domain_rules(
                         fixture->database, domain_rules,
                         sizeof(domain_rules) / sizeof(domain_rules[0U])),
                     0);
    (void)memset(destination_rules, 0, sizeof(destination_rules));
    destination_rules[0U].id = 5U;
    destination_rules[0U].effect = JG_POLICY_BLOCK;
    destination_rules[0U].enforcement = JG_POLICY_OBSERVE;
    destination_rules[0U].source = JG_POLICY_SOURCE_EXPLICIT;
    destination_rules[0U].transport = JG_POLICY_TRANSPORT_ANY;
    destination_rules[0U].has_port = true;
    destination_rules[0U].port = 853U;
    destination_rules[0U].scope.type = JG_POLICY_SCOPE_GLOBAL;
    destination_rules[0U].attribution = "encrypted DNS";
    destination_rules[1U].id = 3U;
    destination_rules[1U].effect = JG_POLICY_ALLOW;
    destination_rules[1U].source = JG_POLICY_SOURCE_EXPLICIT;
    destination_rules[1U].transport = JG_POLICY_TRANSPORT_TCP;
    destination_rules[1U].has_address = true;
    destination_rules[1U].address_family = JG_POLICY_ADDRESS_IPV4;
    destination_rules[1U].address[0U] = 203U;
    destination_rules[1U].address[1U] = 0U;
    destination_rules[1U].address[2U] = 113U;
    destination_rules[1U].address[3U] = 99U;
    destination_rules[1U].prefix_length = 24U;
    destination_rules[1U].scope.type = JG_POLICY_SCOPE_VLAN;
    destination_rules[1U].scope.value.vlan_id = 20U;
    destination_rules[1U].attribution = "resolver exception";
    assert_int_equal(
        jg_database_replace_destination_rules(
            fixture->database, destination_rules,
            sizeof(destination_rules) / sizeof(destination_rules[0U])),
        0);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"domains-1\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/domains\",\"query\":\"limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 1);
    assert_true(json_is_true(json_object_get(body, "has_more")));
    assert_int_equal(json_integer_value(json_object_get(body, "next_after_id")),
                     1);
    value = json_array_get(json_object_get(body, "domains"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "domain")),
                        "safe.example");
    assert_true(json_is_null(json_object_get(value, "group_id")));
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(value, "scope"), "type")),
                        "vlan");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"domains-2\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/domains\","
                 "\"query\":\"after_id=1&limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "has_more")));
    assert_true(json_is_null(json_object_get(body, "next_after_id")));
    value = json_array_get(json_object_get(body, "domains"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "domain")),
                        "blocked.example");
    assert_true(json_is_true(json_object_get(value, "include_subdomains")));
    assert_string_equal(
        json_string_value(json_object_get(value, "enforcement")), "observe");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"policy-mode\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/policies/mode\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_string_equal(json_string_value(json_object_get(body, "enforcement")),
                        "enforce");
    assert_int_equal(json_integer_value(json_object_get(body, "revision")), 1);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"policy-groups\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/policies/groups\",\"query\":\"limit=100\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 0);
    assert_true(json_is_array(json_object_get(body, "groups")));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"policy-scopes\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/policies/scopes\",\"query\":\"limit=100\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 0);
    assert_true(json_is_array(json_object_get(body, "scope_modes")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destinations-1\",\"method\":\"GET\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"query\":\"limit=1\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\",\"body\":{}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "has_more")));
    value = json_array_get(json_object_get(body, "destination_rules"), 0U);
    assert_int_equal(json_integer_value(json_object_get(value, "id")), 3);
    assert_string_equal(json_string_value(json_object_get(value, "address")),
                        "203.0.113.0");
    assert_int_equal(
        json_integer_value(json_object_get(value, "prefix_length")), 24);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destinations-2\",\"method\":\"GET\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"query\":\"after_id=3&limit=1\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\",\"body\":{}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "has_more")));
    value = json_array_get(json_object_get(body, "destination_rules"), 0U);
    assert_int_equal(json_integer_value(json_object_get(value, "id")), 5);
    assert_int_equal(json_integer_value(json_object_get(value, "port")), 853);
    assert_true(json_is_null(json_object_get(value, "address")));
    assert_string_equal(
        json_string_value(json_object_get(value, "enforcement")), "observe");
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"action\":\"block\","
        "\"transport\":\"any\",\"address\":null,\"prefix_length\":null,"
        "\"port\":853,\"scope\":{\"type\":\"global\"},"
        "\"attribution\":\"encrypted DNS\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/destinations\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"action\":\"block\","
        "\"transport\":\"tcp\",\"address\":null,\"prefix_length\":null,"
        "\"port\":null,\"scope\":{\"type\":\"global\"},"
        "\"attribution\":\"invalid\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/policies/destinations/3\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1,\"action\":\"allow\","
        "\"transport\":\"tcp\",\"address\":\"203.0.113.0\","
        "\"prefix_length\":24,\"port\":null,"
        "\"scope\":{\"type\":\"vlan\",\"vlan\":20},"
        "\"attribution\":\"resolver exception\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"destination-delete\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/policies/destinations/3\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/domains\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"domain\":\"new.example\","
        "\"include_subdomains\":true,\"action\":\"block\","
        "\"target\":\"dns\",\"scope\":{\"type\":\"global\"},"
        "\"attribution\":\"local policy\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/domains\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"domain\":\"new.example\","
        "\"include_subdomains\":true,\"action\":\"block\","
        "\"target\":\"dns\",\"scope\":{\"type\":\"mac\","
        "\"address\":\"invalid\"},\"attribution\":\"local policy\","
        "\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/domains/1\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1,"
        "\"domain\":\"safe.example\",\"include_subdomains\":false,"
        "\"action\":\"allow\",\"target\":\"dns\","
        "\"scope\":{\"type\":\"vlan\",\"vlan\":20},"
        "\"attribution\":\"local exception\",\"enabled\":true}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"domain-delete\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/domains/1\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":1}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"policy-simulate\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/simulate\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"body\":{\"domain\":\"Example.ORG.\",\"source_ip\":\"192.0.2.50\","
        "\"source_mac\":\"02:00:00:00:00:01\",\"vlan\":20,"
        "\"destination_ip\":\"203.0.113.53\","
        "\"destination_port\":53,\"transport\":\"udp\"}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"policy-simulate-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/policies/simulate\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"body\":{\"domain\":\"example.org\","
        "\"source_mac\":\"not-a-mac\"}}",
        session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"metrics-1\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/metrics\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"logout-1\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/logout\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{}}",
        session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    assert_true(json_is_true(json_object_get(response, "clear_session")));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"session-2\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);
}

/** @brief Verify browser login limits one source without global lockout. */
static void test_browser_login_rate_limit(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[1024U];
    json_t *response = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    for (size_t attempt = 0U; attempt < 11U; ++attempt) {
        written =
            snprintf(request, sizeof(request),
                     "{\"request_id\":\"login-rate-%zu\",\"method\":\"POST\","
                     "\"path\":\"/api/v1/auth/login\","
                     "\"host\":\"192.168.77.1\","
                     "\"origin\":\"https://192.168.77.1\","
                     "\"remote_address\":\"192.0.2.20\",\"body\":{"
                     "\"username\":\"administrator\",\"password\":\"%s\"}}",
                     attempt, password);
        assert_true(written > 0);
        assert_true((size_t)written < sizeof(request));
        response = process_request(fixture, request);
        assert_int_equal(
            json_integer_value(json_object_get(response, "status")),
            attempt < 10U ? 200 : 429);
        json_decref(response);
    }
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"login-other-source\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/auth/login\","
                 "\"host\":\"192.168.77.1\","
                 "\"origin\":\"https://192.168.77.1\","
                 "\"remote_address\":\"192.0.2.21\",\"body\":{"
                 "\"username\":\"administrator\",\"password\":\"%s\"}}",
                 password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    json_decref(response);
    sodium_memzero(bootstrap, sizeof(bootstrap));
}

/** @brief Verify forced password change and authenticated session rotation. */
static void test_password_change(void **state)
{
    static const char administrator_password[] = "correct horse battery staple";
    static const char initial_password[] = "initial operator password is long";
    static const char replacement_password[] =
        "replacement operator password is long";
    struct management_fixture *fixture = *state;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[4096U];
    char administrator_session[JG_AUTH_SECRET_TEXT_SIZE];
    char administrator_csrf[JG_AUTH_SECRET_TEXT_SIZE];
    char operator_session[JG_AUTH_SECRET_TEXT_SIZE];
    char operator_csrf[JG_AUTH_SECRET_TEXT_SIZE];
    char renewed_session[JG_AUTH_SECRET_TEXT_SIZE];
    char renewed_csrf[JG_AUTH_SECRET_TEXT_SIZE];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-bootstrap\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        bootstrap, administrator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(administrator_session, sizeof(administrator_session), "%s",
                   json_string_value(value));
    value = json_object_get(json_object_get(response, "body"), "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(administrator_csrf, sizeof(administrator_csrf), "%s",
                   json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-user-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"username\":\"operator\",\"password\":\"%s\","
        "\"role\":\"operator\",\"force_password_change\":true}}",
        administrator_session, administrator_csrf, initial_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-login\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/login\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.20\",\"body\":{"
        "\"username\":\"operator\",\"password\":\"%s\"}}",
        initial_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(operator_session, sizeof(operator_session), "%s",
                   json_string_value(value));
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(json_object_get(body, "user"),
                                             "force_password_change")));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(operator_csrf, sizeof(operator_csrf), "%s",
                   json_string_value(value));
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"password-status\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.20\",\"session\":\"%s\","
                       "\"body\":{}}",
                       operator_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     403);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-change\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/password\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.20\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"current_password\":\"%s\",\"new_password\":\"%s\"}}",
        operator_session, operator_csrf, initial_password,
        replacement_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(renewed_session, sizeof(renewed_session), "%s",
                   json_string_value(value));
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(json_object_get(body, "user"),
                                              "force_password_change")));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(renewed_csrf, sizeof(renewed_csrf), "%s",
                   json_string_value(value));
    assert_string_not_equal(renewed_session, operator_session);
    assert_string_not_equal(renewed_csrf, operator_csrf);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"password-old-session\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.20\","
                 "\"session\":\"%s\",\"body\":{}}",
                 operator_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"password-new-session\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/auth/session\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.20\","
                 "\"session\":\"%s\",\"body\":{}}",
                 renewed_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(json_object_get(body, "user"),
                                              "force_password_change")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"password-audit\",\"method\":\"GET\","
        "\"path\":\"/api/v1/audit\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\",\"body\":{}}",
        administrator_session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 2);
    value = json_array_get(json_object_get(body, "events"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "action")),
                        "user.password_change");
    json_decref(response);
}

/** @brief Verify authorized user CRUD, pagination, and audit chaining. */
static void test_user_api(void **state)
{
    static const char administrator_password[] = "correct horse battery staple";
    static const char operator_password[] =
        "operator password is suitably long";
    static const char replacement_password[] =
        "replacement password is suitably long";
    struct management_fixture *fixture = *state;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[4096U];
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    uint8_t key[JG_AUTH_TOTP_KEY_SIZE];
    uint8_t secret[JG_AUTH_TOTP_SECRET_SIZE];
    struct jg_account_totp_provisioning provisioning;
    struct jg_account_recovery_codes recovery;
    struct jg_audit_verification verification;
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    json_t *user = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t revision = 0U;
    uint32_t code = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"users-bootstrap\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        bootstrap, administrator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(session, sizeof(session), "%s", json_string_value(value));
    body = json_object_get(response, "body");
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"username\":\"operator\",\"password\":\"%s\","
        "\"role\":\"operator\",\"force_password_change\":false}}",
        session, csrf, operator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    user = json_object_get(json_object_get(response, "body"), "user");
    user_id = (uint64_t)json_integer_value(json_object_get(user, "id"));
    revision = (uint64_t)json_integer_value(json_object_get(user, "revision"));
    assert_true(user_id > 0U);
    assert_int_equal(revision, 1U);
    assert_string_equal(json_string_value(json_object_get(user, "role")),
                        "operator");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"users-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/users\",\"query\":\"offset=1&limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"session\":\"%s\",\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 2);
    assert_int_equal(json_array_size(json_object_get(body, "users")), 1U);
    user = json_array_get(json_object_get(body, "users"), 0U);
    assert_string_equal(json_string_value(json_object_get(user, "username")),
                        "operator");
    assert_true(json_is_null(json_object_get(body, "next_offset")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/users/%llu\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"revision\":%llu,\"role\":\"auditor\",\"enabled\":true,"
        "\"force_password_change\":true}}",
        (unsigned long long)user_id, session, csrf,
        (unsigned long long)revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    user = json_object_get(json_object_get(response, "body"), "user");
    revision = (uint64_t)json_integer_value(json_object_get(user, "revision"));
    assert_int_equal(revision, 2U);
    assert_true(json_is_true(json_object_get(user, "force_password_change")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-password\",\"method\":\"POST\","
        "\"path\":\"/api/v1/users/%llu/password\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"revision\":%llu,\"password\":\"%s\","
        "\"force_password_change\":false}}",
        (unsigned long long)user_id, session, csrf,
        (unsigned long long)revision, replacement_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    user = json_object_get(json_object_get(response, "body"), "user");
    revision = (uint64_t)json_integer_value(json_object_get(user, "revision"));
    assert_int_equal(revision, 3U);
    assert_false(json_is_true(json_object_get(user, "force_password_change")));
    json_decref(response);

    for (size_t index = 0U; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(index + 1U);
    }
    assert_int_equal(jg_account_totp_provision(fixture->database, user_id, key,
                                               (uint64_t)now, &provisioning),
                     0);
    assert_int_equal(jg_auth_totp_secret_decode(provisioning.secret, secret),
                     0);
    assert_int_equal(jg_auth_totp_generate(secret, (uint64_t)now, &code), 0);
    assert_int_equal(jg_account_totp_confirm(fixture->database, user_id, key,
                                             code, (uint64_t)now, &recovery),
                     0);
    ++revision;
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"user-totp-disable\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/users/%llu/totp\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{\"revision\":%llu}}",
        (unsigned long long)user_id, session, csrf,
        (unsigned long long)revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    user = json_object_get(json_object_get(response, "body"), "user");
    assert_false(json_is_true(json_object_get(user, "totp_enabled")));
    assert_int_equal(json_integer_value(json_object_get(user, "revision")),
                     (json_int_t)(revision + 1U));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"users-query-invalid\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/users\",\"query\":\"limit=0\","
                 "\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
                 "\"body\":{}}",
                 session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"audit-list\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/audit\",\"query\":\"limit=2\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
                       "\"body\":{}}",
                       session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 4);
    assert_int_equal(json_array_size(json_object_get(body, "events")), 2U);
    value = json_array_get(json_object_get(body, "events"), 0U);
    assert_string_equal(json_string_value(json_object_get(value, "action")),
                        "user.totp_disable");
    assert_int_equal(json_string_length(json_object_get(value, "event_hash")),
                     JG_AUDIT_HASH_SIZE * 2U);
    json_decref(response);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"audit-verify\",\"method\":\"GET\","
                       "\"path\":\"/api/v1/audit/verify\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
                       "\"body\":{}}",
                       session);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "valid")));
    assert_int_equal(
        json_integer_value(json_object_get(body, "records_inspected")), 4);
    assert_true(json_is_null(json_object_get(body, "first_invalid_id")));
    json_decref(response);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 4U);
}

/** @brief Verify one-time token issue, inventory, use, and revocation. */
static void test_token_api(void **state)
{
    static const char administrator_password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[4096U];
    char session[JG_AUTH_SECRET_TEXT_SIZE];
    char csrf[JG_AUTH_SECRET_TEXT_SIZE];
    char secret[JG_AUTH_SECRET_TEXT_SIZE];
    struct jg_audit_verification verification;
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    json_t *token = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t token_id = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"tokens-bootstrap\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/bootstrap\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{"
        "\"token\":\"%s\",\"username\":\"administrator\","
        "\"password\":\"%s\"}}",
        bootstrap, administrator_password);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    value = json_object_get(response, "set_session");
    assert_true(json_is_string(value));
    (void)snprintf(session, sizeof(session), "%s", json_string_value(value));
    body = json_object_get(response, "body");
    user_id = (uint64_t)json_integer_value(
        json_object_get(json_object_get(body, "user"), "id"));
    value = json_object_get(body, "csrf");
    assert_true(json_is_string(value));
    (void)snprintf(csrf, sizeof(csrf), "%s", json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"token-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/tokens\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{"
        "\"user_id\":%llu,\"name\":\"management automation\","
        "\"scopes\":\"status:read,access:write\",\"expires_at\":null,"
        "\"source_network\":\"192.0.2.0/24\","
        "\"requests_per_minute\":60}}",
        session, csrf, (unsigned long long)user_id);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    token = json_object_get(json_object_get(response, "body"), "token");
    token_id = (uint64_t)json_integer_value(json_object_get(token, "id"));
    value = json_object_get(token, "secret");
    assert_true(token_id > 0U);
    assert_true(json_is_string(value));
    assert_int_equal(json_string_length(value), JG_AUTH_SECRET_TEXT_SIZE - 1U);
    (void)snprintf(secret, sizeof(secret), "%s", json_string_value(value));
    assert_string_equal(
        json_string_value(json_object_get(token, "source_network")),
        "192.0.2.0/24");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"tokens-bearer-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/tokens\",\"query\":\"limit=10\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 1);
    token = json_array_get(json_object_get(body, "tokens"), 0U);
    assert_null(json_object_get(token, "secret"));
    assert_false(json_is_true(json_object_get(token, "revoked")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"token-revoke\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/tokens/%llu\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"session\":\"%s\","
        "\"csrf\":\"%s\",\"body\":{}}",
        (unsigned long long)token_id, session, csrf);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    token = json_object_get(json_object_get(response, "body"), "token");
    assert_true(json_is_true(json_object_get(token, "revoked")));
    assert_int_equal(json_integer_value(json_object_get(token, "revision")), 2);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"tokens-revoked-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/tokens\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     401);
    json_decref(response);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 2U);
}

/** @brief Verify certificate inspection, CSR retention, and installation. */
static void test_certificate_api(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    struct jg_account_token_config token_config = {
        .name = "certificate administrator",
        .permissions = JG_ACCESS_SECURITY_WRITE,
        .requests_per_minute = JG_ACCOUNT_TOKEN_RATE_MAX,
    };
    struct jg_account_api_token token;
    struct jg_certificate_material material;
    struct jg_certificate_info installed;
    struct jg_audit_verification verification;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[16384U];
    char pending_path[256U];
    char fingerprint[65U];
    char *encoded_certificate = NULL;
    char *encoded_key = NULL;
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    json_t *text = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    int written = 0;

    assert_true(now > 0);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator", password,
                         sizeof(password) - 1U, &password_policy, (uint64_t)now,
                         &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"certificate-show\",\"method\":\"GET\","
        "\"path\":\"/api/v1/certificates\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    value = json_object_get(json_object_get(body, "certificate"),
                            "fingerprint_sha256");
    assert_true(json_is_string(value));
    assert_int_equal(json_string_length(value), 64U);
    (void)snprintf(fingerprint, sizeof(fingerprint), "%s",
                   json_string_value(value));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"certificate-csr\",\"method\":\"POST\","
        "\"path\":\"/api/v1/certificates/csr\","
        "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
        "\"bearer\":\"%s\",\"body\":{\"common_name\":\"gateway.example\","
        "\"alternative_names\":[\"gateway.example\",\"192.168.77.1\"]}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    body = json_object_get(response, "body");
    value = json_object_get(body, "request");
    assert_true(json_is_string(value));
    assert_non_null(
        strstr(json_string_value(value), "BEGIN CERTIFICATE REQUEST"));
    assert_null(strstr(json_string_value(value), "PRIVATE KEY"));
    assert_true(json_is_true(json_object_get(body, "private_key_stored")));
    json_decref(response);
    written = snprintf(pending_path, sizeof(pending_path), "%s.pending-key",
                       fixture->certificate_path);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(pending_path));
    assert_int_equal(access(pending_path, F_OK), 0);

    assert_int_equal(jg_certificate_create_self_signed(
                         "replacement.example", NULL, 0U, 365U, &material),
                     0);
    text = json_stringn(material.certificate, material.certificate_size);
    assert_non_null(text);
    encoded_certificate = json_dumps(text, JSON_COMPACT | JSON_ENCODE_ANY);
    json_decref(text);
    text = json_stringn(material.private_key, material.private_key_size);
    assert_non_null(text);
    encoded_key = json_dumps(text, JSON_COMPACT | JSON_ENCODE_ANY);
    json_decref(text);
    assert_non_null(encoded_certificate);
    assert_non_null(encoded_key);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"certificate-install\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/certificates/install\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{\"expected_fingerprint\":\"%s\","
                 "\"certificate\":%s,\"private_key\":%s}}",
                 token.secret, fingerprint, encoded_certificate, encoded_key);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    sodium_memzero(request, sizeof(request));
    sodium_memzero(encoded_key, strlen(encoded_key));
    free(encoded_key);
    free(encoded_certificate);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "reload_required")));
    assert_true(json_is_true(
        json_object_get(json_object_get(body, "certificate"), "self_signed")));
    json_decref(response);
    assert_int_equal(access(pending_path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(
        jg_certificate_inspect_file(fixture->certificate_path, &installed), 0);
    assert_string_equal(installed.subject, "CN=replacement.example");
    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 2U);
    jg_certificate_material_clear(&material);
    sodium_memzero(&token, sizeof(token));
}

/** @brief Verify startup restores a durable interrupted certificate change. */
static void test_cross_resource_recovery(void **state)
{
    static const uint8_t recovery_payload[] = {1U, 1U, 3U};
    static const struct jg_database_operation_context operation_context = {
        .actor_type = JG_AUDIT_ACTOR_LOCAL,
        .source = "127.0.0.1",
        .request_id = "interrupted-install",
        .requested_action = "certificate.install",
    };
    struct management_fixture *fixture = *state;
    struct jg_certificate_material replacement;
    struct jg_certificate_info original;
    struct jg_certificate_info installed;
    struct jg_certificate_info recovered;
    struct jg_database_operation operation;
    struct jg_audit_record audit;
    char snapshot[160U];
    size_t audit_count = 0U;
    uint64_t audit_total = 0U;
    int written = 0;

    assert_int_equal(
        jg_certificate_inspect_file(fixture->certificate_path, &original), 0);
    written = snprintf(snapshot, sizeof(snapshot), "%s.rollback",
                       fixture->certificate_path);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(snapshot));
    assert_int_equal(jg_database_operation_prepare(
                         fixture->database, "certificate_install",
                         recovery_payload, sizeof(recovery_payload),
                         &operation_context, 100U),
                     0);
    assert_int_equal(
        jg_certificate_identity_copy(fixture->certificate_path, snapshot), 0);
    assert_int_equal(jg_database_operation_mark_ready(fixture->database), 0);
    assert_int_equal(jg_certificate_create_self_signed(
                         "interrupted.example", NULL, 0U, 30U, &replacement),
                     0);
    assert_int_equal(jg_certificate_install(
                         fixture->certificate_path, replacement.certificate,
                         replacement.certificate_size, replacement.private_key,
                         replacement.private_key_size, &installed),
                     0);
    assert_true(sodium_memcmp(installed.fingerprint_sha256,
                              original.fingerprint_sha256,
                              sizeof(original.fingerprint_sha256)) != 0);

    jg_management_destroy(fixture->management);
    fixture->management = NULL;
    assert_int_equal(
        jg_management_create(fixture->database, fixture->key_path,
                             fixture->certificate_path, fixture->client_ca_path,
                             fixture->directory, NULL, &fixture->management),
        0);
    assert_int_equal(
        jg_certificate_inspect_file(fixture->certificate_path, &recovered), 0);
    assert_memory_equal(recovered.fingerprint_sha256,
                        original.fingerprint_sha256,
                        sizeof(original.fingerprint_sha256));
    assert_int_equal(jg_database_operation_load(fixture->database, &operation),
                     -ENOENT);
    assert_int_equal(access(snapshot, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, &audit, 1U,
                                            &audit_count, &audit_total),
                     0);
    assert_int_equal(audit_count, 1U);
    assert_int_equal(audit.actor_type, JG_AUDIT_ACTOR_SYSTEM);
    assert_string_equal(audit.request_id, "interrupted-install");
    assert_non_null(
        strstr(audit.details, "\"requested_action\":\"certificate.install\""));
    assert_non_null(strstr(audit.details, "\"original_actor_type\":\"local\""));
    jg_certificate_material_clear(&replacement);
}

/** @brief Verify startup removes an archive left before metadata commit. */
static void test_backup_creation_recovery(void **state)
{
    static const uint8_t database_image[] = "uncommitted backup snapshot";
    static const char filename[] = "backup-100-0123456789abcdef.jgb";
    static const struct jg_database_operation_context operation_context = {
        .actor_type = JG_AUDIT_ACTOR_LOCAL,
        .source = "127.0.0.1",
        .request_id = "interrupted-backup",
        .requested_action = "backup.create",
    };
    struct management_fixture *fixture = *state;
    struct jg_database_operation operation;
    struct jg_audit_record audit;
    uint8_t payload[1U + sizeof(filename) - 1U];
    uint8_t *archive = NULL;
    size_t archive_size = 0U;
    size_t audit_count = 0U;
    uint64_t audit_total = 0U;
    char path[256U];
    int written = 0;

    payload[0U] = MANAGEMENT_RECOVERY_VERSION;
    (void)memcpy(payload + 1U, filename, sizeof(filename) - 1U);
    assert_int_equal(
        jg_backup_create(JG_BACKUP_CONFIGURATION, database_image,
                         sizeof(database_image) - 1U, NULL, 0U, NULL, 0U, 100U,
                         JG_DATABASE_SCHEMA_VERSION, &archive, &archive_size),
        0);
    jg_management_destroy(fixture->management);
    fixture->management = NULL;
    assert_int_equal(jg_database_operation_prepare(
                         fixture->database, "backup_create", payload,
                         sizeof(payload), &operation_context, 100U),
                     0);
    assert_int_equal(jg_database_operation_mark_ready(fixture->database), 0);
    assert_int_equal(
        jg_backup_store(fixture->directory, filename, archive, archive_size),
        0);
    jg_backup_data_clear(archive, archive_size);
    written =
        snprintf(path, sizeof(path), "%s/%s", fixture->directory, filename);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(path));
    assert_int_equal(access(path, F_OK), 0);
    assert_int_equal(
        jg_management_create(fixture->database, fixture->key_path,
                             fixture->certificate_path, fixture->client_ca_path,
                             fixture->directory, NULL, &fixture->management),
        0);
    assert_int_equal(access(path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(jg_database_operation_load(fixture->database, &operation),
                     -ENOENT);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, &audit, 1U,
                                            &audit_count, &audit_total),
                     0);
    assert_int_equal(audit_count, 1U);
    assert_string_equal(audit.request_id, "interrupted-backup");
    assert_string_equal(audit.action, "management.operation.recover");
}

/** @brief Verify audit failure restores and retains a retryable operation. */
static void test_cross_resource_audit_failure(void **state)
{
    static const char reject_audit[] =
        "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events "
        "BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;";
    struct management_fixture *fixture = *state;
    struct jg_database_operation operation;
    char request[16384U];
    char *authority = NULL;
    char *client = NULL;
    char *encoded_authority = NULL;
    size_t authority_size = 0U;
    size_t client_size = 0U;
    sqlite3 *injection = NULL;
    json_t *text = NULL;
    json_t *response = NULL;
    int written = 0;

    create_management_test_identity(&authority, &authority_size, &client,
                                    &client_size);
    text = json_stringn(authority, authority_size);
    assert_non_null(text);
    encoded_authority = json_dumps(text, JSON_COMPACT | JSON_ENCODE_ANY);
    json_decref(text);
    assert_non_null(encoded_authority);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"mtls-audit-failure\",\"method\":\"PUT\","
                 "\"path\":\"/api/v1/mtls/authorities\",\"host\":\"localhost\","
                 "\"remote_address\":\"127.0.0.1\",\"body\":{"
                 "\"certificate_authorities\":%s}}",
                 encoded_authority);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    assert_int_equal(sqlite3_open_v2(fixture->database_path, &injection,
                                     SQLITE_OPEN_READWRITE, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_exec(injection, reject_audit, NULL, NULL, NULL),
                     SQLITE_OK);
    assert_int_equal(sqlite3_close(injection), SQLITE_OK);
    injection = NULL;

    response = process_local_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     500);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "audit_failure");
    json_decref(response);
    assert_int_equal(access(fixture->client_ca_path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(jg_database_operation_load(fixture->database, &operation),
                     0);
    assert_true(operation.ready);
    response = process_local_request(
        fixture, "{\"request_id\":\"degraded-health\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/health\",\"host\":\"localhost\","
                 "\"remote_address\":\"127.0.0.1\",\"body\":{}}");
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    assert_true(json_is_true(json_object_get(
        json_object_get(json_object_get(response, "body"), "management"),
        "degraded")));
    assert_false(json_is_true(json_object_get(
        json_object_get(json_object_get(response, "body"), "management"),
        "mutations_allowed")));
    json_decref(response);
    response = process_local_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "management_degraded");
    json_decref(response);

    assert_int_equal(sqlite3_open_v2(fixture->database_path, &injection,
                                     SQLITE_OPEN_READWRITE, NULL),
                     SQLITE_OK);
    assert_int_equal(
        sqlite3_exec(injection, "DROP TRIGGER reject_audit;", NULL, NULL, NULL),
        SQLITE_OK);
    assert_int_equal(sqlite3_close(injection), SQLITE_OK);
    jg_management_destroy(fixture->management);
    fixture->management = NULL;
    assert_int_equal(
        jg_management_create(fixture->database, fixture->key_path,
                             fixture->certificate_path, fixture->client_ca_path,
                             fixture->directory, NULL, &fixture->management),
        0);
    assert_int_equal(jg_database_operation_load(fixture->database, &operation),
                     -ENOENT);
    assert_int_equal(access(fixture->client_ca_path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    response = process_local_request(
        fixture, "{\"request_id\":\"recovered-health\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/health\",\"host\":\"localhost\","
                 "\"remote_address\":\"127.0.0.1\",\"body\":{}}");
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    assert_false(json_is_true(json_object_get(
        json_object_get(json_object_get(response, "body"), "management"),
        "degraded")));
    assert_true(json_is_true(json_object_get(
        json_object_get(json_object_get(response, "body"), "management"),
        "mutations_allowed")));
    json_decref(response);

    sodium_memzero(encoded_authority, strlen(encoded_authority));
    free(encoded_authority);
    sodium_memzero(client, client_size);
    free(client);
    sodium_memzero(authority, authority_size);
    free(authority);
}

/** @brief Verify policy divergence survives restart and suspends mutations. */
static void test_policy_sync_health(void **state)
{
    static const char health_request[] =
        "{\"request_id\":\"policy-health\",\"method\":\"GET\","
        "\"path\":\"/api/v1/health\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    static const char mutation_request[] =
        "{\"request_id\":\"policy-blocked\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/mtls/authorities\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    struct management_fixture *fixture = *state;
    struct jg_database_policy_sync sync;
    json_t *response = NULL;
    json_t *management = NULL;
    json_t *policy = NULL;
    const time_t now = time(NULL);

    assert_true(now > 0);
    assert_int_equal(jg_database_policy_sync_advance(fixture->database,
                                                     (uint64_t)now, &sync),
                     0);
    assert_int_equal(jg_database_policy_sync_record(
                         fixture->database, sync.desired_revision, false,
                         "runtime_reload_failed", (uint64_t)now, &sync),
                     0);

    jg_management_destroy(fixture->management);
    fixture->management = NULL;
    assert_int_equal(
        jg_management_create(fixture->database, fixture->key_path,
                             fixture->certificate_path, fixture->client_ca_path,
                             fixture->directory, NULL, &fixture->management),
        0);
    response = process_local_request(fixture, health_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    management =
        json_object_get(json_object_get(response, "body"), "management");
    policy = json_object_get(management, "policy");
    assert_true(json_is_true(json_object_get(management, "degraded")));
    assert_false(
        json_is_true(json_object_get(management, "mutations_allowed")));
    assert_string_equal(json_string_value(json_array_get(
                            json_object_get(management, "reasons"), 0U)),
                        "policy_sync");
    assert_true(json_is_true(json_object_get(policy, "available")));
    assert_false(json_is_true(json_object_get(policy, "synchronized")));
    assert_int_equal(
        json_integer_value(json_object_get(policy, "desired_revision")), 2);
    assert_int_equal(
        json_integer_value(json_object_get(policy, "applied_revision")), 1);
    assert_string_equal(
        json_string_value(json_object_get(policy, "last_error")),
        "runtime_reload_failed");
    json_decref(response);

    response = process_local_request(fixture, mutation_request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "management_degraded");
    json_decref(response);

    synchronize_policy(fixture);
    response = process_local_request(fixture, health_request);
    management =
        json_object_get(json_object_get(response, "body"), "management");
    policy = json_object_get(management, "policy");
    assert_false(json_is_true(json_object_get(management, "degraded")));
    assert_true(json_is_true(json_object_get(management, "mutations_allowed")));
    assert_true(json_is_true(json_object_get(policy, "synchronized")));
    assert_int_equal(
        json_integer_value(json_object_get(policy, "applied_revision")), 2);
    assert_true(json_is_null(json_object_get(policy, "last_error")));
    json_decref(response);
}

/** @brief Verify private CA and client-certificate mapping administration. */
static void test_mtls_api(void **state)
{
    static const char authorities_show[] =
        "{\"request_id\":\"mtls-ca-show\",\"method\":\"GET\","
        "\"path\":\"/api/v1/mtls/authorities\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    static const char mappings_show[] =
        "{\"request_id\":\"mtls-map-show\",\"method\":\"GET\","
        "\"path\":\"/api/v1/mtls/mappings\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    static const char authorities_remove[] =
        "{\"request_id\":\"mtls-ca-remove\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/mtls/authorities\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    struct management_fixture *fixture = *state;
    struct jg_audit_record audits[4U];
    char request[16384U];
    char *authority = NULL;
    char *client = NULL;
    size_t authority_size = 0U;
    size_t client_size = 0U;
    char *encoded_authority = NULL;
    char *encoded_client = NULL;
    json_t *text = NULL;
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t audit_total = 0U;
    size_t audit_count = 0U;
    uint64_t mapping_id = 0U;
    int written = 0;

    response = process_local_request(fixture, authorities_show);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "configured")));
    assert_int_equal(json_array_size(json_object_get(body, "authorities")), 0U);
    json_decref(response);

    create_management_test_identity(&authority, &authority_size, &client,
                                    &client_size);
    text = json_stringn(authority, authority_size);
    assert_non_null(text);
    encoded_authority = json_dumps(text, JSON_COMPACT | JSON_ENCODE_ANY);
    json_decref(text);
    assert_non_null(encoded_authority);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"mtls-ca-install\",\"method\":\"PUT\","
                 "\"path\":\"/api/v1/mtls/authorities\",\"host\":\"localhost\","
                 "\"remote_address\":\"127.0.0.1\",\"body\":{"
                 "\"certificate_authorities\":%s}}",
                 encoded_authority);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_local_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "configured")));
    assert_true(json_is_true(json_object_get(body, "reload_required")));
    items = json_object_get(body, "authorities");
    assert_int_equal(json_array_size(items), 1U);
    assert_string_equal(json_string_value(json_object_get(
                            json_array_get(items, 0U), "subject")),
                        "CN=JanusGate private CA");
    json_decref(response);
    assert_int_equal(access(fixture->client_ca_path, F_OK), 0);

    text = json_stringn(client, client_size);
    assert_non_null(text);
    encoded_client = json_dumps(text, JSON_COMPACT | JSON_ENCODE_ANY);
    json_decref(text);
    assert_non_null(encoded_client);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"mtls-map-create\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/mtls/mappings\",\"host\":\"localhost\","
                 "\"remote_address\":\"127.0.0.1\",\"body\":{"
                 "\"certificate\":%s,\"user_id\":null,"
                 "\"role\":\"administrator\"}}",
                 encoded_client);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_local_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    body = json_object_get(response, "body");
    mapping_id = (uint64_t)json_integer_value(
        json_object_get(json_object_get(body, "mapping"), "id"));
    assert_true(mapping_id > 0U);
    json_decref(response);

    response = process_local_request(fixture, mappings_show);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "total")), 2);
    assert_int_equal(json_array_size(json_object_get(body, "mappings")), 2U);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"mtls-map-revoke\",\"method\":\"DELETE\","
        "\"path\":\"/api/v1/mtls/mappings/%llu\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}",
        (unsigned long long)mapping_id);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_local_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_integer(
        json_object_get(json_object_get(body, "mapping"), "revoked_at")));
    json_decref(response);

    response = process_local_request(fixture, authorities_remove);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "configured")));
    assert_true(json_is_true(json_object_get(body, "reload_required")));
    json_decref(response);
    assert_int_equal(access(fixture->client_ca_path, F_OK), -1);
    assert_int_equal(errno, ENOENT);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, audits,
                                            sizeof(audits) / sizeof(audits[0U]),
                                            &audit_count, &audit_total),
                     0);
    assert_int_equal(audit_count, 4U);
    assert_int_equal(audit_total, 4U);
    assert_string_equal(audits[0U].action, "mtls.authorities.remove");
    assert_string_equal(audits[3U].action, "mtls.authorities.install");

    sodium_memzero(client, client_size);
    free(client);
    free(encoded_client);
    free(encoded_authority);
    free(authority);
}

/** @brief Verify backup creation, pagination, and manifest inspection. */
static void test_backup_api(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    const struct jg_account_token_config token_config = {
        .name = "backup administrator",
        .permissions = JG_ACCESS_BACKUPS_WRITE,
        .requests_per_minute = 100U,
    };
    const struct jg_account_token_config other_token_config = {
        .name = "other backup administrator",
        .permissions = JG_ACCESS_BACKUPS_WRITE,
        .requests_per_minute = 100U,
    };
    struct jg_account_api_token token;
    struct jg_account_api_token other_token;
    struct jg_audit_verification verification;
    struct jg_database_backup records[4U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *backup = NULL;
    json_t *manifest = NULL;
    const time_t now = time(NULL);
    uint64_t full_backup_id = 0U;
    uint64_t job_id = 0U;
    uint64_t user_id = 0U;
    size_t count = 0U;
    bool has_more = false;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator", password,
                         sizeof(password) - 1U, &password_policy, (uint64_t)now,
                         &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &other_token_config, (uint64_t)now,
                                            &other_token),
                     0);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"backup-configuration\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"configuration\","
                 "\"include_private_key\":false,\"passphrase\":null}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    job_id = (uint64_t)json_integer_value(json_object_get(
        json_object_get(json_object_get(response, "body"), "job"), "id"));
    assert_true(job_id > 0U);
    assert_true(job_id <= UINT64_C(9007199254740991));

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"backup-job-foreign\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/jobs/%llu\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{}}",
                 (unsigned long long)job_id, other_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    body = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(body, "status")), 404);
    json_decref(body);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"backup-job-local\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/jobs/%llu\",\"host\":\"localhost\","
                 "\"remote_address\":\"127.0.0.1\",\"body\":{}}",
                 (unsigned long long)job_id);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    body = process_local_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(body, "status")), 200);
    json_decref(body);

    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    backup = json_object_get(json_object_get(response, "body"), "backup");
    assert_string_equal(json_string_value(json_object_get(backup, "kind")),
                        "configuration");
    assert_false(json_is_true(json_object_get(backup, "encrypted")));
    assert_int_equal(
        json_string_length(json_object_get(backup, "checksum_sha256")), 64U);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"backup-full\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"full\",\"include_private_key\":true,"
                 "\"passphrase\":\"archive passphrase\"}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    backup = json_object_get(json_object_get(response, "body"), "backup");
    full_backup_id =
        (uint64_t)json_integer_value(json_object_get(backup, "id"));
    assert_true(full_backup_id > 0U);
    assert_string_equal(json_string_value(json_object_get(backup, "kind")),
                        "full");
    assert_true(json_is_true(json_object_get(backup, "encrypted")));
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"backup-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/backups\",\"query\":\"limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 1);
    assert_true(json_is_true(json_object_get(body, "has_more")));
    assert_true(json_is_integer(json_object_get(body, "next_after_id")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"backup-inspect\",\"method\":\"GET\","
        "\"path\":\"/api/v1/backups/%llu\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        (unsigned long long)full_backup_id, token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    manifest = json_object_get(body, "manifest");
    assert_int_equal(
        json_integer_value(json_object_get(manifest, "format_version")),
        JG_BACKUP_FORMAT_VERSION);
    assert_true(json_is_true(json_object_get(manifest, "encrypted")));
    assert_true(
        json_integer_value(json_object_get(manifest, "certificate_size")) > 0);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"backup-invalid\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"full\",\"include_private_key\":false,"
                 "\"passphrase\":null}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 2U);
    assert_int_equal(
        jg_database_list_backups(fixture->database, 0U,
                                 sizeof(records) / sizeof(records[0U]), records,
                                 &count, &has_more),
        0);
    assert_false(has_more);
    assert_int_equal(count, 2U);
    for (size_t index = 0U; index < count; ++index) {
        assert_int_equal(
            jg_backup_remove(fixture->directory, records[index].filename), 0);
    }
    sodium_memzero(&other_token, sizeof(other_token));
    sodium_memzero(&token, sizeof(token));
}

/** @brief Verify retained results, per-actor quota, and slot release. */
static void test_job_lifecycle(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    const struct jg_account_token_config token_config = {
        .name = "job lifecycle administrator",
        .permissions = JG_ACCESS_BACKUPS_WRITE,
        .requests_per_minute = 100U,
    };
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    struct jg_account_api_token token;
    struct jg_database_backup backups[4U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *accepted_first = NULL;
    json_t *accepted_second = NULL;
    json_t *accepted_third = NULL;
    json_t *response = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    size_t count = 0U;
    bool has_more = false;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator", password,
                         sizeof(password) - 1U, &password_policy, (uint64_t)now,
                         &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"job-lifecycle-first\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"configuration\","
                 "\"include_private_key\":false,\"passphrase\":null}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    accepted_first = process_request(fixture, request);
    assert_int_equal(
        json_integer_value(json_object_get(accepted_first, "status")), 202);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"job-lifecycle-second\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"configuration\","
                 "\"include_private_key\":false,\"passphrase\":null}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    accepted_second = process_request(fixture, request);
    assert_int_equal(
        json_integer_value(json_object_get(accepted_second, "status")), 202);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"job-lifecycle-limited\",\"method\":\"POST\","
        "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"kind\":\"configuration\","
        "\"include_private_key\":false,\"passphrase\":null}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     429);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "job_quota_exceeded");
    json_decref(response);

    response = complete_accepted_job(fixture, accepted_first, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"job-lifecycle-third\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"configuration\","
                 "\"include_private_key\":false,\"passphrase\":null}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    accepted_third = process_request(fixture, request);
    assert_int_equal(
        json_integer_value(json_object_get(accepted_third, "status")), 202);

    response = complete_accepted_job(fixture, accepted_second, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    json_decref(response);
    response = complete_accepted_job(fixture, accepted_third, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    json_decref(response);

    assert_int_equal(
        jg_database_list_backups(fixture->database, 0U,
                                 sizeof(backups) / sizeof(backups[0U]), backups,
                                 &count, &has_more),
        0);
    assert_false(has_more);
    assert_int_equal(count, 3U);
    for (size_t index = 0U; index < count; ++index) {
        assert_int_equal(
            jg_backup_remove(fixture->directory, backups[index].filename), 0);
    }
    sodium_memzero(&token, sizeof(token));
    sodium_memzero(bootstrap, sizeof(bootstrap));
}

/** @brief Verify backup dry runs, confirmation, checkpoints, and restore. */
static void test_backup_restore_api(void **state)
{
    static const uint8_t password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    const struct jg_account_token_config token_config = {
        .name = "restore administrator",
        .permissions = JG_ACCESS_BACKUPS_WRITE,
        .requests_per_minute = 100U,
    };
    const struct jg_network_config initial = {
        .bridge = "br-data",
        .ingress = "eth0",
        .egress = "eth1",
        .management = "eth2",
        .queue_first = 100U,
        .queue_count = 4U,
        .queue_length = 4096U,
        .failure_mode = JG_NETWORK_FAIL_OPEN,
        .multicast_snooping = true,
        .queue_cpu_fanout = true,
    };
    const struct jg_network_config changed = {
        .bridge = "br-data",
        .ingress = "eth0",
        .egress = "eth1",
        .management = "eth2",
        .queue_first = 100U,
        .queue_count = 4U,
        .queue_length = 8192U,
        .failure_mode = JG_NETWORK_FAIL_CLOSED,
        .multicast_snooping = true,
        .queue_cpu_fanout = true,
    };
    struct jg_account_api_token token;
    struct jg_audit_record audits[JG_AUDIT_PAGE_MAX];
    struct jg_audit_verification verification;
    struct jg_database_backup records[4U];
    struct jg_network_config loaded;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *backup = NULL;
    json_t *checkpoint = NULL;
    const time_t now = time(NULL);
    uint64_t configuration_backup_id = 0U;
    uint64_t full_backup_id = 0U;
    uint64_t user_id = 0U;
    size_t count = 0U;
    size_t audit_count = 0U;
    size_t checkpoint_audits = 0U;
    size_t restore_audits = 0U;
    uint64_t audit_total = 0U;
    bool has_more = false;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator", password,
                         sizeof(password) - 1U, &password_policy, (uint64_t)now,
                         &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);
    assert_int_equal(
        jg_database_store_network_config(fixture->database, &initial), 0);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"restore-configuration-create\","
                 "\"method\":\"POST\",\"path\":\"/api/v1/backups\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{\"kind\":\"configuration\","
                 "\"include_private_key\":false,\"passphrase\":null}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    backup = json_object_get(json_object_get(response, "body"), "backup");
    configuration_backup_id =
        (uint64_t)json_integer_value(json_object_get(backup, "id"));
    assert_true(configuration_backup_id > 0U);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"restore-full-create\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/backups\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"kind\":\"full\",\"include_private_key\":true,"
                 "\"passphrase\":\"archive passphrase\"}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     201);
    backup = json_object_get(json_object_get(response, "body"), "backup");
    full_backup_id =
        (uint64_t)json_integer_value(json_object_get(backup, "id"));
    assert_true(full_backup_id > configuration_backup_id);
    json_decref(response);

    assert_int_equal(
        jg_database_store_network_config(fixture->database, &changed), 0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restore-configuration-dry\",\"method\":\"POST\","
        "\"path\":\"/api/v1/backups/%llu/restore\","
        "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
        "\"bearer\":\"%s\",\"body\":{\"passphrase\":null,"
        "\"dry_run\":true,\"confirm\":false}}",
        (unsigned long long)configuration_backup_id, token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "dry_run")));
    assert_true(json_is_true(json_object_get(body, "changes")));
    assert_true(json_is_null(json_object_get(body, "checkpoint")));
    assert_false(json_is_true(json_object_get(body, "reload_required")));
    assert_true(json_is_true(
        json_object_get(json_object_get(body, "database"), "changes")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restore-configuration-apply\",\"method\":\"POST\","
        "\"path\":\"/api/v1/backups/%llu/restore\","
        "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
        "\"bearer\":\"%s\",\"body\":{\"passphrase\":null,"
        "\"dry_run\":false,\"confirm\":true}}",
        (unsigned long long)configuration_backup_id, token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    checkpoint = json_object_get(body, "checkpoint");
    assert_false(json_is_true(json_object_get(body, "dry_run")));
    assert_true(json_is_true(json_object_get(body, "reload_required")));
    assert_string_equal(json_string_value(json_object_get(checkpoint, "kind")),
                        "configuration");
    json_decref(response);
    assert_int_equal(
        jg_database_load_network_config(fixture->database, &loaded), 0);
    assert_int_equal(loaded.queue_length, initial.queue_length);
    assert_int_equal(loaded.failure_mode, initial.failure_mode);
    synchronize_policy(fixture);

    assert_int_equal(
        jg_database_store_network_config(fixture->database, &changed), 0);
    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restore-full-wrong-passphrase\","
        "\"method\":\"POST\",\"path\":\"/api/v1/backups/%llu/restore\","
        "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
        "\"bearer\":\"%s\",\"body\":{\"passphrase\":\"wrong passphrase\","
        "\"dry_run\":true,\"confirm\":false}}",
        (unsigned long long)full_backup_id, token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "incorrect_passphrase");
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restore-full-apply\",\"method\":\"POST\","
        "\"path\":\"/api/v1/backups/%llu/restore\","
        "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
        "\"bearer\":\"%s\",\"body\":{\"passphrase\":\"archive passphrase\","
        "\"dry_run\":false,\"confirm\":true}}",
        (unsigned long long)full_backup_id, token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    checkpoint = json_object_get(body, "checkpoint");
    assert_true(json_is_true(json_object_get(body, "changes")));
    assert_false(json_is_true(json_object_get(body, "certificate_changes")));
    assert_string_equal(json_string_value(json_object_get(checkpoint, "kind")),
                        "full");
    json_decref(response);
    assert_int_equal(
        jg_database_load_network_config(fixture->database, &loaded), 0);
    assert_int_equal(loaded.queue_length, initial.queue_length);
    assert_int_equal(loaded.failure_mode, initial.failure_mode);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 7U);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, audits,
                                            sizeof(audits) / sizeof(audits[0U]),
                                            &audit_count, &audit_total),
                     0);
    assert_int_equal(audit_count, JG_AUDIT_PAGE_MAX);
    assert_int_equal(audit_total, 7U);
    for (size_t index = 0U; index < audit_count; ++index) {
        if (strcmp(audits[index].action, "backup.checkpoint.create") == 0) {
            checkpoint_audits += 1U;
            assert_non_null(
                strstr(audits[index].details, "\"restore_backup_id\":"));
            assert_non_null(strstr(audits[index].details,
                                   "\"restore_request_id\":\"restore-"));
        } else if (strcmp(audits[index].action, "backup.restore") == 0) {
            restore_audits += 1U;
            assert_non_null(
                strstr(audits[index].details, "\"checkpoint_id\":"));
        }
    }
    assert_int_equal(checkpoint_audits, 2U);
    assert_int_equal(restore_audits, 2U);
    assert_int_equal(
        jg_database_list_backups(fixture->database, 0U,
                                 sizeof(records) / sizeof(records[0U]), records,
                                 &count, &has_more),
        0);
    assert_false(has_more);
    assert_int_equal(count, 4U);
    for (size_t index = 0U; index < count; ++index) {
        assert_int_equal(
            jg_backup_remove(fixture->directory, records[index].filename), 0);
    }
    sodium_memzero(&token, sizeof(token));
}

/** @brief Verify runtime operation authorization and request bounds. */
static void test_configuration_api(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    const struct jg_account_token_config token_config = {
        .name = "configuration operator",
        .permissions = JG_ACCESS_OPERATE,
        .requests_per_minute = 100U,
    };
    struct jg_account_api_token token;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[1024U];
    json_t *response = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"config-validate\",\"method\":\"POST\","
        "\"path\":\"/api/v1/config/validate\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"config-reload\",\"method\":\"POST\","
        "\"path\":\"/api/v1/config/reload\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"config-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/config/validate\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"unexpected\":true}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"diagnostics-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/diagnostics\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     503);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"diagnostics-invalid\",\"method\":\"POST\","
                 "\"path\":\"/api/v1/diagnostics\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"unexpected\":true}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);
    sodium_memzero(&token, sizeof(token));
}

/** @brief Verify authenticated network inspection and proposal validation. */
static void test_network_api(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    const struct jg_account_token_config token_config = {
        .name = "network administrator",
        .permissions = JG_ACCESS_STATUS_READ | JG_ACCESS_NETWORK_WRITE,
        .requests_per_minute = 100U,
    };
    const struct jg_network_config config = {
        .bridge = "br-data",
        .ingress = "eth0",
        .egress = "eth1",
        .management = "eth2",
        .queue_first = 100U,
        .queue_count = 4U,
        .queue_length = 4096U,
        .failure_mode = JG_NETWORK_FAIL_OPEN,
        .multicast_snooping = true,
        .queue_cpu_fanout = true,
    };
    struct jg_account_api_token token;
    struct jg_audit_record audits[3U];
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *configuration = NULL;
    const time_t now = time(NULL);
    uint64_t total = 0U;
    uint64_t user_id = 0U;
    size_t count = 0U;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);
    assert_int_equal(
        jg_database_store_network_config(fixture->database, &config), 0);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"network-get\",\"method\":\"GET\","
        "\"path\":\"/api/v1/network\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "revision")), 1);
    configuration = json_object_get(body, "configuration");
    assert_string_equal(
        json_string_value(json_object_get(configuration, "bridge")), "br-data");
    assert_string_equal(
        json_string_value(json_object_get(configuration, "failure_mode")),
        "fail_open");
    assert_int_equal(
        json_integer_value(json_object_get(configuration, "queue_count")), 4);
    assert_true(
        json_is_true(json_object_get(configuration, "queue_cpu_fanout")));
    assert_false(json_is_true(json_object_get(body, "runtime_available")));
    assert_true(json_is_null(json_object_get(body, "runtime")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"network-invalid\",\"method\":\"POST\","
        "\"path\":\"/api/v1/network/validate\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"bridge\":\"eth0\",\"ingress\":\"eth0\",\"egress\":\"eth1\","
        "\"management\":\"eth2\",\"bridge_mtu\":0,\"queue_first\":100,"
        "\"queue_count\":4,\"queue_length\":4096,"
        "\"failure_mode\":\"fail_open\",\"stp\":false,"
        "\"multicast_snooping\":true,\"queue_cpu_fanout\":true}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "invalid_network");
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"network-stale\",\"method\":\"POST\","
        "\"path\":\"/api/v1/network/apply\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"revision\":2,\"configuration\":{"
        "\"bridge\":\"br-data\",\"ingress\":\"eth0\",\"egress\":\"eth1\","
        "\"management\":\"eth2\",\"bridge_mtu\":0,\"queue_first\":100,"
        "\"queue_count\":4,\"queue_length\":8192,"
        "\"failure_mode\":\"fail_open\",\"stp\":false,"
        "\"multicast_snooping\":true,\"queue_cpu_fanout\":true}}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     409);
    assert_string_equal(
        json_string_value(json_object_get(
            json_object_get(json_object_get(response, "body"), "error"),
            "code")),
        "revision_conflict");
    json_decref(response);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, audits, 1U,
                                            &count, &total),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 1U);
    assert_string_equal(audits[0U].action, "network.apply");
    assert_int_equal(audits[0U].previous_revision, 1U);
    assert_false(audits[0U].has_new_revision);
    assert_false(audits[0U].success);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"network-confirm-stale\",\"method\":\"POST\","
        "\"path\":\"/api/v1/network/confirm\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"revision\":2}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     409);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"network-rollback-stale\",\"method\":\"POST\","
        "\"path\":\"/api/v1/network/rollback\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"revision\":2}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     409);
    json_decref(response);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, audits, 3U,
                                            &count, &total),
                     0);
    assert_int_equal(count, 3U);
    assert_int_equal(total, 3U);
    assert_string_equal(audits[0U].action, "network.rollback");
    assert_string_equal(audits[1U].action, "network.confirm");
    assert_string_equal(audits[2U].action, "network.apply");
}

/** @brief Verify authenticated blocklist-source paging and state JSON. */
static void test_source_api(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    struct jg_account_token_config token_config = {
        .name = "source test",
        .permissions = JG_ACCESS_POLICY_READ | JG_ACCESS_POLICY_WRITE,
        .requests_per_minute = 100U,
    };
    struct jg_database_blocklist_source_config source_config = {
        .name = "Threat domains",
        .url = "https://lists.example/domains",
        .format = JG_BLOCKLIST_FORMAT_HOSTS,
        .mode = JG_BLOCKLIST_TOLERANT,
        .enabled = true,
        .update_interval_seconds = 3600U,
        .max_download_bytes = 1048576U,
        .max_decompressed_bytes = 4194304U,
        .connect_timeout_ms = 5000U,
        .transfer_timeout_ms = 30000U,
        .redirect_limit = 3U,
        .retry_base_seconds = 60U,
        .retry_max_seconds = 3600U,
    };
    struct jg_database_blocklist_source source;
    struct jg_database_domain_rule rules[2U];
    struct jg_account_api_token api_token;
    struct jg_audit_verification verification;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *value = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t source_id = 0U;
    uint64_t source_revision = 0U;
    size_t count = 0U;
    bool has_more = false;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &api_token),
                     0);
    assert_int_equal(jg_database_create_blocklist_source(
                         fixture->database, &source_config, &source),
                     0);
    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"sources-list\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/sources\",\"query\":\"limit=1\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 1);
    assert_false(json_is_true(json_object_get(body, "has_more")));
    assert_true(json_is_null(json_object_get(body, "next_after_id")));
    value = json_array_get(json_object_get(body, "sources"), 0U);
    assert_int_equal(json_integer_value(json_object_get(value, "id")),
                     (json_int_t)source.id);
    assert_string_equal(json_string_value(json_object_get(value, "name")),
                        source_config.name);
    assert_string_equal(json_string_value(json_object_get(value, "format")),
                        "hosts");
    assert_string_equal(json_string_value(json_object_get(value, "mode")),
                        "tolerant");
    assert_string_equal(json_string_value(json_object_get(value, "health")),
                        "unknown");
    assert_true(json_is_null(json_object_get(value, "active_checksum")));
    assert_true(json_is_null(json_object_get(value, "last_attempt_at")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"source-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/sources\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"name\":\"API source\","
        "\"url\":\"https://127.0.0.1:1/blocklist\","
        "\"signature_url\":null,\"format\":\"domain\",\"mode\":\"strict\","
        "\"enabled\":true,\"update_interval_seconds\":7200,"
        "\"max_download_bytes\":2048,\"max_decompressed_bytes\":8192,"
        "\"connect_timeout_ms\":100,\"transfer_timeout_ms\":100,"
        "\"redirect_limit\":2,\"retry_base_seconds\":60,"
        "\"retry_max_seconds\":600,\"sha256_pin\":null,"
        "\"ed25519_public_key\":null}}",
        api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "published")));
    value = json_object_get(body, "source");
    source_id = (uint64_t)json_integer_value(json_object_get(value, "id"));
    source_revision =
        (uint64_t)json_integer_value(json_object_get(value, "revision"));
    assert_true(source_id > source.id);
    assert_int_equal(source_revision, 1U);
    json_decref(response);
    synchronize_policy(fixture);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"source-update\",\"method\":\"PATCH\","
        "\"path\":\"/api/v1/sources/%llu\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"revision\":%llu,\"name\":\"API source updated\","
        "\"url\":\"https://127.0.0.1:1/blocklist\","
        "\"signature_url\":null,"
        "\"format\":\"hosts\",\"mode\":\"tolerant\",\"enabled\":false,"
        "\"update_interval_seconds\":7200,\"max_download_bytes\":2048,"
        "\"max_decompressed_bytes\":8192,\"connect_timeout_ms\":100,"
        "\"transfer_timeout_ms\":100,\"redirect_limit\":2,"
        "\"retry_base_seconds\":60,\"retry_max_seconds\":600,"
        "\"sha256_pin\":null,\"ed25519_public_key\":null}}",
        (unsigned long long)source_id, api_token.secret,
        (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    value = json_object_get(json_object_get(response, "body"), "source");
    source_revision =
        (uint64_t)json_integer_value(json_object_get(value, "revision"));
    assert_int_equal(source_revision, 2U);
    assert_false(json_is_true(json_object_get(value, "enabled")));
    assert_string_equal(json_string_value(json_object_get(value, "format")),
                        "hosts");
    json_decref(response);
    synchronize_policy(fixture);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"source-refresh\",\"method\":\"POST\","
                       "\"path\":\"/api/v1/sources/%llu/refresh\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{\"revision\":%llu}}",
                       (unsigned long long)source_id, api_token.secret,
                       (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, api_token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     502);
    body = json_object_get(response, "body");
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(body, "error"), "code")),
                        "blocklist_update_failed");
    value = json_object_get(body, "source");
    assert_string_equal(json_string_value(json_object_get(value, "health")),
                        "failed");
    assert_int_equal(
        json_integer_value(json_object_get(value, "consecutive_failures")), 1);
    value = json_object_get(body, "attempt");
    assert_false(json_is_true(json_object_get(value, "success")));
    assert_string_equal(json_string_value(json_object_get(value, "outcome")),
                        "failed");
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"source-delete\",\"method\":\"DELETE\","
                 "\"path\":\"/api/v1/sources/%llu\",\"host\":\"192.168.77.1\","
                 "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                 "\"body\":{\"revision\":%llu}}",
                 (unsigned long long)source_id, api_token.secret,
                 (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "deleted")));
    assert_int_equal(json_integer_value(json_object_get(body, "id")),
                     (json_int_t)source_id);
    json_decref(response);
    synchronize_policy(fixture);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"local-source-create\",\"method\":\"POST\","
        "\"path\":\"/api/v1/sources\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"name\":\"Local upload\",\"url\":null,\"signature_url\":null,"
        "\"format\":\"domain\",\"mode\":\"strict\",\"enabled\":true,"
        "\"update_interval_seconds\":7200,\"max_download_bytes\":2048,"
        "\"max_decompressed_bytes\":8192,\"connect_timeout_ms\":100,"
        "\"transfer_timeout_ms\":100,\"redirect_limit\":2,"
        "\"retry_base_seconds\":60,\"retry_max_seconds\":600,"
        "\"sha256_pin\":null,\"ed25519_public_key\":null}}",
        api_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    value = json_object_get(json_object_get(response, "body"), "source");
    source_id = (uint64_t)json_integer_value(json_object_get(value, "id"));
    source_revision =
        (uint64_t)json_integer_value(json_object_get(value, "revision"));
    json_decref(response);
    synchronize_policy(fixture);

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"local-blocklist-import\","
                       "\"method\":\"POST\",\"path\":\"/api/v1/blocklists\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{\"source_id\":%llu,\"revision\":%llu,"
                       "\"content\":\"ads.example\\ntracking.example\\n\"}}",
                       api_token.secret, (unsigned long long)source_id,
                       (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, api_token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    body = json_object_get(response, "body");
    assert_false(json_is_true(json_object_get(body, "published")));
    value = json_object_get(body, "source");
    assert_string_equal(json_string_value(json_object_get(value, "health")),
                        "healthy");
    assert_int_equal(
        json_integer_value(json_object_get(value, "active_entries")), 2);
    value = json_object_get(body, "attempt");
    assert_true(json_is_true(json_object_get(value, "success")));
    assert_string_equal(json_string_value(json_object_get(value, "outcome")),
                        "updated");
    json_decref(response);
    synchronize_policy(fixture);
    assert_int_equal(jg_database_list_domain_rules(fixture->database, 0U, 2U,
                                                   rules, &count, &has_more),
                     0);
    assert_int_equal(count, 2U);
    assert_false(has_more);
    assert_string_equal(rules[0U].domain, "ads.example");
    assert_string_equal(rules[1U].domain, "tracking.example");

    written = snprintf(request, sizeof(request),
                       "{\"request_id\":\"local-blocklist-invalid\","
                       "\"method\":\"POST\",\"path\":\"/api/v1/blocklists\","
                       "\"host\":\"192.168.77.1\","
                       "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
                       "\"body\":{\"source_id\":%llu,\"revision\":%llu,"
                       "\"content\":\"not a domain\\n\"}}",
                       api_token.secret, (unsigned long long)source_id,
                       (unsigned long long)source_revision);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    response = complete_accepted_job(fixture, response, api_token.secret);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     422);
    body = json_object_get(response, "body");
    assert_string_equal(json_string_value(json_object_get(
                            json_object_get(body, "error"), "code")),
                        "blocklist_import_failed");
    value = json_object_get(body, "source");
    assert_string_equal(json_string_value(json_object_get(value, "health")),
                        "degraded");
    assert_int_equal(
        json_integer_value(json_object_get(value, "active_entries")), 2);
    json_decref(response);

    assert_int_equal(jg_database_audit_verify(fixture->database, &verification),
                     0);
    assert_true(verification.valid);
    assert_int_equal(verification.records_inspected, 7U);
}

/** @brief Verify due remote sources retain health and system audit state. */
static void test_scheduled_source_update(void **state)
{
    struct management_fixture *fixture = *state;
    const struct jg_database_blocklist_source_config config = {
        .name = "Scheduled source",
        .url = "https://127.0.0.1:1/blocklist",
        .format = JG_BLOCKLIST_FORMAT_DOMAIN,
        .mode = JG_BLOCKLIST_STRICT,
        .enabled = true,
        .update_interval_seconds = 3600U,
        .max_download_bytes = 4096U,
        .max_decompressed_bytes = 8192U,
        .connect_timeout_ms = 100U,
        .transfer_timeout_ms = 100U,
        .redirect_limit = 2U,
        .retry_base_seconds = 10U,
        .retry_max_seconds = 80U,
    };
    struct jg_database_blocklist_source source;
    struct jg_database_blocklist_source updated;
    struct jg_audit_record audit;
    struct jg_event_record event;
    struct jg_event_filter event_filter = {
        .severity = JG_EVENT_SEVERITY_ANY,
    };
    uint64_t total = 0U;
    size_t attempts = 0U;
    size_t count = 0U;
    bool has_more = false;

    assert_int_equal(jg_database_create_blocklist_source(fixture->database,
                                                         &config, &source),
                     0);
    assert_int_equal(jg_management_update_due_blocklists(fixture->management,
                                                         100U, &attempts),
                     0);
    assert_int_equal(attempts, 0U);
    wait_for_source_attempt(fixture, source.id, 100U, &updated);
    assert_int_equal(updated.health, JG_DATABASE_BLOCKLIST_FAILED);
    assert_int_equal(updated.last_attempt_at, 100U);
    assert_int_equal(updated.consecutive_failures, 1U);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U, &audit, 1U,
                                            &count, &total),
                     0);
    assert_int_equal(count, 1U);
    assert_int_equal(total, 1U);
    assert_int_equal(audit.actor_type, JG_AUDIT_ACTOR_SYSTEM);
    assert_false(audit.has_actor_id);
    assert_false(audit.success);
    assert_string_equal(audit.source, "scheduler");
    assert_string_equal(audit.action, "blocklist.source.refresh");
    assert_int_equal(jg_database_event_list(fixture->database, &event_filter,
                                            &event, 1U, &count, &has_more),
                     0);
    assert_int_equal(count, 1U);
    assert_false(has_more);
    assert_int_equal(event.severity, JG_EVENT_SEVERITY_WARNING);
    assert_string_equal(event.component, "blocklist");
    assert_string_equal(event.code, "source.update_failed");

    attempts = 1U;
    assert_int_equal(jg_management_update_due_blocklists(fixture->management,
                                                         101U, &attempts),
                     0);
    assert_int_equal(attempts, 0U);
}

/** @brief Verify authenticated operational-event filters and public JSON. */
static void test_event_api(void **state)
{
    static const char password[] = "correct horse battery staple";
    struct management_fixture *fixture = *state;
    struct jg_auth_password_policy password_policy;
    const struct jg_account_token_config token_config = {
        .name = "event reader",
        .permissions = JG_ACCESS_EVENTS_READ,
        .requests_per_minute = 100U,
    };
    const struct jg_event first = {
        .occurred_at = 100U,
        .severity = JG_EVENT_SEVERITY_INFO,
        .component = "daemon",
        .code = "startup.complete",
        .message = "Packet enforcement started.",
        .details = "{}",
    };
    const struct jg_event second = {
        .occurred_at = 101U,
        .severity = JG_EVENT_SEVERITY_WARNING,
        .component = "daemon",
        .code = "queue.pressure",
        .message = "Queue pressure crossed its warning threshold.",
        .details = "{\"depth\":42}",
    };
    const struct jg_event third = {
        .occurred_at = 102U,
        .severity = JG_EVENT_SEVERITY_WARNING,
        .component = "blocklist",
        .code = "source.update_failed",
        .message = "The scheduled source update failed.",
        .details = "{\"source_id\":3}",
    };
    struct jg_account_api_token token;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *event = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);
    assert_int_equal(jg_database_event_append(fixture->database, &first, NULL),
                     0);
    assert_int_equal(jg_database_event_append(fixture->database, &second, NULL),
                     0);
    assert_int_equal(jg_database_event_append(fixture->database, &third, NULL),
                     0);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"events-filtered\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/events\","
                 "\"query\":\"limit=1&severity=warning&component=daemon\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "count")), 1);
    assert_false(json_is_true(json_object_get(body, "has_more")));
    assert_true(json_is_null(json_object_get(body, "next_after_id")));
    assert_string_equal(json_string_value(json_object_get(body, "severity")),
                        "warning");
    assert_string_equal(json_string_value(json_object_get(body, "component")),
                        "daemon");
    event = json_array_get(json_object_get(body, "events"), 0U);
    assert_string_equal(json_string_value(json_object_get(event, "code")),
                        "queue.pressure");
    assert_int_equal(json_integer_value(json_object_get(
                         json_object_get(event, "details"), "depth")),
                     42);
    json_decref(response);

    written =
        snprintf(request, sizeof(request),
                 "{\"request_id\":\"events-invalid\",\"method\":\"GET\","
                 "\"path\":\"/api/v1/events\","
                 "\"query\":\"severity=warning&severity=error\","
                 "\"host\":\"192.168.77.1\",\"remote_address\":\"192.0.2.10\","
                 "\"bearer\":\"%s\",\"body\":{}}",
                 token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);
}

/** @brief Verify malformed, cross-origin, and routing requests fail closed. */
static void test_request_rejection(void **state)
{
    struct management_fixture *fixture = *state;
    json_t *response = process_request(fixture, "{}");
    json_t *error = NULL;
    const char invalid_origin[] =
        "{\"request_id\":\"login-1\",\"method\":\"POST\","
        "\"path\":\"/api/v1/auth/login\","
        "\"host\":\"192.168.77.1\",\"origin\":\"https://192.0.2.1\","
        "\"remote_address\":\"192.0.2.10\","
        "\"body\":{\"username\":\"nobody\",\"password\":\"invalid\"}}";
    const char embedded_null[] =
        "{\"request_id\":\"nul-1\",\"method\":\"GET\\u0000POST\","
        "\"path\":\"/api/v1/status\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"body\":{}}";
    const char wrong_static_method[] =
        "{\"request_id\":\"method-static\",\"method\":\"GET\","
        "\"path\":\"/api/v1/auth/login\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    const char wrong_dynamic_method[] =
        "{\"request_id\":\"method-dynamic\",\"method\":\"GET\","
        "\"path\":\"/api/v1/sources/1\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";
    const char unknown_path[] =
        "{\"request_id\":\"path-unknown\",\"method\":\"GET\","
        "\"path\":\"/api/v1/unknown\",\"host\":\"localhost\","
        "\"remote_address\":\"127.0.0.1\",\"body\":{}}";

    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);
    response = process_request(fixture, invalid_origin);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     403);
    json_decref(response);
    response = process_request(fixture, embedded_null);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    json_decref(response);

    response = process_local_request(fixture, wrong_static_method);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     405);
    error = json_object_get(json_object_get(response, "body"), "error");
    assert_string_equal(json_string_value(json_object_get(error, "code")),
                        "method_not_allowed");
    json_decref(response);

    response = process_local_request(fixture, wrong_dynamic_method);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     405);
    json_decref(response);

    response = process_local_request(fixture, unknown_path);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     404);
    error = json_object_get(json_object_get(response, "body"), "error");
    assert_string_equal(json_string_value(json_object_get(error, "code")),
                        "not_found");
    json_decref(response);
}

/** @brief Verify lifecycle actions require permission and confirmation. */
static void test_system_actions(void **state)
{
    struct management_fixture *fixture = *state;
    static const char password[] = "Correct-Horse-Battery-Staple-9!";
    const struct jg_account_token_config system_config = {
        .name = "system operations",
        .permissions = JG_ACCESS_SYSTEM_WRITE,
        .requests_per_minute = 20U,
    };
    const struct jg_account_token_config reader_config = {
        .name = "status reader",
        .permissions = JG_ACCESS_STATUS_READ,
        .requests_per_minute = 20U,
    };
    struct jg_auth_password_policy password_policy;
    struct jg_account_api_token system_token;
    struct jg_account_api_token reader_token;
    struct jg_audit_record audit_record;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[1024U];
    json_t *response = NULL;
    json_t *body = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t audit_total = 0U;
    size_t audit_count = 0U;
    int written = 0;

    assert_true(now > 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &system_config, (uint64_t)now,
                                            &system_token),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &reader_config, (uint64_t)now,
                                            &reader_token),
                     0);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restart-unconfirmed\",\"method\":\"POST\","
        "\"path\":\"/api/v1/service/restart\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"confirm\":false}}",
        system_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     400);
    assert_int_equal(jg_management_take_system_action(fixture->management),
                     JG_SYSTEM_ACTION_NONE);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restart-forbidden\",\"method\":\"POST\","
        "\"path\":\"/api/v1/service/restart\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"confirm\":true}}",
        reader_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     403);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"restart-accepted\",\"method\":\"POST\","
        "\"path\":\"/api/v1/service/restart\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"confirm\":true}}",
        system_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    body = json_object_get(response, "body");
    assert_true(json_is_true(json_object_get(body, "accepted")));
    assert_string_equal(json_string_value(json_object_get(body, "action")),
                        "service.restart");
    assert_int_equal(jg_management_take_system_action(fixture->management),
                     JG_SYSTEM_ACTION_RESTART);
    assert_int_equal(jg_management_take_system_action(fixture->management),
                     JG_SYSTEM_ACTION_NONE);
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"shutdown-accepted\",\"method\":\"POST\","
        "\"path\":\"/api/v1/system/shutdown\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\","
        "\"body\":{\"confirm\":true}}",
        system_token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     202);
    assert_int_equal(jg_management_take_system_action(fixture->management),
                     JG_SYSTEM_ACTION_POWEROFF);
    json_decref(response);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U,
                                            &audit_record, 1U, &audit_count,
                                            &audit_total),
                     0);
    assert_int_equal(audit_count, 1U);
    assert_true(audit_total >= 2U);
    assert_string_equal(audit_record.action, "system.shutdown");
    assert_true(audit_record.success);
    sodium_memzero(&system_token, sizeof(system_token));
    sodium_memzero(&reader_token, sizeof(reader_token));
    sodium_memzero(bootstrap, sizeof(bootstrap));
}

/** @brief Verify logging authorization, activation, traces, and auditing. */
static void test_logging_api(void **state)
{
    struct management_fixture *fixture = *state;
    static const char password[] = "Correct-Horse-Battery-Staple-9!";
    const struct jg_account_token_config token_config = {
        .name = "logging administrator",
        .permissions =
            JG_ACCESS_STATUS_READ | JG_ACCESS_OPERATE | JG_ACCESS_SYSTEM_WRITE,
        .requests_per_minute = 20U,
    };
    struct jg_auth_password_policy password_policy;
    struct jg_account_api_token token;
    struct jg_audit_record audit_record;
    struct jg_logging_config logging;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE];
    char request[2048U];
    json_t *response = NULL;
    json_t *body = NULL;
    json_t *records = NULL;
    const time_t now = time(NULL);
    uint64_t user_id = 0U;
    uint64_t audit_total = 0U;
    size_t audit_count = 0U;
    int written = 0;

    assert_true(now > 0);
    jg_logging_config_default(&logging);
    logging.destinations = JG_LOG_DESTINATION_SYSLOG;
    assert_int_equal(jg_logging_initialize("management-test", &logging), 0);
    jg_auth_password_policy_default(&password_policy);
    assert_int_equal(jg_account_bootstrap_issue(fixture->database,
                                                (uint64_t)now, 600U, bootstrap),
                     0);
    assert_int_equal(jg_account_create_initial_administrator(
                         fixture->database, (const uint8_t *)bootstrap,
                         strlen(bootstrap), "administrator",
                         (const uint8_t *)password, strlen(password),
                         &password_policy, (uint64_t)now, &user_id),
                     0);
    assert_int_equal(jg_account_token_issue(fixture->database, user_id,
                                            &token_config, (uint64_t)now,
                                            &token),
                     0);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"logging-show\",\"method\":\"GET\","
        "\"path\":\"/api/v1/logging\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "revision")), 1);
    assert_string_equal(
        json_string_value(json_object_get(body, "global_level")), "info");
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"logging-update\",\"method\":\"PUT\","
        "\"path\":\"/api/v1/logging\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{"
        "\"revision\":1,\"global_level\":\"debug\","
        "\"destinations\":[\"syslog\"],\"rate_limit_per_second\":100,"
        "\"trace_capacity\":4,\"diagnostic_duration_seconds\":120,"
        "\"include_identifiers\":false,\"overrides\":["
        "{\"component\":\"management\",\"level\":\"trace\"}]}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    assert_int_equal(json_integer_value(json_object_get(body, "revision")), 2);
    assert_true(json_is_true(json_object_get(body, "diagnostic_active")));
    assert_false(json_is_true(json_object_get(body, "include_identifiers")));
    json_decref(response);

    written = snprintf(
        request, sizeof(request),
        "{\"request_id\":\"logging-traces\",\"method\":\"GET\","
        "\"path\":\"/api/v1/logging/traces\",\"host\":\"192.168.77.1\","
        "\"remote_address\":\"192.0.2.10\",\"bearer\":\"%s\",\"body\":{}}",
        token.secret);
    assert_true(written > 0);
    assert_true((size_t)written < sizeof(request));
    response = process_request(fixture, request);
    assert_int_equal(json_integer_value(json_object_get(response, "status")),
                     200);
    body = json_object_get(response, "body");
    records = json_object_get(body, "records");
    assert_true(json_is_array(records));
    assert_true(json_array_size(records) >= 1U);
    assert_string_equal(json_string_value(json_object_get(
                            json_array_get(records, 0U), "correlation_id")),
                        "logging-update");
    json_decref(response);
    assert_int_equal(jg_database_audit_list(fixture->database, 0U,
                                            &audit_record, 1U, &audit_count,
                                            &audit_total),
                     0);
    assert_int_equal(audit_count, 1U);
    assert_true(audit_total >= 1U);
    assert_string_equal(audit_record.action, "logging.update");
    assert_true(audit_record.success);
    jg_logging_shutdown();
    sodium_memzero(&token, sizeof(token));
    sodium_memzero(bootstrap, sizeof(bootstrap));
}

/** @brief Run the serialized management authentication test group. */
int jg_test_management(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_management_consistency),
        cmocka_unit_test_setup_teardown(test_restore_request_exclusion,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_local_administration,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_atomic_user_audit,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_remote_api_authentication,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_browser_authentication,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_browser_login_rate_limit,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_password_change, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_user_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_token_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_certificate_api,
                                        setup_certificate_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_cross_resource_recovery,
                                        setup_certificate_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_backup_creation_recovery,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_cross_resource_audit_failure,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_policy_sync_health,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_mtls_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(
            test_backup_api, setup_certificate_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_job_lifecycle,
                                        setup_certificate_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_backup_restore_api,
                                        setup_certificate_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_configuration_api,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_network_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_source_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_scheduled_source_update,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_event_api, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_request_rejection,
                                        setup_management, teardown_management),
        cmocka_unit_test_setup_teardown(test_system_actions, setup_management,
                                        teardown_management),
        cmocka_unit_test_setup_teardown(test_logging_api, setup_management,
                                        teardown_management),
    };

    return cmocka_run_group_tests_name("management", tests, NULL, NULL);
}
