/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_certificate.c
 * @brief Server-certificate and mutual-TLS management.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "database_internal.h"
#include "janusgate/access.h"
#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/certificate.h"
#include "janusgate/database.h"

/** @brief Convert validated server-certificate metadata to public JSON. */
static json_t *certificate_json(const struct jg_certificate_info *certificate)
{
    char fingerprint[sizeof(certificate->fingerprint_sha256) * 2U + 1U];
    json_t *body = json_object();

    if (sodium_bin2hex(fingerprint, sizeof(fingerprint),
                       certificate->fingerprint_sha256,
                       sizeof(certificate->fingerprint_sha256)) == NULL ||
        body == NULL ||
        json_object_set_new(body, "subject",
                            json_string(certificate->subject)) != 0 ||
        json_object_set_new(body, "issuer", json_string(certificate->issuer)) !=
            0 ||
        json_object_set_new(body, "fingerprint_sha256",
                            json_string(fingerprint)) != 0 ||
        json_object_set_new(
            body, "not_before",
            json_integer((json_int_t)certificate->not_before)) != 0 ||
        json_object_set_new(body, "not_after",
                            json_integer((json_int_t)certificate->not_after)) !=
            0 ||
        json_object_set_new(body, "self_signed",
                            json_boolean(certificate->self_signed)) != 0 ||
        json_object_set_new(body, "private_key_available",
                            json_boolean(certificate->private_key_matches)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert trusted client-authority metadata to public JSON. */
static json_t *certificate_authority_json(
    const struct jg_certificate_info *authority)
{
    char fingerprint[sizeof(authority->fingerprint_sha256) * 2U + 1U];
    json_t *body = json_object();

    if (sodium_bin2hex(fingerprint, sizeof(fingerprint),
                       authority->fingerprint_sha256,
                       sizeof(authority->fingerprint_sha256)) == NULL ||
        body == NULL ||
        json_object_set_new(body, "subject", json_string(authority->subject)) !=
            0 ||
        json_object_set_new(body, "issuer", json_string(authority->issuer)) !=
            0 ||
        json_object_set_new(body, "fingerprint_sha256",
                            json_string(fingerprint)) != 0 ||
        json_object_set_new(body, "not_before",
                            json_integer((json_int_t)authority->not_before)) !=
            0 ||
        json_object_set_new(body, "not_after",
                            json_integer((json_int_t)authority->not_after)) !=
            0 ||
        json_object_set_new(body, "self_signed",
                            json_boolean(authority->self_signed)) != 0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert one client-certificate mapping to public JSON fields. */
static json_t *mtls_mapping_json(const struct jg_account_mtls_mapping *mapping)
{
    char fingerprint[sizeof(mapping->fingerprint_sha256) * 2U + 1U];
    const char *role = management_role_name(mapping->role);
    json_t *body = json_object();

    if (sodium_bin2hex(fingerprint, sizeof(fingerprint),
                       mapping->fingerprint_sha256,
                       sizeof(mapping->fingerprint_sha256)) == NULL ||
        body == NULL ||
        json_object_set_new(
            body, "id", json_integer((json_int_t)mapping->mapping_id)) != 0 ||
        json_object_set_new(body, "fingerprint_sha256",
                            json_string(fingerprint)) != 0 ||
        json_object_set_new(body, "subject", json_string(mapping->subject)) !=
            0 ||
        json_object_set_new(body, "issuer", json_string(mapping->issuer)) !=
            0 ||
        json_object_set_new(body, "not_before",
                            json_integer((json_int_t)mapping->not_before)) !=
            0 ||
        json_object_set_new(body, "not_after",
                            json_integer((json_int_t)mapping->not_after)) !=
            0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)mapping->created_at)) !=
            0 ||
        set_optional_timestamp(body, "revoked_at", mapping->revoked_at) != 0 ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)mapping->revision)) != 0 ||
        json_object_set_new(body, "user_id",
                            mapping->user_id == 0U
                                ? json_null()
                                : json_integer((json_int_t)mapping->user_id)) !=
            0 ||
        json_object_set_new(body, "username",
                            mapping->user_id == 0U
                                ? json_null()
                                : json_string(mapping->username)) != 0 ||
        json_object_set_new(body, "role",
                            role == NULL ? json_null() : json_string(role)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Append one successful server-certificate lifecycle event. */
static int append_certificate_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    const char *common_name,
    const struct jg_certificate_info *certificate,
    uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    char fingerprint[65U] = {0};
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL ||
        details == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 && common_name != NULL &&
        json_object_set_new(details, "common_name", json_string(common_name)) !=
            0) {
        result = -ENOMEM;
    }
    if (result == 0 && certificate != NULL) {
        if (sodium_bin2hex(fingerprint, sizeof(fingerprint),
                           certificate->fingerprint_sha256,
                           sizeof(certificate->fingerprint_sha256)) == NULL ||
            json_object_set_new(details, "subject",
                                json_string(certificate->subject)) != 0 ||
            json_object_set_new(details, "fingerprint_sha256",
                                json_string(fingerprint)) != 0 ||
            json_object_set_new(
                details, "not_after",
                json_integer((json_int_t)certificate->not_after)) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source,
            .action = action,
            .object_type = "certificate",
            .object_id = "server",
            .details = encoded,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one successful client-authority trust-store event. */
static int append_mtls_authority_audit(struct jg_management *management,
                                       const struct management_request *request,
                                       const struct remote_address *remote,
                                       const struct authenticated_actor *actor,
                                       const char *action,
                                       size_t authority_count,
                                       uint64_t now)
{
    char source[INET6_ADDRSTRLEN];
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int result = 0;

    if (inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "authority_count",
                            json_integer((json_int_t)authority_count)) != 0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source,
            .action = action,
            .object_type = "client_trust_store",
            .object_id = "remote_api",
            .details = encoded,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Append one successful client-certificate mapping event. */
static int append_mtls_mapping_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    bool has_previous_revision,
    uint64_t previous_revision,
    const struct jg_account_mtls_mapping *mapping,
    uint64_t now)
{
    char object_id[32U];
    char source[INET6_ADDRSTRLEN];
    char fingerprint[65U];
    const char *role = management_role_name(mapping->role);
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)mapping->mapping_id);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(object_id) ||
        sodium_bin2hex(fingerprint, sizeof(fingerprint),
                       mapping->fingerprint_sha256,
                       sizeof(mapping->fingerprint_sha256)) == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "fingerprint_sha256",
                            json_string(fingerprint)) != 0 ||
        json_object_set_new(details, "user_id",
                            mapping->user_id == 0U
                                ? json_null()
                                : json_integer((json_int_t)mapping->user_id)) !=
            0 ||
        json_object_set_new(details, "role",
                            role == NULL ? json_null() : json_string(role)) !=
            0) {
        result = -ENOMEM;
    }
    if (result == 0) {
        encoded = json_dumps(details, JSON_COMPACT | JSON_SORT_KEYS);
        if (encoded == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        event = (struct jg_audit_event){
            .occurred_at = now,
            .actor_type = actor_audit_type(actor),
            .has_actor_id = actor_has_identifier(actor),
            .actor_id = actor->actor_id,
            .source = source,
            .action = action,
            .object_type = "client_certificate_mapping",
            .object_id = object_id,
            .details = encoded,
            .has_previous_revision = has_previous_revision,
            .previous_revision = previous_revision,
            .has_new_revision = true,
            .new_revision = mapping->revision,
            .success = true,
            .request_id = request->request_id,
        };
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    free(encoded);
    json_decref(details);
    return result;
}

/** @brief Build the private pending-key path next to the server identity. */
int certificate_pending_path(const struct jg_management *management,
                             char path[PATH_MAX])
{
    const int written = snprintf(path, PATH_MAX, "%s.pending-key",
                                 management->certificate_path);

    return written > 0 && written < PATH_MAX ? 0 : -ENOSPC;
}

/** @brief Decode one bounded array of certificate subject alternative names. */
static int certificate_alternative_names(
    const json_t *body,
    const char *names[JG_CERTIFICATE_SAN_MAX],
    size_t *name_count)
{
    json_t *values = json_object_get(body, "alternative_names");
    const size_t count = json_array_size(values);

    *name_count = 0U;
    if (!json_is_array(values) || count > JG_CERTIFICATE_SAN_MAX) {
        return -EINVAL;
    }
    for (size_t index = 0U; index < count; ++index) {
        json_t *value = json_array_get(values, index);
        const char *text = json_string_value(value);
        const size_t text_size =
            bounded_length(text, MANAGEMENT_CERTIFICATE_NAME_MAX);

        if (!json_is_string(value) || text_size == 0U ||
            text_size > MANAGEMENT_CERTIFICATE_NAME_MAX ||
            json_string_length(value) != text_size) {
            return -EINVAL;
        }
        names[index] = text;
    }
    *name_count = count;
    return 0;
}

/** @brief Return current public server-certificate metadata. */
int handle_certificate_show(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written)
{
    struct authenticated_actor actor;
    struct jg_certificate_info certificate;
    json_t *body = NULL;
    json_t *value = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The certificate request is not valid.",
                             request->request_id, output, output_size, written);
    }
    result =
        jg_certificate_inspect_file(management->certificate_path, &certificate);
    if (result == -ENOENT) {
        return respond_error(404, "certificate_not_found",
                             "The server certificate is not installed.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "certificate_unavailable",
                             "The server certificate could not be inspected.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    value = certificate_json(&certificate);
    if (body == NULL || value == NULL ||
        json_object_set(body, "certificate", value) != 0) {
        json_decref(value);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(value);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Execute one CSR while retaining its private key on the appliance. */
int execute_certificate_csr_job(struct jg_management *management,
                                const struct management_job *job,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written)
{
    const struct management_request request = {
        .request_id = job->request_id,
    };
    const struct management_operation_origin operation_origin = {
        .request = &request,
        .remote = &job->remote,
        .actor = &job->actor,
        .action = "certificate.csr",
    };
    struct jg_certificate_material material;
    const char *names[JG_CERTIFICATE_SAN_MAX];
    uint8_t recovery_payload[3U] = {
        MANAGEMENT_RECOVERY_VERSION,
        0U,
        MANAGEMENT_RECOVERY_PENDING_KEY,
    };
    char pending_path[PATH_MAX];
    bool pending_exists = false;
    bool recovery_started = false;
    json_t *body = NULL;
    int result = 0;

    (void)memset(&material, 0, sizeof(material));
    for (size_t index = 0U;
         index < job->parameters.certificate_csr.alternative_name_count;
         ++index) {
        names[index] = job->parameters.certificate_csr.alternative_names[index];
    }
    result = certificate_pending_path(management, pending_path);
    if (result == 0) {
        result = pending_key_present(pending_path, &pending_exists);
    }
    if (result == 0) {
        result = jg_certificate_create_csr(
            job->parameters.certificate_csr.common_name, names,
            job->parameters.certificate_csr.alternative_name_count, &material);
    }
    if (result == 0) {
        recovery_payload[1U] =
            pending_exists ? MANAGEMENT_RECOVERY_PENDING_KEY : 0U;
        result = start_recovery_operation(
            management, MANAGEMENT_OPERATION_CERTIFICATE_CSR, recovery_payload,
            sizeof(recovery_payload), recovery_payload[1U], false,
            &operation_origin, job->started_at);
        recovery_started = result == 0;
    }
    if (result == 0) {
        result = jg_certificate_private_key_store(
            pending_path, material.private_key, material.private_key_size);
    }
    if (result == -EINVAL) {
        jg_certificate_material_clear(&material);
        return respond_error(400, "invalid_certificate_name",
                             "The certificate names are not valid.",
                             request.request_id, output, output_size, written);
    }
    if (result == -EBUSY) {
        jg_certificate_material_clear(&material);
        return respond_error(
            409, "operation_conflict",
            "Another recoverable management operation is in progress.",
            request.request_id, output, output_size, written);
    }
    if (result != 0) {
        if (recovery_started) {
            result = abort_recovery_operation(management, result);
        }
        jg_certificate_material_clear(&material);
        return respond_error(
            result == -EIO ? 503 : 500,
            result == -EIO ? "recovery_failure" : "csr_create_failed",
            result == -EIO
                ? "The failed certificate request could not be recovered."
                : "The certificate request could not be created.",
            request.request_id, output, output_size, written);
    }
    result = jg_database_transaction_begin(management->database);
    if (result == 0) {
        result = append_certificate_audit(
            management, &request, &job->remote, &job->actor, "certificate.csr",
            job->parameters.certificate_csr.common_name, NULL, job->started_at);
    }
    result = finish_recovery_operation(management, result);
    if (result != 0) {
        jg_certificate_material_clear(&material);
        return respond_error(
            500, "audit_failure",
            "The certificate request and pending key were not committed.",
            request.request_id, output, output_size, written);
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(
            body, "request",
            json_stringn(material.request, material.request_size)) != 0 ||
        json_object_set_new(body, "private_key_stored", json_true()) != 0) {
        json_decref(body);
        jg_certificate_material_clear(&material);
        return -ENOMEM;
    }
    jg_certificate_material_clear(&material);
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Queue one private-key and certificate-request generation. */
int handle_certificate_csr(struct jg_management *management,
                           const struct management_request *request,
                           const struct remote_address *remote,
                           uint64_t now,
                           uint8_t *output,
                           size_t output_size,
                           size_t *written)
{
    static const char *const fields[] = {
        "common_name",
        "alternative_names",
    };
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_SECURITY_WRITE,
        .kind = MANAGEMENT_JOB_CERTIFICATE_CSR,
    };
    const char *names[JG_CERTIFICATE_SAN_MAX];
    const char *common_name = NULL;
    size_t name_count = 0U;
    uint64_t job_id = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    common_name = required_string(request->body, "common_name", 1U,
                                  MANAGEMENT_CERTIFICATE_NAME_MAX);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        common_name == NULL ||
        certificate_alternative_names(request->body, names, &name_count) != 0) {
        return respond_error(400, "invalid_body",
                             "The certificate request is not valid.",
                             request->request_id, output, output_size, written);
    }
    (void)memcpy(prepared.parameters.certificate_csr.common_name, common_name,
                 strlen(common_name) + 1U);
    prepared.parameters.certificate_csr.alternative_name_count = name_count;
    for (size_t index = 0U; index < name_count; ++index) {
        (void)memcpy(
            prepared.parameters.certificate_csr.alternative_names[index],
            names[index], strlen(names[index]) + 1U);
    }
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    management_job_parameters_clear(prepared.kind, &prepared.parameters);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The certificate request could not be queued.",
            output, output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
}

/** @brief Install one validated server certificate with concurrency control. */
int handle_certificate_install(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    static const char *const fields[] = {
        "expected_fingerprint",
        "certificate",
        "private_key",
    };
    struct authenticated_actor actor;
    const struct management_operation_origin operation_origin = {
        .request = request,
        .remote = remote,
        .actor = &actor,
        .action = "certificate.install",
    };
    struct jg_certificate_info current;
    struct jg_certificate_info installed;
    uint8_t recovery_payload[3U] = {
        MANAGEMENT_RECOVERY_VERSION,
        0U,
        MANAGEMENT_RECOVERY_CERTIFICATE | MANAGEMENT_RECOVERY_PENDING_KEY,
    };
    uint8_t expected[32U];
    const char *certificate = NULL;
    const char *private_key = NULL;
    char pending_path[PATH_MAX];
    char *loaded_key = NULL;
    size_t certificate_size = 0U;
    size_t private_key_size = 0U;
    bool expected_present = false;
    bool current_present = false;
    bool pending_present = false;
    bool recovery_started = false;
    json_t *body = NULL;
    json_t *value = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    certificate = required_string(request->body, "certificate", 1U,
                                  JG_CERTIFICATE_PEM_MAX);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        certificate == NULL ||
        !required_nullable_string(request->body, "private_key",
                                  JG_CERTIFICATE_PEM_MAX, &private_key) ||
        !required_optional_digest(request->body, "expected_fingerprint",
                                  expected, &expected_present)) {
        return respond_error(400, "invalid_body",
                             "The certificate installation is not valid.",
                             request->request_id, output, output_size, written);
    }
    certificate_size =
        json_string_length(json_object_get(request->body, "certificate"));
    if (private_key != NULL) {
        private_key_size =
            json_string_length(json_object_get(request->body, "private_key"));
    }
    result =
        jg_certificate_inspect_file(management->certificate_path, &current);
    current_present = result == 0;
    if (result != 0 && result != -ENOENT) {
        return respond_error(500, "certificate_unavailable",
                             "The current certificate could not be inspected.",
                             request->request_id, output, output_size, written);
    }
    if (current_present != expected_present ||
        (current_present && sodium_memcmp(current.fingerprint_sha256, expected,
                                          sizeof(expected)) != 0)) {
        return respond_error(
            409, "certificate_conflict",
            "The current certificate has changed; reload and retry.",
            request->request_id, output, output_size, written);
    }
    result = certificate_pending_path(management, pending_path);
    if (result == 0) {
        result = pending_key_present(pending_path, &pending_present);
    }
    if (result == 0 && private_key == NULL) {
        result = jg_certificate_private_key_load(pending_path, &loaded_key,
                                                 &private_key_size);
        private_key = loaded_key;
    }
    if (result == 0) {
        recovery_payload[1U] =
            (current_present ? MANAGEMENT_RECOVERY_CERTIFICATE : 0U) |
            (pending_present ? MANAGEMENT_RECOVERY_PENDING_KEY : 0U);
        result = start_recovery_operation(
            management, MANAGEMENT_OPERATION_CERTIFICATE_INSTALL,
            recovery_payload, sizeof(recovery_payload), recovery_payload[1U],
            false, &operation_origin, now);
        recovery_started = result == 0;
    }
    if (result == 0) {
        result = jg_certificate_install(
            management->certificate_path, certificate, certificate_size,
            private_key, private_key_size, &installed);
    }
    if (loaded_key != NULL) {
        sodium_memzero(loaded_key, private_key_size);
        free(loaded_key);
    }
    if (result == -EBUSY && !recovery_started) {
        return respond_error(
            409, "operation_conflict",
            "Another recoverable management operation is in progress.",
            request->request_id, output, output_size, written);
    }
    if (result == -ENOENT) {
        return respond_error(
            409, "pending_key_not_found",
            "No pending private key is available for this certificate.",
            request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -EACCES) {
        if (recovery_started &&
            abort_recovery_operation(management, result) == -EIO) {
            return respond_error(
                503, "recovery_failure",
                "The failed certificate installation could not be recovered.",
                request->request_id, output, output_size, written);
        }
        return respond_error(400, "invalid_certificate",
                             "The certificate or its private key is not valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        if (recovery_started) {
            result = abort_recovery_operation(management, result);
        }
        return respond_error(
            result == -EIO ? 503 : 500,
            result == -EIO ? "recovery_failure" : "certificate_install_failed",
            result == -EIO
                ? "The failed certificate installation could not be recovered."
                : "The server certificate could not be installed.",
            request->request_id, output, output_size, written);
    }
    result = jg_certificate_private_key_remove(pending_path);
    if (result == -ENOENT) {
        result = 0;
    }
    if (result != 0) {
        result = abort_recovery_operation(management, result);
        return respond_error(
            result == -EIO ? 503 : 500, "pending_key_cleanup_failed",
            result == -EIO
                ? "Pending-key cleanup failed and recovery was incomplete."
                : "Pending-key cleanup failed; the previous state was "
                  "restored.",
            request->request_id, output, output_size, written);
    }
    result = jg_database_transaction_begin(management->database);
    if (result == 0) {
        result = append_certificate_audit(management, request, remote, &actor,
                                          "certificate.install", NULL,
                                          &installed, now);
    }
    result = finish_recovery_operation(management, result);
    if (result != 0) {
        return respond_error(500, "audit_failure",
                             "The certificate installation was not committed.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    value = certificate_json(&installed);
    if (body == NULL || value == NULL ||
        json_object_set(body, "certificate", value) != 0 ||
        json_object_set_new(body, "reload_required", json_true()) != 0) {
        json_decref(value);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(value);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Encode the installed client-authority trust-store state. */
static int respond_mtls_authorities(
    const struct jg_certificate_info *authorities,
    size_t authority_count,
    bool configured,
    bool reload_required,
    int status,
    uint8_t *output,
    size_t output_size,
    size_t *written)
{
    json_t *body = json_object();
    json_t *items = json_array();
    int result = 0;

    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < authority_count; ++index) {
        json_t *item = certificate_authority_json(&authorities[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "configured", json_boolean(configured)) !=
             0 ||
         json_object_set(body, "authorities", items) != 0 ||
         json_object_set_new(body, "reload_required",
                             json_boolean(reload_required)) != 0)) {
        result = -ENOMEM;
    }
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(status, body, NULL, output, output_size, written);
}

/** @brief Return the installed client-authority trust-store state. */
int handle_mtls_authorities_show(struct jg_management *management,
                                 const struct management_request *request,
                                 const struct remote_address *remote,
                                 uint64_t now,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written)
{
    struct authenticated_actor actor;
    struct jg_certificate_info *authorities = NULL;
    size_t authority_count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The client-authority request is not valid.",
                             request->request_id, output, output_size, written);
    }
    authorities = calloc(JG_CERTIFICATE_AUTHORITY_MAX, sizeof(*authorities));
    if (authorities == NULL) {
        return -ENOMEM;
    }
    result = jg_certificate_trust_store_inspect_file(
        management->client_ca_path, authorities, JG_CERTIFICATE_AUTHORITY_MAX,
        &authority_count);
    if (result == -ENOENT) {
        result = respond_mtls_authorities(NULL, 0U, false, false, 200, output,
                                          output_size, written);
    } else if (result != 0) {
        result = respond_error(
            500, "client_authorities_unavailable",
            "The client-certificate authorities could not be inspected.",
            request->request_id, output, output_size, written);
    } else {
        result =
            respond_mtls_authorities(authorities, authority_count, true, false,
                                     200, output, output_size, written);
    }
    free(authorities);
    return result;
}

/** @brief Validate and install a client-authority trust-store bundle. */
int handle_mtls_authorities_install(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    uint64_t now,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *written)
{
    static const char *const fields[] = {
        "certificate_authorities",
    };
    struct authenticated_actor actor;
    const struct management_operation_origin operation_origin = {
        .request = request,
        .remote = remote,
        .actor = &actor,
        .action = "mtls.authorities.install",
    };
    struct jg_certificate_info *authorities = NULL;
    uint8_t recovery_payload[3U] = {
        MANAGEMENT_RECOVERY_VERSION,
        0U,
        MANAGEMENT_RECOVERY_CLIENT_CA,
    };
    const char *pem = NULL;
    size_t pem_size = 0U;
    size_t authority_count = 0U;
    bool existing = false;
    bool recovery_started = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    pem = required_string(request->body, "certificate_authorities", 1U,
                          JG_CERTIFICATE_PEM_MAX);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        pem == NULL) {
        return respond_error(400, "invalid_body",
                             "The client-authority bundle is not valid.",
                             request->request_id, output, output_size, written);
    }
    pem_size = json_string_length(
        json_object_get(request->body, "certificate_authorities"));
    authorities = calloc(JG_CERTIFICATE_AUTHORITY_MAX, sizeof(*authorities));
    if (authorities == NULL) {
        return -ENOMEM;
    }
    result = jg_certificate_trust_store_inspect(pem, pem_size, authorities,
                                                JG_CERTIFICATE_AUTHORITY_MAX,
                                                &authority_count);
    if (result == -EINVAL || result == -ENOSPC || result == -EACCES) {
        free(authorities);
        return respond_error(
            400, "invalid_client_authorities",
            "The bundle must contain only unique CA certificates.",
            request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = client_ca_present(management->client_ca_path, &existing);
    }
    if (result == 0) {
        recovery_payload[1U] = existing ? MANAGEMENT_RECOVERY_CLIENT_CA : 0U;
        result = start_recovery_operation(
            management, MANAGEMENT_OPERATION_MTLS_AUTHORITIES, recovery_payload,
            sizeof(recovery_payload), recovery_payload[1U], false,
            &operation_origin, now);
        recovery_started = result == 0;
    }
    if (result == 0) {
        result = jg_certificate_trust_store_install(
            management->client_ca_path, pem, pem_size, authorities,
            JG_CERTIFICATE_AUTHORITY_MAX, &authority_count);
    }
    if (result == -EBUSY && !recovery_started) {
        free(authorities);
        return respond_error(
            409, "operation_conflict",
            "Another recoverable management operation is in progress.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        if (recovery_started) {
            result = abort_recovery_operation(management, result);
        }
        free(authorities);
        return respond_error(
            result == -EIO ? 503 : 500,
            result == -EIO ? "recovery_failure"
                           : "client_authorities_install_failed",
            result == -EIO
                ? "The failed trust-store installation could not be recovered."
                : "The client-certificate authorities could not be installed.",
            request->request_id, output, output_size, written);
    }
    result = jg_database_transaction_begin(management->database);
    if (result == 0) {
        result = append_mtls_authority_audit(management, request, remote,
                                             &actor, "mtls.authorities.install",
                                             authority_count, now);
    }
    result = finish_recovery_operation(management, result);
    if (result != 0) {
        free(authorities);
        return respond_error(500, "audit_failure",
                             "The trust-store installation was not committed.",
                             request->request_id, output, output_size, written);
    }
    result = respond_mtls_authorities(authorities, authority_count, true, true,
                                      200, output, output_size, written);
    free(authorities);
    return result;
}

/** @brief Remove the client-authority trust store and disable remote mTLS. */
int handle_mtls_authorities_remove(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written)
{
    struct authenticated_actor actor;
    const struct management_operation_origin operation_origin = {
        .request = request,
        .remote = remote,
        .actor = &actor,
        .action = "mtls.authorities.remove",
    };
    struct jg_certificate_info *authorities = NULL;
    uint8_t recovery_payload[3U] = {
        MANAGEMENT_RECOVERY_VERSION,
        0U,
        MANAGEMENT_RECOVERY_CLIENT_CA,
    };
    size_t authority_count = 0U;
    bool existing = true;
    bool recovery_started = false;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The client-authority removal is not valid.",
                             request->request_id, output, output_size, written);
    }
    authorities = calloc(JG_CERTIFICATE_AUTHORITY_MAX, sizeof(*authorities));
    if (authorities == NULL) {
        return -ENOMEM;
    }
    result = jg_certificate_trust_store_inspect_file(
        management->client_ca_path, authorities, JG_CERTIFICATE_AUTHORITY_MAX,
        &authority_count);
    if (result == -ENOENT) {
        authority_count = 0U;
        existing = false;
        result = 0;
    }
    free(authorities);
    if (result != 0) {
        return respond_error(
            500, "client_authorities_unavailable",
            "The client-certificate authorities could not be inspected.",
            request->request_id, output, output_size, written);
    }
    recovery_payload[1U] = existing ? MANAGEMENT_RECOVERY_CLIENT_CA : 0U;
    result = start_recovery_operation(
        management, MANAGEMENT_OPERATION_MTLS_AUTHORITIES, recovery_payload,
        sizeof(recovery_payload), recovery_payload[1U], false,
        &operation_origin, now);
    recovery_started = result == 0;
    if (result == -EBUSY) {
        return respond_error(
            409, "operation_conflict",
            "Another recoverable management operation is in progress.",
            request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(
            503, "recovery_unavailable",
            "Durable trust-store recovery could not be prepared.",
            request->request_id, output, output_size, written);
    }
    result = jg_certificate_trust_store_remove(management->client_ca_path);
    if (result != 0) {
        if (recovery_started) {
            result = abort_recovery_operation(management, result);
        }
        return respond_error(
            result == -EIO ? 503 : 500,
            result == -EIO ? "recovery_failure"
                           : "client_authorities_remove_failed",
            result == -EIO
                ? "The failed trust-store removal could not be recovered."
                : "The client-certificate authorities could not be removed.",
            request->request_id, output, output_size, written);
    }
    result = jg_database_transaction_begin(management->database);
    if (result == 0) {
        result = append_mtls_authority_audit(management, request, remote,
                                             &actor, "mtls.authorities.remove",
                                             authority_count, now);
    }
    result = finish_recovery_operation(management, result);
    if (result != 0) {
        return respond_error(500, "audit_failure",
                             "The trust-store removal was not committed.",
                             request->request_id, output, output_size, written);
    }
    return respond_mtls_authorities(NULL, 0U, false, true, 200, output,
                                    output_size, written);
}

/** @brief Return one authenticated stable page of certificate mappings. */
int handle_mtls_mappings_list(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    struct authenticated_actor actor;
    struct jg_account_mtls_mapping *mappings = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t offset = 0U;
    uint64_t total = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "offset", JG_ACCOUNT_MTLS_PAGE_MAX,
                         &offset, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The mapping pagination parameters are not valid.",
                             request->request_id, output, output_size, written);
    }
    mappings = calloc(limit, sizeof(*mappings));
    if (mappings == NULL) {
        return -ENOMEM;
    }
    result = jg_account_mtls_mapping_list(management->database, offset,
                                          mappings, limit, &count, &total);
    if (result != 0) {
        free(mappings);
        return respond_error(
            500, "mtls_mappings_unavailable",
            "The client-certificate mappings could not be read.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = mtls_mapping_json(&mappings[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "offset",
                             json_integer((json_int_t)offset)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "total", json_integer((json_int_t)total)) !=
             0 ||
         json_object_set(body, "mappings", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        const uint64_t next = offset + (uint64_t)count;
        json_t *next_value = count > 0U && next < total
                                 ? json_integer((json_int_t)next)
                                 : json_null();

        if (json_object_set_new(body, "next_offset", next_value) != 0) {
            result = -ENOMEM;
        }
    }
    free(mappings);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Create a user- or role-bound client-certificate mapping. */
int handle_mtls_mapping_create(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    static const char *const fields[] = {
        "certificate",
        "user_id",
        "role",
    };
    struct authenticated_actor actor;
    struct jg_certificate_info certificate;
    struct jg_account_mtls_mapping_config config;
    struct jg_account_mtls_mapping mapping = {0};
    json_t *user_value = json_object_get(request->body, "user_id");
    json_t *role_value = json_object_get(request->body, "role");
    const char *certificate_pem = NULL;
    const char *role_text = NULL;
    size_t certificate_size = 0U;
    json_int_t user_id = 0;
    json_t *body = NULL;
    json_t *mapping_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    certificate_pem = required_string(request->body, "certificate", 1U,
                                      JG_CERTIFICATE_PEM_MAX);
    if (json_is_integer(user_value)) {
        user_id = json_integer_value(user_value);
    }
    if (json_is_string(role_value)) {
        role_text = json_string_value(role_value);
    }
    (void)memset(&config, 0, sizeof(config));
    config.user_id = user_id > 0 ? (uint64_t)user_id : 0U;
    config.role = management_parse_role(role_text);
    if (request->query[0U] != '\0' ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        certificate_pem == NULL ||
        !((config.user_id != 0U && json_is_null(role_value)) ||
          (json_is_null(user_value) && config.role != JG_ACCESS_ROLE_NONE))) {
        return respond_error(400, "invalid_body",
                             "Map the certificate to exactly one user or role.",
                             request->request_id, output, output_size, written);
    }
    certificate_size =
        json_string_length(json_object_get(request->body, "certificate"));
    result = jg_certificate_client_validate(certificate_pem, certificate_size,
                                            management->client_ca_path,
                                            &certificate);
    if (result == -ENOENT) {
        return respond_error(409, "client_ca_not_configured",
                             "Install the client certificate authority first.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EINVAL || result == -EACCES) {
        return respond_error(400, "invalid_client_certificate",
                             "The client certificate is not valid for the "
                             "installed trust store.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(500, "client_certificate_validation_failed",
                             "The client certificate could not be validated.",
                             request->request_id, output, output_size, written);
    }
    (void)memcpy(config.fingerprint_sha256, certificate.fingerprint_sha256,
                 sizeof(config.fingerprint_sha256));
    config.subject = certificate.subject;
    config.issuer = certificate.issuer;
    config.not_before = certificate.not_before;
    config.not_after = certificate.not_after;
    result = audited_mutation_begin(management);
    if (result == 0) {
        result = jg_account_mtls_mapping_create(management->database, &config,
                                                now, &mapping);
    }
    result = audited_mutation_check(management, result);
    if (result == -ENOENT) {
        return respond_error(404, "user_not_found",
                             "The selected local user was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EEXIST) {
        return respond_error(409, "mtls_mapping_exists",
                             "The client certificate is already mapped.",
                             request->request_id, output, output_size, written);
    }
    if (result == -EACCES) {
        return respond_error(400, "client_certificate_expired",
                             "The client certificate is not currently valid.",
                             request->request_id, output, output_size, written);
    }
    if (result != 0) {
        return respond_error(
            500, "mtls_mapping_create_failed",
            "The client-certificate mapping could not be created.",
            request->request_id, output, output_size, written);
    }
    result = append_mtls_mapping_audit(management, request, remote, &actor,
                                       "mtls.mapping.create", false, 0U,
                                       &mapping, now);
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The mapping creation and its audit record were not committed.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    mapping_body = mtls_mapping_json(&mapping);
    if (body == NULL || mapping_body == NULL ||
        json_object_set(body, "mapping", mapping_body) != 0) {
        json_decref(mapping_body);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(mapping_body);
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Revoke one client-certificate mapping idempotently. */
int handle_mtls_mapping_revoke(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t mapping_id,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    struct authenticated_actor actor;
    struct jg_account_mtls_mapping previous = {0};
    struct jg_account_mtls_mapping mapping = {0};
    json_t *body = NULL;
    json_t *mapping_body = NULL;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_SECURITY_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "The mapping revocation is not valid.",
                             request->request_id, output, output_size, written);
    }
    result = jg_account_mtls_mapping_get(management->database, mapping_id,
                                         &previous);
    if (result == -ENOENT) {
        return respond_error(404, "mtls_mapping_not_found",
                             "The client-certificate mapping was not found.",
                             request->request_id, output, output_size, written);
    }
    if (result == 0) {
        result = audited_mutation_begin(management);
    }
    if (result == 0) {
        result = jg_account_mtls_mapping_revoke(management->database,
                                                mapping_id, now);
    }
    result = audited_mutation_check(management, result);
    if (result == 0) {
        result = jg_account_mtls_mapping_get(management->database, mapping_id,
                                             &mapping);
    }
    result = audited_mutation_check(management, result);
    if (result != 0) {
        return respond_error(
            500, "mtls_mapping_revoke_failed",
            "The client-certificate mapping could not be revoked.",
            request->request_id, output, output_size, written);
    }
    result = append_mtls_mapping_audit(management, request, remote, &actor,
                                       "mtls.mapping.revoke", true,
                                       previous.revision, &mapping, now);
    result = audited_mutation_finish(management, result, false);
    if (result != 0) {
        return respond_error(
            500, "audit_failure",
            "The mapping revocation and its audit record were not committed.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    mapping_body = mtls_mapping_json(&mapping);
    if (body == NULL || mapping_body == NULL ||
        json_object_set(body, "mapping", mapping_body) != 0) {
        json_decref(mapping_body);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(mapping_body);
    return encode_response(200, body, NULL, output, output_size, written);
}
