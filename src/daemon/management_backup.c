/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_backup.c
 * @brief Authenticated backup creation, inspection, and recovery.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "database_internal.h"
#include "janusgate/access.h"
#include "janusgate/backup.h"
#include "janusgate/certificate.h"

/** Optional relationship between a restore and its automatic checkpoint. */
struct backup_audit_relationship {
    uint64_t restore_backup_id;
    uint64_t checkpoint_id;
    const char *restore_request_id;
};

/** Audit context completed with newly stored backup metadata. */
struct backup_creation_audit {
    struct jg_management *management;
    const struct management_request *request;
    const struct remote_address *remote;
    const struct authenticated_actor *actor;
    const char *action;
    struct backup_audit_relationship relationship;
    uint64_t now;
};

/** @brief Return the stable external name for one backup kind. */
static const char *backup_kind_name(enum jg_backup_kind kind)
{
    if (kind == JG_BACKUP_CONFIGURATION) {
        return "configuration";
    }
    if (kind == JG_BACKUP_FULL) {
        return "full";
    }
    return NULL;
}

/** @brief Parse one stable external backup kind. */
static enum jg_backup_kind parse_backup_kind(const char *name)
{
    if (name != NULL && strcmp(name, "configuration") == 0) {
        return JG_BACKUP_CONFIGURATION;
    }
    if (name != NULL && strcmp(name, "full") == 0) {
        return JG_BACKUP_FULL;
    }
    return 0;
}

/** @brief Convert persistent backup metadata to public JSON fields. */
static json_t *backup_json(const struct jg_database_backup *backup)
{
    char checksum[sizeof(backup->checksum) * 2U + 1U];
    const char *kind = backup_kind_name(backup->kind);
    json_t *body = json_object();

    if (kind == NULL ||
        sodium_bin2hex(checksum, sizeof(checksum), backup->checksum,
                       sizeof(backup->checksum)) == NULL ||
        body == NULL ||
        json_object_set_new(body, "id", json_integer((json_int_t)backup->id)) !=
            0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)backup->created_at)) !=
            0 ||
        json_object_set_new(body, "kind", json_string(kind)) != 0 ||
        json_object_set_new(body, "encrypted",
                            json_boolean(backup->kind == JG_BACKUP_FULL)) !=
            0 ||
        json_object_set_new(body, "checksum_sha256", json_string(checksum)) !=
            0 ||
        json_object_set_new(body, "schema_version",
                            json_integer((json_int_t)backup->schema_version)) !=
            0 ||
        json_object_set_new(body, "size_bytes",
                            json_integer((json_int_t)backup->size_bytes)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert a validated archive manifest to public JSON fields. */
static json_t *backup_manifest_json(const struct jg_backup_info *info)
{
    const char *kind = backup_kind_name(info->kind);
    json_t *body = json_object();

    if (kind == NULL || body == NULL ||
        json_object_set_new(body, "kind", json_string(kind)) != 0 ||
        json_object_set_new(body, "format_version",
                            json_integer(info->format_version)) != 0 ||
        json_object_set_new(body, "compatible_version_min",
                            json_integer(info->compatible_version_min)) != 0 ||
        json_object_set_new(body, "compatible_version_max",
                            json_integer(info->compatible_version_max)) != 0 ||
        json_object_set_new(body, "schema_version",
                            json_integer((json_int_t)info->schema_version)) !=
            0 ||
        json_object_set_new(body, "created_at",
                            json_integer((json_int_t)info->created_at)) != 0 ||
        json_object_set_new(body, "database_size",
                            json_integer((json_int_t)info->database_size)) !=
            0 ||
        json_object_set_new(body, "certificate_size",
                            json_integer((json_int_t)info->certificate_size)) !=
            0 ||
        json_object_set_new(body, "totp_key_size",
                            json_integer((json_int_t)info->totp_key_size)) !=
            0 ||
        json_object_set_new(body, "client_ca_size",
                            json_integer((json_int_t)info->client_ca_size)) !=
            0 ||
        json_object_set_new(body, "archive_size",
                            json_integer((json_int_t)info->archive_size)) !=
            0 ||
        json_object_set_new(body, "encrypted", json_boolean(info->encrypted)) !=
            0 ||
        json_object_set_new(body, "portable", json_boolean(info->portable)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Convert one database restore comparison to public JSON fields. */
static json_t *restore_report_json(
    const struct jg_database_restore_report *report)
{
    char current[sizeof(report->current_checksum) * 2U + 1U];
    char replacement[sizeof(report->replacement_checksum) * 2U + 1U];
    json_t *body = json_object();

    if (sodium_bin2hex(current, sizeof(current), report->current_checksum,
                       sizeof(report->current_checksum)) == NULL ||
        sodium_bin2hex(replacement, sizeof(replacement),
                       report->replacement_checksum,
                       sizeof(report->replacement_checksum)) == NULL ||
        body == NULL ||
        json_object_set_new(body, "schema_version",
                            json_integer((json_int_t)report->schema_version)) !=
            0 ||
        json_object_set_new(body, "current_size",
                            json_integer((json_int_t)report->current_size)) !=
            0 ||
        json_object_set_new(
            body, "replacement_size",
            json_integer((json_int_t)report->replacement_size)) != 0 ||
        json_object_set_new(body, "current_checksum_sha256",
                            json_string(current)) != 0 ||
        json_object_set_new(body, "replacement_checksum_sha256",
                            json_string(replacement)) != 0 ||
        json_object_set_new(body, "changes", json_boolean(report->changes)) !=
            0) {
        json_decref(body);
        return NULL;
    }
    return body;
}

/** @brief Append one successful backup lifecycle event without secrets. */
static int append_backup_audit(
    struct jg_management *management,
    const struct management_request *request,
    const struct remote_address *remote,
    const struct authenticated_actor *actor,
    const char *action,
    const struct jg_database_backup *backup,
    const struct jg_database_restore_report *report,
    bool dry_run,
    const struct backup_audit_relationship *relationship,
    uint64_t now)
{
    char object_id[32U];
    char source[INET6_ADDRSTRLEN];
    char checksum[sizeof(backup->checksum) * 2U + 1U];
    const char *kind = backup_kind_name(backup->kind);
    json_t *details = json_object();
    char *encoded = NULL;
    struct jg_audit_event event;
    int written = snprintf(object_id, sizeof(object_id), "%llu",
                           (unsigned long long)backup->id);
    int result = 0;

    if (written <= 0 || (size_t)written >= sizeof(object_id) || kind == NULL ||
        inet_ntop(remote->family == JG_POLICY_ADDRESS_IPV4 ? AF_INET : AF_INET6,
                  remote->address, source, sizeof(source)) == NULL ||
        sodium_bin2hex(checksum, sizeof(checksum), backup->checksum,
                       sizeof(backup->checksum)) == NULL ||
        details == NULL ||
        json_object_set_new(details, "kind", json_string(kind)) != 0 ||
        json_object_set_new(details, "checksum_sha256",
                            json_string(checksum)) != 0 ||
        json_object_set_new(details, "schema_version",
                            json_integer((json_int_t)backup->schema_version)) !=
            0 ||
        json_object_set_new(details, "size_bytes",
                            json_integer((json_int_t)backup->size_bytes)) !=
            0) {
        result = -ENOMEM;
    }
    if (result == 0 && report != NULL &&
        (json_object_set_new(details, "dry_run", json_boolean(dry_run)) != 0 ||
         json_object_set_new(details, "changes",
                             json_boolean(report->changes)) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0 && relationship != NULL &&
        ((relationship->restore_backup_id != 0U &&
          json_object_set_new(
              details, "restore_backup_id",
              json_integer((json_int_t)relationship->restore_backup_id)) !=
              0) ||
         (relationship->checkpoint_id != 0U &&
          json_object_set_new(
              details, "checkpoint_id",
              json_integer((json_int_t)relationship->checkpoint_id)) != 0) ||
         (relationship->restore_request_id != NULL &&
          json_object_set_new(details, "restore_request_id",
                              json_string(relationship->restore_request_id)) !=
              0))) {
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
            .object_type = "backup",
            .object_id = object_id,
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

/** @brief Append backup creation audit inside its metadata transaction. */
static int complete_backup_creation(void *context,
                                    const struct jg_database_backup *created)
{
    const struct backup_creation_audit *audit = context;

    return append_backup_audit(audit->management, audit->request, audit->remote,
                               audit->actor, audit->action, created, NULL,
                               false, &audit->relationship, audit->now);
}

/** Completion invoked while newly stored backup metadata is transactional. */
typedef int (*backup_creation_completion)(
    void *context,
    const struct jg_database_backup *created);

/** @brief Store and transactionally record one validated backup archive. */
static int record_backup_archive(
    struct jg_management *management,
    const uint8_t *archive,
    size_t archive_size,
    const struct jg_backup_info *info,
    uint64_t now,
    const struct management_operation_origin *origin,
    backup_creation_completion completion,
    void *context,
    struct jg_database_backup *created)
{
    uint8_t suffix[8U];
    uint8_t recovery_payload[1U + JG_BACKUP_FILENAME_MAX];
    char suffix_text[sizeof(suffix) * 2U + 1U];
    struct jg_database_backup metadata = {0};
    bool journal_started = false;
    bool transaction_started = false;
    int result = 0;
    int written = 0;

    if (management == NULL || archive == NULL || archive_size == 0U ||
        info == NULL || origin == NULL || created == NULL) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    randombytes_buf(suffix, sizeof(suffix));
    if (sodium_bin2hex(suffix_text, sizeof(suffix_text), suffix,
                       sizeof(suffix)) == NULL) {
        result = -EIO;
    }
    if (result == 0) {
        written = snprintf(metadata.filename, sizeof(metadata.filename),
                           "backup-%llu-%s.jgb", (unsigned long long)now,
                           suffix_text);
        if (written <= 0 || (size_t)written >= sizeof(metadata.filename)) {
            result = -EOVERFLOW;
        }
    }
    if (result == 0) {
        const size_t filename_size = strlen(metadata.filename);

        recovery_payload[0U] = MANAGEMENT_RECOVERY_VERSION;
        (void)memcpy(recovery_payload + 1U, metadata.filename, filename_size);
        result = start_recovery_operation(
            management, MANAGEMENT_OPERATION_BACKUP_CREATE, recovery_payload,
            filename_size + 1U, 0U, false, origin, now);
        journal_started = result == 0;
    }
    if (result == 0) {
        result = jg_backup_store(management->backup_directory,
                                 metadata.filename, archive, archive_size);
    }
    if (result == 0) {
        metadata.created_at = info->created_at;
        metadata.kind = info->kind;
        (void)memcpy(metadata.checksum, info->checksum,
                     sizeof(metadata.checksum));
        metadata.schema_version = info->schema_version;
        metadata.size_bytes = archive_size;
        result = jg_database_transaction_begin(management->database);
        transaction_started = result == 0;
    }
    if (result == 0) {
        result =
            jg_database_create_backup(management->database, &metadata, created);
    }
    if (result == 0 && completion != NULL) {
        result = completion(context, created);
    }
    if (result == 0) {
        result = jg_database_operation_clear(management->database);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(management->database);
        transaction_started = result != 0;
        journal_started = result != 0;
    }
    if (result != 0 && transaction_started &&
        jg_database_transaction_rollback(management->database) != 0) {
        result = -EIO;
    }
    if (result != 0 && journal_started) {
        result = abort_recovery_operation(management, result);
    }
    sodium_memzero(suffix, sizeof(suffix));
    return result;
}

/** @brief Create, store, and transactionally record one backup archive. */
static int create_backup(struct jg_management *management,
                         enum jg_backup_kind kind,
                         bool include_private_key,
                         const char *passphrase,
                         size_t passphrase_size,
                         uint64_t now,
                         const struct management_operation_origin *origin,
                         backup_creation_completion completion,
                         void *context,
                         struct jg_database_backup *created)
{
    char *certificate = NULL;
    char *client_ca = NULL;
    uint8_t *database = NULL;
    uint8_t *archive = NULL;
    size_t certificate_size = 0U;
    size_t client_ca_size = 0U;
    size_t database_size = 0U;
    size_t archive_size = 0U;
    struct jg_backup_payload payload;
    struct jg_backup_info info;
    int result = 0;

    if (management == NULL || origin == NULL || created == NULL ||
        (kind == JG_BACKUP_CONFIGURATION && include_private_key)) {
        return -EINVAL;
    }
    (void)memset(created, 0, sizeof(*created));
    (void)memset(&payload, 0, sizeof(payload));
    result = jg_database_export(management->database, kind == JG_BACKUP_FULL,
                                &database, &database_size);
    if (result == 0) {
        result = jg_certificate_export_file(management->certificate_path,
                                            include_private_key, &certificate,
                                            &certificate_size);
        if (result == -ENOENT) {
            result = 0;
        }
    }
    if (result == 0) {
        payload.database = database;
        payload.database_size = database_size;
        payload.certificate = (const uint8_t *)certificate;
        payload.certificate_size = certificate_size;
        if (kind == JG_BACKUP_FULL) {
            payload.totp_key = management->secrets->totp_key;
            payload.totp_key_size = JG_AUTH_TOTP_KEY_SIZE;
            result = jg_certificate_trust_store_export_file(
                management->client_ca_path, &client_ca, &client_ca_size);
            if (result == -ENOENT) {
                result = 0;
            }
            payload.client_ca = (const uint8_t *)client_ca;
            payload.client_ca_size = client_ca_size;
        }
        if (result == 0) {
            result = jg_backup_create(
                kind, &payload, passphrase, passphrase_size, now,
                JG_DATABASE_SCHEMA_VERSION, &archive, &archive_size);
        }
    }
    if (result == 0) {
        result = jg_backup_inspect(archive, archive_size, &info);
    }
    if (result == 0) {
        result =
            record_backup_archive(management, archive, archive_size, &info, now,
                                  origin, completion, context, created);
    }
    jg_backup_data_clear(archive, archive_size);
    jg_database_export_clear(database, database_size);
    jg_certificate_pem_clear(certificate, certificate_size);
    jg_certificate_pem_clear(client_ca, client_ca_size);
    return result;
}

/** @brief Load and cross-check one recorded backup archive. */
static int load_backup(struct jg_management *management,
                       uint64_t backup_id,
                       struct jg_database_backup *metadata,
                       uint8_t **archive,
                       size_t *archive_size,
                       struct jg_backup_info *info)
{
    int result = 0;

    if (management == NULL || metadata == NULL || archive == NULL ||
        archive_size == NULL || info == NULL) {
        return -EINVAL;
    }
    *archive = NULL;
    *archive_size = 0U;
    (void)memset(metadata, 0, sizeof(*metadata));
    (void)memset(info, 0, sizeof(*info));
    result = jg_database_load_backup(management->database, backup_id, metadata);
    if (result == 0) {
        result = jg_backup_load(management->backup_directory,
                                metadata->filename, archive, archive_size);
    }
    if (result == 0) {
        result = jg_backup_inspect(*archive, *archive_size, info);
    }
    if (result == 0 && (*archive_size != metadata->size_bytes ||
                        info->archive_size != metadata->size_bytes ||
                        info->created_at != metadata->created_at ||
                        info->kind != metadata->kind ||
                        info->schema_version != metadata->schema_version ||
                        sodium_memcmp(info->checksum, metadata->checksum,
                                      sizeof(metadata->checksum)) != 0)) {
        result = -EBADMSG;
    }
    if (result != 0) {
        jg_backup_data_clear(*archive, *archive_size);
        *archive = NULL;
        *archive_size = 0U;
        (void)memset(info, 0, sizeof(*info));
    }
    return result;
}

/** @brief Parse one exact local backup transfer request body. */
static const char *backup_transfer_path(
    const struct management_request *request)
{
    static const char *const fields[] = {"path"};

    if (request->query[0U] != '\0' || json_object_size(request->body) != 1U ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U]))) {
        return NULL;
    }
    return required_string(request->body, "path", 2U, PATH_MAX - 1U);
}

/** @brief Import one private local archive into managed backup storage. */
int handle_backup_import(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    struct backup_creation_audit audit;
    struct management_operation_origin origin;
    struct jg_backup_info info;
    struct jg_database_backup created;
    const char *path = NULL;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;
    json_t *body = NULL;
    json_t *backup = NULL;
    json_t *manifest = NULL;
    int result = 0;

    if (!request->local_administrator) {
        return respond_error(404, "not_found",
                             "The requested API resource was not found.",
                             request->request_id, output, output_size, written);
    }
    result = authenticate_actor(management, request, remote, true,
                                JG_ACCESS_BACKUPS_WRITE, now, &actor);
    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    path = backup_transfer_path(request);
    if (path == NULL || path[0U] != '/') {
        return respond_error(400, "invalid_body",
                             "An absolute private archive path is required.",
                             request->request_id, output, output_size, written);
    }
    result = jg_backup_load_path(path, &archive, &archive_size);
    if (result == 0) {
        result = jg_backup_inspect(archive, archive_size, &info);
    }
    if (result != 0) {
        jg_backup_data_clear(archive, archive_size);
        return respond_error(
            result == -ENOENT ? 404 : 409,
            result == -ENOENT ? "backup_file_not_found" : "backup_invalid",
            result == -ENOENT
                ? "The local backup archive does not exist."
                : "The local archive is insecure, malformed, or incompatible.",
            request->request_id, output, output_size, written);
    }
    audit = (struct backup_creation_audit){
        .management = management,
        .request = request,
        .remote = remote,
        .actor = &actor,
        .action = "backup.import",
        .now = now,
    };
    origin = (struct management_operation_origin){
        .request = request,
        .remote = remote,
        .actor = &actor,
        .action = "backup.import",
    };

    result = record_backup_archive(management, archive, archive_size, &info,
                                   now, &origin, complete_backup_creation,
                                   &audit, &created);
    jg_backup_data_clear(archive, archive_size);
    if (result != 0) {
        return respond_error(500, "backup_import_failed",
                             "The backup archive could not be imported.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    backup = backup_json(&created);
    manifest = backup_manifest_json(&info);
    if (body == NULL || backup == NULL || manifest == NULL ||
        json_object_set(body, "backup", backup) != 0 ||
        json_object_set(body, "manifest", manifest) != 0) {
        result = -ENOMEM;
    }
    json_decref(backup);
    json_decref(manifest);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Export one managed archive to a private local path. */
int handle_backup_export(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t backup_id,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_backup metadata;
    struct jg_backup_info info;
    const char *path = NULL;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;
    bool exported = false;
    bool transaction_started = false;
    json_t *body = NULL;
    json_t *backup = NULL;
    int result = 0;

    if (!request->local_administrator) {
        return respond_error(404, "not_found",
                             "The requested API resource was not found.",
                             request->request_id, output, output_size, written);
    }
    result = authenticate_actor(management, request, remote, true,
                                JG_ACCESS_BACKUPS_WRITE, now, &actor);
    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    path = backup_transfer_path(request);
    if (path == NULL || path[0U] != '/') {
        return respond_error(400, "invalid_body",
                             "An absolute private archive path is required.",
                             request->request_id, output, output_size, written);
    }
    result = load_backup(management, backup_id, &metadata, &archive,
                         &archive_size, &info);
    if (result != 0) {
        const bool missing = result == -ENOENT && metadata.id == 0U;

        return respond_error(
            missing ? 404 : 409,
            missing ? "backup_not_found" : "backup_invalid",
            missing ? "The requested backup does not exist."
                    : "The recorded backup archive is missing or invalid.",
            request->request_id, output, output_size, written);
    }
    result = jg_backup_store_path(path, archive, archive_size);
    exported = result == 0;
    jg_backup_data_clear(archive, archive_size);
    if (result == 0) {
        result = jg_database_transaction_begin(management->database);
        transaction_started = result == 0;
    }
    if (result == 0) {
        result = append_backup_audit(management, request, remote, &actor,
                                     "backup.export", &metadata, NULL, false,
                                     NULL, now);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(management->database);
        transaction_started = result != 0;
    }
    if (result != 0 && transaction_started &&
        jg_database_transaction_rollback(management->database) != 0) {
        result = -EIO;
    }
    if (result != 0 && exported) {
        const int cleanup_result = jg_backup_remove_path(path);

        if (cleanup_result != 0 && cleanup_result != -ENOENT) {
            result = -EIO;
        }
    }
    if (result != 0) {
        return respond_error(
            result == -EEXIST ? 409 : 500,
            result == -EEXIST ? "backup_file_exists" : "backup_export_failed",
            result == -EEXIST ? "The local destination already exists."
                              : "The backup archive could not be exported.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    backup = backup_json(&metadata);
    if (body == NULL || backup == NULL ||
        json_object_set(body, "backup", backup) != 0) {
        json_decref(backup);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(backup);
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Validate or atomically apply one backed-up server identity. */
static int restore_backup_certificate(struct jg_management *management,
                                      const uint8_t *certificate,
                                      size_t certificate_size,
                                      bool apply,
                                      bool *changes)
{
    struct jg_certificate_info current;
    struct jg_certificate_info replacement;
    struct jg_certificate_info installed;
    char *current_identity = NULL;
    size_t current_identity_size = 0U;
    const char *private_key = (const char *)certificate;
    size_t private_key_size = certificate_size;
    bool current_present = false;
    int result = 0;

    if (management == NULL || changes == NULL ||
        (certificate == NULL && certificate_size != 0U)) {
        return -EINVAL;
    }
    *changes = false;
    result =
        jg_certificate_inspect_file(management->certificate_path, &current);
    if (result == 0) {
        current_present = true;
    } else if (result == -ENOENT) {
        result = 0;
    }
    if (result == 0 && certificate_size == 0U) {
        return 0;
    }
    if (result == 0) {
        result = jg_certificate_inspect(
            (const char *)certificate, certificate_size,
            (const char *)certificate, certificate_size, &replacement);
    }
    if (result != 0 && current_present) {
        result = jg_certificate_export_file(management->certificate_path, true,
                                            &current_identity,
                                            &current_identity_size);
        if (result == 0) {
            private_key = current_identity;
            private_key_size = current_identity_size;
            result = jg_certificate_inspect((const char *)certificate,
                                            certificate_size, private_key,
                                            private_key_size, &replacement);
        }
    }
    if (result == 0) {
        *changes = !current_present ||
                   sodium_memcmp(current.fingerprint_sha256,
                                 replacement.fingerprint_sha256,
                                 sizeof(current.fingerprint_sha256)) != 0;
    }
    if (result == 0 && apply && *changes) {
        result = jg_certificate_install(
            management->certificate_path, (const char *)certificate,
            certificate_size, private_key, private_key_size, &installed);
    }
    jg_certificate_pem_clear(current_identity, current_identity_size);
    return result;
}

/** @brief Validate or atomically apply a portable TOTP protection key. */
static int restore_backup_totp_key(struct jg_management *management,
                                   const struct jg_backup_contents *contents,
                                   bool apply,
                                   bool *changes)
{
    int result = 0;

    if (management == NULL || contents == NULL || changes == NULL) {
        return -EINVAL;
    }
    *changes = false;
    if (!contents->info.portable) {
        return 0;
    }
    if (contents->totp_key == NULL ||
        contents->totp_key_size != JG_AUTH_TOTP_KEY_SIZE) {
        return -EINVAL;
    }
    *changes = sodium_memcmp(contents->totp_key, management->secrets->totp_key,
                             JG_AUTH_TOTP_KEY_SIZE) != 0;
    if (apply && *changes) {
        result = management_totp_key_store(management->totp_key_path,
                                           contents->totp_key);
        if (result == 0) {
            (void)memcpy(management->secrets->totp_key, contents->totp_key,
                         JG_AUTH_TOTP_KEY_SIZE);
        }
    }
    return result;
}

/** @brief Validate or atomically apply a portable client trust store. */
static int restore_backup_client_ca(struct jg_management *management,
                                    const struct jg_backup_contents *contents,
                                    bool apply,
                                    bool *changes)
{
    struct jg_certificate_info *authorities = NULL;
    char *current = NULL;
    size_t current_size = 0U;
    size_t authority_count = 0U;
    bool current_present = false;
    int result = 0;

    if (management == NULL || contents == NULL || changes == NULL) {
        return -EINVAL;
    }
    *changes = false;
    if (!contents->info.portable) {
        return 0;
    }
    if ((contents->client_ca == NULL) != (contents->client_ca_size == 0U)) {
        return -EINVAL;
    }
    result = jg_certificate_trust_store_export_file(management->client_ca_path,
                                                    &current, &current_size);
    if (result == 0) {
        current_present = true;
    } else if (result == -ENOENT) {
        result = 0;
    }
    if (result == 0 && contents->client_ca_size > 0U) {
        authorities =
            calloc(JG_CERTIFICATE_AUTHORITY_MAX, sizeof(*authorities));
        if (authorities == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0 && contents->client_ca_size > 0U) {
        result = jg_certificate_trust_store_inspect(
            (const char *)contents->client_ca, contents->client_ca_size,
            authorities, JG_CERTIFICATE_AUTHORITY_MAX, &authority_count);
    }
    if (result == 0) {
        *changes =
            current_present != (contents->client_ca_size > 0U) ||
            current_size != contents->client_ca_size ||
            (current_size > 0U &&
             sodium_memcmp(current, contents->client_ca, current_size) != 0);
    }
    if (result == 0 && apply && *changes && contents->client_ca_size > 0U) {
        result = jg_certificate_trust_store_install(
            management->client_ca_path, (const char *)contents->client_ca,
            contents->client_ca_size, authorities, JG_CERTIFICATE_AUTHORITY_MAX,
            &authority_count);
    } else if (result == 0 && apply && *changes) {
        result = jg_certificate_trust_store_remove(management->client_ca_path);
    }
    free(authorities);
    jg_certificate_pem_clear(current, current_size);
    return result;
}

/** @brief Return one authenticated stable page of backup metadata. */
int handle_backups_list(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_backup *backups = NULL;
    json_t *body = NULL;
    json_t *items = NULL;
    uint64_t after_id = 0U;
    size_t limit = 0U;
    size_t count = 0U;
    bool has_more = false;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_BACKUPS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (json_object_size(request->body) != 0U ||
        parse_page_query(request->query, "after_id",
                         JG_DATABASE_BACKUP_PAGE_MAX, &after_id, &limit) != 0) {
        return respond_error(400, "invalid_query",
                             "The backup pagination parameters are not valid.",
                             request->request_id, output, output_size, written);
    }
    backups = calloc(limit, sizeof(*backups));
    if (backups == NULL) {
        return -ENOMEM;
    }
    result = jg_database_list_backups(management->database, after_id, limit,
                                      backups, &count, &has_more);
    if (result != 0) {
        free(backups);
        return respond_error(500, "backups_unavailable",
                             "The backup records could not be read.",
                             request->request_id, output, output_size, written);
    }
    body = json_object();
    items = json_array();
    if (body == NULL || items == NULL) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = backup_json(&backups[index]);

        if (item == NULL || json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (result == 0 &&
        (json_object_set_new(body, "after_id",
                             json_integer((json_int_t)after_id)) != 0 ||
         json_object_set_new(body, "limit", json_integer((json_int_t)limit)) !=
             0 ||
         json_object_set_new(body, "count", json_integer((json_int_t)count)) !=
             0 ||
         json_object_set_new(body, "has_more", json_boolean(has_more)) != 0 ||
         json_object_set(body, "backups", items) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        json_t *next = has_more && count > 0U
                           ? json_integer((json_int_t)backups[count - 1U].id)
                           : json_null();

        if (json_object_set_new(body, "next_after_id", next) != 0) {
            result = -ENOMEM;
        }
    }
    free(backups);
    json_decref(items);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Execute one authenticated backup creation job. */
int execute_backup_create_job(struct jg_management *management,
                              const struct management_job *job,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written)
{
    const struct management_request request = {
        .request_id = job->request_id,
    };
    struct backup_creation_audit audit = {
        .management = management,
        .request = &request,
        .remote = &job->remote,
        .actor = &job->actor,
        .action = "backup.create",
        .now = job->started_at,
    };
    const struct management_operation_origin operation_origin = {
        .request = &request,
        .remote = &job->remote,
        .actor = &job->actor,
        .action = "backup.create",
    };
    struct jg_database_backup created = {0};
    json_t *body = NULL;
    json_t *backup = NULL;
    int result = create_backup(
        management, job->parameters.backup_create.kind,
        job->parameters.backup_create.include_private_key,
        job->parameters.backup_create.passphrase_size == 0U
            ? NULL
            : job->parameters.backup_create.passphrase,
        job->parameters.backup_create.passphrase_size, job->started_at,
        &operation_origin, complete_backup_creation, &audit, &created);

    if (result != 0) {
        return respond_error(
            500, "backup_create_failed",
            "The backup archive and audit could not be stored.",
            request.request_id, output, output_size, written);
    }
    body = json_object();
    backup = backup_json(&created);
    if (body == NULL || backup == NULL ||
        json_object_set(body, "backup", backup) != 0) {
        json_decref(backup);
        json_decref(body);
        return -ENOMEM;
    }
    json_decref(backup);
    return encode_response(201, body, NULL, output, output_size, written);
}

/** @brief Queue one configuration or encrypted full backup. */
int handle_backup_create(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written)
{
    static const char *const fields[] = {
        "kind",
        "include_private_key",
        "passphrase",
    };
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_BACKUPS_WRITE,
        .kind = MANAGEMENT_JOB_BACKUP_CREATE,
    };
    const char *kind_text = NULL;
    const char *passphrase = NULL;
    uint64_t job_id = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_BACKUPS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    kind_text = required_string(request->body, "kind", 4U, 13U);
    prepared.parameters.backup_create.kind = parse_backup_kind(kind_text);
    if (request->query[0U] != '\0' ||
        json_object_size(request->body) !=
            sizeof(fields) / sizeof(fields[0U]) ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        prepared.parameters.backup_create.kind == 0 ||
        !required_boolean(
            request->body, "include_private_key",
            &prepared.parameters.backup_create.include_private_key) ||
        !required_nullable_string(request->body, "passphrase",
                                  JG_BACKUP_PASSPHRASE_MAX, &passphrase) ||
        (prepared.parameters.backup_create.kind == JG_BACKUP_CONFIGURATION &&
         (prepared.parameters.backup_create.include_private_key ||
          passphrase != NULL)) ||
        (prepared.parameters.backup_create.kind == JG_BACKUP_FULL &&
         (passphrase == NULL ||
          strlen(passphrase) < JG_BACKUP_PASSPHRASE_MIN))) {
        return respond_error(
            400, "invalid_body",
            "The backup kind, private-key choice, or passphrase is not valid.",
            request->request_id, output, output_size, written);
    }
    if (passphrase != NULL) {
        prepared.parameters.backup_create.passphrase_size = strlen(passphrase);
        (void)memcpy(prepared.parameters.backup_create.passphrase, passphrase,
                     prepared.parameters.backup_create.passphrase_size + 1U);
    }
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    management_job_parameters_clear(prepared.kind, &prepared.parameters);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The backup creation could not be queued.", output,
            output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
}

/** @brief Inspect one recorded backup and its validated manifest. */
int handle_backup_inspect(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t backup_id,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    struct authenticated_actor actor;
    struct jg_database_backup metadata;
    struct jg_backup_info info;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;
    json_t *body = NULL;
    json_t *backup = NULL;
    json_t *manifest = NULL;
    int result = authenticate_actor(management, request, remote, false,
                                    JG_ACCESS_BACKUPS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    if (request->query[0U] != '\0' || json_object_size(request->body) != 0U) {
        return respond_error(400, "invalid_request",
                             "Backup inspection accepts no query or body.",
                             request->request_id, output, output_size, written);
    }
    result = load_backup(management, backup_id, &metadata, &archive,
                         &archive_size, &info);
    if (result != 0) {
        const bool missing = result == -ENOENT && metadata.id == 0U;

        return respond_error(
            missing ? 404 : 409,
            missing ? "backup_not_found" : "backup_invalid",
            missing ? "The requested backup does not exist."
                    : "The recorded backup archive is missing or invalid.",
            request->request_id, output, output_size, written);
    }
    body = json_object();
    backup = backup_json(&metadata);
    manifest = backup_manifest_json(&info);
    if (body == NULL || backup == NULL || manifest == NULL ||
        json_object_set(body, "backup", backup) != 0 ||
        json_object_set(body, "manifest", manifest) != 0) {
        result = -ENOMEM;
    }
    json_decref(backup);
    json_decref(manifest);
    jg_backup_data_clear(archive, archive_size);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Execute one authenticated backup restore job. */
int execute_backup_restore_job(struct jg_management *management,
                               const struct management_job *job,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written)
{
    const struct management_request request_value = {
        .request_id = job->request_id,
    };
    const struct management_request *request = &request_value;
    const struct remote_address *remote = &job->remote;
    const struct authenticated_actor *actor = &job->actor;
    const struct management_operation_origin operation_origin = {
        .request = request,
        .remote = remote,
        .actor = actor,
        .action = "backup.restore",
    };
    const struct management_operation_origin checkpoint_origin = {
        .request = request,
        .remote = remote,
        .actor = actor,
        .action = "backup.checkpoint.create",
    };
    struct jg_database_backup metadata;
    struct jg_database_backup checkpoint;
    struct jg_backup_info info;
    struct jg_backup_contents contents;
    struct jg_database_restore_report report;
    struct jg_database_restore_report audit_report;
    struct jg_database_policy_sync policy_sync;
    uint8_t recovery_payload[3U] = {MANAGEMENT_RECOVERY_VERSION, 0U, 0U};
    const char *passphrase =
        job->parameters.backup_restore.passphrase_size == 0U
            ? NULL
            : job->parameters.backup_restore.passphrase;
    uint8_t *archive = NULL;
    size_t archive_size = 0U;
    const bool dry_run = job->parameters.backup_restore.dry_run;
    bool certificate_changes = false;
    bool totp_key_changes = false;
    bool client_ca_changes = false;
    bool changes = false;
    bool checkpoint_created = false;
    bool certificate_present = false;
    bool client_ca_was_present = false;
    bool recovery_started = false;
    bool restore_active = false;
    json_t *body = NULL;
    json_t *backup = NULL;
    json_t *database_report = NULL;
    json_t *checkpoint_body = NULL;
    const uint64_t backup_id = job->parameters.backup_restore.backup_id;
    const uint64_t now = job->started_at;
    struct backup_creation_audit checkpoint_audit = {
        .management = management,
        .request = request,
        .remote = remote,
        .actor = actor,
        .action = "backup.checkpoint.create",
        .relationship =
            {
                .restore_backup_id = backup_id,
                .restore_request_id = request->request_id,
            },
        .now = now,
    };
    struct backup_audit_relationship restore_relationship = {0};
    int result = 0;

    (void)memset(&contents, 0, sizeof(contents));
    (void)memset(&checkpoint, 0, sizeof(checkpoint));
    result = load_backup(management, backup_id, &metadata, &archive,
                         &archive_size, &info);
    if (result != 0) {
        const bool missing = result == -ENOENT && metadata.id == 0U;

        return respond_error(
            missing ? 404 : 409,
            missing ? "backup_not_found" : "backup_invalid",
            missing ? "The requested backup does not exist."
                    : "The recorded backup archive is missing or invalid.",
            request->request_id, output, output_size, written);
    }
    if ((metadata.kind == JG_BACKUP_CONFIGURATION && passphrase != NULL) ||
        (metadata.kind == JG_BACKUP_FULL &&
         (passphrase == NULL ||
          strlen(passphrase) < JG_BACKUP_PASSPHRASE_MIN))) {
        jg_backup_data_clear(archive, archive_size);
        return respond_error(
            400, "invalid_body",
            "The passphrase does not match the selected backup kind.",
            request->request_id, output, output_size, written);
    }
    result =
        jg_backup_open(archive, archive_size, passphrase,
                       passphrase == NULL ? 0U : strlen(passphrase), &contents);
    jg_backup_data_clear(archive, archive_size);
    if (result != 0) {
        return respond_error(
            result == -EACCES ? 400 : 409,
            result == -EACCES ? "incorrect_passphrase" : "backup_invalid",
            result == -EACCES ? "The full-backup passphrase is not correct."
                              : "The backup payload could not be validated.",
            request->request_id, output, output_size, written);
    }
    if (!dry_run) {
        result = management_restore_begin(management);
        restore_active = result == 0;
    }
    if (result != 0) {
        jg_backup_contents_clear(&contents);
        return respond_error(
            result == -EBUSY ? 409 : 503,
            result == -EBUSY ? "restore_conflict" : "consistency_unavailable",
            result == -EBUSY
                ? "Another applied restore is already in progress."
                : "The management consistency gate is unavailable.",
            request->request_id, output, output_size, written);
    }
    result = jg_database_restore(
        management->database, contents.database, contents.database_size,
        metadata.kind == JG_BACKUP_FULL, true, &report);
    if (result == 0) {
        result = restore_backup_certificate(management, contents.certificate,
                                            contents.certificate_size, false,
                                            &certificate_changes);
    }
    if (result == 0) {
        result = restore_backup_totp_key(management, &contents, false,
                                         &totp_key_changes);
    }
    if (result == 0) {
        result = restore_backup_client_ca(management, &contents, false,
                                          &client_ca_changes);
    }
    if (result != 0) {
        if (restore_active) {
            management_restore_end(management);
        }
        jg_backup_contents_clear(&contents);
        return respond_error(
            result == -ENOTSUP ? 409 : 400, "restore_validation_failed",
            "The backup contents cannot be restored on this appliance.",
            request->request_id, output, output_size, written);
    }
    changes = report.changes || certificate_changes || totp_key_changes ||
              client_ca_changes;
    if (!dry_run && changes) {
        result = create_backup(
            management, metadata.kind, metadata.kind == JG_BACKUP_FULL,
            passphrase, passphrase == NULL ? 0U : strlen(passphrase), now,
            &checkpoint_origin, complete_backup_creation, &checkpoint_audit,
            &checkpoint);
        checkpoint_created = result == 0;
    }
    if (!dry_run && changes && result != 0) {
        management_restore_end(management);
        jg_backup_contents_clear(&contents);
        return respond_error(
            500, "checkpoint_failed",
            "The automatic pre-restore checkpoint could not be created.",
            request->request_id, output, output_size, written);
    }
    if (!dry_run && changes && certificate_changes) {
        result = server_identity_present(management->certificate_path,
                                         &certificate_present);
    }
    if (!dry_run && changes && result == 0 && client_ca_changes) {
        result = client_ca_present(management->client_ca_path,
                                   &client_ca_was_present);
    }
    if (!dry_run && changes && result == 0) {
        recovery_payload[1U] =
            certificate_present ? MANAGEMENT_RECOVERY_CERTIFICATE : 0U;
        recovery_payload[1U] |=
            client_ca_was_present ? MANAGEMENT_RECOVERY_CLIENT_CA : 0U;
        recovery_payload[1U] |=
            totp_key_changes ? MANAGEMENT_RECOVERY_TOTP_KEY : 0U;
        recovery_payload[2U] =
            certificate_changes ? MANAGEMENT_RECOVERY_CERTIFICATE : 0U;
        recovery_payload[2U] |=
            client_ca_changes ? MANAGEMENT_RECOVERY_CLIENT_CA : 0U;
        recovery_payload[2U] |=
            totp_key_changes ? MANAGEMENT_RECOVERY_TOTP_KEY : 0U;
        result = start_recovery_operation(
            management, MANAGEMENT_OPERATION_BACKUP_RESTORE, recovery_payload,
            sizeof(recovery_payload), recovery_payload[1U], true,
            &operation_origin, now);
        recovery_started = result == 0;
    }
    if (!dry_run && changes && result != 0) {
        management_restore_end(management);
        jg_backup_contents_clear(&contents);
        return respond_error(
            result == -EBUSY ? 409 : 503,
            result == -EBUSY ? "operation_conflict" : "recovery_unavailable",
            result == -EBUSY
                ? "Another recoverable management operation is in progress."
                : "Durable restore recovery could not be prepared.",
            request->request_id, output, output_size, written);
    }
    if (!dry_run && changes) {
        result = jg_database_restore(
            management->database, contents.database, contents.database_size,
            metadata.kind == JG_BACKUP_FULL, false, &report);
    }
    if (!dry_run && changes && result == 0) {
        result = restore_backup_certificate(management, contents.certificate,
                                            contents.certificate_size, true,
                                            &certificate_changes);
    }
    if (!dry_run && changes && result == 0) {
        result = restore_backup_totp_key(management, &contents, true,
                                         &totp_key_changes);
    }
    if (!dry_run && changes && result == 0) {
        result = restore_backup_client_ca(management, &contents, true,
                                          &client_ca_changes);
    }
    if (!dry_run && changes && result == 0) {
        result = jg_database_policy_sync_advance(management->database, now,
                                                 &policy_sync);
    }
    if (!dry_run && changes && result != 0) {
        const int rollback_result =
            abort_recovery_operation(management, result);

        management_restore_end(management);
        jg_backup_contents_clear(&contents);
        return respond_error(
            rollback_result == -EIO ? 503 : 500,
            rollback_result == -EIO ? "restore_rollback_failed"
                                    : "restore_failed",
            rollback_result != -EIO
                ? "The restore failed and the previous state was recovered."
                : "The restore and its automatic rollback both failed.",
            request->request_id, output, output_size, written);
    }
    audit_report = report;
    audit_report.changes = changes;
    restore_relationship.checkpoint_id =
        checkpoint_created ? checkpoint.id : 0U;
    if (recovery_started) {
        result = jg_database_transaction_begin(management->database);
    }
    if (result == 0) {
        result = append_backup_audit(
            management, request, remote, actor,
            dry_run ? "backup.restore.dry_run" : "backup.restore", &metadata,
            &audit_report, dry_run,
            checkpoint_created ? &restore_relationship : NULL, now);
    }
    if (recovery_started) {
        result = finish_recovery_operation(management, result);
        refresh_policy_sync_health(management);
    }
    if (result != 0) {
        if (restore_active) {
            management_restore_end(management);
        }
        jg_backup_contents_clear(&contents);
        return respond_error(
            500, "audit_failure",
            "The restore and its audit record were not committed.",
            request->request_id, output, output_size, written);
    }
    if (restore_active) {
        management_restore_end(management);
    }
    body = json_object();
    backup = backup_json(&metadata);
    database_report = restore_report_json(&report);
    checkpoint_body =
        checkpoint_created ? backup_json(&checkpoint) : json_null();
    if (body == NULL || backup == NULL || database_report == NULL ||
        checkpoint_body == NULL ||
        json_object_set(body, "backup", backup) != 0 ||
        json_object_set_new(body, "dry_run", json_boolean(dry_run)) != 0 ||
        json_object_set_new(body, "changes", json_boolean(changes)) != 0 ||
        json_object_set(body, "database", database_report) != 0 ||
        json_object_set_new(body, "certificate_changes",
                            json_boolean(certificate_changes)) != 0 ||
        json_object_set_new(body, "totp_key_changes",
                            json_boolean(totp_key_changes)) != 0 ||
        json_object_set_new(body, "client_ca_changes",
                            json_boolean(client_ca_changes)) != 0 ||
        json_object_set_new(body, "portable", json_boolean(info.portable)) !=
            0 ||
        json_object_set(body, "checkpoint", checkpoint_body) != 0 ||
        json_object_set_new(
            body, "reload_required",
            json_boolean(!dry_run && (report.changes || certificate_changes ||
                                      client_ca_changes))) != 0) {
        result = -ENOMEM;
    }
    json_decref(backup);
    json_decref(database_report);
    json_decref(checkpoint_body);
    jg_backup_contents_clear(&contents);
    if (result != 0) {
        json_decref(body);
        return result;
    }
    return encode_response(200, body, NULL, output, output_size, written);
}

/** @brief Queue one validated or confirmed backup restore. */
int handle_backup_restore(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t backup_id,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written)
{
    static const char *const fields[] = {
        "passphrase",
        "dry_run",
        "confirm",
    };
    struct authenticated_actor actor;
    struct management_job_submission prepared = {
        .required_permission = JG_ACCESS_BACKUPS_WRITE,
        .kind = MANAGEMENT_JOB_BACKUP_RESTORE,
    };
    const char *passphrase = NULL;
    bool confirm = false;
    uint64_t job_id = 0U;
    int result = authenticate_actor(management, request, remote, true,
                                    JG_ACCESS_BACKUPS_WRITE, now, &actor);

    if (result != 0) {
        return respond_actor_error(result, request, output, output_size,
                                   written);
    }
    prepared.parameters.backup_restore.backup_id = backup_id;
    if (request->query[0U] != '\0' ||
        json_object_size(request->body) !=
            sizeof(fields) / sizeof(fields[0U]) ||
        !fields_allowed(request->body, fields,
                        sizeof(fields) / sizeof(fields[0U])) ||
        !required_nullable_string(request->body, "passphrase",
                                  JG_BACKUP_PASSPHRASE_MAX, &passphrase) ||
        !required_boolean(request->body, "dry_run",
                          &prepared.parameters.backup_restore.dry_run) ||
        !required_boolean(request->body, "confirm", &confirm) ||
        (prepared.parameters.backup_restore.dry_run && confirm) ||
        (!prepared.parameters.backup_restore.dry_run && !confirm)) {
        return respond_error(
            400, "invalid_body",
            "A dry run must be unconfirmed and an applied restore confirmed.",
            request->request_id, output, output_size, written);
    }
    if (passphrase != NULL) {
        prepared.parameters.backup_restore.passphrase_size = strlen(passphrase);
        (void)memcpy(prepared.parameters.backup_restore.passphrase, passphrase,
                     prepared.parameters.backup_restore.passphrase_size + 1U);
    }
    result = submit_management_job(management, request, remote, &actor,
                                   &prepared, now, &job_id);
    management_job_parameters_clear(prepared.kind, &prepared.parameters);
    if (result != 0) {
        return respond_job_submission_error(
            result, request, "The backup restore could not be queued.", output,
            output_size, written);
    }
    return respond_job_accepted(job_id, output, output_size, written);
}
