/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_recovery.c
 * @brief Durable management recovery and cross-resource compensation.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database_internal.h"
#include "janusgate/audit.h"
#include "janusgate/certificate.h"
#include "janusgate/logging.h"
#include "netd_client.h"

/** @brief Append the fixed recovery suffix to one validated absolute path. */
static int recovery_path(const char *path, char output[PATH_MAX])
{
    const int written = path == NULL ? -1
                                     : snprintf(output, PATH_MAX, "%s%s", path,
                                                MANAGEMENT_RECOVERY_SUFFIX);

    return written <= 0 || written >= PATH_MAX ? -ENAMETOOLONG : 0;
}

/** @brief Remove one secure recovery snapshot when it exists. */
static int remove_recovery_file(const char *path)
{
    const int result = jg_certificate_private_key_remove(path);

    return result == -ENOENT ? 0 : result;
}

/** @brief Inspect whether a secure server identity currently exists. */
int server_identity_present(const char *path, bool *present)
{
    struct jg_certificate_info info;
    int result = 0;

    if (present == NULL) {
        return -EINVAL;
    }
    result = jg_certificate_inspect_file(path, &info);
    *present = result == 0;
    return result == -ENOENT ? 0 : result;
}

/** @brief Inspect whether a secure pending private key currently exists. */
int pending_key_present(const char *path, bool *present)
{
    char *private_key = NULL;
    size_t private_key_size = 0U;
    int result = 0;

    if (present == NULL) {
        return -EINVAL;
    }
    result =
        jg_certificate_private_key_load(path, &private_key, &private_key_size);
    *present = result == 0;
    jg_certificate_pem_clear(private_key, private_key_size);
    return result == -ENOENT ? 0 : result;
}

/** @brief Inspect whether a secure client trust store currently exists. */
int client_ca_present(const char *path, bool *present)
{
    struct jg_certificate_info *authorities = NULL;
    size_t authority_count = 0U;
    int result = 0;

    if (present == NULL) {
        return -EINVAL;
    }
    authorities = calloc(JG_CERTIFICATE_AUTHORITY_MAX, sizeof(*authorities));
    if (authorities == NULL) {
        return -ENOMEM;
    }
    result = jg_certificate_trust_store_inspect_file(
        path, authorities, JG_CERTIFICATE_AUTHORITY_MAX, &authority_count);
    *present = result == 0;
    free(authorities);
    return result == -ENOENT ? 0 : result;
}

/** @brief Snapshot one pending private key into its reserved recovery path. */
static int snapshot_pending_key(const char *path)
{
    char snapshot[PATH_MAX];
    char *private_key = NULL;
    size_t private_key_size = 0U;
    int result = recovery_path(path, snapshot);

    if (result == 0) {
        result = jg_certificate_private_key_load(path, &private_key,
                                                 &private_key_size);
    }
    if (result == 0) {
        result = jg_certificate_private_key_store(snapshot, private_key,
                                                  private_key_size);
    }
    jg_certificate_pem_clear(private_key, private_key_size);
    return result;
}

/** @brief Create every durable snapshot selected by one operation. */
static int create_recovery_snapshots(struct jg_management *management,
                                     uint8_t files,
                                     bool database)
{
    char pending[PATH_MAX];
    char snapshot[PATH_MAX];
    int result = 0;

    if ((files & MANAGEMENT_RECOVERY_CERTIFICATE) != 0U) {
        result = recovery_path(management->certificate_path, snapshot);
        if (result == 0) {
            result = jg_certificate_identity_copy(management->certificate_path,
                                                  snapshot);
        }
    }
    if (result == 0 && (files & MANAGEMENT_RECOVERY_PENDING_KEY) != 0U) {
        result = certificate_pending_path(management, pending);
        if (result == 0) {
            result = snapshot_pending_key(pending);
        }
    }
    if (result == 0 && (files & MANAGEMENT_RECOVERY_CLIENT_CA) != 0U) {
        result = recovery_path(management->client_ca_path, snapshot);
        if (result == 0) {
            result = jg_certificate_trust_store_copy(management->client_ca_path,
                                                     snapshot);
        }
    }
    if (result == 0 && database) {
        result = jg_database_recovery_checkpoint_create(management->database);
    }
    return result;
}

/** @brief Remove every reserved recovery snapshot left by an operation. */
static int cleanup_recovery_snapshots(struct jg_management *management)
{
    char pending[PATH_MAX];
    char snapshot[PATH_MAX];
    int result = 0;
    int cleanup_result = recovery_path(management->certificate_path, snapshot);

    if (cleanup_result == 0) {
        cleanup_result = remove_recovery_file(snapshot);
    }
    if (cleanup_result != 0) {
        result = cleanup_result;
    }
    cleanup_result = certificate_pending_path(management, pending);
    if (cleanup_result == 0) {
        cleanup_result = recovery_path(pending, snapshot);
    }
    if (cleanup_result == 0) {
        cleanup_result = remove_recovery_file(snapshot);
    }
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    cleanup_result = recovery_path(management->client_ca_path, snapshot);
    if (cleanup_result == 0) {
        cleanup_result = remove_recovery_file(snapshot);
    }
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    cleanup_result =
        jg_database_recovery_checkpoint_remove(management->database);
    if (cleanup_result == -ENOENT) {
        cleanup_result = 0;
    }
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    return result;
}

/** @brief Restore one file from a snapshot or remove a newly created file. */
static int restore_recovery_file(const char *path,
                                 bool existed,
                                 bool trust_store)
{
    char snapshot[PATH_MAX];
    int result = recovery_path(path, snapshot);

    if (result == 0 && existed) {
        result = trust_store ? jg_certificate_trust_store_copy(snapshot, path)
                             : jg_certificate_identity_copy(snapshot, path);
    } else if (result == 0) {
        result = remove_recovery_file(path);
    }
    return result;
}

/** @brief Restore a pending key from a snapshot or remove its new value. */
static int restore_pending_key(const char *path, bool existed)
{
    char snapshot[PATH_MAX];
    char *private_key = NULL;
    size_t private_key_size = 0U;
    int result = recovery_path(path, snapshot);

    if (result == 0 && existed) {
        result = jg_certificate_private_key_load(snapshot, &private_key,
                                                 &private_key_size);
        if (result == 0) {
            result = jg_certificate_private_key_store(path, private_key,
                                                      private_key_size);
        }
    } else if (result == 0) {
        result = remove_recovery_file(path);
    }
    jg_certificate_pem_clear(private_key, private_key_size);
    return result;
}

/** @brief Restore all file generations selected by a recovery bit mask. */
static int restore_recovery_files(struct jg_management *management,
                                  uint8_t files,
                                  uint8_t tracked)
{
    char pending[PATH_MAX];
    int result = 0;

    if ((tracked & MANAGEMENT_RECOVERY_CERTIFICATE) != 0U) {
        result = restore_recovery_file(
            management->certificate_path,
            (files & MANAGEMENT_RECOVERY_CERTIFICATE) != 0U, false);
    }
    if (result == 0 && (tracked & MANAGEMENT_RECOVERY_PENDING_KEY) != 0U) {
        result = certificate_pending_path(management, pending);
        if (result == 0) {
            result = restore_pending_key(
                pending, (files & MANAGEMENT_RECOVERY_PENDING_KEY) != 0U);
        }
    }
    if (result == 0 && (tracked & MANAGEMENT_RECOVERY_CLIENT_CA) != 0U) {
        result = restore_recovery_file(
            management->client_ca_path,
            (files & MANAGEMENT_RECOVERY_CLIENT_CA) != 0U, true);
    }
    return result;
}

/** @brief Reserve, snapshot, and arm one cross-resource operation. */
int start_recovery_operation(struct jg_management *management,
                             const char *kind,
                             const uint8_t *payload,
                             size_t payload_size,
                             uint8_t files,
                             bool database,
                             uint64_t now)
{
    int result = jg_database_operation_prepare(management->database, kind,
                                               payload, payload_size, now);
    const bool prepared = result == 0;

    if (result == 0) {
        result = create_recovery_snapshots(management, files, database);
    }
    if (result == 0) {
        result = jg_database_operation_mark_ready(management->database);
    }
    if (result != 0 && prepared) {
        const int cleanup_result = cleanup_recovery_snapshots(management);
        const int clear_result =
            jg_database_operation_clear(management->database);

        if ((cleanup_result != 0 ||
             (clear_result != 0 && clear_result != -ENOENT)) &&
            result != -EIO) {
            result = -EIO;
        }
    }
    return result;
}

/** @brief Persist one recovery network value only when it differs. */
static int restore_persistent_network(struct jg_management *management,
                                      const struct jg_network_config *config)
{
    struct jg_database_network_config current;
    struct jg_database_network_config updated;
    int result =
        jg_database_load_network_config_record(management->database, &current);

    if (result == 0 && !network_configs_equal(&current.config, config)) {
        result = jg_database_replace_network_config(
            management->database, config, current.revision, &updated);
    }
    return result;
}

/** @brief Recover a confirmed network mutation to its previous generation. */
static int restore_recovery_network(struct jg_management *management,
                                    const uint8_t *payload,
                                    size_t payload_size)
{
    const size_t expected_size = 1U + JG_NETWORK_CONFIG_WIRE_SIZE * 2U;
    struct jg_network_config previous;
    struct jg_network_config replacement;
    struct jg_network_state state;
    int result = 0;

    if (payload == NULL || payload_size != expected_size ||
        payload[0U] != MANAGEMENT_RECOVERY_VERSION ||
        jg_network_config_decode(payload + 1U, JG_NETWORK_CONFIG_WIRE_SIZE,
                                 &previous) != 0 ||
        jg_network_config_decode(payload + 1U + JG_NETWORK_CONFIG_WIRE_SIZE,
                                 JG_NETWORK_CONFIG_WIRE_SIZE,
                                 &replacement) != 0) {
        return -EILSEQ;
    }
    result = jg_netd_client_state(&state);
    if (result == 0 && state.pending) {
        result = jg_netd_client_rollback();
    }
    if (result == -EBUSY) {
        result = 0;
    }
    if (result == 0) {
        result = jg_netd_client_apply(&previous);
    }
    if (result == 0) {
        result = restore_persistent_network(management, &previous);
        if (result != 0) {
            (void)jg_netd_client_rollback();
        }
    }
    if (result == 0) {
        result = jg_netd_client_confirm();
    }
    if (result != 0) {
        const int rollback_result = jg_netd_client_rollback();
        const int database_result =
            restore_persistent_network(management, &replacement);

        if ((rollback_result != 0 && rollback_result != -EBUSY) ||
            database_result != 0) {
            result = -EIO;
        }
    }
    return result;
}

/** @brief Append and atomically retire one recovered durable operation. */
static int finish_recovered_operation(
    struct jg_management *management,
    const struct jg_database_operation *operation)
{
    char details[JG_DATABASE_OPERATION_KIND_MAX + 48U];
    const time_t wall_clock = time(NULL);
    struct jg_audit_event event;
    int written = 0;
    int result = 0;

    if (wall_clock < 0) {
        return -EIO;
    }
    written =
        snprintf(details, sizeof(details), "{\"kind\":\"%s\",\"ready\":%s}",
                 operation->kind, operation->ready ? "true" : "false");
    if (written <= 0 || (size_t)written >= sizeof(details)) {
        return -EOVERFLOW;
    }
    event = (struct jg_audit_event){
        .occurred_at = (uint64_t)wall_clock,
        .actor_type = JG_AUDIT_ACTOR_SYSTEM,
        .source = "local",
        .action = operation->ready ? "management.operation.recover"
                                   : "management.operation.discard",
        .object_type = "management_operation",
        .object_id = operation->kind,
        .details = details,
        .success = true,
        .request_id = "",
    };
    result = jg_database_transaction_begin(management->database);
    if (result == 0) {
        result = jg_database_audit_append(management->database, &event, NULL);
    }
    if (result == 0) {
        result = jg_database_operation_clear(management->database);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(management->database);
    }
    if (result != 0) {
        const int rollback_result =
            jg_database_transaction_rollback(management->database);

        if (rollback_result != 0) {
            result = -EIO;
        }
    }
    return result;
}

/** @brief Restore or discard one operation left pending across a restart. */
int recover_pending_operation(struct jg_management *management)
{
    struct jg_database_operation operation;
    uint8_t existing = 0U;
    uint8_t tracked = 0U;
    int result = jg_database_operation_load(management->database, &operation);

    if (result == -ENOENT) {
        return cleanup_recovery_snapshots(management);
    }
    if (result != 0) {
        return result;
    }
    if (!operation.ready) {
        result = 0;
    } else if (strcmp(operation.kind, MANAGEMENT_OPERATION_NETWORK_CONFIRM) ==
               0) {
        result = restore_recovery_network(management, operation.payload,
                                          operation.payload_size);
    } else {
        if (operation.payload_size != 3U ||
            operation.payload[0U] != MANAGEMENT_RECOVERY_VERSION) {
            result = -EILSEQ;
        } else {
            existing = operation.payload[1U];
            tracked = operation.payload[2U];
        }
        if (result == 0 && (existing & (uint8_t)~tracked) != 0U) {
            result = -EILSEQ;
        }
        if (result == 0 &&
            strcmp(operation.kind, MANAGEMENT_OPERATION_CERTIFICATE_CSR) == 0) {
            if (tracked != MANAGEMENT_RECOVERY_PENDING_KEY) {
                result = -EILSEQ;
            }
        } else if (result == 0 &&
                   strcmp(operation.kind,
                          MANAGEMENT_OPERATION_CERTIFICATE_INSTALL) == 0) {
            if (tracked != (MANAGEMENT_RECOVERY_CERTIFICATE |
                            MANAGEMENT_RECOVERY_PENDING_KEY)) {
                result = -EILSEQ;
            }
        } else if (result == 0 &&
                   strcmp(operation.kind,
                          MANAGEMENT_OPERATION_MTLS_AUTHORITIES) == 0) {
            if (tracked != MANAGEMENT_RECOVERY_CLIENT_CA) {
                result = -EILSEQ;
            }
        } else if (result == 0 &&
                   strcmp(operation.kind,
                          MANAGEMENT_OPERATION_BACKUP_RESTORE) == 0) {
            if ((tracked & ~MANAGEMENT_RECOVERY_CERTIFICATE) != 0U) {
                result = -EILSEQ;
            }
            if (result == 0) {
                result = jg_database_recovery_checkpoint_restore(
                    management->database);
            }
            if (result == 0) {
                result = jg_database_operation_mark_ready(management->database);
            }
        } else if (result == 0) {
            result = -EILSEQ;
        }
        if (result == 0) {
            result = restore_recovery_files(management, existing, tracked);
        }
    }
    if (result == 0) {
        result = finish_recovered_operation(management, &operation);
    }
    if (result == 0) {
        result = cleanup_recovery_snapshots(management);
    }
    return result;
}

/** @brief Commit one final audit and retire its durable recovery intent. */
int finish_recovery_operation(struct jg_management *management,
                              int audit_result)
{
    int result = audit_result;

    if (result == 0) {
        result = jg_database_operation_clear(management->database);
    }
    if (result == 0) {
        result = jg_database_transaction_commit(management->database);
    }
    if (result != 0) {
        const int rollback_result =
            jg_database_transaction_rollback(management->database);
        const int recovery_result = recover_pending_operation(management);

        if (rollback_result != 0) {
            mark_management_degraded(
                management, MANAGEMENT_DEGRADED_DATABASE_ROLLBACK,
                "management.database_rollback",
                "A recovery audit transaction could not be rolled back");
        }
        if (recovery_result != 0) {
            mark_management_degraded(
                management, MANAGEMENT_DEGRADED_EXTERNAL_RECOVERY,
                "management.external_recovery",
                "A cross-resource mutation could not be recovered");
        }
        if (rollback_result != 0 || recovery_result != 0) {
            result = -EIO;
        }
    } else {
        const int cleanup_result = cleanup_recovery_snapshots(management);

        if (cleanup_result != 0) {
            (void)jg_log_emit(
                JG_LOG_WARNING, "management", "management.recovery_cleanup", "",
                "Committed recovery snapshots remain on disk", NULL);
        }
    }
    return result;
}

/** @brief Compensate a failed external operation using its durable intent. */
int abort_recovery_operation(struct jg_management *management,
                             int operation_result)
{
    const int recovery_result = recover_pending_operation(management);

    if (recovery_result != 0) {
        mark_management_degraded(
            management, MANAGEMENT_DEGRADED_EXTERNAL_RECOVERY,
            "management.external_recovery",
            "A failed cross-resource mutation could not be recovered");
    }
    return recovery_result == 0 ? operation_result : -EIO;
}

/** @brief Arm durable recovery for one confirmed network mutation. */
int start_network_recovery(struct jg_management *management,
                           const struct jg_network_config *previous,
                           const struct jg_network_config *replacement,
                           uint64_t now)
{
    uint8_t payload[1U + JG_NETWORK_CONFIG_WIRE_SIZE * 2U];
    size_t previous_size = 0U;
    size_t replacement_size = 0U;
    int result = 0;

    payload[0U] = MANAGEMENT_RECOVERY_VERSION;
    result = jg_network_config_encode(
        previous, payload + 1U, JG_NETWORK_CONFIG_WIRE_SIZE, &previous_size);
    if (result == 0) {
        result = jg_network_config_encode(
            replacement, payload + 1U + JG_NETWORK_CONFIG_WIRE_SIZE,
            JG_NETWORK_CONFIG_WIRE_SIZE, &replacement_size);
    }
    if (result == 0 && (previous_size != JG_NETWORK_CONFIG_WIRE_SIZE ||
                        replacement_size != JG_NETWORK_CONFIG_WIRE_SIZE)) {
        result = -EIO;
    }
    if (result == 0) {
        result = start_recovery_operation(
            management, MANAGEMENT_OPERATION_NETWORK_CONFIRM, payload,
            sizeof(payload), 0U, false, now);
    }
    return result;
}
