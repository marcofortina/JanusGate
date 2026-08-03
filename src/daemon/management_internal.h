/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/* Private state shared by management control-plane modules. */

#ifndef JANUSGATE_DAEMON_MANAGEMENT_INTERNAL_H
#define JANUSGATE_DAEMON_MANAGEMENT_INTERNAL_H

/** @cond INTERNAL */

#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "daemon_runtime.h"
#include "janusgate/account.h"
#include "janusgate/audit.h"
#include "janusgate/backup.h"
#include "janusgate/ipc.h"
#include "management.h"

/** Absolute authenticated web-session lifetime. */
#define MANAGEMENT_SESSION_LIFETIME 43200U

/** Authenticated web-session inactivity timeout. */
#define MANAGEMENT_SESSION_INACTIVITY 1800U

/** Maximum internal management request bytes. */
#define MANAGEMENT_REQUEST_SIZE_MAX 65536U

/** Maximum request identifier bytes excluding its terminator. */
#define MANAGEMENT_REQUEST_ID_MAX 64U

/** Maximum management route bytes excluding its terminator. */
#define MANAGEMENT_PATH_MAX 256U

/** Maximum management query bytes excluding its terminator. */
#define MANAGEMENT_QUERY_MAX 256U

/** Maximum distinct API-token rate windows retained in memory. */
#define MANAGEMENT_TOKEN_RATE_SLOT_COUNT 256U

/** Maximum distinct browser-login source windows retained in memory. */
#define MANAGEMENT_LOGIN_RATE_SLOT_COUNT 256U

/** Accepted logins from one IPv4 address or IPv6 /64 per 60-second window. */
#define MANAGEMENT_LOGIN_SOURCE_RATE 10U

/** Accepted login attempts appliance-wide per 60-second window. */
#define MANAGEMENT_LOGIN_GLOBAL_RATE 100U

/** Maximum diagnostic archive bytes carried by one management response. */
#define MANAGEMENT_DIAGNOSTIC_ARCHIVE_SIZE_MAX 45000U

/** Shortest accepted diagnostic logging interval in seconds. */
#define MANAGEMENT_DIAGNOSTIC_DURATION_MIN 60U

/** Longest accepted diagnostic logging interval in seconds. */
#define MANAGEMENT_DIAGNOSTIC_DURATION_MAX 3600U

/** Complete timestamped diagnostic archive filename bytes. */
#define MANAGEMENT_DIAGNOSTIC_FILENAME_SIZE 48U

/** Maximum DNS or textual IP name accepted in a certificate request. */
#define MANAGEMENT_CERTIFICATE_NAME_MAX 253U

/** Maximum retained queued, running, or completed slow operations. */
#define MANAGEMENT_JOB_CAPACITY 8U

/** Maximum retained user jobs, leaving one slot for scheduled work. */
#define MANAGEMENT_JOB_USER_CAPACITY (MANAGEMENT_JOB_CAPACITY - 1U)

/** Maximum unconsumed jobs retained for one authenticated actor. */
#define MANAGEMENT_JOB_ACTOR_CAPACITY 2U

/** Maximum completed-job retention before its slot may be reused. */
#define MANAGEMENT_JOB_RETENTION_SECONDS 3600U

/** Largest job identifier represented exactly by every supported client. */
#define MANAGEMENT_JOB_IDENTIFIER_MAX UINT64_C(9007199254740991)

/** Version byte for durable cross-resource recovery payloads. */
#define MANAGEMENT_RECOVERY_VERSION UINT8_C(1)

/** Suffix reserved for durable certificate recovery snapshots. */
#define MANAGEMENT_RECOVERY_SUFFIX ".rollback"

/** Persistent cross-resource operation kinds. */
#define MANAGEMENT_OPERATION_CERTIFICATE_CSR "certificate_csr"
#define MANAGEMENT_OPERATION_CERTIFICATE_INSTALL "certificate_install"
#define MANAGEMENT_OPERATION_MTLS_AUTHORITIES "mtls_authorities"
#define MANAGEMENT_OPERATION_BACKUP_CREATE "backup_create"
#define MANAGEMENT_OPERATION_BACKUP_RESTORE "backup_restore"
#define MANAGEMENT_OPERATION_NETWORK_CONFIRM "network_confirm"

/** Files whose previous generation is retained by one recovery operation. */
enum management_recovery_file {
    MANAGEMENT_RECOVERY_CERTIFICATE = 1U << 0U,
    MANAGEMENT_RECOVERY_PENDING_KEY = 1U << 1U,
    MANAGEMENT_RECOVERY_CLIENT_CA = 1U << 2U
};

/** Consistency failures that suspend ordinary management mutations. */
enum management_degraded_reason {
    MANAGEMENT_DEGRADED_DATABASE_ROLLBACK = 1U << 0U,
    MANAGEMENT_DEGRADED_EXTERNAL_RECOVERY = 1U << 1U,
    MANAGEMENT_DEGRADED_POLICY_SYNC = 1U << 2U
};

/** Health state shared by request and slow-operation worker contexts. */
struct management_health {
    _Atomic uint32_t degraded_reasons;
};

/** Opaque bounded slow-operation queue owned by management state. */
struct management_jobs;

/** Opaque reader/exclusive gate shared by every management context. */
struct management_consistency;

/** One bounded fixed-window token request counter. */
struct token_rate_slot {
    uint64_t token_id;
    uint64_t minute;
    uint64_t last_request;
    uint32_t requests;
};

/** One bounded source-address login window. */
struct login_rate_slot {
    enum jg_policy_address_family family;
    uint8_t source[16U];
    uint64_t window_started_at;
    uint64_t last_request;
    uint32_t requests;
};

/** Complete borrowed and secret state for serialized request processing. */
struct jg_management {
    struct jg_database *database;
    struct jg_daemon_runtime *runtime;
    struct management_health *health;
    struct jg_auth_password_policy password_policy;
    struct token_rate_slot token_rates[MANAGEMENT_TOKEN_RATE_SLOT_COUNT];
    struct login_rate_slot login_rates[MANAGEMENT_LOGIN_RATE_SLOT_COUNT];
    uint64_t login_global_window_started_at;
    uint32_t login_global_requests;
    char certificate_path[PATH_MAX];
    char client_ca_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    uint8_t totp_key[JG_AUTH_TOTP_KEY_SIZE];
    enum jg_system_action pending_system_action;
    struct management_consistency *consistency;
    struct management_jobs *jobs;
};

/** Validated borrowed view of one internal JSON request envelope. */
struct management_request {
    const char *request_id;
    const char *method;
    const char *path;
    const char *query;
    const char *host;
    const char *origin;
    const char *remote_address;
    const char *session;
    const char *csrf;
    const char *bearer;
    const char *client_certificate;
    json_t *body;
    bool local_administrator;
};

/** Parsed network-order remote management address. */
struct remote_address {
    enum jg_policy_address_family family;
    uint8_t address[16U];
};

/** Optional session-cookie instructions returned to the HTTPS process. */
struct session_result {
    const char *set_session;
    bool clear_session;
};

/** Authentication mechanism assigned to one authorized management actor. */
enum authenticated_actor_kind {
    AUTHENTICATED_ACTOR_USER = 1,
    AUTHENTICATED_ACTOR_TOKEN = 2,
    AUTHENTICATED_ACTOR_LOCAL = 3
};

/** Authenticated actor used for backend authorization and audit provenance. */
struct authenticated_actor {
    struct jg_account_identity identity;
    uint64_t actor_id;
    enum authenticated_actor_kind kind;
};

/** Initiating authenticated request retained by a durable operation. */
struct management_operation_origin {
    const struct management_request *request;
    const struct remote_address *remote;
    const struct authenticated_actor *actor;
    const char *action;
};

/** Slow operation kinds executed by the single bounded worker. */
enum management_job_kind {
    MANAGEMENT_JOB_SOURCE_REFRESH = 1,
    MANAGEMENT_JOB_SCHEDULED_SOURCES = 2,
    MANAGEMENT_JOB_BLOCKLIST_IMPORT = 3,
    MANAGEMENT_JOB_BACKUP_CREATE = 4,
    MANAGEMENT_JOB_BACKUP_RESTORE = 5,
    MANAGEMENT_JOB_DIAGNOSTICS_CREATE = 6,
    MANAGEMENT_JOB_CERTIFICATE_CSR = 7
};

/** Stable lifecycle states exposed through the management API. */
enum management_job_state {
    MANAGEMENT_JOB_QUEUED = 1,
    MANAGEMENT_JOB_RUNNING = 2,
    MANAGEMENT_JOB_COMPLETED = 3
};

/** Type-specific bounded input retained only until a job starts. */
union management_job_parameters {
    struct {
        uint64_t id;
        uint64_t revision;
    } source;
    struct {
        uint8_t *content;
        size_t content_size;
        uint64_t source_id;
        uint64_t revision;
    } blocklist_import;
    struct {
        char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U];
        size_t passphrase_size;
        enum jg_backup_kind kind;
        bool include_private_key;
    } backup_create;
    struct {
        char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U];
        size_t passphrase_size;
        uint64_t backup_id;
        bool dry_run;
    } backup_restore;
    struct {
        char common_name[MANAGEMENT_CERTIFICATE_NAME_MAX + 1U];
        char alternative_names[JG_CERTIFICATE_SAN_MAX]
                              [MANAGEMENT_CERTIFICATE_NAME_MAX + 1U];
        size_t alternative_name_count;
    } certificate_csr;
};

/** Compact slow-operation input prepared by the control thread. */
struct management_job_submission {
    union management_job_parameters parameters;
    uint32_t required_permission;
    enum management_job_kind kind;
};

/** Reauthorization material retained without plaintext credentials. */
struct management_job_authorization {
    uint8_t session_digest[JG_AUTH_SECRET_DIGEST_SIZE];
    uint8_t certificate_fingerprint[32U];
};

/** One fixed-slot slow operation and its bounded final response. */
struct management_job {
    struct authenticated_actor actor;
    struct management_job_authorization authorization;
    struct remote_address remote;
    uint8_t response[JG_IPC_MAX_BODY_SIZE];
    size_t response_size;
    uint64_t id;
    uint64_t resource_id;
    uint64_t sequence;
    uint64_t submitted_at;
    uint64_t started_at;
    uint64_t completed_at;
    uint32_t required_permission;
    enum management_job_kind kind;
    enum management_job_state state;
    union management_job_parameters parameters;
    char request_id[MANAGEMENT_REQUEST_ID_MAX + 1U];
    bool occupied;
    bool system_job;
    bool observed;
};

/** Complete synchronized queue and independent worker database connection. */
struct management_jobs {
    struct jg_database *database;
    struct jg_management worker;
    struct management_job slots[MANAGEMENT_JOB_CAPACITY];
    struct management_job worker_job;
    pthread_mutex_t mutex;
    pthread_cond_t ready;
    pthread_t thread;
    uint64_t next_sequence;
    bool mutex_initialized;
    bool condition_initialized;
    bool thread_started;
    bool stopping;
};

/** @brief Read the consistency reasons currently affecting management. */
uint32_t management_degraded_reasons(const struct jg_management *management);

/** @brief Create one management mutation and restore consistency gate. */
int management_consistency_create(struct management_consistency **consistency);

/** @brief Release one unused management consistency gate. */
void management_consistency_destroy(struct management_consistency *consistency);

/** @brief Enter one ordinary state-changing management operation. */
int management_mutation_begin(struct jg_management *management);

/** @brief Leave one ordinary state-changing management operation. */
void management_mutation_end(struct jg_management *management);

/** @brief Exclude new mutations and wait for active mutations to finish. */
int management_restore_begin(struct jg_management *management);

/** @brief Reopen management mutations after a restore attempt. */
void management_restore_end(struct jg_management *management);

/** @brief Report whether an exclusive restore currently owns the gate. */
bool management_restore_in_progress(struct jg_management *management);

/** @brief Parse one exact lowercase SHA-256 certificate fingerprint. */
int parse_certificate_fingerprint(const char *text, uint8_t fingerprint[32U]);

/** @brief Securely release one job's transient input. */
void management_job_parameters_clear(
    enum management_job_kind kind,
    union management_job_parameters *parameters);

/** @brief Create one fixed-capacity slow-operation worker. */
int management_jobs_create(struct jg_management *management,
                           struct management_jobs **jobs);

/** @brief Stop and release one slow-operation queue. */
void management_jobs_destroy(struct management_jobs *jobs);

/** @brief Queue one prepared authenticated slow operation. */
int submit_management_job(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          const struct authenticated_actor *actor,
                          struct management_job_submission *prepared,
                          uint64_t now,
                          uint64_t *job_id);

/** @brief Queue one coalesced scheduled-source scan. */
int submit_scheduled_source_job(struct jg_management *management, uint64_t now);

/** @brief Copy one retained job visible to an authenticated actor. */
int management_jobs_snapshot(struct management_jobs *jobs,
                             uint64_t job_id,
                             const struct authenticated_actor *actor,
                             struct management_job *snapshot);

/** @brief Mark one completed retained job as consumed. */
int management_jobs_observe(struct management_jobs *jobs, uint64_t job_id);

/** @brief Return the stable API spelling for one job state. */
const char *management_job_state_name(enum management_job_state state);

/** @brief Return the stable API spelling for one job kind. */
const char *management_job_kind_name(enum management_job_kind kind);

/** @brief Execute or reject one reauthorized worker-owned operation. */
int execute_management_job(struct jg_management *management,
                           struct management_job *job,
                           int authorization_result,
                           size_t *response_size);

/** @brief Accept only named fields in one exact request object. */
bool fields_allowed(json_t *object,
                    const char *const *fields,
                    size_t field_count);

/** @brief Read one required nonempty string from an object. */
const char *required_string(const json_t *object,
                            const char *name,
                            size_t minimum,
                            size_t maximum);

/** @brief Read one required Boolean from an object. */
bool required_boolean(const json_t *object, const char *name, bool *value);

/** @brief Read one required positive client-safe identifier. */
bool required_identifier(const json_t *object,
                         const char *name,
                         uint64_t *value);

/** @brief Read one required bounded nonnegative integer. */
bool required_unsigned(const json_t *object,
                       const char *name,
                       uint64_t maximum,
                       uint64_t *value);

/** @brief Read one required string or explicit null from an object. */
bool required_nullable_string(const json_t *object,
                              const char *name,
                              size_t maximum,
                              const char **value);

/** @brief Parse bounded after/limit pagination parameters. */
int parse_page_query(const char *query,
                     const char *cursor_name,
                     size_t maximum_limit,
                     uint64_t *position,
                     size_t *limit);

/** @brief Encode one JSON API response envelope. */
int encode_response(int status,
                    json_t *body,
                    const struct session_result *session,
                    uint8_t *output,
                    size_t output_size,
                    size_t *written);

/** @brief Return one bounded stable API error envelope. */
int respond_error(int status,
                  const char *code,
                  const char *message,
                  const char *request_id,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written);

/** @brief Return one accepted slow-operation reference. */
int respond_job_accepted(uint64_t job_id,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Return one consistent slow-operation submission error. */
int respond_job_submission_error(int result,
                                 const struct management_request *request,
                                 const char *failure_message,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written);

/** @brief Return the persistent audit kind for one authenticated actor. */
enum jg_audit_actor_type actor_audit_type(
    const struct authenticated_actor *actor);

/** @brief Return whether one actor has a persistent database identifier. */
bool actor_has_identifier(const struct authenticated_actor *actor);

/** @brief Authenticate one session, token, certificate, or local root actor. */
int authenticate_actor(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       bool state_change,
                       uint32_t permission,
                       uint64_t now,
                       struct authenticated_actor *actor);

/** @brief Convert one authentication failure to its stable API response. */
int respond_actor_error(int result,
                        const struct management_request *request,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

/** @brief Add one nonnegative runtime counter to a JSON object. */
int set_counter(json_t *object, const char *name, uint64_t value);

/** @brief Return persistent logging configuration and runtime counters. */
int handle_logging_get(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Persist, audit, and activate logging configuration. */
int handle_logging_update(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written);

/** @brief Return the bounded in-memory diagnostic trace window. */
int handle_logging_traces(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written);

/** @brief Reconcile shared health with persistent policy publication state. */
void refresh_policy_sync_health(struct jg_management *management);

/** @brief Execute one authenticated backup creation job. */
int execute_backup_create_job(struct jg_management *management,
                              const struct management_job *job,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Execute one authenticated backup restore job. */
int execute_backup_restore_job(struct jg_management *management,
                               const struct management_job *job,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Return one authenticated stable page of backup metadata. */
int handle_backups_list(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

/** @brief Queue one authenticated backup creation. */
int handle_backup_create(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Inspect one authenticated stored backup. */
int handle_backup_inspect(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t backup_id,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written);

/** @brief Queue one validated or confirmed backup restore. */
int handle_backup_restore(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t backup_id,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written);

/** @brief Build the private pending-key path paired with the server identity.
 */
int certificate_pending_path(const struct jg_management *management,
                             char path[PATH_MAX]);

/** @brief Compare every semantic field of two network configurations. */
bool network_configs_equal(const struct jg_network_config *left,
                           const struct jg_network_config *right);

/** @brief Record one consistency failure and emit its first occurrence. */
void mark_management_degraded(struct jg_management *management,
                              uint32_t reason,
                              const char *event_code,
                              const char *message);

/** @brief Inspect whether a secure server identity currently exists. */
int server_identity_present(const char *path, bool *present);

/** @brief Inspect whether a secure pending private key currently exists. */
int pending_key_present(const char *path, bool *present);

/** @brief Inspect whether a secure client trust store currently exists. */
int client_ca_present(const char *path, bool *present);

/** @brief Reserve, snapshot, and arm one cross-resource operation. */
int start_recovery_operation(struct jg_management *management,
                             const char *kind,
                             const uint8_t *payload,
                             size_t payload_size,
                             uint8_t files,
                             bool database,
                             const struct management_operation_origin *origin,
                             uint64_t now);

/** @brief Restore or discard one operation left pending across a restart. */
int recover_pending_operation(struct jg_management *management);

/** @brief Commit one final audit and retire its durable recovery intent. */
int finish_recovery_operation(struct jg_management *management,
                              int audit_result);

/** @brief Compensate a failed external operation using its durable intent. */
int abort_recovery_operation(struct jg_management *management,
                             int operation_result);

/** @brief Arm durable recovery for one confirmed network mutation. */
int start_network_recovery(struct jg_management *management,
                           const struct jg_network_config *previous,
                           const struct jg_network_config *replacement,
                           const struct management_operation_origin *origin,
                           uint64_t now);

/** @endcond */

#endif
