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
#include "janusgate/alert.h"
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
    MANAGEMENT_RECOVERY_CLIENT_CA = 1U << 2U,
    MANAGEMENT_RECOVERY_TOTP_KEY = 1U << 3U
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
    _Atomic uint64_t authentication_failures_total;
    _Atomic uint64_t alert_open_by_type[JG_ALERT_TYPE_COUNT];
    _Atomic uint64_t alert_incidents_retained;
    _Atomic uint64_t alert_resolutions_retained;
    _Atomic uint64_t alert_deliveries_pending;
    _Atomic uint64_t alert_deliveries_succeeded;
    _Atomic uint64_t alert_deliveries_failed;
    _Atomic uint64_t alert_last_evaluation_at;
    _Atomic uint64_t certificate_expiry_timestamp;
    _Atomic uint64_t blocklist_sources_unhealthy;
    _Atomic uint64_t blocklist_sources_stale;
    _Atomic uint64_t filesystem_minimum_available_bytes;
    _Atomic uint64_t filesystem_minimum_available_basis_points;
    _Atomic bool alert_evaluation_successful;
    _Atomic bool audit_valid;
    _Atomic bool policy_synchronized;
};

/** Secret material shared by request processing and the job worker. */
struct management_secrets {
    uint8_t totp_key[JG_AUTH_TOTP_KEY_SIZE];
};

/** Opaque bounded slow-operation queue owned by management state. */
struct management_jobs;

/** Opaque native alert evaluator and delivery worker. */
struct management_alerts;

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
    char totp_key_path[PATH_MAX];
    char certificate_path[PATH_MAX];
    char client_ca_path[PATH_MAX];
    char backup_directory[PATH_MAX];
    struct management_secrets *secrets;
    enum jg_system_action pending_system_action;
    struct management_consistency *consistency;
    struct management_jobs *jobs;
    struct management_alerts *alerts;
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

/** @brief Advance, publish, and persist one policy revision attempt. */
int management_publish_policy_change(struct jg_management *management,
                                     uint64_t now,
                                     bool *published,
                                     uint64_t *runtime_generation);

/** @brief Return the stable external name for one fixed backend role. */
const char *management_role_name(enum jg_access_role role);

/** @brief Parse one exact fixed backend role name. */
enum jg_access_role management_parse_role(const char *name);

/** @brief Securely release one job's transient input. */
void management_job_parameters_clear(
    enum management_job_kind kind,
    union management_job_parameters *parameters);

/** @brief Create one fixed-capacity slow-operation worker. */
int management_jobs_create(struct jg_management *management,
                           struct management_jobs **jobs);

/** @brief Stop and release one slow-operation queue. */
void management_jobs_destroy(struct management_jobs *jobs);

/** @brief Start native alert evaluation and asynchronous delivery. */
int management_alerts_create(struct jg_management *management,
                             struct management_alerts **alerts);

/** @brief Start one fully initialized native alert worker. */
int management_alerts_start(struct management_alerts *alerts);

/** @brief Stop and release native alert evaluation state. */
void management_alerts_destroy(struct management_alerts *alerts);

/** @brief Wake alert evaluation after a relevant configuration change. */
void management_alerts_wake(struct management_alerts *alerts);

/** @brief Count one rejected credential or authenticated transport. */
void management_alert_authentication_failed(struct jg_management *management);

/** @brief Return one filtered page of native alert incidents. */
int handle_alerts_list(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Return or replace native alert configuration. */
int handle_alert_configuration(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Rotate and return the webhook secret exactly once. */
int handle_alert_webhook_secret(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                uint64_t now,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written);

/** @brief Enqueue one authenticated webhook test notification. */
int handle_alert_webhook_test(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

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

/** @brief Return a bounded string length or one past the maximum. */
size_t bounded_length(const char *text, size_t maximum);

/** @brief Read one required nonempty string from an object. */
const char *required_string(const json_t *object,
                            const char *name,
                            size_t minimum,
                            size_t maximum);

/** @brief Read one optional bounded JSON string field. */
const char *optional_string(const json_t *object,
                            const char *name,
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

/** @brief Decode one ASCII hexadecimal digit. */
int hexadecimal_value(char character, uint8_t *value);

/** @brief Decode one required nullable 32-byte hexadecimal field. */
bool required_optional_digest(const json_t *object,
                              const char *name,
                              uint8_t digest[32U],
                              bool *present);

/** @brief Parse an exact numeric IPv4 or IPv6 remote address. */
int parse_remote_address(const char *text, struct remote_address *remote);

/** @brief Add a timestamp or JSON null to one response object. */
int set_optional_timestamp(json_t *object, const char *name, uint64_t value);

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

/** @brief Parse one bounded unsigned decimal text span. */
int parse_decimal(const char *text,
                  size_t size,
                  uint64_t maximum,
                  uint64_t *value);

/** @brief Encode one JSON API response envelope. */
int encode_response(int status,
                    json_t *body,
                    const struct session_result *session,
                    uint8_t *output,
                    size_t output_size,
                    size_t *written);

/** @brief Encode one plain-text API response envelope. */
int encode_text_response(int status,
                         const char *content_type,
                         const char *text,
                         size_t text_size,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Create one consistent API error body. */
json_t *error_body(const char *code,
                   const char *message,
                   const char *request_id);

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

/** @brief Execute one authenticated remote-source refresh job. */
int execute_source_refresh_job(struct jg_management *management,
                               const struct management_job *job,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Execute one authenticated local blocklist import job. */
int execute_blocklist_import_job(struct jg_management *management,
                                 const struct management_job *job,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written);

/** @brief Process and audit every enabled remote source currently due. */
int update_due_blocklists_now(struct jg_management *management,
                              uint64_t now,
                              size_t *attempts);

/** @brief Execute one authenticated certificate-request generation job. */
int execute_certificate_csr_job(struct jg_management *management,
                                const struct management_job *job,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written);

/** @brief Execute one authenticated diagnostic archive job. */
int execute_diagnostics_create_job(struct jg_management *management,
                                   const struct management_job *job,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Report whether the appliance still requires initial setup. */
int handle_authentication_state(struct jg_management *management,
                                const struct management_request *request,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written);

/** @brief Consume bootstrap access and create the first administrator. */
int handle_bootstrap(struct jg_management *management,
                     const struct management_request *request,
                     const struct remote_address *remote,
                     uint64_t now,
                     uint8_t *output,
                     size_t output_size,
                     size_t *written);

/** @brief Authenticate a password and return one browser session. */
int handle_login(struct jg_management *management,
                 const struct management_request *request,
                 const struct remote_address *remote,
                 uint64_t now,
                 uint8_t *output,
                 size_t output_size,
                 size_t *written);

/** @brief Change the current user's password and rotate its web session. */
int handle_password_change(struct jg_management *management,
                           const struct management_request *request,
                           const struct remote_address *remote,
                           uint64_t now,
                           uint8_t *output,
                           size_t output_size,
                           size_t *written);

/** @brief Return one authenticated stable page of local users. */
int handle_users_list(struct jg_management *management,
                      const struct management_request *request,
                      const struct remote_address *remote,
                      uint64_t now,
                      uint8_t *output,
                      size_t output_size,
                      size_t *written);

/** @brief Create one local user through an authorized API request. */
int handle_user_create(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Replace one local user's mutable administration state. */
int handle_user_update(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t user_id,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Reset one local user's password without echoing credential data. */
int handle_user_password_reset(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t user_id,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Administratively remove one local user's TOTP credentials. */
int handle_user_totp_disable(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t user_id,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written);

/** @brief Return one authenticated stable page of API-token metadata. */
int handle_tokens_list(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Issue and display one new scoped API token exactly once. */
int handle_token_issue(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Revoke one API token idempotently and audit the action. */
int handle_token_revoke(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t token_id,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

/** @brief Return current public server-certificate metadata. */
int handle_certificate_show(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written);

/** @brief Queue one private-key and certificate-request generation. */
int handle_certificate_csr(struct jg_management *management,
                           const struct management_request *request,
                           const struct remote_address *remote,
                           uint64_t now,
                           uint8_t *output,
                           size_t output_size,
                           size_t *written);

/** @brief Install one validated server certificate with concurrency control. */
int handle_certificate_install(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Return the installed client-authority trust-store state. */
int handle_mtls_authorities_show(struct jg_management *management,
                                 const struct management_request *request,
                                 const struct remote_address *remote,
                                 uint64_t now,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *written);

/** @brief Validate and install a client-authority trust-store bundle. */
int handle_mtls_authorities_install(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    uint64_t now,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *written);

/** @brief Remove the client-authority trust store and disable remote mTLS. */
int handle_mtls_authorities_remove(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Return one authenticated stable page of certificate mappings. */
int handle_mtls_mappings_list(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Create a user- or role-bound client-certificate mapping. */
int handle_mtls_mapping_create(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Revoke one client-certificate mapping idempotently. */
int handle_mtls_mapping_revoke(struct jg_management *management,
                               const struct management_request *request,
                               const struct remote_address *remote,
                               uint64_t mapping_id,
                               uint64_t now,
                               uint8_t *output,
                               size_t output_size,
                               size_t *written);

/** @brief Return the current authenticated browser identity. */
int handle_session(struct jg_management *management,
                   const struct management_request *request,
                   const struct remote_address *remote,
                   uint64_t now,
                   uint8_t *output,
                   size_t output_size,
                   size_t *written);

/** @brief Revoke the current authenticated browser session. */
int handle_logout(struct jg_management *management,
                  const struct management_request *request,
                  const struct remote_address *remote,
                  uint64_t now,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written);

/** @brief Begin TOTP enrollment for the authenticated user. */
int handle_totp_provision(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          uint64_t now,
                          uint8_t *output,
                          size_t output_size,
                          size_t *written);

/** @brief Confirm TOTP and return newly issued recovery codes once. */
int handle_totp_confirm(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

/** @brief Verify current TOTP and disable multifactor authentication. */
int handle_totp_disable(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

/** @brief Simulate one authenticated decision on the active policy snapshot. */
int handle_policy_simulation(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written);

/** @brief Return impact and conservative findings for one policy rule. */
int handle_policy_rule_analysis(struct jg_management *management,
                                const struct management_request *request,
                                const struct remote_address *remote,
                                enum jg_policy_stats_dimension dimension,
                                uint64_t rule_id,
                                uint64_t now,
                                uint8_t *output,
                                size_t output_size,
                                size_t *written);

/** @brief Return or replace detailed policy-statistics retention. */
int handle_policy_statistics(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written);

/** @brief Preview or execute one detailed-statistics cleanup batch. */
int handle_policy_statistics_cleanup(struct jg_management *management,
                                     const struct management_request *request,
                                     const struct remote_address *remote,
                                     uint64_t now,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *written);

/** @brief Return one authenticated stable page of blocklist sources. */
int handle_blocklist_sources_list(struct jg_management *management,
                                  const struct management_request *request,
                                  const struct remote_address *remote,
                                  uint64_t now,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *written);

/** @brief Create one blocklist source through an authorized API request. */
int handle_blocklist_source_create(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Replace one blocklist source through an authorized API request. */
int handle_blocklist_source_update(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t source_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Delete one blocklist source through an authorized API request. */
int handle_blocklist_source_delete(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t source_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Refresh one remote blocklist source through an authorized request. */
int handle_blocklist_source_refresh(struct jg_management *management,
                                    const struct management_request *request,
                                    const struct remote_address *remote,
                                    uint64_t source_id,
                                    uint64_t now,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *written);

/** @brief Queue one uploaded blocklist for an authorized local source. */
int handle_blocklist_import(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written);

/** @brief Return one authenticated stable page of domain rules. */
int handle_domain_rules_list(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written);

/** @brief Return one authenticated stable page of destination rules. */
int handle_destination_rules_list(struct jg_management *management,
                                  const struct management_request *request,
                                  const struct remote_address *remote,
                                  uint64_t now,
                                  uint8_t *output,
                                  size_t output_size,
                                  size_t *written);

/** @brief Create one explicit domain rule and publish a new snapshot. */
int handle_domain_rule_create(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Update one explicit domain rule and publish a new snapshot. */
int handle_domain_rule_update(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t rule_id,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Delete one explicit domain rule and publish a new snapshot. */
int handle_domain_rule_delete(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t rule_id,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Create one explicit destination rule and publish a snapshot. */
int handle_destination_rule_create(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Update one explicit destination rule and publish a snapshot. */
int handle_destination_rule_update(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t rule_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Delete one explicit destination rule and publish a snapshot. */
int handle_destination_rule_delete(struct jg_management *management,
                                   const struct management_request *request,
                                   const struct remote_address *remote,
                                   uint64_t rule_id,
                                   uint64_t now,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *written);

/** @brief Return or replace snapshot-wide policy enforcement. */
int handle_policy_global_mode(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief List or create policy rule groups. */
int handle_policy_groups(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Replace or remove one policy rule group. */
int handle_policy_group(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t group_id,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

/** @brief List or create client-scoped policy modes. */
int handle_policy_scope_modes(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Replace or remove one client-scoped policy mode. */
int handle_policy_scope_mode(struct jg_management *management,
                             const struct management_request *request,
                             const struct remote_address *remote,
                             uint64_t mode_id,
                             uint64_t now,
                             uint8_t *output,
                             size_t output_size,
                             size_t *written);

/** @brief Return the persistent audit kind for one authenticated actor. */
enum jg_audit_actor_type actor_audit_type(
    const struct authenticated_actor *actor);

/** @brief Return whether one actor has a persistent database identifier. */
bool actor_has_identifier(const struct authenticated_actor *actor);

/** @brief Begin one persistent mutation that must share its audit commit. */
int audited_mutation_begin(struct jg_management *management);

/** @brief Abandon an audit scope when its persistent mutation fails. */
int audited_mutation_check(struct jg_management *management,
                           int operation_result);

/** @brief Commit a mutation with its audit event or restore prior state. */
int audited_mutation_finish(struct jg_management *management,
                            int operation_result,
                            bool reload_policy);

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

/** @brief Return authenticated daemon readiness and packet counters. */
int handle_status(struct jg_management *management,
                  const struct management_request *request,
                  const struct remote_address *remote,
                  uint64_t now,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written);

/** @brief Return authenticated management, daemon, and helper health. */
int handle_health(struct jg_management *management,
                  const struct management_request *request,
                  const struct remote_address *remote,
                  uint64_t now,
                  uint8_t *output,
                  size_t output_size,
                  size_t *written);

/** @brief Return authenticated Prometheus text for the current runtime. */
int handle_metrics(struct jg_management *management,
                   const struct management_request *request,
                   const struct remote_address *remote,
                   uint64_t now,
                   uint8_t *output,
                   size_t output_size,
                   size_t *written);

/** @brief Validate or atomically reload persistent runtime configuration. */
int handle_configuration(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         bool reload,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Authorize, audit, and defer one appliance lifecycle action. */
int handle_system_action(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         enum jg_system_action action,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Queue one authenticated diagnostic archive creation. */
int handle_diagnostics_create(struct jg_management *management,
                              const struct management_request *request,
                              const struct remote_address *remote,
                              uint64_t now,
                              uint8_t *output,
                              size_t output_size,
                              size_t *written);

/** @brief Return one authenticated filtered page of operational events. */
int handle_events_list(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Return one authenticated page of immutable audit records. */
int handle_audit_list(struct jg_management *management,
                      const struct management_request *request,
                      const struct remote_address *remote,
                      uint64_t now,
                      uint8_t *output,
                      size_t output_size,
                      size_t *written);

/** @brief Verify and report the complete authenticated audit chain. */
int handle_audit_verify(struct jg_management *management,
                        const struct management_request *request,
                        const struct remote_address *remote,
                        uint64_t now,
                        uint8_t *output,
                        size_t output_size,
                        size_t *written);

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

/** @brief Return the persistent inline-network configuration. */
int handle_network_get(struct jg_management *management,
                       const struct management_request *request,
                       const struct remote_address *remote,
                       uint64_t now,
                       uint8_t *output,
                       size_t output_size,
                       size_t *written);

/** @brief Validate a proposed network configuration without applying it. */
int handle_network_validate(struct jg_management *management,
                            const struct management_request *request,
                            const struct remote_address *remote,
                            uint64_t now,
                            uint8_t *output,
                            size_t output_size,
                            size_t *written);

/** @brief Stage one revision-bound network change for confirmation. */
int handle_network_apply(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Confirm one pending network change and persist its revision. */
int handle_network_confirm(struct jg_management *management,
                           const struct management_request *request,
                           const struct remote_address *remote,
                           uint64_t now,
                           uint8_t *output,
                           size_t output_size,
                           size_t *written);

/** @brief Roll back one pending network change without persistence. */
int handle_network_rollback(struct jg_management *management,
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

/** @brief Import one backup archive from a private local file. */
int handle_backup_import(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t now,
                         uint8_t *output,
                         size_t output_size,
                         size_t *written);

/** @brief Export one backup archive to a private local file. */
int handle_backup_export(struct jg_management *management,
                         const struct management_request *request,
                         const struct remote_address *remote,
                         uint64_t backup_id,
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

/** @brief Load one exact owner-private TOTP protection key. */
int management_totp_key_load(const char *path,
                             uint8_t key[JG_AUTH_TOTP_KEY_SIZE]);

/** @brief Atomically replace one owner-private TOTP protection key. */
int management_totp_key_store(const char *path,
                              const uint8_t key[JG_AUTH_TOTP_KEY_SIZE]);

/** @brief Atomically copy one validated TOTP protection key. */
int management_totp_key_copy(const char *source, const char *destination);

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
