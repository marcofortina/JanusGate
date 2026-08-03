/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_jobs.c
 * @brief Bounded authenticated management job scheduling and retention.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "database_internal.h"
#include "janusgate/access.h"
#include "janusgate/auth.h"

/** @brief Run queued slow operations until management shutdown. */
static void *run_management_jobs(void *context);

/** @brief Read the current Unix time for job lifecycle timestamps. */
static int current_job_time(uint64_t *now)
{
    const time_t current = time(NULL);

    if (now == NULL || current < 0) {
        return -EIO;
    }
    *now = (uint64_t)current;
    return 0;
}

/** @brief Securely release one job's transient input. */
void management_job_parameters_clear(
    enum management_job_kind kind,
    union management_job_parameters *parameters)
{
    if (kind == MANAGEMENT_JOB_BLOCKLIST_IMPORT &&
        parameters->blocklist_import.content != NULL) {
        sodium_memzero(parameters->blocklist_import.content,
                       parameters->blocklist_import.content_size);
        free(parameters->blocklist_import.content);
    }
    sodium_memzero(parameters, sizeof(*parameters));
}

/** @brief Stop and release one slow-operation queue. */
void management_jobs_destroy(struct management_jobs *jobs)
{
    if (jobs == NULL) {
        return;
    }
    if (jobs->mutex_initialized) {
        (void)pthread_mutex_lock(&jobs->mutex);
        jobs->stopping = true;
        if (jobs->condition_initialized) {
            (void)pthread_cond_broadcast(&jobs->ready);
        }
        (void)pthread_mutex_unlock(&jobs->mutex);
    }
    if (jobs->thread_started) {
        (void)pthread_join(jobs->thread, NULL);
    }
    jg_database_close(jobs->database);
    jobs->database = NULL;
    if (jobs->condition_initialized) {
        (void)pthread_cond_destroy(&jobs->ready);
    }
    if (jobs->mutex_initialized) {
        (void)pthread_mutex_destroy(&jobs->mutex);
    }
    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        management_job_parameters_clear(jobs->slots[index].kind,
                                        &jobs->slots[index].parameters);
    }
    sodium_memzero(jobs->slots, sizeof(jobs->slots));
    sodium_memzero(&jobs->worker_job, sizeof(jobs->worker_job));
    sodium_memzero(&jobs->worker, sizeof(jobs->worker));
    free(jobs);
}

/** @brief Create one fixed-capacity slow-operation worker. */
int management_jobs_create(struct jg_management *management,
                           struct management_jobs **jobs)
{
    struct management_jobs *created = NULL;
    int status = 0;
    int result = 0;

    if (management == NULL || jobs == NULL) {
        return -EINVAL;
    }
    *jobs = NULL;
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    created->next_sequence = 1U;
    result = jg_database_open_peer(management->database, &created->database);
    if (result == 0) {
        created->worker.database = created->database;
        created->worker.runtime = management->runtime;
        created->worker.health = management->health;
        created->worker.secrets = management->secrets;
        created->worker.consistency = management->consistency;
        (void)memcpy(created->worker.totp_key_path, management->totp_key_path,
                     strlen(management->totp_key_path) + 1U);
        (void)memcpy(created->worker.certificate_path,
                     management->certificate_path,
                     strlen(management->certificate_path) + 1U);
        (void)memcpy(created->worker.client_ca_path, management->client_ca_path,
                     strlen(management->client_ca_path) + 1U);
        (void)memcpy(created->worker.backup_directory,
                     management->backup_directory,
                     strlen(management->backup_directory) + 1U);
    }
    if (result == 0) {
        status = pthread_mutex_init(&created->mutex, NULL);
        result = status == 0 ? 0 : -status;
        created->mutex_initialized = result == 0;
    }
    if (result == 0) {
        status = pthread_cond_init(&created->ready, NULL);
        result = status == 0 ? 0 : -status;
        created->condition_initialized = result == 0;
    }
    if (result == 0) {
        status = pthread_create(&created->thread, NULL, run_management_jobs,
                                created);
        result = status == 0 ? 0 : -status;
        created->thread_started = result == 0;
    }
    if (result != 0) {
        management_jobs_destroy(created);
        return result;
    }
    *jobs = created;
    return 0;
}

/** @brief Return whether one completed job slot may be safely reused. */
static bool job_slot_reusable(const struct management_job *job, uint64_t now)
{
    return !job->occupied ||
           (job->state == MANAGEMENT_JOB_COMPLETED &&
            (job->observed ||
             (job->completed_at <= now &&
              now - job->completed_at >= MANAGEMENT_JOB_RETENTION_SECONDS)));
}

/** @brief Select one free, observed, or expired completed job slot. */
static struct management_job *select_job_slot(struct management_jobs *jobs,
                                              uint64_t now)
{
    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        struct management_job *job = &jobs->slots[index];

        if (job_slot_reusable(job, now)) {
            return job;
        }
    }
    return NULL;
}

/** @brief Return whether two authenticated actors own the same job scope. */
static bool job_actors_equal(const struct authenticated_actor *left,
                             const struct authenticated_actor *right)
{
    return left->kind == right->kind && left->actor_id == right->actor_id;
}

/** @brief Match the exact authorization and origin of one queued job. */
static bool job_context_equal(
    const struct management_job *job,
    const struct authenticated_actor *actor,
    const struct management_job_authorization *authorization,
    const struct remote_address *remote)
{
    const uint8_t *job_credential = NULL;
    const uint8_t *credential = NULL;
    size_t credential_size = 0U;

    if (!job_actors_equal(&job->actor, actor) ||
        job->remote.family != remote->family ||
        sodium_memcmp(job->remote.address, remote->address,
                      sizeof(job->remote.address)) != 0) {
        return false;
    }
    if (actor->kind == AUTHENTICATED_ACTOR_LOCAL) {
        return true;
    }
    if (actor->kind == AUTHENTICATED_ACTOR_USER) {
        job_credential = job->authorization.session_digest;
        credential = authorization->session_digest;
        credential_size = sizeof(authorization->session_digest);
    } else if (actor->kind == AUTHENTICATED_ACTOR_TOKEN) {
        job_credential = job->authorization.certificate_fingerprint;
        credential = authorization->certificate_fingerprint;
        credential_size = sizeof(authorization->certificate_fingerprint);
    } else {
        return false;
    }
    return sodium_memcmp(job_credential, credential, credential_size) == 0;
}

/** @brief Enforce per-actor and reserved-system queue capacity. */
static int check_job_capacity(const struct management_jobs *jobs,
                              const struct authenticated_actor *actor,
                              uint64_t now)
{
    size_t actor_jobs = 0U;
    size_t user_jobs = 0U;

    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        const struct management_job *job = &jobs->slots[index];

        if (job_slot_reusable(job, now) || job->system_job) {
            continue;
        }
        ++user_jobs;
        if (job_actors_equal(&job->actor, actor)) {
            ++actor_jobs;
        }
    }
    if (actor_jobs >= MANAGEMENT_JOB_ACTOR_CAPACITY) {
        return -EAGAIN;
    }
    return user_jobs >= MANAGEMENT_JOB_USER_CAPACITY ? -EBUSY : 0;
}

/** @brief Coalesce refreshes and serialize restore operations. */
static int check_job_conflict(
    const struct management_jobs *jobs,
    const struct authenticated_actor *actor,
    const struct management_job_authorization *authorization,
    const struct remote_address *remote,
    const struct management_job_submission *prepared,
    uint64_t now,
    uint64_t *job_id)
{
    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        const struct management_job *job = &jobs->slots[index];

        if (!job->occupied) {
            continue;
        }
        if (prepared->kind == MANAGEMENT_JOB_CERTIFICATE_CSR &&
            job->kind == MANAGEMENT_JOB_CERTIFICATE_CSR &&
            !job_slot_reusable(job, now)) {
            return -EALREADY;
        }
        if (job->state == MANAGEMENT_JOB_COMPLETED) {
            continue;
        }
        if (prepared->kind == MANAGEMENT_JOB_SOURCE_REFRESH &&
            job->kind == MANAGEMENT_JOB_SOURCE_REFRESH &&
            job->resource_id == prepared->parameters.source.id) {
            if (job->state == MANAGEMENT_JOB_QUEUED &&
                job_context_equal(job, actor, authorization, remote)) {
                *job_id = job->id;
                return 1;
            }
            return -EALREADY;
        }
        if (prepared->kind == MANAGEMENT_JOB_BACKUP_RESTORE &&
            job->kind == MANAGEMENT_JOB_BACKUP_RESTORE) {
            return -EALREADY;
        }
    }
    return 0;
}

/** @brief Generate one nonzero client-safe job identifier without collision.
 */
static int generate_job_identifier(const struct management_jobs *jobs,
                                   uint64_t *identifier)
{
    for (size_t attempt = 0U; attempt < MANAGEMENT_JOB_CAPACITY * 2U;
         ++attempt) {
        uint64_t candidate = 0U;
        bool collision = false;

        randombytes_buf(&candidate, sizeof(candidate));
        candidate &= MANAGEMENT_JOB_IDENTIFIER_MAX;
        if (candidate == 0U) {
            continue;
        }
        for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
            if (jobs->slots[index].occupied &&
                jobs->slots[index].id == candidate) {
                collision = true;
                break;
            }
        }
        if (!collision) {
            *identifier = candidate;
            return 0;
        }
    }
    return -EIO;
}

/** @brief Prepare deferred authorization without retaining a credential. */
static int prepare_job_authorization(
    const struct management_request *request,
    const struct authenticated_actor *actor,
    struct management_job_authorization *authorization)
{
    (void)memset(authorization, 0, sizeof(*authorization));
    if (actor->kind == AUTHENTICATED_ACTOR_LOCAL) {
        return 0;
    }
    if (actor->kind == AUTHENTICATED_ACTOR_USER) {
        return jg_auth_secret_digest((const uint8_t *)request->session,
                                     strlen(request->session),
                                     authorization->session_digest);
    }
    if (actor->kind == AUTHENTICATED_ACTOR_TOKEN) {
        return parse_certificate_fingerprint(
            request->client_certificate,
            authorization->certificate_fingerprint);
    }
    return -EINVAL;
}

/** @brief Queue one prepared authenticated slow operation. */
int submit_management_job(struct jg_management *management,
                          const struct management_request *request,
                          const struct remote_address *remote,
                          const struct authenticated_actor *actor,
                          struct management_job_submission *prepared,
                          uint64_t now,
                          uint64_t *job_id)
{
    struct management_jobs *jobs = management->jobs;
    struct management_job *job = NULL;
    struct management_job_authorization authorization;
    uint64_t identifier = 0U;
    bool coalesced = false;
    int status = 0;
    int result = prepare_job_authorization(request, actor, &authorization);

    if (result != 0) {
        return result;
    }
    status = pthread_mutex_lock(&jobs->mutex);
    if (status != 0) {
        sodium_memzero(&authorization, sizeof(authorization));
        return -status;
    }
    result = check_job_conflict(jobs, actor, &authorization, remote, prepared,
                                now, job_id);
    if (result == 1) {
        result = 0;
        coalesced = true;
    }
    if (result == 0 && !coalesced) {
        result = check_job_capacity(jobs, actor, now);
    }
    if (result == 0 && !coalesced) {
        job = select_job_slot(jobs, now);
        if (job == NULL || jobs->next_sequence == 0U) {
            result = job == NULL ? -EBUSY : -EOVERFLOW;
        } else {
            result = generate_job_identifier(jobs, &identifier);
        }
    }
    if (result == 0 && !coalesced) {
        management_job_parameters_clear(job->kind, &job->parameters);
        sodium_memzero(job, sizeof(*job));
        job->parameters = prepared->parameters;
        job->required_permission = prepared->required_permission;
        job->kind = prepared->kind;
        if (prepared->kind == MANAGEMENT_JOB_BLOCKLIST_IMPORT) {
            prepared->parameters.blocklist_import.content = NULL;
            prepared->parameters.blocklist_import.content_size = 0U;
        }
        job->actor = *actor;
        job->authorization = authorization;
        job->remote = *remote;
        job->id = identifier;
        if (prepared->kind == MANAGEMENT_JOB_SOURCE_REFRESH) {
            job->resource_id = prepared->parameters.source.id;
        }
        job->sequence = jobs->next_sequence++;
        job->submitted_at = now;
        job->state = MANAGEMENT_JOB_QUEUED;
        job->occupied = true;
        (void)snprintf(job->request_id, sizeof(job->request_id), "%s",
                       request->request_id);
        *job_id = job->id;
        status = pthread_cond_signal(&jobs->ready);
        if (status != 0) {
            management_job_parameters_clear(job->kind, &job->parameters);
            sodium_memzero(job, sizeof(*job));
            result = -status;
        }
    }
    status = pthread_mutex_unlock(&jobs->mutex);
    if (result == 0 && status != 0) {
        result = -status;
    }
    sodium_memzero(&authorization, sizeof(authorization));
    return result;
}

/** @brief Return the oldest queued job while holding the queue mutex. */
static struct management_job *next_queued_job(struct management_jobs *jobs)
{
    struct management_job *next = NULL;

    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        struct management_job *job = &jobs->slots[index];

        if (job->occupied && job->state == MANAGEMENT_JOB_QUEUED &&
            (next == NULL || job->sequence < next->sequence)) {
            next = job;
        }
    }
    return next;
}

/** @brief Find one retained job by identifier while holding the queue mutex. */
static struct management_job *find_job(struct management_jobs *jobs,
                                       uint64_t job_id)
{
    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        if (jobs->slots[index].occupied && jobs->slots[index].id == job_id) {
            return &jobs->slots[index];
        }
    }
    return NULL;
}

/** @brief Return whether one actor may inspect a retained user job. */
static bool job_is_visible_to_actor(const struct management_job *job,
                                    const struct authenticated_actor *actor)
{
    if (actor->kind == AUTHENTICATED_ACTOR_LOCAL) {
        return true;
    }
    return actor->actor_id != 0U && job_actors_equal(actor, &job->actor);
}

/** @brief Recheck a queued job against current persistent authorization. */
static int reauthorize_management_job(struct jg_management *management,
                                      struct management_job *job,
                                      uint64_t now)
{
    struct jg_account_identity identity;
    int result = 0;

    if (management_degraded_reasons(management) != 0U &&
        job->kind != MANAGEMENT_JOB_DIAGNOSTICS_CREATE) {
        return -EROFS;
    }
    if (job->system_job || job->actor.kind == AUTHENTICATED_ACTOR_LOCAL) {
        return 0;
    }
    if (job->actor.kind == AUTHENTICATED_ACTOR_USER) {
        result = jg_account_session_reauthorize(
            management->database, job->authorization.session_digest, now,
            MANAGEMENT_SESSION_INACTIVITY, job->remote.family,
            job->remote.address, &identity);
    } else if (job->actor.kind == AUTHENTICATED_ACTOR_TOKEN) {
        result = jg_account_token_reauthorize(
            management->database, job->actor.actor_id, now, job->remote.family,
            job->remote.address, &identity);
        if (result == 0) {
            result = jg_account_mtls_mapping_authorize(
                management->database,
                job->authorization.certificate_fingerprint, identity.user_id,
                now);
        }
    } else {
        result = -EACCES;
    }
    if (result == 0 &&
        (identity.user_id != job->actor.identity.user_id ||
         identity.force_password_change ||
         !jg_access_grants(identity.permissions, job->required_permission))) {
        result = -EPERM;
    }
    if (result == 0) {
        job->actor.identity = identity;
    }
    sodium_memzero(&identity, sizeof(identity));
    return result;
}

/** @brief Execute queued slow operations on an independent DB connection. */
static void *run_management_jobs(void *context)
{
    struct management_jobs *jobs = context;
    struct jg_management *worker = &jobs->worker;
    struct management_job *work = &jobs->worker_job;

    for (;;) {
        struct management_job *queued = NULL;
        uint64_t started_at = 0U;
        uint64_t completed_at = 0U;
        size_t response_size = 0U;
        int authorization_result = 0;
        int status = pthread_mutex_lock(&jobs->mutex);

        if (status != 0) {
            return NULL;
        }
        queued = next_queued_job(jobs);
        while (!jobs->stopping && queued == NULL) {
            status = pthread_cond_wait(&jobs->ready, &jobs->mutex);
            if (status != 0) {
                jobs->stopping = true;
                break;
            }
            queued = next_queued_job(jobs);
        }
        if (jobs->stopping) {
            (void)pthread_mutex_unlock(&jobs->mutex);
            break;
        }
        *work = *queued;
        (void)current_job_time(&started_at);
        (void)pthread_mutex_unlock(&jobs->mutex);

        authorization_result =
            reauthorize_management_job(worker, work, started_at);
        status = pthread_mutex_lock(&jobs->mutex);
        if (status != 0) {
            break;
        }
        queued = find_job(jobs, work->id);
        if (queued == NULL) {
            (void)pthread_mutex_unlock(&jobs->mutex);
            management_job_parameters_clear(work->kind, &work->parameters);
            sodium_memzero(work, sizeof(*work));
            continue;
        }
        if (authorization_result == 0) {
            queued->actor = work->actor;
            queued->state = MANAGEMENT_JOB_RUNNING;
            queued->started_at = started_at;
            work->started_at = started_at;
        }
        if (queued->kind == MANAGEMENT_JOB_BLOCKLIST_IMPORT) {
            queued->parameters.blocklist_import.content = NULL;
            queued->parameters.blocklist_import.content_size = 0U;
        }
        sodium_memzero(&queued->parameters, sizeof(queued->parameters));
        sodium_memzero(&queued->authorization, sizeof(queued->authorization));
        (void)pthread_mutex_unlock(&jobs->mutex);
        sodium_memzero(&work->authorization, sizeof(work->authorization));

        (void)execute_management_job(worker, work, authorization_result,
                                     &response_size);
        management_job_parameters_clear(work->kind, &work->parameters);
        (void)current_job_time(&completed_at);

        if (pthread_mutex_lock(&jobs->mutex) != 0) {
            break;
        }
        queued = find_job(jobs, work->id);
        if (queued != NULL && queued->system_job) {
            sodium_memzero(queued, sizeof(*queued));
        } else if (queued != NULL) {
            queued->response_size = response_size;
            queued->completed_at = completed_at;
            queued->state = MANAGEMENT_JOB_COMPLETED;
            if (response_size > 0U) {
                (void)memcpy(queued->response, work->response, response_size);
            }
        }
        (void)pthread_mutex_unlock(&jobs->mutex);
        sodium_memzero(work, sizeof(*work));
    }
    return NULL;
}

/** @brief Queue one coalesced scheduled-source scan. */
int submit_scheduled_source_job(struct jg_management *management, uint64_t now)
{
    struct management_jobs *jobs = management->jobs;
    struct management_job *job = NULL;
    uint64_t identifier = 0U;
    int status = pthread_mutex_lock(&jobs->mutex);
    int result = 0;

    if (status != 0) {
        return -status;
    }
    for (size_t index = 0U; index < MANAGEMENT_JOB_CAPACITY; ++index) {
        if (jobs->slots[index].occupied &&
            jobs->slots[index].kind == MANAGEMENT_JOB_SCHEDULED_SOURCES) {
            job = &jobs->slots[index];
            break;
        }
    }
    if (job == NULL) {
        job = select_job_slot(jobs, now);
        if (job == NULL || jobs->next_sequence == 0U) {
            result = job == NULL ? -EBUSY : -EOVERFLOW;
        } else if (generate_job_identifier(jobs, &identifier) != 0) {
            result = -EAGAIN;
        } else {
            sodium_memzero(job, sizeof(*job));
            job->id = identifier;
            job->sequence = jobs->next_sequence++;
            job->submitted_at = now;
            job->kind = MANAGEMENT_JOB_SCHEDULED_SOURCES;
            job->state = MANAGEMENT_JOB_QUEUED;
            job->occupied = true;
            job->system_job = true;
            status = pthread_cond_signal(&jobs->ready);
            if (status != 0) {
                sodium_memzero(job, sizeof(*job));
                result = -status;
            }
        }
    }
    status = pthread_mutex_unlock(&jobs->mutex);
    if (result == 0 && status != 0) {
        result = -status;
    }
    return result;
}

/** @brief Return the stable API spelling for one job state. */
const char *management_job_state_name(enum management_job_state state)
{
    switch (state) {
    case MANAGEMENT_JOB_QUEUED:
        return "queued";
    case MANAGEMENT_JOB_RUNNING:
        return "running";
    case MANAGEMENT_JOB_COMPLETED:
        return "completed";
    default:
        return NULL;
    }
}

/** @brief Return the stable API spelling for one job kind. */
const char *management_job_kind_name(enum management_job_kind kind)
{
    switch (kind) {
    case MANAGEMENT_JOB_SOURCE_REFRESH:
        return "source_refresh";
    case MANAGEMENT_JOB_SCHEDULED_SOURCES:
        return "scheduled_sources";
    case MANAGEMENT_JOB_BLOCKLIST_IMPORT:
        return "blocklist_import";
    case MANAGEMENT_JOB_BACKUP_CREATE:
        return "backup_create";
    case MANAGEMENT_JOB_BACKUP_RESTORE:
        return "backup_restore";
    case MANAGEMENT_JOB_DIAGNOSTICS_CREATE:
        return "diagnostics_create";
    case MANAGEMENT_JOB_CERTIFICATE_CSR:
        return "certificate_csr";
    default:
        return NULL;
    }
}

/** @brief Copy one retained job visible to an authenticated actor. */
int management_jobs_snapshot(struct management_jobs *jobs,
                             uint64_t job_id,
                             const struct authenticated_actor *actor,
                             struct management_job *snapshot)
{
    const struct management_job *stored = NULL;
    int status = 0;
    int result = 0;

    if (jobs == NULL || job_id == 0U || actor == NULL || snapshot == NULL) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&jobs->mutex);
    if (status != 0) {
        return -status;
    }
    stored = find_job(jobs, job_id);
    if (stored == NULL || stored->system_job ||
        !job_is_visible_to_actor(stored, actor)) {
        result = -ENOENT;
    } else {
        *snapshot = *stored;
    }
    status = pthread_mutex_unlock(&jobs->mutex);
    if (result == 0 && status != 0) {
        result = -status;
    }
    return result;
}

/** @brief Mark one completed retained job as consumed. */
int management_jobs_observe(struct management_jobs *jobs, uint64_t job_id)
{
    struct management_job *stored = NULL;
    int status = 0;
    int result = 0;

    if (jobs == NULL || job_id == 0U) {
        return -EINVAL;
    }
    status = pthread_mutex_lock(&jobs->mutex);
    if (status != 0) {
        return -status;
    }
    stored = find_job(jobs, job_id);
    if (stored != NULL && stored->state == MANAGEMENT_JOB_COMPLETED) {
        stored->observed = true;
    }
    status = pthread_mutex_unlock(&jobs->mutex);
    if (status != 0) {
        result = -status;
    }
    return result;
}
