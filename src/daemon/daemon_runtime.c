/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "daemon_runtime.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <net/if.h>

#include "dataplane_worker.h"
#include "janusgate/database.h"
#include "janusgate/network.h"
#include "management.h"
#include "netd_client.h"
#include "nfqueue.h"
#include "nfqueue_group.h"
#include "packet_output.h"
#include "policy_store.h"

/** Complete ownership tree for one packet runtime. */
struct jg_daemon_runtime {
    struct jg_database *database;
    struct jg_management *management;
    struct jg_policy_store *policies;
    struct jg_dataplane_worker *workers[JG_NETWORK_QUEUE_COUNT_MAX];
    struct jg_packet_output *outputs[JG_NETWORK_QUEUE_COUNT_MAX];
    struct jg_nfqueue_group *queues;
    atomic_uint_fast64_t policy_generation;
    size_t worker_count;
};

/** @brief Add one counter with saturation at its largest representation. */
static void saturating_add(uint64_t value, uint64_t *total)
{
    *total = value > UINT64_MAX - *total ? UINT64_MAX : *total + value;
}

/** @brief Add one worker's packet-path counters to an aggregate snapshot. */
static int aggregate_worker(const struct jg_daemon_runtime *runtime,
                            size_t index,
                            struct jg_daemon_runtime_stats *stats)
{
    struct jg_dataplane_stats dataplane;
    struct jg_fragment_stats fragments;
    struct jg_tcp_stream_stats tcp_streams;
    struct jg_packet_output_stats output;
    int result =
        jg_dataplane_worker_get_stats(runtime->workers[index], &dataplane);

    if (result == 0) {
        result = jg_dataplane_worker_get_fragment_stats(runtime->workers[index],
                                                        &fragments);
    }
    if (result == 0) {
        result = jg_dataplane_worker_get_stream_stats(runtime->workers[index],
                                                      &tcp_streams);
    }
    if (result == 0) {
        result = jg_packet_output_get_stats(runtime->outputs[index], &output);
    }
    if (result != 0) {
        return result;
    }

    saturating_add(dataplane.packets, &stats->dataplane.packets);
    saturating_add(dataplane.accepted, &stats->dataplane.accepted);
    saturating_add(dataplane.blocked, &stats->dataplane.blocked);
    saturating_add(dataplane.malformed, &stats->dataplane.malformed);
    saturating_add(dataplane.fragments, &stats->dataplane.fragments);
    saturating_add(dataplane.streams, &stats->dataplane.streams);
    saturating_add(dataplane.tcp_resets, &stats->dataplane.tcp_resets);
    saturating_add(dataplane.dns_dropped, &stats->dataplane.dns_dropped);
    saturating_add(dataplane.dns_refused, &stats->dataplane.dns_refused);
    saturating_add(dataplane.dns_nxdomain, &stats->dataplane.dns_nxdomain);
    saturating_add(dataplane.dns_sinkholed, &stats->dataplane.dns_sinkholed);
    saturating_add(dataplane.internal_errors,
                   &stats->dataplane.internal_errors);
    saturating_add(dataplane.sni_inspected, &stats->dataplane.sni_inspected);
    saturating_add(dataplane.sni_encrypted_or_unavailable,
                   &stats->dataplane.sni_encrypted_or_unavailable);

    saturating_add(fragments.stored, &stats->fragments.stored);
    saturating_add(fragments.duplicates, &stats->fragments.duplicates);
    saturating_add(fragments.completed, &stats->fragments.completed);
    saturating_add(fragments.malformed, &stats->fragments.malformed);
    saturating_add(fragments.overlaps, &stats->fragments.overlaps);
    saturating_add(fragments.exhausted, &stats->fragments.exhausted);
    saturating_add(fragments.timeouts, &stats->fragments.timeouts);

    saturating_add(tcp_streams.buffered, &stats->tcp_streams.buffered);
    saturating_add(tcp_streams.duplicates, &stats->tcp_streams.duplicates);
    saturating_add(tcp_streams.messages, &stats->tcp_streams.messages);
    saturating_add(tcp_streams.closed, &stats->tcp_streams.closed);
    saturating_add(tcp_streams.malformed, &stats->tcp_streams.malformed);
    saturating_add(tcp_streams.conflicts, &stats->tcp_streams.conflicts);
    saturating_add(tcp_streams.exhausted, &stats->tcp_streams.exhausted);
    saturating_add(tcp_streams.timeouts, &stats->tcp_streams.timeouts);

    saturating_add(output.sent, &stats->output.sent);
    saturating_add(output.errors, &stats->output.errors);
    return 0;
}

/** @brief Resolve one configured Linux interface to its stable index. */
static int resolve_interface(const char *name, uint32_t *index)
{
    unsigned int resolved = 0U;

    errno = 0;
    resolved = if_nametoindex(name);
    if (resolved == 0U) {
        return errno == 0 ? -ENODEV : -errno;
    }
    *index = (uint32_t)resolved;
    return 0;
}

/** @brief Create every exclusive policy worker and raw packet output. */
static int create_workers(struct jg_daemon_runtime *runtime,
                          const struct jg_daemon_runtime_config *config,
                          const struct jg_network_config *network,
                          const struct jg_dns_response_config *dns_response,
                          uint32_t ingress_index,
                          uint32_t egress_index)
{
    const struct jg_packet_output_config output_config = {
        .client_interface_index = ingress_index,
        .server_interface_index = egress_index,
        .send_buffer_size = config->packet_send_buffer_size,
    };
    size_t index = 0U;
    int result = jg_packet_output_config_validate(&output_config);

    runtime->worker_count = network->queue_count;
    for (index = 0U; result == 0 && index < runtime->worker_count; ++index) {
        result =
            jg_dataplane_worker_create(runtime->policies, index, NULL, NULL,
                                       NULL, &runtime->workers[index]);
        if (result == 0) {
            result =
                jg_packet_output_open(&output_config, &runtime->outputs[index]);
        }
        if (result == 0) {
            result = jg_dataplane_worker_set_reset_sender(
                runtime->workers[index], jg_packet_output_send_tcp_resets,
                runtime->outputs[index]);
        }
        if (result == 0) {
            result = jg_dataplane_worker_set_dns_response(
                runtime->workers[index], dns_response,
                jg_packet_output_send_client_frame, runtime->outputs[index]);
        }
    }
    return result;
}

/** @brief Start the validated persistent queue range last. */
static int start_queues(struct jg_daemon_runtime *runtime,
                        const struct jg_daemon_runtime_config *config,
                        const struct jg_network_config *network,
                        uint32_t ingress_index)
{
    const struct jg_nfqueue_group_config queue_config = {
        .queue_first = network->queue_first,
        .queue_count = network->queue_count,
        .ingress_index = ingress_index,
        .queue_length = network->queue_length,
        .receive_buffer_size = config->queue_receive_buffer_size,
        .first_cpu = config->first_cpu,
        .fail_open = network->failure_mode == JG_NETWORK_FAIL_OPEN,
        .pin_workers = config->pin_workers,
    };
    void *contexts[JG_NETWORK_QUEUE_COUNT_MAX] = {0};
    size_t index = 0U;
    int result = jg_nfqueue_group_config_validate(&queue_config);

    for (index = 0U; result == 0 && index < runtime->worker_count; ++index) {
        contexts[index] = runtime->workers[index];
    }
    if (result == 0) {
        result =
            jg_nfqueue_group_start(&queue_config, jg_dataplane_worker_process,
                                   contexts, &runtime->queues);
    }
    return result;
}

/** @brief Initialize conservative process-local runtime defaults. */
void jg_daemon_runtime_config_default(struct jg_daemon_runtime_config *config)
{
    if (config == NULL) {
        return;
    }
    *config = (struct jg_daemon_runtime_config){
        .database_path = JG_DAEMON_DATABASE_PATH,
        .totp_key_path = JG_DAEMON_TOTP_KEY_PATH,
        .certificate_path = JG_CERTIFICATE_DEFAULT_PATH,
        .backup_directory = JG_BACKUP_DEFAULT_DIRECTORY,
        .database_busy_timeout_ms = 5000U,
        .queue_receive_buffer_size = JG_NFQUEUE_RECEIVE_BUFFER_DEFAULT,
        .packet_send_buffer_size = JG_PACKET_OUTPUT_BUFFER_DEFAULT,
    };
    jg_dns_response_config_default(&config->dns_response);
}

/** @brief Validate process-local database and socket bounds. */
int jg_daemon_runtime_config_validate(
    const struct jg_daemon_runtime_config *config)
{
    if (config == NULL || config->database_path == NULL ||
        config->database_path[0] != '/' || config->database_path[1] == '\0' ||
        config->totp_key_path == NULL || config->totp_key_path[0] != '/' ||
        config->totp_key_path[1] == '\0' || config->certificate_path == NULL ||
        config->certificate_path[0] != '/' ||
        config->certificate_path[1] == '\0' ||
        config->backup_directory == NULL ||
        config->backup_directory[0] != '/' ||
        config->backup_directory[1] == '\0' ||
        config->database_busy_timeout_ms == 0U ||
        config->queue_receive_buffer_size == 0U ||
        config->packet_send_buffer_size == 0U ||
        jg_dns_response_config_validate(&config->dns_response) != 0) {
        return -EINVAL;
    }
    if (config->database_busy_timeout_ms > JG_DATABASE_BUSY_TIMEOUT_MAX ||
        config->queue_receive_buffer_size > JG_NFQUEUE_RECEIVE_BUFFER_MAX ||
        config->packet_send_buffer_size > JG_PACKET_OUTPUT_BUFFER_MAX) {
        return -ERANGE;
    }
    return 0;
}

/** @brief Load state, prepare workers, apply networking, and start queues. */
int jg_daemon_runtime_start(const struct jg_daemon_runtime_config *config,
                            struct jg_daemon_runtime **runtime)
{
    struct jg_daemon_runtime *started = NULL;
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_network_config network;
    struct jg_dns_response_config dns_response = {0};
    uint32_t ingress_index = 0U;
    uint32_t egress_index = 0U;
    int result = 0;

    if (runtime == NULL) {
        return -EINVAL;
    }
    *runtime = NULL;
    result = jg_daemon_runtime_config_validate(config);
    if (result == 0) {
        dns_response = config->dns_response;
    }
    if (result == 0) {
        started = calloc(1U, sizeof(*started));
        if (started == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        atomic_init(&started->policy_generation, 1U);
        result = jg_database_open(config->database_path,
                                  config->database_busy_timeout_ms,
                                  &started->database);
    }
    if (result == 0) {
        result = jg_management_create(
            started->database, config->totp_key_path, config->certificate_path,
            config->backup_directory, started, &started->management);
    }
    if (result == 0) {
        result = jg_database_load_network_config(started->database, &network);
    }
    if (result == 0) {
        result = jg_database_load_dns_response_config(started->database,
                                                      &dns_response);
        if (result == -ENOENT) {
            result = 0;
        }
    }
    if (result == 0) {
        result = resolve_interface(network.ingress, &ingress_index);
    }
    if (result == 0) {
        result = resolve_interface(network.egress, &egress_index);
    }
    if (result == 0) {
        result =
            jg_database_load_policy_snapshot(started->database, 1U, &snapshot);
    }
    if (result == 0) {
        result = jg_policy_store_create(snapshot, network.queue_count + 1U,
                                        &started->policies);
        if (result == 0) {
            snapshot = NULL;
        }
    }
    if (result == 0) {
        result = create_workers(started, config, &network, &dns_response,
                                ingress_index, egress_index);
    }
    if (result == 0) {
        result = jg_netd_client_apply(&network);
    }
    if (result == 0) {
        result = jg_netd_client_confirm();
        if (result != 0) {
            (void)jg_netd_client_rollback();
        }
    }
    if (result == 0) {
        result = start_queues(started, config, &network, ingress_index);
    }
    jg_policy_snapshot_destroy(snapshot);
    if (result != 0) {
        jg_daemon_runtime_destroy(started);
        return result;
    }
    *runtime = started;
    return 0;
}

/** @brief Request a non-blocking stop from every queue worker. */
int jg_daemon_runtime_request_stop(struct jg_daemon_runtime *runtime)
{
    return runtime == NULL ? -EINVAL
                           : jg_nfqueue_group_request_stop(runtime->queues);
}

/** @brief Wait for an external stop request or queue-worker failure. */
int jg_daemon_runtime_wait(struct jg_daemon_runtime *runtime)
{
    return runtime == NULL ? -EINVAL : jg_nfqueue_group_wait(runtime->queues);
}

/** @brief Stop and join every queue worker. */
int jg_daemon_runtime_join(struct jg_daemon_runtime *runtime)
{
    return runtime == NULL ? -EINVAL : jg_nfqueue_group_join(runtime->queues);
}

/** @brief Load and publish the next persistent policy generation. */
int jg_daemon_runtime_reload_policy(struct jg_daemon_runtime *runtime)
{
    uint64_t generation = 0U;
    int result = 0;

    if (runtime == NULL) {
        return -EINVAL;
    }
    generation =
        atomic_load_explicit(&runtime->policy_generation, memory_order_acquire);
    if (generation == UINT64_MAX) {
        return -EOVERFLOW;
    }
    ++generation;
    result = jg_policy_store_reload_from_database(
        runtime->policies, runtime->database, generation);
    if (result == 0) {
        atomic_store_explicit(&runtime->policy_generation, generation,
                              memory_order_release);
    }
    return result;
}

/** @brief Read the current published policy generation. */
int jg_daemon_runtime_get_policy_generation(
    const struct jg_daemon_runtime *runtime,
    uint64_t *generation)
{
    if (runtime == NULL || generation == NULL) {
        return -EINVAL;
    }
    *generation =
        atomic_load_explicit(&runtime->policy_generation, memory_order_acquire);
    return 0;
}

/** @brief Simulate policy through a management-only protected reader slot. */
int jg_daemon_runtime_simulate_policy(
    struct jg_daemon_runtime *runtime,
    enum jg_policy_domain_target target,
    const char *domain,
    const struct jg_policy_client *client,
    const struct jg_policy_destination *destination,
    struct jg_policy_simulation *simulation)
{
    const struct jg_policy_snapshot *snapshot = NULL;
    int result = 0;

    if (runtime == NULL) {
        return -EINVAL;
    }
    snapshot =
        jg_policy_store_acquire(runtime->policies, runtime->worker_count);
    if (snapshot == NULL) {
        return -EIO;
    }
    result = jg_policy_simulate(snapshot, target, domain, client, destination,
                                simulation);
    jg_policy_store_release(runtime->policies, runtime->worker_count);
    return result;
}

/** @brief Aggregate relaxed queue and packet-path counter snapshots. */
int jg_daemon_runtime_get_stats(const struct jg_daemon_runtime *runtime,
                                struct jg_daemon_runtime_stats *stats)
{
    struct jg_daemon_runtime_stats aggregate = {0};
    size_t index = 0U;
    int result = 0;

    if (runtime == NULL || stats == NULL) {
        return -EINVAL;
    }
    aggregate.policy_generation =
        atomic_load_explicit(&runtime->policy_generation, memory_order_acquire);
    result = jg_nfqueue_group_get_stats(runtime->queues, &aggregate.queues);
    for (index = 0U; result == 0 && index < runtime->worker_count; ++index) {
        result = aggregate_worker(runtime, index, &aggregate);
    }
    if (result == 0) {
        *stats = aggregate;
    }
    return result;
}

/** @brief Dispatch one serialized management request through runtime state. */
int jg_daemon_runtime_process_management(struct jg_daemon_runtime *runtime,
                                         const uint8_t *request,
                                         size_t request_size,
                                         uint8_t *response,
                                         size_t response_size,
                                         size_t *written)
{
    if (runtime == NULL) {
        return -EINVAL;
    }
    return jg_management_process(runtime->management, request, request_size,
                                 response, response_size, written);
}

/** @brief Run due blocklist updates through serialized management state. */
int jg_daemon_runtime_update_blocklists(struct jg_daemon_runtime *runtime,
                                        uint64_t now,
                                        size_t *attempts)
{
    if (runtime == NULL) {
        return -EINVAL;
    }
    return jg_management_update_due_blocklists(runtime->management, now,
                                               attempts);
}

/** @brief Release the packet runtime in reverse ownership order. */
void jg_daemon_runtime_destroy(struct jg_daemon_runtime *runtime)
{
    size_t index = 0U;

    if (runtime == NULL) {
        return;
    }
    jg_nfqueue_group_destroy(runtime->queues);
    for (index = 0U; index < runtime->worker_count; ++index) {
        jg_packet_output_close(runtime->outputs[index]);
        jg_dataplane_worker_destroy(runtime->workers[index]);
    }
    jg_policy_store_destroy(runtime->policies);
    jg_management_destroy(runtime->management);
    jg_database_close(runtime->database);
    free(runtime);
}
