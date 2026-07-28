/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "daemon_runtime.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <net/if.h>

#include "dataplane_worker.h"
#include "janusgate/database.h"
#include "janusgate/network.h"
#include "netd_client.h"
#include "nfqueue.h"
#include "nfqueue_group.h"
#include "packet_output.h"
#include "policy_store.h"

/** Complete ownership tree for one packet runtime. */
struct jg_daemon_runtime {
    struct jg_database *database;
    struct jg_policy_store *policies;
    struct jg_dataplane_worker *workers[JG_NETWORK_QUEUE_COUNT_MAX];
    struct jg_packet_output *outputs[JG_NETWORK_QUEUE_COUNT_MAX];
    struct jg_nfqueue_group *queues;
    size_t worker_count;
};

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
        .database_busy_timeout_ms = 5000U,
        .queue_receive_buffer_size = JG_NFQUEUE_RECEIVE_BUFFER_DEFAULT,
        .packet_send_buffer_size = JG_PACKET_OUTPUT_BUFFER_DEFAULT,
    };
}

/** @brief Validate process-local database and socket bounds. */
int jg_daemon_runtime_config_validate(
    const struct jg_daemon_runtime_config *config)
{
    if (config == NULL || config->database_path == NULL ||
        config->database_path[0] != '/' || config->database_path[1] == '\0' ||
        config->database_busy_timeout_ms == 0U ||
        config->queue_receive_buffer_size == 0U ||
        config->packet_send_buffer_size == 0U) {
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
    uint32_t ingress_index = 0U;
    uint32_t egress_index = 0U;
    int result = 0;

    if (runtime == NULL) {
        return -EINVAL;
    }
    *runtime = NULL;
    result = jg_daemon_runtime_config_validate(config);
    if (result == 0) {
        started = calloc(1U, sizeof(*started));
        if (started == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        result = jg_database_open(config->database_path,
                                  config->database_busy_timeout_ms,
                                  &started->database);
    }
    if (result == 0) {
        result = jg_database_load_network_config(started->database, &network);
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
        result = jg_policy_store_create(snapshot, network.queue_count,
                                        &started->policies);
        if (result == 0) {
            snapshot = NULL;
        }
    }
    if (result == 0) {
        result = create_workers(started, config, &network, ingress_index,
                                egress_index);
    }
    if (result == 0) {
        result = jg_netd_client_apply(&network);
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
    jg_database_close(runtime->database);
    free(runtime);
}
