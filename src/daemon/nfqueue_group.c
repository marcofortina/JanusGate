/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nfqueue_group.h"

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <pthread.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "janusgate/network.h"

/** Per-thread state retained by an NFQUEUE worker group. */
struct group_worker {
    struct jg_nfqueue_group *group;
    struct jg_nfqueue_worker *queue;
    pthread_t thread;
    atomic_int result;
    bool started;
    bool pin_worker;
    uint32_t cpu;
};

/** Complete owner of a fixed contiguous set of queue workers. */
struct jg_nfqueue_group {
    struct jg_nfqueue_group_config config;
    struct group_worker workers[JG_NETWORK_QUEUE_COUNT_MAX];
    bool joined;
    int stop_fd;
};

/** @brief Add one counter with saturation at the largest representation. */
static void saturating_add(uint64_t value, uint64_t *total)
{
    *total = value > UINT64_MAX - *total ? UINT64_MAX : *total + value;
}

/** @brief Notify every worker through the shared level-triggered event. */
static int notify_stop(struct jg_nfqueue_group *group)
{
    const uint64_t notification = 1U;
    const ssize_t written =
        write(group->stop_fd, &notification, sizeof(notification));

    if (written == (ssize_t)sizeof(notification) ||
        (written < 0 && errno == EAGAIN)) {
        return 0;
    }
    return written < 0 ? -errno : -EIO;
}

/** @brief Run one configured queue and propagate fatal worker errors. */
static void *run_worker(void *context)
{
    struct group_worker *worker = context;
    int result = 0;

    if (worker->pin_worker) {
        cpu_set_t affinity;

        CPU_ZERO_S(sizeof(affinity), &affinity);
        CPU_SET_S((size_t)worker->cpu, sizeof(affinity), &affinity);
        result =
            pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    }
    if (result == 0) {
        result = jg_nfqueue_worker_run(worker->queue, worker->group->stop_fd);
    } else {
        result = -result;
    }

    atomic_store_explicit(&worker->result, result, memory_order_release);
    if (result != 0) {
        (void)notify_stop(worker->group);
    }
    return NULL;
}

/** @brief Close every queue and release the group allocation. */
static void release_group(struct jg_nfqueue_group *group)
{
    size_t index = 0U;

    if (group == NULL) {
        return;
    }
    for (index = 0U; index < group->config.queue_count; ++index) {
        jg_nfqueue_worker_close(group->workers[index].queue);
    }
    if (group->stop_fd >= 0) {
        (void)close(group->stop_fd);
    }
    free(group);
}

/** @brief Join each thread which successfully started. */
static int join_workers(struct jg_nfqueue_group *group)
{
    int result = 0;
    size_t index = 0U;

    for (index = 0U; index < group->config.queue_count; ++index) {
        if (group->workers[index].started) {
            const int join_result =
                pthread_join(group->workers[index].thread, NULL);
            const int worker_result = atomic_load_explicit(
                &group->workers[index].result, memory_order_acquire);

            group->workers[index].started = false;
            if (result == 0 && join_result != 0) {
                result = -join_result;
            }
            if (result == 0 && worker_result != 0) {
                result = worker_result;
            }
        }
    }
    group->joined = true;
    return result;
}

/** @brief Configure affinity and start one group thread. */
static int start_worker(struct group_worker *worker,
                        bool pin_worker,
                        uint32_t cpu)
{
    int result = 0;

    worker->pin_worker = pin_worker;
    worker->cpu = cpu;
    result = pthread_create(&worker->thread, NULL, run_worker, worker);
    if (result == 0) {
        worker->started = true;
    }
    return result == 0 ? 0 : -result;
}

/** @brief Validate one bounded worker-group configuration. */
int jg_nfqueue_group_config_validate(
    const struct jg_nfqueue_group_config *config)
{
    struct jg_nfqueue_worker_config worker_config;
    uint32_t queue_end = 0U;
    uint32_t cpu_end = 0U;
    int result = 0;

    if (config == NULL || config->queue_count == 0U) {
        return -EINVAL;
    }
    if (config->queue_count > JG_NETWORK_QUEUE_COUNT_MAX) {
        return -ERANGE;
    }
    queue_end = (uint32_t)config->queue_first + (uint32_t)config->queue_count;
    cpu_end = config->first_cpu + (uint32_t)config->queue_count;
    if (queue_end > 65536U ||
        (config->pin_workers &&
         (cpu_end < config->first_cpu || cpu_end > (uint32_t)CPU_SETSIZE))) {
        return -ERANGE;
    }

    worker_config.queue_number = config->queue_first;
    worker_config.ingress_index = config->ingress_index;
    worker_config.queue_length = config->queue_length;
    worker_config.receive_buffer_size = config->receive_buffer_size;
    worker_config.fail_open = config->fail_open;
    result = jg_nfqueue_worker_config_validate(&worker_config);
    return result;
}

/** @brief Open a contiguous queue range and start one thread per queue. */
int jg_nfqueue_group_start(const struct jg_nfqueue_group_config *config,
                           jg_nfqueue_processor processor,
                           void *const *contexts,
                           struct jg_nfqueue_group **group)
{
    struct jg_nfqueue_group *started = NULL;
    size_t index = 0U;
    int result = 0;

    if (group == NULL) {
        return -EINVAL;
    }
    *group = NULL;
    if (processor == NULL) {
        return -EINVAL;
    }
    result = jg_nfqueue_group_config_validate(config);
    if (result != 0) {
        return result;
    }
    started = calloc(1U, sizeof(*started));
    if (started == NULL) {
        return -ENOMEM;
    }
    started->config = *config;
    started->stop_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
    if (started->stop_fd < 0) {
        result = -errno;
    }
    for (index = 0U; result == 0 && index < config->queue_count; ++index) {
        struct jg_nfqueue_worker_config worker_config = {
            .queue_number =
                (uint16_t)((uint32_t)config->queue_first + (uint32_t)index),
            .ingress_index = config->ingress_index,
            .queue_length = config->queue_length,
            .receive_buffer_size = config->receive_buffer_size,
            .fail_open = config->fail_open,
        };

        started->workers[index].group = started;
        atomic_init(&started->workers[index].result, 0);
        result =
            jg_nfqueue_worker_open(&worker_config, processor,
                                   contexts == NULL ? NULL : contexts[index],
                                   &started->workers[index].queue);
    }
    for (index = 0U; result == 0 && index < config->queue_count; ++index) {
        result = start_worker(&started->workers[index], config->pin_workers,
                              config->first_cpu + (uint32_t)index);
    }
    if (result != 0) {
        (void)notify_stop(started);
        (void)join_workers(started);
        release_group(started);
        return result;
    }
    *group = started;
    return 0;
}

/** @brief Request a shared orderly worker stop. */
int jg_nfqueue_group_request_stop(struct jg_nfqueue_group *group)
{
    return group == NULL ? -EINVAL : notify_stop(group);
}

/** @brief Join workers without initiating a new stop request. */
int jg_nfqueue_group_wait(struct jg_nfqueue_group *group)
{
    if (group == NULL) {
        return -EINVAL;
    }
    return group->joined ? 0 : join_workers(group);
}

/** @brief Join every worker after requesting an orderly stop. */
int jg_nfqueue_group_join(struct jg_nfqueue_group *group)
{
    int result = 0;

    if (group == NULL) {
        return -EINVAL;
    }
    if (group->joined) {
        return 0;
    }
    result = notify_stop(group);
    if (result == 0) {
        result = join_workers(group);
    }
    return result;
}

/** @brief Aggregate relaxed per-worker counters with saturation. */
int jg_nfqueue_group_get_stats(const struct jg_nfqueue_group *group,
                               struct jg_nfqueue_stats *stats)
{
    size_t index = 0U;

    if (group == NULL || stats == NULL) {
        return -EINVAL;
    }
    *stats = (struct jg_nfqueue_stats){0};
    for (index = 0U; index < group->config.queue_count; ++index) {
        struct jg_nfqueue_stats worker_stats;
        int result = jg_nfqueue_worker_get_stats(group->workers[index].queue,
                                                 &worker_stats);

        if (result != 0) {
            return result;
        }
        saturating_add(worker_stats.packets, &stats->packets);
        saturating_add(worker_stats.accepted, &stats->accepted);
        saturating_add(worker_stats.dropped, &stats->dropped);
        saturating_add(worker_stats.malformed, &stats->malformed);
        saturating_add(worker_stats.overflows, &stats->overflows);
        saturating_add(worker_stats.message_errors, &stats->message_errors);
        saturating_add(worker_stats.verdict_errors, &stats->verdict_errors);
    }
    return 0;
}

/** @brief Stop and release one complete queue-worker group. */
void jg_nfqueue_group_destroy(struct jg_nfqueue_group *group)
{
    if (group == NULL) {
        return;
    }
    if (!group->joined) {
        (void)notify_stop(group);
        (void)join_workers(group);
    }
    release_group(group);
}
