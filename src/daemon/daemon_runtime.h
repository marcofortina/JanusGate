/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file daemon_runtime.h
 * @brief Ownership and lifecycle of the JanusGate packet runtime.
 */

#ifndef JANUSGATE_DAEMON_RUNTIME_H
#define JANUSGATE_DAEMON_RUNTIME_H

#include <stdbool.h>
#include <stdint.h>

/** Default persistent database used by the production daemon. */
#define JG_DAEMON_DATABASE_PATH "/var/lib/janusgate/janusgate.db"

/**
 * @brief Process-local runtime tuning outside persistent appliance policy.
 */
struct jg_daemon_runtime_config {
    /** Absolute path to the persistent JanusGate database. */
    const char *database_path;
    /** SQLite busy timeout in milliseconds. */
    uint32_t database_busy_timeout_ms;
    /** Requested netlink receive-buffer bytes for every queue. */
    uint32_t queue_receive_buffer_size;
    /** Requested raw packet send-buffer bytes for every worker. */
    uint32_t packet_send_buffer_size;
    /** First CPU used when worker pinning is enabled. */
    uint32_t first_cpu;
    /** Whether queue workers are pinned to consecutive CPUs. */
    bool pin_workers;
};

/** Opaque owner of one running or stopped packet runtime. */
struct jg_daemon_runtime;

/**
 * @brief Initialize conservative production runtime defaults.
 *
 * @param[out] config Configuration to initialize; null is ignored.
 *
 * @thread_safety This function is reentrant.
 */
void jg_daemon_runtime_config_default(struct jg_daemon_runtime_config *config);

/**
 * @brief Validate process-local runtime tuning.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for a null or non-absolute database path or zero bounds.
 * @return -ERANGE when a socket buffer exceeds its supported maximum.
 *
 * @thread_safety This function is reentrant.
 */
int jg_daemon_runtime_config_validate(
    const struct jg_daemon_runtime_config *config);

/**
 * @brief Load persistent state and start the complete packet runtime.
 *
 * Network state is applied through the privileged helper only after all
 * userspace workers and raw outputs are ready. The NFQUEUE group starts last.
 *
 * @param[in] config Validated process-local runtime configuration.
 * @param[out] runtime Receives the owned running runtime.
 *
 * @return 0 on success.
 * @return A negative errno-style configuration, database, interface, helper,
 * allocation, raw-socket, or NFQUEUE error otherwise.
 *
 * @thread_safety Only one process may own the configured queue range.
 *
 * @side_effects Opens persistent storage and privileged packet sockets,
 * applies owned kernel network state, and starts queue threads.
 */
int jg_daemon_runtime_start(const struct jg_daemon_runtime_config *config,
                            struct jg_daemon_runtime **runtime);

/**
 * @brief Request an orderly non-blocking packet-runtime stop.
 *
 * @param[in,out] runtime Running runtime.
 *
 * @return 0 when the stop request is present.
 * @return -EINVAL for a null runtime.
 * @return A negative errno-style notification error otherwise.
 *
 * @thread_safety Safe to call concurrently and repeatedly.
 */
int jg_daemon_runtime_request_stop(struct jg_daemon_runtime *runtime);

/**
 * @brief Wait until a signal or worker failure stops the packet runtime.
 *
 * This function does not initiate shutdown.
 *
 * @param[in,out] runtime Running or stopped runtime.
 *
 * @return 0 after an orderly external stop.
 * @return -EINVAL for a null runtime.
 * @return The first negative worker or join error otherwise.
 *
 * @thread_safety Exactly one control thread may wait for the runtime.
 */
int jg_daemon_runtime_wait(struct jg_daemon_runtime *runtime);

/**
 * @brief Request an orderly stop and join every queue worker.
 *
 * @param[in,out] runtime Running or stopped runtime.
 *
 * @return 0 after an orderly stop.
 * @return -EINVAL for a null runtime.
 * @return The first negative worker or join error otherwise.
 *
 * @thread_safety Exactly one control thread may join the runtime.
 */
int jg_daemon_runtime_join(struct jg_daemon_runtime *runtime);

/**
 * @brief Reload persistent domain policy into a new immutable generation.
 *
 * A failed database read or snapshot build leaves the active policy and
 * generation unchanged.
 *
 * @param[in,out] runtime Running packet runtime.
 *
 * @return 0 on success.
 * @return -EINVAL for a null runtime.
 * @return -EOVERFLOW when the generation counter is exhausted.
 * @return A negative errno-style database, allocation, validation, or
 * replacement error otherwise.
 *
 * @thread_safety Calls require one externally serialized control writer.
 */
int jg_daemon_runtime_reload_policy(struct jg_daemon_runtime *runtime);

/**
 * @brief Read the current immutable policy generation.
 *
 * @param[in] runtime Packet runtime.
 * @param[out] generation Receives the current nonzero generation.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while one control writer reloads policy.
 */
int jg_daemon_runtime_get_policy_generation(
    const struct jg_daemon_runtime *runtime,
    uint64_t *generation);

/**
 * @brief Stop and release the complete packet runtime.
 *
 * @param[in,out] runtime Runtime to release; null is accepted.
 *
 * @thread_safety No other control operation may use the runtime concurrently.
 *
 * @side_effects Stops queue threads and closes packet and database resources.
 */
void jg_daemon_runtime_destroy(struct jg_daemon_runtime *runtime);

#endif
