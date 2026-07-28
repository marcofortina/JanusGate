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
#include <stddef.h>
#include <stdint.h>

#include "dataplane_worker.h"
#include "janusgate/backup.h"
#include "janusgate/certificate.h"
#include "janusgate/policy.h"
#include "nfqueue.h"
#include "packet_output.h"

/** Default persistent database used by the production daemon. */
#define JG_DAEMON_DATABASE_PATH "/var/lib/janusgate/janusgate.db"

/** Default appliance-local TOTP protection key. */
#define JG_DAEMON_TOTP_KEY_PATH "/var/lib/janusgate/totp.key"

/**
 * @brief Process-local runtime tuning outside persistent appliance policy.
 */
struct jg_daemon_runtime_config {
    /** Absolute path to the persistent JanusGate database. */
    const char *database_path;
    /** Absolute path to the appliance-local TOTP protection key. */
    const char *totp_key_path;
    /** Absolute combined server certificate PEM path. */
    const char *certificate_path;
    /** Absolute private backup archive directory. */
    const char *backup_directory;
    /** SQLite busy timeout in milliseconds. */
    uint32_t database_busy_timeout_ms;
    /** Requested netlink receive-buffer bytes for every queue. */
    uint32_t queue_receive_buffer_size;
    /** Requested raw packet send-buffer bytes for every worker. */
    uint32_t packet_send_buffer_size;
    /** Blocked UDP DNS response behavior. */
    struct jg_dns_response_config dns_response;
    /** First CPU used when worker pinning is enabled. */
    uint32_t first_cpu;
    /** Whether queue workers are pinned to consecutive CPUs. */
    bool pin_workers;
};

/** Opaque owner of one running or stopped packet runtime. */
struct jg_daemon_runtime;

/**
 * @brief Lock-efficient aggregate health counters for one packet runtime.
 */
struct jg_daemon_runtime_stats {
    /** Current immutable policy generation. */
    uint64_t policy_generation;
    /** Aggregate kernel queue transport counters. */
    struct jg_nfqueue_stats queues;
    /** Aggregate packet classification counters. */
    struct jg_dataplane_stats dataplane;
    /** Aggregate fragment reconstruction counters. */
    struct jg_fragment_stats fragments;
    /** Aggregate DNS-over-TCP stream counters. */
    struct jg_tcp_stream_stats tcp_streams;
    /** Aggregate raw frame output counters. */
    struct jg_packet_output_stats output;
};

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
 * @brief Simulate policy against the currently published snapshot.
 *
 * @param[in,out] runtime Running packet runtime.
 * @param[in] target DNS or visible-SNI domain context.
 * @param[in] domain UTF-8 domain to normalize and evaluate.
 * @param[in] client Optional client attributes used by scoped rules.
 * @param[in] destination Optional destination address, port, and transport.
 * @param[out] simulation Receives a self-contained policy explanation.
 *
 * @return 0 on success, including a default-allow result.
 * @return -EINVAL for a null or invalid argument.
 * @return A negative errno-style normalization error otherwise.
 *
 * @thread_safety Safe while packet workers evaluate policy and one control
 * writer reloads it.
 */
int jg_daemon_runtime_simulate_policy(
    struct jg_daemon_runtime *runtime,
    enum jg_policy_domain_target target,
    const char *domain,
    const struct jg_policy_client *client,
    const struct jg_policy_destination *destination,
    struct jg_policy_simulation *simulation);

/**
 * @brief Aggregate current queue and packet-path counters.
 *
 * Counter sums saturate at UINT64_MAX.
 *
 * @param[in] runtime Running packet runtime.
 * @param[out] stats Receives one relaxed aggregate snapshot.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 * @return A negative worker-counter error otherwise.
 *
 * @thread_safety Safe while packet workers run and policy reloads.
 */
int jg_daemon_runtime_get_stats(const struct jg_daemon_runtime *runtime,
                                struct jg_daemon_runtime_stats *stats);

/**
 * @brief Process one authenticated internal management request.
 *
 * @param[in,out] runtime Running packet runtime.
 * @param[in] request Exact bounded JSON request bytes.
 * @param[in] request_size Request byte count.
 * @param[out] response Destination for JSON response bytes.
 * @param[in] response_size Available response bytes.
 * @param[out] written Receives the exact response byte count.
 *
 * @return 0 when an HTTP-level response was encoded.
 * @return -EINVAL for invalid arguments.
 * @return A negative errno-style management processing error otherwise.
 *
 * @thread_safety Calls require external serialization with other management
 * writers.
 */
int jg_daemon_runtime_process_management(struct jg_daemon_runtime *runtime,
                                         const uint8_t *request,
                                         size_t request_size,
                                         uint8_t *response,
                                         size_t response_size,
                                         size_t *written);

/**
 * @brief Process every scheduled blocklist source currently due.
 *
 * @param[in,out] runtime Running packet runtime.
 * @param[in] now Current Unix time in seconds.
 * @param[out] attempts Receives the number of HTTPS attempts; null discards it.
 *
 * @return 0 when all due sources were processed.
 * @return -EINVAL for an invalid runtime or timestamp.
 * @return A negative errno-style update, audit, or policy-publication error
 * otherwise.
 *
 * @thread_safety Calls require the same external serialization as management
 * requests and policy reloads.
 */
int jg_daemon_runtime_update_blocklists(struct jg_daemon_runtime *runtime,
                                        uint64_t now,
                                        size_t *attempts);

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
