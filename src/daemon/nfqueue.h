/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file nfqueue.h
 * @brief Bounded single-queue packet transport for data-plane workers.
 */

#ifndef JANUSGATE_DAEMON_NFQUEUE_H
#define JANUSGATE_DAEMON_NFQUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Default kernel socket receive-buffer request. */
#define JG_NFQUEUE_RECEIVE_BUFFER_DEFAULT 4194304U

/** Largest accepted kernel socket receive-buffer request. */
#define JG_NFQUEUE_RECEIVE_BUFFER_MAX 67108864U

/**
 * @brief Final kernel action selected for one queued packet.
 */
enum jg_nfqueue_verdict {
    /** Continue normal kernel processing. */
    JG_NFQUEUE_ACCEPT = 1,
    /** Discard the packet. */
    JG_NFQUEUE_DROP = 2
};

/**
 * @brief Immutable metadata passed to one packet processor.
 */
struct jg_nfqueue_packet {
    /** Queue number which received the packet. */
    uint16_t queue_number;
    /** Logical input-interface index reported by the kernel. */
    uint32_t ingress_index;
    /** Physical bridge input-interface index, or zero when unavailable. */
    uint32_t physical_ingress_index;
    /** Kernel checksum and segmentation metadata. */
    uint32_t socket_buffer_info;
    /** Immutable complete captured packet bytes. */
    const uint8_t *data;
    /** Number of captured packet bytes. */
    size_t size;
};

/**
 * @brief Configuration of one independent NFQUEUE worker.
 */
struct jg_nfqueue_worker_config {
    /** Queue number owned exclusively by this worker. */
    uint16_t queue_number;
    /** Expected physical data-ingress interface index. */
    uint32_t ingress_index;
    /** Maximum packets retained by the kernel queue. */
    uint32_t queue_length;
    /** Requested netlink socket receive-buffer bytes. */
    uint32_t receive_buffer_size;
    /** Whether queue overflow or absence permits traffic. */
    bool fail_open;
};

/**
 * @brief Lock-free counters maintained by one queue worker.
 */
struct jg_nfqueue_stats {
    /** Packets delivered by the kernel with complete metadata. */
    uint64_t packets;
    /** Packets accepted by the processor. */
    uint64_t accepted;
    /** Packets dropped by the processor or input validation. */
    uint64_t dropped;
    /** Packets rejected for missing, truncated, or unexpected metadata. */
    uint64_t malformed;
    /** Netlink receive overflows reported by the kernel. */
    uint64_t overflows;
    /** Netlink messages rejected by libnetfilter_queue. */
    uint64_t message_errors;
    /** Verdicts which could not be delivered to the kernel. */
    uint64_t verdict_errors;
};

/** Opaque single-queue worker. */
struct jg_nfqueue_worker;

/**
 * @brief Select a verdict for one immutable queued packet.
 *
 * @param[in] packet Kernel packet and metadata.
 * @param[in,out] context Caller-owned processor state.
 *
 * @return JG_NFQUEUE_ACCEPT or JG_NFQUEUE_DROP.
 *
 * @thread_safety A processor is called by one worker at a time. Distinct
 * workers may call the same function concurrently with distinct contexts.
 */
typedef enum jg_nfqueue_verdict (*jg_nfqueue_processor)(
    const struct jg_nfqueue_packet *packet,
    void *context);

/**
 * @brief Validate one queue-worker configuration.
 *
 * @param[in] config Configuration to validate.
 *
 * @return 0 on success.
 * @return -EINVAL for a null configuration, zero interface index, or zero
 * receive buffer.
 * @return -ERANGE for an unsafe queue length or receive-buffer size.
 *
 * @thread_safety This function is reentrant.
 */
int jg_nfqueue_worker_config_validate(
    const struct jg_nfqueue_worker_config *config);

/**
 * @brief Open and configure one exclusive kernel queue.
 *
 * @param[in] config Validated worker configuration.
 * @param[in] processor Packet decision function.
 * @param[in,out] context Opaque state passed to @p processor.
 * @param[out] worker Receives the owned worker.
 *
 * @return 0 on success.
 * @return A negative errno-style validation, allocation, socket, or queue
 * configuration error otherwise.
 *
 * @thread_safety Different queue numbers may be opened independently.
 *
 * @side_effects Binds the queue and tunes its netlink receive socket.
 */
int jg_nfqueue_worker_open(const struct jg_nfqueue_worker_config *config,
                           jg_nfqueue_processor processor,
                           void *context,
                           struct jg_nfqueue_worker **worker);

/**
 * @brief Service packets until the supplied descriptor becomes readable.
 *
 * Every valid packet callback attempts exactly one definitive verdict.
 * Shutdown drains already delivered netlink messages within the configured
 * queue bound before returning.
 *
 * @param[in,out] worker Open queue worker.
 * @param[in] stop_fd Descriptor made readable to request shutdown.
 *
 * @return 0 after an orderly stop.
 * @return A negative errno-style poll, receive, or queue error otherwise.
 *
 * @thread_safety Exactly one thread may run a worker.
 *
 * @side_effects Receives queued packets and sends kernel verdicts.
 */
int jg_nfqueue_worker_run(struct jg_nfqueue_worker *worker, int stop_fd);

/**
 * @brief Read a coherent relaxed snapshot of worker counters.
 *
 * @param[in] worker Queue worker.
 * @param[out] stats Receives current counters.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe while the worker is running.
 */
int jg_nfqueue_worker_get_stats(const struct jg_nfqueue_worker *worker,
                                struct jg_nfqueue_stats *stats);

/**
 * @brief Close and release one stopped queue worker.
 *
 * @param[in,out] worker Worker to release; null is accepted.
 *
 * @thread_safety The worker must not be running.
 *
 * @side_effects Unbinds the queue and closes its netlink socket.
 */
void jg_nfqueue_worker_close(struct jg_nfqueue_worker *worker);

#endif
