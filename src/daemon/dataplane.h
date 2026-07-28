/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file dataplane.h
 * @brief Stateless packet classification against immutable domain policy.
 */

#ifndef JANUSGATE_DAEMON_DATAPLANE_H
#define JANUSGATE_DAEMON_DATAPLANE_H

#include <stddef.h>

#include "janusgate/dns.h"
#include "janusgate/packet.h"
#include "janusgate/policy.h"
#include "nfqueue.h"

/**
 * @brief Explanation class for one stateless packet decision.
 */
enum jg_dataplane_reason {
    /** Packet is valid but does not require stateless domain policy. */
    JG_DATAPLANE_PASS = 1,
    /** Every DNS question is permitted by current policy. */
    JG_DATAPLANE_POLICY_ALLOW = 2,
    /** At least one DNS question is blocked by current policy. */
    JG_DATAPLANE_POLICY_BLOCK = 3,
    /** Packet or selected DNS message is malformed or exceeds limits. */
    JG_DATAPLANE_MALFORMED = 4,
    /** Fragment handling must complete before a domain verdict is possible. */
    JG_DATAPLANE_FRAGMENT_PENDING = 5,
    /** TCP stream handling must complete before a domain verdict is possible.
     */
    JG_DATAPLANE_STREAM_PENDING = 6
};

/**
 * @brief Complete result of one stateless packet evaluation.
 */
struct jg_dataplane_result {
    /** Final immediate kernel verdict. */
    enum jg_nfqueue_verdict verdict;
    /** Stable explanation class. */
    enum jg_dataplane_reason reason;
    /** Packet parser result. */
    enum jg_packet_result packet_result;
    /** DNS parser result when UDP DNS was selected. */
    enum jg_dns_result dns_result;
    /** Index of the question producing @ref policy, or SIZE_MAX. */
    size_t question_index;
    /** Domain-policy explanation, borrowing immutable snapshot storage. */
    struct jg_policy_match policy;
};

/**
 * @brief Evaluate one complete Ethernet frame against immutable domain policy.
 *
 * Valid non-IP and non-DNS traffic is accepted. Complete UDP DNS queries are
 * blocked when any question has a blocking match. Malformed selected traffic
 * is dropped. Fragments and TCP policy traffic are accepted provisionally and
 * explicitly marked for the stateful layers which consume this result.
 *
 * @param[in] frame Complete immutable Ethernet frame.
 * @param[in] frame_size Number of frame bytes.
 * @param[in] limits Packet parser resource limits, or null for defaults.
 * @param[in] snapshot Immutable policy snapshot.
 * @param[out] result Receives the packet verdict and explanation.
 *
 * @return 0 when an explicit verdict was produced.
 * @return -EINVAL for null frame, snapshot, or result arguments.
 *
 * @thread_safety Safe for concurrent calls using the same immutable snapshot.
 */
int jg_dataplane_evaluate(const uint8_t *frame,
                          size_t frame_size,
                          const struct jg_packet_limits *limits,
                          const struct jg_policy_snapshot *snapshot,
                          struct jg_dataplane_result *result);

#endif
