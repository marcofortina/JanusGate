/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file tcp_reset.h
 * @brief Standards-correct TCP reset frame construction.
 */

#ifndef JANUSGATE_DAEMON_TCP_RESET_H
#define JANUSGATE_DAEMON_TCP_RESET_H

#include <stddef.h>
#include <stdint.h>

#include "janusgate/packet.h"

/** Largest reset frame for supported VLAN, IPv4, and IPv6 headers. */
#define JG_TCP_RESET_FRAME_MAX 128U

/**
 * @brief Reset frames directed to both endpoints of one blocked TCP flow.
 */
struct jg_tcp_reset_pair {
    /** Reset spoofing the server and directed back to the client. */
    uint8_t to_client[JG_TCP_RESET_FRAME_MAX];
    /** Bytes populated in @ref to_client. */
    size_t to_client_size;
    /** Reset spoofing the client and directed toward the server. */
    uint8_t to_server[JG_TCP_RESET_FRAME_MAX];
    /** Bytes populated in @ref to_server. */
    size_t to_server_size;
};

/**
 * @brief Build reset frames for both endpoints of one blocked TCP packet.
 *
 * The client-facing reset follows RFC reset generation rules. The
 * server-facing reset uses the first sequence number of the dropped segment,
 * which remains the server's next acceptable byte. Both frames preserve the
 * complete Ethernet and VLAN envelope.
 *
 * @param[in] packet Parsed, complete, non-fragmented TCP packet.
 * @param[out] resets Receives both reset frames.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid packet metadata or arguments.
 * @return -ENOSPC when the preserved link envelope exceeds the fixed bound.
 *
 * @thread_safety This function is reentrant.
 */
int jg_tcp_reset_build(const struct jg_packet_view *packet,
                       struct jg_tcp_reset_pair *resets);

#endif
