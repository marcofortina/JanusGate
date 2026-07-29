/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _POSIX_C_SOURCE 200809L

#include "netd.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "nftables.h"
#include "rtnetlink.h"

/** Single serialized network transaction owned by the helper process. */
static struct {
    struct jg_netd_bridge_checkpoint checkpoint;
    struct jg_network_config current;
    struct jg_network_config pending;
    uint64_t expires_at;
    bool current_valid;
    bool pending_valid;
} transaction;

/** @brief Read monotonic seconds for rollback deadlines. */
static int monotonic_seconds(uint64_t *seconds)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -errno;
    }
    if (now.tv_sec < 0) {
        return -EIO;
    }
    *seconds = (uint64_t)now.tv_sec;
    return 0;
}

/** @brief Discard a completed pending transaction without kernel changes. */
static void clear_pending_transaction(void)
{
    (void)memset(&transaction.checkpoint, 0, sizeof(transaction.checkpoint));
    (void)memset(&transaction.pending, 0, sizeof(transaction.pending));
    transaction.expires_at = 0U;
    transaction.pending_valid = false;
}

/** @brief Apply bridge and native packet-filter state as one transaction. */
int jg_netd_apply_network(const struct jg_network_config *config)
{
    struct jg_netd_bridge_checkpoint checkpoint = {0};
    uint64_t now = 0U;
    int rollback_result = 0;
    int result = 0;

    if (transaction.pending_valid) {
        return -EBUSY;
    }
    result = monotonic_seconds(&now);
    if (result == 0 &&
        now > UINT64_MAX - (uint64_t)JG_NETD_CONFIRM_TIMEOUT_SECONDS) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        result = jg_netd_apply_bridge(config, &checkpoint);
    }
    if (result == 0) {
        result = jg_netd_apply_nft_rules(config);
    }
    if (result != 0 && checkpoint.valid) {
        rollback_result = jg_netd_restore_bridge(&checkpoint);
    }
    if (rollback_result != 0) {
        return -EIO;
    }
    if (result == 0) {
        transaction.checkpoint = checkpoint;
        transaction.pending = *config;
        transaction.expires_at =
            now + (uint64_t)JG_NETD_CONFIRM_TIMEOUT_SECONDS;
        transaction.pending_valid = true;
    }
    return result;
}

/** @brief Confirm and consume the current pending network transaction. */
int jg_netd_confirm_network(void)
{
    if (!transaction.pending_valid) {
        return -EBUSY;
    }
    transaction.current = transaction.pending;
    transaction.current_valid = true;
    clear_pending_transaction();
    return 0;
}

/** @brief Restore and consume the current pending network transaction. */
int jg_netd_rollback_network(void)
{
    int rules_result = 0;
    int bridge_result = 0;

    if (!transaction.pending_valid) {
        return -EBUSY;
    }
    rules_result = transaction.current_valid
                       ? jg_netd_apply_nft_rules(&transaction.current)
                       : jg_netd_remove_nft_rules();
    bridge_result = jg_netd_restore_bridge(&transaction.checkpoint);
    if (rules_result == 0 && bridge_result == 0) {
        clear_pending_transaction();
        return 0;
    }
    if (bridge_result == 0) {
        transaction.current_valid = false;
        clear_pending_transaction();
    }
    return -EIO;
}

/** @brief Roll back one pending transaction whose deadline has elapsed. */
int jg_netd_expire_network(void)
{
    uint64_t now = 0U;
    int result = 0;

    if (!transaction.pending_valid) {
        return 0;
    }
    result = monotonic_seconds(&now);
    if (result == 0 && now >= transaction.expires_at) {
        result = jg_netd_rollback_network();
    }
    return result;
}

/** @brief Read one self-contained transactional helper state snapshot. */
int jg_netd_get_network_state(struct jg_network_state *state)
{
    uint64_t now = 0U;
    int result = 0;

    if (state == NULL) {
        return -EINVAL;
    }
    (void)memset(state, 0, sizeof(*state));
    if (transaction.current_valid) {
        state->confirmed = transaction.current;
        state->has_confirmed = true;
    }
    if (transaction.pending_valid) {
        result = monotonic_seconds(&now);
        if (result == 0) {
            const uint64_t remaining = transaction.expires_at > now
                                           ? transaction.expires_at - now
                                           : 0U;

            state->pending_config = transaction.pending;
            state->confirmation_seconds_remaining = (uint32_t)remaining;
            state->pending = true;
        }
    }
    return result;
}
