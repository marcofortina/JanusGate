/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "netd.h"

#include <errno.h>

#include "nftables.h"
#include "rtnetlink.h"

/** @brief Apply bridge and nftables state as one rollback-safe transaction. */
int jg_netd_apply_network(const struct jg_network_config *config)
{
    struct jg_netd_bridge_checkpoint checkpoint;
    int rollback_result = 0;
    int result = jg_netd_apply_bridge(config, &checkpoint);

    if (result == 0) {
        result = jg_netd_apply_nft_rules(config);
    }
    if (result != 0 && checkpoint.valid) {
        rollback_result = jg_netd_restore_bridge(&checkpoint);
    }
    return rollback_result == 0 ? result : -EUCLEAN;
}
