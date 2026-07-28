/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>

#include <cmocka.h>

#include "dataplane_worker.h"
#include "janusgate/policy.h"
#include "policy_store.h"

int jg_test_dataplane_worker(void);

/** Minimal valid non-IP Ethernet frame. */
static const uint8_t arp_frame[] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U,
    0x77U, 0x88U, 0x99U, 0xaaU, 0xbbU, 0x08U, 0x06U,
};

/** @brief Build one empty immutable policy store. */
static struct jg_policy_store *build_store(void)
{
    struct jg_policy_snapshot *snapshot = NULL;
    struct jg_policy_store *store = NULL;

    assert_int_equal(jg_policy_snapshot_build(NULL, 0U, 1U, &snapshot), 0);
    assert_int_equal(jg_policy_store_create(snapshot, 1U, &store), 0);
    return store;
}

/** @brief Verify direct queue adaptation and relaxed worker counters. */
static void test_processing(void **state)
{
    const struct jg_nfqueue_packet packet = {
        .queue_number = 100U,
        .ingress_index = 2U,
        .data = arp_frame,
        .size = sizeof(arp_frame),
    };
    struct jg_policy_store *store = build_store();
    struct jg_dataplane_worker *worker = NULL;
    struct jg_dataplane_stats stats;

    (void)state;
    assert_int_equal(jg_dataplane_worker_create(store, 0U, NULL, &worker), 0);
    assert_int_equal(jg_dataplane_worker_process(&packet, worker),
                     JG_NFQUEUE_ACCEPT);
    assert_int_equal(jg_dataplane_worker_get_stats(worker, &stats), 0);
    assert_int_equal(stats.packets, 1U);
    assert_int_equal(stats.accepted, 1U);
    assert_int_equal(stats.blocked, 0U);
    assert_int_equal(stats.internal_errors, 0U);
    jg_dataplane_worker_destroy(worker);
    jg_policy_store_destroy(store);
}

/** @brief Verify invalid limits, reader slots, and packet arguments. */
static void test_arguments(void **state)
{
    struct jg_packet_limits limits = {
        .max_vlan_tags = JG_PACKET_VLAN_LIMIT + 1U,
        .max_ipv6_extensions = 1U,
        .max_ipv6_extension_bytes = 8U,
    };
    struct jg_policy_store *store = build_store();
    struct jg_dataplane_worker *worker = NULL;

    (void)state;
    assert_int_equal(jg_dataplane_worker_create(store, 1U, NULL, &worker),
                     -EINVAL);
    assert_int_equal(jg_dataplane_worker_create(store, 0U, &limits, &worker),
                     -EINVAL);
    assert_int_equal(jg_dataplane_worker_create(store, 0U, NULL, NULL),
                     -EINVAL);
    assert_int_equal(jg_dataplane_worker_process(NULL, NULL), JG_NFQUEUE_DROP);
    assert_int_equal(jg_dataplane_worker_get_stats(NULL, NULL), -EINVAL);
    jg_dataplane_worker_destroy(NULL);
    jg_policy_store_destroy(store);
}

/** @brief Run the per-queue data-plane worker test group. */
int jg_test_dataplane_worker(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_processing),
        cmocka_unit_test(test_arguments),
    };

    return cmocka_run_group_tests_name("dataplane worker", tests, NULL, NULL);
}
