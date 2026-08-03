/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "metrics.h"

int jg_test_metrics(void);

/** @brief Verify stable metric names, types, values, and final newline. */
static void test_render_snapshot(void **state)
{
    struct jg_daemon_runtime_stats stats = {0};
    struct jg_management_metrics management = {0};
    char output[16384U];
    size_t written = 0U;

    (void)state;
    stats.policy_generation = 17U;
    stats.queues.packets = 101U;
    stats.dataplane.accepted = 89U;
    stats.dataplane.blocked = 12U;
    stats.dataplane.sni_inspected = 8U;
    stats.dataplane.sni_encrypted_or_unavailable = 2U;
    stats.dataplane.dns_refused = 9U;
    stats.tcp_streams.messages = 7U;
    stats.output.errors = 3U;
    stats.policy_stats.submitted = 34U;
    stats.policy_stats.dropped = 5U;
    management.authentication_failures_total = 6U;
    management.alert_open_by_type[JG_ALERT_TYPE_QUEUE_DROPS - 1U] = 2U;
    management.alert_deliveries_pending = 3U;
    management.filesystem_minimum_available_basis_points = 987U;
    management.policy_synchronized = 1U;
    assert_int_equal(jg_metrics_render(&stats, &management, output,
                                       sizeof(output), &written),
                     0);
    assert_int_equal(written, strlen(output));
    assert_true(written > 0U);
    assert_int_equal(output[written - 1U], '\n');
    assert_non_null(strstr(output, "# TYPE janusgate_policy_generation gauge"));
    assert_non_null(strstr(output, "janusgate_policy_generation 17\n"));
    assert_non_null(strstr(output, "janusgate_nfqueue_packets_total 101\n"));
    assert_non_null(strstr(output, "janusgate_dataplane_allowed_total 89\n"));
    assert_non_null(strstr(output, "janusgate_dataplane_blocked_total 12\n"));
    assert_non_null(strstr(output, "janusgate_tls_sni_inspected_total 8\n"));
    assert_non_null(
        strstr(output, "janusgate_tls_sni_encrypted_or_unavailable_total 2\n"));
    assert_non_null(strstr(output, "janusgate_dns_block_refused_total 9\n"));
    assert_non_null(strstr(output, "janusgate_tcp_stream_messages_total 7\n"));
    assert_non_null(strstr(output, "janusgate_packet_output_errors_total 3\n"));
    assert_non_null(
        strstr(output, "janusgate_policy_stats_submitted_total 34\n"));
    assert_non_null(strstr(output, "janusgate_policy_stats_dropped_total 5\n"));
    assert_non_null(
        strstr(output, "janusgate_authentication_failures_total 6\n"));
    assert_non_null(
        strstr(output, "janusgate_alerts_open{type=\"queue_drops\"} 2\n"));
    assert_non_null(strstr(output, "janusgate_alert_deliveries_pending 3\n"));
    assert_non_null(strstr(
        output, "janusgate_filesystem_minimum_available_ratio 0.0987\n"));
    assert_non_null(strstr(output, "janusgate_policy_synchronized 1\n"));
}

/** @brief Verify exact sizing and the no-partial-output contract. */
static void test_bounded_rendering(void **state)
{
    struct jg_daemon_runtime_stats stats = {0};
    struct jg_management_metrics management = {0};
    char probe[1U] = {'x'};
    char *output = NULL;
    size_t required = 0U;
    size_t written = 0U;

    (void)state;
    assert_int_equal(
        jg_metrics_render(&stats, &management, probe, sizeof(probe), &required),
        -ENOSPC);
    assert_true(required > 0U);
    assert_int_equal(probe[0], '\0');

    output = malloc(required + 1U);
    assert_non_null(output);
    assert_int_equal(
        jg_metrics_render(&stats, &management, output, required + 1U, &written),
        0);
    assert_int_equal(written, required);
    free(output);

    assert_int_equal(
        jg_metrics_render(NULL, &management, probe, sizeof(probe), &written),
        -EINVAL);
    assert_int_equal(
        jg_metrics_render(&stats, NULL, probe, sizeof(probe), &written),
        -EINVAL);
    assert_int_equal(jg_metrics_render(&stats, &management, NULL, 0U, &written),
                     -EINVAL);
}

/** @brief Run the Prometheus metric serialization test group. */
int jg_test_metrics(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_render_snapshot),
        cmocka_unit_test(test_bounded_rendering),
    };

    return cmocka_run_group_tests_name("metrics", tests, NULL, NULL);
}
