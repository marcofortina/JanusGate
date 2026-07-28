/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <errno.h>

#include <cmocka.h>

#include "janusgate/network.h"
#include "nfqueue.h"

int jg_test_nfqueue(void);

/** @brief Build one valid single-worker queue configuration. */
static struct jg_nfqueue_worker_config test_config(void)
{
    const struct jg_nfqueue_worker_config config = {
        .queue_number = 100U,
        .ingress_index = 2U,
        .queue_length = 4096U,
        .receive_buffer_size = JG_NFQUEUE_RECEIVE_BUFFER_DEFAULT,
        .fail_open = true,
    };

    return config;
}

/** @brief Verify accepted queue and socket resource bounds. */
static void test_configuration(void **state)
{
    struct jg_nfqueue_worker_config config = test_config();

    (void)state;
    assert_int_equal(jg_nfqueue_worker_config_validate(&config), 0);
    assert_int_equal(jg_nfqueue_worker_config_validate(NULL), -EINVAL);

    config.ingress_index = 0U;
    assert_int_equal(jg_nfqueue_worker_config_validate(&config), -EINVAL);
    config = test_config();
    config.queue_length = 0U;
    assert_int_equal(jg_nfqueue_worker_config_validate(&config), -ERANGE);
    config.queue_length = JG_NETWORK_QUEUE_LENGTH_MAX + 1U;
    assert_int_equal(jg_nfqueue_worker_config_validate(&config), -ERANGE);
    config = test_config();
    config.receive_buffer_size = JG_NFQUEUE_RECEIVE_BUFFER_MAX + 1U;
    assert_int_equal(jg_nfqueue_worker_config_validate(&config), -ERANGE);
}

/** @brief Verify argument rejection without opening a privileged queue. */
static void test_open_arguments(void **state)
{
    const struct jg_nfqueue_worker_config config = test_config();
    struct jg_nfqueue_worker *worker = NULL;

    (void)state;
    assert_int_equal(jg_nfqueue_worker_open(&config, NULL, NULL, &worker),
                     -EINVAL);
    assert_null(worker);
    assert_int_equal(jg_nfqueue_worker_open(&config, NULL, NULL, NULL),
                     -EINVAL);
    assert_int_equal(jg_nfqueue_worker_get_stats(NULL, NULL), -EINVAL);
    jg_nfqueue_worker_close(NULL);
}

/** @brief Run the single-queue transport test group. */
int jg_test_nfqueue(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_configuration),
        cmocka_unit_test(test_open_arguments),
    };

    return cmocka_run_group_tests_name("nfqueue", tests, NULL, NULL);
}
