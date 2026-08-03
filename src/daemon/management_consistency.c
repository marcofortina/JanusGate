/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file management_consistency.c
 * @brief Shared exclusion between ordinary mutations and applied restores.
 */

#define _POSIX_C_SOURCE 200809L

#include "management_internal.h"

#include <errno.h>
#include <stdlib.h>

/** Shared state protecting one appliance-wide restore boundary. */
struct management_consistency {
    pthread_mutex_t mutex;
    pthread_cond_t available;
    size_t active_mutations;
    bool restore_active;
};

/** @brief Create one management mutation and restore consistency gate. */
int management_consistency_create(struct management_consistency **consistency)
{
    struct management_consistency *created = NULL;
    int status = 0;

    if (consistency == NULL) {
        return -EINVAL;
    }
    *consistency = NULL;
    created = calloc(1U, sizeof(*created));
    if (created == NULL) {
        return -ENOMEM;
    }
    status = pthread_mutex_init(&created->mutex, NULL);
    if (status != 0) {
        free(created);
        return -status;
    }
    status = pthread_cond_init(&created->available, NULL);
    if (status != 0) {
        (void)pthread_mutex_destroy(&created->mutex);
        free(created);
        return -status;
    }
    *consistency = created;
    return 0;
}

/** @brief Release one unused management consistency gate. */
void management_consistency_destroy(struct management_consistency *consistency)
{
    if (consistency == NULL) {
        return;
    }
    (void)pthread_cond_destroy(&consistency->available);
    (void)pthread_mutex_destroy(&consistency->mutex);
    free(consistency);
}

/** @brief Enter one ordinary state-changing management operation. */
int management_mutation_begin(struct jg_management *management)
{
    struct management_consistency *consistency = NULL;
    int status = 0;

    if (management == NULL || management->consistency == NULL) {
        return -EINVAL;
    }
    consistency = management->consistency;
    status = pthread_mutex_lock(&consistency->mutex);
    if (status != 0) {
        return -status;
    }
    if (consistency->restore_active) {
        status = EBUSY;
    } else {
        ++consistency->active_mutations;
    }
    (void)pthread_mutex_unlock(&consistency->mutex);
    return -status;
}

/** @brief Leave one ordinary state-changing management operation. */
void management_mutation_end(struct jg_management *management)
{
    struct management_consistency *consistency = NULL;

    if (management == NULL || management->consistency == NULL) {
        return;
    }
    consistency = management->consistency;
    if (pthread_mutex_lock(&consistency->mutex) != 0) {
        return;
    }
    if (consistency->active_mutations > 0U) {
        --consistency->active_mutations;
        if (consistency->active_mutations == 0U) {
            (void)pthread_cond_broadcast(&consistency->available);
        }
    }
    (void)pthread_mutex_unlock(&consistency->mutex);
}

/** @brief Exclude new mutations and wait for active mutations to finish. */
int management_restore_begin(struct jg_management *management)
{
    struct management_consistency *consistency = NULL;
    int status = 0;

    if (management == NULL || management->consistency == NULL) {
        return -EINVAL;
    }
    consistency = management->consistency;
    status = pthread_mutex_lock(&consistency->mutex);
    if (status != 0) {
        return -status;
    }
    if (consistency->restore_active) {
        status = EBUSY;
    } else {
        consistency->restore_active = true;
        while (status == 0 && consistency->active_mutations != 0U) {
            status =
                pthread_cond_wait(&consistency->available, &consistency->mutex);
        }
        if (status != 0) {
            consistency->restore_active = false;
            (void)pthread_cond_broadcast(&consistency->available);
        }
    }
    (void)pthread_mutex_unlock(&consistency->mutex);
    return -status;
}

/** @brief Reopen management mutations after a restore attempt. */
void management_restore_end(struct jg_management *management)
{
    struct management_consistency *consistency = NULL;

    if (management == NULL || management->consistency == NULL) {
        return;
    }
    consistency = management->consistency;
    if (pthread_mutex_lock(&consistency->mutex) != 0) {
        return;
    }
    consistency->restore_active = false;
    (void)pthread_cond_broadcast(&consistency->available);
    (void)pthread_mutex_unlock(&consistency->mutex);
}

/** @brief Report whether an exclusive restore currently owns the gate. */
bool management_restore_in_progress(struct jg_management *management)
{
    struct management_consistency *consistency = NULL;
    bool active = true;

    if (management == NULL || management->consistency == NULL) {
        return false;
    }
    consistency = management->consistency;
    if (pthread_mutex_lock(&consistency->mutex) != 0) {
        return true;
    }
    active = consistency->restore_active;
    (void)pthread_mutex_unlock(&consistency->mutex);
    return active;
}
