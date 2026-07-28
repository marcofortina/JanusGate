/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file identity.h
 * @brief Fixed service identities used for local privilege separation.
 */

#ifndef JANUSGATE_IDENTITY_H
#define JANUSGATE_IDENTITY_H

/** Main packet and policy service account. */
#define JG_SERVICE_USER "janusgate"

/** Unprivileged HTTPS administration service account. */
#define JG_WEB_SERVICE_USER "janusgate-web"

/** Shared filesystem group for authenticated local control sockets. */
#define JG_CONTROL_GROUP "janusgate-control"

#endif
