/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/version.h"

/** @brief Return the configured JanusGate semantic version. */
const char *jg_version_string(void)
{
    return JANUSGATE_VERSION;
}

/** @brief Return the source revision embedded at configure time. */
const char *jg_build_commit(void)
{
    return JANUSGATE_BUILD_COMMIT;
}

/** @brief Return the reproducible build timestamp. */
const char *jg_build_timestamp(void)
{
    return JANUSGATE_BUILD_TIMESTAMP;
}

/** @brief Return the compiler identity embedded at configure time. */
const char *jg_build_compiler(void)
{
    return JANUSGATE_BUILD_COMPILER;
}

/** @brief Return the configured target system and processor. */
const char *jg_build_target(void)
{
    return JANUSGATE_BUILD_TARGET;
}
