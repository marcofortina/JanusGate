/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file domain.h
 * @brief IDNA2008 domain normalization and label-boundary comparison.
 *
 * Output is caller-owned and always uses lowercase ASCII A-labels. Functions
 * allocate only through libidn2 during administrator-input conversion and
 * release that temporary storage before returning.
 *
 * @thread_safety Functions are reentrant, subject to the documented
 * thread-safety guarantees of the linked libidn2 release.
 *
 * @error_handling Normalization returns negative errno-style values and leaves
 * the destination empty on failure.
 */

#ifndef JANUSGATE_DOMAIN_H
#define JANUSGATE_DOMAIN_H

#include <stdbool.h>
#include <stddef.h>

#include "janusgate/version.h"

/** Maximum normalized domain bytes excluding the null terminator. */
#define JG_DOMAIN_NAME_MAX 253U

/** Maximum bytes in one DNS label. */
#define JG_DOMAIN_LABEL_MAX 63U

/**
 * @brief Normalize administrator-provided UTF-8 using IDNA2008.
 *
 * ASCII letters are lowercased without locale rules and one trailing root dot
 * is removed. Empty names, consecutive dots, invalid Unicode, and disallowed
 * IDNA input are rejected.
 *
 * @param[in] input Null-terminated UTF-8 domain.
 * @param[out] output Destination for a lowercase A-label domain.
 * @param[in] output_size Destination size including the null terminator.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid input or domain syntax.
 * @return -ENOSPC when @p output is too small.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC int jg_domain_normalize(const char *input,
                                  char *output,
                                  size_t output_size);

/**
 * @brief Validate an already normalized ASCII policy domain.
 *
 * @param[in] domain Null-terminated lowercase A-label domain.
 *
 * @return `true` when the name follows policy-domain length and label rules.
 * @return `false` for null, empty, uppercase, or malformed input.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_domain_is_normalized(const char *domain);

/**
 * @brief Match a normalized name against an exact or subtree rule.
 *
 * @param[in] name Normalized candidate name.
 * @param[in] rule Normalized rule domain.
 * @param[in] include_subdomains Whether names below @p rule also match.
 *
 * @return `true` for an exact match, or a label-boundary suffix match when
 * requested.
 * @return `false` for invalid inputs and byte-only false suffixes.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_domain_matches(const char *name,
                                 const char *rule,
                                 bool include_subdomains);

#endif
