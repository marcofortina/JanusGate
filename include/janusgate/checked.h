/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file checked.h
 * @brief Overflow-safe arithmetic and bounded byte access.
 *
 * Functions never allocate memory. Output pointers are written only after all
 * validation succeeds. Callers retain ownership of every input and output
 * object.
 *
 * @thread_safety Every function is reentrant and accesses only caller-owned
 * storage.
 *
 * @error_handling Boolean functions return `false` for invalid pointers,
 * arithmetic overflow, or an out-of-bounds range.
 */

#ifndef JANUSGATE_CHECKED_H
#define JANUSGATE_CHECKED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/**
 * @brief Add two byte counts without wrapping.
 *
 * @param[in] left First non-negative byte count.
 * @param[in] right Second non-negative byte count.
 * @param[out] result Sum on success; unchanged on failure.
 *
 * @return `true` when the addition is representable.
 * @return `false` when @p result is null or the addition would overflow.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_size_add(size_t left, size_t right, size_t *result);

/**
 * @brief Multiply two byte counts without wrapping.
 *
 * @param[in] left First non-negative factor.
 * @param[in] right Second non-negative factor.
 * @param[out] result Product on success; unchanged on failure.
 *
 * @return `true` when the multiplication is representable.
 * @return `false` when @p result is null or the multiplication would overflow.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_size_multiply(size_t left, size_t right, size_t *result);

/**
 * @brief Check that a byte range is fully inside a containing buffer.
 *
 * @param[in] offset First byte of the candidate range.
 * @param[in] length Number of bytes in the candidate range.
 * @param[in] total_size Size of the containing buffer.
 *
 * @return `true` when `[offset, offset + length)` lies within the buffer.
 * @return `false` when the range overflows or exceeds @p total_size.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_range_valid(size_t offset, size_t length, size_t total_size);

/**
 * @brief Read an unsigned 16-bit integer in network byte order.
 *
 * @param[in] data Buffer containing the integer.
 * @param[in] data_size Available bytes in @p data.
 * @param[in] offset Offset of the first integer byte.
 * @param[out] value Decoded host-order value on success.
 *
 * @return `true` on success.
 * @return `false` for null pointers or an incomplete range.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_read_u16_be(const uint8_t *data,
                              size_t data_size,
                              size_t offset,
                              uint16_t *value);

/**
 * @brief Read an unsigned 32-bit integer in network byte order.
 *
 * @param[in] data Buffer containing the integer.
 * @param[in] data_size Available bytes in @p data.
 * @param[in] offset Offset of the first integer byte.
 * @param[out] value Decoded host-order value on success.
 *
 * @return `true` on success.
 * @return `false` for null pointers or an incomplete range.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_read_u32_be(const uint8_t *data,
                              size_t data_size,
                              size_t offset,
                              uint32_t *value);

/**
 * @brief Store an unsigned 16-bit integer in network byte order.
 *
 * @param[out] data Destination buffer.
 * @param[in] data_size Available bytes in @p data.
 * @param[in] offset Offset of the first destination byte.
 * @param[in] value Host-order value to store.
 *
 * @return `true` on success.
 * @return `false` for a null destination or an incomplete range.
 *
 * @thread_safety This function is reentrant.
 */
JG_PUBLIC bool jg_write_u16_be(uint8_t *data,
                               size_t data_size,
                               size_t offset,
                               uint16_t value);

/**
 * @brief Overwrite sensitive caller-owned storage.
 *
 * The implementation uses a volatile access path so an optimizing compiler
 * cannot discard the writes.
 *
 * @param[out] data Storage to clear. A null pointer is accepted only when
 * @p data_size is zero.
 * @param[in] data_size Number of bytes to clear.
 *
 * @thread_safety Concurrent calls are safe for distinct storage. Callers must
 * synchronize access to overlapping storage.
 */
JG_PUBLIC void jg_secure_clear(void *data, size_t data_size);

#endif
