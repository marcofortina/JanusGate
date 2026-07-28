/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/checked.h"

#include <stdint.h>

/** @brief Add two byte counts without unsigned overflow. */
bool jg_size_add(size_t left, size_t right, size_t *result)
{
    if (result == NULL || right > SIZE_MAX - left) {
        return false;
    }
    *result = left + right;
    return true;
}

/** @brief Multiply two byte counts without unsigned overflow. */
bool jg_size_multiply(size_t left, size_t right, size_t *result)
{
    if (result == NULL || (left != 0U && right > SIZE_MAX / left)) {
        return false;
    }
    *result = left * right;
    return true;
}

/** @brief Validate a bounded half-open byte range. */
bool jg_range_valid(size_t offset, size_t length, size_t total_size)
{
    return offset <= total_size && length <= total_size - offset;
}

/** @brief Read a network-order 16-bit integer from a bounded buffer. */
bool jg_read_u16_be(const uint8_t *data,
                    size_t data_size,
                    size_t offset,
                    uint16_t *value)
{
    if (data == NULL || value == NULL ||
        !jg_range_valid(offset, 2U, data_size)) {
        return false;
    }
    *value = (uint16_t)(((uint16_t)data[offset] << 8U) |
                        (uint16_t)data[offset + 1U]);
    return true;
}

/** @brief Read a network-order 32-bit integer from a bounded buffer. */
bool jg_read_u32_be(const uint8_t *data,
                    size_t data_size,
                    size_t offset,
                    uint32_t *value)
{
    if (data == NULL || value == NULL ||
        !jg_range_valid(offset, 4U, data_size)) {
        return false;
    }
    *value = ((uint32_t)data[offset] << 24U) |
             ((uint32_t)data[offset + 1U] << 16U) |
             ((uint32_t)data[offset + 2U] << 8U) | (uint32_t)data[offset + 3U];
    return true;
}

/** @brief Read a network-order 64-bit integer from a bounded buffer. */
bool jg_read_u64_be(const uint8_t *data,
                    size_t data_size,
                    size_t offset,
                    uint64_t *value)
{
    uint32_t high = 0U;
    uint32_t low = 0U;

    if (value == NULL || !jg_read_u32_be(data, data_size, offset, &high) ||
        !jg_read_u32_be(data, data_size, offset + 4U, &low)) {
        return false;
    }
    *value = ((uint64_t)high << 32U) | (uint64_t)low;
    return true;
}

/** @brief Write a network-order 16-bit integer to a bounded buffer. */
bool jg_write_u16_be(uint8_t *data,
                     size_t data_size,
                     size_t offset,
                     uint16_t value)
{
    if (data == NULL || !jg_range_valid(offset, 2U, data_size)) {
        return false;
    }
    data[offset] = (uint8_t)(value >> 8U);
    data[offset + 1U] = (uint8_t)(value & UINT16_C(0xff));
    return true;
}

/** @brief Write a network-order 32-bit integer to a bounded buffer. */
bool jg_write_u32_be(uint8_t *data,
                     size_t data_size,
                     size_t offset,
                     uint32_t value)
{
    if (data == NULL || !jg_range_valid(offset, 4U, data_size)) {
        return false;
    }
    data[offset] = (uint8_t)(value >> 24U);
    data[offset + 1U] = (uint8_t)((value >> 16U) & UINT32_C(0xff));
    data[offset + 2U] = (uint8_t)((value >> 8U) & UINT32_C(0xff));
    data[offset + 3U] = (uint8_t)(value & UINT32_C(0xff));
    return true;
}

/** @brief Write a network-order 64-bit integer to a bounded buffer. */
bool jg_write_u64_be(uint8_t *data,
                     size_t data_size,
                     size_t offset,
                     uint64_t value)
{
    return jg_write_u32_be(data, data_size, offset, (uint32_t)(value >> 32U)) &&
           jg_write_u32_be(data, data_size, offset + 4U,
                           (uint32_t)(value & UINT64_C(0xffffffff)));
}

/** @brief Validate bounded UTF-8 text and reject ASCII controls. */
bool jg_utf8_text_valid(const uint8_t *data, size_t data_size, bool allow_empty)
{
    size_t index = 0U;

    if ((!allow_empty && data_size == 0U) ||
        (data == NULL && data_size != 0U)) {
        return false;
    }
    while (index < data_size) {
        const uint8_t first = data[index];
        size_t sequence_size = 0U;

        if (first <= UINT8_C(0x7f)) {
            if (first < UINT8_C(0x20) || first == UINT8_C(0x7f)) {
                return false;
            }
            ++index;
            continue;
        }
        if (first >= UINT8_C(0xc2) && first <= UINT8_C(0xdf)) {
            sequence_size = 2U;
        } else if (first >= UINT8_C(0xe0) && first <= UINT8_C(0xef)) {
            sequence_size = 3U;
        } else if (first >= UINT8_C(0xf0) && first <= UINT8_C(0xf4)) {
            sequence_size = 4U;
        } else {
            return false;
        }
        if (sequence_size > data_size - index) {
            return false;
        }
        if ((data[index + 1U] & UINT8_C(0xc0)) != UINT8_C(0x80) ||
            (sequence_size >= 3U &&
             (data[index + 2U] & UINT8_C(0xc0)) != UINT8_C(0x80)) ||
            (sequence_size == 4U &&
             (data[index + 3U] & UINT8_C(0xc0)) != UINT8_C(0x80))) {
            return false;
        }
        if ((first == UINT8_C(0xe0) && data[index + 1U] < UINT8_C(0xa0)) ||
            (first == UINT8_C(0xed) && data[index + 1U] > UINT8_C(0x9f)) ||
            (first == UINT8_C(0xf0) && data[index + 1U] < UINT8_C(0x90)) ||
            (first == UINT8_C(0xf4) && data[index + 1U] > UINT8_C(0x8f))) {
            return false;
        }
        index += sequence_size;
    }
    return true;
}

/** @brief Clear caller-owned storage through a non-elidable access path. */
void jg_secure_clear(void *data, size_t data_size)
{
    volatile uint8_t *cursor = data;

    if (cursor == NULL) {
        return;
    }
    while (data_size > 0U) {
        *cursor = 0U;
        ++cursor;
        --data_size;
    }
}
