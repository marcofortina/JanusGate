/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "janusgate/blocklist.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "janusgate/checked.h"
#include "janusgate/domain.h"

/** Non-owning byte range used by bounded text parsers. */
struct byte_span {
    const uint8_t *data;
    size_t size;
};

/** Temporary entry storing offsets into a growable string arena. */
struct staged_entry {
    uint32_t domain_offset;
    uint32_t category_offset;
};

/** Growable state used only during import. */
struct blocklist_stage {
    struct staged_entry *entries;
    size_t entry_count;
    size_t entry_capacity;
    char *strings;
    size_t strings_size;
    size_t strings_capacity;
};

/** Sort view created after the temporary arena stops moving. */
struct sort_entry {
    const char *domain;
    const char *category;
};

/** Compact immutable entry representation. */
struct stored_entry {
    uint32_t domain_offset;
    uint32_t category_offset;
};

/** Private immutable blocklist layout. */
struct jg_blocklist {
    struct jg_blocklist_info info;
    struct stored_entry *entries;
    char *strings;
};

/** @brief Determine whether one byte is ASCII whitespace. */
static bool is_space(uint8_t value)
{
    return value == (uint8_t)' ' || value == (uint8_t)'\t' ||
           value == (uint8_t)'\r' || value == (uint8_t)'\n' ||
           value == (uint8_t)'\f' || value == (uint8_t)'\v';
}

/** @brief Remove leading and trailing ASCII whitespace from a span. */
static struct byte_span trim_span(struct byte_span span)
{
    while (span.size > 0U && is_space(span.data[0])) {
        ++span.data;
        --span.size;
    }
    while (span.size > 0U && is_space(span.data[span.size - 1U])) {
        --span.size;
    }
    return span;
}

/** @brief Remove an inline comment introduced at a token boundary. */
static struct byte_span strip_comment(struct byte_span span, bool semicolon)
{
    size_t index = 0U;

    for (index = 0U; index < span.size; ++index) {
        const bool marker = span.data[index] == (uint8_t)'#' ||
                            (semicolon && span.data[index] == (uint8_t)';');

        if (marker && (index == 0U || is_space(span.data[index - 1U]))) {
            span.size = index;
            break;
        }
    }
    return trim_span(span);
}

/** @brief Extract the next ASCII-whitespace-delimited token. */
static struct byte_span next_token(struct byte_span *remaining)
{
    struct byte_span token = {0};
    size_t length = 0U;

    *remaining = trim_span(*remaining);
    token.data = remaining->data;
    while (length < remaining->size && !is_space(remaining->data[length])) {
        ++length;
    }
    token.size = length;
    remaining->data += length;
    remaining->size -= length;
    return token;
}

/** @brief Compare an ASCII span to a literal without locale rules. */
static bool span_equals_case_insensitive(struct byte_span span,
                                         const char *literal)
{
    size_t index = 0U;
    const size_t literal_size = strlen(literal);

    if (span.size != literal_size) {
        return false;
    }
    for (index = 0U; index < span.size; ++index) {
        uint8_t left = span.data[index];
        uint8_t right = (uint8_t)literal[index];

        if (left >= (uint8_t)'A' && left <= (uint8_t)'Z') {
            left = (uint8_t)(left + ((uint8_t)'a' - (uint8_t)'A'));
        }
        if (right >= (uint8_t)'A' && right <= (uint8_t)'Z') {
            right = (uint8_t)(right + ((uint8_t)'a' - (uint8_t)'A'));
        }
        if (left != right) {
            return false;
        }
    }
    return true;
}

/** @brief Measure and validate a null-terminated attribution string. */
static int attribution_size(const char *attribution, size_t *size)
{
    size_t length = 0U;

    if (attribution == NULL || size == NULL) {
        return -EINVAL;
    }
    while (length <= JG_BLOCKLIST_ATTRIBUTION_MAX &&
           attribution[length] != '\0') {
        ++length;
    }
    if (length == 0U || length > JG_BLOCKLIST_ATTRIBUTION_MAX) {
        return -EINVAL;
    }
    if (!jg_utf8_text_valid((const uint8_t *)attribution, length, false)) {
        return -EILSEQ;
    }
    *size = length + 1U;
    return 0;
}

/** @brief Grow the temporary entry array without losing its old allocation. */
static int reserve_entries(struct blocklist_stage *stage, size_t required)
{
    struct staged_entry *resized = NULL;
    size_t capacity = stage->entry_capacity == 0U ? 64U : stage->entry_capacity;
    size_t allocation_size = 0U;

    while (capacity < required) {
        if (capacity > SIZE_MAX / 2U) {
            return -EOVERFLOW;
        }
        capacity *= 2U;
    }
    if (capacity == stage->entry_capacity) {
        return 0;
    }
    if (!jg_size_multiply(capacity, sizeof(*stage->entries),
                          &allocation_size)) {
        return -EOVERFLOW;
    }
    resized = realloc(stage->entries, allocation_size);
    if (resized == NULL) {
        return -ENOMEM;
    }
    stage->entries = resized;
    stage->entry_capacity = capacity;
    return 0;
}

/** @brief Grow the temporary packed string arena. */
static int reserve_strings(struct blocklist_stage *stage, size_t required)
{
    char *resized = NULL;
    size_t capacity =
        stage->strings_capacity == 0U ? 4096U : stage->strings_capacity;

    while (capacity < required) {
        if (capacity > SIZE_MAX / 2U) {
            return -EOVERFLOW;
        }
        capacity *= 2U;
    }
    if (capacity == stage->strings_capacity) {
        return 0;
    }
    resized = realloc(stage->strings, capacity);
    if (resized == NULL) {
        return -ENOMEM;
    }
    stage->strings = resized;
    stage->strings_capacity = capacity;
    return 0;
}

/** @brief Normalize and append one staged domain and optional category. */
static int stage_entry(struct blocklist_stage *stage,
                       struct byte_span domain,
                       struct byte_span category,
                       size_t max_entries)
{
    char input[JG_DOMAIN_NAME_MAX * 4U + 2U];
    char normalized[JG_DOMAIN_NAME_MAX + 1U];
    size_t domain_size = 0U;
    size_t category_size = category.size + 1U;
    size_t required_strings = 0U;
    int result = 0;

    domain = trim_span(domain);
    category = trim_span(category);
    if (stage->entry_count >= max_entries) {
        return -E2BIG;
    }
    if (domain.size == 0U || domain.size >= sizeof(input) ||
        category.size > JG_BLOCKLIST_CATEGORY_MAX) {
        return -EINVAL;
    }
    if (!jg_utf8_text_valid(category.data, category.size, true)) {
        return -EILSEQ;
    }
    (void)memcpy(input, domain.data, domain.size);
    input[domain.size] = '\0';
    result = jg_domain_normalize(input, normalized, sizeof(normalized));
    if (result != 0) {
        return -EINVAL;
    }
    domain_size = strlen(normalized) + 1U;
    if (!jg_size_add(stage->strings_size, domain_size, &required_strings) ||
        !jg_size_add(required_strings, category_size, &required_strings) ||
        required_strings > (size_t)UINT32_MAX) {
        return -EOVERFLOW;
    }
    result = reserve_entries(stage, stage->entry_count + 1U);
    if (result == 0) {
        result = reserve_strings(stage, required_strings);
    }
    if (result != 0) {
        return result;
    }

    stage->entries[stage->entry_count].domain_offset =
        (uint32_t)stage->strings_size;
    (void)memcpy(stage->strings + stage->strings_size, normalized, domain_size);
    stage->strings_size += domain_size;
    stage->entries[stage->entry_count].category_offset =
        (uint32_t)stage->strings_size;
    if (category.size != 0U) {
        (void)memcpy(stage->strings + stage->strings_size, category.data,
                     category.size);
    }
    stage->strings[stage->strings_size + category.size] = '\0';
    stage->strings_size += category_size;
    ++stage->entry_count;
    return 0;
}

/** @brief Parse one plain domain record. */
static int parse_domain_record(struct blocklist_stage *stage,
                               struct byte_span line,
                               size_t max_entries)
{
    const struct byte_span empty = {0};

    line = strip_comment(line, true);
    if (line.size == 0U) {
        return 1;
    }
    return stage_entry(stage, line, empty, max_entries);
}

/** @brief Parse one domain with an optional category field. */
static int parse_category_record(struct blocklist_stage *stage,
                                 struct byte_span line,
                                 size_t max_entries)
{
    struct byte_span domain = {0};
    struct byte_span category = {0};
    size_t separator = 0U;

    line = strip_comment(line, false);
    if (line.size == 0U) {
        return 1;
    }
    separator = line.size;
    for (size_t index = 0U; index < line.size; ++index) {
        if (line.data[index] == (uint8_t)',' ||
            line.data[index] == (uint8_t)'\t') {
            separator = index;
            break;
        }
    }
    domain.data = line.data;
    domain.size = separator;
    if (separator < line.size) {
        category.data = line.data + separator + 1U;
        category.size = line.size - separator - 1U;
    }
    return stage_entry(stage, domain, category, max_entries);
}

/** @brief Parse one hosts-file record and append each declared hostname. */
static int parse_hosts_record(struct blocklist_stage *stage,
                              struct byte_span line,
                              size_t max_entries)
{
    const struct byte_span empty = {0};
    struct byte_span address = {0};
    char address_text[INET6_ADDRSTRLEN];
    uint8_t binary_address[16U];
    size_t initial_count = stage->entry_count;
    int family = AF_INET;
    int result = 0;

    line = strip_comment(line, false);
    if (line.size == 0U) {
        return 1;
    }
    address = next_token(&line);
    if (address.size == 0U || address.size >= sizeof(address_text)) {
        return -EINVAL;
    }
    (void)memcpy(address_text, address.data, address.size);
    address_text[address.size] = '\0';
    if (inet_pton(AF_INET, address_text, binary_address) != 1) {
        family = AF_INET6;
        if (inet_pton(family, address_text, binary_address) != 1) {
            return -EINVAL;
        }
    }

    while (result == 0) {
        const struct byte_span hostname = next_token(&line);

        if (hostname.size == 0U) {
            break;
        }
        result = stage_entry(stage, hostname, empty, max_entries);
    }
    if (result == 0 && stage->entry_count == initial_count) {
        result = -EINVAL;
    }
    return result;
}

/** @brief Parse one supported RPZ blocking CNAME record. */
static int parse_rpz_record(struct blocklist_stage *stage,
                            struct byte_span line,
                            size_t max_entries)
{
    const struct byte_span empty = {0};
    struct byte_span tokens[10U] = {0};
    size_t token_count = 0U;
    size_t type_index = 0U;

    line = strip_comment(line, true);
    if (line.size == 0U) {
        return 1;
    }
    while (line.size != 0U &&
           token_count < sizeof(tokens) / sizeof(tokens[0])) {
        tokens[token_count] = next_token(&line);
        if (tokens[token_count].size != 0U) {
            ++token_count;
        }
    }
    if (token_count == 0U || tokens[0].data[0] == (uint8_t)'$') {
        return 1;
    }
    for (type_index = 1U; type_index < token_count; ++type_index) {
        if (span_equals_case_insensitive(tokens[type_index], "CNAME") ||
            span_equals_case_insensitive(tokens[type_index], "SOA") ||
            span_equals_case_insensitive(tokens[type_index], "NS")) {
            break;
        }
    }
    if (type_index == token_count ||
        span_equals_case_insensitive(tokens[type_index], "SOA") ||
        span_equals_case_insensitive(tokens[type_index], "NS")) {
        return type_index == token_count ? -EINVAL : 1;
    }
    if (type_index + 1U >= token_count ||
        !(span_equals_case_insensitive(tokens[type_index + 1U], ".") ||
          span_equals_case_insensitive(tokens[type_index + 1U], "rpz-drop.") ||
          span_equals_case_insensitive(tokens[type_index + 1U],
                                       "rpz-nxdomain."))) {
        return -EINVAL;
    }
    return stage_entry(stage, tokens[0], empty, max_entries);
}

/** @brief Classify errors that tolerant mode may skip safely. */
static bool record_error_recoverable(int result)
{
    return result == -EINVAL || result == -EILSEQ || result == -EMSGSIZE;
}

/** @brief Record the first rejected record and increment rejection statistics.
 */
static void report_rejection(struct jg_blocklist_report *report,
                             size_t record,
                             int result)
{
    ++report->records_rejected;
    if (report->first_error == 0) {
        report->first_error_record = record;
        report->first_error = result;
    }
}

/** @brief Dispatch one bounded text record to its format parser. */
static int parse_text_record(struct blocklist_stage *stage,
                             struct byte_span line,
                             enum jg_blocklist_format format,
                             size_t max_entries)
{
    switch (format) {
    case JG_BLOCKLIST_FORMAT_DOMAIN:
        return parse_domain_record(stage, line, max_entries);
    case JG_BLOCKLIST_FORMAT_HOSTS:
        return parse_hosts_record(stage, line, max_entries);
    case JG_BLOCKLIST_FORMAT_CATEGORY:
        return parse_category_record(stage, line, max_entries);
    case JG_BLOCKLIST_FORMAT_RPZ:
        return parse_rpz_record(stage, line, max_entries);
    case JG_BLOCKLIST_FORMAT_JSON:
    default:
        return -EINVAL;
    }
}

/** @brief Parse every line of a bounded text-format input. */
static int parse_text(struct blocklist_stage *stage,
                      const uint8_t *data,
                      size_t data_size,
                      enum jg_blocklist_format format,
                      enum jg_blocklist_mode mode,
                      const struct jg_blocklist_limits *limits,
                      struct jg_blocklist_report *report)
{
    size_t offset = 0U;
    int result = 0;

    while (offset < data_size && result == 0) {
        const uint8_t *newline =
            memchr(data + offset, '\n', data_size - offset);
        const size_t line_size = newline == NULL
                                     ? data_size - offset
                                     : (size_t)(newline - (data + offset));
        const size_t old_entry_count = stage->entry_count;
        const size_t old_strings_size = stage->strings_size;
        const size_t record = report->records_seen + 1U;
        int line_result = 0;

        ++report->records_seen;
        if (line_size > limits->max_line_bytes) {
            line_result = -EMSGSIZE;
        } else {
            const struct byte_span line = {data + offset, line_size};

            line_result =
                parse_text_record(stage, line, format, limits->max_entries);
        }
        if (line_result < 0) {
            stage->entry_count = old_entry_count;
            stage->strings_size = old_strings_size;
            report_rejection(report, record, line_result);
            if (mode == JG_BLOCKLIST_STRICT ||
                !record_error_recoverable(line_result)) {
                result = line_result;
            }
        }
        offset += line_size + (newline == NULL ? 0U : 1U);
    }
    report->entries_parsed = stage->entry_count;
    return result;
}

/** @brief Parse the versioned JSON blocklist representation. */
static int parse_json(struct blocklist_stage *stage,
                      const uint8_t *data,
                      size_t data_size,
                      enum jg_blocklist_mode mode,
                      size_t max_entries,
                      struct jg_blocklist_report *report)
{
    json_error_t error;
    json_t *root = json_loadb((const char *)data, data_size,
                              JSON_REJECT_DUPLICATES, &error);
    json_t *version = NULL;
    json_t *entries = NULL;
    size_t index = 0U;
    int result = 0;

    if (root == NULL) {
        report_rejection(report, error.line > 0 ? (size_t)error.line : 1U,
                         -EINVAL);
        return -EINVAL;
    }
    if (!json_is_object(root)) {
        json_decref(root);
        report_rejection(report, 1U, -EINVAL);
        return -EINVAL;
    }
    version = json_object_get(root, "version");
    entries = json_object_get(root, "entries");
    if (!json_is_integer(version) || json_integer_value(version) != 1 ||
        !json_is_array(entries)) {
        json_decref(root);
        report_rejection(report, 1U, -EINVAL);
        return -EINVAL;
    }

    for (index = 0U; result == 0 && index < json_array_size(entries); ++index) {
        json_t *item = json_array_get(entries, index);
        json_t *domain_value =
            json_is_object(item) ? json_object_get(item, "domain") : NULL;
        json_t *category_value =
            json_is_object(item) ? json_object_get(item, "category") : NULL;
        struct byte_span domain = {0};
        struct byte_span category = {0};
        const size_t old_entry_count = stage->entry_count;
        const size_t old_strings_size = stage->strings_size;
        int entry_result = 0;

        ++report->records_seen;
        if (!json_is_string(domain_value) ||
            (category_value != NULL && !json_is_string(category_value))) {
            entry_result = -EINVAL;
        } else {
            domain.data = (const uint8_t *)json_string_value(domain_value);
            domain.size = json_string_length(domain_value);
            if (category_value != NULL) {
                category.data =
                    (const uint8_t *)json_string_value(category_value);
                category.size = json_string_length(category_value);
            }
            if (strlen((const char *)domain.data) != domain.size ||
                (category.data != NULL &&
                 strlen((const char *)category.data) != category.size)) {
                entry_result = -EILSEQ;
            } else {
                entry_result =
                    stage_entry(stage, domain, category, max_entries);
            }
        }
        if (entry_result < 0) {
            stage->entry_count = old_entry_count;
            stage->strings_size = old_strings_size;
            report_rejection(report, index + 1U, entry_result);
            if (mode == JG_BLOCKLIST_STRICT ||
                !record_error_recoverable(entry_result)) {
                result = entry_result;
            }
        }
    }
    report->entries_parsed = stage->entry_count;
    json_decref(root);
    return result;
}

/** @brief Compare staged entries by domain and preferred category. */
static int sort_entry_compare(const void *left_value, const void *right_value)
{
    const struct sort_entry *left = left_value;
    const struct sort_entry *right = right_value;
    int result = strcmp(left->domain, right->domain);

    if (result != 0) {
        return result;
    }
    if (left->category[0] == '\0' && right->category[0] != '\0') {
        return 1;
    }
    if (left->category[0] != '\0' && right->category[0] == '\0') {
        return -1;
    }
    return strcmp(left->category, right->category);
}

/** @brief Feed a canonical length-prefixed string to SHA-256. */
static void checksum_string(crypto_hash_sha256_state *state, const char *value)
{
    const size_t length = strlen(value);
    uint8_t encoded_length[8U];
    uint64_t remaining = (uint64_t)length;

    for (size_t index = 0U; index < sizeof(encoded_length); ++index) {
        encoded_length[sizeof(encoded_length) - index - 1U] =
            (uint8_t)(remaining & UINT64_C(0xff));
        remaining >>= 8U;
    }
    (void)crypto_hash_sha256_update(state, encoded_length,
                                    sizeof(encoded_length));
    (void)crypto_hash_sha256_update(state, (const uint8_t *)value,
                                    (unsigned long long)length);
}

/** @brief Compute a canonical checksum over sorted unique entries. */
static void blocklist_checksum(struct jg_blocklist *blocklist)
{
    static const uint8_t format[] = "JanusGate blocklist 1";
    crypto_hash_sha256_state state;

    (void)crypto_hash_sha256_init(&state);
    (void)crypto_hash_sha256_update(&state, format, sizeof(format) - 1U);
    for (size_t index = 0U; index < blocklist->info.entry_count; ++index) {
        checksum_string(&state, blocklist->strings +
                                    blocklist->entries[index].domain_offset);
        checksum_string(&state, blocklist->strings +
                                    blocklist->entries[index].category_offset);
    }
    (void)crypto_hash_sha256_final(&state, blocklist->info.checksum);
}

/** @brief Pack sorted unique entries into their immutable representation. */
static int finalize_blocklist(const struct blocklist_stage *stage,
                              const char *attribution,
                              size_t attribution_bytes,
                              struct jg_blocklist_report *report,
                              struct jg_blocklist **output)
{
    struct sort_entry *sorted = NULL;
    struct jg_blocklist *blocklist = NULL;
    size_t unique_count = 0U;
    size_t strings_size = attribution_bytes;
    size_t entries_size = 0U;
    size_t sorted_size = 0U;
    size_t cursor = attribution_bytes;
    int result = 0;

    if (stage->entry_count != 0U) {
        if (!jg_size_multiply(stage->entry_count, sizeof(*sorted),
                              &sorted_size)) {
            return -EOVERFLOW;
        }
        sorted = malloc(sorted_size);
        if (sorted == NULL) {
            return -ENOMEM;
        }
        for (size_t index = 0U; index < stage->entry_count; ++index) {
            sorted[index].domain =
                stage->strings + stage->entries[index].domain_offset;
            sorted[index].category =
                stage->strings + stage->entries[index].category_offset;
        }
        qsort(sorted, stage->entry_count, sizeof(*sorted), sort_entry_compare);
        for (size_t index = 0U; result == 0 && index < stage->entry_count;
             ++index) {
            if (index == 0U ||
                strcmp(sorted[index - 1U].domain, sorted[index].domain) != 0) {
                ++unique_count;
                if (!jg_size_add(strings_size,
                                 strlen(sorted[index].domain) + 1U,
                                 &strings_size) ||
                    !jg_size_add(strings_size,
                                 strlen(sorted[index].category) + 1U,
                                 &strings_size) ||
                    strings_size > (size_t)UINT32_MAX) {
                    result = -EOVERFLOW;
                    break;
                }
            }
        }
    }
    if (result == 0 &&
        !jg_size_multiply(unique_count, sizeof(*blocklist->entries),
                          &entries_size)) {
        result = -EOVERFLOW;
    }
    if (result == 0) {
        blocklist = calloc(1U, sizeof(*blocklist));
        if (blocklist == NULL) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        blocklist->strings = malloc(strings_size);
        if (unique_count != 0U) {
            blocklist->entries = malloc(entries_size);
        }
        if (blocklist->strings == NULL ||
            (unique_count != 0U && blocklist->entries == NULL)) {
            result = -ENOMEM;
        }
    }
    if (result == 0) {
        (void)memcpy(blocklist->strings, attribution, attribution_bytes);
        blocklist->info.attribution = blocklist->strings;
        blocklist->info.entry_count = unique_count;
        unique_count = 0U;
        for (size_t index = 0U; index < stage->entry_count; ++index) {
            if (index != 0U &&
                strcmp(sorted[index - 1U].domain, sorted[index].domain) == 0) {
                continue;
            }
            blocklist->entries[unique_count].domain_offset = (uint32_t)cursor;
            (void)memcpy(blocklist->strings + cursor, sorted[index].domain,
                         strlen(sorted[index].domain) + 1U);
            cursor += strlen(sorted[index].domain) + 1U;
            blocklist->entries[unique_count].category_offset = (uint32_t)cursor;
            (void)memcpy(blocklist->strings + cursor, sorted[index].category,
                         strlen(sorted[index].category) + 1U);
            cursor += strlen(sorted[index].category) + 1U;
            ++unique_count;
        }
        report->duplicates_removed =
            stage->entry_count - blocklist->info.entry_count;
        blocklist_checksum(blocklist);
        *output = blocklist;
    } else {
        jg_blocklist_destroy(blocklist);
    }
    free(sorted);
    return result;
}

/** @brief Initialize conservative blocklist import limits. */
void jg_blocklist_limits_default(struct jg_blocklist_limits *limits)
{
    if (limits == NULL) {
        return;
    }
    limits->max_file_bytes = 64U * 1024U * 1024U;
    limits->max_line_bytes = 4096U;
    limits->max_entries = 1000000U;
}

/** @brief Import, normalize, deduplicate, and pack a blocklist buffer. */
int jg_blocklist_import(const uint8_t *data,
                        size_t data_size,
                        enum jg_blocklist_format format,
                        enum jg_blocklist_mode mode,
                        const char *attribution,
                        const struct jg_blocklist_limits *limits,
                        struct jg_blocklist **blocklist,
                        struct jg_blocklist_report *report)
{
    struct jg_blocklist_limits default_limits;
    const struct jg_blocklist_limits *active_limits = limits;
    struct jg_blocklist_report local_report = {0};
    struct blocklist_stage stage = {0};
    size_t attribution_bytes = 0U;
    int result = 0;

    if (blocklist == NULL) {
        return -EINVAL;
    }
    *blocklist = NULL;
    if (report != NULL) {
        (void)memset(report, 0, sizeof(*report));
    }
    if (active_limits == NULL) {
        jg_blocklist_limits_default(&default_limits);
        active_limits = &default_limits;
    }
    if ((data == NULL && data_size != 0U) ||
        (mode != JG_BLOCKLIST_STRICT && mode != JG_BLOCKLIST_TOLERANT) ||
        format < JG_BLOCKLIST_FORMAT_DOMAIN ||
        format > JG_BLOCKLIST_FORMAT_JSON ||
        active_limits->max_file_bytes == 0U ||
        active_limits->max_line_bytes == 0U ||
        active_limits->max_entries == 0U) {
        return -EINVAL;
    }
    if (data_size > active_limits->max_file_bytes) {
        return -EFBIG;
    }
    if (data_size != 0U && memchr(data, '\0', data_size) != NULL) {
        return -EILSEQ;
    }
    result = attribution_size(attribution, &attribution_bytes);
    if (result == 0 && sodium_init() < 0) {
        result = -EIO;
    }
    if (result == 0 && format == JG_BLOCKLIST_FORMAT_JSON) {
        result = parse_json(&stage, data != NULL ? data : (const uint8_t *)"",
                            data_size, mode, active_limits->max_entries,
                            &local_report);
    } else if (result == 0) {
        result = parse_text(&stage, data, data_size, format, mode,
                            active_limits, &local_report);
    }
    if (result == 0) {
        result = finalize_blocklist(&stage, attribution, attribution_bytes,
                                    &local_report, blocklist);
    }
    free(stage.strings);
    free(stage.entries);
    if (report != NULL) {
        *report = local_report;
    }
    return result;
}

/** @brief Destroy an imported immutable blocklist. */
void jg_blocklist_destroy(struct jg_blocklist *blocklist)
{
    if (blocklist == NULL) {
        return;
    }
    free(blocklist->entries);
    free(blocklist->strings);
    free(blocklist);
}

/** @brief Copy metadata from an immutable blocklist. */
int jg_blocklist_get_info(const struct jg_blocklist *blocklist,
                          struct jg_blocklist_info *info)
{
    if (blocklist == NULL || info == NULL) {
        return -EINVAL;
    }
    *info = blocklist->info;
    return 0;
}

/** @brief Borrow one canonically ordered blocklist entry. */
int jg_blocklist_get_entry(const struct jg_blocklist *blocklist,
                           size_t index,
                           struct jg_blocklist_entry *entry)
{
    if (blocklist == NULL || entry == NULL ||
        index >= blocklist->info.entry_count) {
        return -EINVAL;
    }
    entry->domain =
        blocklist->strings + blocklist->entries[index].domain_offset;
    entry->category =
        blocklist->strings + blocklist->entries[index].category_offset;
    return 0;
}
