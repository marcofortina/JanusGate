/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#include "nftables.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <nftables/libnftables.h>

/** Maximum accepted diagnostic output from one libnftables list operation. */
#define JG_NFT_LIST_OUTPUT_MAX 1048576U

/** Presence and ownership state of the fixed bridge-family table. */
enum table_state {
    TABLE_ABSENT = 0,
    TABLE_OWNED = 1,
    TABLE_FOREIGN = 2
};

/** @brief Create one quiet, numeric libnftables context. */
static struct nft_ctx *create_context(void)
{
    struct nft_ctx *context = nft_ctx_new(NFT_CTX_DEFAULT);

    if (context == NULL) {
        return NULL;
    }
    (void)nft_ctx_input_set_flags(context, NFT_CTX_INPUT_NO_DNS);
    nft_ctx_output_set_flags(context, NFT_CTX_OUTPUT_NUMERIC_ALL);
    if (nft_ctx_buffer_output(context) != 0 ||
        nft_ctx_buffer_error(context) != 0) {
        nft_ctx_free(context);
        return NULL;
    }
    return context;
}

/** @brief Run one fixed or internally constructed libnftables command. */
static int run_command(const char *command)
{
    struct nft_ctx *context = create_context();
    int result = 0;

    if (context == NULL) {
        return -ENOMEM;
    }
    errno = 0;
    if (nft_run_cmd_from_buffer(context, command) != 0) {
        result = errno == 0 ? -EIO : -errno;
    }
    nft_ctx_free(context);
    return result;
}

/** @brief Measure a libnftables buffer without unbounded scanning. */
static int bounded_output_size(const char *output, size_t *output_size)
{
    size_t size = 0U;

    if (output == NULL || output_size == NULL) {
        return -EIO;
    }
    while (size <= JG_NFT_LIST_OUTPUT_MAX && output[size] != '\0') {
        ++size;
    }
    if (size > JG_NFT_LIST_OUTPUT_MAX) {
        return -EFBIG;
    }
    *output_size = size;
    return 0;
}

/** @brief Match one exact table declaration in `list tables` output. */
static bool table_declared(const char *output, size_t output_size)
{
    static const char declaration[] = "table bridge " JG_NETD_NFT_TABLE;
    size_t offset = 0U;

    while (offset < output_size) {
        size_t line_size = 0U;

        while (offset + line_size < output_size &&
               output[offset + line_size] != '\n') {
            ++line_size;
        }
        if (line_size == sizeof(declaration) - 1U &&
            memcmp(output + offset, declaration, line_size) == 0) {
            return true;
        }
        offset += line_size;
        if (offset < output_size) {
            ++offset;
        }
    }
    return false;
}

/** @brief Query whether the fixed table is absent, owned, or foreign. */
static int query_table_state(enum table_state *state)
{
    static const char owned_prefix[] =
        "table bridge " JG_NETD_NFT_TABLE " {\n\tcomment \"" JG_NETD_NFT_COMMENT
        "\"";
    static const char list_tables[] = "list tables bridge\n";
    static const char list_table[] =
        "list table bridge " JG_NETD_NFT_TABLE "\n";
    struct nft_ctx *context = NULL;
    const char *output = NULL;
    size_t output_size = 0U;
    int result = 0;

    if (state == NULL) {
        return -EINVAL;
    }
    context = create_context();
    if (context == NULL) {
        return -ENOMEM;
    }
    if (nft_run_cmd_from_buffer(context, list_tables) != 0) {
        result = -EIO;
    }
    if (result == 0) {
        output = nft_ctx_get_output_buffer(context);
        result = bounded_output_size(output, &output_size);
    }
    if (result == 0 && !table_declared(output, output_size)) {
        *state = TABLE_ABSENT;
    } else if (result == 0) {
        nft_ctx_free(context);
        context = create_context();
        if (context == NULL) {
            return -ENOMEM;
        }
        if (nft_run_cmd_from_buffer(context, list_table) != 0) {
            result = -EIO;
        }
        if (result == 0) {
            output = nft_ctx_get_output_buffer(context);
            result = bounded_output_size(output, &output_size);
        }
        if (result == 0) {
            *state = output_size >= sizeof(owned_prefix) - 1U &&
                             memcmp(output, owned_prefix,
                                    sizeof(owned_prefix) - 1U) == 0
                         ? TABLE_OWNED
                         : TABLE_FOREIGN;
        }
    }
    nft_ctx_free(context);
    return result;
}

/** @brief Generate one complete bounded owned nftables transaction. */
int jg_netd_build_nft_rules(const struct jg_network_config *config,
                            bool replace_owned,
                            char *output,
                            size_t output_size)
{
    char fragment_queue[64U];
    char queue[128U];
    char queue_range[32U];
    const char *queue_flags = "";
    uint32_t queue_last = 0U;
    int written = 0;
    int result = jg_network_config_validate(config);

    if (output == NULL) {
        return -EINVAL;
    }
    if (result != 0) {
        return result;
    }
    queue_last =
        (uint32_t)config->queue_first + (uint32_t)config->queue_count - 1U;
    if (config->failure_mode == JG_NETWORK_FAIL_OPEN &&
        config->queue_cpu_fanout && config->queue_count > 1U) {
        queue_flags = " flags bypass,fanout";
    } else if (config->failure_mode == JG_NETWORK_FAIL_OPEN) {
        queue_flags = " flags bypass";
    } else if (config->queue_cpu_fanout && config->queue_count > 1U) {
        queue_flags = " flags fanout";
    }
    if (config->queue_count == 1U) {
        (void)snprintf(queue_range, sizeof(queue_range), "%u",
                       (unsigned int)config->queue_first);
    } else {
        (void)snprintf(queue_range, sizeof(queue_range), "%u-%u",
                       (unsigned int)config->queue_first,
                       (unsigned int)queue_last);
    }
    written = snprintf(queue, sizeof(queue), "queue%s to %s", queue_flags,
                       queue_range);
    if (written < 0 || (size_t)written >= sizeof(queue)) {
        return -ENOSPC;
    }
    written = snprintf(fragment_queue, sizeof(fragment_queue),
                       config->failure_mode == JG_NETWORK_FAIL_OPEN
                           ? "queue flags bypass to %u"
                           : "queue to %u",
                       (unsigned int)config->queue_first);
    if (written < 0 || (size_t)written >= sizeof(fragment_queue)) {
        return -ENOSPC;
    }

    written = snprintf(
        output, output_size,
        "%s"
        "table bridge " JG_NETD_NFT_TABLE " {\n"
        "  comment \"" JG_NETD_NFT_COMMENT "\"\n"
        "  set ingress_port { type ifname; elements = { \"%s\" }; }\n"
        "  set destination_ipv4 { type ipv4_addr; flags interval; }\n"
        "  set destination_ipv6 { type ipv6_addr; flags interval; }\n"
        "  set encrypted_dns_ipv4 { type ipv4_addr; flags interval; }\n"
        "  set encrypted_dns_ipv6 { type ipv6_addr; flags interval; }\n"
        "  chain inspect {\n"
        "    type filter hook prerouting priority -300; policy accept;\n"
        "    iifname @ingress_port ether type ip ip frag-off & 0x3fff != 0 "
        "counter %s comment \"JanusGate IPv4 fragments\"\n"
        "    iifname @ingress_port ether type ip6 exthdr frag exists "
        "counter %s comment \"JanusGate IPv6 fragments\"\n"
        "    iifname @ingress_port ether type ip ip daddr @destination_ipv4 "
        "counter %s comment \"JanusGate destination IPv4\"\n"
        "    iifname @ingress_port ether type ip6 ip6 daddr @destination_ipv6 "
        "counter %s comment \"JanusGate destination IPv6\"\n"
        "    iifname @ingress_port ether type ip ip daddr @encrypted_dns_ipv4 "
        "counter %s comment \"JanusGate encrypted DNS IPv4\"\n"
        "    iifname @ingress_port ether type ip6 ip6 daddr "
        "@encrypted_dns_ipv6 "
        "counter %s comment \"JanusGate encrypted DNS IPv6\"\n"
        "    iifname @ingress_port meta l4proto udp udp dport 53 counter %s "
        "comment \"JanusGate DNS UDP\"\n"
        "    iifname @ingress_port meta l4proto tcp tcp dport 53 counter %s "
        "comment \"JanusGate DNS TCP\"\n"
        "    iifname @ingress_port meta l4proto udp udp dport 853 counter %s "
        "comment \"JanusGate encrypted DNS UDP\"\n"
        "    iifname @ingress_port meta l4proto tcp tcp dport 853 counter %s "
        "comment \"JanusGate encrypted DNS TCP\"\n"
        "    iifname @ingress_port meta l4proto udp udp dport 443 counter %s "
        "comment \"JanusGate QUIC inspection\"\n"
        "    iifname @ingress_port meta l4proto tcp tcp dport 443 counter %s "
        "comment \"JanusGate TLS inspection\"\n"
        "    iifname @ingress_port counter comment \"JanusGate pass-through\"\n"
        "  }\n"
        "}\n",
        replace_owned ? "flush table bridge " JG_NETD_NFT_TABLE "\n" : "",
        config->ingress, fragment_queue, fragment_queue, queue, queue, queue,
        queue, queue, queue, queue, queue, queue, queue);
    return written < 0 || (size_t)written >= output_size ? -ENOSPC : 0;
}

/** @brief Atomically create or replace the verified owned table. */
int jg_netd_apply_nft_rules(const struct jg_network_config *config)
{
    char rules[JG_NETD_NFT_RULESET_MAX];
    enum table_state state = TABLE_ABSENT;
    int result = jg_network_config_validate(config);

    if (result == 0) {
        result = query_table_state(&state);
    }
    if (result == 0 && state == TABLE_FOREIGN) {
        result = -EEXIST;
    }
    if (result == 0) {
        result = jg_netd_build_nft_rules(config, state == TABLE_OWNED, rules,
                                         sizeof(rules));
    }
    if (result == 0) {
        result = run_command(rules);
    }
    return result;
}

/** @brief Remove only the verified owned table when present. */
int jg_netd_remove_nft_rules(void)
{
    static const char remove_table[] =
        "delete table bridge " JG_NETD_NFT_TABLE "\n";
    enum table_state state = TABLE_ABSENT;
    int result = query_table_state(&state);

    if (result == 0 && state == TABLE_FOREIGN) {
        result = -EEXIST;
    }
    if (result == 0 && state == TABLE_OWNED) {
        result = run_command(remove_table);
    }
    return result;
}
