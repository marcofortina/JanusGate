/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file policy.h
 * @brief Immutable domain-policy snapshots and deterministic matching.
 *
 * A snapshot owns packed normalized names, rule metadata, and its lookup
 * table. The builder transfers ownership through the output pointer; callers
 * release the snapshot with jg_policy_snapshot_destroy().
 *
 * Snapshot contents never change after construction. Consequently, any
 * number of threads may match against the same snapshot. The owner must
 * arrange publication and defer destruction until all readers have finished.
 *
 * @error_handling Fallible functions return zero on success and a negative
 * errno-style value on failure. A failed build leaves the output pointer null.
 */

#ifndef JANUSGATE_POLICY_H
#define JANUSGATE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/version.h"

/** Number of bytes in a policy snapshot SHA-256 checksum. */
#define JG_POLICY_CHECKSUM_SIZE 32U

/** Maximum rule-attribution bytes excluding the null terminator. */
#define JG_POLICY_ATTRIBUTION_MAX 255U

/**
 * @brief Action selected by a policy rule.
 */
enum jg_policy_effect {
    /** Permit matching traffic. */
    JG_POLICY_ALLOW = 1,
    /** Reject matching traffic. */
    JG_POLICY_BLOCK = 2
};

/**
 * @brief Origin and precedence class of a policy rule.
 */
enum jg_policy_source {
    /** No rule matched; used only in match results. */
    JG_POLICY_SOURCE_DEFAULT = 0,
    /** Rule imported from a blocklist source. */
    JG_POLICY_SOURCE_BLOCKLIST = 1,
    /** Administrator-defined allow or block rule. */
    JG_POLICY_SOURCE_EXPLICIT = 2,
    /** Highest-priority local emergency allow rule. */
    JG_POLICY_SOURCE_EMERGENCY = 3
};

/** Protocol context in which a domain rule may match. */
enum jg_policy_domain_target {
    /** Classic DNS question name. */
    JG_POLICY_DOMAIN_DNS = 0,
    /** Visible TLS ClientHello server name. */
    JG_POLICY_DOMAIN_TLS_SNI = 1
};

/**
 * @brief Address family used by client identity data.
 */
enum jg_policy_address_family {
    /** No source IP address is available. */
    JG_POLICY_ADDRESS_NONE = 0,
    /** Four-byte IPv4 source address. */
    JG_POLICY_ADDRESS_IPV4 = 4,
    /** Sixteen-byte IPv6 source address. */
    JG_POLICY_ADDRESS_IPV6 = 6
};

/**
 * @brief Transport selector used by destination policy.
 */
enum jg_policy_transport {
    /** Match either TCP or UDP. */
    JG_POLICY_TRANSPORT_ANY = 0,
    /** Match TCP traffic only. */
    JG_POLICY_TRANSPORT_TCP = 6,
    /** Match UDP traffic only. */
    JG_POLICY_TRANSPORT_UDP = 17
};

/**
 * @brief Optional client constraint attached to a rule.
 */
enum jg_policy_scope_type {
    /** Rule applies to every client. */
    JG_POLICY_SCOPE_GLOBAL = 0,
    /** Rule applies to one source MAC address. */
    JG_POLICY_SCOPE_MAC = 1,
    /** Rule applies to an IPv4 source prefix. */
    JG_POLICY_SCOPE_IPV4 = 2,
    /** Rule applies to an IPv6 source prefix. */
    JG_POLICY_SCOPE_IPV6 = 3,
    /** Rule applies to one VLAN identifier. */
    JG_POLICY_SCOPE_VLAN = 4
};

/**
 * @brief Rule scope in canonical network form.
 */
struct jg_policy_scope {
    /** Kind of constraint stored in @ref value. */
    enum jg_policy_scope_type type;
    /** Data selected by @ref type. */
    union {
        /** Source MAC bytes for JG_POLICY_SCOPE_MAC. */
        uint8_t mac[6U];
        /** Source network for an IPv4 or IPv6 scope. */
        struct {
            /** Network address in network byte order. */
            uint8_t address[16U];
            /** Significant leading address bits. */
            uint8_t prefix_length;
        } network;
        /** VLAN identifier from 0 through 4094. */
        uint16_t vlan_id;
    } value;
};

/**
 * @brief Client properties available during matching.
 */
struct jg_policy_client {
    /** Whether @ref mac contains a source MAC address. */
    bool has_mac;
    /** Source MAC address. */
    uint8_t mac[6U];
    /** Available source IP address family. */
    enum jg_policy_address_family address_family;
    /** Source address in network byte order; IPv4 uses the first four bytes. */
    uint8_t address[16U];
    /** Whether @ref vlan_id is available. */
    bool has_vlan;
    /** Source VLAN identifier. */
    uint16_t vlan_id;
};

/**
 * @brief Administrator or blocklist rule supplied to the snapshot builder.
 */
struct jg_policy_rule_input {
    /** Stable nonzero identifier used to explain a verdict. */
    uint64_t id;
    /** UTF-8 domain normalized by the builder using IDNA2008. */
    const char *domain;
    /** Whether descendants at DNS label boundaries also match. */
    bool include_subdomains;
    /** Allow or block action. */
    enum jg_policy_effect effect;
    /** Rule origin and precedence class. */
    enum jg_policy_source source;
    /** DNS or visible TLS-SNI matching context. */
    enum jg_policy_domain_target target;
    /** Global or client-specific applicability. */
    struct jg_policy_scope scope;
    /** Nonempty source description copied into the snapshot. */
    const char *attribution;
};

/**
 * @brief Administrator or source rule for a destination network or port.
 */
struct jg_policy_destination_rule_input {
    /** Stable nonzero identifier used to explain a verdict. */
    uint64_t id;
    /** Allow or block action. */
    enum jg_policy_effect effect;
    /** Rule origin and precedence class. */
    enum jg_policy_source source;
    /** Any, TCP, or UDP transport selector. */
    enum jg_policy_transport transport;
    /** Whether an address prefix participates in matching. */
    bool has_address;
    /** Address family when @ref has_address is true. */
    enum jg_policy_address_family address_family;
    /** Network-order prefix address; IPv4 uses the first four bytes. */
    uint8_t address[16U];
    /** Significant leading bits in @ref address. */
    uint8_t prefix_length;
    /** Whether @ref port participates in matching. */
    bool has_port;
    /** Destination port when @ref has_port is true. */
    uint16_t port;
    /** Global or client-specific applicability. */
    struct jg_policy_scope scope;
    /** Nonempty source description copied into the snapshot. */
    const char *attribution;
};

/**
 * @brief Destination properties supplied to immutable policy matching.
 */
struct jg_policy_destination {
    /** TCP, UDP, or any when no transport selector is available. */
    enum jg_policy_transport transport;
    /** IPv4 or IPv6 destination family. */
    enum jg_policy_address_family address_family;
    /** Network-order destination address. */
    uint8_t address[16U];
    /** Destination transport port, or zero when unavailable. */
    uint16_t port;
};

/**
 * @brief Stable snapshot metadata.
 */
struct jg_policy_snapshot_info {
    /** Caller-supplied nonzero configuration generation. */
    uint64_t generation;
    /** Snapshot construction time as Unix seconds. */
    uint64_t built_at;
    /** Number of rules retained after normalization and deduplication. */
    size_t rule_count;
    /** Number of destination rules retained after deduplication. */
    size_t destination_rule_count;
    /** Canonical SHA-256 digest independent of hash-table layout. */
    uint8_t checksum[JG_POLICY_CHECKSUM_SIZE];
};

/**
 * @brief Explanation of a domain-policy verdict.
 *
 * Domain and attribution pointers refer to immutable snapshot storage and
 * remain valid until that snapshot is destroyed.
 */
struct jg_policy_match {
    /** Final policy action. */
    enum jg_policy_effect effect;
    /** Whether a rule, rather than the default policy, selected the action. */
    bool matched;
    /** Matching rule identifier, or zero for the default action. */
    uint64_t rule_id;
    /** Matching rule origin, or JG_POLICY_SOURCE_DEFAULT. */
    enum jg_policy_source source;
    /** Matched normalized rule domain, or null for the default action. */
    const char *domain;
    /** Matching rule attribution, or null for the default action. */
    const char *attribution;
};

/**
 * @brief Explanation of a destination-policy verdict.
 *
 * Attribution refers to immutable snapshot storage and remains valid until
 * that snapshot is destroyed.
 */
struct jg_policy_destination_match {
    /** Final policy action. */
    enum jg_policy_effect effect;
    /** Whether a rule, rather than default policy, selected the action. */
    bool matched;
    /** Matching rule identifier, or zero for default policy. */
    uint64_t rule_id;
    /** Matching rule origin, or JG_POLICY_SOURCE_DEFAULT. */
    enum jg_policy_source source;
    /** Matching rule attribution, or null for default policy. */
    const char *attribution;
};

/** Opaque immutable policy snapshot. */
struct jg_policy_snapshot;

/**
 * @brief Build a complete immutable policy snapshot.
 *
 * Domains are normalized, scopes are canonicalized, and identical rules are
 * deduplicated while retaining the lowest identifier. The checksum describes
 * canonical rule content and does not include generation, construction time,
 * or the process-random lookup key.
 *
 * @param[in] rules Input rules, or null when @p rule_count is zero.
 * @param[in] rule_count Number of elements in @p rules.
 * @param[in] generation Nonzero configuration generation.
 * @param[out] snapshot Receives the owned snapshot on success.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid rules, scopes, attribution, or arguments.
 * @return -EOVERFLOW when the packed representation is too large.
 * @return -ENOMEM when allocation fails.
 * @return -EIO when cryptographic initialization fails.
 *
 * @thread_safety Concurrent builds are safe.
 *
 * @side_effects Initializes libsodium and obtains random bytes from the
 * operating system.
 */
JG_PUBLIC int jg_policy_snapshot_build(const struct jg_policy_rule_input *rules,
                                       size_t rule_count,
                                       uint64_t generation,
                                       struct jg_policy_snapshot **snapshot);

/**
 * @brief Build one snapshot containing domain and destination policy.
 *
 * @param[in] rules Domain rules, or null when @p rule_count is zero.
 * @param[in] rule_count Number of domain rules.
 * @param[in] destination_rules Destination rules, or null when
 * @p destination_rule_count is zero.
 * @param[in] destination_rule_count Number of destination rules.
 * @param[in] generation Nonzero configuration generation.
 * @param[out] snapshot Receives the owned snapshot on success.
 *
 * @return 0 on success.
 * @return -EINVAL for invalid rules or arguments.
 * @return -EOVERFLOW when the packed representation is too large.
 * @return -ENOMEM when allocation fails.
 * @return -EIO when cryptographic initialization fails.
 *
 * @thread_safety Concurrent builds are safe.
 */
JG_PUBLIC int jg_policy_snapshot_build_complete(
    const struct jg_policy_rule_input *rules,
    size_t rule_count,
    const struct jg_policy_destination_rule_input *destination_rules,
    size_t destination_rule_count,
    uint64_t generation,
    struct jg_policy_snapshot **snapshot);

/**
 * @brief Destroy a policy snapshot.
 *
 * @param[in,out] snapshot Snapshot to release; null is accepted.
 *
 * @thread_safety Safe only after callers have excluded concurrent readers of
 * the same snapshot.
 */
JG_PUBLIC void jg_policy_snapshot_destroy(struct jg_policy_snapshot *snapshot);

/**
 * @brief Copy metadata from an immutable snapshot.
 *
 * @param[in] snapshot Snapshot to inspect.
 * @param[out] info Destination metadata structure.
 *
 * @return 0 on success.
 * @return -EINVAL for a null argument.
 *
 * @thread_safety Safe for concurrent calls on the same snapshot.
 */
JG_PUBLIC int jg_policy_snapshot_get_info(
    const struct jg_policy_snapshot *snapshot,
    struct jg_policy_snapshot_info *info);

/**
 * @brief Evaluate a normalized domain for one client.
 *
 * The complete domain is checked first, followed by suffixes beginning after
 * each label separator. A null client can match only global rules.
 *
 * @param[in] snapshot Immutable policy snapshot.
 * @param[in] domain Lowercase normalized A-label domain.
 * @param[in] client Client properties, or null when unavailable.
 * @param[out] match Verdict and its explanation.
 *
 * @return 0 on success, including a default-allow verdict.
 * @return -EINVAL for a null argument, malformed domain, or invalid client.
 *
 * @thread_safety Safe for concurrent calls on the same snapshot.
 */
JG_PUBLIC int jg_policy_match_domain(const struct jg_policy_snapshot *snapshot,
                                     const char *domain,
                                     const struct jg_policy_client *client,
                                     struct jg_policy_match *match);

/**
 * @brief Evaluate a visible normalized TLS SNI for one client.
 *
 * Only rules explicitly configured for JG_POLICY_DOMAIN_TLS_SNI participate.
 * DNS rules and imported DNS blocklists remain isolated.
 *
 * @param[in] snapshot Immutable policy snapshot.
 * @param[in] server_name Lowercase normalized visible SNI.
 * @param[in] client Client properties, or null when unavailable.
 * @param[out] match Verdict and its explanation.
 *
 * @return 0 on success, including a default-allow verdict.
 * @return -EINVAL for a null argument, malformed name, or invalid client.
 *
 * @thread_safety Safe for concurrent calls on the same snapshot.
 */
JG_PUBLIC int jg_policy_match_visible_sni(
    const struct jg_policy_snapshot *snapshot,
    const char *server_name,
    const struct jg_policy_client *client,
    struct jg_policy_match *match);

/**
 * @brief Evaluate one destination address, transport, and port.
 *
 * @param[in] snapshot Immutable policy snapshot.
 * @param[in] destination Valid destination properties.
 * @param[in] client Client properties, or null when unavailable.
 * @param[out] match Verdict and its explanation.
 *
 * @return 0 on success, including a default-allow verdict.
 * @return -EINVAL for a null argument or invalid destination or client.
 *
 * @thread_safety Safe for concurrent calls on the same snapshot.
 */
JG_PUBLIC int jg_policy_match_destination(
    const struct jg_policy_snapshot *snapshot,
    const struct jg_policy_destination *destination,
    const struct jg_policy_client *client,
    struct jg_policy_destination_match *match);

#endif
