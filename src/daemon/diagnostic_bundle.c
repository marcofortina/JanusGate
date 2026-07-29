/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#if defined(__OpenBSD__)
#define _BSD_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "diagnostic_bundle.h"

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__OpenBSD__)
#include <sys/sysctl.h>
#include <sys/time.h>
#else
#include <sys/sysinfo.h>
#include <sys/timex.h>
#endif
#include <sys/utsname.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>

#include <curl/curlver.h>
#include <idn2.h>
#include <jansson.h>
#include <openssl/opensslv.h>
#include <sodium/version.h>
#include <sqlite3.h>
#include <zlib.h>

#include "janusgate/diagnostic.h"
#include "janusgate/event.h"
#include "janusgate/network.h"
#include "janusgate/version.h"
#include "netd_client.h"

/** Number of recent severe operational events retained in a bundle. */
#define DIAGNOSTIC_EVENT_COUNT 20U

/** Maximum fixed operating-system release file bytes. */
#define DIAGNOSTIC_OS_RELEASE_SIZE_MAX 16384U

/** Number of JSON documents in the current bundle. */
#define DIAGNOSTIC_DOCUMENT_COUNT 7U

/** One JSON document retained until archive compression completes. */
struct diagnostic_document {
    const char *name;
    json_t *value;
    char *encoded;
};

/** Non-secret operating-system resource and clock status. */
struct diagnostic_resources {
    uint64_t uptime_seconds;
    uint64_t total_memory_bytes;
    uint64_t free_memory_bytes;
    uint64_t process_count;
    bool ntp_available;
    bool ntp_synchronized;
};

/** @brief Set one representable unsigned counter on a JSON object. */
static int set_counter(json_t *object, const char *name, uint64_t value)
{
    if (value > (uint64_t)INT64_MAX) {
        return -EOVERFLOW;
    }
    return json_object_set_new(object, name, json_integer((json_int_t)value)) ==
                   0
               ? 0
               : -ENOMEM;
}

/** @brief Return the stable name for one network failure mode. */
static const char *failure_mode_name(enum jg_network_failure_mode mode)
{
    return mode == JG_NETWORK_FAIL_OPEN ? "open" : "closed";
}

/** @brief Serialize one validated inline-network configuration. */
static json_t *network_configuration_json(
    const struct jg_network_config *config)
{
    json_t *object = json_object();

    if (object == NULL ||
        json_object_set_new(object, "bridge", json_string(config->bridge)) !=
            0 ||
        json_object_set_new(object, "ingress", json_string(config->ingress)) !=
            0 ||
        json_object_set_new(object, "egress", json_string(config->egress)) !=
            0 ||
        json_object_set_new(object, "management",
                            json_string(config->management)) != 0 ||
        json_object_set_new(object, "bridge_mtu",
                            json_integer((json_int_t)config->bridge_mtu)) !=
            0 ||
        json_object_set_new(object, "queue_first",
                            json_integer((json_int_t)config->queue_first)) !=
            0 ||
        json_object_set_new(object, "queue_count",
                            json_integer((json_int_t)config->queue_count)) !=
            0 ||
        json_object_set_new(object, "queue_length",
                            json_integer((json_int_t)config->queue_length)) !=
            0 ||
        json_object_set_new(
            object, "failure_mode",
            json_string(failure_mode_name(config->failure_mode))) != 0 ||
        json_object_set_new(object, "stp", json_boolean(config->stp)) != 0 ||
        json_object_set_new(object, "multicast_snooping",
                            json_boolean(config->multicast_snooping)) != 0 ||
        json_object_set_new(object, "queue_cpu_fanout",
                            json_boolean(config->queue_cpu_fanout)) != 0) {
        json_decref(object);
        return NULL;
    }
    return object;
}

/** @brief Return the stable name for one blocked DNS response action. */
static const char *dns_action_name(enum jg_dns_block_action action)
{
    switch (action) {
    case JG_DNS_BLOCK_DROP:
        return "drop";
    case JG_DNS_BLOCK_REFUSED:
        return "refused";
    case JG_DNS_BLOCK_NXDOMAIN:
        return "nxdomain";
    case JG_DNS_BLOCK_SINKHOLE:
        return "sinkhole";
    default:
        return NULL;
    }
}

/** @brief Serialize non-secret blocked DNS response configuration. */
static json_t *dns_configuration_json(
    const struct jg_dns_response_config *config)
{
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
    const char *action = dns_action_name(config->action);
    json_t *object = json_object();
    json_t *ipv4_value = NULL;
    json_t *ipv6_value = NULL;

    if (config->has_ipv4_sinkhole) {
        ipv4_value = inet_ntop(AF_INET, config->ipv4_sinkhole, ipv4,
                               sizeof(ipv4)) == NULL
                         ? NULL
                         : json_string(ipv4);
    } else {
        ipv4_value = json_null();
    }
    if (config->has_ipv6_sinkhole) {
        ipv6_value = inet_ntop(AF_INET6, config->ipv6_sinkhole, ipv6,
                               sizeof(ipv6)) == NULL
                         ? NULL
                         : json_string(ipv6);
    } else {
        ipv6_value = json_null();
    }
    if (action == NULL || object == NULL || ipv4_value == NULL ||
        ipv6_value == NULL ||
        json_object_set_new(object, "action", json_string(action)) != 0 ||
        json_object_set(object, "ipv4_sinkhole", ipv4_value) != 0 ||
        json_object_set(object, "ipv6_sinkhole", ipv6_value) != 0 ||
        json_object_set_new(object, "checksum_ipv4_udp",
                            json_boolean(config->checksum_ipv4_udp)) != 0 ||
        json_object_set_new(object, "sinkhole_ttl",
                            json_integer((json_int_t)config->sinkhole_ttl)) !=
            0) {
        json_decref(ipv6_value);
        json_decref(ipv4_value);
        json_decref(object);
        return NULL;
    }
    json_decref(ipv6_value);
    json_decref(ipv4_value);
    return object;
}

/** @brief Collect sanitized persistent network and DNS configuration. */
static json_t *configuration_document(struct jg_database *database)
{
    struct jg_database_network_config network;
    struct jg_dns_response_config dns;
    json_t *object = NULL;
    json_t *network_value = NULL;
    json_t *dns_value = NULL;
    int result = jg_database_load_network_config_record(database, &network);

    jg_dns_response_config_default(&dns);
    if (result == 0) {
        result = jg_database_load_dns_response_config(database, &dns);
        if (result == -ENOENT) {
            result = 0;
        }
    }
    if (result != 0) {
        return NULL;
    }
    object = json_object();
    network_value = network_configuration_json(&network.config);
    dns_value = dns_configuration_json(&dns);
    if (object == NULL || network_value == NULL || dns_value == NULL ||
        json_object_set_new(object, "network_revision",
                            json_integer((json_int_t)network.revision)) != 0 ||
        json_object_set(object, "network", network_value) != 0 ||
        json_object_set(object, "dns_response", dns_value) != 0 ||
        json_object_set_new(object, "sensitive_values_included",
                            json_false()) != 0) {
        json_decref(dns_value);
        json_decref(network_value);
        json_decref(object);
        return NULL;
    }
    json_decref(dns_value);
    json_decref(network_value);
    return object;
}

/** @brief Serialize one kernel interface identity without addresses. */
static json_t *interface_json(const char *name, const char *role)
{
    unsigned int index = if_nametoindex(name);
    json_t *object = json_object();

    if (object == NULL ||
        json_object_set_new(object, "name", json_string(name)) != 0 ||
        json_object_set_new(object, "role", json_string(role)) != 0 ||
        json_object_set_new(object, "present", json_boolean(index != 0U)) !=
            0 ||
        json_object_set_new(
            object, "index",
            index == 0U ? json_null() : json_integer((json_int_t)index)) != 0) {
        json_decref(object);
        return NULL;
    }
    return object;
}

/** @brief Append effective interface identities for one confirmed state. */
static int append_interfaces(json_t *array,
                             const struct jg_network_config *config)
{
    static const char *const roles[] = {
        "bridge",
        "data_ingress",
        "data_egress",
        "management",
    };
    const char *const names[] = {
        config->bridge,
        config->ingress,
        config->egress,
        config->management,
    };

    for (size_t index = 0U; index < sizeof(names) / sizeof(names[0U]);
         ++index) {
        json_t *interface = interface_json(names[index], roles[index]);

        if (interface == NULL || json_array_append_new(array, interface) != 0) {
            return -ENOMEM;
        }
    }
    return 0;
}

/** @brief Describe the fixed JanusGate-owned packet-filter semantics. */
static json_t *packet_filter_json(const struct jg_network_config *config)
{
#if defined(__OpenBSD__)
    static const char *const rules[] = {
        "UDP and TCP destination port 53 enter inspection",
        "UDP and TCP destination port 853 enter inspection",
        "UDP and TCP destination port 443 enter encrypted DNS inspection",
        "all remaining ingress traffic remains in the kernel path",
    };
    const char *backend = "pf";
    const char *scope = "anchor";
    const char *ownership = "JanusGate owned anchor";
    const char *hook = "ingress quick no state";
#else
    static const char *const rules[] = {
        "IPv4 and IPv6 fragments enter the first stateful queue",
        "configured destination address sets enter the balanced queue range",
        "known encrypted DNS endpoint sets enter the balanced queue range",
        "UDP and TCP destination port 53 enter the balanced queue range",
        "UDP and TCP destination port 853 enter inspection",
        "UDP and TCP destination port 443 enter encrypted DNS inspection",
        "all remaining ingress traffic is accepted",
    };
    const char *backend = "nftables";
    const char *scope = "table";
    const char *ownership = "JanusGate owned table";
    const char *hook = "prerouting priority -300 policy accept";
#endif
    json_t *object = json_object();
    json_t *items = json_array();
    uint32_t queue_last =
        (uint32_t)config->queue_first + (uint32_t)config->queue_count - 1U;
    int result = 0;

    for (size_t index = 0U; result == 0 && items != NULL &&
                            index < sizeof(rules) / sizeof(rules[0U]);
         ++index) {
        if (json_array_append_new(items, json_string(rules[index])) != 0) {
            result = -ENOMEM;
        }
    }
    if (object == NULL || items == NULL || result != 0) {
        json_decref(items);
        json_decref(object);
        return NULL;
    }
    if (json_object_set_new(object, "backend", json_string(backend)) != 0 ||
        json_object_set_new(object, "scope", json_string(scope)) != 0 ||
        json_object_set_new(object, "name", json_string("janusgate")) != 0 ||
        json_object_set_new(object, "ownership", json_string(ownership)) != 0 ||
        json_object_set_new(object, "hook", json_string(hook)) != 0 ||
        json_object_set_new(object, "queue_first",
                            json_integer((json_int_t)config->queue_first)) !=
            0 ||
        json_object_set_new(object, "queue_last",
                            json_integer((json_int_t)queue_last)) != 0 ||
        json_object_set_new(
            object, "failure_mode",
            json_string(failure_mode_name(config->failure_mode))) != 0 ||
        json_object_set(object, "rules", items) != 0) {
        json_decref(items);
        json_decref(object);
        return NULL;
    }
    json_decref(items);
    return object;
}

/** @brief Collect confirmed helper state and effective interface identities. */
static json_t *network_document(void)
{
    struct jg_network_state state;
    json_t *object = json_object();
    json_t *confirmed = NULL;
    json_t *pending = NULL;
    json_t *interfaces = json_array();
    json_t *packet_filter = NULL;
    int state_result = jg_netd_client_state(&state);
    int result = 0;

    if (object == NULL || interfaces == NULL) {
        json_decref(interfaces);
        json_decref(object);
        return NULL;
    }
    if (state_result == 0 && state.has_confirmed) {
        confirmed = network_configuration_json(&state.confirmed);
        packet_filter = packet_filter_json(&state.confirmed);
        result = append_interfaces(interfaces, &state.confirmed);
    } else {
        confirmed = json_null();
        packet_filter = json_null();
    }
    pending = state_result == 0 && state.pending
                  ? network_configuration_json(&state.pending_config)
                  : json_null();
    if (confirmed == NULL || pending == NULL || packet_filter == NULL ||
        result != 0 ||
        json_object_set_new(object, "helper_available",
                            json_boolean(state_result == 0)) != 0 ||
        json_object_set(object, "confirmed", confirmed) != 0 ||
        json_object_set(object, "pending", pending) != 0 ||
        json_object_set_new(
            object, "confirmation_seconds_remaining",
            json_integer((json_int_t)(state_result == 0
                                          ? state.confirmation_seconds_remaining
                                          : 0U))) != 0 ||
        json_object_set(object, "interfaces", interfaces) != 0 ||
        json_object_set(object, "packet_filter", packet_filter) != 0) {
        json_decref(packet_filter);
        json_decref(interfaces);
        json_decref(pending);
        json_decref(confirmed);
        json_decref(object);
        return NULL;
    }
    json_decref(packet_filter);
    json_decref(interfaces);
    json_decref(pending);
    json_decref(confirmed);
    return object;
}

/** @brief Extract one unescaped bounded field from the fixed OS release file.
 */
static void read_os_release_value(const char *data,
                                  const char *name,
                                  char *value,
                                  size_t value_size)
{
    const size_t name_size = strlen(name);
    const char *line = data;

    value[0U] = '\0';
    while (*line != '\0') {
        const char *end = strchr(line, '\n');
        size_t line_size = end == NULL ? strlen(line) : (size_t)(end - line);

        if (line_size > name_size + 1U && memcmp(line, name, name_size) == 0 &&
            line[name_size] == '=') {
            const char *start = line + name_size + 1U;
            size_t length = line_size - name_size - 1U;

            if (length >= 2U && start[0U] == '"' && start[length - 1U] == '"') {
                ++start;
                length -= 2U;
            }
            if (length < value_size) {
                (void)memcpy(value, start, length);
                value[length] = '\0';
            }
            return;
        }
        line = end == NULL ? line + line_size : end + 1;
    }
}

/** @brief Read selected non-secret identity fields from `/etc/os-release`. */
static json_t *os_release_json(void)
{
    char data[DIAGNOSTIC_OS_RELEASE_SIZE_MAX + 1U];
    char pretty_name[256U];
    char identifier[64U];
    char version[64U];
    struct stat metadata;
    json_t *object = json_object();
    size_t size = 0U;
    int descriptor = open("/etc/os-release", O_RDONLY | O_CLOEXEC);
    int result = 0;

    if (descriptor < 0) {
        result = -errno;
    } else if (fstat(descriptor, &metadata) != 0 ||
               !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
               metadata.st_size > (off_t)DIAGNOSTIC_OS_RELEASE_SIZE_MAX) {
        result = -EIO;
    }
    while (result == 0 && size < (size_t)metadata.st_size) {
        const ssize_t count =
            read(descriptor, data + size, (size_t)metadata.st_size - size);

        if (count < 0 && errno != EINTR) {
            result = -errno;
        } else if (count > 0) {
            size += (size_t)count;
        } else if (count == 0) {
            result = -EIO;
        }
    }
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0) {
        data[size] = '\0';
        read_os_release_value(data, "PRETTY_NAME", pretty_name,
                              sizeof(pretty_name));
        read_os_release_value(data, "ID", identifier, sizeof(identifier));
        read_os_release_value(data, "VERSION_ID", version, sizeof(version));
    } else {
        pretty_name[0U] = '\0';
        identifier[0U] = '\0';
        version[0U] = '\0';
    }
    if (object == NULL ||
        json_object_set_new(object, "available", json_boolean(result == 0)) !=
            0 ||
        json_object_set_new(object, "pretty_name",
                            pretty_name[0U] == '\0'
                                ? json_null()
                                : json_string(pretty_name)) != 0 ||
        json_object_set_new(object, "id",
                            identifier[0U] == '\0'
                                ? json_null()
                                : json_string(identifier)) != 0 ||
        json_object_set_new(object, "version_id",
                            version[0U] == '\0' ? json_null()
                                                : json_string(version)) != 0) {
        json_decref(object);
        return NULL;
    }
    return object;
}

#if defined(__OpenBSD__)
/** @brief Read one fixed-size OpenBSD sysctl value. */
static int read_sysctl(const int name[2U], void *value, size_t value_size)
{
    size_t actual_size = value_size;

    if (sysctl(name, 2U, value, &actual_size, NULL, 0U) != 0) {
        return -errno;
    }
    return actual_size == value_size ? 0 : -EIO;
}

/** @brief Collect OpenBSD resource counters without spawning utilities. */
static int collect_system_resources(struct diagnostic_resources *resources)
{
    const int boot_name[2U] = {CTL_KERN, KERN_BOOTTIME};
    const int memory_name[2U] = {CTL_HW, HW_PHYSMEM64};
    const int process_name[2U] = {CTL_KERN, KERN_NPROCS};
    const int virtual_memory_name[2U] = {CTL_VM, VM_UVMEXP};
    struct timeval boot_time;
    struct timeval current_time;
    struct uvmexp virtual_memory;
    int process_count = 0;
    int64_t total_memory = 0;
    int result = 0;

    (void)memset(resources, 0, sizeof(*resources));
    (void)memset(&boot_time, 0, sizeof(boot_time));
    (void)memset(&virtual_memory, 0, sizeof(virtual_memory));
    result = read_sysctl(boot_name, &boot_time, sizeof(boot_time));
    if (result == 0) {
        result = read_sysctl(memory_name, &total_memory, sizeof(total_memory));
    }
    if (result == 0) {
        result =
            read_sysctl(process_name, &process_count, sizeof(process_count));
    }
    if (result == 0) {
        result = read_sysctl(virtual_memory_name, &virtual_memory,
                             sizeof(virtual_memory));
    }
    if (result == 0 && gettimeofday(&current_time, NULL) != 0) {
        result = -errno;
    }
    if (result == 0 &&
        (boot_time.tv_sec < 0 || current_time.tv_sec < boot_time.tv_sec ||
         total_memory < 0 || process_count < 0 || virtual_memory.pagesize < 0 ||
         virtual_memory.free < 0)) {
        result = -EIO;
    }
    if (result == 0) {
        resources->uptime_seconds =
            (uint64_t)(current_time.tv_sec - boot_time.tv_sec);
        resources->total_memory_bytes = (uint64_t)total_memory;
        resources->free_memory_bytes =
            (uint64_t)(unsigned)virtual_memory.free *
            (uint64_t)(unsigned)virtual_memory.pagesize;
        resources->process_count = (uint64_t)(unsigned)process_count;
    }
    return result;
}
#else
/** @brief Convert one sysinfo memory value to bytes with saturation. */
static uint64_t memory_bytes(unsigned long value, unsigned int unit)
{
    return unit != 0U && (uint64_t)value > UINT64_MAX / (uint64_t)unit
               ? UINT64_MAX
               : (uint64_t)value * (uint64_t)unit;
}

/** @brief Collect Linux resource counters and kernel clock status. */
static int collect_system_resources(struct diagnostic_resources *resources)
{
    struct sysinfo system_resources;
    struct timex clock_state;
    int ntp_result = 0;

    (void)memset(resources, 0, sizeof(*resources));
    (void)memset(&system_resources, 0, sizeof(system_resources));
    (void)memset(&clock_state, 0, sizeof(clock_state));
    if (sysinfo(&system_resources) != 0) {
        return -errno;
    }
    resources->uptime_seconds =
        system_resources.uptime > 0 ? (uint64_t)system_resources.uptime : 0U;
    resources->total_memory_bytes =
        memory_bytes(system_resources.totalram, system_resources.mem_unit);
    resources->free_memory_bytes =
        memory_bytes(system_resources.freeram, system_resources.mem_unit);
    resources->process_count = (uint64_t)system_resources.procs;
    ntp_result = adjtimex(&clock_state);
    resources->ntp_available = ntp_result >= 0;
    resources->ntp_synchronized =
        ntp_result >= 0 && (clock_state.status & STA_UNSYNC) == 0;
    return 0;
}
#endif

/** @brief Collect build, dependency, kernel, resource, time, and service data.
 */
static json_t *system_document(uint64_t created_at)
{
    struct utsname kernel;
    struct diagnostic_resources resources;
    json_t *object = json_object();
    json_t *build = json_object();
    json_t *dependencies = json_object();
    json_t *kernel_value = json_object();
    json_t *resource_value = json_object();
    json_t *time_value = json_object();
    json_t *services = json_object();
    json_t *os_release = os_release_json();
    struct jg_network_state network;
    int kernel_result = uname(&kernel);
    int resource_result = collect_system_resources(&resources);
    int network_result = jg_netd_client_state(&network);
    int result = 0;

    if (object == NULL || build == NULL || dependencies == NULL ||
        kernel_value == NULL || resource_value == NULL || time_value == NULL ||
        services == NULL || os_release == NULL) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(build, "version",
                             json_string(jg_version_string())) != 0 ||
         json_object_set_new(build, "commit", json_string(jg_build_commit())) !=
             0 ||
         json_object_set_new(build, "timestamp",
                             json_string(jg_build_timestamp())) != 0 ||
         json_object_set_new(build, "compiler",
                             json_string(jg_build_compiler())) != 0 ||
         json_object_set_new(build, "target", json_string(jg_build_target())) !=
             0 ||
         json_object_set_new(dependencies, "openssl",
                             json_string(OPENSSL_VERSION_TEXT)) != 0 ||
         json_object_set_new(dependencies, "sqlite",
                             json_string(SQLITE_VERSION)) != 0 ||
         json_object_set_new(dependencies, "libsodium",
                             json_string(SODIUM_VERSION_STRING)) != 0 ||
         json_object_set_new(dependencies, "jansson",
                             json_string(JANSSON_VERSION)) != 0 ||
         json_object_set_new(dependencies, "libcurl",
                             json_string(LIBCURL_VERSION)) != 0 ||
         json_object_set_new(dependencies, "libidn2",
                             json_string(IDN2_VERSION)) != 0 ||
         json_object_set_new(dependencies, "zlib", json_string(ZLIB_VERSION)) !=
             0)) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(kernel_value, "available",
                             json_boolean(kernel_result == 0)) != 0 ||
         json_object_set_new(kernel_value, "name",
                             kernel_result == 0 ? json_string(kernel.sysname)
                                                : json_null()) != 0 ||
         json_object_set_new(kernel_value, "release",
                             kernel_result == 0 ? json_string(kernel.release)
                                                : json_null()) != 0 ||
         json_object_set_new(kernel_value, "machine",
                             kernel_result == 0 ? json_string(kernel.machine)
                                                : json_null()) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set_new(resource_value, "available",
                             json_boolean(resource_result == 0)) != 0 ||
         set_counter(resource_value, "uptime_seconds",
                     resource_result == 0 ? resources.uptime_seconds : 0U) !=
             0 ||
         set_counter(resource_value, "total_memory_bytes",
                     resource_result == 0 ? resources.total_memory_bytes
                                          : 0U) != 0 ||
         set_counter(resource_value, "free_memory_bytes",
                     resource_result == 0 ? resources.free_memory_bytes : 0U) !=
             0 ||
         set_counter(resource_value, "process_count",
                     resource_result == 0 ? resources.process_count : 0U) !=
             0)) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (set_counter(time_value, "unix_seconds", created_at) != 0 ||
         json_object_set_new(time_value, "ntp_available",
                             json_boolean(resources.ntp_available)) != 0 ||
         json_object_set_new(time_value, "ntp_synchronized",
                             json_boolean(resources.ntp_synchronized)) != 0 ||
         json_object_set_new(services, "janusgated", json_string("running")) !=
             0 ||
         json_object_set_new(
             services, "janusgate-netd",
             json_string(network_result == 0 ? "running" : "unavailable")) !=
             0 ||
         json_object_set_new(services, "janusgate-web",
                             json_string("unknown")) != 0)) {
        result = -ENOMEM;
    }
    if (result == 0 &&
        (json_object_set(object, "build", build) != 0 ||
         json_object_set(object, "dependencies", dependencies) != 0 ||
         json_object_set(object, "kernel", kernel_value) != 0 ||
         json_object_set(object, "os_image", os_release) != 0 ||
         json_object_set(object, "resources", resource_value) != 0 ||
         json_object_set(object, "time", time_value) != 0 ||
         json_object_set(object, "services", services) != 0)) {
        result = -ENOMEM;
    }
    json_decref(services);
    json_decref(time_value);
    json_decref(resource_value);
    json_decref(kernel_value);
    json_decref(os_release);
    json_decref(dependencies);
    json_decref(build);
    if (result != 0) {
        json_decref(object);
        return NULL;
    }
    return object;
}

/** @brief Return the stable name for one severe event level. */
static const char *event_severity_name(enum jg_event_severity severity)
{
    return severity == JG_EVENT_SEVERITY_CRITICAL ? "critical" : "error";
}

/** @brief Collect recent severe operational events without detail payloads. */
static json_t *events_document(struct jg_database *database)
{
    struct jg_event_record records[DIAGNOSTIC_EVENT_COUNT];
    json_t *object = json_object();
    json_t *items = json_array();
    size_t count = 0U;
    int result = jg_database_event_list_recent_errors(
        database, records, DIAGNOSTIC_EVENT_COUNT, &count);

    if (result == 0 && (object == NULL || items == NULL)) {
        result = -ENOMEM;
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        json_t *item = json_object();

        if (item == NULL || set_counter(item, "id", records[index].id) != 0 ||
            set_counter(item, "occurred_at", records[index].occurred_at) != 0 ||
            json_object_set_new(item, "severity",
                                json_string(event_severity_name(
                                    records[index].severity))) != 0 ||
            json_object_set_new(item, "component",
                                json_string(records[index].component)) != 0 ||
            json_object_set_new(item, "code",
                                json_string(records[index].code)) != 0 ||
            json_object_set_new(item, "message",
                                json_string(records[index].message)) != 0) {
            json_decref(item);
            result = -ENOMEM;
        } else if (json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    if (object == NULL || items == NULL || result != 0 ||
        json_object_set_new(object, "details_included", json_false()) != 0 ||
        json_object_set_new(object, "count", json_integer((json_int_t)count)) !=
            0 ||
        json_object_set(object, "events", items) != 0) {
        json_decref(items);
        json_decref(object);
        return NULL;
    }
    json_decref(items);
    return object;
}

/** @brief Serialize a complete queue and parser counter snapshot. */
static json_t *counters_document(const struct jg_daemon_runtime *runtime)
{
    struct jg_daemon_runtime_stats stats;
    json_t *object = json_object();
    json_t *queues = json_object();
    json_t *dataplane = json_object();
    json_t *fragments = json_object();
    json_t *streams = json_object();
    json_t *output = json_object();
    int result = jg_daemon_runtime_get_stats(runtime, &stats);

    if (result == 0 &&
        (object == NULL || queues == NULL || dataplane == NULL ||
         fragments == NULL || streams == NULL || output == NULL)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result =
            set_counter(object, "policy_generation", stats.policy_generation);
    }
#define JG_SET_COUNTER(group, field, value)                                    \
    do {                                                                       \
        if (result == 0) {                                                     \
            result = set_counter((group), (field), (value));                   \
        }                                                                      \
    } while (0)
    JG_SET_COUNTER(queues, "packets", stats.queues.packets);
    JG_SET_COUNTER(queues, "accepted", stats.queues.accepted);
    JG_SET_COUNTER(queues, "dropped", stats.queues.dropped);
    JG_SET_COUNTER(queues, "malformed", stats.queues.malformed);
    JG_SET_COUNTER(queues, "overflows", stats.queues.overflows);
    JG_SET_COUNTER(queues, "message_errors", stats.queues.message_errors);
    JG_SET_COUNTER(queues, "verdict_errors", stats.queues.verdict_errors);
    JG_SET_COUNTER(dataplane, "packets", stats.dataplane.packets);
    JG_SET_COUNTER(dataplane, "accepted", stats.dataplane.accepted);
    JG_SET_COUNTER(dataplane, "blocked", stats.dataplane.blocked);
    JG_SET_COUNTER(dataplane, "malformed", stats.dataplane.malformed);
    JG_SET_COUNTER(dataplane, "internal_errors",
                   stats.dataplane.internal_errors);
    JG_SET_COUNTER(dataplane, "dns_dropped", stats.dataplane.dns_dropped);
    JG_SET_COUNTER(dataplane, "dns_refused", stats.dataplane.dns_refused);
    JG_SET_COUNTER(dataplane, "dns_nxdomain", stats.dataplane.dns_nxdomain);
    JG_SET_COUNTER(dataplane, "dns_sinkholed", stats.dataplane.dns_sinkholed);
    JG_SET_COUNTER(dataplane, "sni_inspected", stats.dataplane.sni_inspected);
    JG_SET_COUNTER(dataplane, "sni_encrypted_or_unavailable",
                   stats.dataplane.sni_encrypted_or_unavailable);
    JG_SET_COUNTER(fragments, "stored", stats.fragments.stored);
    JG_SET_COUNTER(fragments, "duplicates", stats.fragments.duplicates);
    JG_SET_COUNTER(fragments, "completed", stats.fragments.completed);
    JG_SET_COUNTER(fragments, "malformed", stats.fragments.malformed);
    JG_SET_COUNTER(fragments, "overlaps", stats.fragments.overlaps);
    JG_SET_COUNTER(fragments, "exhausted", stats.fragments.exhausted);
    JG_SET_COUNTER(fragments, "timeouts", stats.fragments.timeouts);
    JG_SET_COUNTER(streams, "buffered", stats.tcp_streams.buffered);
    JG_SET_COUNTER(streams, "duplicates", stats.tcp_streams.duplicates);
    JG_SET_COUNTER(streams, "messages", stats.tcp_streams.messages);
    JG_SET_COUNTER(streams, "closed", stats.tcp_streams.closed);
    JG_SET_COUNTER(streams, "malformed", stats.tcp_streams.malformed);
    JG_SET_COUNTER(streams, "conflicts", stats.tcp_streams.conflicts);
    JG_SET_COUNTER(streams, "exhausted", stats.tcp_streams.exhausted);
    JG_SET_COUNTER(streams, "timeouts", stats.tcp_streams.timeouts);
    JG_SET_COUNTER(output, "sent", stats.output.sent);
    JG_SET_COUNTER(output, "errors", stats.output.errors);
#undef JG_SET_COUNTER
    if (object == NULL || queues == NULL || dataplane == NULL ||
        fragments == NULL || streams == NULL || output == NULL || result != 0 ||
        json_object_set(object, "queues", queues) != 0 ||
        json_object_set(object, "dataplane", dataplane) != 0 ||
        json_object_set(object, "fragments", fragments) != 0 ||
        json_object_set(object, "tcp_streams", streams) != 0 ||
        json_object_set(object, "output", output) != 0) {
        json_decref(output);
        json_decref(streams);
        json_decref(fragments);
        json_decref(dataplane);
        json_decref(queues);
        json_decref(object);
        return NULL;
    }
    json_decref(output);
    json_decref(streams);
    json_decref(fragments);
    json_decref(dataplane);
    json_decref(queues);
    return object;
}

/** @brief Return a stable blocklist health name. */
static const char *blocklist_health_name(
    enum jg_database_blocklist_health health)
{
    switch (health) {
    case JG_DATABASE_BLOCKLIST_UNKNOWN:
        return "unknown";
    case JG_DATABASE_BLOCKLIST_HEALTHY:
        return "healthy";
    case JG_DATABASE_BLOCKLIST_DEGRADED:
        return "degraded";
    case JG_DATABASE_BLOCKLIST_FAILED:
        return "failed";
    default:
        return NULL;
    }
}

/** @brief Collect database integrity and bounded blocklist source health. */
static json_t *health_document(struct jg_database *database)
{
    struct jg_database_blocklist_source *sources =
        calloc(JG_DATABASE_POLICY_PAGE_MAX, sizeof(*sources));
    json_t *object = json_object();
    json_t *database_value = json_object();
    json_t *blocklists = json_object();
    json_t *items = json_array();
    uint32_t schema_version = 0U;
    size_t count = 0U;
    bool has_more = false;
    int integrity_result = jg_database_check_integrity(database);
    int result = jg_database_schema_version(database, &schema_version);

    if (result == 0 &&
        (sources == NULL || object == NULL || database_value == NULL ||
         blocklists == NULL || items == NULL)) {
        result = -ENOMEM;
    }
    if (result == 0) {
        result = jg_database_list_blocklist_sources(database, 0U,
                                                    JG_DATABASE_POLICY_PAGE_MAX,
                                                    sources, &count, &has_more);
    }
    for (size_t index = 0U; result == 0 && index < count; ++index) {
        const char *health = blocklist_health_name(sources[index].health);
        json_t *item = json_object();

        if (health == NULL || item == NULL ||
            set_counter(item, "id", sources[index].id) != 0 ||
            json_object_set_new(item, "name",
                                json_string(sources[index].name)) != 0 ||
            json_object_set_new(item, "enabled",
                                json_boolean(sources[index].enabled)) != 0 ||
            json_object_set_new(item, "health", json_string(health)) != 0 ||
            set_counter(item, "last_attempt_at",
                        sources[index].last_attempt_at) != 0 ||
            set_counter(item, "last_success_at",
                        sources[index].last_success_at) != 0 ||
            set_counter(item, "active_entries",
                        (uint64_t)sources[index].active_entries) != 0 ||
            set_counter(item, "rejected_entries",
                        (uint64_t)sources[index].rejected_entries) != 0 ||
            json_object_set_new(
                item, "has_error",
                json_boolean(sources[index].last_error[0U] != '\0')) != 0) {
            json_decref(item);
            result = -ENOMEM;
        } else if (json_array_append_new(items, item) != 0) {
            result = -ENOMEM;
        }
    }
    free(sources);
    if (object == NULL || database_value == NULL || blocklists == NULL ||
        items == NULL || result != 0 ||
        json_object_set_new(database_value, "schema_version",
                            json_integer((json_int_t)schema_version)) != 0 ||
        json_object_set_new(
            database_value, "integrity",
            json_string(integrity_result == 0 ? "ok" : "failed")) != 0 ||
        json_object_set_new(blocklists, "count",
                            json_integer((json_int_t)count)) != 0 ||
        json_object_set_new(blocklists, "truncated", json_boolean(has_more)) !=
            0 ||
        json_object_set(blocklists, "sources", items) != 0 ||
        json_object_set(object, "database", database_value) != 0 ||
        json_object_set(object, "blocklists", blocklists) != 0) {
        json_decref(items);
        json_decref(blocklists);
        json_decref(database_value);
        json_decref(object);
        return NULL;
    }
    json_decref(items);
    json_decref(blocklists);
    json_decref(database_value);
    return object;
}

/** @brief Append fixed manifest text values to one JSON array. */
static int append_manifest_values(json_t *array,
                                  const char *const *values,
                                  size_t value_count)
{
    for (size_t index = 0U; index < value_count; ++index) {
        if (json_array_append_new(array, json_string(values[index])) != 0) {
            return -ENOMEM;
        }
    }
    return 0;
}

/** @brief Build the explicit diagnostic inclusion and exclusion manifest. */
static json_t *manifest_document(uint64_t created_at)
{
    static const char *const included[] = {
        "manifest.json", "configuration.json", "network.json", "system.json",
        "events.json",   "counters.json",      "health.json",
    };
    static const char *const excluded[] = {
        "passwords and password hashes",
        "API tokens and sessions",
        "private keys",
        "TOTP secrets and recovery codes",
        "full query logs",
        "event detail payloads",
        "unrelated system files",
    };
    json_t *object = json_object();
    json_t *included_values = json_array();
    json_t *excluded_values = json_array();
    int result =
        included_values == NULL || excluded_values == NULL ? -ENOMEM : 0;

    if (result == 0) {
        result = append_manifest_values(
            included_values, included, sizeof(included) / sizeof(included[0U]));
    }
    if (result == 0) {
        result = append_manifest_values(
            excluded_values, excluded, sizeof(excluded) / sizeof(excluded[0U]));
    }
    if (object == NULL || included_values == NULL || excluded_values == NULL ||
        result != 0 ||
        json_object_set_new(object, "format_version", json_integer(1)) != 0 ||
        set_counter(object, "created_at", created_at) != 0 ||
        json_object_set_new(object, "selection",
                            json_string("explicit_allowlist")) != 0 ||
        json_object_set(object, "included", included_values) != 0 ||
        json_object_set(object, "excluded", excluded_values) != 0) {
        json_decref(excluded_values);
        json_decref(included_values);
        json_decref(object);
        return NULL;
    }
    json_decref(excluded_values);
    json_decref(included_values);
    return object;
}

/** @brief Serialize and release all diagnostic JSON documents. */
static void clear_documents(struct diagnostic_document *documents,
                            size_t document_count)
{
    for (size_t index = 0U; index < document_count; ++index) {
        free(documents[index].encoded);
        json_decref(documents[index].value);
    }
}

/** @brief Serialize selected JSON documents into diagnostic archive entries. */
static int create_archive(struct diagnostic_document *documents,
                          size_t document_count,
                          uint64_t created_at,
                          uint8_t **archive,
                          size_t *archive_size)
{
    struct jg_diagnostic_entry entries[DIAGNOSTIC_DOCUMENT_COUNT];
    int result = 0;

    for (size_t index = 0U; result == 0 && index < document_count; ++index) {
        if (documents[index].value == NULL) {
            result = -EIO;
        } else {
            documents[index].encoded = json_dumps(
                documents[index].value, JSON_COMPACT | JSON_SORT_KEYS);
            if (documents[index].encoded == NULL) {
                result = -ENOMEM;
            } else {
                entries[index] = (struct jg_diagnostic_entry){
                    .name = documents[index].name,
                    .data = (const uint8_t *)documents[index].encoded,
                    .size = strlen(documents[index].encoded),
                };
            }
        }
    }
    if (result == 0) {
        result = jg_diagnostic_archive_create(
            entries, document_count, created_at, archive, archive_size);
    }
    return result;
}

/** @brief Collect one complete sanitized appliance diagnostic archive. */
int jg_diagnostic_bundle_create(struct jg_database *database,
                                const struct jg_daemon_runtime *runtime,
                                uint64_t created_at,
                                uint8_t **archive,
                                size_t *archive_size)
{
    struct diagnostic_document documents[DIAGNOSTIC_DOCUMENT_COUNT] = {
        {.name = "manifest.json"}, {.name = "configuration.json"},
        {.name = "network.json"},  {.name = "system.json"},
        {.name = "events.json"},   {.name = "counters.json"},
        {.name = "health.json"},
    };
    int result = 0;

    if (database == NULL || runtime == NULL || created_at == 0U ||
        archive == NULL || archive_size == NULL) {
        return -EINVAL;
    }
    *archive = NULL;
    *archive_size = 0U;
    documents[0U].value = manifest_document(created_at);
    documents[1U].value = configuration_document(database);
    documents[2U].value = network_document();
    documents[3U].value = system_document(created_at);
    documents[4U].value = events_document(database);
    documents[5U].value = counters_document(runtime);
    documents[6U].value = health_document(database);
    result = create_archive(documents, DIAGNOSTIC_DOCUMENT_COUNT, created_at,
                            archive, archive_size);
    clear_documents(documents, DIAGNOSTIC_DOCUMENT_COUNT);
    return result;
}
