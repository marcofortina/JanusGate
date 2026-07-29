/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#define _GNU_SOURCE

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#if defined(__OpenBSD__)
#include <ifaddrs.h>
#endif
#include <limits.h>
#include <net/if.h>
#if defined(__OpenBSD__)
#include <net/if_dl.h>
#include <net/if_types.h>
// clang-format off
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_bridge.h>
// clang-format on
#else
#include <net/if_arp.h>
#include <netinet/in.h>
#endif
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "janusgate/account.h"
#include "janusgate/auth.h"
#include "janusgate/backup.h"
#include "janusgate/certificate.h"
#include "janusgate/database.h"
#include "janusgate/domain.h"
#include "janusgate/identity.h"
#include "janusgate/ipc.h"
#include "janusgate/network.h"
#include "janusgate/version.h"

/** Largest accepted setup document in bytes. */
#define SETUP_DOCUMENT_SIZE_MAX 65536U

/** Largest accepted certificate common name. */
#define SETUP_COMMON_NAME_MAX 253U

/** Default persistent database path. */
#define SETUP_DATABASE_PATH "/var/lib/janusgate/janusgate.db"

/** Default appliance-local TOTP key path. */
#define SETUP_TOTP_KEY_PATH "/var/lib/janusgate/totp.key"

/** Parsed setup command options. */
struct setup_options {
    const char *config_path;
    bool confirm_network;
    bool image_build;
    bool validate_only;
    bool dry_run;
    bool disable_services;
    bool help;
    bool version;
};

/** Complete validated non-secret setup configuration. */
struct setup_configuration {
    struct jg_network_config network;
    char certificate_source[PATH_MAX];
    char common_name[SETUP_COMMON_NAME_MAX + 1U];
    char alternative_names[JG_CERTIFICATE_SAN_MAX][JG_DOMAIN_NAME_MAX + 1U];
    size_t alternative_name_count;
    uint32_t validity_days;
    bool enable_services;
};

/** Supported account-management command family. */
enum account_backend {
    ACCOUNT_BACKEND_NONE = 0,
    ACCOUNT_BACKEND_SHADOW,
    ACCOUNT_BACKEND_BUSYBOX,
    ACCOUNT_BACKEND_OPENBSD
};

/** Resolved service account and group identifiers. */
struct service_identities {
    uid_t service_user;
    gid_t service_group;
    uid_t web_user;
    gid_t web_group;
    gid_t control_group;
};

/** @brief Print the stable non-interactive setup synopsis. */
static void print_usage(FILE *output)
{
    (void)fprintf(
        output,
        "usage: janusgate-setup --config FILE "
        "(--confirm-network | --image-build)\n"
        "                       [--dry-run] [--no-enable-services]\n"
        "       janusgate-setup --config FILE --validate-only "
        "[--image-build]\n"
        "       janusgate-setup --version\n"
        "\n"
        "Options:\n"
        "  --config FILE          validated non-interactive setup document\n"
        "  --confirm-network      accept the configured interface roles\n"
        "  --image-build          permit interface names absent on this host\n"
        "  --validate-only        validate without changing the system\n"
        "  --dry-run              print planned actions without changing "
        "state\n"
        "  --no-enable-services   leave installed services disabled\n"
        "  --help                 show this help\n"
        "  --version              show the program version\n");
}

/** @brief Parse exact setup options without positional arguments. */
static int parse_options(int argc, char **argv, struct setup_options *options)
{
    int index = 1;

    (void)memset(options, 0, sizeof(*options));
    while (index < argc) {
        if (strcmp(argv[index], "--config") == 0 && index + 1 < argc &&
            options->config_path == NULL) {
            options->config_path = argv[index + 1];
            index += 2;
        } else if (strcmp(argv[index], "--confirm-network") == 0) {
            options->confirm_network = true;
            ++index;
        } else if (strcmp(argv[index], "--image-build") == 0) {
            options->image_build = true;
            ++index;
        } else if (strcmp(argv[index], "--validate-only") == 0) {
            options->validate_only = true;
            ++index;
        } else if (strcmp(argv[index], "--dry-run") == 0) {
            options->dry_run = true;
            ++index;
        } else if (strcmp(argv[index], "--no-enable-services") == 0) {
            options->disable_services = true;
            ++index;
        } else if (strcmp(argv[index], "--help") == 0) {
            options->help = true;
            ++index;
        } else if (strcmp(argv[index], "--version") == 0) {
            options->version = true;
            ++index;
        } else {
            return -EINVAL;
        }
    }
    if (options->help || options->version) {
        return argc == 2 ? 0 : -EINVAL;
    }
    if (options->config_path == NULL ||
        (options->validate_only && options->dry_run) ||
        (!options->validate_only && !options->dry_run &&
         !options->confirm_network && !options->image_build)) {
        return -EINVAL;
    }
    return 0;
}

/** @brief Read one secure bounded setup document without following links. */
static int read_document(const char *path, char **document, size_t *size)
{
    struct stat metadata;
    size_t offset = 0U;
    int descriptor = -1;
    int result = 0;

    *document = NULL;
    *size = 0U;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
               (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0U) {
        result = -EACCES;
    } else if (metadata.st_size <= 0 ||
               metadata.st_size > (off_t)SETUP_DOCUMENT_SIZE_MAX) {
        result = -EMSGSIZE;
    }
    if (result == 0) {
        *document = malloc((size_t)metadata.st_size + 1U);
        if (*document == NULL) {
            result = -ENOMEM;
        }
    }
    while (result == 0 && offset < (size_t)metadata.st_size) {
        const ssize_t count = read(descriptor, *document + offset,
                                   (size_t)metadata.st_size - offset);

        if (count < 0 && errno != EINTR) {
            result = -errno;
        } else if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            result = -EIO;
        }
    }
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (result == 0) {
        (*document)[offset] = '\0';
        *size = offset;
    } else {
        free(*document);
        *document = NULL;
    }
    return result;
}

/** @brief Reject object members outside one explicit field allowlist. */
static bool fields_allowed(json_t *object,
                           const char *const *fields,
                           size_t field_count)
{
    const char *name = NULL;
    json_t *value = NULL;

    json_object_foreach(object, name, value)
    {
        bool allowed = false;

        (void)value;
        for (size_t index = 0U; index < field_count && !allowed; ++index) {
            allowed = strcmp(name, fields[index]) == 0;
        }
        if (!allowed) {
            return false;
        }
    }
    return true;
}

/** @brief Copy one required bounded JSON string without embedded nulls. */
static bool required_string(const json_t *object,
                            const char *name,
                            size_t minimum,
                            size_t maximum,
                            char *output,
                            size_t output_size)
{
    json_t *value = json_object_get(object, name);
    const char *text = json_string_value(value);
    const size_t size = json_is_string(value) ? json_string_length(value) : 0U;

    if (text == NULL || size < minimum || size > maximum ||
        size >= output_size || strlen(text) != size) {
        return false;
    }
    (void)memcpy(output, text, size + 1U);
    return true;
}

/** @brief Decode one required bounded nonnegative JSON integer. */
static bool required_unsigned(const json_t *object,
                              const char *name,
                              uint64_t maximum,
                              uint64_t *output)
{
    json_t *value = json_object_get(object, name);
    const json_int_t number =
        json_is_integer(value) ? json_integer_value(value) : -1;

    if (number < 0 || (uint64_t)number > maximum) {
        return false;
    }
    *output = (uint64_t)number;
    return true;
}

/** @brief Decode one required JSON boolean. */
static bool required_boolean(const json_t *object,
                             const char *name,
                             bool *output)
{
    json_t *value = json_object_get(object, name);

    if (!json_is_boolean(value)) {
        return false;
    }
    *output = json_is_true(value);
    return true;
}

/** @brief Parse the complete inline-network setup object. */
static int parse_network(json_t *object, struct jg_network_config *network)
{
    static const char *const fields[] = {
        "bridge",
        "ingress",
        "egress",
        "management",
        "bridge_mtu",
        "queue_first",
        "queue_count",
        "queue_length",
        "failure_mode",
        "stp",
        "multicast_snooping",
        "queue_cpu_fanout",
    };
    char failure_mode[16U];
    uint64_t bridge_mtu = 0U;
    uint64_t queue_first = 0U;
    uint64_t queue_count = 0U;
    uint64_t queue_length = 0U;

    (void)memset(network, 0, sizeof(*network));
    if (!json_is_object(object) ||
        json_object_size(object) != sizeof(fields) / sizeof(fields[0U]) ||
        !fields_allowed(object, fields, sizeof(fields) / sizeof(fields[0U])) ||
        !required_string(object, "bridge", 1U, JG_INTERFACE_NAME_MAX,
                         network->bridge, sizeof(network->bridge)) ||
        !required_string(object, "ingress", 1U, JG_INTERFACE_NAME_MAX,
                         network->ingress, sizeof(network->ingress)) ||
        !required_string(object, "egress", 1U, JG_INTERFACE_NAME_MAX,
                         network->egress, sizeof(network->egress)) ||
        !required_string(object, "management", 1U, JG_INTERFACE_NAME_MAX,
                         network->management, sizeof(network->management)) ||
        !required_string(object, "failure_mode", 9U, sizeof(failure_mode) - 1U,
                         failure_mode, sizeof(failure_mode)) ||
        !required_unsigned(object, "bridge_mtu", UINT32_MAX, &bridge_mtu) ||
        !required_unsigned(object, "queue_first", UINT16_MAX, &queue_first) ||
        !required_unsigned(object, "queue_count", UINT16_MAX, &queue_count) ||
        !required_unsigned(object, "queue_length", UINT32_MAX, &queue_length) ||
        !required_boolean(object, "stp", &network->stp) ||
        !required_boolean(object, "multicast_snooping",
                          &network->multicast_snooping) ||
        !required_boolean(object, "queue_cpu_fanout",
                          &network->queue_cpu_fanout)) {
        return -EINVAL;
    }
    if (strcmp(failure_mode, "fail_open") == 0) {
        network->failure_mode = JG_NETWORK_FAIL_OPEN;
    } else if (strcmp(failure_mode, "fail_closed") == 0) {
        network->failure_mode = JG_NETWORK_FAIL_CLOSED;
    } else {
        return -EINVAL;
    }
    network->bridge_mtu = (uint32_t)bridge_mtu;
    network->queue_first = (uint16_t)queue_first;
    network->queue_count = (uint16_t)queue_count;
    network->queue_length = (uint32_t)queue_length;
    return jg_network_config_validate(network);
}

/** @brief Validate one certificate subject name without creating key data. */
static bool certificate_name_valid(const char *name)
{
    const size_t size = strlen(name);

    if (size == 0U || size > SETUP_COMMON_NAME_MAX) {
        return false;
    }
    for (size_t index = 0U; index < size; ++index) {
        const uint8_t character = (uint8_t)name[index];

        if (character < UINT8_C(0x20) || character == UINT8_C(0x7f)) {
            return false;
        }
    }
    return true;
}

/** @brief Validate one DNS or numeric IP certificate alternative name. */
static bool alternative_name_valid(const char *name)
{
    uint8_t address[16U];
    char normalized[JG_DOMAIN_NAME_MAX + 1U];

    return inet_pton(AF_INET, name, address) == 1 ||
           inet_pton(AF_INET6, name, address) == 1 ||
           jg_domain_normalize(name, normalized, sizeof(normalized)) == 0;
}

/** @brief Parse certificate source or local-identity configuration. */
static int parse_certificate(json_t *object,
                             struct setup_configuration *configuration)
{
    static const char *const fields[] = {
        "source",
        "common_name",
        "alternative_names",
        "validity_days",
    };
    json_t *source = NULL;
    json_t *names = NULL;
    uint64_t validity_days = 0U;

    if (!json_is_object(object) ||
        json_object_size(object) != sizeof(fields) / sizeof(fields[0U]) ||
        !fields_allowed(object, fields, sizeof(fields) / sizeof(fields[0U])) ||
        !required_string(object, "common_name", 1U, SETUP_COMMON_NAME_MAX,
                         configuration->common_name,
                         sizeof(configuration->common_name)) ||
        !certificate_name_valid(configuration->common_name) ||
        !required_unsigned(object, "validity_days",
                           JG_CERTIFICATE_VALIDITY_DAYS_MAX, &validity_days) ||
        validity_days == 0U) {
        return -EINVAL;
    }
    source = json_object_get(object, "source");
    if (!json_is_null(source) &&
        !required_string(object, "source", 2U, PATH_MAX - 1U,
                         configuration->certificate_source,
                         sizeof(configuration->certificate_source))) {
        return -EINVAL;
    }
    if (configuration->certificate_source[0U] != '\0' &&
        configuration->certificate_source[0U] != '/') {
        return -EINVAL;
    }
    names = json_object_get(object, "alternative_names");
    if (!json_is_array(names) ||
        json_array_size(names) > JG_CERTIFICATE_SAN_MAX) {
        return -EINVAL;
    }
    configuration->alternative_name_count = json_array_size(names);
    for (size_t index = 0U; index < configuration->alternative_name_count;
         ++index) {
        json_t *name = json_array_get(names, index);
        const char *text = json_string_value(name);
        const size_t size =
            json_is_string(name) ? json_string_length(name) : 0U;

        if (text == NULL || size == 0U || size > JG_DOMAIN_NAME_MAX ||
            strlen(text) != size || !alternative_name_valid(text)) {
            return -EINVAL;
        }
        (void)memcpy(configuration->alternative_names[index], text, size + 1U);
    }
    configuration->validity_days = (uint32_t)validity_days;
    return 0;
}

/** @brief Parse and validate one complete strict setup document. */
static int load_configuration(const char *path,
                              struct setup_configuration *configuration)
{
    static const char *const fields[] = {
        "_license", "_copyright", "network", "certificate", "enable_services",
    };
    char *document = NULL;
    size_t document_size = 0U;
    json_error_t error;
    json_t *root = NULL;
    int result = read_document(path, &document, &document_size);

    (void)memset(configuration, 0, sizeof(*configuration));
    if (result == 0) {
        root =
            json_loadb(document, document_size, JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(root) ||
            !fields_allowed(root, fields,
                            sizeof(fields) / sizeof(fields[0U])) ||
            json_object_get(root, "network") == NULL ||
            json_object_get(root, "certificate") == NULL ||
            !required_boolean(root, "enable_services",
                              &configuration->enable_services)) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        result = parse_network(json_object_get(root, "network"),
                               &configuration->network);
    }
    if (result == 0) {
        result = parse_certificate(json_object_get(root, "certificate"),
                                   configuration);
    }
    json_decref(root);
    free(document);
    return result;
}

/** @brief Verify one existing Ethernet-compatible interface. */
static int validate_interface(int socket_fd, const char *name)
{
    struct ifreq request;

    (void)memset(&request, 0, sizeof(request));
    if (if_nametoindex(name) == 0U ||
        snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name) <= 0) {
        return -ENODEV;
    }
    if (ioctl(socket_fd, SIOCGIFFLAGS, &request) != 0) {
        return -errno;
    }
    if ((request.ifr_flags & IFF_LOOPBACK) != 0) {
        return -EINVAL;
    }
#if defined(__OpenBSD__)
    {
        struct ifaddrs *addresses = NULL;
        struct ifaddrs *current = NULL;
        bool ethernet = false;
        int result = 0;

        if (getifaddrs(&addresses) != 0) {
            return -errno;
        }
        for (current = addresses; current != NULL;
             current = current->ifa_next) {
            struct sockaddr_dl link_address;
            size_t address_size = 0U;

            if (current->ifa_name != NULL && current->ifa_addr != NULL &&
                strcmp(current->ifa_name, name) == 0 &&
                current->ifa_addr->sa_family == AF_LINK) {
                address_size = (size_t)current->ifa_addr->sa_len;
                if (address_size <= sizeof(link_address) &&
                    address_size > offsetof(struct sockaddr_dl, sdl_type)) {
                    (void)memset(&link_address, 0, sizeof(link_address));
                    (void)memcpy(&link_address, current->ifa_addr,
                                 address_size);
                    if (link_address.sdl_type == IFT_ETHER) {
                        ethernet = true;
                        break;
                    }
                }
            }
        }
        freeifaddrs(addresses);
        result = ethernet ? 0 : -EINVAL;
        return result;
    }
#else
    if (ioctl(socket_fd, SIOCGIFHWADDR, &request) != 0) {
        return -errno;
    }
    return request.ifr_hwaddr.sa_family == ARPHRD_ETHER ? 0 : -EINVAL;
#endif
}

/** @brief Validate real interface suitability unless building an image. */
static int validate_interfaces(const struct jg_network_config *network,
                               bool image_build)
{
#if !defined(__OpenBSD__)
    char bridge_path[PATH_MAX];
    struct stat metadata;
#else
    struct ifbifconf request;
#endif
    int socket_fd = -1;
    int result = 0;

    if (image_build) {
        return 0;
    }
    socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return -errno;
    }
    result = validate_interface(socket_fd, network->ingress);
    if (result == 0) {
        result = validate_interface(socket_fd, network->egress);
    }
    if (result == 0) {
        result = validate_interface(socket_fd, network->management);
    }
    if (close(socket_fd) != 0 && result == 0) {
        result = -errno;
    }
    if (result != 0) {
        return result;
    }
    if (if_nametoindex(network->bridge) == 0U) {
        return 0;
    }
#if defined(__OpenBSD__)
    (void)memset(&request, 0, sizeof(request));
    (void)snprintf(request.ifbic_name, sizeof(request.ifbic_name), "%s",
                   network->bridge);
    socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        return -errno;
    }
    result = ioctl(socket_fd, SIOCBRDGIFS, &request) == 0 ? 0 : -EEXIST;
    if (close(socket_fd) != 0 && result == 0) {
        result = -errno;
    }
    return result;
#else
    if (snprintf(bridge_path, sizeof(bridge_path), "/sys/class/net/%s/bridge",
                 network->bridge) <= 0 ||
        stat(bridge_path, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
        return -EEXIST;
    }
    return 0;
#endif
}

/** @brief Return the first executable from two fixed trusted paths. */
static const char *available_tool(const char *first, const char *second)
{
    if (access(first, X_OK) == 0) {
        return first;
    }
    return access(second, X_OK) == 0 ? second : NULL;
}

/** @brief Wait for one account-management child to exit successfully. */
static int wait_for_command(pid_t process)
{
    int status = 0;
    pid_t waited = -1;

    do {
        waited = waitpid(process, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        return -errno;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -ECHILD;
}

/** @brief Execute one trusted group-creation command without a shell. */
static int create_group(enum account_backend backend,
                        const char *tool,
                        const char *name)
{
    pid_t process = fork();

    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        if (backend == ACCOUNT_BACKEND_SHADOW) {
            (void)execl(tool, tool, "--system", name, (char *)NULL);
        } else if (backend == ACCOUNT_BACKEND_OPENBSD) {
            (void)execl(tool, tool, name, (char *)NULL);
        } else {
            (void)execl(tool, tool, "-S", name, (char *)NULL);
        }
        _exit(127);
    }
    return wait_for_command(process);
}

/** @brief Execute one trusted service-user creation command. */
static int create_user(enum account_backend backend,
                       const char *tool,
                       const char *name,
                       const char *group,
                       const char *home,
                       const char *shell)
{
    pid_t process = fork();

    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        if (backend == ACCOUNT_BACKEND_SHADOW) {
            (void)execl(tool, tool, "--system", "--gid", group, "--home-dir",
                        home, "--no-create-home", "--shell", shell, name,
                        (char *)NULL);
        } else if (backend == ACCOUNT_BACKEND_OPENBSD) {
            (void)execl(tool, tool, "-g", group, "-d", home, "-s", shell, name,
                        (char *)NULL);
        } else {
            (void)execl(tool, tool, "-S", "-D", "-H", "-h", home, "-s", shell,
                        "-G", group, name, (char *)NULL);
        }
        _exit(127);
    }
    return wait_for_command(process);
}

/** @brief Execute one trusted supplementary-group update command. */
static int add_group_member(enum account_backend backend,
                            const char *tool,
                            const char *user,
                            const char *group)
{
    pid_t process = fork();

    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        if (backend == ACCOUNT_BACKEND_SHADOW) {
            (void)execl(tool, tool, "--append", "--groups", group, user,
                        (char *)NULL);
        } else if (backend == ACCOUNT_BACKEND_OPENBSD) {
            (void)execl(tool, tool, "-G", group, user, (char *)NULL);
        } else {
            (void)execl(tool, tool, user, group, (char *)NULL);
        }
        _exit(127);
    }
    return wait_for_command(process);
}

/** @brief Detect one complete supported local account toolchain. */
static enum account_backend detect_account_backend(const char **group_tool,
                                                   const char **user_tool,
                                                   const char **member_tool)
{
    *group_tool = available_tool("/usr/sbin/groupadd", "/sbin/groupadd");
    *user_tool = available_tool("/usr/sbin/useradd", "/sbin/useradd");
    *member_tool = available_tool("/usr/sbin/usermod", "/sbin/usermod");
    if (*group_tool != NULL && *user_tool != NULL && *member_tool != NULL) {
#if defined(__OpenBSD__)
        return ACCOUNT_BACKEND_OPENBSD;
#else
        return ACCOUNT_BACKEND_SHADOW;
#endif
    }
#if defined(__OpenBSD__)
    return ACCOUNT_BACKEND_NONE;
#else
    *group_tool = available_tool("/usr/sbin/addgroup", "/sbin/addgroup");
    *user_tool = available_tool("/usr/sbin/adduser", "/sbin/adduser");
    *member_tool = *group_tool;
    return *group_tool != NULL && *user_tool != NULL ? ACCOUNT_BACKEND_BUSYBOX
                                                     : ACCOUNT_BACKEND_NONE;
#endif
}

/** @brief Ensure one non-root system group exists. */
static int ensure_group(enum account_backend backend,
                        const char *tool,
                        const char *name,
                        gid_t *group_id)
{
    const struct group *group = NULL;
    int result = 0;

    errno = 0;
    group = getgrnam(name);
    if (group == NULL) {
        result = errno == 0 ? create_group(backend, tool, name) : -errno;
        if (result == 0) {
            errno = 0;
            group = getgrnam(name);
            if (group == NULL && errno != 0) {
                result = -errno;
            }
        }
    }
    if (result == 0 && (group == NULL || group->gr_gid == 0U)) {
        result = -EACCES;
    }
    if (result == 0) {
        *group_id = group->gr_gid;
    }
    return result;
}

/** @brief Ensure one locked service user has the expected primary group. */
static int ensure_user(enum account_backend backend,
                       const char *tool,
                       const char *name,
                       const char *group,
                       gid_t group_id,
                       const char *home,
                       uid_t *user_id)
{
    const struct passwd *user = NULL;
    const char *shell = available_tool("/usr/sbin/nologin", "/sbin/nologin");
    int result = 0;

    if (shell == NULL) {
        shell = "/bin/false";
    }
    errno = 0;
    user = getpwnam(name);
    if (user == NULL) {
        result = errno == 0
                     ? create_user(backend, tool, name, group, home, shell)
                     : -errno;
        if (result == 0) {
            errno = 0;
            user = getpwnam(name);
            if (user == NULL && errno != 0) {
                result = -errno;
            }
        }
    }
    if (result == 0 &&
        (user == NULL || user->pw_uid == 0U || user->pw_gid != group_id)) {
        result = -EACCES;
    }
    if (result == 0) {
        *user_id = user->pw_uid;
    }
    return result;
}

/** @brief Determine whether one user already belongs to a group. */
static bool group_contains_user(const struct group *group,
                                const char *user,
                                gid_t primary_group)
{
    if (group->gr_gid == primary_group) {
        return true;
    }
    for (char *const *member = group->gr_mem; member != NULL && *member != NULL;
         ++member) {
        if (strcmp(*member, user) == 0) {
            return true;
        }
    }
    return false;
}

/** @brief Ensure one service user can access the local control group. */
static int ensure_group_member(enum account_backend backend,
                               const char *tool,
                               const char *user_name,
                               gid_t primary_group)
{
    const struct group *group = NULL;

    errno = 0;
    group = getgrnam(JG_CONTROL_GROUP);
    if (group == NULL) {
        return errno == 0 ? -ENOENT : -errno;
    }
    return group_contains_user(group, user_name, primary_group)
               ? 0
               : add_group_member(backend, tool, user_name, JG_CONTROL_GROUP);
}

/** @brief Create and resolve all dedicated service identities. */
static int ensure_identities(struct service_identities *identities)
{
    const char *group_tool = NULL;
    const char *user_tool = NULL;
    const char *member_tool = NULL;
    enum account_backend backend =
        detect_account_backend(&group_tool, &user_tool, &member_tool);
    int result = backend == ACCOUNT_BACKEND_NONE ? -ENOTSUP : 0;

    (void)memset(identities, 0, sizeof(*identities));
    if (result == 0) {
        result = ensure_group(backend, group_tool, JG_CONTROL_GROUP,
                              &identities->control_group);
    }
    if (result == 0) {
        result = ensure_group(backend, group_tool, JG_SERVICE_USER,
                              &identities->service_group);
    }
    if (result == 0) {
        result = ensure_group(backend, group_tool, JG_WEB_SERVICE_USER,
                              &identities->web_group);
    }
    if (result == 0) {
        result = ensure_user(backend, user_tool, JG_SERVICE_USER,
                             JG_SERVICE_USER, identities->service_group,
                             "/var/lib/janusgate", &identities->service_user);
    }
    if (result == 0) {
        result = ensure_user(backend, user_tool, JG_WEB_SERVICE_USER,
                             JG_WEB_SERVICE_USER, identities->web_group,
                             "/var/empty", &identities->web_user);
    }
    if (result == 0) {
        result = ensure_group_member(backend, member_tool, JG_SERVICE_USER,
                                     identities->service_group);
    }
    if (result == 0) {
        result = ensure_group_member(backend, member_tool, JG_WEB_SERVICE_USER,
                                     identities->web_group);
    }
    return result;
}

/** @brief Create or normalize one JanusGate-owned directory. */
static int ensure_directory(const char *path,
                            mode_t mode,
                            uid_t owner,
                            gid_t group)
{
    int descriptor = -1;
    int result = 0;

    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        return -errno;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    if (fchown(descriptor, owner, group) != 0 ||
        fchmod(descriptor, mode) != 0) {
        result = -errno;
    }
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** @brief Create the complete private runtime filesystem layout. */
static int ensure_directories(const struct service_identities *identities)
{
    int result =
        ensure_directory("/etc/janusgate", 0750, 0U, identities->control_group);

    if (result == 0) {
        result = ensure_directory("/etc/janusgate/certs", 0750,
                                  identities->service_user,
                                  identities->control_group);
    }
    if (result == 0) {
        result = ensure_directory("/var/lib/janusgate", 0750,
                                  identities->service_user,
                                  identities->service_group);
    }
    if (result == 0) {
        result = ensure_directory(JG_BACKUP_DEFAULT_DIRECTORY, 0700,
                                  identities->service_user,
                                  identities->service_group);
    }
    if (result == 0) {
        result = ensure_directory("/var/log/janusgate", 0750,
                                  identities->service_user,
                                  identities->service_group);
    }
    if (result == 0) {
        result = ensure_directory(JG_RUNTIME_DIRECTORY, 0750, 0U,
                                  identities->control_group);
    }
    if (result == 0) {
        result = ensure_directory(JG_CONTROL_RUNTIME_DIRECTORY, 0750,
                                  identities->service_user,
                                  identities->control_group);
    }
    return result;
}

/** @brief Write all bytes while retrying interrupted writes. */
static int write_exact(int descriptor, const uint8_t *data, size_t size)
{
    size_t offset = 0U;

    while (offset < size) {
        const ssize_t written = write(descriptor, data + offset, size - offset);

        if (written < 0 && errno != EINTR) {
            return -errno;
        }
        if (written == 0) {
            return -EIO;
        }
        if (written > 0) {
            offset += (size_t)written;
        }
    }
    return 0;
}

/** @brief Create or validate the appliance-local TOTP protection key. */
static int ensure_totp_key(const struct service_identities *identities)
{
    uint8_t key[JG_AUTH_TOTP_KEY_SIZE];
    struct stat metadata;
    bool created = false;
    int descriptor =
        open(SETUP_TOTP_KEY_PATH,
             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    int result = 0;

    if (descriptor < 0 && errno != EEXIST) {
        return -errno;
    }
    if (descriptor >= 0) {
        created = true;
        randombytes_buf(key, sizeof(key));
        if (fchown(descriptor, identities->service_user,
                   identities->service_group) != 0 ||
            fchmod(descriptor, 0600) != 0) {
            result = -errno;
        }
        if (result == 0) {
            result = write_exact(descriptor, key, sizeof(key));
        }
        if (result == 0 && fsync(descriptor) != 0) {
            result = -errno;
        }
        if (close(descriptor) != 0 && result == 0) {
            result = -errno;
        }
        sodium_memzero(key, sizeof(key));
    } else if (lstat(SETUP_TOTP_KEY_PATH, &metadata) != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) ||
               metadata.st_uid != identities->service_user ||
               metadata.st_gid != identities->service_group ||
               (metadata.st_mode & 0777) != 0600 ||
               metadata.st_size != (off_t)JG_AUTH_TOTP_KEY_SIZE) {
        result = -EACCES;
    }
    if (created && result != 0) {
        (void)unlink(SETUP_TOTP_KEY_PATH);
    }
    return result;
}

/** @brief Compare two validated network configurations canonically. */
static bool network_equal(const struct jg_network_config *left,
                          const struct jg_network_config *right)
{
    uint8_t left_data[JG_NETWORK_CONFIG_WIRE_SIZE];
    uint8_t right_data[JG_NETWORK_CONFIG_WIRE_SIZE];
    size_t left_size = 0U;
    size_t right_size = 0U;

    return jg_network_config_encode(left, left_data, sizeof(left_data),
                                    &left_size) == 0 &&
           jg_network_config_encode(right, right_data, sizeof(right_data),
                                    &right_size) == 0 &&
           left_size == right_size &&
           sodium_memcmp(left_data, right_data, left_size) == 0;
}

/** @brief Initialize persistent schema, network roles, and bootstrap access. */
static int initialize_database(const struct setup_configuration *configuration,
                               const struct service_identities *identities,
                               char bootstrap[JG_AUTH_SECRET_TEXT_SIZE])
{
    struct jg_database *database = NULL;
    struct jg_network_config existing;
    struct jg_account_user user;
    struct stat metadata;
    uint64_t total = 0U;
    size_t count = 0U;
    bool created = false;
    time_t now = time(NULL);
    int result = lstat(SETUP_DATABASE_PATH, &metadata);

    bootstrap[0U] = '\0';
    if (result != 0 && errno == ENOENT) {
        created = true;
        result = 0;
    } else if (result != 0) {
        result = -errno;
    } else if (!S_ISREG(metadata.st_mode) ||
               metadata.st_uid != identities->service_user ||
               (metadata.st_mode & 0777) != 0600) {
        result = -EACCES;
    }
    if (result == 0 && now <= 0) {
        result = -EIO;
    }
    if (result == 0) {
        result = jg_database_open(SETUP_DATABASE_PATH, 5000U, &database);
    }
    if (result == 0) {
        result = jg_database_load_network_config(database, &existing);
        if (result == -ENOENT) {
            result = jg_database_store_network_config(database,
                                                      &configuration->network);
        } else if (result == 0 &&
                   !network_equal(&existing, &configuration->network)) {
            result = -EEXIST;
        }
    }
    if (result == 0) {
        result = jg_database_check_integrity(database);
    }
    if (result == 0) {
        result = jg_account_user_list(database, 0U, &user, 1U, &count, &total);
    }
    if (result == 0 && total == 0U) {
        result = jg_account_bootstrap_issue(database, (uint64_t)now,
                                            JG_ACCOUNT_BOOTSTRAP_LIFETIME_MAX,
                                            bootstrap);
    }
    jg_database_close(database);
    if (result == 0 && (chown(SETUP_DATABASE_PATH, identities->service_user,
                              identities->service_group) != 0 ||
                        chmod(SETUP_DATABASE_PATH, 0600) != 0)) {
        result = -errno;
    }
    if (created && result != 0) {
        (void)unlink(SETUP_DATABASE_PATH);
    }
    return result;
}

/** @brief Locate the private-key portion of one combined PEM identity. */
static char *find_private_key(char *pem)
{
    static const char *const markers[] = {
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    };
    char *first = NULL;

    for (size_t index = 0U; index < sizeof(markers) / sizeof(markers[0U]);
         ++index) {
        char *candidate = strstr(pem, markers[index]);

        if (candidate != NULL && (first == NULL || candidate < first)) {
            first = candidate;
        }
    }
    return first;
}

/** @brief Inspect one service-group-readable certificate as that group. */
static int inspect_shared_certificate(gid_t control_group)
{
    struct jg_certificate_info info;
    gid_t original_group = getegid();
    int result = setegid(control_group) == 0 ? 0 : -errno;

    if (result == 0) {
        result =
            jg_certificate_inspect_file(JG_CERTIFICATE_DEFAULT_PATH, &info);
    }
    if (setegid(original_group) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** @brief Install an administrator identity or create a local certificate. */
static int ensure_certificate(const struct setup_configuration *configuration,
                              const struct service_identities *identities)
{
    struct stat metadata;
    struct jg_certificate_material material;
    struct jg_certificate_info info;
    const char *names[JG_CERTIFICATE_SAN_MAX];
    char *imported = NULL;
    char *private_key = NULL;
    size_t imported_size = 0U;
    size_t public_size = 0U;
    bool created = false;
    int result = lstat(JG_CERTIFICATE_DEFAULT_PATH, &metadata);

    if (result == 0) {
        if (!S_ISREG(metadata.st_mode) ||
            metadata.st_uid != identities->service_user ||
            metadata.st_gid != identities->control_group ||
            (metadata.st_mode & 0777) != 0640) {
            return -EACCES;
        }
        return inspect_shared_certificate(identities->control_group);
    }
    if (errno != ENOENT) {
        return -errno;
    }
    created = true;
    (void)memset(&material, 0, sizeof(material));
    for (size_t index = 0U; index < configuration->alternative_name_count;
         ++index) {
        names[index] = configuration->alternative_names[index];
    }
    if (configuration->certificate_source[0U] != '\0') {
        result = jg_certificate_export_file(configuration->certificate_source,
                                            true, &imported, &imported_size);
        if (result == 0) {
            private_key = find_private_key(imported);
            if (private_key == NULL) {
                result = -EINVAL;
            } else {
                public_size = (size_t)(private_key - imported);
                result = jg_certificate_install(
                    JG_CERTIFICATE_DEFAULT_PATH, imported, public_size,
                    private_key, imported_size - public_size, &info);
            }
        }
    } else {
        result = jg_certificate_create_self_signed(
            configuration->common_name, names,
            configuration->alternative_name_count, configuration->validity_days,
            &material);
        if (result == 0) {
            result = jg_certificate_install(
                JG_CERTIFICATE_DEFAULT_PATH, material.certificate,
                material.certificate_size, material.private_key,
                material.private_key_size, &info);
        }
    }
    if (result == 0 &&
        (chown(JG_CERTIFICATE_DEFAULT_PATH, identities->service_user,
               identities->control_group) != 0 ||
         chmod(JG_CERTIFICATE_DEFAULT_PATH, 0640) != 0)) {
        result = -errno;
    }
    if (result == 0) {
        result = inspect_shared_certificate(identities->control_group);
    }
    if (created && result != 0) {
        (void)unlink(JG_CERTIFICATE_DEFAULT_PATH);
    }
    jg_certificate_pem_clear(imported, imported_size);
    jg_certificate_material_clear(&material);
    return result;
}

#if !defined(__OpenBSD__)
/** @brief Enable all services through systemd without starting them. */
static int enable_systemd_services(const char *tool)
{
    pid_t process = fork();

    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        (void)execl(tool, tool, "enable", "janusgate-netd.service",
                    "janusgated.service", "janusgate-web.service",
                    (char *)NULL);
        _exit(127);
    }
    return wait_for_command(process);
}

/** @brief Enable one OpenRC service in the default runlevel. */
static int enable_openrc_service(const char *tool, const char *service)
{
    pid_t process = fork();

    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        (void)execl(tool, tool, "add", service, "default", (char *)NULL);
        _exit(127);
    }
    return wait_for_command(process);
}

#else
/** @brief Enable OpenBSD services in their required startup order. */
static int enable_openbsd_services(const char *tool)
{
    pid_t process = fork();
    int result = 0;

    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        (void)execl(tool, tool, "enable", "janusgate_netd", "janusgated",
                    "janusgate_web", (char *)NULL);
        _exit(127);
    }
    result = wait_for_command(process);
    if (result != 0) {
        return result;
    }
    process = fork();
    if (process < 0) {
        return -errno;
    }
    if (process == 0) {
        (void)execl(tool, tool, "order", "janusgate_netd", "janusgated",
                    "janusgate_web", (char *)NULL);
        _exit(127);
    }
    return wait_for_command(process);
}
#endif

/** @brief Enable installed services through the active init system. */
static int enable_services(void)
{
#if defined(__OpenBSD__)
    const char *rcctl = available_tool("/usr/sbin/rcctl", "/sbin/rcctl");

    return rcctl == NULL ? -ENOTSUP : enable_openbsd_services(rcctl);
#else
    const char *systemctl =
        available_tool("/usr/bin/systemctl", "/bin/systemctl");
    const char *rc_update =
        available_tool("/sbin/rc-update", "/usr/sbin/rc-update");
    int result = 0;

    if (systemctl != NULL && access("/run/systemd/system", F_OK) == 0) {
        return enable_systemd_services(systemctl);
    }
    if (rc_update == NULL) {
        return -ENOTSUP;
    }
    result = enable_openrc_service(rc_update, "janusgate-netd");
    if (result == 0) {
        result = enable_openrc_service(rc_update, "janusgated");
    }
    if (result == 0) {
        result = enable_openrc_service(rc_update, "janusgate-web");
    }
    return result;
#endif
}

/** @brief Print the exact setup plan without changing system state. */
static void print_plan(const struct setup_configuration *configuration,
                       bool enable)
{
    (void)printf("Network roles:\n");
    (void)printf("  ingress:   %s\n", configuration->network.ingress);
    (void)printf("  egress:    %s\n", configuration->network.egress);
    (void)printf("  management:%s\n", configuration->network.management);
    (void)printf("  bridge:    %s\n", configuration->network.bridge);
    (void)printf("Planned actions:\n");
    (void)printf("  create or validate service identities and private paths\n");
    (void)printf(
        "  initialize persistent configuration and bootstrap access\n");
    (void)printf("  install or validate the HTTPS server identity\n");
    (void)printf("  services: %s\n",
                 enable ? "enable at boot" : "leave disabled");
    (void)printf("No interface or service will be activated by setup.\n");
}

/** @brief Run the complete idempotent first-boot setup transaction. */
static int apply_setup(const struct setup_configuration *configuration,
                       bool enable,
                       char bootstrap[JG_AUTH_SECRET_TEXT_SIZE])
{
    struct service_identities identities;
    int result = ensure_identities(&identities);

    if (result == 0) {
        result = ensure_directories(&identities);
    }
    if (result == 0) {
        result = ensure_totp_key(&identities);
    }
    if (result == 0) {
        result = ensure_certificate(configuration, &identities);
    }
    if (result == 0) {
        result = initialize_database(configuration, &identities, bootstrap);
    }
    if (result == 0 && enable) {
        result = enable_services();
    }
    return result;
}

/** @brief Run JanusGate non-interactive installation and first-boot setup. */
int main(int argc, char **argv)
{
    struct setup_options options;
    struct setup_configuration configuration;
    char bootstrap[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    bool enable = false;
    int result = parse_options(argc, argv, &options);

    if (result != 0) {
        print_usage(stderr);
        return 2;
    }
    if (options.help) {
        print_usage(stdout);
        return 0;
    }
    if (options.version) {
        (void)printf("janusgate-setup %s\n", jg_version_string());
        return 0;
    }
    (void)umask(0077);
    result = load_configuration(options.config_path, &configuration);
    if (result == 0) {
        result =
            validate_interfaces(&configuration.network, options.image_build);
    }
    if (result != 0) {
        (void)fprintf(stderr, "janusgate-setup: configuration: %s\n",
                      strerror(-result));
        return 1;
    }
    enable = configuration.enable_services && !options.disable_services;
    if (options.validate_only) {
        (void)puts("JanusGate setup configuration is valid.");
        return 0;
    }
    if (options.dry_run) {
        print_plan(&configuration, enable);
        return 0;
    }
    if (geteuid() != 0U) {
        (void)fprintf(stderr, "janusgate-setup must run as root\n");
        return 1;
    }
    if (!options.image_build && getenv("SSH_CONNECTION") != NULL) {
        (void)fprintf(
            stderr, "janusgate-setup: warning: verify that the management role "
                    "preserves this SSH path before enabling services\n");
    }
    result = apply_setup(&configuration, enable, bootstrap);
    if (result != 0) {
        sodium_memzero(bootstrap, sizeof(bootstrap));
        (void)fprintf(stderr, "janusgate-setup: %s\n", strerror(-result));
        return 1;
    }
    (void)puts("JanusGate setup completed. Services were not started.");
    if (bootstrap[0U] != '\0') {
        (void)printf("One-time bootstrap credential: %s\n", bootstrap);
        (void)puts("The credential expires in 24 hours.");
    } else {
        (void)puts("An administrator already exists; no bootstrap credential "
                   "was issued.");
    }
    sodium_memzero(bootstrap, sizeof(bootstrap));
    return 0;
}
