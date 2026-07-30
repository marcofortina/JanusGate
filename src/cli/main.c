/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "client.h"
#include "janusgate/backup.h"
#include "janusgate/ipc.h"
#include "janusgate/ipc_client.h"
#include "janusgate/version.h"

/** Successful command completion. */
#define CLI_EXIT_SUCCESS 0

/** Transport, protocol, or generic API failure. */
#define CLI_EXIT_FAILURE 1

/** Invalid command-line usage. */
#define CLI_EXIT_USAGE 2

/** Authentication or authorization failure. */
#define CLI_EXIT_AUTH 3

/** Revision or transaction conflict. */
#define CLI_EXIT_CONFLICT 4

/** Required service is unhealthy or unavailable. */
#define CLI_EXIT_UNAVAILABLE 5

/** Parsed process-wide command options. */
struct cli_options {
    const char *socket_path;
    const char *endpoint;
    const char *token_file;
    const char *passphrase_file;
    const char *client_certificate;
    const char *client_key;
    const char *ca_file;
    unsigned timeout_seconds;
    bool socket_set;
    bool json;
    bool quiet;
    bool verbose;
    bool yes;
    bool include_private_key;
    bool help;
    bool version;
};

/** Long-option values kept outside the unsigned-character range. */
enum cli_option {
    CLI_OPTION_SOCKET = 256,
    CLI_OPTION_ENDPOINT,
    CLI_OPTION_TOKEN_FILE,
    CLI_OPTION_PASSPHRASE_FILE,
    CLI_OPTION_CLIENT_CERTIFICATE,
    CLI_OPTION_CLIENT_KEY,
    CLI_OPTION_CA_FILE,
    CLI_OPTION_JSON,
    CLI_OPTION_TIMEOUT,
    CLI_OPTION_QUIET,
    CLI_OPTION_VERBOSE,
    CLI_OPTION_YES,
    CLI_OPTION_INCLUDE_PRIVATE_KEY,
    CLI_OPTION_VERSION,
    CLI_OPTION_HELP
};

/** @brief Print the stable command synopsis. */
static void print_usage(FILE *output)
{
    (void)fprintf(
        output,
        "usage: janusgatectl [OPTIONS] status\n"
        "       janusgatectl [OPTIONS] health\n"
        "       janusgatectl [OPTIONS] stats\n"
        "       janusgatectl [OPTIONS] network show\n"
        "       janusgatectl [OPTIONS] network validate FILE\n"
        "       janusgatectl [OPTIONS] network apply FILE\n"
        "       janusgatectl [OPTIONS] network set FILE\n"
        "       janusgatectl [OPTIONS] network confirm\n"
        "       janusgatectl [OPTIONS] network rollback\n"
        "       janusgatectl [OPTIONS] policy list\n"
        "       janusgatectl [OPTIONS] policy show KIND ID\n"
        "       janusgatectl [OPTIONS] policy add KIND FILE\n"
        "       janusgatectl [OPTIONS] policy update KIND ID FILE\n"
        "       janusgatectl [OPTIONS] policy remove KIND ID\n"
        "       janusgatectl [OPTIONS] policy simulate FILE\n"
        "       janusgatectl [OPTIONS] domain block DOMAIN\n"
        "       janusgatectl [OPTIONS] domain allow DOMAIN\n"
        "       janusgatectl [OPTIONS] domain remove ID\n"
        "       janusgatectl [OPTIONS] blocklist list\n"
        "       janusgatectl [OPTIONS] blocklist import SOURCE FILE\n"
        "       janusgatectl [OPTIONS] blocklist export\n"
        "       janusgatectl [OPTIONS] source list\n"
        "       janusgatectl [OPTIONS] source add FILE\n"
        "       janusgatectl [OPTIONS] source update ID FILE\n"
        "       janusgatectl [OPTIONS] source refresh ID\n"
        "       janusgatectl [OPTIONS] source enable ID\n"
        "       janusgatectl [OPTIONS] source disable ID\n"
        "       janusgatectl [OPTIONS] events [QUERY]\n"
        "       janusgatectl [OPTIONS] audit [QUERY]\n"
        "       janusgatectl [OPTIONS] audit verify\n"
        "       janusgatectl [OPTIONS] user list\n"
        "       janusgatectl [OPTIONS] user add FILE\n"
        "       janusgatectl [OPTIONS] user update ID FILE\n"
        "       janusgatectl [OPTIONS] user disable ID\n"
        "       janusgatectl [OPTIONS] user password ID FILE\n"
        "       janusgatectl [OPTIONS] user totp ID\n"
        "       janusgatectl [OPTIONS] token list\n"
        "       janusgatectl [OPTIONS] token create FILE\n"
        "       janusgatectl [OPTIONS] token revoke ID\n"
        "       janusgatectl [OPTIONS] certificate show\n"
        "       janusgatectl [OPTIONS] certificate install FILE\n"
        "       janusgatectl [OPTIONS] certificate csr FILE\n"
        "       janusgatectl [OPTIONS] backup create configuration\n"
        "       janusgatectl [OPTIONS] backup create full\n"
        "       janusgatectl [OPTIONS] backup inspect ID\n"
        "       janusgatectl [OPTIONS] backup restore ID\n"
        "       janusgatectl [OPTIONS] diagnostics create\n"
        "       janusgatectl [OPTIONS] logging show\n"
        "       janusgatectl [OPTIONS] logging set FILE\n"
        "       janusgatectl [OPTIONS] logging traces\n"
        "       janusgatectl [OPTIONS] config validate\n"
        "       janusgatectl [OPTIONS] config reload\n"
        "       janusgatectl [OPTIONS] service restart\n"
        "       janusgatectl [OPTIONS] system reboot\n"
        "       janusgatectl [OPTIONS] system shutdown\n"
        "       janusgatectl [--socket PATH] [--json] ping\n"
        "       janusgatectl [--socket PATH] [--json] policy reload\n"
        "       janusgatectl --version\n"
        "\n"
        "Transport options:\n"
        "  --socket PATH       local control socket\n"
        "  --endpoint URL      remote HTTPS management origin\n"
        "  --token-file PATH   private file containing one API token\n"
        "  --passphrase-file PATH\n"
        "                      private full-backup passphrase file\n"
        "  --client-cert PATH  optional mTLS client certificate\n"
        "  --client-key PATH   optional mTLS client private key\n"
        "  --ca-file PATH      optional PEM trust-anchor file\n"
        "  --timeout SECONDS   remote request timeout (1-300)\n"
        "\n"
        "Output options:\n"
        "  --json              stable compact JSON output\n"
        "  --quiet             suppress successful output\n"
        "  --verbose           report transport and request details\n"
        "  --yes               confirm destructive operations\n"
        "  --include-private-key\n"
        "                      include the server key in a full backup\n"
        "  --help              show this help\n"
        "  --version           show the program version\n");
}

/** @brief Parse one bounded positive decimal option. */
static int parse_timeout(const char *text, unsigned *timeout_seconds)
{
    char *end = NULL;
    unsigned long value = 0UL;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0UL ||
        value > JG_CLI_REMOTE_TIMEOUT_MAX) {
        return -EINVAL;
    }
    *timeout_seconds = (unsigned)value;
    return 0;
}

/** @brief Parse one nonzero decimal resource identifier. */
static int parse_identifier(const char *text, uint64_t *identifier)
{
    char *end = NULL;
    unsigned long long value = 0ULL;

    if (text == NULL || identifier == NULL) {
        return -EINVAL;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0ULL) {
        return -EINVAL;
    }
    *identifier = (uint64_t)value;
    return 0;
}

/** @brief Initialize deterministic CLI defaults. */
static void options_default(struct cli_options *options)
{
    *options = (struct cli_options){
        .socket_path = JG_CONTROL_SOCKET_PATH,
        .timeout_seconds = JG_CLI_REMOTE_TIMEOUT_DEFAULT,
    };
}

/** @brief Parse and cross-validate process-wide options. */
static int parse_options(int argc,
                         char **argv,
                         struct cli_options *options,
                         int *command_index)
{
    static const struct option long_options[] = {
        {"socket", required_argument, NULL, CLI_OPTION_SOCKET},
        {"endpoint", required_argument, NULL, CLI_OPTION_ENDPOINT},
        {"token-file", required_argument, NULL, CLI_OPTION_TOKEN_FILE},
        {"passphrase-file", required_argument, NULL,
         CLI_OPTION_PASSPHRASE_FILE},
        {"client-cert", required_argument, NULL, CLI_OPTION_CLIENT_CERTIFICATE},
        {"client-key", required_argument, NULL, CLI_OPTION_CLIENT_KEY},
        {"ca-file", required_argument, NULL, CLI_OPTION_CA_FILE},
        {"json", no_argument, NULL, CLI_OPTION_JSON},
        {"timeout", required_argument, NULL, CLI_OPTION_TIMEOUT},
        {"quiet", no_argument, NULL, CLI_OPTION_QUIET},
        {"verbose", no_argument, NULL, CLI_OPTION_VERBOSE},
        {"yes", no_argument, NULL, CLI_OPTION_YES},
        {"include-private-key", no_argument, NULL,
         CLI_OPTION_INCLUDE_PRIVATE_KEY},
        {"version", no_argument, NULL, CLI_OPTION_VERSION},
        {"help", no_argument, NULL, CLI_OPTION_HELP},
        {NULL, 0, NULL, 0},
    };
    int result = 0;
    int option = 0;

    opterr = 0;
    while (result == 0 &&
           (option = getopt_long(argc, argv, "+", long_options, NULL)) != -1) {
        switch (option) {
        case CLI_OPTION_SOCKET:
            if (options->socket_set) {
                result = -EINVAL;
            } else {
                options->socket_path = optarg;
                options->socket_set = true;
            }
            break;
        case CLI_OPTION_ENDPOINT:
            if (options->endpoint != NULL) {
                result = -EINVAL;
            } else {
                options->endpoint = optarg;
            }
            break;
        case CLI_OPTION_TOKEN_FILE:
            if (options->token_file != NULL) {
                result = -EINVAL;
            } else {
                options->token_file = optarg;
            }
            break;
        case CLI_OPTION_PASSPHRASE_FILE:
            if (options->passphrase_file != NULL) {
                result = -EINVAL;
            } else {
                options->passphrase_file = optarg;
            }
            break;
        case CLI_OPTION_CLIENT_CERTIFICATE:
            if (options->client_certificate != NULL) {
                result = -EINVAL;
            } else {
                options->client_certificate = optarg;
            }
            break;
        case CLI_OPTION_CLIENT_KEY:
            if (options->client_key != NULL) {
                result = -EINVAL;
            } else {
                options->client_key = optarg;
            }
            break;
        case CLI_OPTION_CA_FILE:
            if (options->ca_file != NULL) {
                result = -EINVAL;
            } else {
                options->ca_file = optarg;
            }
            break;
        case CLI_OPTION_JSON:
            options->json = true;
            break;
        case CLI_OPTION_TIMEOUT:
            result = parse_timeout(optarg, &options->timeout_seconds);
            break;
        case CLI_OPTION_QUIET:
            options->quiet = true;
            break;
        case CLI_OPTION_VERBOSE:
            options->verbose = true;
            break;
        case CLI_OPTION_YES:
            options->yes = true;
            break;
        case CLI_OPTION_INCLUDE_PRIVATE_KEY:
            options->include_private_key = true;
            break;
        case CLI_OPTION_VERSION:
            options->version = true;
            break;
        case CLI_OPTION_HELP:
            options->help = true;
            break;
        default:
            result = -EINVAL;
            break;
        }
    }
    if (result == 0 &&
        ((options->socket_set && options->endpoint != NULL) ||
         (options->quiet && options->verbose) ||
         ((options->client_certificate != NULL || options->client_key != NULL ||
           options->ca_file != NULL) &&
          options->endpoint == NULL) ||
         ((options->client_certificate == NULL) !=
          (options->client_key == NULL)))) {
        result = -EINVAL;
    }
    *command_index = optind;
    return result;
}

/** @brief Read one complete private token file without following symlinks. */
static int read_token_file(const char *path,
                           char token[JG_AUTH_SECRET_TEXT_SIZE])
{
    uint8_t data[JG_AUTH_SECRET_TEXT_SIZE + 1U];
    struct stat status;
    size_t size = 0U;
    ssize_t count = 0;
    int descriptor = -1;
    int result = 0;

    if (path == NULL || path[0U] != '/') {
        return -EINVAL;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &status) != 0) {
        result = -errno;
    } else if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
               (status.st_mode & (S_IRWXG | S_IRWXO | S_IXUSR)) != 0U ||
               (status.st_mode & S_IRUSR) == 0U ||
               status.st_size < (off_t)(JG_AUTH_SECRET_TEXT_SIZE - 1U) ||
               status.st_size > (off_t)JG_AUTH_SECRET_TEXT_SIZE) {
        result = -EACCES;
    }
    while (result == 0 && size < sizeof(data)) {
        count = read(descriptor, data + size, sizeof(data) - size);
        if (count < 0) {
            if (errno != EINTR) {
                result = -errno;
            }
        } else if (count == 0) {
            break;
        } else {
            size += (size_t)count;
        }
    }
    if (result == 0 &&
        !((size == JG_AUTH_SECRET_TEXT_SIZE - 1U) ||
          (size == JG_AUTH_SECRET_TEXT_SIZE &&
           data[JG_AUTH_SECRET_TEXT_SIZE - 1U] == (uint8_t)'\n'))) {
        result = -EINVAL;
    }
    if (result == 0) {
        (void)memcpy(token, data, JG_AUTH_SECRET_TEXT_SIZE - 1U);
        token[JG_AUTH_SECRET_TEXT_SIZE - 1U] = '\0';
    }
    sodium_memzero(data, sizeof(data));
    (void)close(descriptor);
    return result;
}

/** @brief Read one bounded passphrase from a private regular file. */
static int read_passphrase_file(const char *path,
                                char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U],
                                size_t *passphrase_size)
{
    uint8_t data[JG_BACKUP_PASSPHRASE_MAX + 2U];
    struct stat status;
    size_t size = 0U;
    int descriptor = -1;
    int result = 0;

    *passphrase_size = 0U;
    if (path == NULL || path[0U] != '/') {
        return -EINVAL;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -errno;
    }
    if (fstat(descriptor, &status) != 0) {
        result = -errno;
    } else if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
               (status.st_mode & (S_IRWXG | S_IRWXO | S_IXUSR)) != 0U ||
               (status.st_mode & S_IRUSR) == 0U ||
               status.st_size < (off_t)JG_BACKUP_PASSPHRASE_MIN ||
               status.st_size > (off_t)(JG_BACKUP_PASSPHRASE_MAX + 1U)) {
        result = -EACCES;
    }
    while (result == 0 && size < sizeof(data)) {
        const ssize_t count =
            read(descriptor, data + size, sizeof(data) - size);

        if (count > 0) {
            size += (size_t)count;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            result = -errno;
        }
    }
    if (result == 0 && size > 0U && data[size - 1U] == (uint8_t)'\n') {
        --size;
    }
    if (result == 0 &&
        (size < JG_BACKUP_PASSPHRASE_MIN || size > JG_BACKUP_PASSPHRASE_MAX ||
         memchr(data, '\0', size) != NULL ||
         memchr(data, '\n', size) != NULL)) {
        result = -EINVAL;
    }
    if (result == 0) {
        (void)memcpy(passphrase, data, size);
        passphrase[size] = '\0';
        *passphrase_size = size;
    }
    sodium_memzero(data, sizeof(data));
    if (close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    return result;
}

/** @brief Read one passphrase from a terminal while suppressing echo. */
static int read_terminal_passphrase(
    const char *message,
    char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U],
    size_t *passphrase_size)
{
    char input[JG_BACKUP_PASSPHRASE_MAX + 2U];
    struct termios original;
    struct termios hidden;
    sigset_t blocked;
    sigset_t previous;
    size_t size = 0U;
    bool signals_blocked = false;
    bool terminal_changed = false;
    int result = 0;

    *passphrase_size = 0U;
    if (isatty(STDIN_FILENO) == 0) {
        return -ENOTTY;
    }
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGINT) != 0 ||
        sigaddset(&blocked, SIGTERM) != 0 || sigaddset(&blocked, SIGHUP) != 0 ||
        sigaddset(&blocked, SIGQUIT) != 0) {
        result = -errno;
    }
    if (result == 0 && sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        result = -errno;
    } else if (result == 0) {
        signals_blocked = true;
    }
    if (result == 0 && tcgetattr(STDIN_FILENO, &original) != 0) {
        result = -errno;
    }
    if (result == 0) {
        hidden = original;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            result = -errno;
        } else {
            terminal_changed = true;
        }
    }
    if (result == 0 && (fputs(message, stderr) == EOF || fflush(stderr) != 0)) {
        result = -EIO;
    }
    if (result == 0 && fgets(input, sizeof(input), stdin) == NULL) {
        result = ferror(stdin) != 0 ? -EIO : -EINVAL;
    }
    if (terminal_changed &&
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original) != 0 && result == 0) {
        result = -errno;
    }
    if (terminal_changed) {
        (void)fputc('\n', stderr);
    }
    if (signals_blocked && sigprocmask(SIG_SETMASK, &previous, NULL) != 0 &&
        result == 0) {
        result = -errno;
    }
    if (result == 0) {
        size = strlen(input);
        if (size > 0U && input[size - 1U] == '\n') {
            input[--size] = '\0';
        }
        if (size < JG_BACKUP_PASSPHRASE_MIN ||
            size > JG_BACKUP_PASSPHRASE_MAX) {
            result = -EINVAL;
        }
    }
    if (result == 0) {
        (void)memcpy(passphrase, input, size + 1U);
        *passphrase_size = size;
    }
    sodium_memzero(input, sizeof(input));
    return result;
}

/** @brief Acquire and optionally confirm one full-backup passphrase. */
static int read_backup_passphrase(
    const struct cli_options *options,
    bool confirm,
    char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U],
    size_t *passphrase_size)
{
    char verification[JG_BACKUP_PASSPHRASE_MAX + 1U];
    size_t verification_size = 0U;
    int result = 0;

    if (options->passphrase_file != NULL) {
        return read_passphrase_file(options->passphrase_file, passphrase,
                                    passphrase_size);
    }
    result = read_terminal_passphrase("Backup passphrase: ", passphrase,
                                      passphrase_size);
    if (result == 0 && confirm) {
        result = read_terminal_passphrase(
            "Confirm backup passphrase: ", verification, &verification_size);
        if (result == 0 &&
            (verification_size != *passphrase_size ||
             sodium_memcmp(verification, passphrase, *passphrase_size) != 0)) {
            result = -EACCES;
        }
    }
    sodium_memzero(verification, sizeof(verification));
    return result;
}

/** @brief Execute one control operation requiring an empty response body. */
static int call_empty(const char *socket_path, enum jg_ipc_operation operation)
{
    size_t response_size = 0U;

    return jg_ipc_client_call(socket_path, operation, NULL, 0U, NULL, 0U,
                              &response_size);
}

/** @brief Present successful legacy local-control output. */
static void print_local_success(const struct cli_options *options,
                                const char *operation)
{
    if (options->quiet) {
        return;
    }
    if (options->json) {
        (void)printf("{\"%s\":true}\n", operation);
    } else if (strcmp(operation, "ok") == 0) {
        (void)puts("ok");
    } else {
        (void)printf("%s\n", operation);
    }
}

/** @brief Extract a nonnegative JSON integer or return zero. */
static uint64_t json_counter(json_t *object, const char *name)
{
    json_t *value = json_object_get(object, name);
    const json_int_t integer =
        json_is_integer(value) ? json_integer_value(value) : 0;

    return integer > 0 ? (uint64_t)integer : 0U;
}

/** @brief Print the principal runtime state for an operator. */
static void print_status_human(json_t *body)
{
    json_t *queues = json_object_get(body, "queues");
    json_t *dataplane = json_object_get(body, "dataplane");

    (void)printf("Enforcement:       %s\n",
                 json_is_true(json_object_get(body, "ready")) ? "ready"
                                                              : "not ready");
    (void)printf("Policy generation: %llu\n",
                 (unsigned long long)json_counter(body, "policy_generation"));
    (void)printf("Allowed:           %llu\n",
                 (unsigned long long)json_counter(dataplane, "accepted"));
    (void)printf("Blocked:           %llu\n",
                 (unsigned long long)json_counter(dataplane, "blocked"));
    (void)printf("Malformed:         %llu\n",
                 (unsigned long long)json_counter(dataplane, "malformed"));
    (void)printf("Queue dropped:     %llu\n",
                 (unsigned long long)json_counter(queues, "dropped"));
    (void)printf("Queue overflows:   %llu\n",
                 (unsigned long long)json_counter(queues, "overflows"));
}

/** @brief Print component health for an operator. */
static void print_health_human(json_t *body)
{
    json_t *daemon = json_object_get(body, "daemon");
    json_t *network = json_object_get(body, "network");

    (void)printf("Overall:        %s\n",
                 json_is_true(json_object_get(body, "healthy")) ? "healthy"
                                                                : "unhealthy");
    (void)printf("Daemon:         %s\n",
                 json_is_true(json_object_get(daemon, "available"))
                     ? "available"
                     : "unavailable");
    (void)printf("Network helper: %s\n",
                 json_is_true(json_object_get(network, "available"))
                     ? "available"
                     : "unavailable");
}

/** @brief Print a stable API failure and map its status to an exit code. */
static int report_api_failure(const struct jg_cli_response *response)
{
    json_error_t error;
    json_t *root = json_loadb(response->body, response->body_size,
                              JSON_REJECT_DUPLICATES, &error);
    json_t *detail = json_object_get(root, "error");
    const char *code = json_string_value(json_object_get(detail, "code"));
    const char *message = json_string_value(json_object_get(detail, "message"));

    (void)fprintf(stderr, "janusgatectl: %s",
                  message == NULL ? "management request failed" : message);
    if (code != NULL) {
        (void)fprintf(stderr, " (%s)", code);
    }
    (void)fprintf(stderr, " [request %s]\n", response->request_id);
    json_decref(root);
    if (response->status == 401 || response->status == 403) {
        return CLI_EXIT_AUTH;
    }
    if (response->status == 409) {
        return CLI_EXIT_CONFLICT;
    }
    return response->status >= 500 ? CLI_EXIT_UNAVAILABLE : CLI_EXIT_FAILURE;
}

/** @brief Present one successful JSON management response. */
static int present_api_response(const struct cli_options *options,
                                const char *command,
                                const struct jg_cli_response *response)
{
    json_error_t error;
    json_t *body = NULL;
    int result = CLI_EXIT_SUCCESS;

    if (response->status < 200 || response->status >= 300) {
        return report_api_failure(response);
    }
    body = json_loadb(response->body, response->body_size,
                      JSON_REJECT_DUPLICATES, &error);
    if (!json_is_object(body)) {
        json_decref(body);
        return CLI_EXIT_FAILURE;
    }
    if (!options->quiet) {
        if (options->json) {
            (void)printf("%s\n", response->body);
        } else if (strcmp(command, "status") == 0) {
            print_status_human(body);
        } else if (strcmp(command, "health") == 0) {
            print_health_human(body);
        } else {
            (void)json_dumpf(body, stdout, JSON_INDENT(2) | JSON_SORT_KEYS);
            (void)putchar('\n');
        }
    }
    if (strcmp(command, "health") == 0 &&
        !json_is_true(json_object_get(body, "healthy"))) {
        result = CLI_EXIT_UNAVAILABLE;
    }
    json_decref(body);
    return result;
}

/** @brief Perform one request through the selected authenticated transport. */
static int request_api(const struct cli_options *options,
                       const char *token,
                       const char *method,
                       const char *path,
                       const char *query,
                       json_t *body,
                       struct jg_cli_response *response)
{
    struct jg_cli_remote_config remote;
    int result = 0;

    if (options->verbose) {
        (void)fprintf(stderr, "janusgatectl: %s %s %s%s%s\n",
                      options->endpoint == NULL ? "local" : "remote", method,
                      path, query == NULL ? "" : "?",
                      query == NULL ? "" : query);
    }
    if (options->endpoint == NULL) {
        result = jg_cli_local_request(options->socket_path, token, method, path,
                                      query, body, response);
    } else {
        jg_cli_remote_config_default(&remote);
        remote.endpoint = options->endpoint;
        remote.token = token;
        remote.client_certificate = options->client_certificate;
        remote.client_key = options->client_key;
        remote.ca_file = options->ca_file;
        remote.timeout_seconds = options->timeout_seconds;
        result =
            jg_cli_remote_request(&remote, method, path, query, body, response);
    }
    if (result == 0 && options->verbose) {
        (void)fprintf(stderr, "janusgatectl: response %d [request %s]\n",
                      response->status, response->request_id);
    }
    return result;
}

/** @brief Read and report the configured private API token. */
static int load_token(const struct cli_options *options,
                      char token[JG_AUTH_SECRET_TEXT_SIZE])
{
    int result = 0;

    if (options->token_file == NULL) {
        (void)fprintf(stderr, "janusgatectl: --token-file is required\n");
        return CLI_EXIT_USAGE;
    }
    result = read_token_file(options->token_file, token);
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: token file: %s\n",
                      strerror(-result));
        return result == -EINVAL ? CLI_EXIT_USAGE : CLI_EXIT_FAILURE;
    }
    return CLI_EXIT_SUCCESS;
}

/** @brief Execute one API-backed CLI command through the selected transport. */
static int run_api_command(const struct cli_options *options,
                           const char *command)
{
    struct jg_cli_response response = {0};
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    json_t *body = NULL;
    const char *path =
        strcmp(command, "health") == 0 ? "/api/v1/health" : "/api/v1/status";
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    body = json_object();
    if (body == NULL) {
        sodium_memzero(token, sizeof(token));
        return CLI_EXIT_FAILURE;
    }
    result = request_api(options, token, "GET", path, NULL, body, &response);
    sodium_memzero(token, sizeof(token));
    json_decref(body);
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: request failed: %s\n",
                      strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    result = present_api_response(options, command, &response);
    jg_cli_response_clear(&response);
    return result;
}

/** @brief Read one bounded JSON object from a file or standard input. */
static json_t *read_json_object(const char *path, int *result)
{
    FILE *input = NULL;
    char *data = NULL;
    size_t size = 0U;
    json_error_t error;
    json_t *object = NULL;

    *result = 0;
    input = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (input == NULL) {
        *result = -errno;
        return NULL;
    }
    data = malloc(JG_IPC_MAX_BODY_SIZE + 1U);
    if (data == NULL) {
        *result = -ENOMEM;
    }
    if (*result == 0) {
        size = fread(data, 1U, JG_IPC_MAX_BODY_SIZE + 1U, input);
        if (ferror(input) != 0) {
            *result = -EIO;
        } else if (size == 0U || size > JG_IPC_MAX_BODY_SIZE) {
            *result = -EMSGSIZE;
        }
    }
    if (input != stdin && fclose(input) != 0 && *result == 0) {
        *result = -errno;
    }
    if (*result == 0) {
        object = json_loadb(data, size, JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(object)) {
            json_decref(object);
            object = NULL;
            *result = -EINVAL;
        }
    }
    if (data != NULL) {
        sodium_memzero(data, size);
        free(data);
    }
    return object;
}

/** @brief Read one bounded text file or standard input. */
static char *read_text(const char *path, size_t *text_size, int *result)
{
    FILE *input = NULL;
    char *text = NULL;
    size_t size = 0U;

    *text_size = 0U;
    *result = 0;
    input = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (input == NULL) {
        *result = -errno;
        return NULL;
    }
    text = malloc(JG_IPC_MAX_BODY_SIZE + 1U);
    if (text == NULL) {
        *result = -ENOMEM;
    }
    if (*result == 0) {
        size = fread(text, 1U, JG_IPC_MAX_BODY_SIZE + 1U, input);
        if (ferror(input) != 0) {
            *result = -EIO;
        } else if (size == 0U || size > JG_IPC_MAX_BODY_SIZE ||
                   memchr(text, '\0', size) != NULL) {
            *result = -EMSGSIZE;
        } else {
            text[size] = '\0';
        }
    }
    if (input != stdin && fclose(input) != 0 && *result == 0) {
        *result = -errno;
    }
    if (*result != 0) {
        if (text != NULL) {
            sodium_memzero(text, size);
            free(text);
            text = NULL;
        }
    } else {
        *text_size = size;
    }
    return text;
}

/** @brief Load the current persistent network revision through the API. */
static int load_network_revision(const struct cli_options *options,
                                 const char *token,
                                 uint64_t *revision)
{
    struct jg_cli_response response = {0};
    json_error_t error;
    json_t *request_body = json_object();
    json_t *response_body = NULL;
    json_t *value = NULL;
    int result = 0;

    if (request_body == NULL) {
        return CLI_EXIT_FAILURE;
    }
    result = request_api(options, token, "GET", "/api/v1/network", NULL,
                         request_body, &response);
    json_decref(request_body);
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: request failed: %s\n",
                      strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    if (response.status < 200 || response.status >= 300) {
        result = report_api_failure(&response);
    } else {
        response_body = json_loadb(response.body, response.body_size,
                                   JSON_REJECT_DUPLICATES, &error);
        value = json_object_get(response_body, "revision");
        if (!json_is_integer(value) || json_integer_value(value) <= 0) {
            result = CLI_EXIT_FAILURE;
        } else {
            *revision = (uint64_t)json_integer_value(value);
        }
        json_decref(response_body);
    }
    jg_cli_response_clear(&response);
    return result;
}

/** @brief Send and present one JSON management request. */
static int send_api_request(const struct cli_options *options,
                            const char *token,
                            const char *command,
                            const char *method,
                            const char *path,
                            json_t *body)
{
    struct jg_cli_response response = {0};
    int result =
        request_api(options, token, method, path, NULL, body, &response);

    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: request failed: %s\n",
                      strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    result = present_api_response(options, command, &response);
    jg_cli_response_clear(&response);
    return result;
}

/** @brief Fetch and decode one successful JSON API object. */
static int fetch_api_object(const struct cli_options *options,
                            const char *token,
                            const char *path,
                            const char *query,
                            json_t **object)
{
    struct jg_cli_response response = {0};
    json_error_t error;
    json_t *body = json_object();
    int result = 0;

    *object = NULL;
    if (body == NULL) {
        return CLI_EXIT_FAILURE;
    }
    result = request_api(options, token, "GET", path, query, body, &response);
    json_decref(body);
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: request failed: %s\n",
                      strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    if (response.status < 200 || response.status >= 300) {
        result = report_api_failure(&response);
    } else {
        *object = json_loadb(response.body, response.body_size,
                             JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(*object)) {
            json_decref(*object);
            *object = NULL;
            result = CLI_EXIT_FAILURE;
        }
    }
    jg_cli_response_clear(&response);
    return result;
}

/** @brief Send one JSON body and decode a successful JSON response. */
static int post_api_object(const struct cli_options *options,
                           const char *token,
                           const char *path,
                           json_t *body,
                           json_t **object)
{
    struct jg_cli_response response = {0};
    json_error_t error;
    int result = 0;

    *object = NULL;
    result = request_api(options, token, "POST", path, NULL, body, &response);
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: request failed: %s\n",
                      strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    if (response.status < 200 || response.status >= 300) {
        result = report_api_failure(&response);
    } else {
        *object = json_loadb(response.body, response.body_size,
                             JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(*object)) {
            json_decref(*object);
            *object = NULL;
            result = CLI_EXIT_FAILURE;
        }
    }
    jg_cli_response_clear(&response);
    return result;
}

/** @brief Present one locally assembled JSON result. */
static int present_object(const struct cli_options *options, json_t *object)
{
    char *encoded = NULL;

    if (options->quiet) {
        return CLI_EXIT_SUCCESS;
    }
    if (!options->json) {
        if (json_dumpf(object, stdout, JSON_INDENT(2) | JSON_SORT_KEYS) != 0 ||
            putchar('\n') == EOF) {
            return CLI_EXIT_FAILURE;
        }
        return CLI_EXIT_SUCCESS;
    }
    encoded = json_dumps(object, JSON_COMPACT | JSON_SORT_KEYS);
    if (encoded == NULL) {
        return CLI_EXIT_FAILURE;
    }
    (void)printf("%s\n", encoded);
    free(encoded);
    return CLI_EXIT_SUCCESS;
}

/** @brief Validate or stage one complete network configuration document. */
static int run_network_configuration(const struct cli_options *options,
                                     const char *token,
                                     const char *operation,
                                     const char *path)
{
    json_t *configuration = NULL;
    json_t *body = NULL;
    uint64_t revision = 0U;
    int result = 0;

    configuration = read_json_object(path, &result);
    if (configuration == NULL) {
        (void)fprintf(stderr, "janusgatectl: network configuration: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    if (strcmp(operation, "validate") == 0) {
        result = send_api_request(options, token, "network validate", "POST",
                                  "/api/v1/network/validate", configuration);
        json_decref(configuration);
        return result;
    }
    result = load_network_revision(options, token, &revision);
    if (result == CLI_EXIT_SUCCESS) {
        body = json_object();
        if (body == NULL ||
            json_object_set_new(body, "revision",
                                json_integer((json_int_t)revision)) != 0 ||
            json_object_set(body, "configuration", configuration) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(
            options, token,
            strcmp(operation, "set") == 0 ? "network set" : "network apply",
            "POST", "/api/v1/network/apply", body);
    }
    json_decref(body);
    json_decref(configuration);
    return result;
}

/** @brief Confirm or roll back the current pending network transaction. */
static int run_network_transaction(const struct cli_options *options,
                                   const char *token,
                                   const char *operation)
{
    json_t *body = NULL;
    char path[sizeof("/api/v1/network/rollback")];
    uint64_t revision = 0U;
    int result = load_network_revision(options, token, &revision);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    body = json_object();
    if (body == NULL ||
        json_object_set_new(body, "revision",
                            json_integer((json_int_t)revision)) != 0) {
        json_decref(body);
        return CLI_EXIT_FAILURE;
    }
    (void)snprintf(path, sizeof(path), "/api/v1/network/%s", operation);
    result = send_api_request(options, token, operation, "POST", path, body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized network administration command. */
static int run_network_command(const struct cli_options *options,
                               int argc,
                               char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    json_t *body = NULL;
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (argc == 2 && strcmp(argv[1], "show") == 0) {
        body = json_object();
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        } else {
            result = send_api_request(options, token, "network show", "GET",
                                      "/api/v1/network", body);
        }
        json_decref(body);
    } else if (argc == 3) {
        result = run_network_configuration(options, token, argv[1], argv[2]);
    } else {
        result = run_network_transaction(options, token, argv[1]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Map one CLI policy kind to its API collection and array field. */
static int policy_collection(const char *kind,
                             const char **path,
                             const char **array_name)
{
    if (strcmp(kind, "domain") == 0) {
        *path = "/api/v1/domains";
        *array_name = "domains";
        return 0;
    }
    if (strcmp(kind, "destination") == 0) {
        *path = "/api/v1/policies/destinations";
        *array_name = "destination_rules";
        return 0;
    }
    return -EINVAL;
}

/** @brief Fetch one exact policy rule and return an owned JSON object. */
static int fetch_policy_rule(const struct cli_options *options,
                             const char *token,
                             const char *kind,
                             uint64_t identifier,
                             json_t **rule)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    char query[96U];
    json_t *page = NULL;
    json_t *rules = NULL;
    json_t *candidate = NULL;
    json_t *value = NULL;
    int result = policy_collection(kind, &collection, &array_name);

    *rule = NULL;
    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    (void)snprintf(query, sizeof(query), "after_id=%llu&limit=1",
                   (unsigned long long)(identifier - 1U));
    result = fetch_api_object(options, token, collection, query, &page);
    if (result == CLI_EXIT_SUCCESS) {
        rules = json_object_get(page, array_name);
        candidate = json_array_get(rules, 0U);
        value = json_object_get(candidate, "id");
        if (!json_is_integer(value) ||
            (uint64_t)json_integer_value(value) != identifier) {
            (void)fprintf(stderr, "janusgatectl: policy rule not found\n");
            result = CLI_EXIT_FAILURE;
        } else {
            *rule = json_deep_copy(candidate);
            if (*rule == NULL) {
                result = CLI_EXIT_FAILURE;
            }
        }
    }
    json_decref(page);
    return result;
}

/** @brief Confirm a destructive operation unless approval was already given. */
static bool destructive_operation_confirmed(const struct cli_options *options,
                                            const char *description)
{
    char answer[8U];

    if (options->yes) {
        return true;
    }
    if (isatty(STDIN_FILENO) == 0) {
        (void)fprintf(stderr,
                      "janusgatectl: %s requires --yes in non-interactive "
                      "mode\n",
                      description);
        return false;
    }
    (void)fprintf(stderr, "%s? [y/N] ", description);
    if (fgets(answer, sizeof(answer), stdin) == NULL) {
        return false;
    }
    return (answer[0U] == 'y' || answer[0U] == 'Y') &&
           (answer[1U] == '\n' || answer[1U] == '\0');
}

/** @brief List both policy-rule collections as one stable document. */
static int run_policy_list(const struct cli_options *options, const char *token)
{
    json_t *domains = NULL;
    json_t *destinations = NULL;
    json_t *body = NULL;
    int result =
        fetch_api_object(options, token, "/api/v1/domains", NULL, &domains);

    if (result == CLI_EXIT_SUCCESS) {
        result =
            fetch_api_object(options, token, "/api/v1/policies/destinations",
                             NULL, &destinations);
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = json_object();
        if (body == NULL ||
            json_object_set(body, "domain_rules", domains) != 0 ||
            json_object_set(body, "destination_rules", destinations) != 0) {
            result = CLI_EXIT_FAILURE;
        } else {
            result = present_object(options, body);
        }
    }
    json_decref(body);
    json_decref(destinations);
    json_decref(domains);
    return result;
}

/** @brief Display one exact domain or destination policy rule. */
static int run_policy_show(const struct cli_options *options,
                           const char *token,
                           const char *kind,
                           const char *identifier_text)
{
    json_t *rule = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_policy_rule(options, token, kind, identifier, &rule);
    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, rule);
    }
    json_decref(rule);
    return result;
}

/** @brief Build one exact API path for a typed policy rule. */
static int policy_rule_path(const char *kind,
                            uint64_t identifier,
                            char *path,
                            size_t path_size)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    int written = 0;

    if (policy_collection(kind, &collection, &array_name) != 0) {
        return -EINVAL;
    }
    (void)array_name;
    written = snprintf(path, path_size, "%s/%llu", collection,
                       (unsigned long long)identifier);
    return written > 0 && (size_t)written < path_size ? 0 : -ENOSPC;
}

/** @brief Create or replace one typed policy rule from a JSON document. */
static int run_policy_write(const struct cli_options *options,
                            const char *token,
                            const char *operation,
                            const char *kind,
                            const char *identifier_text,
                            const char *file)
{
    const char *collection = NULL;
    const char *array_name = NULL;
    char path[128U];
    json_t *body = NULL;
    json_t *current = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = policy_collection(kind, &collection, &array_name);

    (void)array_name;
    if (result != 0 || (identifier_text != NULL &&
                        parse_identifier(identifier_text, &identifier) != 0)) {
        return CLI_EXIT_USAGE;
    }
    body = read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: policy document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    if (identifier_text == NULL) {
        (void)snprintf(path, sizeof(path), "%s", collection);
    } else {
        result = fetch_policy_rule(options, token, kind, identifier, &current);
        revision = json_object_get(current, "revision");
        if (result == CLI_EXIT_SUCCESS &&
            (!json_is_integer(revision) ||
             json_object_set(body, "revision", revision) != 0 ||
             policy_rule_path(kind, identifier, path, sizeof(path)) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(
            options, token,
            strcmp(operation, "add") == 0 ? "policy add" : "policy update",
            strcmp(operation, "add") == 0 ? "POST" : "PATCH", path, body);
    }
    json_decref(current);
    json_decref(body);
    return result;
}

/** @brief Delete one revision-bound typed policy rule. */
static int run_policy_remove(const struct cli_options *options,
                             const char *token,
                             const char *kind,
                             const char *identifier_text)
{
    char path[128U];
    json_t *rule = NULL;
    json_t *revision = NULL;
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_policy_rule(options, token, kind, identifier, &rule);
    if (result == CLI_EXIT_SUCCESS &&
        !destructive_operation_confirmed(options, "Remove the policy rule")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(rule, "revision");
        body = json_object();
        if (!json_is_integer(revision) || body == NULL ||
            json_object_set(body, "revision", revision) != 0 ||
            policy_rule_path(kind, identifier, path, sizeof(path)) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(options, token, "policy remove", "DELETE",
                                  path, body);
    }
    json_decref(body);
    json_decref(rule);
    return result;
}

/** @brief Simulate one policy decision from a JSON document. */
static int run_policy_simulation(const struct cli_options *options,
                                 const char *token,
                                 const char *file)
{
    json_t *body = NULL;
    int result = 0;

    body = read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: simulation document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    result = send_api_request(options, token, "policy simulate", "POST",
                              "/api/v1/policies/simulate", body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized policy administration command. */
static int run_policy_command(const struct cli_options *options,
                              int argc,
                              char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (argc == 2) {
        result = run_policy_list(options, token);
    } else if (strcmp(argv[1], "show") == 0) {
        result = run_policy_show(options, token, argv[2], argv[3]);
    } else if (strcmp(argv[1], "add") == 0) {
        result =
            run_policy_write(options, token, "add", argv[2], NULL, argv[3]);
    } else if (strcmp(argv[1], "update") == 0) {
        result = run_policy_write(options, token, "update", argv[2], argv[3],
                                  argv[4]);
    } else if (strcmp(argv[1], "remove") == 0) {
        result = run_policy_remove(options, token, argv[2], argv[3]);
    } else {
        result = run_policy_simulation(options, token, argv[2]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Create one global DNS domain rule from a CLI shorthand. */
static int run_domain_create(const struct cli_options *options,
                             const char *token,
                             const char *action,
                             const char *domain)
{
    json_t *body = json_object();
    json_t *scope = json_object();
    int result = 0;

    if (body == NULL || scope == NULL ||
        json_object_set_new(scope, "type", json_string("global")) != 0 ||
        json_object_set_new(body, "domain", json_string(domain)) != 0 ||
        json_object_set_new(body, "include_subdomains", json_true()) != 0 ||
        json_object_set_new(body, "action", json_string(action)) != 0 ||
        json_object_set_new(body, "target", json_string("dns")) != 0 ||
        json_object_set(body, "scope", scope) != 0 ||
        json_object_set_new(body, "attribution", json_string("janusgatectl")) !=
            0 ||
        json_object_set_new(body, "enabled", json_true()) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(options, token,
                                  strcmp(action, "block") == 0 ? "domain block"
                                                               : "domain allow",
                                  "POST", "/api/v1/domains", body);
    }
    json_decref(scope);
    json_decref(body);
    return result;
}

/** @brief Run one recognized domain-policy shorthand command. */
static int run_domain_command(const struct cli_options *options, char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "remove") == 0) {
        result = run_policy_remove(options, token, "domain", argv[2]);
    } else {
        result = run_domain_create(options, token, argv[1], argv[2]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Fetch one exact blocklist source and return an owned object. */
static int fetch_source(const struct cli_options *options,
                        const char *token,
                        uint64_t identifier,
                        json_t **source)
{
    char query[96U];
    json_t *page = NULL;
    json_t *sources = NULL;
    json_t *candidate = NULL;
    json_t *value = NULL;
    int result = 0;

    *source = NULL;
    (void)snprintf(query, sizeof(query), "after_id=%llu&limit=1",
                   (unsigned long long)(identifier - 1U));
    result = fetch_api_object(options, token, "/api/v1/sources", query, &page);
    if (result == CLI_EXIT_SUCCESS) {
        sources = json_object_get(page, "sources");
        candidate = json_array_get(sources, 0U);
        value = json_object_get(candidate, "id");
        if (!json_is_integer(value) ||
            (uint64_t)json_integer_value(value) != identifier) {
            (void)fprintf(stderr, "janusgatectl: blocklist source not found\n");
            result = CLI_EXIT_FAILURE;
        } else {
            *source = json_deep_copy(candidate);
            if (*source == NULL) {
                result = CLI_EXIT_FAILURE;
            }
        }
    }
    json_decref(page);
    return result;
}

/** @brief Remove read-only source-state fields before an update. */
static void retain_source_configuration(json_t *source)
{
    static const char *const read_only[] = {
        "id",
        "created_at",
        "updated_at",
        "etag",
        "last_modified",
        "last_attempt_at",
        "last_success_at",
        "next_attempt_at",
        "consecutive_failures",
        "active_checksum",
        "active_entries",
        "rejected_entries",
        "health",
        "last_error",
    };

    for (size_t index = 0U; index < sizeof(read_only) / sizeof(read_only[0U]);
         ++index) {
        json_object_del(source, read_only[index]);
    }
}

/** @brief List blocklist-source configuration and update health. */
static int run_source_list(const struct cli_options *options, const char *token)
{
    json_t *body = NULL;
    int result =
        fetch_api_object(options, token, "/api/v1/sources", NULL, &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Add or replace one blocklist-source JSON configuration. */
static int run_source_write(const struct cli_options *options,
                            const char *token,
                            const char *operation,
                            const char *identifier_text,
                            const char *file)
{
    char path[96U];
    json_t *body = NULL;
    json_t *source = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = 0;

    if (identifier_text != NULL &&
        parse_identifier(identifier_text, &identifier) != 0) {
        return CLI_EXIT_USAGE;
    }
    body = read_json_object(file, &result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: source document: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    if (identifier_text == NULL) {
        (void)snprintf(path, sizeof(path), "/api/v1/sources");
    } else {
        result = fetch_source(options, token, identifier, &source);
        revision = json_object_get(source, "revision");
        if (result == CLI_EXIT_SUCCESS &&
            (!json_is_integer(revision) ||
             json_object_set(body, "revision", revision) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
        (void)snprintf(path, sizeof(path), "/api/v1/sources/%llu",
                       (unsigned long long)identifier);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(
            options, token,
            strcmp(operation, "add") == 0 ? "source add" : "source update",
            strcmp(operation, "add") == 0 ? "POST" : "PATCH", path, body);
    }
    json_decref(source);
    json_decref(body);
    return result;
}

/** @brief Refresh, enable, or disable one blocklist source. */
static int run_source_operation(const struct cli_options *options,
                                const char *token,
                                const char *operation,
                                const char *identifier_text)
{
    char path[128U];
    json_t *source = NULL;
    json_t *revision = NULL;
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_source(options, token, identifier, &source);
    revision = json_object_get(source, "revision");
    if (result == CLI_EXIT_SUCCESS && !json_is_integer(revision)) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS && strcmp(operation, "refresh") == 0) {
        body = json_object();
        if (body == NULL || json_object_set(body, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
        (void)snprintf(path, sizeof(path), "/api/v1/sources/%llu/refresh",
                       (unsigned long long)identifier);
    } else if (result == CLI_EXIT_SUCCESS) {
        body = json_deep_copy(source);
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        } else {
            retain_source_configuration(body);
            if (json_object_set_new(
                    body, "enabled",
                    json_boolean(strcmp(operation, "enable") == 0)) != 0) {
                result = CLI_EXIT_FAILURE;
            }
        }
        (void)snprintf(path, sizeof(path), "/api/v1/sources/%llu",
                       (unsigned long long)identifier);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(
            options, token, operation,
            strcmp(operation, "refresh") == 0 ? "POST" : "PATCH", path, body);
    }
    json_decref(body);
    json_decref(source);
    return result;
}

/** @brief Run one recognized blocklist-source administration command. */
static int run_source_command(const struct cli_options *options,
                              int argc,
                              char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (argc == 2) {
        result = run_source_list(options, token);
    } else if (strcmp(argv[1], "add") == 0) {
        result = run_source_write(options, token, "add", NULL, argv[2]);
    } else if (strcmp(argv[1], "update") == 0) {
        result = run_source_write(options, token, "update", argv[2], argv[3]);
    } else {
        result = run_source_operation(options, token, argv[1], argv[2]);
    }
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Import one local source payload with its current revision. */
static int run_blocklist_import(const struct cli_options *options,
                                const char *token,
                                const char *identifier_text,
                                const char *file)
{
    char *text = NULL;
    json_t *source = NULL;
    json_t *revision = NULL;
    json_t *body = NULL;
    size_t text_size = 0U;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_source(options, token, identifier, &source);
    if (result == CLI_EXIT_SUCCESS) {
        text = read_text(file, &text_size, &result);
        if (text == NULL) {
            (void)fprintf(stderr, "janusgatectl: blocklist input: %s\n",
                          strerror(-result));
            result = result == -EINVAL || result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(source, "revision");
        body = json_object();
        if (!json_is_integer(revision) || body == NULL ||
            json_object_set_new(body, "source_id",
                                json_integer((json_int_t)identifier)) != 0 ||
            json_object_set(body, "revision", revision) != 0 ||
            json_object_set_new(body, "content",
                                json_stringn(text, text_size)) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(options, token, "blocklist import", "POST",
                                  "/api/v1/blocklists", body);
    }
    json_decref(body);
    json_decref(source);
    if (text != NULL) {
        sodium_memzero(text, text_size);
        free(text);
    }
    return result;
}

/** @brief Export active blocklist-derived domain rules as JSON. */
static int run_blocklist_export(const struct cli_options *options,
                                const char *token)
{
    json_t *exported = json_object();
    json_t *domains = json_array();
    uint64_t after_id = 0U;
    bool more = true;
    int result = exported == NULL || domains == NULL ? CLI_EXIT_FAILURE
                                                     : CLI_EXIT_SUCCESS;

    while (result == CLI_EXIT_SUCCESS && more) {
        char query[96U];
        json_t *page = NULL;
        json_t *items = NULL;
        json_t *next = NULL;

        (void)snprintf(query, sizeof(query), "after_id=%llu&limit=100",
                       (unsigned long long)after_id);
        result =
            fetch_api_object(options, token, "/api/v1/domains", query, &page);
        if (result == CLI_EXIT_SUCCESS) {
            items = json_object_get(page, "domains");
            for (size_t index = 0U; index < json_array_size(items); ++index) {
                json_t *item = json_array_get(items, index);
                const char *source =
                    json_string_value(json_object_get(item, "source"));

                if (source != NULL && strcmp(source, "blocklist") == 0 &&
                    json_array_append(domains, item) != 0) {
                    result = CLI_EXIT_FAILURE;
                    break;
                }
            }
            more = json_is_true(json_object_get(page, "has_more"));
            next = json_object_get(page, "next_after_id");
            if (result == CLI_EXIT_SUCCESS && more &&
                (!json_is_integer(next) ||
                 json_integer_value(next) <= (json_int_t)after_id)) {
                result = CLI_EXIT_FAILURE;
            } else if (result == CLI_EXIT_SUCCESS && more) {
                after_id = (uint64_t)json_integer_value(next);
            }
        }
        json_decref(page);
    }
    if (result == CLI_EXIT_SUCCESS &&
        json_object_set(exported, "domains", domains) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, exported);
    }
    json_decref(domains);
    json_decref(exported);
    return result;
}

/** @brief Run one recognized blocklist administration command. */
static int run_blocklist_command(const struct cli_options *options,
                                 int argc,
                                 char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = run_source_list(options, token);
    } else if (strcmp(argv[1], "export") == 0) {
        result = run_blocklist_export(options, token);
    } else {
        result = run_blocklist_import(options, token, argv[2], argv[3]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Fetch one exact local user from stable paginated API results. */
static int fetch_user(const struct cli_options *options,
                      const char *token,
                      uint64_t identifier,
                      json_t **user)
{
    uint64_t offset = 0U;
    bool more = true;
    int result = CLI_EXIT_SUCCESS;

    *user = NULL;
    while (result == CLI_EXIT_SUCCESS && more && *user == NULL) {
        char query[96U];
        json_t *page = NULL;
        json_t *users = NULL;
        json_t *next = NULL;

        (void)snprintf(query, sizeof(query), "offset=%llu&limit=100",
                       (unsigned long long)offset);
        result =
            fetch_api_object(options, token, "/api/v1/users", query, &page);
        if (result == CLI_EXIT_SUCCESS) {
            users = json_object_get(page, "users");
            if (!json_is_array(users)) {
                result = CLI_EXIT_FAILURE;
            }
        }
        for (size_t index = 0U;
             result == CLI_EXIT_SUCCESS && index < json_array_size(users);
             ++index) {
            json_t *candidate = json_array_get(users, index);
            json_t *value = json_object_get(candidate, "id");

            if (json_is_integer(value) &&
                (uint64_t)json_integer_value(value) == identifier) {
                *user = json_deep_copy(candidate);
                if (*user == NULL) {
                    result = CLI_EXIT_FAILURE;
                }
            }
        }
        if (result == CLI_EXIT_SUCCESS && *user == NULL) {
            next = json_object_get(page, "next_offset");
            more = !json_is_null(next);
            if (more && (!json_is_integer(next) ||
                         json_integer_value(next) <= (json_int_t)offset)) {
                result = CLI_EXIT_FAILURE;
            } else if (more) {
                offset = (uint64_t)json_integer_value(next);
            }
        }
        json_decref(page);
    }
    if (result == CLI_EXIT_SUCCESS && *user == NULL) {
        (void)fprintf(stderr, "janusgatectl: local user not found\n");
        result = CLI_EXIT_FAILURE;
    }
    return result;
}

/** @brief List the first stable page of local-user administration state. */
static int run_user_list(const struct cli_options *options, const char *token)
{
    json_t *body = NULL;
    int result =
        fetch_api_object(options, token, "/api/v1/users", "limit=100", &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Add or update one local user from an exact JSON document. */
static int run_user_write(const struct cli_options *options,
                          const char *token,
                          const char *operation,
                          const char *identifier_text,
                          const char *file)
{
    const bool add = strcmp(operation, "add") == 0;
    const bool password = strcmp(operation, "password") == 0;
    char path[128U];
    json_t *body = NULL;
    json_t *user = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = CLI_EXIT_SUCCESS;
    int read_result = 0;

    if (!add && parse_identifier(identifier_text, &identifier) != 0) {
        return CLI_EXIT_USAGE;
    }
    if (!add) {
        result = fetch_user(options, token, identifier, &user);
    }
    if (result == CLI_EXIT_SUCCESS && password &&
        !destructive_operation_confirmed(options,
                                         "Replace the user's password")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = read_json_object(file, &read_result);
        if (body == NULL) {
            (void)fprintf(stderr, "janusgatectl: user document: %s\n",
                          strerror(-read_result));
            result = read_result == -EINVAL || read_result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS && !add) {
        revision = json_object_get(user, "revision");
        if (!json_is_integer(revision) ||
            json_object_set(body, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (add) {
        (void)snprintf(path, sizeof(path), "/api/v1/users");
    } else if (password) {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu/password",
                       (unsigned long long)identifier);
    } else {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu",
                       (unsigned long long)identifier);
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(
            options, token,
            add ? "user add" : (password ? "user password" : "user update"),
            add || password ? "POST" : "PATCH", path, body);
    }
    json_decref(user);
    json_decref(body);
    return result;
}

/** @brief Disable one local user while preserving its remaining state. */
static int run_user_disable(const struct cli_options *options,
                            const char *token,
                            const char *identifier_text)
{
    char path[96U];
    json_t *user = NULL;
    json_t *body = NULL;
    json_t *revision = NULL;
    json_t *role = NULL;
    json_t *force_password_change = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_user(options, token, identifier, &user);
    if (result == CLI_EXIT_SUCCESS &&
        !destructive_operation_confirmed(options, "Disable the local user")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(user, "revision");
        role = json_object_get(user, "role");
        force_password_change = json_object_get(user, "force_password_change");
        body = json_object();
        if (!json_is_integer(revision) || !json_is_string(role) ||
            !json_is_boolean(force_password_change) || body == NULL ||
            json_object_set(body, "revision", revision) != 0 ||
            json_object_set(body, "role", role) != 0 ||
            json_object_set_new(body, "enabled", json_false()) != 0 ||
            json_object_set(body, "force_password_change",
                            force_password_change) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu",
                       (unsigned long long)identifier);
        result = send_api_request(options, token, "user disable", "PATCH", path,
                                  body);
    }
    json_decref(body);
    json_decref(user);
    return result;
}

/** @brief Remove one local user's TOTP and recovery credentials. */
static int run_user_totp_disable(const struct cli_options *options,
                                 const char *token,
                                 const char *identifier_text)
{
    char path[sizeof("/api/v1/users/18446744073709551615/totp")];
    json_t *user = NULL;
    json_t *body = NULL;
    json_t *revision = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    result = fetch_user(options, token, identifier, &user);
    if (result == CLI_EXIT_SUCCESS &&
        !destructive_operation_confirmed(
            options, "Remove the user's TOTP credentials")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        revision = json_object_get(user, "revision");
        body = json_object();
        if (!json_is_integer(revision) || body == NULL ||
            json_object_set(body, "revision", revision) != 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        (void)snprintf(path, sizeof(path), "/api/v1/users/%llu/totp",
                       (unsigned long long)identifier);
        result =
            send_api_request(options, token, "user totp", "DELETE", path, body);
    }
    json_decref(body);
    json_decref(user);
    return result;
}

/** @brief Run one recognized local-user administration command. */
static int run_user_command(const struct cli_options *options,
                            int argc,
                            char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = run_user_list(options, token);
    } else if (strcmp(argv[1], "add") == 0) {
        result = run_user_write(options, token, "add", NULL, argv[2]);
    } else if (strcmp(argv[1], "update") == 0 ||
               strcmp(argv[1], "password") == 0) {
        result = run_user_write(options, token, argv[1], argv[2], argv[3]);
    } else if (strcmp(argv[1], "disable") == 0) {
        result = run_user_disable(options, token, argv[2]);
    } else {
        result = run_user_totp_disable(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief List the first stable page of API-token metadata. */
static int run_token_list(const struct cli_options *options, const char *token)
{
    json_t *body = NULL;
    int result =
        fetch_api_object(options, token, "/api/v1/tokens", "limit=100", &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Issue one scoped API token from an exact JSON document. */
static int run_token_create(const struct cli_options *options,
                            const char *token,
                            const char *file)
{
    json_t *body = NULL;
    int read_result = 0;
    int result = CLI_EXIT_SUCCESS;

    body = read_json_object(file, &read_result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: token document: %s\n",
                      strerror(-read_result));
        return read_result == -EINVAL || read_result == -EMSGSIZE
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    result = send_api_request(options, token, "token create", "POST",
                              "/api/v1/tokens", body);
    json_decref(body);
    return result;
}

/** @brief Revoke one API token after an explicit destructive confirmation. */
static int run_token_revoke(const struct cli_options *options,
                            const char *token,
                            const char *identifier_text)
{
    char path[sizeof("/api/v1/tokens/18446744073709551615")];
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    if (!destructive_operation_confirmed(options, "Revoke the API token")) {
        return CLI_EXIT_FAILURE;
    }
    body = json_object();
    if (body == NULL) {
        return CLI_EXIT_FAILURE;
    }
    (void)snprintf(path, sizeof(path), "/api/v1/tokens/%llu",
                   (unsigned long long)identifier);
    result =
        send_api_request(options, token, "token revoke", "DELETE", path, body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized API-token administration command. */
static int run_token_command(const struct cli_options *options,
                             int argc,
                             char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "list") == 0) {
        result = run_token_list(options, token);
    } else if (strcmp(argv[1], "create") == 0) {
        result = run_token_create(options, token, argv[2]);
    } else {
        result = run_token_revoke(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Inspect current public server-certificate metadata. */
static int run_certificate_show(const struct cli_options *options,
                                const char *token)
{
    json_t *body = NULL;
    int result =
        fetch_api_object(options, token, "/api/v1/certificates", NULL, &body);

    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Install one certificate document against the current fingerprint. */
static int run_certificate_install(const struct cli_options *options,
                                   const char *token,
                                   const char *file)
{
    json_t *current = NULL;
    json_t *certificate = NULL;
    json_t *fingerprint = NULL;
    json_t *body = NULL;
    int read_result = 0;
    int result = fetch_api_object(options, token, "/api/v1/certificates", NULL,
                                  &current);

    if (result == CLI_EXIT_SUCCESS &&
        !destructive_operation_confirmed(options,
                                         "Replace the server certificate")) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = read_json_object(file, &read_result);
        if (body == NULL) {
            (void)fprintf(stderr, "janusgatectl: certificate document: %s\n",
                          strerror(-read_result));
            result = read_result == -EINVAL || read_result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        certificate = json_object_get(current, "certificate");
        fingerprint = json_object_get(certificate, "fingerprint_sha256");
        if (!json_is_string(fingerprint) ||
            json_object_set(body, "expected_fingerprint", fingerprint) != 0 ||
            (json_object_get(body, "private_key") == NULL &&
             json_object_set_new(body, "private_key", json_null()) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(options, token, "certificate install", "POST",
                                  "/api/v1/certificates/install", body);
    }
    json_decref(body);
    json_decref(current);
    return result;
}

/** @brief Create one CSR from a bounded local JSON document. */
static int run_certificate_csr(const struct cli_options *options,
                               const char *token,
                               const char *file)
{
    json_t *body = NULL;
    int read_result = 0;
    int result = CLI_EXIT_SUCCESS;

    body = read_json_object(file, &read_result);
    if (body == NULL) {
        (void)fprintf(stderr, "janusgatectl: CSR document: %s\n",
                      strerror(-read_result));
        return read_result == -EINVAL || read_result == -EMSGSIZE
                   ? CLI_EXIT_USAGE
                   : CLI_EXIT_FAILURE;
    }
    result = send_api_request(options, token, "certificate csr", "POST",
                              "/api/v1/certificates/csr", body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized server-certificate administration command. */
static int run_certificate_command(const struct cli_options *options,
                                   int argc,
                                   char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "show") == 0) {
        result = run_certificate_show(options, token);
    } else if (strcmp(argv[1], "install") == 0) {
        result = run_certificate_install(options, token, argv[2]);
    } else {
        result = run_certificate_csr(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Create one configuration or full backup through the API. */
static int run_backup_create(const struct cli_options *options,
                             const char *token,
                             const char *kind)
{
    const bool full = strcmp(kind, "full") == 0;
    char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U];
    size_t passphrase_size = 0U;
    json_t *body = NULL;
    json_t *passphrase_value = NULL;
    int result = CLI_EXIT_SUCCESS;

    if (!full &&
        (options->include_private_key || options->passphrase_file != NULL)) {
        (void)fprintf(
            stderr,
            "janusgatectl: configuration backups cannot contain secrets\n");
        return CLI_EXIT_USAGE;
    }
    (void)memset(passphrase, 0, sizeof(passphrase));
    if (full) {
        const int read_result =
            read_backup_passphrase(options, true, passphrase, &passphrase_size);

        if (read_result != 0) {
            (void)fprintf(stderr, "janusgatectl: backup passphrase: %s\n",
                          read_result == -EACCES ? "confirmation does not match"
                                                 : strerror(-read_result));
            sodium_memzero(passphrase, sizeof(passphrase));
            return read_result == -EINVAL || read_result == -ENOTTY
                       ? CLI_EXIT_USAGE
                       : CLI_EXIT_FAILURE;
        }
    }
    body = json_object();
    passphrase_value =
        full ? json_stringn(passphrase, passphrase_size) : json_null();
    if (body == NULL || passphrase_value == NULL ||
        json_object_set_new(body, "kind", json_string(kind)) != 0 ||
        json_object_set_new(
            body, "include_private_key",
            json_boolean(full && options->include_private_key)) != 0 ||
        json_object_set(body, "passphrase", passphrase_value) != 0) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(options, token, "backup create", "POST",
                                  "/api/v1/backups", body);
    }
    json_decref(passphrase_value);
    json_decref(body);
    sodium_memzero(passphrase, sizeof(passphrase));
    return result;
}

/** @brief Inspect one backup manifest by persistent identifier. */
static int run_backup_inspect(const struct cli_options *options,
                              const char *token,
                              const char *identifier_text)
{
    char path[sizeof("/api/v1/backups/18446744073709551615")];
    json_t *body = NULL;
    uint64_t identifier = 0U;
    int result = parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    (void)snprintf(path, sizeof(path), "/api/v1/backups/%llu",
                   (unsigned long long)identifier);
    result = fetch_api_object(options, token, path, NULL, &body);
    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Build one exact dry-run or confirmed restore request body. */
static json_t *backup_restore_body(const char *passphrase,
                                   size_t passphrase_size,
                                   bool dry_run)
{
    json_t *body = json_object();
    json_t *passphrase_value = passphrase == NULL
                                   ? json_null()
                                   : json_stringn(passphrase, passphrase_size);

    if (body == NULL || passphrase_value == NULL ||
        json_object_set(body, "passphrase", passphrase_value) != 0 ||
        json_object_set_new(body, "dry_run", json_boolean(dry_run)) != 0 ||
        json_object_set_new(body, "confirm", json_boolean(!dry_run)) != 0) {
        json_decref(passphrase_value);
        json_decref(body);
        return NULL;
    }
    json_decref(passphrase_value);
    return body;
}

/** @brief Dry-run and explicitly confirm one backup restore. */
static int run_backup_restore(const struct cli_options *options,
                              const char *token,
                              const char *identifier_text)
{
    char path[sizeof("/api/v1/backups/18446744073709551615/restore")];
    char inspect_path[sizeof("/api/v1/backups/18446744073709551615")];
    char passphrase[JG_BACKUP_PASSPHRASE_MAX + 1U];
    json_t *inspection = NULL;
    json_t *backup = NULL;
    json_t *kind_value = NULL;
    json_t *body = NULL;
    json_t *dry_run = NULL;
    const char *kind = NULL;
    size_t passphrase_size = 0U;
    uint64_t identifier = 0U;
    bool full = false;
    bool changes = false;
    int result = parse_identifier(identifier_text, &identifier);

    (void)memset(passphrase, 0, sizeof(passphrase));
    if (result != 0 || options->include_private_key) {
        return CLI_EXIT_USAGE;
    }
    (void)snprintf(inspect_path, sizeof(inspect_path), "/api/v1/backups/%llu",
                   (unsigned long long)identifier);
    (void)snprintf(path, sizeof(path), "/api/v1/backups/%llu/restore",
                   (unsigned long long)identifier);
    result = fetch_api_object(options, token, inspect_path, NULL, &inspection);
    if (result == CLI_EXIT_SUCCESS) {
        backup = json_object_get(inspection, "backup");
        kind_value = json_object_get(backup, "kind");
        kind =
            json_is_string(kind_value) ? json_string_value(kind_value) : NULL;
        if (kind == NULL ||
            (strcmp(kind, "configuration") != 0 && strcmp(kind, "full") != 0)) {
            result = CLI_EXIT_FAILURE;
        } else {
            full = strcmp(kind, "full") == 0;
        }
    }
    if (result == CLI_EXIT_SUCCESS && !full &&
        options->passphrase_file != NULL) {
        (void)fprintf(stderr, "janusgatectl: configuration restores have no "
                              "passphrase\n");
        result = CLI_EXIT_USAGE;
    }
    if (result == CLI_EXIT_SUCCESS && full) {
        const int read_result = read_backup_passphrase(
            options, false, passphrase, &passphrase_size);

        if (read_result != 0) {
            (void)fprintf(stderr, "janusgatectl: backup passphrase: %s\n",
                          strerror(-read_result));
            result = read_result == -EINVAL || read_result == -ENOTTY
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        body = backup_restore_body(full ? passphrase : NULL, passphrase_size,
                                   true);
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = post_api_object(options, token, path, body, &dry_run);
    }
    json_decref(body);
    body = NULL;
    if (result == CLI_EXIT_SUCCESS) {
        json_t *value = json_object_get(dry_run, "changes");

        if (!json_is_boolean(value)) {
            result = CLI_EXIT_FAILURE;
        } else {
            changes = json_is_true(value);
        }
    }
    if (result == CLI_EXIT_SUCCESS && !options->json) {
        result = present_object(options, dry_run);
    }
    if (result == CLI_EXIT_SUCCESS && !changes) {
        if (options->json) {
            result = present_object(options, dry_run);
        }
    } else if (result == CLI_EXIT_SUCCESS &&
               !destructive_operation_confirmed(options,
                                                "Apply the backup restore")) {
        result = CLI_EXIT_FAILURE;
    } else if (result == CLI_EXIT_SUCCESS) {
        body = backup_restore_body(full ? passphrase : NULL, passphrase_size,
                                   false);
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        } else {
            result = send_api_request(options, token, "backup restore", "POST",
                                      path, body);
        }
    }
    json_decref(body);
    json_decref(dry_run);
    json_decref(inspection);
    sodium_memzero(passphrase, sizeof(passphrase));
    return result;
}

/** @brief Run one recognized backup administration command. */
static int run_backup_command(const struct cli_options *options,
                              int argc,
                              char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "create") == 0) {
        result = run_backup_create(options, token, argv[2]);
    } else if (strcmp(argv[1], "inspect") == 0) {
        result = run_backup_inspect(options, token, argv[2]);
    } else {
        result = run_backup_restore(options, token, argv[2]);
    }
    (void)argc;
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Validate or reload persistent appliance configuration. */
static int run_config_command(const struct cli_options *options,
                              const char *operation)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    const char *path = strcmp(operation, "reload") == 0
                           ? "/api/v1/config/reload"
                           : "/api/v1/config/validate";
    json_t *body = NULL;
    int result = load_token(options, token);

    if (result == CLI_EXIT_SUCCESS) {
        body = json_object();
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = send_api_request(options, token, "config", "POST", path, body);
    }
    json_decref(body);
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Show, replace, or inspect bounded operational logging state. */
static int run_logging_command(const struct cli_options *options,
                               int argc,
                               char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    json_t *body = NULL;
    json_t *current = NULL;
    json_t *revision = NULL;
    int result = load_token(options, token);

    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    if (strcmp(argv[1], "show") == 0 || strcmp(argv[1], "traces") == 0) {
        const char *path = strcmp(argv[1], "show") == 0
                               ? "/api/v1/logging"
                               : "/api/v1/logging/traces";

        result = fetch_api_object(options, token, path, NULL, &body);
        if (result == CLI_EXIT_SUCCESS) {
            result = present_object(options, body);
        }
    } else {
        body = read_json_object(argv[2], &result);
        if (body == NULL) {
            (void)fprintf(stderr, "janusgatectl: logging document: %s\n",
                          strerror(-result));
            result = result == -EINVAL || result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
        if (result == CLI_EXIT_SUCCESS) {
            result = fetch_api_object(options, token, "/api/v1/logging", NULL,
                                      &current);
        }
        revision = json_object_get(current, "revision");
        if (result == CLI_EXIT_SUCCESS &&
            (!json_is_integer(revision) ||
             json_object_set(body, "revision", revision) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
        if (result == CLI_EXIT_SUCCESS) {
            result = send_api_request(options, token, "logging set", "PUT",
                                      "/api/v1/logging", body);
        }
    }
    json_decref(current);
    json_decref(body);
    sodium_memzero(token, sizeof(token));
    (void)argc;
    return result;
}

/** @brief Validate one canonical root-level diagnostic archive filename. */
static bool diagnostic_filename_valid(const char *filename, size_t size)
{
    static const char prefix[] = "janusgate-diagnostics-";
    static const char suffix[] = ".tar.gz";
    const size_t prefix_size = sizeof(prefix) - 1U;
    const size_t suffix_size = sizeof(suffix) - 1U;
    const size_t timestamp_size = 16U;
    const char *timestamp = NULL;

    if (filename == NULL ||
        size != prefix_size + timestamp_size + suffix_size ||
        memcmp(filename, prefix, prefix_size) != 0 ||
        memcmp(filename + size - suffix_size, suffix, suffix_size) != 0) {
        return false;
    }
    timestamp = filename + prefix_size;
    for (size_t index = 0U; index < timestamp_size; ++index) {
        if (index == 8U) {
            if (timestamp[index] != 'T') {
                return false;
            }
        } else if (index == 15U) {
            if (timestamp[index] != 'Z') {
                return false;
            }
        } else if (timestamp[index] < '0' || timestamp[index] > '9') {
            return false;
        }
    }
    return true;
}

/** @brief Write one verified diagnostic archive as a new private file. */
static int write_diagnostic_archive(const char *filename,
                                    const uint8_t *archive,
                                    size_t archive_size)
{
    size_t offset = 0U;
    int descriptor = open(
        filename, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    int result = descriptor < 0 ? -errno : 0;

    while (result == 0 && offset < archive_size) {
        const ssize_t count =
            write(descriptor, archive + offset, archive_size - offset);

        if (count < 0 && errno != EINTR) {
            result = -errno;
        } else if (count > 0) {
            offset += (size_t)count;
        } else if (count == 0) {
            result = -EIO;
        }
    }
    if (result == 0 && fsync(descriptor) != 0) {
        result = -errno;
    }
    if (descriptor >= 0 && close(descriptor) != 0 && result == 0) {
        result = -errno;
    }
    if (descriptor >= 0 && result != 0) {
        (void)unlink(filename);
    }
    return result;
}

/** @brief Create, verify, and store one sanitized diagnostic archive. */
static int run_diagnostics_create(const struct cli_options *options)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    uint8_t expected_checksum[crypto_hash_sha256_BYTES];
    uint8_t actual_checksum[crypto_hash_sha256_BYTES];
    json_t *request = NULL;
    json_t *response = NULL;
    json_t *filename_value = NULL;
    json_t *media_type_value = NULL;
    json_t *size_value = NULL;
    json_t *checksum_value = NULL;
    json_t *data_value = NULL;
    const char *filename = NULL;
    const char *checksum_text = NULL;
    const char *data = NULL;
    uint8_t *archive = NULL;
    size_t filename_size = 0U;
    size_t checksum_size = 0U;
    size_t data_size = 0U;
    size_t archive_size = 0U;
    size_t checksum_bytes = 0U;
    json_int_t expected_size = 0;
    bool verification_failed = false;
    int result = load_token(options, token);

    if (result == CLI_EXIT_SUCCESS) {
        request = json_object();
        if (request == NULL) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        result = post_api_object(options, token, "/api/v1/diagnostics", request,
                                 &response);
    }
    sodium_memzero(token, sizeof(token));
    json_decref(request);
    if (result != CLI_EXIT_SUCCESS) {
        json_decref(response);
        return result;
    }
    filename_value = json_object_get(response, "filename");
    media_type_value = json_object_get(response, "media_type");
    size_value = json_object_get(response, "size_bytes");
    checksum_value = json_object_get(response, "checksum_sha256");
    data_value = json_object_get(response, "data_base64");
    filename = json_string_value(filename_value);
    checksum_text = json_string_value(checksum_value);
    data = json_string_value(data_value);
    filename_size = json_is_string(filename_value)
                        ? json_string_length(filename_value)
                        : 0U;
    checksum_size = json_is_string(checksum_value)
                        ? json_string_length(checksum_value)
                        : 0U;
    data_size =
        json_is_string(data_value) ? json_string_length(data_value) : 0U;
    expected_size =
        json_is_integer(size_value) ? json_integer_value(size_value) : 0;
    if (!diagnostic_filename_valid(filename, filename_size) ||
        !json_is_string(media_type_value) ||
        json_string_length(media_type_value) !=
            sizeof("application/gzip") - 1U ||
        strcmp(json_string_value(media_type_value), "application/gzip") != 0 ||
        expected_size <= 0 ||
        (uint64_t)expected_size > (uint64_t)JG_IPC_MAX_BODY_SIZE ||
        checksum_size != crypto_hash_sha256_BYTES * 2U || data_size == 0U) {
        verification_failed = true;
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS) {
        archive = malloc((size_t)expected_size);
        if (archive == NULL) {
            (void)fprintf(stderr, "janusgatectl: diagnostic archive: %s\n",
                          strerror(ENOMEM));
            result = CLI_EXIT_FAILURE;
        } else if (sodium_hex2bin(expected_checksum, sizeof(expected_checksum),
                                  checksum_text, checksum_size, NULL,
                                  &checksum_bytes, NULL) != 0 ||
                   checksum_bytes != sizeof(expected_checksum) ||
                   sodium_base642bin(archive, (size_t)expected_size, data,
                                     data_size, NULL, &archive_size, NULL,
                                     sodium_base64_VARIANT_ORIGINAL) != 0 ||
                   archive_size != (size_t)expected_size) {
            verification_failed = true;
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        (void)crypto_hash_sha256(actual_checksum, archive, archive_size);
        if (sodium_memcmp(actual_checksum, expected_checksum,
                          sizeof(actual_checksum)) != 0) {
            verification_failed = true;
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS) {
        const int write_result =
            write_diagnostic_archive(filename, archive, archive_size);

        if (write_result != 0) {
            (void)fprintf(stderr, "janusgatectl: diagnostic archive: %s\n",
                          strerror(-write_result));
            result = CLI_EXIT_FAILURE;
        }
    }
    if (result == CLI_EXIT_SUCCESS &&
        (json_object_del(response, "data_base64") != 0 ||
         json_object_set_new(response, "path", json_string(filename)) != 0)) {
        result = CLI_EXIT_FAILURE;
    }
    if (result == CLI_EXIT_SUCCESS && !options->quiet) {
        if (options->json) {
            result = present_object(options, response);
        } else if (printf("Created %s (%zu bytes)\nSHA-256: %s\n", filename,
                          archive_size, checksum_text) < 0) {
            result = CLI_EXIT_FAILURE;
        }
    }
    if (verification_failed) {
        (void)fprintf(stderr,
                      "janusgatectl: diagnostic archive verification failed\n");
    }
    sodium_memzero(actual_checksum, sizeof(actual_checksum));
    sodium_memzero(expected_checksum, sizeof(expected_checksum));
    free(archive);
    json_decref(response);
    return result;
}

/** @brief Query operational events or immutable audit records. */
static int run_record_command(const struct cli_options *options,
                              int argc,
                              char **argv)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    const bool audit = strcmp(argv[0], "audit") == 0;
    const bool verify = audit && argc == 2 && strcmp(argv[1], "verify") == 0;
    const char *path = verify ? "/api/v1/audit/verify"
                              : (audit ? "/api/v1/audit" : "/api/v1/events");
    const char *query = argc == 2 && !verify ? argv[1] : NULL;
    json_t *body = NULL;
    int result = load_token(options, token);

    if (result == CLI_EXIT_SUCCESS) {
        result = fetch_api_object(options, token, path, query, &body);
    }
    sodium_memzero(token, sizeof(token));
    if (result == CLI_EXIT_SUCCESS) {
        result = present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Confirm and request one authenticated appliance lifecycle action. */
static int run_system_command(const struct cli_options *options,
                              const char *family,
                              const char *operation)
{
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    char path[sizeof("/api/v1/service/restart")];
    json_t *body = NULL;
    const char *message =
        strcmp(operation, "restart") == 0
            ? "Restart the JanusGate service"
            : (strcmp(operation, "reboot") == 0 ? "Reboot the appliance"
                                                : "Shut down the appliance");
    int result = 0;

    if (!destructive_operation_confirmed(options, message)) {
        return CLI_EXIT_USAGE;
    }
    result = load_token(options, token);
    if (result != CLI_EXIT_SUCCESS) {
        return result;
    }
    result = snprintf(path, sizeof(path), "/api/v1/%s/%s", family, operation);
    body = json_object();
    if (result <= 0 || (size_t)result >= sizeof(path) || body == NULL ||
        json_object_set_new(body, "confirm", json_true()) != 0) {
        result = CLI_EXIT_FAILURE;
    } else {
        result =
            send_api_request(options, token, operation, "POST", path, body);
    }
    json_decref(body);
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Run one recognized CLI command. */
static int run_command(const struct cli_options *options,
                       int argc,
                       char **argv,
                       bool *recognized)
{
    const bool full_backup_create =
        argc == 3 && strcmp(argv[0], "backup") == 0 &&
        strcmp(argv[1], "create") == 0 && strcmp(argv[2], "full") == 0;
    const bool backup_restore = argc == 3 && strcmp(argv[0], "backup") == 0 &&
                                strcmp(argv[1], "restore") == 0;
    int result = 0;

    *recognized = true;
    if ((options->passphrase_file != NULL && !full_backup_create &&
         !backup_restore) ||
        (options->include_private_key && !full_backup_create)) {
        *recognized = false;
        return CLI_EXIT_USAGE;
    }
    if (argc == 1 &&
        (strcmp(argv[0], "status") == 0 || strcmp(argv[0], "health") == 0 ||
         strcmp(argv[0], "stats") == 0)) {
        return run_api_command(options, argv[0]);
    }
    if (argc >= 2 && strcmp(argv[0], "network") == 0 &&
        ((argc == 2 &&
          (strcmp(argv[1], "show") == 0 || strcmp(argv[1], "confirm") == 0 ||
           strcmp(argv[1], "rollback") == 0)) ||
         (argc == 3 &&
          (strcmp(argv[1], "validate") == 0 || strcmp(argv[1], "apply") == 0 ||
           strcmp(argv[1], "set") == 0)))) {
        return run_network_command(options, argc, argv);
    }
    if (argc >= 2 && strcmp(argv[0], "policy") == 0 &&
        ((argc == 2 && strcmp(argv[1], "list") == 0) ||
         (argc == 3 && strcmp(argv[1], "simulate") == 0) ||
         (argc == 4 &&
          (strcmp(argv[1], "show") == 0 || strcmp(argv[1], "add") == 0 ||
           strcmp(argv[1], "remove") == 0)) ||
         (argc == 5 && strcmp(argv[1], "update") == 0))) {
        return run_policy_command(options, argc, argv);
    }
    if (argc == 3 && strcmp(argv[0], "domain") == 0 &&
        (strcmp(argv[1], "block") == 0 || strcmp(argv[1], "allow") == 0 ||
         strcmp(argv[1], "remove") == 0)) {
        return run_domain_command(options, argv);
    }
    if (argc >= 2 && strcmp(argv[0], "source") == 0 &&
        ((argc == 2 && strcmp(argv[1], "list") == 0) ||
         (argc == 3 &&
          (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "refresh") == 0 ||
           strcmp(argv[1], "enable") == 0 ||
           strcmp(argv[1], "disable") == 0)) ||
         (argc == 4 && strcmp(argv[1], "update") == 0))) {
        return run_source_command(options, argc, argv);
    }
    if (argc >= 2 && strcmp(argv[0], "blocklist") == 0 &&
        ((argc == 2 &&
          (strcmp(argv[1], "list") == 0 || strcmp(argv[1], "export") == 0)) ||
         (argc == 4 && strcmp(argv[1], "import") == 0))) {
        return run_blocklist_command(options, argc, argv);
    }
    if ((argc == 1 || argc == 2) &&
        (strcmp(argv[0], "events") == 0 || strcmp(argv[0], "audit") == 0)) {
        return run_record_command(options, argc, argv);
    }
    if (argc >= 2 && strcmp(argv[0], "user") == 0 &&
        ((argc == 2 && strcmp(argv[1], "list") == 0) ||
         (argc == 3 &&
          (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "disable") == 0 ||
           strcmp(argv[1], "totp") == 0)) ||
         (argc == 4 && (strcmp(argv[1], "update") == 0 ||
                        strcmp(argv[1], "password") == 0)))) {
        return run_user_command(options, argc, argv);
    }
    if (argc >= 2 && strcmp(argv[0], "token") == 0 &&
        ((argc == 2 && strcmp(argv[1], "list") == 0) ||
         (argc == 3 && (strcmp(argv[1], "create") == 0 ||
                        strcmp(argv[1], "revoke") == 0)))) {
        return run_token_command(options, argc, argv);
    }
    if (argc >= 2 && strcmp(argv[0], "certificate") == 0 &&
        ((argc == 2 && strcmp(argv[1], "show") == 0) ||
         (argc == 3 &&
          (strcmp(argv[1], "install") == 0 || strcmp(argv[1], "csr") == 0)))) {
        return run_certificate_command(options, argc, argv);
    }
    if (argc == 3 && strcmp(argv[0], "backup") == 0 &&
        ((strcmp(argv[1], "create") == 0 &&
          (strcmp(argv[2], "configuration") == 0 ||
           strcmp(argv[2], "full") == 0)) ||
         strcmp(argv[1], "inspect") == 0 || strcmp(argv[1], "restore") == 0)) {
        return run_backup_command(options, argc, argv);
    }
    if (argc == 2 && strcmp(argv[0], "config") == 0 &&
        (strcmp(argv[1], "validate") == 0 || strcmp(argv[1], "reload") == 0)) {
        return run_config_command(options, argv[1]);
    }
    if (argc == 2 && strcmp(argv[0], "diagnostics") == 0 &&
        strcmp(argv[1], "create") == 0) {
        return run_diagnostics_create(options);
    }
    if (argc >= 2 && strcmp(argv[0], "logging") == 0 &&
        ((argc == 2 &&
          (strcmp(argv[1], "show") == 0 || strcmp(argv[1], "traces") == 0)) ||
         (argc == 3 && strcmp(argv[1], "set") == 0))) {
        return run_logging_command(options, argc, argv);
    }
    if (argc == 2 && strcmp(argv[0], "service") == 0 &&
        strcmp(argv[1], "restart") == 0) {
        return run_system_command(options, argv[0], argv[1]);
    }
    if (argc == 2 && strcmp(argv[0], "system") == 0 &&
        (strcmp(argv[1], "reboot") == 0 || strcmp(argv[1], "shutdown") == 0)) {
        return run_system_command(options, argv[0], argv[1]);
    }
    if (argc == 1 && strcmp(argv[0], "ping") == 0 &&
        options->endpoint == NULL) {
        result = call_empty(options->socket_path, JG_IPC_PING);
        if (result == 0) {
            print_local_success(options, "ok");
        }
    } else if (argc == 2 && strcmp(argv[0], "policy") == 0 &&
               strcmp(argv[1], "reload") == 0 && options->endpoint == NULL) {
        result = call_empty(options->socket_path, JG_IPC_POLICY_RELOAD);
        if (result == 0) {
            print_local_success(options, "reloaded");
        }
    } else {
        *recognized = false;
        return CLI_EXIT_USAGE;
    }
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: %s\n", strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    return CLI_EXIT_SUCCESS;
}

/** @brief Run the JanusGate administration client. */
int main(int argc, char **argv)
{
    struct cli_options options;
    bool recognized = false;
    int command_index = 0;
    int result = 0;

    options_default(&options);
    result = parse_options(argc, argv, &options, &command_index);
    if (result != 0) {
        print_usage(stderr);
        return CLI_EXIT_USAGE;
    }
    if (options.version) {
        if (command_index != argc || options.help) {
            print_usage(stderr);
            return CLI_EXIT_USAGE;
        }
        (void)printf("janusgatectl %s\n", jg_version_string());
        return CLI_EXIT_SUCCESS;
    }
    if (options.help) {
        if (command_index != argc) {
            print_usage(stderr);
            return CLI_EXIT_USAGE;
        }
        print_usage(stdout);
        return CLI_EXIT_SUCCESS;
    }
    result = run_command(&options, argc - command_index, argv + command_index,
                         &recognized);
    if (!recognized) {
        print_usage(stderr);
    }
    return result;
}
