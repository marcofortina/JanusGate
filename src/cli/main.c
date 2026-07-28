/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "client.h"
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
    const char *client_certificate;
    const char *client_key;
    const char *ca_file;
    unsigned timeout_seconds;
    bool socket_set;
    bool json;
    bool quiet;
    bool verbose;
    bool help;
    bool version;
};

/** Long-option values kept outside the unsigned-character range. */
enum cli_option {
    CLI_OPTION_SOCKET = 256,
    CLI_OPTION_ENDPOINT,
    CLI_OPTION_TOKEN_FILE,
    CLI_OPTION_CLIENT_CERTIFICATE,
    CLI_OPTION_CLIENT_KEY,
    CLI_OPTION_CA_FILE,
    CLI_OPTION_JSON,
    CLI_OPTION_TIMEOUT,
    CLI_OPTION_QUIET,
    CLI_OPTION_VERBOSE,
    CLI_OPTION_VERSION,
    CLI_OPTION_HELP
};

/** @brief Print the stable command synopsis. */
static void print_usage(FILE *output)
{
    (void)fprintf(
        output, "usage: janusgatectl [OPTIONS] status\n"
                "       janusgatectl [OPTIONS] health\n"
                "       janusgatectl [OPTIONS] stats\n"
                "       janusgatectl [--socket PATH] [--json] ping\n"
                "       janusgatectl [--socket PATH] [--json] policy reload\n"
                "       janusgatectl --version\n"
                "\n"
                "Transport options:\n"
                "  --socket PATH       local control socket\n"
                "  --endpoint URL      remote HTTPS management origin\n"
                "  --token-file PATH   private file containing one API token\n"
                "  --client-cert PATH  optional mTLS client certificate\n"
                "  --client-key PATH   optional mTLS client private key\n"
                "  --ca-file PATH      optional PEM trust-anchor file\n"
                "  --timeout SECONDS   remote request timeout (1-300)\n"
                "\n"
                "Output options:\n"
                "  --json              stable compact JSON output\n"
                "  --quiet             suppress successful output\n"
                "  --verbose           report transport and request details\n"
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
        {"client-cert", required_argument, NULL, CLI_OPTION_CLIENT_CERTIFICATE},
        {"client-key", required_argument, NULL, CLI_OPTION_CLIENT_KEY},
        {"ca-file", required_argument, NULL, CLI_OPTION_CA_FILE},
        {"json", no_argument, NULL, CLI_OPTION_JSON},
        {"timeout", required_argument, NULL, CLI_OPTION_TIMEOUT},
        {"quiet", no_argument, NULL, CLI_OPTION_QUIET},
        {"verbose", no_argument, NULL, CLI_OPTION_VERBOSE},
        {"version", no_argument, NULL, CLI_OPTION_VERSION},
        {"help", no_argument, NULL, CLI_OPTION_HELP},
        {NULL, 0, NULL, 0},
    };
    int result = 0;
    int option = 0;

    opterr = 0;
    while (result == 0 &&
           (option = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
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

/** @brief Execute one API-backed CLI command through the selected transport. */
static int run_api_command(const struct cli_options *options,
                           const char *command)
{
    struct jg_cli_remote_config remote;
    struct jg_cli_response response = {0};
    char token[JG_AUTH_SECRET_TEXT_SIZE] = {0};
    json_t *body = NULL;
    const char *path =
        strcmp(command, "health") == 0 ? "/api/v1/health" : "/api/v1/status";
    int result = read_token_file(options->token_file, token);

    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: token file: %s\n",
                      strerror(-result));
        return result == -EINVAL ? CLI_EXIT_USAGE : CLI_EXIT_FAILURE;
    }
    body = json_object();
    if (body == NULL) {
        sodium_memzero(token, sizeof(token));
        return CLI_EXIT_FAILURE;
    }
    if (options->verbose) {
        (void)fprintf(stderr, "janusgatectl: %s GET %s\n",
                      options->endpoint == NULL ? "local" : "remote", path);
    }
    if (options->endpoint == NULL) {
        result = jg_cli_local_request(options->socket_path, token, "GET", path,
                                      NULL, body, &response);
    } else {
        jg_cli_remote_config_default(&remote);
        remote.endpoint = options->endpoint;
        remote.token = token;
        remote.client_certificate = options->client_certificate;
        remote.client_key = options->client_key;
        remote.ca_file = options->ca_file;
        remote.timeout_seconds = options->timeout_seconds;
        result =
            jg_cli_remote_request(&remote, "GET", path, NULL, body, &response);
    }
    sodium_memzero(token, sizeof(token));
    json_decref(body);
    if (result != 0) {
        (void)fprintf(stderr, "janusgatectl: request failed: %s\n",
                      strerror(-result));
        return CLI_EXIT_FAILURE;
    }
    if (options->verbose) {
        (void)fprintf(stderr, "janusgatectl: response %d [request %s]\n",
                      response.status, response.request_id);
    }
    result = present_api_response(options, command, &response);
    jg_cli_response_clear(&response);
    return result;
}

/** @brief Run one recognized CLI command. */
static int run_command(const struct cli_options *options,
                       int argc,
                       char **argv,
                       bool *recognized)
{
    int result = 0;

    *recognized = true;
    if (argc == 1 &&
        (strcmp(argv[0], "status") == 0 || strcmp(argv[0], "health") == 0 ||
         strcmp(argv[0], "stats") == 0)) {
        if (options->token_file == NULL) {
            (void)fprintf(stderr, "janusgatectl: --token-file is required\n");
            return CLI_EXIT_USAGE;
        }
        return run_api_command(options, argv[0]);
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
