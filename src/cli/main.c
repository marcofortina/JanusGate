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
                "       janusgatectl [OPTIONS] network show\n"
                "       janusgatectl [OPTIONS] network validate FILE\n"
                "       janusgatectl [OPTIONS] network apply FILE\n"
                "       janusgatectl [OPTIONS] network set FILE\n"
                "       janusgatectl [OPTIONS] network confirm\n"
                "       janusgatectl [OPTIONS] network rollback\n"
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
    free(data);
    return object;
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

/** @brief Send and present one network management request. */
static int send_network_request(const struct cli_options *options,
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
        result =
            send_network_request(options, token, "network validate", "POST",
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
        result = send_network_request(
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
    result =
        send_network_request(options, token, operation, "POST", path, body);
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
            result = send_network_request(options, token, "network show", "GET",
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
