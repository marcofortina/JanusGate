/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file commands_appliance.c
 * @brief Appliance administration commands.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
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

#include "cli_internal.h"
#include "janusgate/backup.h"
#include "janusgate/ipc.h"

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

/** @brief Load the current persistent network revision through the API. */
static int load_network_revision(const struct cli_options *options,
                                 const char *token,
                                 uint64_t *revision)
{
    json_t *body = NULL;
    json_t *value = NULL;
    int result =
        jg_cli_fetch_api_object(options, token, "/api/v1/network", NULL, &body);

    if (result == CLI_EXIT_SUCCESS) {
        value = json_object_get(body, "revision");
        if (!json_is_integer(value) || json_integer_value(value) <= 0) {
            result = CLI_EXIT_FAILURE;
        } else {
            *revision = (uint64_t)json_integer_value(value);
        }
    }
    json_decref(body);
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

    configuration = jg_cli_read_json_object(path, &result);
    if (configuration == NULL) {
        (void)fprintf(stderr, "janusgatectl: network configuration: %s\n",
                      strerror(-result));
        return result == -EINVAL || result == -EMSGSIZE ? CLI_EXIT_USAGE
                                                        : CLI_EXIT_FAILURE;
    }
    if (strcmp(operation, "validate") == 0) {
        result =
            jg_cli_send_api_request(options, token, "network validate", "POST",
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
        result = jg_cli_send_api_request(
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
        jg_cli_send_api_request(options, token, operation, "POST", path, body);
    json_decref(body);
    return result;
}

/** @brief Run one recognized network administration command. */
int jg_cli_run_network_command(const struct cli_options *options,
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
            result = jg_cli_send_api_request(options, token, "network show",
                                             "GET", "/api/v1/network", body);
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
        json_t *completed = NULL;

        result = jg_cli_post_api_job(options, token, "/api/v1/backups", body,
                                     &completed);
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_present_object(options, completed);
        }
        json_decref(completed);
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
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    if (result != 0) {
        return CLI_EXIT_USAGE;
    }
    (void)snprintf(path, sizeof(path), "/api/v1/backups/%llu",
                   (unsigned long long)identifier);
    result = jg_cli_fetch_api_object(options, token, path, NULL, &body);
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
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
    int result = jg_cli_parse_identifier(identifier_text, &identifier);

    (void)memset(passphrase, 0, sizeof(passphrase));
    if (result != 0 || options->include_private_key) {
        return CLI_EXIT_USAGE;
    }
    (void)snprintf(inspect_path, sizeof(inspect_path), "/api/v1/backups/%llu",
                   (unsigned long long)identifier);
    (void)snprintf(path, sizeof(path), "/api/v1/backups/%llu/restore",
                   (unsigned long long)identifier);
    result = jg_cli_fetch_api_object(options, token, inspect_path, NULL,
                                     &inspection);
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
        result = jg_cli_post_api_job(options, token, path, body, &dry_run);
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
        result = jg_cli_present_object(options, dry_run);
    }
    if (result == CLI_EXIT_SUCCESS && !changes) {
        if (options->json) {
            result = jg_cli_present_object(options, dry_run);
        }
    } else if (result == CLI_EXIT_SUCCESS &&
               !jg_cli_destructive_operation_confirmed(
                   options, "Apply the backup restore")) {
        result = CLI_EXIT_FAILURE;
    } else if (result == CLI_EXIT_SUCCESS) {
        body = backup_restore_body(full ? passphrase : NULL, passphrase_size,
                                   false);
        if (body == NULL) {
            result = CLI_EXIT_FAILURE;
        } else {
            json_t *completed = NULL;

            result =
                jg_cli_post_api_job(options, token, path, body, &completed);
            if (result == CLI_EXIT_SUCCESS) {
                result = jg_cli_present_object(options, completed);
            }
            json_decref(completed);
        }
    }
    json_decref(body);
    json_decref(dry_run);
    json_decref(inspection);
    sodium_memzero(passphrase, sizeof(passphrase));
    return result;
}

/** @brief Run one recognized backup administration command. */
int jg_cli_run_backup_command(const struct cli_options *options,
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
int jg_cli_run_config_command(const struct cli_options *options,
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
        result = jg_cli_send_api_request(options, token, "config", "POST", path,
                                         body);
    }
    json_decref(body);
    sodium_memzero(token, sizeof(token));
    return result;
}

/** @brief Show, replace, or inspect bounded operational logging state. */
int jg_cli_run_logging_command(const struct cli_options *options,
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

        result = jg_cli_fetch_api_object(options, token, path, NULL, &body);
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_present_object(options, body);
        }
    } else {
        body = jg_cli_read_json_object(argv[2], &result);
        if (body == NULL) {
            (void)fprintf(stderr, "janusgatectl: logging document: %s\n",
                          strerror(-result));
            result = result == -EINVAL || result == -EMSGSIZE
                         ? CLI_EXIT_USAGE
                         : CLI_EXIT_FAILURE;
        }
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_fetch_api_object(options, token, "/api/v1/logging",
                                             NULL, &current);
        }
        revision = json_object_get(current, "revision");
        if (result == CLI_EXIT_SUCCESS &&
            (!json_is_integer(revision) ||
             json_object_set(body, "revision", revision) != 0)) {
            result = CLI_EXIT_FAILURE;
        }
        if (result == CLI_EXIT_SUCCESS) {
            result = jg_cli_send_api_request(options, token, "logging set",
                                             "PUT", "/api/v1/logging", body);
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
int jg_cli_run_diagnostics_create(const struct cli_options *options)
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
        result = jg_cli_post_api_job(options, token, "/api/v1/diagnostics",
                                     request, &response);
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
            result = jg_cli_present_object(options, response);
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
int jg_cli_run_record_command(const struct cli_options *options,
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
        result = jg_cli_fetch_api_object(options, token, path, query, &body);
    }
    sodium_memzero(token, sizeof(token));
    if (result == CLI_EXIT_SUCCESS) {
        result = jg_cli_present_object(options, body);
    }
    json_decref(body);
    return result;
}

/** @brief Confirm and request one authenticated appliance lifecycle action. */
int jg_cli_run_system_command(const struct cli_options *options,
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

    if (!jg_cli_destructive_operation_confirmed(options, message)) {
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
        result = jg_cli_send_api_request(options, token, operation, "POST",
                                         path, body);
    }
    json_decref(body);
    sodium_memzero(token, sizeof(token));
    return result;
}
