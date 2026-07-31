/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
 */

/**
 * @file web_server.h
 * @brief Internal ownership and configuration of the HTTPS management server.
 */

#ifndef JANUSGATE_WEB_SERVER_H
#define JANUSGATE_WEB_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janusgate/certificate.h"
#include "janusgate/ipc.h"

/** Default first-boot management address. */
#define JG_WEB_DEFAULT_ADDRESS "192.168.77.1"

/** Default HTTPS management port. */
#if defined(__OpenBSD__)
#define JG_WEB_DEFAULT_PORT 8443U
#else
#define JG_WEB_DEFAULT_PORT 443U
#endif

/** Default mTLS remote API port. */
#define JG_WEB_DEFAULT_API_PORT 9443U

/** Default combined certificate and private-key PEM. */
#define JG_WEB_DEFAULT_CERTIFICATE JG_CERTIFICATE_DEFAULT_PATH

/** Default installed local web assets. */
#if defined(__OpenBSD__)
#define JG_WEB_DEFAULT_ROOT "/usr/local/share/janusgate/web"
#else
#define JG_WEB_DEFAULT_ROOT "/usr/share/janusgate/web"
#endif

/** Largest accepted request including headers and body. */
#define JG_WEB_REQUEST_SIZE_MAX 1048576U

/** Complete process-local HTTPS server configuration. */
struct jg_web_config {
    /** Numeric IPv4 or IPv6 management address. */
    const char *listen_address;
    /** HTTPS TCP port. */
    uint16_t port;
    /** Dedicated mTLS remote API port. */
    uint16_t api_port;
    /** Absolute combined certificate and private-key PEM path. */
    const char *certificate_path;
    /** Absolute trusted client-certificate authority bundle path. */
    const char *client_ca_path;
    /** Absolute local static-asset root. */
    const char *web_root;
    /** Absolute daemon management control-socket path. */
    const char *control_socket_path;
    /** Maximum complete request bytes. */
    uint32_t max_request_size;
    /** Fixed CivetWeb worker count. */
    uint16_t worker_count;
    /** Whether HSTS is emitted after first-boot setup is complete. */
    bool hsts;
};

/** Opaque owner of one running CivetWeb context. */
struct jg_web_server;

/** @brief Initialize conservative first-boot HTTPS defaults. */
void jg_web_config_default(struct jg_web_config *config);

/** @brief Validate scalar management-listener configuration. */
int jg_web_config_validate(const struct jg_web_config *config);

/** @brief Build the exact CivetWeb TLS listener expression. */
int jg_web_build_listener(const struct jg_web_config *config,
                          uint16_t port,
                          char *output,
                          size_t output_size);

/** @brief Start one TLS-only management service. */
int jg_web_server_start(const struct jg_web_config *config,
                        struct jg_web_server **server);

/** @brief Stop and release one management service. */
void jg_web_server_destroy(struct jg_web_server *server);

#endif
