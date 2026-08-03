<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Management API

The versioned API is rooted at `/api/v1`. Browser administration is served on
the normal management HTTPS listener. Remote automation is served separately
on TCP 9443 only after a client CA bundle is installed. `api/openapi.yaml` is
the normative OpenAPI 3.1 contract.

## Authentication and request rules

Interactive browsers authenticate through `/auth/login` and use the secure
session cookie plus the returned CSRF value for every state-changing request.
The browser listener uses username, password, and optional TOTP; it does not
request a client certificate.

Automation connects to TCP 9443 with a trusted client certificate and sends
`Authorization: Bearer TOKEN`. Both factors are mandatory. The leaf
certificate fingerprint must have a current user or role mapping compatible
with the token owner. Authentication routes and static WebGUI assets are not
available on this listener. See [Remote API](remote-api.md) for private and
home-lab CA setup.

Requests must use the configured management host, an accepted media type, and
bounded JSON. Unknown object fields, invalid UTF-8, trailing content, and
unsupported methods are rejected. Responses use JSON and carry a request
identifier suitable for audit correlation.

```http
GET /api/v1/status HTTP/1.1
Host: 192.168.77.1:9443
Authorization: Bearer <token>
Accept: application/json
```

## Revisions and errors

Mutable resources expose a revision. Update and delete requests must present
the revision they read. A stale value returns HTTP `409`, allowing clients to
refetch rather than overwrite another operator's work.

Errors contain a stable machine code, a concise message, and the request
identifier. Authentication and role failures use `401` and `403`; schema
failures use `400` or `422`; missing resources use `404`; known resources with
an unsupported method use `405`; rate limiting uses `429`; internal or
temporarily unavailable operations use `5xx`.

`GET /health` exposes the persistent policy `desired_revision` and
`applied_revision`. A mismatch is retained across restarts and suspends normal
mutations. An authorized `POST /config/reload` remains available as the
explicit validation and publication retry. During an applied restore,
`management.restore_in_progress` is true and
`management.mutations_allowed` is false. New writes receive
`503 restore_in_progress`; authenticated reads and job polling continue.

Blocklist updates, backups, diagnostics, and CSR generation return a bounded
job reference with HTTP `202`. Poll `/jobs/{id}` as the same authenticated
actor; completed results remain available until read, or for at most one hour.
A full restore replaces sessions, tokens, users, TOTP credentials, and mTLS
mappings. A remote actor may consequently lose permission to poll the job that
performed it; use the local Unix-socket CLI for full recovery restores.

## Resource groups

- `/auth/*`: bootstrap, login, password, session, logout, and TOTP.
- `/status`, `/health`, `/metrics`: runtime observations.
- `/config/*` and `/network/*`: validation, reload, transactional network
  apply, confirmation, and rollback.
- `/policies/destinations`, `/domains`, and `/policies/simulate`: policy rules
  and dry evaluation.
- `/blocklists` and `/sources/*`: local imports and remote source lifecycle.
- `/events`, `/audit`, and `/audit/verify`: bounded operational history.
- `/users/*` and `/tokens/*`: identities, roles, TOTP removal, and API tokens.
- `/certificates/*`: inspection, replacement, and CSR creation.
- `/mtls/authorities` and `/mtls/mappings/*`: client trust and revocable
  certificate identities for remote automation.
- `/backups/*` and `/diagnostics`: protected recovery and support artifacts.
- `/logging` and `/logging/traces`: revisioned runtime configuration,
  bounded counters, and the operator trace window.
- `/service/restart`, `/system/reboot`, and `/system/shutdown`: explicit
  lifecycle actions.

Validate the contract with:

```sh
cmake --build --preset debug --target openapi-check
```

API consumers should pin the `/api/v1` contract, tolerate added response
fields, reject unknown enum values locally, and never record passwords,
tokens, passphrases, cookies, TOTP seeds, or private keys.
