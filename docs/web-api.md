<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Management API

The versioned API is rooted at `/api/v1` and served only through management
HTTPS by default. `api/openapi.yaml` is the normative OpenAPI 3.1 contract.

## Authentication and request rules

Interactive clients authenticate through `/auth/login` and use the secure
session cookie plus the returned CSRF value for every state-changing request.
Automation sends `Authorization: Bearer TOKEN`. Deployments may additionally
require a validated client certificate.

Requests must use the configured management host, an accepted media type, and
bounded JSON. Unknown object fields, invalid UTF-8, trailing content, and
unsupported methods are rejected. Responses use JSON and carry a request
identifier suitable for audit correlation.

```http
GET /api/v1/status HTTP/1.1
Host: 192.168.77.1
Authorization: Bearer <token>
Accept: application/json
```

## Revisions and errors

Mutable resources expose a revision. Update and delete requests must present
the revision they read. A stale value returns HTTP `409`, allowing clients to
refetch rather than overwrite another operator's work.

Errors contain a stable machine code, a concise message, and the request
identifier. Authentication and role failures use `401` and `403`; schema
failures use `400` or `422`; missing resources use `404`; rate limiting uses
`429`; internal or temporarily unavailable operations use `5xx`.

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
- `/backups/*` and `/diagnostics`: protected recovery and support artifacts.
- `/service/restart`, `/system/reboot`, and `/system/shutdown`: explicit
  lifecycle actions.

Validate the contract with:

```sh
cmake --build --preset debug --target openapi-check
```

API consumers should pin the `/api/v1` contract, tolerate added response
fields, reject unknown enum values locally, and never record passwords,
tokens, passphrases, cookies, TOTP seeds, or private keys.
