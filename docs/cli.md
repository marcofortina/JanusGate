<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Command-line administration

By default, `janusgatectl` performs the complete command set through the local
Unix-domain control socket. Local administration is authorized by Unix peer
credentials and must run as root:

```sh
sudo janusgatectl status
```

Specify `--endpoint` to use the remote HTTPS management API on TCP 9443.
Remote requests require both an API token and a client certificate:

```sh
janusgatectl --endpoint https://192.168.77.1:9443 \
  --token-file /secure/janusgate.token \
  --client-cert /secure/operator.pem \
  --client-key /secure/operator.key \
  --ca-file /secure/root-ca.pem status
```

`--token-file`, `--client-cert`, and `--client-key` are mandatory with
`--endpoint`. `--ca-file` is optional when the server identity is already in
the system trust store. These options and `--timeout` apply only to remote
requests. Secret and passphrase files must be regular, caller-owned, private
files. `--timeout` accepts 1–300 seconds. `--json` selects stable compact
output; `--quiet`, `--verbose`, `--yes`, and `--include-private-key` control
output and explicit high-impact operations.

## Read operations

- `status`, `health`, and `stats` report appliance, service, policy, and metric
  state.
- `network show` reports the active network document.
- `policy list` and `policy show KIND ID` inspect domain or destination rules.
- `blocklist list`, `blocklist export`, and `source list` inspect list state.
- `events [QUERY]` and `audit [QUERY]` accept a bounded query string;
  `audit verify` validates the chain.
- `user list`, `token list`, `certificate show`, `mtls ca show`, and
  `mtls mapping list` inspect access and TLS state.
- `backup inspect ID` reports a stored backup without restoring it.
- `logging show` reports configuration, expiry, buffered records, and
  suppression; `logging traces` returns the bounded live trace window.

## Network and policy writes

- `network validate FILE` performs schema and semantic checks only.
- `network apply FILE` or `network set FILE` starts a transactional change.
  Complete it with `network confirm`, or use `network rollback`.
- `policy add KIND FILE`, `policy update KIND ID FILE`, and
  `policy remove KIND ID` manage typed rules; `policy explain FILE` evaluates
  and explains a proposed query without changing state. The older
  `policy simulate FILE` spelling remains available.
- `domain block DOMAIN`, `domain allow DOMAIN`, and `domain remove ID` are
  concise domain-rule operations.
- `blocklist import SOURCE FILE` imports a local list.
- `source add FILE`, `source update ID FILE`, `source refresh ID`,
  `source enable ID`, and `source disable ID` manage remote list sources.

Blocklist imports and remote refreshes submit bounded asynchronous jobs. The
CLI waits for their retained results while the daemon continues serving short
management requests.

## Identities, certificates, and recovery data

- `user add FILE`, `user update ID FILE`, `user disable ID`,
  `user password ID FILE`, and `user totp ID` manage operator identities.
- `token create FILE` returns a new secret once; `token revoke ID` invalidates
  it.
- `certificate install FILE` performs a transactional PEM replacement;
  `certificate csr FILE` creates a signing request.
- `mtls ca install FILE` and `mtls ca remove` manage the remote client trust
  store. `mtls mapping add FILE user ID` or `mtls mapping add FILE role ROLE`
  binds one client leaf; `mtls mapping revoke ID` invalidates it.
- `backup create configuration` creates a non-secret backup.
- `backup create full` requires `--passphrase-file`; private-key inclusion also
  requires `--include-private-key`.
- `backup restore ID` requires the matching passphrase for an encrypted
  backup, performs a dry run, and creates an audited checkpoint before
  applying changes.
- `diagnostics create` creates a bounded diagnostic archive.

CSR generation, backup creation and restore, and diagnostic archive creation
use the same bounded job queue; the CLI waits for completion before presenting
or saving the result. An applied restore temporarily excludes other management
writes. Full restores replace users, sessions, tokens, TOTP credentials, and
mTLS mappings, so a remote caller can lose authorization before reading the
job result. Run full recovery restores through the default local socket from a
retained console.

## Runtime operations

- `config validate` checks active configuration; `config reload` publishes it.
- `logging set FILE` revision-checks and activates a strict logging document.
  Debug or trace levels require a 60–3600 second duration; identifier inclusion
  is accepted only during that interval.
- `service restart`, `system reboot`, and `system shutdown` require `--yes`
  in non-interactive use.
- `--socket PATH ping` verifies the local daemon protocol.
- `--socket PATH policy reload` requests a local policy rebuild.
- `--version` prints version, source revision, compiler, and target metadata.

## Exit status

`0` means success, `1` a request or local failure, `2` invalid command syntax,
`3` an authentication or authorization failure, `4` a revision conflict, and
`5` an unavailable service. Scripts should consume `--json` and the exit
status rather than human-readable text. The installed
`janusgatectl(1)` page is the concise offline reference.

The configuration example, component names, and safe troubleshooting sequence
are documented in [Operations](operations.md). Private and home-lab CA setup is
documented in [Remote API](remote-api.md).
