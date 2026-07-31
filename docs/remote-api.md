<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Remote API and private certificate authorities

JanusGate deliberately separates interactive browser administration from
remote automation:

| Client | Port | Authentication |
| --- | --- | --- |
| Web browser | 443/8443 | Password, optional TOTP, session, CSRF |
| Remote CLI/API | 9443 | Trusted client certificate and token |
| Local CLI | Unix socket | Root peer credentials |

The browser listener never requests a client certificate. The remote listener
is absent until `/etc/janusgate/certs/client-ca.pem` contains a valid trust
bundle. Every accepted remote request must then satisfy all of these checks:

1. CivetWeb validates the client chain against the installed CA bundle.
2. JanusGate maps the exact leaf SHA-256 fingerprint to a local user or role.
3. The bearer token is current, scoped, rate-limited, and owned by that user or
   by a current member of that role.

Revoking either the mapping or token immediately denies the request. Removing
the CA bundle disables TCP 9443 when the HTTPS listeners reload. Authentication
routes and WebGUI assets are never exposed through the remote listener.

## Supported authorities

Public, enterprise, private, self-hosted, and home-lab authorities are treated
identically. The PEM trust store may contain one root CA or a root plus one or
more intermediate CAs. Every entry must assert the CA basic constraint.
JanusGate rejects duplicate certificates, leaf certificates, private keys,
CRLs, malformed trailing data, and bundles containing more than 64 CAs.

A private CA is often the simplest and most appropriate choice for a home lab.
Keep its private key offline or on a dedicated administration host; upload only
the public CA certificate bundle to JanusGate.

## Minimal home-lab CA with OpenSSL

The following example creates a private root and one client identity. Run it on
a trusted administration system, not on the appliance:

```sh
umask 077
mkdir janusgate-home-ca
cd janusgate-home-ca

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out root-ca.key
openssl req -new -x509 -sha256 -days 3650 \
  -key root-ca.key -out root-ca.pem \
  -subj "/CN=JanusGate Home CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out operator.key
openssl req -new -sha256 -key operator.key -out operator.csr \
  -subj "/CN=JanusGate remote operator"
openssl x509 -req -sha256 -days 397 \
  -in operator.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
  -out operator.pem -extfile /dev/stdin <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl verify -CAfile root-ca.pem -purpose sslclient operator.pem
```

Protect `root-ca.key` and `operator.key` with mode `0600`. Delete the CSR and
serial file when they are no longer needed. Issue a separate client certificate
for each automation identity so it can be revoked independently.

## Enable remote administration

Use the Certificates page to install `root-ca.pem`, upload `operator.pem`, and
map it to a specific user or to a role. The page reloads the HTTPS listeners
after a trust-store change. Create a least-privilege API token on the Users and
access page and store its one-time secret in a caller-owned mode `0600` file.

The same bootstrap can be performed locally:

```json
{
  "user_id": 1,
  "name": "remote administration",
  "scopes": "status:read",
  "expires_at": null,
  "source_network": null,
  "requests_per_minute": 60
}
```

Save that document as `/secure/remote-token.json`, adjusting its owner, scopes,
expiry, and source network for the intended automation. Then run:

```sh
sudo janusgatectl --yes mtls ca install /secure/root-ca.pem
sudo janusgatectl mtls mapping add /secure/operator.pem user 1
sudo janusgatectl token create /secure/remote-token.json
```

Copy the displayed one-time token secret, and only that secret, to
`/secure/janusgate.token` with mode `0600`.

Trust-store changes made through the local control socket require restarting
`janusgate-web` with the operating-system service manager:

```sh
rc-service janusgate-web restart       # Alpine
systemctl restart janusgate-web        # systemd
rcctl restart janusgate_web            # OpenBSD
```

Connect to the dedicated endpoint after placing the token, client certificate,
and key on the remote administration host:

```sh
janusgatectl --endpoint https://192.168.77.1:9443 \
  --token-file /secure/janusgate.token \
  --client-cert /secure/operator.pem \
  --client-key /secure/operator.key \
  --ca-file /secure/root-ca.pem status
```

`--ca-file` is optional when the HTTPS server certificate is already trusted by
the host system. It authenticates the JanusGate server and is independent of
the client CA bundle installed on the appliance.

List and revoke client identities locally with:

```sh
sudo janusgatectl mtls mapping list
sudo janusgatectl --yes mtls mapping revoke 1
```

Use a user mapping when one certificate belongs to one automation principal.
Role mappings are convenient for centrally issued operator certificates but
follow the current role of the token owner, so role changes affect access.
