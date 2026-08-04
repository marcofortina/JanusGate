# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Serve one blocking HTTPS webhook request for the integration tests."""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import ssl
import time

MAX_BODY_SIZE = 1_048_576
WAIT_SECONDS = 10.0


def write_private_json(path: Path, value: object) -> None:
    """Atomically write one private JSON fixture file."""
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


class WebhookServer(http.server.HTTPServer):
    """Hold the synchronization paths and outcome for one request."""

    capture_path: Path
    release_path: Path
    succeeded = False


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    """Capture one request, then wait until the parent releases its response."""

    server: WebhookServer

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        """Capture a bounded webhook POST and return HTTP 204 when released."""
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_SIZE:
            self.send_error(http.HTTPStatus.BAD_REQUEST)
            return

        body = self.rfile.read(length)
        capture = {
            "body": body.decode("utf-8"),
            "content_type": self.headers.get("Content-Type"),
            "event_id": self.headers.get("X-JanusGate-Event-ID"),
            "method": self.command,
            "path": self.path,
            "signature": self.headers.get("X-JanusGate-Signature"),
            "signature_version": self.headers.get(
                "X-JanusGate-Signature-Version"
            ),
            "timestamp": self.headers.get("X-JanusGate-Timestamp"),
        }
        write_private_json(self.server.capture_path, capture)

        deadline = time.monotonic() + WAIT_SECONDS
        while not self.server.release_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not self.server.release_path.exists():
            self.send_error(http.HTTPStatus.GATEWAY_TIMEOUT)
            return

        self.send_response(http.HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.server.succeeded = True

    def log_message(self, format_string: str, *arguments: object) -> None:
        """Keep the test output free of routine HTTP access messages."""


def parse_arguments() -> argparse.Namespace:
    """Parse the isolated receiver paths supplied by the C test."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--port", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    """Serve exactly one loopback HTTPS request."""
    arguments = parse_arguments()
    server = WebhookServer(("127.0.0.1", 0), WebhookHandler)
    server.capture_path = arguments.capture
    server.release_path = arguments.release
    server.timeout = WAIT_SECONDS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(arguments.certificate)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    write_private_json(arguments.port, {"port": server.server_port})
    try:
        server.handle_request()
    finally:
        server.server_close()
    return 0 if server.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
