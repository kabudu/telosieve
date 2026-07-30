#!/usr/bin/env python3
"""Bounded authenticated loopback artifact endpoint for local qualification."""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_ARTIFACT_BYTES = 64 * 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument(
        "--mode", choices=("normal", "delay", "drop", "oversized"), default="normal"
    )
    parser.add_argument("--delay-ms", type=int, default=0)
    arguments = parser.parse_args()
    if not arguments.token or len(arguments.token) > 128:
        raise SystemExit("witness-endpoint: invalid token")
    with open(arguments.artifact, "rb") as stream:
        artifact = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(artifact) > MAX_ARTIFACT_BYTES and arguments.mode != "oversized":
        raise SystemExit("witness-endpoint: artifact exceeds bound")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/artifact":
                self.send_error(404)
                return
            if self.headers.get("Authorization") != f"Bearer {arguments.token}":
                self.send_error(401)
                return
            if arguments.mode == "drop":
                self.connection.shutdown(2)
                self.connection.close()
                return
            if arguments.mode == "delay":
                time.sleep(max(0, arguments.delay_ms) / 1000)
            body = (
                b"x" * (MAX_ARTIFACT_BYTES + 1)
                if arguments.mode == "oversized"
                else artifact
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_arguments: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    print(
        json.dumps(
            {"schema_version": "telosieve.witness-endpoint/v1", "port": server.server_port},
            separators=(",", ":"),
        ),
        flush=True,
    )
    server.serve_forever(poll_interval=0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
