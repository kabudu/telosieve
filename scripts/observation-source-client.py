#!/usr/bin/env python3
"""Bounded client for one local observation producer relay."""

import argparse
import socket
from pathlib import Path

MAX_TOKEN_BYTES = 128
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 6


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    socket_path = Path(arguments.socket)
    token_path = Path(arguments.token)
    if not socket_path.is_absolute() or not token_path.is_absolute():
        raise SystemExit("observation-source-client: paths must be absolute")
    if socket_path.is_symlink() or not socket_path.is_socket():
        raise SystemExit("observation-source-client: socket is invalid")
    if token_path.is_symlink() or not token_path.is_file():
        raise SystemExit("observation-source-client: token is invalid")
    metadata = token_path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > MAX_TOKEN_BYTES:
        raise SystemExit("observation-source-client: token is invalid")
    if metadata.st_mode & 0o007 or metadata.st_mode & 0o220:
        raise SystemExit("observation-source-client: token permissions are unsafe")
    token = token_path.read_bytes()
    if not 32 <= len(token) <= MAX_TOKEN_BYTES or b"\n" in token:
        raise SystemExit("observation-source-client: token is invalid")
    response = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        connection.connect(str(socket_path))
        method = b"CHECK" if arguments.check else b"OBSERVE"
        connection.sendall(method + b" " + token + b"\n")
        while len(response) <= MAX_RESPONSE_BYTES:
            part = connection.recv(min(64 * 1024, MAX_RESPONSE_BYTES + 1 - len(response)))
            if not part:
                break
            response.extend(part)
    if not response or len(response) > MAX_RESPONSE_BYTES:
        raise SystemExit("observation-source-client: relay refused or exceeded response bound")
    if arguments.check:
        if response != b"READY\n":
            raise SystemExit("observation-source-client: relay readiness response is invalid")
        print('{"schema_version":"telosieve.observation-relay-health/v1","status":"ready"}')
        return 0
    print(response.decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
