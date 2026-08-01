#!/usr/bin/env python3
"""Bounded Unix-socket relay for an observation producer identity."""

import argparse
import hmac
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_CONFIG_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 128
MAX_REQUEST_BYTES = MAX_TOKEN_BYTES + 9
MAX_ARGUMENTS = 32
MAX_ARGUMENT_BYTES = 4096
MAX_STDOUT_BYTES = 5 * 1024 * 1024
MAX_STDERR_BYTES = 16 * 1024
PRODUCER_TIMEOUT_SECONDS = 5
SOCKET_BACKLOG = 4


def prepare_socket(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SystemExit("observation-source-relay: unsafe existing socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.1)
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        path.unlink(missing_ok=True)
        return
    except OSError as error:
        raise SystemExit("observation-source-relay: cannot verify existing socket") from error
    finally:
        probe.close()
    raise SystemExit("observation-source-relay: socket is already active")


def strict_json(path: Path) -> dict:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit("observation-source-relay: invalid configuration path")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_mode & 0o022:
        raise SystemExit("observation-source-relay: unsafe configuration permissions")
    data = path.read_bytes()
    if len(data) > MAX_CONFIG_BYTES:
        raise SystemExit("observation-source-relay: oversized configuration")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key {key}")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit("observation-source-relay: invalid configuration JSON") from error
    fields = {"schema_version", "socket_path", "token_path", "producer"}
    producer_fields = {"executable_path", "arguments"}
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != "telosieve.observation-relay/v1"
        or not isinstance(value.get("socket_path"), str)
        or not isinstance(value.get("token_path"), str)
        or not isinstance(value.get("producer"), dict)
        or set(value["producer"]) != producer_fields
        or not isinstance(value["producer"].get("executable_path"), str)
    ):
        raise SystemExit("observation-source-relay: invalid configuration shape")
    return value


def bounded_regular(path_value: str, maximum: int, label: str) -> tuple[Path, os.stat_result]:
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit(f"observation-source-relay: invalid {label}")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > maximum:
        raise SystemExit(f"observation-source-relay: invalid {label}")
    return path, metadata


def validate(value: dict) -> tuple[Path, bytes, Path, list[str]]:
    socket_path = Path(value["socket_path"])
    if not socket_path.is_absolute() or not socket_path.parent.is_dir():
        raise SystemExit("observation-source-relay: unsafe socket path")
    parent_mode = socket_path.parent.stat().st_mode
    if parent_mode & 0o027:
        raise SystemExit("observation-source-relay: unsafe socket directory permissions")
    prepare_socket(socket_path)
    token_path, token_metadata = bounded_regular(value["token_path"], MAX_TOKEN_BYTES, "token")
    if token_metadata.st_mode & 0o007 or token_metadata.st_mode & 0o220:
        raise SystemExit("observation-source-relay: unsafe token permissions")
    token = token_path.read_bytes()
    if not 32 <= len(token) <= MAX_TOKEN_BYTES or b"\n" in token:
        raise SystemExit("observation-source-relay: invalid token")
    producer = value["producer"]
    executable, executable_metadata = bounded_regular(
        producer["executable_path"], 128 * 1024 * 1024, "producer executable"
    )
    if executable_metadata.st_mode & 0o111 == 0 or executable_metadata.st_mode & 0o022:
        raise SystemExit("observation-source-relay: unsafe producer executable")
    arguments = producer["arguments"]
    if (
        not isinstance(arguments, list)
        or len(arguments) > MAX_ARGUMENTS
        or any(
            not isinstance(argument, str)
            or not argument
            or len(argument) > MAX_ARGUMENT_BYTES
            or any(ord(character) < 32 or ord(character) == 127 for character in argument)
            for argument in arguments
        )
    ):
        raise SystemExit("observation-source-relay: invalid producer arguments")
    return socket_path, token, executable, arguments


def invoke(executable: Path, arguments: list[str]) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                [str(executable), *arguments], stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, check=False,
                timeout=PRODUCER_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("producer timed out") from error
        if result.returncode or stdout.tell() > MAX_STDOUT_BYTES or stderr.tell() > MAX_STDERR_BYTES:
            raise RuntimeError("producer failed or exceeded output bounds")
        stdout.seek(0)
        return stdout.read(MAX_STDOUT_BYTES + 1)


def serve(connection: socket.socket, token: bytes, executable: Path, arguments: list[str]) -> None:
    connection.settimeout(1)
    request = b""
    while len(request) <= MAX_REQUEST_BYTES:
        part = connection.recv(MAX_REQUEST_BYTES + 1 - len(request))
        if not part:
            break
        request += part
        if request.endswith(b"\n"):
            request = request[:-1]
            break
    try:
        method, supplied = request.split(b" ", 1)
    except ValueError:
        return
    if not hmac.compare_digest(supplied, token):
        return
    if method == b"CHECK":
        connection.sendall(b"READY\n")
        return
    if method != b"OBSERVE":
        return
    try:
        output = invoke(executable, arguments)
    except RuntimeError as error:
        print(f"observation-source-relay: {error}", file=sys.stderr, flush=True)
        return
    connection.sendall(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    socket_path, token, executable, producer_arguments = validate(
        strict_json(Path(arguments.config))
    )
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_identity = None

    def terminate(_signal, _frame) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        server.bind(str(socket_path))
        socket_identity = socket_path.lstat().st_ino
        os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
        server.listen(SOCKET_BACKLOG)
        while True:
            connection, _ = server.accept()
            with connection:
                serve(connection, token, executable, producer_arguments)
    finally:
        server.close()
        try:
            metadata = socket_path.lstat()
            if stat.S_ISSOCK(metadata.st_mode) and metadata.st_ino == socket_identity:
                socket_path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
