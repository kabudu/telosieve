#!/usr/bin/env python3
"""Bounded Redis read-only collection for Telosieve integration processes."""

from __future__ import annotations

import json
import os
import socket
import stat
from pathlib import Path


CONTRACT = "telosieve.integration-contract/v1"
REQUEST_SCHEMA = "telosieve.integration-request/v1"
RESPONSE_SCHEMA = "telosieve.integration-response/v1"
CREDENTIAL_SCHEMA = "telosieve.redis-credentials/v1"
MAX_CREDENTIAL_BYTES = 4096
MAX_NETWORK_BYTES = 2 * 1024 * 1024
MAX_BULK_BYTES = 4096
MAX_ARRAY_ITEMS = 512
MAX_REPLICAS = 64
MAX_VALUES = 256
MAX_TEXT_BYTES = 128
SOCKET_TIMEOUT_SECONDS = 1.0


class RedisIntegrationError(Exception):
    """Expected fail-closed collector rejection."""


def strict_json(value: bytes, label: str) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise RedisIntegrationError(f"{label} contains duplicate key {key!r}")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RedisIntegrationError(f"{label} JSON is invalid") from error


def valid_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_TEXT_BYTES
        and all(character.isascii() and (character.isalnum() or character in "._:/-") for character in value)
    )


def credentials(path_value: str) -> tuple[str, str]:
    path = Path(path_value)
    if not path.is_absolute():
        raise RedisIntegrationError("credential file must be an absolute regular file")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise RedisIntegrationError("credential file cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_CREDENTIAL_BYTES
            or metadata.st_mode & 0o077
        ):
            raise RedisIntegrationError("credential file ownership boundary is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            credential_bytes = stream.read(MAX_CREDENTIAL_BYTES + 1)
        if len(credential_bytes) > MAX_CREDENTIAL_BYTES:
            raise RedisIntegrationError("credential file exceeds bound")
    finally:
        os.close(descriptor)
    value = strict_json(credential_bytes, "credential file")
    if not isinstance(value, dict) or set(value) != {"schema_version", "username", "password"}:
        raise RedisIntegrationError("credential file shape is invalid")
    username, password = value.get("username"), value.get("password")
    if value.get("schema_version") != CREDENTIAL_SCHEMA or not valid_text(username):
        raise RedisIntegrationError("credential file identity is invalid")
    if not isinstance(password, str) or not 16 <= len(password) <= 128 or any(ord(character) < 32 or ord(character) == 127 for character in password):
        raise RedisIntegrationError("credential secret is invalid")
    return username, password


class RedisConnection:
    def __init__(self, host: str, port: int):
        if host not in {"127.0.0.1", "::1"} or not 1 <= port <= 65535:
            raise RedisIntegrationError("only a bounded loopback Redis endpoint is supported")
        try:
            self.socket = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS)
            self.socket.settimeout(SOCKET_TIMEOUT_SECONDS)
        except OSError as error:
            raise RedisIntegrationError("Redis connection failed") from error
        self.buffer = bytearray()
        self.received = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.socket.close()

    def command(self, *parts: str):
        if not parts or any(not isinstance(part, str) or not part or len(part.encode()) > MAX_BULK_BYTES for part in parts):
            raise RedisIntegrationError("Redis command exceeds bounds")
        encoded = [part.encode() for part in parts]
        request = bytearray(f"*{len(encoded)}\r\n".encode())
        for part in encoded:
            request.extend(f"${len(part)}\r\n".encode())
            request.extend(part)
            request.extend(b"\r\n")
        try:
            self.socket.sendall(request)
            return self._response(0)
        except (OSError, UnicodeDecodeError) as error:
            raise RedisIntegrationError("Redis protocol failed") from error

    def transaction(self, commands: list[tuple[str, ...]]) -> list[object]:
        if not commands or len(commands) > MAX_REPLICAS + 4:
            raise RedisIntegrationError("Redis transaction exceeds command bound")
        if self.command("MULTI") != "OK":
            raise RedisIntegrationError("Redis transaction did not start")
        for command in commands:
            if self.command(*command) != "QUEUED":
                raise RedisIntegrationError("Redis transaction command was not queued")
        response = self.command("EXEC")
        if not isinstance(response, list) or len(response) != len(commands):
            raise RedisIntegrationError("Redis transaction response is incomplete")
        return response

    def _more(self) -> None:
        if self.received >= MAX_NETWORK_BYTES:
            raise RedisIntegrationError("Redis response exceeds total byte bound")
        chunk = self.socket.recv(min(8192, MAX_NETWORK_BYTES - self.received + 1))
        if not chunk:
            raise RedisIntegrationError("Redis response ended early")
        self.received += len(chunk)
        if self.received > MAX_NETWORK_BYTES:
            raise RedisIntegrationError("Redis response exceeds total byte bound")
        self.buffer.extend(chunk)

    def _line(self) -> bytes:
        while True:
            marker = self.buffer.find(b"\r\n")
            if marker >= 0:
                line = bytes(self.buffer[:marker])
                del self.buffer[: marker + 2]
                if len(line) > MAX_BULK_BYTES:
                    raise RedisIntegrationError("Redis line exceeds bound")
                return line
            self._more()

    def _exact(self, size: int) -> bytes:
        if size < 0 or size > MAX_BULK_BYTES:
            raise RedisIntegrationError("Redis bulk response exceeds bound")
        while len(self.buffer) < size + 2:
            self._more()
        value = bytes(self.buffer[:size])
        if self.buffer[size : size + 2] != b"\r\n":
            raise RedisIntegrationError("Redis bulk terminator is invalid")
        del self.buffer[: size + 2]
        return value

    def _response(self, depth: int):
        if depth > 2:
            raise RedisIntegrationError("Redis response nesting exceeds bound")
        while not self.buffer:
            self._more()
        prefix = chr(self.buffer.pop(0))
        if prefix == "+":
            return self._line().decode("utf-8")
        if prefix == "-":
            detail = self._line().decode("utf-8", errors="replace")[:256]
            raise RedisIntegrationError(f"Redis refused command: {detail}")
        if prefix == ":":
            try:
                return int(self._line())
            except ValueError as error:
                raise RedisIntegrationError("Redis integer is invalid") from error
        if prefix == "$":
            try:
                size = int(self._line())
            except ValueError as error:
                raise RedisIntegrationError("Redis bulk length is invalid") from error
            return None if size == -1 else self._exact(size).decode("utf-8")
        if prefix == "*":
            try:
                count = int(self._line())
            except ValueError as error:
                raise RedisIntegrationError("Redis array length is invalid") from error
            if not 0 <= count <= MAX_ARRAY_ITEMS:
                raise RedisIntegrationError("Redis array exceeds bound")
            return [self._response(depth + 1) for _ in range(count)]
        raise RedisIntegrationError("Redis response type is unsupported")


def pairs(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, list) or len(value) % 2 or len(value) // 2 > MAX_VALUES:
        raise RedisIntegrationError(f"{label} map shape exceeds bounds")
    result: dict[str, str] = {}
    for index in range(0, len(value), 2):
        key, item = value[index], value[index + 1]
        if not valid_text(key) or not isinstance(item, str) or not item or len(item.encode()) > MAX_BULK_BYTES or key in result:
            raise RedisIntegrationError(f"{label} map value is invalid")
        result[key] = item
    return dict(sorted(result.items()))


def collect(request: object, host: str, port: int, credential_path: str, prefix: str) -> bytes:
    fields = {"schema_version", "contract", "operation", "integration_id", "resource_kind", "target_id", "subject", "evaluation_time"}
    if not isinstance(request, dict) or set(request) != fields:
        raise RedisIntegrationError("integration request shape is invalid")
    if request.get("schema_version") != REQUEST_SCHEMA or request.get("contract") != CONTRACT or request.get("operation") != "observe":
        raise RedisIntegrationError("integration request protocol is invalid")
    for field in ("integration_id", "resource_kind", "target_id", "subject"):
        if not valid_text(request.get(field)):
            raise RedisIntegrationError("integration request identity is invalid")
    if not isinstance(request.get("evaluation_time"), int) or not 0 <= request["evaluation_time"] <= 2**63 - 1:
        raise RedisIntegrationError("integration request time is invalid")
    if not valid_text(prefix) or len(prefix) > 64:
        raise RedisIntegrationError("Redis key prefix is invalid")
    username, password = credentials(credential_path)
    with RedisConnection(host, port) as redis:
        if redis.command("AUTH", username, password) != "OK":
            raise RedisIntegrationError("Redis authentication failed")
        discovered_names = redis.command("SMEMBERS", f"{prefix}:replicas")
        if not isinstance(discovered_names, list) or not 1 <= len(discovered_names) <= MAX_REPLICAS:
            raise RedisIntegrationError("replica set exceeds bounds")
        if len(set(discovered_names)) != len(discovered_names) or any(not valid_text(name) for name in discovered_names):
            raise RedisIntegrationError("replica identity is invalid")
        names = sorted(discovered_names)
        responses = redis.transaction([
            ("GET", f"{prefix}:revision"),
            ("HGETALL", f"{prefix}:desired"),
            ("SMEMBERS", f"{prefix}:replicas"),
            *(("HGETALL", f"{prefix}:replica:{name}") for name in names),
        ])
        revision = responses[0]
        desired = pairs(responses[1], "desired")
        final_names = responses[2]
        if not isinstance(final_names, list) or sorted(final_names) != names:
            raise RedisIntegrationError("replica set changed during collection")
        replicas = {
            name: pairs(responses[index + 3], f"replica {name}")
            for index, name in enumerate(names)
        }
    if not valid_text(revision) or not desired:
        raise RedisIntegrationError("Redis snapshot is incomplete")
    response = {
        "schema_version": RESPONSE_SCHEMA,
        "integration_id": request["integration_id"],
        "resource_kind": request["resource_kind"],
        "subject": request["subject"],
        "captured_at": request["evaluation_time"],
        "capabilities": {
            "contract": CONTRACT,
            "operation": "observe",
            "credential_authority": "read_only",
            "target_mutated": False,
        },
        "target": {"id": request["target_id"], "revision": revision},
        "complete": True,
        "desired": desired,
        "observed": {"replicas": replicas},
    }
    return json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode()
