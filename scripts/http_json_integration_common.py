#!/usr/bin/env python3
"""Bounded HTTP/JSON collection for Telosieve Integration Contract v1."""
from __future__ import annotations

import http.client
import json
import os
import ssl
import stat
from pathlib import Path

CONTRACT = "telosieve.integration-contract/v1"
REQUEST_SCHEMA = "telosieve.integration-request/v1"
RESPONSE_SCHEMA = "telosieve.integration-response/v1"
CREDENTIAL_SCHEMA = "telosieve.http-json-credentials/v1"
TLS_CREDENTIAL_SCHEMA = "telosieve.http-json-mtls-credentials/v1"
SNAPSHOT_SCHEMA = "telosieve.http-json-snapshot/v1"
MAX_REQUEST_BYTES = 64 * 1024
MAX_CREDENTIAL_BYTES = 4096
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 128
MAX_VALUES = 256
MAX_REPLICAS = 64
SOCKET_TIMEOUT_SECONDS = 1.0


class HTTPJSONIntegrationError(Exception):
    """Expected fail-closed collector rejection."""


def strict_json(value: bytes, label: str) -> object:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise HTTPJSONIntegrationError(f"{label} contains duplicate key {key!r}")
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPJSONIntegrationError(f"{label} JSON is invalid") from error


def valid_text(value: object, maximum: int = MAX_TEXT_BYTES) -> bool:
    return (isinstance(value, str) and 0 < len(value.encode()) <= maximum
            and all(c.isascii() and (c.isalnum() or c in "._:/-") for c in value))


def credential(path_value: str) -> str:
    return credential_value(path_value, False)["bearer_token"]


def private_json(path_value: str, maximum: int = MAX_CREDENTIAL_BYTES) -> dict:
    path = Path(path_value)
    if not path.is_absolute():
        raise HTTPJSONIntegrationError("credential path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise HTTPJSONIntegrationError("credential file cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > maximum or metadata.st_mode & 0o077):
            raise HTTPJSONIntegrationError("credential file ownership boundary is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise HTTPJSONIntegrationError("credential file exceeds bound")
    value = strict_json(raw, "credential file")
    if not isinstance(value, dict):
        raise HTTPJSONIntegrationError("credential file shape is invalid")
    return value


def safe_tls_file(path_value: object, label: str, private: bool) -> str:
    if not isinstance(path_value, str): raise HTTPJSONIntegrationError(f"{label} path is invalid")
    path = Path(path_value)
    if not path.is_absolute(): raise HTTPJSONIntegrationError(f"{label} path must be absolute")
    try: descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error: raise HTTPJSONIntegrationError(f"{label} cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        unsafe = (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                  or metadata.st_size > 64 * 1024 or metadata.st_mode & 0o022)
        if private: unsafe = unsafe or bool(metadata.st_mode & 0o077)
        if unsafe: raise HTTPJSONIntegrationError(f"{label} boundary is unsafe")
    finally: os.close(descriptor)
    return str(path)


def credential_value(path_value: str, tls: bool) -> dict:
    value = private_json(path_value)
    expected = ({"schema_version", "bearer_token", "ca_certificate", "client_certificate", "client_key"}
                if tls else {"schema_version", "bearer_token"})
    schema = TLS_CREDENTIAL_SCHEMA if tls else CREDENTIAL_SCHEMA
    if set(value) != expected:
        raise HTTPJSONIntegrationError("credential file shape is invalid")
    token = value.get("bearer_token")
    if (value.get("schema_version") != schema or not isinstance(token, str)
            or not 24 <= len(token) <= 256 or not token.isascii()
            or any(not (c.isalnum() or c in "._~+-") for c in token)):
        raise HTTPJSONIntegrationError("credential token is invalid")
    if tls:
        value["ca_certificate"] = safe_tls_file(value["ca_certificate"], "CA certificate", False)
        value["client_certificate"] = safe_tls_file(value["client_certificate"], "client certificate", False)
        value["client_key"] = safe_tls_file(value["client_key"], "client key", True)
    return value


def bounded_map(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_VALUES:
        raise HTTPJSONIntegrationError(f"{label} exceeds bounds")
    result = {}
    for key, item in value.items():
        if (not valid_text(key) or not isinstance(item, str) or not item
                or len(item.encode()) > 4096):
            raise HTTPJSONIntegrationError(f"{label} value is invalid")
        result[key] = item
    return dict(sorted(result.items()))


def snapshot(value: object) -> tuple[str, dict[str, str], dict[str, dict[str, str]]]:
    fields = {"schema_version", "revision", "complete", "desired", "replicas"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != SNAPSHOT_SCHEMA:
        raise HTTPJSONIntegrationError("HTTP snapshot shape is invalid")
    if value.get("complete") is not True or not valid_text(value.get("revision")):
        raise HTTPJSONIntegrationError("HTTP snapshot is incomplete")
    desired = bounded_map(value.get("desired"), "desired map")
    replicas_value = value.get("replicas")
    if not isinstance(replicas_value, dict) or not 1 <= len(replicas_value) <= MAX_REPLICAS:
        raise HTTPJSONIntegrationError("replica map exceeds bounds")
    replicas = {}
    for name, values in replicas_value.items():
        if not valid_text(name):
            raise HTTPJSONIntegrationError("replica identity is invalid")
        replicas[name] = bounded_map(values, "replica map")
    return value["revision"], desired, dict(sorted(replicas.items()))


def get_snapshot(host: str, port: int, path: str, credential_path: str, transport: str = "http"):
    if host not in {"127.0.0.1", "::1"} or not 1 <= port <= 65535:
        raise HTTPJSONIntegrationError("only a bounded loopback HTTP endpoint is supported")
    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 256
            or "?" in path or "#" in path or any(ord(c) < 33 or ord(c) > 126 for c in path)):
        raise HTTPJSONIntegrationError("HTTP path is invalid")
    if transport not in {"http", "https"}: raise HTTPJSONIntegrationError("HTTP transport is invalid")
    material = credential_value(credential_path, transport == "https"); token = material["bearer_token"]
    if transport == "https":
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3; context.verify_mode = ssl.CERT_REQUIRED; context.check_hostname = True
            context.load_verify_locations(cafile=material["ca_certificate"])
            context.load_cert_chain(material["client_certificate"], material["client_key"])
        except (OSError, ssl.SSLError) as error: raise HTTPJSONIntegrationError("TLS credential setup failed") from error
        connection = http.client.HTTPSConnection(host, port, timeout=SOCKET_TIMEOUT_SECONDS, context=context)
    else: connection = http.client.HTTPConnection(host, port, timeout=SOCKET_TIMEOUT_SECONDS)
    try:
        connection.request("GET", path, headers={"Authorization": f"Bearer {token}",
                           "Accept": "application/json", "Connection": "close",
                           "User-Agent": "telosieve-http-json/1"})
        response = connection.getresponse()
        if response.status != 200:
            raise HTTPJSONIntegrationError("HTTP endpoint refused the read")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPJSONIntegrationError("HTTP content type is invalid")
        lengths = response.headers.get_all("Content-Length", [])
        if (response.getheader("Transfer-Encoding") is not None or len(lengths) != 1
                or not lengths[0].isdigit() or int(lengths[0]) > MAX_RESPONSE_BYTES):
            raise HTTPJSONIntegrationError("HTTP response length is invalid")
        length = lengths[0]
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) != int(length) or len(body) > MAX_RESPONSE_BYTES:
            raise HTTPJSONIntegrationError("HTTP response is incomplete or oversized")
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise HTTPJSONIntegrationError("HTTP transport failed") from error
    finally:
        connection.close()
    return snapshot(strict_json(body, "HTTP snapshot"))


def collect(request: object, host: str, port: int, path: str, credential_path: str, transport: str = "http") -> bytes:
    fields = {"schema_version", "contract", "operation", "integration_id", "resource_kind",
              "target_id", "subject", "evaluation_time"}
    if not isinstance(request, dict) or set(request) != fields:
        raise HTTPJSONIntegrationError("integration request shape is invalid")
    if (request.get("schema_version") != REQUEST_SCHEMA or request.get("contract") != CONTRACT
            or request.get("operation") != "observe"):
        raise HTTPJSONIntegrationError("integration request protocol is invalid")
    if any(not valid_text(request.get(field)) for field in ("integration_id", "resource_kind", "target_id", "subject")):
        raise HTTPJSONIntegrationError("integration request identity is invalid")
    if (not isinstance(request.get("evaluation_time"), int)
            or isinstance(request.get("evaluation_time"), bool)
            or not 0 <= request["evaluation_time"] <= 2**63 - 1):
        raise HTTPJSONIntegrationError("integration request time is invalid")
    revision, desired, replicas = get_snapshot(host, port, path, credential_path, transport)
    response = {"schema_version": RESPONSE_SCHEMA, "integration_id": request["integration_id"],
        "resource_kind": request["resource_kind"], "subject": request["subject"],
        "captured_at": request["evaluation_time"],
        "capabilities": {"contract": CONTRACT, "operation": "observe",
                         "credential_authority": "read_only", "target_mutated": False},
        "target": {"id": request["target_id"], "revision": revision}, "complete": True,
        "desired": desired, "observed": {"replicas": replicas}}
    return json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode()
