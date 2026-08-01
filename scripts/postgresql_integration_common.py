#!/usr/bin/env python3
"""Bounded PostgreSQL collection for Telosieve Integration Contract v1."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path


CONTRACT = "telosieve.integration-contract/v1"
REQUEST_SCHEMA = "telosieve.integration-request/v1"
RESPONSE_SCHEMA = "telosieve.integration-response/v1"
CREDENTIAL_SCHEMA = "telosieve.postgresql-credentials/v1"
MAX_CREDENTIAL_BYTES = 4096
MAX_STDOUT_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_TEXT_BYTES = 128
COMMAND_TIMEOUT_SECONDS = 3


class PostgreSQLIntegrationError(Exception):
    """Expected fail-closed collector rejection."""


def strict_json(value: bytes, label: str) -> object:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise PostgreSQLIntegrationError(f"{label} contains duplicate key {key!r}")
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PostgreSQLIntegrationError(f"{label} JSON is invalid") from error


def valid_text(value: object, maximum: int = MAX_TEXT_BYTES) -> bool:
    return (
        isinstance(value, str) and 0 < len(value) <= maximum
        and all(character.isascii() and (character.isalnum() or character in "._:/-") for character in value)
    )


def bounded_private_json(path_value: str) -> dict:
    path = Path(path_value)
    if not path.is_absolute():
        raise PostgreSQLIntegrationError("credential path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise PostgreSQLIntegrationError("credential file cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > MAX_CREDENTIAL_BYTES or metadata.st_mode & 0o077):
            raise PostgreSQLIntegrationError("credential file ownership boundary is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(MAX_CREDENTIAL_BYTES + 1)
        if len(value) > MAX_CREDENTIAL_BYTES:
            raise PostgreSQLIntegrationError("credential file exceeds bound")
    finally:
        os.close(descriptor)
    parsed = strict_json(value, "credential file")
    if not isinstance(parsed, dict):
        raise PostgreSQLIntegrationError("credential file must be an object")
    return parsed


def credentials(path_value: str) -> tuple[str, str]:
    value = bounded_private_json(path_value)
    if set(value) != {"schema_version", "username", "password"}:
        raise PostgreSQLIntegrationError("credential file shape is invalid")
    username, password = value.get("username"), value.get("password")
    if value.get("schema_version") != CREDENTIAL_SCHEMA or not valid_text(username, 63):
        raise PostgreSQLIntegrationError("credential identity is invalid")
    if not isinstance(password, str) or not 16 <= len(password) <= 128 or not password.isascii() or not password.isalnum():
        raise PostgreSQLIntegrationError("credential secret is invalid")
    return username, password


def executable(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PostgreSQLIntegrationError("psql must be an absolute regular file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_mode & 0o022 or metadata.st_mode & 0o111 == 0:
        raise PostgreSQLIntegrationError("psql executable boundary is unsafe")
    return path


def query(schema: str) -> bytes:
    if not valid_text(schema, 63):
        raise PostgreSQLIntegrationError("schema name is invalid")
    quoted = f'"{schema}"'
    sql = f"""
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '1000ms';
SET LOCAL lock_timeout = '500ms';
WITH
m AS MATERIALIZED (SELECT singleton,left(revision,129) revision FROM {quoted}.metadata ORDER BY singleton LIMIT 2),
d AS MATERIALIZED (SELECT left(key,129) key,left(value,4097) value FROM {quoted}.desired ORDER BY key LIMIT 257),
r AS MATERIALIZED (SELECT left(replica_id,129) replica_id FROM {quoted}.replicas ORDER BY replica_id LIMIT 65),
o AS MATERIALIZED (SELECT left(replica_id,129) replica_id,left(key,129) key,left(value,4097) value FROM {quoted}.observed ORDER BY replica_id,key LIMIT 16385),
c AS (SELECT
 (SELECT count(*) FROM m) mc,(SELECT count(*) FROM d) dc,(SELECT count(*) FROM r) rc,(SELECT count(*) FROM o) oc,
 (SELECT coalesce(bool_and(singleton AND revision ~ '^[A-Za-z0-9._:/-]+$' AND octet_length(revision)<=128),false) FROM m) mok,
 (SELECT coalesce(bool_and(key ~ '^[A-Za-z0-9._:/-]+$' AND octet_length(key)<=128 AND value<>'' AND octet_length(value)<=4096),false) FROM d) dok,
 (SELECT coalesce(bool_and(replica_id ~ '^[A-Za-z0-9._:/-]+$' AND octet_length(replica_id)<=128),false) FROM r) rok,
 (SELECT coalesce(bool_and(replica_id ~ '^[A-Za-z0-9._:/-]+$' AND octet_length(replica_id)<=128 AND key ~ '^[A-Za-z0-9._:/-]+$' AND octet_length(key)<=128 AND value<>'' AND octet_length(value)<=4096),false) FROM o) ook,
 (SELECT coalesce(sum(octet_length(key)+octet_length(value)),0) FROM d) +
 (SELECT coalesce(sum(octet_length(replica_id)+octet_length(key)+octet_length(value)),0) FROM o) payload_bytes),
per_replica AS (SELECT r.replica_id,count(o.key) field_count FROM r LEFT JOIN o USING(replica_id) GROUP BY r.replica_id)
SELECT CASE WHEN mc=1 AND dc BETWEEN 1 AND 256 AND rc BETWEEN 1 AND 64
 AND oc BETWEEN rc AND rc*256 AND mok AND dok AND rok AND ook AND payload_bytes<=1500000
 AND (SELECT bool_and(field_count BETWEEN 1 AND 256) FROM per_replica)
 AND NOT EXISTS (SELECT 1 FROM o LEFT JOIN r USING(replica_id) WHERE r.replica_id IS NULL)
THEN json_build_object(
 'revision',(SELECT revision FROM m),
 'desired',(SELECT json_object_agg(key,value ORDER BY key) FROM d),
 'replicas',(SELECT json_object_agg(replica_id,values ORDER BY replica_id) FROM
   (SELECT r.replica_id,json_object_agg(o.key,o.value ORDER BY o.key) values FROM r JOIN o USING(replica_id) GROUP BY r.replica_id) x)
) ELSE NULL END FROM c;
COMMIT;
"""
    return sql.encode()


def run_psql(psql_value: str, host: str, port: int, database: str,
             credential_path: str, schema: str) -> object:
    psql = executable(psql_value)
    if host not in {"127.0.0.1", "::1"} or not 1 <= port <= 65535 or not valid_text(database, 63):
        raise PostgreSQLIntegrationError("PostgreSQL endpoint is invalid")
    username, password = credentials(credential_path)
    with tempfile.TemporaryDirectory(prefix="telosieve-postgresql-password-") as raw:
        directory = Path(raw); directory.chmod(0o700)
        passfile = directory / "pgpass"
        passfile.write_text(f"{host}:{port}:{database}:{username}:{password}\n")
        passfile.chmod(0o600)
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                result = subprocess.run(
                    [str(psql), "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
                     "--set", "ON_ERROR_STOP=1", "--host", host, "--port", str(port),
                     "--dbname", database, "--username", username],
                    input=query(schema), stdout=stdout, stderr=stderr, check=False,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                    env={"LC_ALL": "C", "PGPASSFILE": str(passfile),
                         "PGCONNECT_TIMEOUT": "1", "PGAPPNAME": "telosieve-read-only"},
                )
            except subprocess.TimeoutExpired as error:
                raise PostgreSQLIntegrationError("psql command timed out") from error
            if result.returncode or stdout.tell() > MAX_STDOUT_BYTES or stderr.tell() > MAX_STDERR_BYTES:
                raise PostgreSQLIntegrationError("bounded psql command failed")
            stdout.seek(0)
            output = stdout.read(MAX_STDOUT_BYTES + 1).strip()
    if not output or output == b"null" or b"\n" in output:
        raise PostgreSQLIntegrationError("PostgreSQL snapshot is incomplete")
    return strict_json(output, "PostgreSQL snapshot")


def collect(request: object, psql: str, host: str, port: int, database: str,
            credential_path: str, schema: str) -> bytes:
    fields = {"schema_version", "contract", "operation", "integration_id", "resource_kind", "target_id", "subject", "evaluation_time"}
    if not isinstance(request, dict) or set(request) != fields:
        raise PostgreSQLIntegrationError("integration request shape is invalid")
    if request.get("schema_version") != REQUEST_SCHEMA or request.get("contract") != CONTRACT or request.get("operation") != "observe":
        raise PostgreSQLIntegrationError("integration request protocol is invalid")
    if any(not valid_text(request.get(field)) for field in ("integration_id", "resource_kind", "target_id", "subject")):
        raise PostgreSQLIntegrationError("integration request identity is invalid")
    if not isinstance(request.get("evaluation_time"), int) or not 0 <= request["evaluation_time"] <= 2**63-1:
        raise PostgreSQLIntegrationError("integration request time is invalid")
    snapshot = run_psql(psql, host, port, database, credential_path, schema)
    if not isinstance(snapshot, dict) or set(snapshot) != {"revision", "desired", "replicas"}:
        raise PostgreSQLIntegrationError("PostgreSQL snapshot shape is invalid")
    response = {
        "schema_version": RESPONSE_SCHEMA, "integration_id": request["integration_id"],
        "resource_kind": request["resource_kind"], "subject": request["subject"],
        "captured_at": request["evaluation_time"],
        "capabilities": {"contract": CONTRACT, "operation": "observe",
                         "credential_authority": "read_only", "target_mutated": False},
        "target": {"id": request["target_id"], "revision": snapshot["revision"]},
        "complete": True, "desired": snapshot["desired"],
        "observed": {"replicas": snapshot["replicas"]},
    }
    return json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode()
