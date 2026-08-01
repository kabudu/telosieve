#!/usr/bin/env python3
"""Independently collect and sign one PostgreSQL integration response."""
import argparse, json, os, stat, subprocess, tempfile
from pathlib import Path
from postgresql_integration_common import CONTRACT, REQUEST_SCHEMA, PostgreSQLIntegrationError, collect, executable, strict_json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config_path = Path(args.config)
    if not config_path.is_absolute() or config_path.is_symlink() or not config_path.is_file() or config_path.stat().st_size > 64 * 1024:
        raise PostgreSQLIntegrationError("producer configuration is invalid")
    config = strict_json(config_path.read_bytes(), "producer configuration")
    fields = {"psql", "host", "port", "database", "credentials", "schema",
              "integration_id", "resource_kind", "target_id", "subject",
              "evaluation_time", "telosieve", "key", "producer", "key_id",
              "domain", "issued", "expires"}
    if not isinstance(config, dict) or set(config) != fields:
        raise PostgreSQLIntegrationError("producer configuration shape is invalid")
    telosieve = executable(config["telosieve"])
    key = Path(config["key"])
    if not key.is_absolute() or key.is_symlink() or not key.is_file() or key.stat().st_size > 4096:
        raise PostgreSQLIntegrationError("signing key is invalid")
    request = {"schema_version": REQUEST_SCHEMA, "contract": CONTRACT, "operation": "observe",
        "integration_id": config["integration_id"], "resource_kind": config["resource_kind"],
        "target_id": config["target_id"], "subject": config["subject"],
        "evaluation_time": int(config["evaluation_time"])}
    response = collect(request, config["psql"], config["host"], int(config["port"]), config["database"],
                       config["credentials"], config["schema"])
    descriptor, raw = tempfile.mkstemp(prefix="telosieve-postgresql-observation-")
    os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "wb") as stream: stream.write(response)
    response_path = Path(raw); attestation_path = response_path.with_suffix(".attestation")
    try:
        with tempfile.TemporaryFile() as stderr:
            result = subprocess.run([str(telosieve), "observation-sign", str(response_path),
                str(key), config["subject"], "external-read-only", config["producer"], config["key_id"],
                config["domain"], str(config["issued"]), str(config["expires"]), str(attestation_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
                check=False, timeout=3)
            if result.returncode or stderr.tell() > 16 * 1024:
                raise PostgreSQLIntegrationError("bounded signing failed")
        if attestation_path.is_symlink() or not attestation_path.is_file() or attestation_path.stat().st_size > 64 * 1024:
            raise PostgreSQLIntegrationError("attestation is invalid")
        envelope = {"schema_version": "telosieve.observation-source/v1",
                    "input_hex": response.hex(),
                    "attestation": json.loads(attestation_path.read_bytes())}
        print(json.dumps(envelope, separators=(",", ":")))
    finally:
        response_path.unlink(missing_ok=True); attestation_path.unlink(missing_ok=True)
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except (PostgreSQLIntegrationError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"postgresql-observation-producer: {error}") from error
