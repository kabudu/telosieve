#!/usr/bin/env python3
"""Independently collect and sign one HTTP/JSON integration response."""
import argparse, json, os, stat, subprocess, tempfile
from pathlib import Path
from http_json_integration_common import CONTRACT, REQUEST_SCHEMA, HTTPJSONIntegrationError, collect, strict_json

FIELDS = {"host", "port", "path", "credentials", "integration_id", "resource_kind", "target_id",
          "subject", "evaluation_time", "telosieve", "key", "producer", "key_id", "domain", "issued", "expires"}

def regular(value, maximum, label, executable=False):
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file(): raise HTTPJSONIntegrationError(f"invalid {label}")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > maximum: raise HTTPJSONIntegrationError(f"invalid {label}")
    if executable and (metadata.st_mode & 0o111 == 0 or metadata.st_mode & 0o022): raise HTTPJSONIntegrationError(f"unsafe {label}")
    return path

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--config", required=True); args = parser.parse_args()
    config_path = regular(args.config, 64 * 1024, "producer configuration")
    config = strict_json(config_path.read_bytes(), "producer configuration")
    if not isinstance(config, dict) or set(config) != FIELDS: raise HTTPJSONIntegrationError("producer configuration shape is invalid")
    if any(not isinstance(config[field], str) for field in FIELDS - {"port", "evaluation_time", "issued", "expires"}):
        raise HTTPJSONIntegrationError("producer configuration type is invalid")
    if any(not isinstance(config[field], int) or isinstance(config[field], bool) for field in {"port", "evaluation_time", "issued", "expires"}):
        raise HTTPJSONIntegrationError("producer configuration integer is invalid")
    binary = regular(config["telosieve"], 128 * 1024 * 1024, "Telosieve executable", True)
    key = regular(config["key"], 4096, "signing key")
    request = {"schema_version": REQUEST_SCHEMA, "contract": CONTRACT, "operation": "observe",
        "integration_id": config["integration_id"], "resource_kind": config["resource_kind"],
        "target_id": config["target_id"], "subject": config["subject"], "evaluation_time": config["evaluation_time"]}
    response = collect(request, config["host"], config["port"], config["path"], config["credentials"])
    descriptor, raw = tempfile.mkstemp(prefix="telosieve-http-json-observation-"); os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "wb") as stream: stream.write(response)
    response_path = Path(raw); attestation_path = response_path.with_suffix(".attestation")
    try:
        with tempfile.TemporaryFile() as stderr:
            result = subprocess.run([str(binary), "observation-sign", str(response_path), str(key), config["subject"],
                "external-read-only", config["producer"], config["key_id"], config["domain"],
                str(config["issued"]), str(config["expires"]), str(attestation_path)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=stderr, check=False, timeout=3)
            if result.returncode or stderr.tell() > 16 * 1024: raise HTTPJSONIntegrationError("bounded signing failed")
        attestation = regular(str(attestation_path), 64 * 1024, "attestation")
        envelope = {"schema_version": "telosieve.observation-source/v1", "input_hex": response.hex(),
                    "attestation": strict_json(attestation.read_bytes(), "attestation")}
        print(json.dumps(envelope, separators=(",", ":")))
    finally:
        response_path.unlink(missing_ok=True); attestation_path.unlink(missing_ok=True)
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except (HTTPJSONIntegrationError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"http-json-observation-producer: {error}") from error
