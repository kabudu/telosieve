#!/usr/bin/env python3
"""Qualify the local Unix relay used for separate producer identities."""

import json
import os
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELAY = (ROOT / "scripts/observation-source-relay.py").resolve()
CLIENT = (ROOT / "scripts/observation-source-client.py").resolve()
UNIT = ROOT / "deploy/systemd/telosieve-observation@.service"
TIMEOUT_SECONDS = 8
EXPECTED = b'{"schema_version":"telosieve.observation-source/v1","fixture":true}\n'


def write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o500)


def config(path: Path, socket_path: Path, token: Path, producer: Path) -> None:
    path.write_text(json.dumps({
        "schema_version": "telosieve.observation-relay/v1",
        "socket_path": str(socket_path),
        "token_path": str(token),
        "producer": {"executable_path": str(producer), "arguments": []},
    }, separators=(",", ":")), encoding="utf-8")


def start(configuration: Path, socket_path: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [str(RELAY), "--config", str(configuration)], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if socket_path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.05)
                probe.connect(str(socket_path))
                return process
            except (ConnectionRefusedError, FileNotFoundError):
                pass
            finally:
                probe.close()
        if process.poll() is not None:
            _, error = process.communicate()
            raise SystemExit(f"producer-isolation: relay failed: {error.decode(errors='replace')}")
        time.sleep(0.01)
    process.terminate()
    process.wait(timeout=2)
    raise SystemExit("producer-isolation: relay readiness timed out")


def client(socket_path: Path, token: Path, success: bool) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [str(CLIENT), "--socket", str(socket_path), "--token", str(token)],
        cwd=ROOT, capture_output=True, check=False, timeout=TIMEOUT_SECONDS,
    )
    if (result.returncode == 0) != success:
        raise SystemExit(
            f"producer-isolation: unexpected client result rc={result.returncode} "
            f"expected_success={success} stderr={result.stderr.decode(errors='replace')}"
        )
    return result


def health(socket_path: Path, token: Path) -> None:
    result = subprocess.run(
        [str(CLIENT), "--socket", str(socket_path), "--token", str(token), "--check"],
        cwd=ROOT, capture_output=True, check=False, timeout=TIMEOUT_SECONDS,
    )
    expected = b'{"schema_version":"telosieve.observation-relay-health/v1","status":"ready"}\n'
    if result.returncode or result.stdout != expected:
        raise SystemExit("producer-isolation: readiness check failed")


def stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="telosieve-producer-isolation-") as raw:
        work = Path(raw)
        token = work / "relay.token"
        token.write_bytes(b"a" * 32)
        token.chmod(0o440)
        wrong_token = work / "wrong.token"
        wrong_token.write_bytes(b"b" * 32)
        wrong_token.chmod(0o440)
        healthy = work / "healthy"
        write_executable(healthy, "printf '%s\\n' '{\"schema_version\":\"telosieve.observation-source/v1\",\"fixture\":true}'")
        relay_config = work / "relay.json"
        socket_path = work / "relay.sock"
        config(relay_config, socket_path, token, healthy)
        process = start(relay_config, socket_path)
        try:
            if stat.S_IMODE(socket_path.stat().st_mode) != 0o660:
                raise SystemExit("producer-isolation: socket mode is unsafe")
            health(socket_path, token)
            if client(socket_path, token, True).stdout != EXPECTED:
                raise SystemExit("producer-isolation: exact producer output changed")
            client(socket_path, wrong_token, False)
        finally:
            stop(process)
        if socket_path.exists():
            raise SystemExit("producer-isolation: clean stop left a socket")

        process = start(relay_config, socket_path)
        process.kill()
        process.wait(timeout=2)
        if not socket_path.exists():
            raise SystemExit("producer-isolation: forced stop did not retain recovery fixture")
        process = start(relay_config, socket_path)
        try:
            if client(socket_path, token, True).stdout != EXPECTED:
                raise SystemExit("producer-isolation: stale-socket recovery changed output")
        finally:
            stop(process)
        if socket_path.exists():
            raise SystemExit("producer-isolation: recovered relay left a socket")

        refused = 1
        socket_path.symlink_to(work / "missing.sock")
        client(socket_path, token, False)
        socket_path.unlink()
        refused += 1
        for name, body in (
            ("timeout", "sleep 6"),
            ("oversized", "dd if=/dev/zero bs=1048576 count=6 2>/dev/null"),
            ("failure", "exit 7"),
        ):
            producer = work / name
            write_executable(producer, body)
            fault_socket = work / f"{name}.sock"
            fault_config = work / f"{name}.json"
            config(fault_config, fault_socket, token, producer)
            process = start(fault_config, fault_socket)
            try:
                client(fault_socket, token, False)
                refused += 1
            finally:
                stop(process)
            if fault_socket.exists():
                raise SystemExit("producer-isolation: fault relay left a socket")

        unit = UNIT.read_text(encoding="utf-8")
        required = (
            "User=telosieve-observation-%i",
            "Group=telosieve-observation-%i-client",
            "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
            "CapabilityBoundingSet=", "AmbientCapabilities=",
            "PrivateTmp=yes", "PrivateDevices=yes", "TasksMax=32",
            "MemoryMax=256M", "StandardOutput=null", "Restart=on-failure",
            "LogRateLimitIntervalSec=30s", "LogRateLimitBurst=10",
        )
        if any(item not in unit for item in required):
            raise SystemExit("producer-isolation: systemd hardening contract drifted")

        unsafe_token = work / "unsafe.token"
        unsafe_token.write_bytes(b"c" * 32)
        unsafe_token.chmod(0o666)
        unsafe_config = work / "unsafe.json"
        config(unsafe_config, work / "unsafe.sock", unsafe_token, healthy)
        result = subprocess.run(
            [str(RELAY), "--config", str(unsafe_config)], cwd=ROOT,
            capture_output=True, check=False, timeout=2,
        )
        if result.returncode == 0 or (work / "unsafe.sock").exists():
            raise SystemExit("producer-isolation: unsafe token accepted")
        refused += 1

        loose_config = work / "loose.json"
        config(loose_config, work / "loose.sock", token, healthy)
        loose_config.chmod(0o666)
        result = subprocess.run(
            [str(RELAY), "--config", str(loose_config)], cwd=ROOT,
            capture_output=True, check=False, timeout=2,
        )
        if result.returncode == 0 or (work / "loose.sock").exists():
            raise SystemExit("producer-isolation: writable configuration accepted")
        refused += 1

    print(json.dumps({
        "schema_version": "telosieve.producer-isolation-qualification/v1",
        "transport": "authenticated-unix-stream",
        "accepted": 3,
        "refused": refused,
        "socket_mode": "0660",
        "separate_os_identities_exercised": False,
        "independent_evidence": False,
        "status": "passed",
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
