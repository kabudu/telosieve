#!/usr/bin/env python3
"""Collect one bounded HTTP/JSON snapshot for Integration Contract v1."""
import argparse, sys
from http_json_integration_common import HTTPJSONIntegrationError, MAX_REQUEST_BYTES, collect, strict_json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True); parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--path", required=True); parser.add_argument("--credentials", required=True)
    args = parser.parse_args(); raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES: raise HTTPJSONIntegrationError("integration request exceeds bound")
    sys.stdout.buffer.write(collect(strict_json(raw, "integration request"), args.host, args.port, args.path, args.credentials))
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except HTTPJSONIntegrationError as error: raise SystemExit(f"http-json-integration-adapter: {error}") from error
