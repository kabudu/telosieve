#!/usr/bin/env python3
"""Collect one bounded read-only Redis snapshot for Integration Contract v1."""

import argparse
import sys

from redis_integration_common import RedisIntegrationError, collect, strict_json


MAX_REQUEST_BYTES = 64 * 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()
    request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        raise RedisIntegrationError("integration request exceeds bound")
    sys.stdout.buffer.write(collect(strict_json(request_bytes, "integration request"), args.host, args.port, args.credentials, args.prefix))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RedisIntegrationError as error:
        raise SystemExit(f"redis-integration-adapter: {error}") from error
