#!/usr/bin/env python3
"""Collect a bounded PostgreSQL snapshot for Integration Contract v1."""
import argparse, sys
from postgresql_integration_common import PostgreSQLIntegrationError, collect, strict_json

MAX_REQUEST_BYTES = 64 * 1024

def main():
    parser = argparse.ArgumentParser()
    for field in ("psql", "host", "port", "database", "credentials", "schema"):
        parser.add_argument(f"--{field}", required=True)
    args = parser.parse_args()
    value = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(value) > MAX_REQUEST_BYTES:
        raise PostgreSQLIntegrationError("integration request exceeds bound")
    sys.stdout.buffer.write(collect(strict_json(value, "integration request"), args.psql,
        args.host, int(args.port), args.database, args.credentials, args.schema))
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except (PostgreSQLIntegrationError, OSError, ValueError) as error:
        raise SystemExit(f"postgresql-integration-adapter: {error}") from error
