#!/usr/bin/env python3
"""Focused PostgreSQL adapter boundary tests."""
import json, os, tempfile, unittest
from pathlib import Path
from postgresql_integration_common import (
    PostgreSQLIntegrationError, credentials, query, run_psql,
)

class PostgreSQLIntegrationTests(unittest.TestCase):
    def credential(self, root: Path) -> Path:
        path = root / "reader.json"
        path.write_text(json.dumps({"schema_version": "telosieve.postgresql-credentials/v1",
                                    "username": "reader_a", "password": "A" * 32}))
        path.chmod(0o600)
        return path

    def test_query_is_fixed_bounded_read_only_transaction(self):
        sql = query("telosieve_state").decode()
        for fragment in ("REPEATABLE READ READ ONLY", "statement_timeout", "LIMIT 16385",
                         "payload_bytes<=1500000"):
            self.assertIn(fragment, sql)
        for token in ("INSERT ", "UPDATE ", "DELETE ", "CREATE ", "DROP ", "ALTER "):
            self.assertNotIn(token, sql)
        with self.assertRaises(PostgreSQLIntegrationError):
            query('unsafe"schema')

    def test_credentials_and_psql_output_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); credential = self.credential(root)
            self.assertEqual(credentials(str(credential)), ("reader_a", "A" * 32))
            credential.chmod(0o644)
            with self.assertRaises(PostgreSQLIntegrationError): credentials(str(credential))
            credential.chmod(0o600)
            linked = root / "linked"; os.link(credential, linked)
            with self.assertRaises(PostgreSQLIntegrationError): credentials(str(credential))
            linked.unlink()
            for name, output, accepted in (
                ("valid", '{"revision":"r1","desired":{"k":"v"},"replicas":{"a":{"k":"v"}}}', True),
                ("null", "null", False), ("malformed", "{", False),
                ("multiline", "{}\n{}", False),
            ):
                program = root / name
                program.write_text("#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + output + "'\n")
                program.chmod(0o700)
                if accepted:
                    self.assertEqual(run_psql(str(program), "127.0.0.1", 5432, "postgres",
                                              str(credential), "telosieve_state")["revision"], "r1")
                else:
                    with self.assertRaises(PostgreSQLIntegrationError):
                        run_psql(str(program), "127.0.0.1", 5432, "postgres",
                                 str(credential), "telosieve_state")

if __name__ == "__main__": unittest.main()
