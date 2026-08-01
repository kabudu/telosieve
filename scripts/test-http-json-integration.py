#!/usr/bin/env python3
"""Focused HTTP/JSON adapter boundary tests."""
import json, os, tempfile, unittest
from pathlib import Path
from http_json_integration_common import HTTPJSONIntegrationError, credential, snapshot

class HTTPJSONIntegrationTests(unittest.TestCase):
    def test_credentials_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "credential.json"
            path.write_text(json.dumps({"schema_version":"telosieve.http-json-credentials/v1","bearer_token":"A"*32})); path.chmod(0o600)
            self.assertEqual(credential(str(path)), "A"*32)
            path.chmod(0o644)
            with self.assertRaises(HTTPJSONIntegrationError): credential(str(path))
            path.chmod(0o600); linked = path.with_name("linked"); os.link(path, linked)
            with self.assertRaises(HTTPJSONIntegrationError): credential(str(path))

    def test_snapshot_shapes_and_bounds_fail_closed(self):
        good = {"schema_version":"telosieve.http-json-snapshot/v1","revision":"r1","complete":True,
                "desired":{"k":"v"},"replicas":{"a":{"k":"v"}}}
        self.assertEqual(snapshot(good)[0], "r1")
        for mutation in (
            {**good,"complete":False}, {**good,"unknown":1},
            {**good,"replicas":{}}, {**good,"desired":{f"k{i}":"v" for i in range(257)}},
            {**good,"replicas":{"a":{"k":"x"*4097}}},
        ):
            with self.assertRaises(HTTPJSONIntegrationError): snapshot(mutation)

if __name__ == "__main__": unittest.main()
