#!/usr/bin/env python3
"""Focused bounded RESP and credential tests for the Redis integration."""

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

from redis_integration_common import RedisConnection, RedisIntegrationError, credentials


class RedisIntegrationTests(unittest.TestCase):
    def response(self, wire: bytes):
        reader, writer = socket.socketpair()
        try:
            connection = RedisConnection.__new__(RedisConnection)
            connection.socket = reader
            connection.socket.settimeout(0.2)
            connection.buffer = bytearray()
            connection.received = 0
            writer.sendall(wire)
            return connection._response(0)
        finally:
            reader.close()
            writer.close()

    def test_resp_types_and_bounds(self):
        self.assertEqual(self.response(b"+OK\r\n"), "OK")
        self.assertEqual(self.response(b"$5\r\nvalue\r\n"), "value")
        self.assertEqual(self.response(b"*2\r\n$1\r\na\r\n:2\r\n"), ["a", 2])
        for wire in (b"-NOPERM denied\r\n", b"$4097\r\n", b"*513\r\n", b"?bad\r\n"):
            with self.assertRaises(RedisIntegrationError):
                self.response(wire)

    def test_credentials_require_private_single_link_file(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "reader.json"
            path.write_text(json.dumps({
                "schema_version": "telosieve.redis-credentials/v1",
                "username": "reader-a", "password": "A" * 32,
            }))
            path.chmod(0o600)
            self.assertEqual(credentials(str(path)), ("reader-a", "A" * 32))
            path.chmod(0o644)
            with self.assertRaises(RedisIntegrationError):
                credentials(str(path))
            path.chmod(0o600)
            linked = Path(raw) / "linked.json"
            os.link(path, linked)
            with self.assertRaises(RedisIntegrationError):
                credentials(str(path))
            linked.unlink()
            symlink = Path(raw) / "symlink.json"
            symlink.symlink_to(path)
            with self.assertRaises(RedisIntegrationError):
                credentials(str(symlink))
            duplicate = (
                '{"schema_version":"telosieve.redis-credentials/v1",'
                '"username":"reader-a","username":"reader-b","password":"'
                + "A" * 32
                + '"}'
            )
            path.write_text(duplicate)
            with self.assertRaises(RedisIntegrationError):
                credentials(str(path))


if __name__ == "__main__":
    unittest.main()
