import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path

from certs import ensure_certificate, fingerprint_of_pem, short_fingerprint
from discovery import (
    DiscoveryResponder,
    FoundServer,
    _dedupe,
    discover,
    lan_address,
)
from settings import Settings


class DiscoveryTest(unittest.TestCase):
    def test_discover_finds_responder(self):
        responder = DiscoveryResponder(
            lambda: {"name": "demo", "port": 5050, "tls": True, "users": 2},
            port=0,
            bind="127.0.0.1",
        )
        responder.start()
        try:
            found = discover(timeout=0.5, targets=[("127.0.0.1", responder.port)])
        finally:
            responder.stop()
        self.assertEqual(found, [FoundServer("127.0.0.1", 5050, "demo", True, 2)])

    def test_discover_returns_empty_when_nobody_answers(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as quiet:
            quiet.bind(("127.0.0.1", 0))
            port = quiet.getsockname()[1]
            self.assertEqual(discover(timeout=0.3, targets=[("127.0.0.1", port)]), [])

    def test_responder_ignores_other_packets(self):
        responder = DiscoveryResponder(lambda: {"name": "x", "port": 1}, port=0, bind="127.0.0.1")
        responder.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.4)
                sock.sendto(b"hello", ("127.0.0.1", responder.port))
                with self.assertRaises(socket.timeout):
                    sock.recvfrom(100)
        finally:
            responder.stop()

    def test_dedupe_prefers_lan_address_over_loopback(self):
        loop = FoundServer("127.0.0.1", 5050, "mac", True, 1)
        lan = FoundServer("192.168.1.9", 5050, "mac", True, 1)
        other = FoundServer("192.168.1.20", 5050, "other", False, 0)
        self.assertEqual(_dedupe([loop, lan, other]), [lan, other])
        self.assertEqual(_dedupe([loop]), [loop])

    def test_lan_address_is_an_ipv4_string(self):
        parts = lan_address().split(".")
        self.assertEqual(len(parts), 4)
        self.assertTrue(all(p.isdigit() for p in parts))


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_values_persist_and_file_is_private(self):
        Settings(self.tmp).set("username", "Revanth")
        again = Settings(self.tmp)
        self.assertEqual(again.get("username"), "Revanth")
        self.assertEqual(again.get("missing", "fallback"), "fallback")
        mode = os.stat(Path(self.tmp) / "settings.json").st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_trusted_servers(self):
        settings = Settings(self.tmp)
        self.assertIsNone(settings.trusted_server("1.2.3.4", 5050))
        settings.trust_server("1.2.3.4", 5050, "PEM", "AA:BB")
        self.assertEqual(Settings(self.tmp).trusted_server("1.2.3.4", 5050)["fingerprint"], "AA:BB")
        settings.forget_server("1.2.3.4", 5050)
        self.assertIsNone(Settings(self.tmp).trusted_server("1.2.3.4", 5050))

    def test_corrupt_file_is_ignored(self):
        Path(self.tmp, "settings.json").write_text("{not json")
        self.assertIsNone(Settings(self.tmp).get("username"))

    def test_environment_override(self):
        os.environ["LANCHAT_HOME"] = self.tmp
        try:
            self.assertEqual(Settings().home, Path(self.tmp))
        finally:
            del os.environ["LANCHAT_HOME"]


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class CertTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_creates_once_and_reuses(self):
        first = ensure_certificate(self.tmp)
        self.assertIsNotNone(first)
        cert, key = first
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        before = cert.read_text()
        self.assertEqual(ensure_certificate(self.tmp), first)
        self.assertEqual(cert.read_text(), before)

    def test_fingerprint_format(self):
        cert, _ = ensure_certificate(self.tmp)
        fingerprint = fingerprint_of_pem(cert.read_text())
        self.assertEqual(len(fingerprint.split(":")), 32)
        self.assertEqual(fingerprint, fingerprint.upper())
        self.assertTrue(short_fingerprint(fingerprint).endswith(":..."))


if __name__ == "__main__":
    unittest.main()
