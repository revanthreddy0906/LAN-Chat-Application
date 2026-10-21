import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path

from accounts import AccountStore
from certs import fingerprint_of_pem
from chat_core import (
    CertificateChanged,
    LoginError,
    TrustDeclined,
    connect_secure,
    fetch_server_certificate,
)
from test_server import RELAXED
from server import ChatServer, build_tls_context
from settings import Settings


def make_cert(directory, cn="lanchat"):
    cert, key = Path(directory) / f"{cn}.crt", Path(directory) / f"{cn}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", f"/CN={cn}", "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    return cert, key


class Recorder:
    """Records and answers the confirmation prompts."""

    def __init__(self, trust=True, plain=True):
        self.trust, self.plain = trust, plain
        self.trust_calls, self.plain_calls = [], []

    def confirm_trust(self, fingerprint, host, port):
        self.trust_calls.append((fingerprint, host, port))
        return self.trust

    def confirm_plain(self, host, port):
        self.plain_calls.append((host, port))
        return self.plain


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TrustOnFirstUseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cert, key = make_cert(self.tmp)
        self.settings = Settings(Path(self.tmp) / "home")
        self.tls_server = ChatServer(
            "127.0.0.1", 0, accounts=AccountStore(Path(self.tmp) / "a.json"),
            tls_context=build_tls_context(str(self.cert), str(key)), quiet=True, **RELAXED,
        )
        self.plain_server = ChatServer(
            "127.0.0.1", 0, accounts=AccountStore(Path(self.tmp) / "b.json"), quiet=True, **RELAXED
        )
        self.tls_server.start()
        self.plain_server.start()
        self.connections = []

    def tearDown(self):
        for connection in self.connections:
            connection.close()
        self.tls_server.stop()
        self.plain_server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def join(self, server, recorder, name="Alice", **kwargs):
        result = connect_secure(
            "127.0.0.1", server.bound_port, name, "pw", self.settings,
            confirm_trust=recorder.confirm_trust, confirm_plain=recorder.confirm_plain, **kwargs,
        )
        self.connections.append(result.connection)
        return result

    def test_first_connection_asks_then_remembers(self):
        first = Recorder()
        result = self.join(self.tls_server, first, "Alice")
        self.assertTrue(result.encrypted)
        self.assertEqual(len(first.trust_calls), 1)
        expected = fingerprint_of_pem(self.cert.read_text())
        self.assertEqual(first.trust_calls[0][0], expected)
        self.assertEqual(result.fingerprint, expected)

        second = Recorder(trust=False)  # would refuse, but must not even be asked
        self.assertTrue(self.join(self.tls_server, second, "Bob").encrypted)
        self.assertEqual(second.trust_calls, [])

    def test_same_certificate_on_another_address_is_not_asked_again(self):
        self.join(self.tls_server, Recorder(), "Alice")  # trusts 127.0.0.1:<port>
        self.settings.forget_server("127.0.0.1", self.tls_server.bound_port)
        self.settings.trust_server("10.9.8.7", 5050, "PEM", fingerprint_of_pem(self.cert.read_text()))
        again = Recorder(trust=False)
        self.assertTrue(self.join(self.tls_server, again, "Bob").encrypted)
        self.assertEqual(again.trust_calls, [])
        self.assertIsNotNone(self.settings.trusted_server("127.0.0.1", self.tls_server.bound_port))

    def test_declined_trust_connects_nothing_and_stores_nothing(self):
        with self.assertRaises(TrustDeclined):
            self.join(self.tls_server, Recorder(trust=False))
        self.assertIsNone(self.settings.trusted_server("127.0.0.1", self.tls_server.bound_port))

    def test_changed_certificate_is_refused(self):
        self.settings.trust_server("127.0.0.1", self.tls_server.bound_port, "OLD", "AA:BB:CC")
        recorder = Recorder()
        with self.assertRaises(CertificateChanged) as raised:
            self.join(self.tls_server, recorder)
        self.assertIn("CHANGED", str(raised.exception))
        self.assertEqual(recorder.trust_calls, [])

    def test_plain_server_needs_explicit_confirmation(self):
        refusing = Recorder(plain=False)
        with self.assertRaises(TrustDeclined):
            self.join(self.plain_server, refusing)
        self.assertEqual(len(refusing.plain_calls), 1)

        accepting = Recorder(plain=True)
        result = self.join(self.plain_server, accepting)
        self.assertFalse(result.encrypted)
        self.assertEqual(accepting.trust_calls, [])

    def test_fetch_certificate(self):
        pem = fetch_server_certificate("127.0.0.1", self.tls_server.bound_port)
        self.assertEqual(fingerprint_of_pem(pem), fingerprint_of_pem(self.cert.read_text()))
        self.assertIsNone(fetch_server_certificate("127.0.0.1", self.plain_server.bound_port))

    def test_explicit_cafile_pins_without_prompting(self):
        recorder = Recorder(trust=False, plain=False)
        result = self.join(self.tls_server, recorder, cafile=str(self.cert))
        self.assertTrue(result.encrypted)
        self.assertEqual((recorder.trust_calls, recorder.plain_calls), ([], []))

        other, _ = make_cert(self.tmp, "impostor")
        with self.assertRaises(ssl.SSLError):
            self.join(self.tls_server, recorder, "Carol", cafile=str(other))

    def test_wrong_password_after_trust_still_reports_login_error(self):
        self.join(self.tls_server, Recorder(), "Dave")
        with self.assertRaises(LoginError):
            connect_secure(
                "127.0.0.1", self.tls_server.bound_port, "Dave", "wrong", self.settings,
                confirm_trust=lambda *a: True, confirm_plain=lambda *a: True,
            )


if __name__ == "__main__":
    unittest.main()
