"""Check what a running LANChat-H server accepts at the TLS layer (our own testing).

    python3 security_tests/tls_probe.py

Starts a server with its default certificate and tries: each TLS version, a plain-text client on
the TLS port, a client that does not trust the certificate, and a client pinned to a different
certificate. Prints a table.
"""
import json
import os
import socket
import ssl
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LANCHAT_HOME", tempfile.mkdtemp())

from accounts import AccountStore  # noqa: E402
from chat_core import fetch_server_certificate, make_tls_context  # noqa: E402
from protocol import receive_message  # noqa: E402
from certs import ensure_certificate  # noqa: E402
from server import ChatServer, build_tls_context, default_tls_context  # noqa: E402


def attempt(port, context):
    try:
        with socket.create_connection(("127.0.0.1", port), 3) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                first = receive_message(tls)
                return f"accepted ({tls.version()}, {tls.cipher()[0]}), first frame {first!r}"
    except (ssl.SSLError, OSError, ValueError) as error:
        return f"refused ({type(error).__name__})"


def main():
    accounts = AccountStore(os.path.join(tempfile.mkdtemp(), "t.db"))
    server = ChatServer("127.0.0.1", 0, accounts=accounts, tls_context=default_tls_context()[0], quiet=True)
    server.start()
    port = server.bound_port
    rows = []
    for name, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
                          ("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3)):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
            context.set_ciphers("ALL:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            pass
        rows.append((f"{name} only, no verification", attempt(port, context)))
    pinned = make_tls_context(cadata=fetch_server_certificate("127.0.0.1", port))
    rows.append(("client pinned to the server's certificate", attempt(port, pinned)))
    pair = ensure_certificate(tempfile.mkdtemp())  # a second, different certificate
    other_context = build_tls_context(str(pair[0]), str(pair[1]))
    other = ChatServer("127.0.0.1", 0, accounts=AccountStore(os.path.join(tempfile.mkdtemp(), "o.db")),
                       tls_context=other_context, quiet=True)
    other.start()
    wrong = make_tls_context(cadata=fetch_server_certificate("127.0.0.1", other.bound_port))
    rows.append(("client pinned to a different certificate", attempt(port, wrong)))
    default = ssl.create_default_context()
    rows.append(("client trusting only public CAs", attempt(port, default)))
    try:
        with socket.create_connection(("127.0.0.1", port), 3) as raw:
            raw.settimeout(2)
            raw.sendall(b"\x00\x00\x00\x05hello")
            data = raw.recv(100)
            rows.append(("plain-text client on the TLS port", f"got {data[:20]!r}" if data else "closed without a reply"))
    except OSError as error:
        rows.append(("plain-text client on the TLS port", f"refused ({type(error).__name__})"))
    for name, result in rows:
        print(f"{name:<45} {result}")
    other.stop()
    server.stop()


if __name__ == "__main__":
    main()
