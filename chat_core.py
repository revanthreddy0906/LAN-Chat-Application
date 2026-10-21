"""Helpers shared by the terminal client and the GUI client."""

from __future__ import annotations

import json
import re
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Callable

from certs import fingerprint_of_pem
from protocol import receive_message, send_message
from settings import Settings

DEFAULT_PORT = 5050
HEARTBEAT_INTERVAL = 10.0
CONNECT_TIMEOUT = 10.0

_CHAT_PATTERN = re.compile(r"\[(\d{2}:\d{2})\] (.+?): (.*)", re.DOTALL)
_USERS_PATTERN = re.compile(r"Online \(\d+\): ?(.*)", re.DOTALL)
_MEMBERS_PATTERN = re.compile(r"Members \(\d+\): ?(.*)", re.DOTALL)


class LoginError(Exception):
    """The server refused the login (bad name, wrong password, already online)."""


class TrustDeclined(Exception):
    """The user chose not to trust the server's certificate or to go unencrypted."""


class CertificateChanged(Exception):
    """A known server now presents a different certificate (possible impersonation)."""

    def __init__(self, host: str, port: int, old: str, new: str) -> None:
        super().__init__(
            f"The certificate for {host}:{port} has CHANGED. This could mean someone is "
            f"impersonating the server. Known: {old}  Now: {new}"
        )
        self.host, self.port, self.old, self.new = host, port, old, new


@dataclass(frozen=True)
class ParsedMessage:
    kind: str  # chat, private, join, leave, shutdown, welcome, error, system
    text: str
    timestamp: str = ""
    name: str = ""


def parse_address(text: str, default_port: int | None = None) -> tuple[str, int | None]:
    """Split 'host' or 'host:port' into (host, port)."""
    text = text.strip()
    host, separator, port = text.rpartition(":")
    if separator and port.isdigit() and host:
        return host, int(port)
    return text, default_port


def parse_message(message: str) -> ParsedMessage:
    if message.endswith("joined the chat."):
        return ParsedMessage("join", message)
    if message.endswith("left the chat."):
        return ParsedMessage("leave", message)
    if "shutting down" in message:
        return ParsedMessage("shutdown", message)
    if message == "Connected to LAN Chat!":
        return ParsedMessage("welcome", message)
    if message.startswith(("Error:", "ERROR:")):
        return ParsedMessage("error", message)
    match = _CHAT_PATTERN.fullmatch(message)
    if match:
        timestamp, name, text = match.groups()
        kind = "private" if name.endswith("(private)") else "chat"
        return ParsedMessage(kind, text, timestamp, name)
    return ParsedMessage("system", message)


def parse_user_list(message: str) -> list[str] | None:
    """Return the names in a '/users' reply, or None if it is something else."""
    match = _USERS_PATTERN.fullmatch(message)
    if not match:
        return None
    return [name.strip() for name in match.group(1).split(",") if name.strip()]


@dataclass(frozen=True)
class Member:
    name: str
    role: str
    online: bool
    status: str = ""  # "online", "away" or "offline" (protocol v2 only)


def parse_members(message: str) -> list[Member] | None:
    """Parse a '/members' reply ('Members (3): Ann:admin:1, Bob:member:0, ...')."""
    match = _MEMBERS_PATTERN.fullmatch(message)
    if not match:
        return None
    members = []
    for part in match.group(1).split(","):
        part = part.strip()
        if not part or part.startswith("+"):  # "+12 more" marks a truncated list
            continue
        name, _, rest = part.partition(":")
        role, _, online = rest.partition(":")
        members.append(Member(name, role or "member", online == "1"))
    return members


def make_tls_context(cafile: str | None = None, *, cadata: str | None = None) -> ssl.SSLContext:
    """Trust only the given self-signed certificate (certificate pinning).

    Hostname checking is off because LAN addresses change; the pinned
    certificate is what authenticates the server.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cafile, cadata=cadata)
    return context


def fetch_server_certificate(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> str | None:
    """Read the server's certificate (PEM) without trusting it.

    Returns None if the server does not speak TLS. Connection problems raise
    OSError as usual.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout) as raw:
            with context.wrap_socket(raw) as secured:
                der = secured.getpeercert(binary_form=True)
    except ssl.SSLError:
        return None
    return ssl.DER_cert_to_PEM_cert(der)


def connect_and_login(
    host: str,
    port: int,
    username: str,
    password: str,
    tls_context: ssl.SSLContext | None = None,
    protocol: int = 1,
    token: str | None = None,
) -> socket.socket:
    """Open a connection and complete the server's login handshake.

    protocol=1 is the plain-text chat; protocol=2 announces itself in the
    username step and then speaks JSON events (see events.py).
    """
    connection = socket.create_connection((host, port), CONNECT_TIMEOUT)
    try:
        if tls_context is not None:
            connection = tls_context.wrap_socket(connection)
        if receive_message(connection) != "USERNAME":
            raise LoginError("unexpected reply from server (is it a LAN Chat server?)")
        if protocol >= 2:
            hello = {"v": protocol, "username": username}
            if token:  # a saved sign-in: the server skips the password step
                hello["token"] = token
            send_message(connection, json.dumps(hello))
        else:
            send_message(connection, username)
        reply = receive_message(connection)
        if reply == "PASSWORD":
            send_message(connection, password)
            reply = receive_message(connection)
        if reply != "OK":
            if reply is None:
                raise LoginError("server closed the connection")
            raise LoginError(reply.removeprefix("ERROR: "))
        connection.settimeout(None)
        return connection
    except BaseException:
        connection.close()
        raise


class SafeSender:
    """Serialises sends so the input thread and heartbeat never interleave frames."""

    def __init__(self, connection: socket.socket) -> None:
        self._connection = connection
        self._lock = threading.Lock()

    def send(self, message: str) -> None:
        with self._lock:
            send_message(self._connection, message)

    def send_event(self, event: dict) -> None:
        """Send a protocol v2 event (a JSON object with a "t" type)."""
        self.send(json.dumps(event, ensure_ascii=False, separators=(",", ":")))


def start_heartbeat(
    sender: SafeSender, stop: threading.Event, interval: float = HEARTBEAT_INTERVAL,
    message: str = "/ping",
) -> threading.Thread:
    def beat() -> None:
        while not stop.wait(interval):
            try:
                sender.send(message)
            except (OSError, ValueError):
                return

    thread = threading.Thread(target=beat, daemon=True)
    thread.start()
    return thread


@dataclass(frozen=True)
class ConnectResult:
    connection: socket.socket
    encrypted: bool
    fingerprint: str | None = None
    context: ssl.SSLContext | None = None  # reused for file-transfer connections


def connect_secure(
    host: str,
    port: int,
    username: str,
    password: str,
    settings: Settings,
    *,
    confirm_trust: Callable[[str, str, int], bool],
    confirm_plain: Callable[[str, int], bool],
    cafile: str | None = None,
    protocol: int = 1,
    token: str | None = None,
) -> ConnectResult:
    """Connect and log in, deciding on encryption automatically.

    - With `cafile`, only that certificate is trusted (explicit pinning).
    - Otherwise trust-on-first-use: ask once per certificate
      (`confirm_trust(fingerprint, host, port)`), remember it, and refuse if
      a known address later presents a different certificate.
    - A server without TLS is only used after `confirm_plain(host, port)`.
    """
    if cafile:
        context = make_tls_context(cafile)
        return ConnectResult(connect_and_login(host, port, username, password, context, protocol, token), True,
                             context=context)

    pem = fetch_server_certificate(host, port)
    if pem is None:
        if not confirm_plain(host, port):
            raise TrustDeclined("Not connecting to an unencrypted server.")
        return ConnectResult(connect_and_login(host, port, username, password, None, protocol, token), False)

    fingerprint = fingerprint_of_pem(pem)
    known = settings.trusted_server(host, port)
    if known is None:
        # The same certificate at a new address (DHCP change, LAN IP vs
        # localhost) was already trusted once, so do not ask again.
        if not settings.is_trusted_fingerprint(fingerprint):
            if not confirm_trust(fingerprint, host, port):
                raise TrustDeclined("Server certificate was not trusted.")
        settings.trust_server(host, port, pem, fingerprint)
    elif known["fingerprint"] != fingerprint:
        raise CertificateChanged(host, port, known["fingerprint"], fingerprint)

    context = make_tls_context(cadata=pem)
    connection = connect_and_login(host, port, username, password, context, protocol, token)
    return ConnectResult(connection, True, fingerprint, context)
