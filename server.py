"""Threaded TCP chat server for the LAN Chat Application."""

from __future__ import annotations

import argparse
import errno
import json
import queue
import e2ee
import hashlib
import math
import re
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import sqlite3

from accounts import AccountStore
from certs import ensure_certificate, fingerprint_of_pem
from colors import CYAN, DIM, GREEN, RED, YELLOW, colorize, supports_color
from discovery import DISCOVERY_PORT, DiscoveryResponder, lan_address
from events import (
    MAX_BODY_BYTES,
    PROTOCOL_VERSION,
    clock,
    decode,
    encode,
    fit_frame,
    legacy_text,
    member_pages,
    message_event,
    pins_event,
    reactions_event,
    search_event,
    snippet,
    snippet_around,
)
from permissions import can
from security import DEFAULT_MIN_PASSWORD, LoginGuard, RateLimiter, SlidingWindow, check_password
from server_admin import AdminMixin
from server_keys import KeysMixin
from protocol import MAX_MESSAGE_BYTES, receive_message, send_message
from settings import default_home
from storage import (
    BLOCKED_EXTENSIONS, CHUNK, SHA256_PATTERN, BlobStore, human_size, is_blocked, kind_for, mime_for,
    sanitize_name,
)
from store import MAX_PAGE, MAX_SEARCH_RESULTS, StoredMessage, search_terms

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5050
AUTO_PORT_RANGE = range(5050, 5060)
SHUTDOWN_COMMANDS = {"quit", "stop", "exit"}
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,32}")
MENTION_PATTERN = re.compile(r"(?<![\w@])@([A-Za-z0-9_.-]{1,32})")
MAX_PASSWORD_LENGTH = 128
MAX_CHAT_BYTES = MAX_MESSAGE_BYTES - 128  # leave room for the "[HH:MM] name: " prefix
HANDSHAKE_TIMEOUT = 10.0
DEFAULT_IDLE_TIMEOUT = 30.0
DEFAULT_QUEUE_SIZE = 100
HISTORY_LIMIT = 50
HISTORY_HEADER = "--- Earlier messages ---"
HISTORY_FOOTER = "--- End of earlier messages ---"
DEFAULT_MAX_UPLOAD = 25 * 1024 * 1024
DEFAULT_USER_QUOTA = 500 * 1024 * 1024
TICKET_LIFETIME = 60.0
MAX_OPEN_TICKETS = 5
MAX_TRANSFERS = 8
TRANSFER_TIMEOUT = 15.0
SESSION_LIFETIME = 12 * 3600.0
DEFAULT_RATE_LIMIT = (30.0, 10.0)  # (burst, per second) of actions per person
DEFAULT_CONNECTION_LIMIT = (240, 60.0)  # new connections per address per minute (every picture preview is one)
LIMITED_EVENTS = {"send": 1.0, "edit": 1.0, "delete": 1.0, "react": 1.0, "pin": 1.0, "upload": 2.0,
                  "download": 1.0, "search": 2.0, "history": 2.0, "passwd": 5.0, "export": 5.0,
                  "keys_publish": 5.0, "keys_get": 1.0, "keys_backup_get": 3.0, "keys_reset": 5.0}
HELP_TEXT = (
    "Commands:\n"
    "  /users            list who is online\n"
    "  /members          list everyone and their role\n"
    "  /msg <name> <text> send a private message (saved)\n"
    "  /search <words>   find messages\n"
    "  /pins             show pinned messages\n"
    "  /passwd <old> <new> change your password\n"
    "  /help             show this help\n"
    "  /quit             leave the chat"
)

_COLOR = supports_color()


def _style(code: str, text: str) -> str:
    return colorize(code, text, enabled=_COLOR)


def _now() -> str:
    return time.strftime("%H:%M")


@dataclass(eq=False)
class Client:
    connection: socket.socket
    address: tuple[str, int]
    username: str
    outbox: queue.Queue = field(repr=False)
    user_id: int = 0
    role: str = "member"
    version: int = 1
    status: str = "online"
    last_typing: float = 0.0
    last_search: float = 0.0
    ip: str = ""
    warned: float = 0.0
    token_hash: str | None = None
    new_token: str | None = None  # handed out once, in the welcome
    limiter: RateLimiter | None = field(default=None, repr=False)
    closed: threading.Event = field(default_factory=threading.Event, repr=False)


def build_tls_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    return context


class ChatServer(AdminMixin, KeysMixin):
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int | None = DEFAULT_PORT,
        *,
        accounts: AccountStore | None = None,
        tls_context: ssl.SSLContext | None = None,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        quiet: bool = False,
        display_name: str | None = None,
        discovery: bool = False,
        discovery_port: int = DISCOVERY_PORT,
        port_range=AUTO_PORT_RANGE,
        storage_dir: str | Path | None = None,
        max_upload: int = DEFAULT_MAX_UPLOAD,
        user_quota: int = DEFAULT_USER_QUOTA,
        transfer_timeout: float = TRANSFER_TIMEOUT,
        rate_limit: tuple[float, float] | None = DEFAULT_RATE_LIMIT,
        connection_limit: tuple[int, float] | None = DEFAULT_CONNECTION_LIMIT,
        enforce_password_policy: bool = True,
        session_lifetime: float = SESSION_LIFETIME,
    ) -> None:
        self.host = host
        self.port = port  # None means: use the first free port in port_range
        self.port_range = port_range
        self.bound_port = port or 0
        self.display_name = display_name or socket.gethostname().split(".")[0]
        self.discovery = discovery
        self.discovery_port = discovery_port
        self._responder: DiscoveryResponder | None = None
        self.accounts = accounts or AccountStore(Path(__file__).with_name("accounts.json"))
        self.store = self.accounts.store
        if storage_dir is None:
            storage_dir = self.store.path.with_name(self.store.path.stem + "_files")
        self.blobs = BlobStore(storage_dir)
        self.default_max_upload = max_upload
        self.default_user_quota = user_quota
        self.transfer_timeout = transfer_timeout
        self._tickets: dict[str, dict] = {}
        self._ticket_lock = threading.Lock()
        self._transfer_slots = threading.BoundedSemaphore(MAX_TRANSFERS)
        self.rate_limit = rate_limit
        self.enforce_password_policy = enforce_password_policy
        self.session_lifetime = session_lifetime
        self.login_guard = LoginGuard()
        self.register_limit = SlidingWindow(10, 3600.0)
        self.connect_limit = SlidingWindow(*connection_limit) if connection_limit else None
        self.tls_context = tls_context
        self.idle_timeout = idle_timeout
        self.queue_size = queue_size
        self.quiet = quiet
        self._clients: dict[socket.socket, Client] = {}
        self._lock = threading.Lock()
        self._shutdown = threading.Event()
        self._server_socket: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None

    def _log(self, code: str, text: str) -> None:
        if not self.quiet:
            print(_style(code, text))

    @property
    def max_upload(self) -> int:
        return self._int_setting("max_upload", self.default_max_upload)

    @property
    def user_quota(self) -> int:
        return self._int_setting("user_quota", self.default_user_quota)

    @property
    def blocked_extensions(self) -> frozenset[str]:
        raw = self.store.get_setting("blocked_extensions")
        if raw is None:
            return BLOCKED_EXTENSIONS
        return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())

    @property
    def open_registration(self) -> bool:
        return self.store.get_setting("open_registration", "1") != "0"

    @property
    def password_min(self) -> int:
        return self._int_setting("password_min", DEFAULT_MIN_PASSWORD)

    def audit(self, actor: str, action: str, target: str = "", detail: str = "") -> None:
        """Record who did what. Never raises: a full disk must not take the chat down."""
        try:
            self.store.append_audit(actor, action, target, detail)
        except sqlite3.Error:
            pass

    def _int_setting(self, key: str, default: int) -> int:
        try:
            return int(self.store.get_setting(key, str(default)))
        except (TypeError, ValueError):
            return default

    def info(self) -> dict:
        return {
            "name": self.display_name,
            "port": self.bound_port,
            "tls": self.tls_context is not None,
            "users": len(self._clients),
        }

    def _bind(self) -> socket.socket:
        candidates = [self.port] if self.port is not None else list(self.port_range)
        last_error: OSError | None = None
        for candidate in candidates:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((self.host, candidate))
                server_socket.listen()
                return server_socket
            except OSError as error:
                server_socket.close()
                last_error = error
                if error.errno != errno.EADDRINUSE:
                    raise
        assert last_error is not None
        raise last_error

    def start(self) -> None:
        server_socket = self._bind()
        self._server_socket = server_socket
        self.bound_port = server_socket.getsockname()[1]
        if self.discovery:
            try:
                self._responder = DiscoveryResponder(self.info, self.discovery_port)
                self._responder.start()
            except OSError as error:
                self._responder = None
                self._log(YELLOW, f"LAN discovery unavailable ({error.strerror or error}); "
                                  "clients must enter the address.")
        self._accept_thread = threading.Thread(
            target=self._accept_loop, args=(server_socket,), daemon=True
        )
        self._accept_thread.start()

    def stop(self) -> None:
        self._shutdown_server()
        if self._responder is not None:
            self._responder.stop()
            self._responder = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1)

    def serve_forever(self) -> None:
        self.start()
        mode = "encrypted (TLS)" if self.tls_context else "NOT encrypted (plain TCP)"
        self._log(CYAN, f"Chat server '{self.display_name}' running on port {self.bound_port}, {mode}")
        self._log(CYAN, f"Address for other devices: {lan_address()}:{self.bound_port}")
        if self._responder is not None:
            self._log(GREEN, "Others on this network can just run:  python3 chat.py")
        self._log(
            DIM, "Type 'quit' + Enter or press Ctrl+C to stop the server."
        )
        self._wait_for_shutdown_command()
        self.stop()

    def _accept_loop(self, server_socket: socket.socket) -> None:
        while not self._shutdown.is_set():
            try:
                connection, address = server_socket.accept()
            except OSError:
                return
            if self.connect_limit is not None and not self.connect_limit.allow(address[0]):
                self._close_socket(connection)  # too many connections from one address
                continue
            threading.Thread(
                target=self._register_client,
                args=(connection, address),
                daemon=True,
            ).start()

    def _wait_for_shutdown_command(self) -> None:
        try:
            while not self._shutdown.is_set():
                command = input().strip()
                lowered = command.lower()
                if lowered in SHUTDOWN_COMMANDS:
                    return
                if lowered == "members":
                    print(self._members_reply())
                elif lowered.startswith("role "):
                    parts = command.split()
                    if len(parts) != 3:
                        print(_style(YELLOW, "usage: role <username> <admin|member|guest>"))
                    else:
                        problem = self.set_role(parts[1], parts[2])
                        print(_style(RED, problem) if problem else _style(GREEN, f"{parts[1]} is now {parts[2]}"))
        except (EOFError, KeyboardInterrupt):
            print()

    def set_role(self, username: str, role: str, actor: str = "console") -> str | None:
        """Change someone's role. Returns an error message, or None on success."""
        try:
            found = self.store.set_role(username, role)
        except ValueError as error:
            return str(error)
        if not found:
            return f"no user named '{username}'"
        with self._lock:
            online = [c for c in self._clients.values() if c.username.lower() == username.lower()]
        for client in online:
            client.role = role
        self._notice("role", f"Your role is now {role}.", targets=online)
        canonical = self.store.get_user(username).username
        self.audit(actor, "role_changed", canonical, f"now {role}")
        self._notice("role", f"{canonical}'s role changed to {role}.")
        self._push_members()
        return None

    def _shutdown_server(self) -> None:
        if self._shutdown.is_set():
            return
        self._shutdown.set()
        self._log(YELLOW, "Stopping server...")

        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()

        self._notice("shutdown", "Server is shutting down. Goodbye!", targets=clients)
        if clients:
            time.sleep(0.2)  # let the writer threads flush the notice
        for client in clients:
            self._log(DIM, f"Disconnecting: {client.username} ({client.address})")
            self._record_departure(client)
            self._close_client(client)

        if self._server_socket is not None:
            self._close_socket(self._server_socket)

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)  # wakes threads blocked on this socket
        except (OSError, ValueError):
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _close_client(self, client: Client) -> None:
        client.closed.set()
        try:
            client.outbox.put_nowait(None)
        except queue.Full:
            pass
        self._close_socket(client.connection)

    def _members_reply(self) -> str:
        """The plain-text member list for legacy clients: 'Members (n): name:role:online, ...'."""
        rows = self._member_rows()
        entries: list[str] = []
        size = 0
        for name, role, status in rows:
            entry = f"{name}:{role}:{int(status != 'offline')}"
            if size + len(entry) + 2 > MAX_CHAT_BYTES - 60:
                break  # keep the reply inside one frame (about 140 members)
            entries.append(entry)
            size += len(entry) + 2
        hidden = len(rows) - len(entries)
        if hidden:
            entries.append(f"+{hidden} more")
        return f"Members ({len(rows)}): {', '.join(entries)}"

    def _member_rows(self) -> list[tuple[str, str, str]]:
        """[(name, role, status)] for everyone with an account; status is online, away or offline."""
        with self._lock:
            states = {client.user_id: client.status for client in self._clients.values()}
        users = sorted((u for u in self.store.list_users() if not u.disabled), key=lambda u: u.username.lower())
        return [(u.username, u.role, states.get(u.id, "offline")) for u in users]

    def _push_members(self, targets: list[Client] | None = None) -> None:
        for page in member_pages(self._member_rows()):
            self._emit(page, targets)

    # ----- delivering events (JSON for v2 clients, plain text for legacy ones)

    def _emit(self, event: dict, targets: list[Client] | None = None, exclude: Client | None = None) -> None:
        if targets is None:
            with self._lock:
                targets = list(self._clients.values())
        encoded: str | None = None
        for client in targets:
            if client is exclude:
                continue
            if client.version >= 2:
                if encoded is None:
                    encoded = fit_frame(event)
                self._enqueue(client, encoded)
            else:
                text = legacy_text(event, client.username)
                if text is not None:
                    self._enqueue(client, text)

    def _notice(self, kind: str, text: str, targets: list[Client] | None = None,
                exclude: Client | None = None) -> None:
        self._emit({"t": "notice", "kind": kind, "text": text, "ts": time.time()}, targets, exclude)

    def _error(self, client: Client, text: str) -> None:
        self._notice("error", f"Error: {text}", [client])

    def _info(self, client: Client, text: str) -> None:
        self._notice("info", text, [client])

    def _targets_for(self, message: StoredMessage) -> list[Client]:
        """Everyone for public messages; only the two people involved for private ones."""
        with self._lock:
            clients = list(self._clients.values())
        if message.recipient_id is None:
            return clients
        return [c for c in clients if c.user_id in (message.sender_id, message.recipient_id)]

    def _message_events(self, messages: list[StoredMessage], history: bool = False) -> list[dict]:
        ids = [m.id for m in messages]
        reactions = self.store.reactions_for(ids)
        mentions = self.store.mentions_for(ids)
        attachments = self.store.attachments_for(ids)
        events = []
        for message in messages:
            parent = self.store.get_message(message.reply_to) if message.reply_to else None
            events.append(message_event(message, parent, reactions.get(message.id), history,
                                        mentions.get(message.id), attachments.get(message.id)))
        return events

    # ----- connecting

    def _register_client(
        self, connection: socket.socket, address: tuple[str, int]
    ) -> None:
        try:
            connection.settimeout(HANDSHAKE_TIMEOUT)
            if self.tls_context is not None:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            client = self._handshake(connection, address)
            if client is None:
                return
            connection.settimeout(self.idle_timeout)
            self._notice("join", f"{client.username} joined the chat.", exclude=client)
            self._push_members()
            self._handle_client(client)
        except (ConnectionError, OSError, UnicodeError, ValueError):
            pass
        finally:
            self._remove_client(connection)

    def _handshake(
        self, connection: socket.socket, address: tuple[str, int]
    ) -> Client | None:
        ip = address[0]
        send_message(connection, "USERNAME")
        first = (receive_message(connection) or "").strip()
        version, username, token = 1, first, None
        if first.startswith("{"):  # a protocol v2 client introduces itself with JSON
            try:
                hello = json.loads(first)
                if isinstance(hello, dict) and "data" in hello:
                    self._handle_transfer(connection, hello)
                    return None
                version = int(hello["v"])
                username = str(hello["username"]).strip()
                token = hello.get("token")
                if token is not None and not isinstance(token, str):
                    raise TypeError("token")
            except (ValueError, KeyError, TypeError):
                send_message(connection, "ERROR: malformed login")
                return None
            if version != PROTOCOL_VERSION:
                send_message(connection, "ERROR: unsupported protocol version")
                return None
        if not USERNAME_PATTERN.fullmatch(username):
            send_message(
                connection,
                "ERROR: username must be 1-32 letters, digits, '_', '.' or '-'",
            )
            return None

        wait = self.login_guard.retry_after(ip, username)
        if wait > 0:
            send_message(connection, f"ERROR: too many failed attempts, try again in {math.ceil(wait)} seconds")
            return None

        if token is not None:
            user = self._user_for_token(token, username)
            if user is None:
                send_message(connection, "ERROR: your session has expired, please sign in again")
                return None
            status = "token"
        else:
            send_message(connection, "PASSWORD")
            password = receive_message(connection)
            if not password or len(password) > MAX_PASSWORD_LENGTH:
                send_message(connection, "ERROR: invalid password")
                return None
            refusal = self._refuse_new_account(ip, username, password)
            if refusal:
                send_message(connection, f"ERROR: {refusal}")
                return None
            status, user = self.accounts.authenticate(username, password)
            if status == "bad_password":
                locked = self.login_guard.failed(ip, username)
                self.audit(username, "login_failed", detail=f"from {ip}")
                if locked:
                    self.audit(username, "lockout", detail=f"{int(locked)} s from {ip}")
                    send_message(connection, f"ERROR: wrong password; too many attempts, locked for {int(locked)} seconds")
                else:
                    send_message(connection, "ERROR: wrong password")
                return None
            self.login_guard.succeeded(ip, username)
        if user.disabled:
            send_message(connection, "ERROR: this account is disabled")
            return None
        name = user.username

        client = Client(
            connection, address, name, queue.Queue(maxsize=self.queue_size),
            user_id=user.id, role=user.role, version=version, ip=ip,
            limiter=RateLimiter(*self.rate_limit) if self.rate_limit else None,
        )
        if not self._claim_name(client, replace=status == "token"):
            send_message(connection, "ERROR: that user is already logged in")
            return None

        if version >= 2:
            if token is not None:
                client.token_hash = hashlib.sha256(token.encode()).hexdigest()
            else:
                client.new_token = secrets.token_urlsafe(32)
                client.token_hash = hashlib.sha256(client.new_token.encode()).hexdigest()
                self.store.create_session(user.id, client.token_hash, self.session_lifetime, ip)
        send_message(connection, "OK")
        # Welcome and history go out directly (before the writer thread starts) so
        # they arrive first, in order, and cannot overflow the outbox.
        self._send_welcome(connection, client)
        client.new_token = None
        threading.Thread(target=self._writer_loop, args=(client,), daemon=True).start()
        if status == "registered":
            self._log(GREEN, f"New account created: {name} ({user.role})")
            self.audit(name, "account_created", detail=f"role {user.role}, from {ip}")
        self.audit(name, "login" if status != "token" else "session_resumed", detail=f"from {ip}")
        self._log(GREEN, f"Connected: {address} as {name} (protocol {version})")
        return client

    def _refuse_new_account(self, ip: str, username: str, password: str) -> str | None:
        """A reason to turn this login away if it would create an account that should not exist."""
        if self.store.get_user(username) is not None:
            return None
        if not self.open_registration:
            return "new accounts are closed on this server; ask an admin to create yours"
        if self.enforce_password_policy:
            problem = check_password(password, username, self.password_min)
            if problem:
                return f"choose a stronger password ({problem})"
        if not self.register_limit.allow(ip):
            return "too many new accounts were created from this address; try again later"
        return None

    def _user_for_token(self, token: str, username: str):
        user_id = self.store.session_user(hashlib.sha256(token.encode()).hexdigest())
        user = self.store.get_user_by_id(user_id) if user_id else None
        return user if user and user.username.lower() == username.lower() else None

    def _claim_name(self, client: Client, replace: bool) -> bool:
        """Register the connection under its username. A signed-in session may take over a stale one."""
        for _attempt in range(2):
            with self._lock:
                old = next((c for c in self._clients.values()
                            if c.username.lower() == client.username.lower()), None)
                if old is None:
                    self._clients[client.connection] = client
                    return True
            if not replace:
                return False
            self._remove_client(old.connection)
        return False

    def _send_welcome(self, connection: socket.socket, client: Client) -> None:
        events = self._message_events(self.store.history_for(client.user_id, HISTORY_LIMIT), history=True)
        if client.version >= 2:
            self._send_welcome_v2(connection, client, events)
            return
        send_message(connection, "Connected to LAN Chat!")
        lines = [text for text in (legacy_text(e, client.username) for e in events) if text]
        if not lines:
            return
        send_message(connection, HISTORY_HEADER)
        for line in lines:
            try:
                send_message(connection, line)
            except ValueError:
                continue  # a stored line too big for one frame is skipped
        send_message(connection, HISTORY_FOOTER)

    def _send_welcome_v2(self, connection: socket.socket, client: Client, events: list[dict]) -> None:
        def push(event: dict) -> None:
            send_message(connection, fit_frame(event))

        push({
            "t": "welcome", "protocol": PROTOCOL_VERSION, "server": self.display_name,
            "you": {"name": client.username, "role": client.role},
            "last_read": self.store.get_last_read(client.user_id),
            "latest": self.store.latest_message_id(),
            "max_body": MAX_BODY_BYTES,
            "token": client.new_token,
            "e2ee": self.e2ee_state(client),
            "limits": {"max_upload": self.max_upload, "blocked": sorted(self.blocked_extensions)},
        })
        if events:
            has_more = self.store.has_older(client.user_id, events[0]["id"])
            push({"t": "history_start", "count": len(events), "has_more": has_more})
            for event in events:
                push(event)
            push({"t": "history_end"})
        push(pins_event(self.store.pinned()))
        for page in member_pages(self._member_rows()):
            push(page)

    def _writer_loop(self, client: Client) -> None:
        """The only thread that writes to a registered client's socket."""
        while True:
            message = client.outbox.get()
            if message is None or client.closed.is_set():
                return
            try:
                send_message(client.connection, message)
            except ValueError:
                continue
            except OSError:
                self._remove_client(client.connection)
                return

    def _enqueue(self, client: Client, message: str) -> None:
        if client.closed.is_set():
            return
        try:
            client.outbox.put_nowait(message)
        except queue.Full:
            self._log(YELLOW, f"Dropping slow client: {client.username}")
            self._remove_client(client.connection)

    # ----- receiving

    def _handle_client(self, client: Client) -> None:
        while True:
            frame = receive_message(client.connection)
            if frame is None:
                return
            if client.version >= 2:
                self._handle_event(client, frame)
            else:
                text = frame.strip()
                if not text:
                    continue
                if not self._within_rate(client, 1.0):
                    continue
                if text.startswith("/"):
                    self._handle_command(client, text)
                else:
                    self._post_message(client, text)

    def _handle_event(self, client: Client, frame: str) -> None:
        event = decode(frame)
        if event is None:
            self._error(client, "unrecognised message.")
            return
        handler = self._EVENT_HANDLERS.get(event["t"])
        if handler is None:
            self._error(client, f"unknown event '{event['t']}'.")
            return
        if not self._within_rate(client, LIMITED_EVENTS.get(event["t"], 0.0)):
            return
        handler(self, client, event)

    def _within_rate(self, client: Client, cost: float) -> bool:
        if cost <= 0 or client.limiter is None or client.limiter.allow(cost):
            return True
        now = time.monotonic()
        if now - client.warned > 5.0:  # tell them, but do not answer a flood with a flood
            client.warned = now
            self._error(client, "you are doing that too fast; wait a moment.")
            self.audit(client.username, "rate_limited", detail=f"from {client.ip}")
        return False

    def _handle_command(self, client: Client, text: str) -> None:
        command = text.split(None, 1)[0].lower()
        if command == "/ping":
            return
        if command == "/help":
            self._info(client, HELP_TEXT)
        elif command == "/users":
            with self._lock:
                names = sorted((c.username for c in self._clients.values()), key=str.lower)
            self._info(client, f"Online ({len(names)}): {', '.join(names)}")
        elif command == "/members":
            if client.version >= 2:
                self._push_members([client])
            else:
                self._info(client, self._members_reply())
        elif command == "/search":
            query = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            results = self.store.search(client.user_id, query, 10)
            if not results:
                self._info(client, "No messages found." if search_terms(query) else "Usage: /search <words>")
            else:
                lines = [f"[{clock(m.created_at)}] {m.sender}: {snippet(m.body, 70)}" for m in results]
                self._info(client, "Search results (newest first):\n" + "\n".join(lines))
        elif command == "/pins":
            pinned = self.store.pinned()
            if not pinned:
                self._info(client, "Nothing is pinned.")
            else:
                lines = [f"{m.sender}: {snippet(m.body, 70)}" for m in pinned]
                self._info(client, "Pinned messages:\n" + "\n".join(lines))
        elif command == "/passwd":
            parts = text.split()
            if len(parts) != 3:
                self._error(client, "usage is /passwd <current password> <new password>")
            else:
                ok, reason, _token = self._change_password(client, parts[1], parts[2])
                self._info(client, "Password changed.") if ok else self._error(client, reason)
        elif command == "/msg":
            parts = text.split(None, 2)
            if len(parts) < 3:
                self._error(client, "usage is /msg <name> <text>")
            else:
                self._post_message(client, parts[2], to_name=parts[1])
        else:
            self._error(client, "unknown command. Type /help.")

    @staticmethod
    def _same_conversation(parent: StoredMessage, sender_id: int, recipient_id: int | None) -> bool:
        if parent.recipient_id is None:
            return recipient_id is None
        return recipient_id is not None and {parent.sender_id, parent.recipient_id} == {sender_id, recipient_id}

    def _check_target(self, sender: Client, to_name, reply_to) -> tuple[bool, object]:
        """Validate the recipient and the reply target. Returns (ok, recipient user or None);
        on a problem the sender has already been told why."""
        recipient = None
        if to_name is not None:
            if not can(sender.role, "send_private"):
                self._error(sender, "your role cannot send private messages.")
                return False, None
            recipient = self.store.get_user(to_name)
            if recipient is None or recipient.disabled:
                self._error(sender, f"no user named '{to_name}'.")
                return False, None
            if recipient.id == sender.user_id:
                self._error(sender, "you cannot message yourself.")
                return False, None
        recipient_id = recipient.id if recipient else None
        if reply_to is not None:
            parent = self.store.get_message(reply_to) if isinstance(reply_to, int) else None
            if parent is None or not self._same_conversation(parent, sender.user_id, recipient_id):
                self._error(sender, "you can only reply to a message in this conversation.")
                return False, None
        return True, recipient

    def _post_message(self, sender: Client, body: str, to_name: str | None = None,
                      reply_to: int | None = None, attachment: dict | None = None,
                      enc: str | None = None) -> int | None:
        """Store and deliver a message. Returns its id, or None if it was refused.

        `enc` is an end-to-end encrypted envelope (JSON text). The server stores and relays it
        without being able to read it, so it skips everything that needs the words themselves."""
        body = body.strip()
        if not body and attachment is None and enc is None:
            return None
        if to_name is not None and enc is None and self.e2ee_policy == "required":
            self._error(sender, "this server requires end-to-end encryption for private messages: "
                                "use the chat window and unlock your keys.")
            return None
        if not can(sender.role, "send_message"):
            self._error(sender, "your role cannot send messages.")
            return None
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            self._error(sender, "message too long.")
            return None
        ok, recipient = self._check_target(sender, to_name, reply_to)
        if not ok:
            return None
        recipient_id = recipient.id if recipient else None

        mention_ids: list[int] = []
        everyone = False
        if recipient is None and enc is None:
            mention_ids, everyone, problem = self._parse_mentions(sender, body)
            if problem:
                self._error(sender, problem)
                return None

        message_id = self.store.add_message(
            sender.user_id, body, recipient_id=recipient_id, reply_to=reply_to,
            mentions=mention_ids, mention_all=everyone,
            kind=attachment["kind"] if attachment else "text", enc=enc,
        )
        if attachment is not None:
            self.store.add_attachment(
                message_id, sender.user_id, attachment["sha256"], attachment["name"],
                attachment["mime"], attachment["size"], attachment["kind"],
            )
        message = self.store.get_message(message_id)
        self._emit(self._message_events([message])[0], self._targets_for(message))
        if recipient is not None:
            with self._lock:
                recipient_online = any(c.user_id == recipient.id for c in self._clients.values())
            if not recipient_online:
                self._info(sender, f"{recipient.username} is offline and will see this when they next join.")
        return message_id

    def _parse_mentions(self, sender: Client, body: str) -> tuple[list[int], bool, str | None]:
        """Who does '@name' point at? Returns (user ids, @everyone?, an error message or None)."""
        ids: list[int] = []
        everyone = False
        for token in dict.fromkeys(MENTION_PATTERN.findall(body)):
            token = token.rstrip(".-")
            if token.lower() == "everyone":
                if not can(sender.role, "mention_everyone"):
                    return [], False, "only admins can mention @everyone."
                everyone = True
                continue
            user = self.store.get_user(token) if token else None
            if user is not None and not user.disabled and user.id != sender.user_id:
                ids.append(user.id)
        return ids, everyone, None

    def _visible_message(self, client: Client, message_id) -> StoredMessage | None:
        """The message, if it exists and this client is allowed to see it."""
        if not isinstance(message_id, int) or isinstance(message_id, bool):
            return None
        message = self.store.get_message(message_id)
        if message is None:
            return None
        if message.recipient_id is not None and client.user_id not in (message.sender_id, message.recipient_id):
            return None
        return message

    # ----- v2 event handlers

    def _on_ping(self, client: Client, event: dict) -> None:
        return

    def _checked_envelope(self, client: Client, enc, to_name) -> str | None:
        """The envelope as JSON text if it is acceptable, else None (the sender has been told why)."""
        if self.e2ee_policy == "off":
            self._error(client, "end-to-end encryption is switched off on this server.")
            return None
        if not isinstance(to_name, str):
            self._error(client, "only private messages can be end-to-end encrypted for now.")
            return None
        recipient = self.store.get_user(to_name)
        try:
            people = e2ee.envelope_people(enc)
            if recipient is None or people != sorted({client.username.lower(), recipient.username.lower()}):
                raise e2ee.CryptoError("wrong recipients")
            if e2ee.envelope_size(enc) > e2ee.MAX_ENVELOPE_CHARS:
                raise e2ee.CryptoError("too large")
        except e2ee.CryptoError:
            self._error(client, "that encrypted message is malformed or too long.")
            return None
        return json.dumps(enc, separators=(",", ":"))

    def _on_send(self, client: Client, event: dict) -> None:
        enc = event.get("enc")
        if enc is not None:
            to_name, reply_to = event.get("to"), event.get("reply_to")
            if event.get("body") not in (None, ""):
                self._error(client, "an encrypted message must not also carry readable text.")
                return
            text = self._checked_envelope(client, enc, to_name)
            if text is not None:
                self._post_message(client, "", to_name=to_name, reply_to=reply_to, enc=text)
            return
        body, to_name, reply_to = event.get("body"), event.get("to"), event.get("reply_to")
        if not isinstance(body, str) or not (to_name is None or isinstance(to_name, str)):
            self._error(client, "malformed message.")
            return
        if body.strip().startswith("/"):
            self._handle_command(client, body.strip())
        else:
            self._post_message(client, body, to_name=to_name, reply_to=reply_to)

    def _on_edit(self, client: Client, event: dict) -> None:
        message = self._visible_message(client, event.get("id"))
        if message is None:
            self._error(client, "that message does not exist.")
            return
        if message.sender_id != client.user_id or not can(client.role, "edit_own"):
            self._error(client, "you can only edit your own messages.")
            return
        if message.deleted_at is not None:
            self._error(client, "that message was deleted.")
            return
        if message.enc is not None or event.get("enc") is not None:
            self._edit_encrypted(client, message, event)
            return
        body = event.get("body")
        if not isinstance(body, str) or not body.strip():
            self._error(client, "a message cannot be empty.")
            return
        body = body.strip()
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            self._error(client, "message too long.")
            return
        if self.store.edit_message(message.id, client.user_id, body):
            updated = self.store.get_message(message.id)
            self._emit({"t": "edited", "id": message.id, "body": body, "edited_at": updated.edited_at},
                       self._targets_for(updated))

    def _edit_encrypted(self, client: Client, message: StoredMessage, event: dict) -> None:
        """Replace the envelope of an encrypted message; an encrypted message never turns into plain text."""
        if message.enc is None or event.get("enc") is None or event.get("body") not in (None, ""):
            self._error(client, "an encrypted message can only be edited with a new encrypted version.")
            return
        text = self._checked_envelope(client, event["enc"], message.recipient)
        if text is None:
            return
        if self.store.edit_message(message.id, client.user_id, "", enc=text):
            updated = self.store.get_message(message.id)
            self._emit({"t": "edited", "id": message.id, "body": "", "enc": json.loads(text),
                        "edited_at": updated.edited_at}, self._targets_for(updated))

    def _on_delete(self, client: Client, event: dict) -> None:
        message = self._visible_message(client, event.get("id"))
        if message is None:
            self._error(client, "that message does not exist.")
            return
        own = message.sender_id == client.user_id
        if not ((own and can(client.role, "delete_own")) or can(client.role, "delete_any")):
            self._error(client, "you cannot delete that message.")
            return
        was_pinned = self.store.is_pinned(message.id)
        attachment = self.store.attachment_for_message(message.id)
        if self.store.delete_message(message.id):
            if attachment and not self.store.sha_in_use(attachment["sha256"]):
                self.blobs.remove(attachment["sha256"])
            if not own:
                self._log(YELLOW, f"{client.username} deleted message {message.id} by {message.sender}")
                self.audit(client.username, "message_deleted", message.sender, f"message {message.id}")
            self._emit({"t": "deleted", "id": message.id}, self._targets_for(message))
            if was_pinned:
                self._emit(pins_event(self.store.pinned()))

    @staticmethod
    def _valid_emoji(emoji) -> bool:
        return (
            isinstance(emoji, str) and 1 <= len(emoji) <= 16 and emoji.isprintable()
            and not any(ch.isspace() for ch in emoji)
        )

    def _on_react(self, client: Client, event: dict) -> None:
        if not can(client.role, "react"):
            self._error(client, "your role cannot react.")
            return
        message = self._visible_message(client, event.get("id"))
        if message is None:
            self._error(client, "that message does not exist.")
            return
        if message.deleted_at is not None:
            self._error(client, "that message was deleted.")
            return
        emoji = event.get("emoji")
        if not self._valid_emoji(emoji):
            self._error(client, "that is not a valid reaction.")
            return
        try:
            self.store.toggle_reaction(message.id, client.user_id, emoji)
        except ValueError as error:
            self._error(client, str(error) + ".")
            return
        reactions = self.store.reactions_for([message.id]).get(message.id, [])
        self._emit(reactions_event(message.id, reactions), self._targets_for(message))

    def _on_typing(self, client: Client, event: dict) -> None:
        on = bool(event.get("on"))
        now = time.monotonic()
        if on and now - client.last_typing < 0.8:
            return  # clients throttle themselves; this just protects the server
        client.last_typing = now
        self._emit({"t": "typing", "user": client.username, "on": on}, exclude=client)

    def _on_presence(self, client: Client, event: dict) -> None:
        status = event.get("status")
        if status not in ("online", "away"):
            return
        client.status = status
        self._emit({"t": "presence", "user": client.username, "status": status})

    def _on_read(self, client: Client, event: dict) -> None:
        up_to = event.get("up_to")
        if not isinstance(up_to, int) or isinstance(up_to, bool) or up_to <= 0:
            return
        up_to = min(up_to, self.store.latest_message_id())
        if self.store.set_last_read(client.user_id, up_to):
            self._emit({"t": "read", "user": client.username, "up_to": up_to})

    def _on_members(self, client: Client, event: dict) -> None:
        self._push_members([client])

    def _on_pin(self, client: Client, event: dict) -> None:
        message = self._visible_message(client, event.get("id"))
        if message is None:
            self._error(client, "that message does not exist.")
            return
        if message.recipient_id is not None:
            self._error(client, "only public messages can be pinned.")
            return
        if message.deleted_at is not None:
            self._error(client, "that message was deleted.")
            return
        allowed = can(client.role, "pin_any") or (message.sender_id == client.user_id and can(client.role, "pin_own"))
        if not allowed:
            self._error(client, "you cannot pin that message.")
            return
        if event.get("on", True):
            try:
                changed = self.store.pin_message(message.id, client.user_id)
            except ValueError as error:
                self._error(client, f"{error}.")
                return
            if changed:
                self._notice("info", f"{client.username} pinned a message.")
        else:
            changed = self.store.unpin_message(message.id)
        if changed:
            self._emit(pins_event(self.store.pinned()))

    def _on_search(self, client: Client, event: dict) -> None:
        query = event.get("q")
        if not isinstance(query, str) or len(query) > 200:
            self._error(client, "that search is not valid.")
            return
        now = time.monotonic()
        if now - client.last_search < 0.2:
            return  # typing fast: only the latest search matters
        client.last_search = now
        terms = search_terms(query)
        results = [
            {"id": m.id, "sender": m.sender, "to": m.recipient, "ts": m.created_at,
             "snippet": snippet_around(m.body, terms)}
            for m in self.store.search(client.user_id, query, MAX_SEARCH_RESULTS)
        ]
        self._emit(search_event(event.get("req", 0), query, results), [client])

    def _on_history(self, client: Client, event: dict) -> None:
        before, limit = event.get("before"), event.get("limit", MAX_PAGE)
        if not isinstance(before, int) or isinstance(before, bool) or before <= 0 or not isinstance(limit, int):
            self._error(client, "that history request is not valid.")
            return
        messages = self.store.history_before(client.user_id, before, limit)
        has_more = bool(messages) and self.store.has_older(client.user_id, messages[0].id)
        self._emit({"t": "page_start", "before": before, "count": len(messages), "has_more": has_more}, [client])
        for page_event in self._message_events(messages, history=True):
            self._emit({**page_event, "page": True}, [client])
        self._emit({"t": "page_end", "before": before}, [client])

    # ----- file transfer: a ticket from the chat connection, then a separate data connection

    def _issue_ticket(self, client: Client, kind: str, **details) -> str | None:
        now = time.time()
        with self._ticket_lock:
            for token in [t for t, d in self._tickets.items() if d["expires"] < now]:
                del self._tickets[token]
            if sum(1 for d in self._tickets.values() if d["user_id"] == client.user_id) >= MAX_OPEN_TICKETS:
                return None
            token = secrets.token_urlsafe(24)
            self._tickets[token] = {"kind": kind, "user_id": client.user_id,
                                    "expires": now + TICKET_LIFETIME, **details}
            return token

    def _take_ticket(self, token, kind: str) -> dict | None:
        """One use only: the ticket is gone as soon as it is presented."""
        if not isinstance(token, str):
            return None
        with self._ticket_lock:
            ticket = self._tickets.pop(token, None)
        if ticket is None or ticket["kind"] != kind or ticket["expires"] < time.time():
            return None
        return ticket

    def _online_client(self, user_id: int) -> Client | None:
        with self._lock:
            return next((c for c in self._clients.values() if c.user_id == user_id), None)

    def _on_upload(self, client: Client, event: dict) -> None:
        req = event.get("req")

        def deny(reason: str) -> None:
            self._emit({"t": "upload_denied", "req": req, "reason": reason}, [client])

        if not can(client.role, "upload"):
            return deny("your role cannot share files.")
        name, size, sha = event.get("name"), event.get("size"), event.get("sha256")
        caption, to_name, reply_to = event.get("caption") or "", event.get("to"), event.get("reply_to")
        enc = event.get("enc")  # an end-to-end encrypted file: the server sees only ciphertext and its size
        if enc is not None:
            name, caption = "encrypted file", ""
        if not isinstance(name, str) or not isinstance(caption, str):
            return deny("malformed upload.")
        if not isinstance(size, int) or isinstance(size, bool) or not isinstance(sha, str):
            return deny("malformed upload.")
        if to_name is not None and not isinstance(to_name, str):
            return deny("malformed upload.")
        envelope = None
        if enc is not None:
            envelope = self._checked_envelope(client, enc, to_name)
            if envelope is None:
                return deny("that encrypted file message is not acceptable.")
        elif to_name is not None and self.e2ee_policy == "required":
            return deny("this server requires end-to-end encryption for private files: use the chat window "
                        "and unlock your keys.")
        name = sanitize_name(name)
        if envelope is None and is_blocked(name, self.blocked_extensions):
            return deny(f"{name.rsplit('.', 1)[-1]} files are not allowed here.")
        if size <= 0:
            return deny("that file is empty.")
        if size > self.max_upload:
            return deny(f"that file is too large (the limit is {human_size(self.max_upload)}).")
        if not SHA256_PATTERN.fullmatch(sha):
            return deny("malformed upload.")
        if self.store.attachment_usage(client.user_id) + size > self.user_quota:
            return deny(f"you have used your {human_size(self.user_quota)} of file space.")
        if len(caption.encode("utf-8")) > MAX_BODY_BYTES:
            return deny("the caption is too long.")
        ok, _recipient = self._check_target(client, to_name, reply_to)
        if not ok:
            return deny("that conversation is not available.")
        token = self._issue_ticket(
            client, "up", name=name, size=size, sha256=sha, caption=caption.strip(), to=to_name,
            reply_to=reply_to, mime="application/octet-stream" if envelope else mime_for(name),
            file_kind="encrypted" if envelope else kind_for(name), enc=envelope,
        )
        if token is None:
            return deny("too many uploads at once; try again in a moment.")
        self._emit({"t": "upload_ready", "req": req, "ticket": token}, [client])

    def _on_download(self, client: Client, event: dict) -> None:
        req = event.get("req")
        message = self._visible_message(client, event.get("id"))
        attachment = self.store.attachment_for_message(message.id) if message else None
        if attachment is None or not self.blobs.exists(attachment["sha256"]):
            self._emit({"t": "transfer_error", "req": req, "reason": "that file is no longer available."}, [client])
            return
        token = self._issue_ticket(client, "down", sha256=attachment["sha256"], size=attachment["size"])
        if token is None:
            self._emit({"t": "transfer_error", "req": req, "reason": "too many transfers at once."}, [client])
            return
        self._emit({"t": "download_ready", "req": req, "ticket": token, "id": message.id,
                    "size": attachment["size"], "name": attachment["name"],
                    "sha256": attachment["sha256"]}, [client])

    def _handle_transfer(self, connection: socket.socket, hello: dict) -> None:
        """A data connection: present a ticket, then raw bytes flow one way."""
        kind = {"up": "up", "down": "down"}.get(hello.get("data"))
        ticket = self._take_ticket(hello.get("ticket"), kind) if kind else None
        if ticket is None:
            send_message(connection, "ERROR: invalid or expired ticket")
            return
        if not self._transfer_slots.acquire(blocking=False):
            send_message(connection, "ERROR: the server is busy, try again")
            return
        try:
            connection.settimeout(self.transfer_timeout)
            send_message(connection, "READY")
            if kind == "up":
                self._receive_upload(connection, ticket)
            else:
                self._send_download(connection, ticket)
        finally:
            self._transfer_slots.release()

    def _receive_upload(self, connection: socket.socket, ticket: dict) -> None:
        temp = self.blobs.new_temp()
        digest, remaining = hashlib.sha256(), ticket["size"]
        deadline = time.time() + max(30.0, ticket["size"] / (64 * 1024))
        try:
            with open(temp, "wb") as handle:
                while remaining:
                    if time.time() > deadline:
                        raise TimeoutError("upload too slow")
                    chunk = connection.recv(min(CHUNK, remaining))
                    if not chunk:
                        raise ConnectionError("connection closed during upload")
                    digest.update(chunk)
                    handle.write(chunk)
                    remaining -= len(chunk)
            if digest.hexdigest() != ticket["sha256"]:
                send_message(connection, "ERROR: the file was damaged in transfer")
                return
            client = self._online_client(ticket["user_id"])
            if client is None or not can(client.role, "upload"):
                send_message(connection, "ERROR: you are no longer allowed to share files")
                return
            if self.store.attachment_usage(client.user_id) + ticket["size"] > self.user_quota:
                send_message(connection, "ERROR: you have used all of your file space")
                return
            self.blobs.commit(temp, ticket["sha256"])
            attachment = {"sha256": ticket["sha256"], "name": ticket["name"], "mime": ticket["mime"],
                          "size": ticket["size"], "kind": ticket["file_kind"]}
            message_id = self._post_message(client, ticket["caption"], to_name=ticket["to"],
                                            reply_to=ticket["reply_to"], attachment=attachment,
                                            enc=ticket.get("enc"))
            if message_id is None:
                send_message(connection, "ERROR: the message could not be posted")
                return
            self._log(GREEN, f"{client.username} shared {ticket['name']} ({human_size(ticket['size'])})")
            self.audit(client.username, "file_shared", ticket["name"] if not ticket.get("enc") else "(encrypted)",
                       f"{human_size(ticket['size'])}, sha256 {ticket['sha256'][:12]}")
            send_message(connection, encode({"t": "upload_done", "id": message_id}))
        except (OSError, ValueError):
            pass
        finally:
            temp.unlink(missing_ok=True)

    def _send_download(self, connection: socket.socket, ticket: dict) -> None:
        try:
            if "payload" in ticket:  # generated on the fly, such as a data export
                connection.sendall(ticket["payload"])
                return
            with open(self.blobs.path_for(ticket["sha256"]), "rb") as handle:
                while chunk := handle.read(CHUNK):
                    connection.sendall(chunk)
        except (OSError, ValueError):
            pass

    _EVENT_HANDLERS = {
        "ping": _on_ping, "send": _on_send, "edit": _on_edit, "delete": _on_delete,
        "react": _on_react, "typing": _on_typing, "presence": _on_presence,
        "read": _on_read, "members": _on_members, "pin": _on_pin, "search": _on_search,
        "history": _on_history, "upload": _on_upload, "download": _on_download,
        **AdminMixin.HANDLERS, **KeysMixin.HANDLERS,
    }

    # ----- leaving

    def _remove_client(self, connection: socket.socket) -> None:
        with self._lock:
            client = self._clients.pop(connection, None)
        if client is not None:
            self._log(YELLOW, f"Disconnected: {client.username} ({client.address})")
            self._record_departure(client)
            self._close_client(client)
            self._notice("leave", f"{client.username} left the chat.")
            self._push_members()
        else:
            self._close_socket(connection)

    def _record_departure(self, client: Client) -> None:
        try:
            self.store.touch_last_seen(client.user_id)
        except sqlite3.Error:
            pass  # the database was closed during shutdown


def default_tls_context() -> tuple[ssl.SSLContext | None, str | None]:
    """TLS with an automatically created certificate, or (None, None) without openssl."""
    pair = ensure_certificate(default_home())
    if pair is None:
        return None, None
    certfile, keyfile = str(pair[0]), str(pair[1])
    return build_tls_context(certfile, keyfile), fingerprint_of_pem(Path(certfile).read_text())


def _tls_context_from_args(args) -> tuple[ssl.SSLContext | None, str | None]:
    """Return (context, fingerprint). TLS is on by default with an auto-made cert."""
    if args.no_tls:
        return None, None
    if args.cert or args.key:
        certfile, keyfile = args.cert or "server.crt", args.key or "server.key"
        fingerprint = fingerprint_of_pem(Path(certfile).read_text())
        return build_tls_context(certfile, keyfile), fingerprint
    context, fingerprint = default_tls_context()
    if context is None:
        print(_style(YELLOW, "openssl not found: running WITHOUT encryption. "
                             "Install openssl or pass --no-tls to hide this warning."))
    return context, fingerprint


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the LAN chat server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address")
    parser.add_argument("--port", type=int, help="TCP port (default: first free port from 5050)")
    parser.add_argument("--no-tls", action="store_true", help="disable encryption")
    parser.add_argument("--tls", action="store_true", help="(default) encrypt with TLS")
    parser.add_argument("--cert", help="TLS certificate file (default: auto-generated)")
    parser.add_argument("--key", help="TLS private key file (default: auto-generated)")
    parser.add_argument("--accounts", help="accounts database (default: accounts.db next to server.py; a .json path means the .db file beside it, and an old .json is imported once)")
    parser.add_argument("--name", help="name shown to people looking for a chat")
    args = parser.parse_args(argv)
    try:
        tls_context, fingerprint = _tls_context_from_args(args)
        accounts = AccountStore(args.accounts) if args.accounts else None
        server = ChatServer(
            args.host,
            args.port,
            accounts=accounts,
            tls_context=tls_context,
            display_name=args.name,
            discovery=True,
        )
        if fingerprint:
            print(_style(DIM, f"Certificate fingerprint (clients confirm this once): {fingerprint}"))
        server.serve_forever()
    except KeyboardInterrupt:
        print(_style(YELLOW, "\nStopping server..."))
    except OSError as error:
        raise SystemExit(_style(RED, f"Could not start server: {error}"))


if __name__ == "__main__":
    main()
