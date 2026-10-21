import errno
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from accounts import AccountStore
from discovery import discover
from chat_core import (
    LoginError,
    connect_and_login,
    make_tls_context,
    parse_members,
    parse_message,
    parse_user_list,
)
from protocol import receive_message, send_message
from server import ChatServer, build_tls_context


class Peer:
    """A bare-socket test client that speaks the protocol directly."""

    def __init__(self, port, username, password="secret", tls_context=None):
        self.sock = connect_and_login("127.0.0.1", port, username, password, tls_context)
        self.sock.settimeout(3)
        self.name = username

    def send(self, text):
        send_message(self.sock, text)

    def recv(self):
        try:
            return receive_message(self.sock)
        except (socket.timeout, OSError):
            return None

    def recv_until(self, predicate, limit=20):
        for _ in range(limit):
            message = self.recv()
            if message is None:
                return None
            if predicate(message):
                return message
        return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# The security limits are on by default; the many tests that send bursts of messages or use short
# throwaway passwords switch them off here. test_security.py tests the real defaults.
RELAXED = dict(rate_limit=None, connection_limit=None, enforce_password_policy=False)


class ServerTestCase(unittest.TestCase):
    server_options = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.accounts_path = Path(self.tmp) / "accounts.json"
        self.server = ChatServer(
            "127.0.0.1",
            0,
            accounts=AccountStore(self.accounts_path),
            quiet=True,
            **{**RELAXED, **self.server_options},
        )
        self.server.start()
        self.port = self.server.bound_port
        self.peers = []

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        self.server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self, username, password="secret", **kwargs):
        peer = Peer(self.port, username, password, **kwargs)
        self.peers.append(peer)
        return peer


class ParseMessageTest(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(parse_message("Bob joined the chat.").kind, "join")
        self.assertEqual(parse_message("Bob left the chat.").kind, "leave")
        self.assertEqual(parse_message("Server is shutting down. Goodbye!").kind, "shutdown")
        self.assertEqual(parse_message("Connected to LAN Chat!").kind, "welcome")
        self.assertEqual(parse_message("Error: unknown command. Type /help.").kind, "error")
        self.assertEqual(parse_message("Commands:\n  /users").kind, "system")

    def test_chat_and_private(self):
        chat = parse_message("[14:32] Potti: hello: world")
        self.assertEqual((chat.kind, chat.timestamp, chat.name, chat.text),
                         ("chat", "14:32", "Potti", "hello: world"))
        private = parse_message("[14:32] Potti (private): psst")
        self.assertEqual((private.kind, private.name), ("private", "Potti (private)"))
        sent = parse_message("[14:32] You -> Potti (private): psst")
        self.assertEqual(sent.kind, "private")

    def test_user_list(self):
        self.assertEqual(parse_user_list("Online (2): Alice, Bob"), ["Alice", "Bob"])
        self.assertIsNone(parse_user_list("[14:32] A: Online (2): x"))


class ChatBehaviourTest(ServerTestCase):
    def test_broadcast_has_timestamp_and_skips_sender(self):
        alice = self.connect("Alice")
        bob = self.connect("Bob")
        self.assertEqual(alice.recv_until(lambda m: "Bob joined" in m), "Bob joined the chat.")
        alice.send("hello")
        message = bob.recv_until(lambda m: "Alice:" in m)
        parsed = parse_message(message)
        self.assertEqual((parsed.kind, parsed.name, parsed.text), ("chat", "Alice", "hello"))
        self.assertRegex(parsed.timestamp, r"^\d\d:\d\d$")

    def test_users_command(self):
        alice = self.connect("Alice")
        self.connect("bob")
        alice.send("/users")
        reply = alice.recv_until(lambda m: m.startswith("Online"))
        self.assertEqual(parse_user_list(reply), ["Alice", "bob"])

    def test_private_message_only_reaches_target(self):
        alice = self.connect("Alice")
        bob = self.connect("Bob")
        carol = self.connect("Carol")
        alice.send("/msg bob top secret")
        received = bob.recv_until(lambda m: "(private)" in m)
        self.assertEqual(parse_message(received).text, "top secret")
        echo = alice.recv_until(lambda m: "You -> Bob" in m)
        self.assertIsNotNone(echo)
        carol.send("/users")  # force a round trip so earlier traffic has arrived
        seen = []
        while True:
            message = carol.recv()
            if message is None or message.startswith("Online"):
                break
            seen.append(message)
        self.assertFalse(any("top secret" in m for m in seen))

    def test_private_message_errors(self):
        alice = self.connect("Alice")
        alice.send("/msg nobody hi")
        self.assertIn("no user named", alice.recv_until(lambda m: m.startswith("Error")))
        alice.send("/msg Alice hi")
        self.assertIn("yourself", alice.recv_until(lambda m: m.startswith("Error")))
        alice.send("/msg Alice")
        self.assertIn("usage", alice.recv_until(lambda m: m.startswith("Error")))

    def test_help_and_unknown_command(self):
        alice = self.connect("Alice")
        alice.send("/help")
        self.assertIn("/msg", alice.recv_until(lambda m: m.startswith("Commands")))
        alice.send("/nope")
        self.assertIn("unknown command", alice.recv_until(lambda m: m.startswith("Error")))

    def test_oversized_chat_line_is_rejected_not_fatal(self):
        alice = self.connect("Alice")
        alice.send("x" * 4000)
        self.assertIn("too long", alice.recv_until(lambda m: m.startswith("Error")))
        alice.send("/users")
        self.assertIsNotNone(alice.recv_until(lambda m: m.startswith("Online")))

    def test_leave_is_announced(self):
        alice = self.connect("Alice")
        bob = self.connect("Bob")
        bob.close()
        self.assertEqual(alice.recv_until(lambda m: "left" in m), "Bob left the chat.")


class LoginTest(ServerTestCase):
    def test_first_login_registers_and_second_checks_password(self):
        self.connect("Alice", "pw1").close()
        time.sleep(0.2)
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, "Alice", "wrong")
        self.assertIn("wrong password", str(raised.exception))
        self.connect("alice", "pw1")  # case-insensitive name, right password

    def test_duplicate_online_user_rejected(self):
        self.connect("Alice", "pw")
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, "ALICE", "pw")
        self.assertIn("already logged in", str(raised.exception))

    def test_invalid_username_rejected(self):
        with self.assertRaises(LoginError):
            connect_and_login("127.0.0.1", self.port, "bad name", "pw")

    def test_passwords_are_stored_hashed(self):
        self.connect("Alice", "correct horse battery staple")
        database = self.accounts_path.with_suffix(".db")
        self.assertNotIn(b"correct horse", database.read_bytes())
        row = sqlite3.connect(database).execute(
            "SELECT salt, hash FROM users WHERE username = 'Alice'"
        ).fetchone()
        self.assertEqual((len(row[0]), len(row[1])), (32, 64))  # hex salt and scrypt hash


class PersistenceTest(ServerTestCase):
    def history_of(self, peer):
        """Read the welcome + history block a freshly joined peer receives."""
        lines = []
        message = peer.recv_until(lambda m: m == "Connected to LAN Chat!")
        self.assertEqual(message, "Connected to LAN Chat!")
        first = peer.recv()
        if first != "--- Earlier messages ---":
            return None
        while True:
            line = peer.recv()
            if line is None or line == "--- End of earlier messages ---":
                return lines
            lines.append(line)

    def test_new_joiner_sees_recent_messages_in_order(self):
        alice = self.connect("Alice")
        alice.send("hello")
        alice.send("world")
        alice.send("/users")
        alice.recv_until(lambda m: m.startswith("Online"))
        bob = self.connect("Bob")
        history = self.history_of(bob)
        self.assertEqual([parse_message(line).text for line in history], ["hello", "world"])
        self.assertTrue(all(parse_message(line).name == "Alice" for line in history))

    def test_first_user_has_no_history_header(self):
        alice = self.connect("Alice")
        self.assertIsNone(self.history_of(alice))

    def test_history_survives_a_server_restart(self):
        alice = self.connect("Alice")
        alice.send("remember me")
        alice.send("/users")
        alice.recv_until(lambda m: m.startswith("Online"))
        alice.close()
        self.server.stop()
        restarted = ChatServer("127.0.0.1", 0, accounts=AccountStore(self.accounts_path), quiet=True, **RELAXED)
        restarted.start()
        self.server = restarted
        self.port = restarted.bound_port
        bob = self.connect("Bob")
        history = self.history_of(bob)
        self.assertEqual([parse_message(line).text for line in history], ["remember me"])

    def test_history_is_limited(self):
        self.connect("Alice")
        user = self.server.store.get_user("Alice")
        for index in range(70):
            self.server.store.add_message(user.id, f"old {index}")
        bob = self.connect("Bob")
        history = self.history_of(bob)
        self.assertEqual(len(history), 50)
        self.assertEqual(parse_message(history[-1]).text, "old 69")

    def test_private_messages_are_saved_for_offline_members_and_stay_private(self):
        alice = self.connect("Alice")
        self.connect("Bob").close()
        time.sleep(0.2)
        alice.send("/msg Bob see you tomorrow")
        self.assertIn("You -> Bob", alice.recv_until(lambda m: "You -> Bob" in m))
        self.assertIn("offline", alice.recv_until(lambda m: "offline" in m))
        bob = self.connect("Bob")
        history = self.history_of(bob)
        self.assertEqual(history[-1].split("] ", 1)[1], "Alice (private): see you tomorrow")
        carol = self.connect("Carol")
        self.assertIsNone(self.history_of(carol))  # nothing public, and the DM is not hers

    def test_own_private_history_uses_you_arrow(self):
        alice = self.connect("Alice")
        self.connect("Bob")
        alice.send("/msg Bob hi")
        alice.recv_until(lambda m: "You -> Bob" in m)
        alice.close()
        time.sleep(0.2)
        again = self.connect("Alice")
        history = self.history_of(again)
        self.assertEqual(history[-1].split("] ", 1)[1], "You -> Bob (private): hi")


class StalledHistoryTest(ServerTestCase):
    """A joiner who never reads must not hang the server or other clients."""

    def test_stalled_client_during_history_is_dropped_and_others_stay_responsive(self):
        import server as server_module

        user = self.connect("Alice")
        stored = self.server.store.get_user("Alice")
        for index in range(300):
            self.server.store.add_message(stored.id, "h" * 3900 + str(index))
        original = (server_module.HANDSHAKE_TIMEOUT, server_module.HISTORY_LIMIT)
        server_module.HANDSHAKE_TIMEOUT, server_module.HISTORY_LIMIT = 1.0, 300
        try:
            raw = socket.socket()
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            raw.connect(("127.0.0.1", self.port))
            raw.settimeout(5)
            self.assertEqual(receive_message(raw), "USERNAME")
            send_message(raw, "Stalled")
            self.assertEqual(receive_message(raw), "PASSWORD")
            send_message(raw, "secret")
            self.assertEqual(receive_message(raw), "OK")  # ...and now we stop reading

            started = time.time()
            user.send("/users")  # everyone else must keep working while the handshake is stuck
            self.assertIsNotNone(user.recv_until(lambda m: m.startswith("Online")))
            self.assertLess(time.time() - started, 2.0)

            left = user.recv_until(lambda m: m == "Stalled left the chat.")
            self.assertEqual(left, "Stalled left the chat.")  # timed out and was removed
            user.send("/users")
            reply = user.recv_until(lambda m: m.startswith("Online"))
            self.assertEqual(parse_user_list(reply), ["Alice"])
            raw.close()
        finally:
            server_module.HANDSHAKE_TIMEOUT, server_module.HISTORY_LIMIT = original


class MembersAndRolesTest(ServerTestCase):
    def test_a_huge_member_list_is_marked_not_silently_cut(self):
        for index in range(220):
            self.server.store.create_user(f"student{index:03d}", "aa", "bb")
        reply = self.server._members_reply()
        self.assertLessEqual(len(reply.encode()), 4096 - 128 + 40)  # fits one frame
        self.assertTrue(reply.startswith("Members (220):"))
        self.assertRegex(reply, r"\+\d+ more$")
        parsed = parse_members(reply)
        self.assertEqual(len(parsed) + int(reply.rsplit("+", 1)[1].split()[0]), 220)
        left, right = socket.socketpair()
        try:
            send_message(left, reply)  # must be sendable as a single frame
            self.assertEqual(receive_message(right), reply)
        finally:
            left.close()
            right.close()

    def test_members_reply_lists_everyone_with_roles_and_presence(self):
        alice = self.connect("Alice")
        self.connect("Bob").close()
        time.sleep(0.2)
        alice.send("/members")
        reply = alice.recv_until(lambda m: m.startswith("Members"))
        members = {m.name: (m.role, m.online) for m in parse_members(reply)}
        self.assertEqual(members, {"Alice": ("admin", True), "Bob": ("member", False)})

    def test_first_user_is_admin_and_later_ones_are_members(self):
        self.connect("Alice")
        self.connect("Bob")
        roles = {u.username: u.role for u in self.server.store.list_users()}
        self.assertEqual(roles, {"Alice": "admin", "Bob": "member"})

    def test_role_change_applies_immediately_to_an_online_user(self):
        self.connect("Alice")
        bob = self.connect("Bob")
        self.assertIsNone(self.server.set_role("Bob", "guest"))
        self.assertIn("guest", bob.recv_until(lambda m: m.startswith("Your role")))
        bob.send("/msg Alice psst")
        self.assertIn("role cannot send private", bob.recv_until(lambda m: m.startswith("Error")))
        bob.send("guests may still talk publicly")  # allowed
        bob.send("/users")
        self.assertIsNotNone(bob.recv_until(lambda m: m.startswith("Online")))

    def test_role_errors(self):
        self.connect("Alice")
        self.assertIn("last admin", self.server.set_role("Alice", "member"))
        self.assertIn("unknown role", self.server.set_role("Alice", "boss"))
        self.assertIn("no user named", self.server.set_role("Ghost", "guest"))

    def test_disabled_account_cannot_sign_in(self):
        self.connect("Alice")
        self.connect("Bob").close()
        time.sleep(0.2)
        self.server.store.set_disabled("Bob", True)
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, "Bob", "secret")
        self.assertIn("disabled", str(raised.exception))
        self.assertNotIn("Bob", [m.name for m in parse_members(self.members_reply())])

    def members_reply(self):
        return self.server._members_reply()

    def test_parse_members(self):
        parsed = parse_members("Members (3): Ann:admin:1, Bob:member:0, Gus:guest:1")
        self.assertEqual([(m.name, m.role, m.online) for m in parsed],
                         [("Ann", "admin", True), ("Bob", "member", False), ("Gus", "guest", True)])
        self.assertIsNone(parse_members("Online (2): Ann, Bob"))
        self.assertEqual(parse_members("Members (0): "), [])


class SlowClientTest(ServerTestCase):
    server_options = {"queue_size": 20}

    def test_slow_client_is_dropped_and_others_keep_working(self):
        sender = self.connect("Sender")
        reader = self.connect("Reader")
        slow = self.connect("Slow")
        slow.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)

        received = []
        stop = threading.Event()

        def drain():
            reader.sock.settimeout(0.5)
            while not stop.is_set():
                try:
                    message = receive_message(reader.sock)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if message is None:
                    return
                received.append(message)

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()

        payload = "y" * 3300
        for _ in range(400):
            sender.send(payload)
            time.sleep(0.002)

        deadline = time.time() + 10
        online = None
        while time.time() < deadline:
            sender.send("/users")
            reply = sender.recv_until(lambda m: m.startswith("Online"), limit=500)
            online = parse_user_list(reply or "")
            if online is not None and "Slow" not in online:
                break
            time.sleep(0.2)
        stop.set()
        thread.join(timeout=2)
        self.assertEqual(sorted(online), ["Reader", "Sender"])
        self.assertGreater(sum(1 for m in received if payload in m), 100)


class HeartbeatTest(ServerTestCase):
    server_options = {"idle_timeout": 0.6}

    def test_silent_client_is_dropped(self):
        silent = self.connect("Silent")
        time.sleep(1.5)  # well past the 0.6 s idle timeout
        checker = self.connect("Checker")
        checker.send("/users")
        reply = checker.recv_until(lambda m: m.startswith("Online"))
        self.assertEqual(parse_user_list(reply), ["Checker"])
        silent.close()

    def test_ping_keeps_client_alive(self):
        alive = self.connect("Alive")
        for _ in range(8):
            alive.send("/ping")
            time.sleep(0.2)
        alive.send("/users")
        reply = alive.recv_until(lambda m: m.startswith("Online"))
        self.assertEqual(parse_user_list(reply), ["Alive"])


class PortAndDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make(self, **kwargs):
        server = ChatServer(
            "127.0.0.1", accounts=AccountStore(Path(self.tmp) / "a.json"), quiet=True, **{**RELAXED, **kwargs}
        )
        self.servers.append(server)
        return server

    @staticmethod
    def free_port():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def test_auto_port_skips_a_busy_port(self):
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        try:
            taken = busy.getsockname()[1]
            free = self.free_port()
            server = self.make(port=None, port_range=[taken, free])
            server.start()
            self.assertEqual(server.bound_port, free)
        finally:
            busy.close()

    def test_explicit_busy_port_fails_instead_of_moving(self):
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        try:
            server = self.make(port=busy.getsockname()[1])
            with self.assertRaises(OSError) as raised:
                server.start()
            self.assertEqual(raised.exception.errno, errno.EADDRINUSE)
        finally:
            busy.close()

    def test_info_reports_name_port_mode_and_users(self):
        server = self.make(port=0, display_name="Demo Room")
        server.start()
        info = server.info()
        self.assertEqual((info["name"], info["tls"], info["users"]), ("Demo Room", False, 0))
        self.assertEqual(info["port"], server.bound_port)
        peer = Peer(server.bound_port, "Alice")
        try:
            self.assertEqual(server.info()["users"], 1)
        finally:
            peer.close()

    def test_server_is_discoverable_and_stops_answering_after_stop(self):
        server = self.make(port=0, display_name="Findable", discovery=True, discovery_port=0)
        server.start()
        target = [("127.0.0.1", server._responder.port)]
        found = discover(timeout=0.5, targets=target)
        self.assertEqual([(f.name, f.port, f.tls) for f in found],
                         [("Findable", server.bound_port, False)])
        server.stop()
        self.assertEqual(discover(timeout=0.3, targets=target), [])


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TlsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cert, key = Path(self.tmp) / "server.crt", Path(self.tmp) / "server.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=lanchat", "-keyout", str(key), "-out", str(cert)],
            check=True, capture_output=True,
        )
        self.cert = str(cert)
        self.server = ChatServer(
            "127.0.0.1", 0,
            accounts=AccountStore(Path(self.tmp) / "accounts.json"),
            tls_context=build_tls_context(str(cert), str(key)),
            quiet=True,
            **RELAXED,
        )
        self.server.start()
        self.port = self.server.bound_port

    def tearDown(self):
        self.server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tls_round_trip(self):
        context = make_tls_context(self.cert)
        alice = Peer(self.port, "Alice", tls_context=context)
        bob = Peer(self.port, "Bob", tls_context=context)
        self.assertIsInstance(alice.sock, ssl.SSLSocket)
        alice.send("encrypted hello")
        message = bob.recv_until(lambda m: "Alice:" in m)
        self.assertEqual(parse_message(message).text, "encrypted hello")
        alice.close()
        bob.close()

    def test_plain_client_cannot_use_tls_server(self):
        with self.assertRaises((LoginError, OSError)):
            connect_and_login("127.0.0.1", self.port, "Mallory", "pw")

    def test_untrusted_certificate_is_rejected(self):
        other = Path(self.tmp) / "other.crt"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=evil", "-keyout", str(Path(self.tmp) / "other.key"), "-out", str(other)],
            check=True, capture_output=True,
        )
        with self.assertRaises(ssl.SSLError):
            connect_and_login("127.0.0.1", self.port, "Alice", "pw", make_tls_context(str(other)))


if __name__ == "__main__":
    unittest.main()
