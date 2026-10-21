"""Lockout, rate limits, password rules, session tokens, password change, data export."""

import hashlib
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

import transfer
from accounts import AccountStore
from chat_core import LoginError, connect_and_login
from protocol import receive_message, send_message
from security import LoginGuard, RateLimiter, SlidingWindow, check_password
from server import ChatServer
from test_v2 import V2Peer, V2TestCase


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class PasswordRulesTest(unittest.TestCase):
    def test_rules(self):
        self.assertIn("at least 6", check_password("abc", "bob"))
        self.assertIn("username", check_password("Bobbie", "bobbie"))
        self.assertIn("easy to guess", check_password("password", "x"))
        self.assertIn("easy to guess", check_password("zzzzzzzz", "x"))
        self.assertIsNone(check_password("river-stone-42", "bob"))
        self.assertIn("at most", check_password("x" * 200 + "y", "bob"))
        self.assertIn("at least 10", check_password("abcdef1", "bob", min_length=10))


class LoginGuardTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.guard = LoginGuard(self.clock)

    def fail(self, times, user="alice", ip="1.1.1.1"):
        return [self.guard.failed(ip, user) for _ in range(times)]

    def test_locks_after_five_failures_then_backs_off(self):
        self.assertEqual(self.fail(4), [0, 0, 0, 0])
        self.assertEqual(self.guard.failed("1.1.1.1", "alice"), 30)
        self.assertGreater(self.guard.retry_after("1.1.1.1", "alice"), 25)
        self.clock.now += 31
        self.assertEqual(self.guard.retry_after("1.1.1.1", "alice"), 0)
        self.assertEqual(self.fail(5)[-1], 60)  # the second lock is twice as long
        self.clock.now += 61
        self.assertEqual(self.fail(5)[-1], 120)

    def test_lock_is_capped(self):
        for _ in range(12):
            self.fail(5)
            self.clock.now += 1000
        self.assertLessEqual(self.guard.retry_after("1.1.1.1", "alice"), LoginGuard.MAX_LOCK)
        self.clock.now += 1000
        self.assertEqual(self.fail(5)[-1], LoginGuard.MAX_LOCK)

    def test_other_users_and_addresses_are_unaffected(self):
        self.fail(5)
        self.assertGreater(self.guard.retry_after("1.1.1.1", "ALICE"), 0)  # names are case-insensitive
        self.assertEqual(self.guard.retry_after("1.1.1.1", "bob"), 0)
        self.assertEqual(self.guard.retry_after("2.2.2.2", "alice"), 0)

    def test_success_clears_the_count(self):
        self.fail(4)
        self.guard.succeeded("1.1.1.1", "alice")
        self.assertEqual(self.fail(4), [0, 0, 0, 0])

    def test_old_failures_expire(self):
        self.fail(4)
        self.clock.now += LoginGuard.WINDOW + 1
        self.assertEqual(self.fail(4), [0, 0, 0, 0])

    def test_one_address_trying_many_names_is_locked(self):
        for number in range(LoginGuard.ADDRESS_MAX_FAILS):
            self.guard.failed("9.9.9.9", f"user{number}")
        self.assertGreater(self.guard.retry_after("9.9.9.9", "someone-new"), 0)


class RateLimiterTest(unittest.TestCase):
    def test_burst_then_refill(self):
        clock = FakeClock()
        limiter = RateLimiter(3, 1.0, clock)
        self.assertEqual([limiter.allow() for _ in range(4)], [True, True, True, False])
        clock.now += 2
        self.assertEqual([limiter.allow() for _ in range(3)], [True, True, False])

    def test_costs_and_cap(self):
        clock = FakeClock()
        limiter = RateLimiter(5, 1.0, clock)
        self.assertTrue(limiter.allow(5))
        self.assertFalse(limiter.allow(1))
        clock.now += 1000
        self.assertTrue(limiter.allow(5))  # never more than the capacity

    def test_sliding_window(self):
        clock = FakeClock()
        window = SlidingWindow(2, 10, clock)
        self.assertEqual([window.allow("a") for _ in range(3)], [True, True, False])
        self.assertTrue(window.allow("b"))
        clock.now += 11
        self.assertTrue(window.allow("a"))


class StrictServerCase(V2TestCase):
    """The real defaults: lockout, password policy, rate limits."""

    server_options = {"rate_limit": (40.0, 20.0), "enforce_password_policy": True}

    def login_error(self, name, password):
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, name, password, None, protocol=2)
        return str(raised.exception)


class LoginProtectionTest(StrictServerCase):
    def test_weak_new_passwords_are_refused_but_strong_ones_work(self):
        self.assertIn("stronger password", self.login_error("Alice", "abc"))
        self.assertIn("stronger password", self.login_error("Alice", "password"))
        self.assertIsNone(self.server.store.get_user("Alice"))
        self.v2("Alice", "river-stone-42")
        self.assertIsNotNone(self.server.store.get_user("Alice"))

    def test_existing_accounts_with_old_weak_passwords_still_sign_in(self):
        self.server.accounts.create_account("Legacy", "pw")
        self.v2("Legacy", "pw")

    def test_repeated_wrong_passwords_lock_the_account(self):
        self.v2("Alice", "river-stone-42").close()
        time.sleep(0.2)
        for _ in range(4):
            self.assertEqual(self.login_error("Alice", "wrong-guess"), "wrong password")
        self.assertIn("locked for 30 seconds", self.login_error("Alice", "wrong-guess"))
        message = self.login_error("Alice", "river-stone-42")  # even the right password waits
        self.assertIn("try again in", message)
        actions = [row["action"] for row in self.server.store.audit_rows(limit=50)]
        self.assertIn("lockout", actions)
        self.assertEqual(actions.count("login_failed"), 5)

    def test_legacy_clients_get_the_same_protection(self):
        self.server.accounts.create_account("Old", "oldpassword")
        for _ in range(5):
            with self.assertRaises(LoginError):
                connect_and_login("127.0.0.1", self.port, "Old", "nope")
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, "Old", "oldpassword")
        self.assertIn("try again", str(raised.exception))

    def test_closed_registration(self):
        self.server.store.set_setting("open_registration", "0")
        self.assertIn("closed", self.login_error("Newbie", "river-stone-42"))
        self.server.accounts.create_account("Member1", "river-stone-42")
        self.v2("Member1", "river-stone-42")

    def test_new_accounts_per_address_are_limited(self):
        for number in range(10):
            connect_and_login("127.0.0.1", self.port, f"User{number}", "river-stone-42", None, protocol=2).close()
        self.assertIn("too many new accounts", self.login_error("OneTooMany", "river-stone-42"))


class RateLimitTest(StrictServerCase):
    server_options = {"rate_limit": (6.0, 0.5), "enforce_password_policy": True}

    def test_flooding_is_throttled_and_warned_once(self):
        alice = self.v2("Alice", "river-stone-42")
        for index in range(40):
            alice.send(t="send", body=f"spam {index}")
        events = alice.drain(1.5)
        delivered = [e for e in events if e["t"] == "message"]
        warnings = [e for e in events if e["t"] == "notice" and "too fast" in e["text"]]
        self.assertLess(len(delivered), 15)
        self.assertEqual(len(warnings), 1)
        self.assertIn("rate_limited", [r["action"] for r in self.server.store.audit_rows(limit=20)])

    def test_normal_use_is_not_throttled(self):
        alice = self.v2("Alice", "river-stone-42")
        for index in range(5):
            self.assertIsNotNone(alice.say(f"hello {index}"))
            time.sleep(0.25)

    def test_typing_and_pings_are_not_limited(self):
        alice = self.v2("Alice", "river-stone-42")
        for _ in range(30):
            alice.send(t="ping")
            alice.send(t="typing", on=True)
        self.assertIsNotNone(alice.say("still here"))


class ConnectionLimitTest(unittest.TestCase):
    def test_too_many_connections_from_one_address_are_dropped(self):
        tmp = tempfile.mkdtemp()
        server = ChatServer("127.0.0.1", 0, accounts=AccountStore(Path(tmp) / "a.json"), quiet=True,
                            connection_limit=(5, 60.0), rate_limit=None)
        server.start()
        try:
            results = []
            for _ in range(8):
                raw = socket.create_connection(("127.0.0.1", server.bound_port), 3)
                raw.settimeout(1)
                try:
                    results.append(receive_message(raw))
                except (OSError, ConnectionError):
                    results.append(None)
                raw.close()
            self.assertEqual(results[:5], ["USERNAME"] * 5)
            self.assertEqual(results[5:], [None] * 3)
        finally:
            server.stop()


class SessionTokenTest(StrictServerCase):
    def test_welcome_carries_a_token_and_only_its_hash_is_stored(self):
        alice = self.v2("Alice", "river-stone-42")
        token = alice.welcome["token"]
        self.assertGreater(len(token), 30)
        rows = self.server.store._db.execute("SELECT token_hash FROM sessions").fetchall()
        self.assertEqual([r["token_hash"] for r in rows], [hashlib.sha256(token.encode()).hexdigest()])
        self.assertNotIn(token, json.dumps([dict(r) for r in rows]))

    def test_reconnect_with_the_token_needs_no_password_and_replaces_a_stale_connection(self):
        alice = self.v2("Alice", "river-stone-42")
        token = alice.welcome["token"]
        second = self.resume("Alice", token)
        self.assertIsNone(second.welcome.get("token"))  # nothing new is issued on a resume
        self.assertEqual(second.welcome["you"]["name"], "Alice")
        self.assertIsNone(alice.until(lambda e: e["t"] == "message", limit=3))  # the old connection was closed

    def resume(self, name, token):
        sock = socket.create_connection(("127.0.0.1", self.port), 3)
        self.assertEqual(receive_message(sock), "USERNAME")
        send_message(sock, json.dumps({"v": 2, "username": name, "token": token}))
        reply = receive_message(sock)
        self.assertEqual(reply, "OK", reply)
        peer = V2Peer.__new__(V2Peer)
        peer.sock, peer.name = sock, name
        sock.settimeout(3)
        peer.welcome = peer.until(lambda e: e["t"] == "welcome")
        self.peers.append(peer)
        return peer

    def test_bad_expired_and_foreign_tokens_are_refused(self):
        alice = self.v2("Alice", "river-stone-42")
        token = alice.welcome["token"]
        for name, tok in (("Alice", "nonsense"), ("Bob", token)):
            sock = socket.create_connection(("127.0.0.1", self.port), 3)
            receive_message(sock)
            send_message(sock, json.dumps({"v": 2, "username": name, "token": tok}))
            self.assertIn("session has expired", receive_message(sock))
            sock.close()
        self.server.store._db.execute("UPDATE sessions SET expires_at = 1")
        self.server.store._db.commit()
        sock = socket.create_connection(("127.0.0.1", self.port), 3)
        receive_message(sock)
        send_message(sock, json.dumps({"v": 2, "username": "Alice", "token": token}))
        self.assertIn("session has expired", receive_message(sock))
        sock.close()

    def test_logout_revokes_the_token(self):
        alice = self.v2("Alice", "river-stone-42")
        token = alice.welcome["token"]
        alice.send(t="logout")
        time.sleep(0.3)
        alice.close()
        time.sleep(0.2)
        sock = socket.create_connection(("127.0.0.1", self.port), 3)
        receive_message(sock)
        send_message(sock, json.dumps({"v": 2, "username": "Alice", "token": token}))
        self.assertIn("expired", receive_message(sock))
        sock.close()

    def test_a_disabled_account_cannot_resume(self):
        self.v2("Alice", "river-stone-42")
        bob = self.v2("Bob", "river-stone-42")
        token = bob.welcome["token"]
        bob.close()
        time.sleep(0.2)
        self.server.store.set_disabled("Bob", True)
        sock = socket.create_connection(("127.0.0.1", self.port), 3)
        receive_message(sock)
        send_message(sock, json.dumps({"v": 2, "username": "Bob", "token": token}))
        self.assertIn("disabled", receive_message(sock))
        sock.close()


class PasswordChangeTest(StrictServerCase):
    def change(self, peer, old, new):
        peer.send(t="passwd", old=old, new=new)
        return peer.until(lambda e: e["t"] == "passwd_result")

    def test_change_password_end_to_end(self):
        alice = self.v2("Alice", "river-stone-42")
        old_token = alice.welcome["token"]
        result = self.change(alice, "river-stone-42", "mountain-lake-77")
        self.assertTrue(result["ok"], result)
        self.assertNotEqual(result["token"], old_token)
        self.assertEqual(self.server.store.session_count(), 1)  # old sign-ins were revoked, a new one issued
        alice.close()
        time.sleep(0.2)
        self.assertIn("wrong password", self.login_error("Alice", "river-stone-42"))
        self.v2("Alice", "mountain-lake-77")
        self.assertIn("password_changed", [r["action"] for r in self.server.store.audit_rows(limit=30)])

    def test_wrong_old_password_and_weak_new_one(self):
        alice = self.v2("Alice", "river-stone-42")
        self.assertIn("wrong", self.change(alice, "guess", "mountain-lake-77")["reason"])
        time.sleep(1.0)
        self.assertIn("stronger", self.change(alice, "river-stone-42", "abc")["reason"])
        time.sleep(1.0)
        self.assertTrue(self.server.accounts.change_password("Alice", "river-stone-42", "river-stone-42"))

    def test_wrong_old_password_counts_toward_lockout(self):
        alice = self.v2("Alice", "river-stone-42")
        for _ in range(5):
            alice.send(t="passwd", old="guess", new="mountain-lake-77")
            time.sleep(0.6)
        result = self.change(alice, "river-stone-42", "mountain-lake-77")
        self.assertFalse(result["ok"])

    def test_terminal_clients_can_change_it_too(self):
        self.server.accounts.create_account("Old", "oldpassword")
        peer = self.connect("Old", "oldpassword")
        peer.send("/passwd oldpassword brand-new-pass-9")
        self.assertIsNotNone(peer.recv_until(lambda m: "Password changed" in m))
        self.assertEqual(self.server.accounts.authenticate("Old", "brand-new-pass-9")[0], "ok")


class ExportTest(StrictServerCase):
    def test_export_contains_only_my_own_conversations(self):
        alice, bob, carol = (self.v2(n, "river-stone-42") for n in ("Alice", "Bob", "Carol"))
        alice.say("public from alice")
        bob.say("public from bob")
        alice.send(t="send", body="secret to bob", to="Bob")
        carol.send(t="send", body="private carol to bob", to="Bob")
        time.sleep(0.5)
        alice.drain(0.3)
        alice.send(t="export", req=5)
        ready = alice.until(lambda e: e["t"] == "download_ready")
        self.assertTrue(ready["export"])
        path = os.path.join(self.tmp, "export.json")
        transfer.download("127.0.0.1", self.port, None, ready["ticket"], ready["size"], ready["sha256"], path)
        document = json.loads(Path(path).read_text())
        texts = [m["text"] for m in document["messages"]]
        self.assertEqual(document["account"]["username"], "Alice")
        self.assertIn("public from alice", texts)
        self.assertIn("secret to bob", texts)
        self.assertNotIn("public from bob", texts)
        self.assertNotIn("private carol to bob", texts)
        self.assertIn("data_exported", [r["action"] for r in self.server.store.audit_rows(limit=30)])


if __name__ == "__main__":
    unittest.main()
