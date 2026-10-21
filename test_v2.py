"""Protocol v2: JSON events, replies, edits, deletes, reactions, typing, presence, read receipts."""

import socket
import time
import unittest

from chat_core import LoginError, connect_and_login, parse_message
from events import decode, encode
from protocol import receive_message, send_message
from test_server import ServerTestCase


class V2Peer:
    """A bare-socket v2 client: sends/receives JSON events."""

    def __init__(self, port, username, password="secret"):
        self.sock = connect_and_login("127.0.0.1", port, username, password, None, protocol=2)
        self.sock.settimeout(3)
        self.name = username
        self.welcome = self.until(lambda e: e["t"] == "welcome")
        self.history = []
        self.history_start = None
        self.pins = []
        self.members = []
        self._read_initial_block()

    def _read_initial_block(self):
        """Consume everything the server sends right after login: history, pins, then members."""
        while True:
            event = self.next()
            if event is None:
                return
            if event["t"] == "history_start":
                self.history_start = event
            elif event["t"] == "history_end":
                continue
            elif event["t"] == "message" and event.get("history"):
                self.history.append(event)
            elif event["t"] == "pins":
                self.pins = event["pins"]
            elif event["t"] == "members":
                self.members += event["members"]
                if event["page"] == event["pages"] - 1:
                    return

    def send(self, **event):
        send_message(self.sock, encode(event))

    def next(self):
        try:
            frame = receive_message(self.sock)
        except (socket.timeout, OSError):
            return None
        return None if frame is None else decode(frame)

    def until(self, predicate, limit=60):
        for _ in range(limit):
            event = self.next()
            if event is None:
                return None
            if predicate(event):
                return event
        return None

    def drain(self, seconds=0.5):
        self.sock.settimeout(0.15)
        events, end = [], time.time() + seconds
        while time.time() < end:
            event = self.next()
            if event is not None:
                events.append(event)
        self.sock.settimeout(3)
        return events

    def say(self, body, **extra):
        self.send(t="send", body=body, **extra)
        return self.until(lambda e: e["t"] == "message" and e["sender"] == self.name and e["body"] == body)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class V2TestCase(ServerTestCase):
    def v2(self, name, password="secret"):
        peer = V2Peer(self.port, name, password)
        self.peers.append(peer)
        return peer


class LoginAndWelcomeTest(V2TestCase):
    def test_welcome_describes_you_and_the_room(self):
        alice = self.v2("Alice")
        self.assertEqual(alice.welcome["protocol"], 2)
        self.assertEqual(alice.welcome["you"], {"name": "Alice", "role": "admin"})
        self.assertEqual(alice.welcome["last_read"], 0)
        self.assertEqual(alice.members, [["Alice", "admin", "online"]])
        self.assertEqual(alice.history, [])

    def test_unknown_protocol_version_is_refused(self):
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, "Alice", "secret", None, protocol=3)
        self.assertIn("unsupported protocol", str(raised.exception))

    def test_malformed_hello_is_refused(self):
        raw = socket.create_connection(("127.0.0.1", self.port), 3)
        self.assertEqual(receive_message(raw), "USERNAME")
        send_message(raw, "{not json")
        self.assertIn("malformed", receive_message(raw))
        raw.close()

    def test_history_arrives_as_flagged_events_in_order(self):
        alice = self.v2("Alice")
        alice.say("one")
        alice.say("two")
        bob = self.v2("Bob")
        self.assertEqual([e["body"] for e in bob.history], ["one", "two"])
        self.assertTrue(all(e["history"] for e in bob.history))
        self.assertLess(bob.history[0]["id"], bob.history[1]["id"])

    def test_many_members_are_sent_in_pages(self):
        for index in range(100):
            self.server.store.create_user(f"student{index:03d}", "aa", "bb")
        alice = self.v2("Alice")
        self.assertEqual(len(alice.members), 101)
        self.assertEqual(alice.members[0][0], "Alice")


class CoexistenceTest(V2TestCase):
    def test_v2_and_legacy_clients_chat_with_each_other(self):
        alice = self.v2("Alice")
        bob = self.connect("Bob")  # legacy text client
        alice.until(lambda e: e["t"] == "notice" and "Bob joined" in e["text"])

        bob.send("hello from legacy")
        seen = alice.until(lambda e: e["t"] == "message")
        self.assertEqual((seen["sender"], seen["body"], seen["to"]), ("Bob", "hello from legacy", None))
        self.assertIsInstance(seen["id"], int)

        sent = alice.say("hello from v2")
        self.assertEqual(sent["sender"], "Alice")  # v2 senders get their own message back, with its id
        line = bob.recv_until(lambda m: "hello from v2" in m)
        self.assertEqual((parse_message(line).name, parse_message(line).text), ("Alice", "hello from v2"))
        bob.send("/users")
        self.assertTrue(bob.recv_until(lambda m: m.startswith("Online")).startswith("Online (2)"))

    def test_legacy_clients_do_not_receive_v2_only_events(self):
        alice = self.v2("Alice")
        bob = self.connect("Bob")
        alice.until(lambda e: e["t"] == "notice" and "Bob joined" in e["text"])
        message = alice.say("react to me")
        alice.send(t="react", id=message["id"], emoji="\U0001F44D")
        alice.send(t="typing", on=True)
        alice.send(t="presence", status="away")
        alice.send(t="read", up_to=message["id"])
        alice.send(t="edit", id=message["id"], body="edited text")
        time.sleep(0.4)
        bob.send("/users")
        lines = []
        while True:
            line = bob.recv()
            if line is None or line.startswith("Online"):
                break
            lines.append(line)
        expected = ("react to me", "joined", "Connected to LAN Chat!")
        self.assertEqual([l for l in lines if not any(text in l for text in expected)], [])

    def test_messages_over_the_limit_are_rejected(self):
        alice = self.v2("Alice")
        alice.send(t="send", body="x" * 3500)
        error = alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")
        self.assertIn("too long", error["text"])


class RepliesTest(V2TestCase):
    def test_reply_carries_a_quoted_snippet_and_legacy_gets_a_label(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        carol = self.connect("Carol")
        original = alice.say("Shall we meet at noon? " + " ".join(["blah"] * 40))
        reply = bob.say("Yes, noon works", reply_to=original["id"])
        self.assertEqual(reply["reply_to"], original["id"])
        self.assertEqual(reply["reply"]["sender"], "Alice")
        self.assertTrue(reply["reply"]["snippet"].startswith("Shall we meet at noon?"))
        self.assertLessEqual(len(reply["reply"]["snippet"]), 80)
        line = carol.recv_until(lambda m: "noon works" in m)
        self.assertIn("Bob (replying to Alice):", line)

    def test_replies_are_validated(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")
        public = alice.say("public one")
        private = alice.say("secret", to="Bob")
        for bad in (99999, "x", None):
            if bad is None:
                continue
            bob.send(t="send", body="nope", reply_to=bad)
            self.assertIn("reply", bob.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        # a public message cannot quote a private one, and nobody else can quote it
        bob.send(t="send", body="leak?", reply_to=private["id"])
        self.assertIn("reply", bob.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        carol.send(t="send", body="peek", reply_to=private["id"], to="Alice")
        self.assertIn("reply", carol.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        ok = bob.say("this one is fine", reply_to=public["id"])
        self.assertEqual(ok["reply"]["id"], public["id"])


class EditAndDeleteTest(V2TestCase):
    def test_author_can_edit_and_everyone_sees_it(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message = alice.say("teh original")
        alice.send(t="edit", id=message["id"], body="the original")
        for peer in (alice, bob):
            edited = peer.until(lambda e: e["t"] == "edited")
            self.assertEqual((edited["id"], edited["body"]), (message["id"], "the original"))
            self.assertIsNotNone(edited["edited_at"])
        carol = self.v2("Carol")
        self.assertEqual([(e["body"], e["edited"]) for e in carol.history], [("the original", True)])

    def test_others_cannot_edit_and_bad_edits_are_refused(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message = alice.say("mine")
        bob.send(t="edit", id=message["id"], body="hijack")
        self.assertIn("your own", bob.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        alice.send(t="edit", id=message["id"], body="   ")
        self.assertIn("empty", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        alice.send(t="edit", id=message["id"], body="y" * 3500)
        self.assertIn("too long", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        alice.send(t="edit", id=424242, body="ghost")
        self.assertIn("does not exist", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        self.assertEqual(self.server.store.get_message(message["id"]).body, "mine")

    def test_delete_rules_and_tombstones(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")  # Alice is the admin
        bobs = bob.say("bob's message")
        alices = alice.say("alice's message")
        carol.send(t="delete", id=bobs["id"])
        self.assertIn("cannot delete", carol.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        bob.send(t="delete", id=alices["id"])
        self.assertIn("cannot delete", bob.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        bob.send(t="delete", id=bobs["id"])  # your own
        for peer in (alice, bob, carol):
            self.assertEqual(peer.until(lambda e: e["t"] == "deleted")["id"], bobs["id"])
        alice.send(t="delete", id=alices["id"])  # admins may delete anything
        self.assertEqual(carol.until(lambda e: e["t"] == "deleted")["id"], alices["id"])
        dave = self.v2("Dave")
        self.assertEqual([(e["body"], e["deleted"]) for e in dave.history], [("", True), ("", True)])


class ReactionsTest(V2TestCase):
    def test_reactions_toggle_and_everyone_sees_the_totals(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message = alice.say("react to this")
        bob.send(t="react", id=message["id"], emoji="\U0001F44D")
        event = alice.until(lambda e: e["t"] == "reactions")
        self.assertEqual(event["reactions"], [{"emoji": "\U0001F44D", "users": ["Bob"]}])
        alice.send(t="react", id=message["id"], emoji="\U0001F44D")
        alice.until(lambda e: e["t"] == "reactions")
        bob.send(t="react", id=message["id"], emoji="\U0001F44D")  # Bob toggles his off
        later = alice.until(lambda e: e["t"] == "reactions" and e["reactions"][0]["users"] == ["Alice"])
        self.assertIsNotNone(later)
        carol = self.v2("Carol")
        self.assertEqual(carol.history[0]["reactions"], [{"emoji": "\U0001F44D", "users": ["Alice"]}])

    def test_bad_reactions_are_refused(self):
        alice = self.v2("Alice")
        message = alice.say("hello")
        for emoji in ("", "two words", "x" * 40, 5, None):
            alice.send(t="react", id=message["id"], emoji=emoji)
            self.assertIn("valid", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        alice.send(t="delete", id=message["id"])
        alice.until(lambda e: e["t"] == "deleted")
        alice.send(t="react", id=message["id"], emoji="\U0001F44D")
        self.assertIn("deleted", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])

    def test_guests_may_react(self):
        alice = self.v2("Alice")
        gus = self.v2("Gus")
        self.server.set_role("Gus", "guest")
        gus.until(lambda e: e["t"] == "notice" and e["kind"] == "role" and "Your role" in e["text"])
        message = alice.say("hi guests")
        gus.send(t="react", id=message["id"], emoji="❤")
        self.assertEqual(alice.until(lambda e: e["t"] == "reactions")["reactions"][0]["users"], ["Gus"])


class PrivacyTest(V2TestCase):
    def test_private_messages_and_everything_about_them_stay_between_two_people(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")
        secret = alice.say("for bob only", to="Bob")
        self.assertEqual(secret["to"], "Bob")
        self.assertEqual(bob.until(lambda e: e["t"] == "message")["body"], "for bob only")
        alice.send(t="edit", id=secret["id"], body="for bob only, edited")
        bob.send(t="react", id=secret["id"], emoji="\U0001F44D")
        alice.until(lambda e: e["t"] == "reactions")
        alice.send(t="delete", id=secret["id"])
        alice.until(lambda e: e["t"] == "deleted")
        seen_by_carol = [e["t"] for e in carol.drain(0.8)]
        self.assertFalse({"message", "edited", "reactions", "deleted"} & set(seen_by_carol))
        carol.send(t="react", id=secret["id"], emoji="\U0001F440")
        self.assertIn("does not exist", carol.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])
        carol.send(t="delete", id=secret["id"])
        self.assertIn("does not exist", carol.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])


class PresenceTypingReadTest(V2TestCase):
    def test_typing_goes_to_other_v2_clients_only(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        legacy = self.connect("Carol")
        alice.until(lambda e: e["t"] == "notice" and "Carol joined" in e["text"])
        alice.send(t="typing", on=True)
        event = bob.until(lambda e: e["t"] == "typing")
        self.assertEqual((event["user"], event["on"]), ("Alice", True))
        self.assertEqual([e for e in alice.drain(0.5) if e["t"] == "typing"], [])  # not echoed
        alice.send(t="typing", on=False)
        self.assertFalse(bob.until(lambda e: e["t"] == "typing")["on"])
        legacy.send("/users")
        lines = []
        while True:
            line = legacy.recv()
            if line is None or line.startswith("Online"):
                break
            lines.append(line)
        self.assertEqual([l for l in lines if "typing" in l.lower()], [])

    def test_typing_events_are_throttled(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        for _ in range(10):
            alice.send(t="typing", on=True)
        typing = [e for e in bob.drain(0.6) if e["t"] == "typing"]
        self.assertEqual(len(typing), 1)

    def test_presence_changes_reach_everyone_and_members_reports_them(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        alice.send(t="presence", status="away")
        event = bob.until(lambda e: e["t"] == "presence")
        self.assertEqual((event["user"], event["status"]), ("Alice", "away"))
        bob.send(t="members")
        page = bob.until(lambda e: e["t"] == "members")
        self.assertIn(["Alice", "admin", "away"], page["members"])
        self.assertIn(["Bob", "member", "online"], page["members"])
        alice.send(t="presence", status="busy")  # ignored: not a known status
        self.assertEqual([e for e in bob.drain(0.4) if e["t"] == "presence"], [])
        alice.close()
        page = bob.until(lambda e: e["t"] == "members" and ["Alice", "admin", "offline"] in e["members"])
        self.assertIsNotNone(page)

    def test_read_receipts_move_forward_only(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message = alice.say("did you see this?")
        bob.send(t="read", up_to=message["id"])
        event = alice.until(lambda e: e["t"] == "read")
        self.assertEqual((event["user"], event["up_to"]), ("Bob", message["id"]))
        bob.send(t="read", up_to=message["id"])   # no change
        bob.send(t="read", up_to=1)               # backwards
        bob.send(t="read", up_to=10_000)          # clamped to the newest message, so no change
        bob.send(t="read", up_to="seven")         # nonsense
        self.assertEqual([e for e in alice.drain(0.5) if e["t"] == "read"], [])
        bob.close()
        again = self.v2("Bob")
        self.assertEqual(again.welcome["last_read"], message["id"])
        self.assertEqual(again.welcome["latest"], message["id"])


class RobustnessTest(V2TestCase):
    def test_garbage_frames_get_errors_but_do_not_drop_the_connection(self):
        alice = self.v2("Alice")
        send_message(alice.sock, "just text, not json")
        self.assertIn("unrecognised", alice.until(lambda e: e["t"] == "notice")["text"])
        alice.send(t="fly_to_the_moon")
        self.assertIn("unknown event", alice.until(lambda e: e["t"] == "notice")["text"])
        alice.send(t="send", body=12345)
        self.assertIn("malformed", alice.until(lambda e: e["t"] == "notice")["text"])
        alice.send(t="edit", id="one", body="x")
        self.assertIn("does not exist", alice.until(lambda e: e["t"] == "notice")["text"])
        self.assertEqual(alice.say("still alive")["body"], "still alive")

    def test_slash_commands_work_inside_v2_messages(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        alice.send(t="send", body="/users")
        self.assertTrue(alice.until(lambda e: e["t"] == "notice" and e["kind"] == "info")["text"].startswith("Online (2)"))
        alice.send(t="send", body="/help")
        self.assertIn("/msg", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "info")["text"])
        alice.send(t="send", body="/msg Bob via the command")
        self.assertEqual(bob.until(lambda e: e["t"] == "message")["body"], "via the command")
        alice.send(t="ping")  # accepted silently
        alice.send(t="send", body="/nonsense")
        self.assertIn("unknown command", alice.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"])

    def test_role_changes_update_everyones_member_list(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.server.set_role("Bob", "guest")
        page = alice.until(lambda e: e["t"] == "members" and ["Bob", "guest", "online"] in e["members"])
        self.assertIsNotNone(page)
        self.assertIn("role changed", bob.until(lambda e: e["t"] == "notice" and e["kind"] == "role" and "changed" in e["text"])["text"])


if __name__ == "__main__":
    unittest.main()
