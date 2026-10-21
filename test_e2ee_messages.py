"""Encrypted private messages through a real server: relay, storage, policy, edits, and what the server can never see."""

import json
import sqlite3
import time
import unittest
from pathlib import Path

import e2ee
from e2ee import Identity
from events import legacy_text
from test_v2 import V2TestCase

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")
MARKER = "SECRET-MARKER-7731"


class Person:
    """A test double for the window: keys, and the encrypt/decrypt steps the real client performs."""

    def __init__(self, case, name):
        self.name = name
        self.identity = Identity.generate()
        self.peer = case.v2(name)
        self.peer.send(t="keys_publish", req=1, **self.identity.public().to_dict())
        self.peer.until(lambda e: e["t"] == "keys_result", limit=400)

    def bundle(self):
        return self.identity.public()

    def envelope(self, text, others, kind="text"):
        return e2ee.encrypt_message(e2ee.encode_payload(text), self.identity, self.name,
                                    {o.name: o.bundle() for o in others}, kind)

    def send(self, text, to, extra=None):
        self.peer.send(t="send", to=to.name, enc=self.envelope(text, [to]), **(extra or {}))

    def read(self, event, sender):
        data = e2ee.decrypt_message(event["enc"], self.identity, self.name, sender.name, sender.bundle())
        return e2ee.decode_payload(data)["b"]


@needs_crypto
class EncryptedFlowTest(V2TestCase):
    def setUp(self):
        super().setUp()
        self.alice, self.bob, self.carol = (Person(self, n) for n in ("Alice", "Bob", "Carol"))

    def next_message(self, person, limit=400):
        return person.peer.until(lambda e: e["t"] == "message", limit=limit)

    def test_round_trip_and_the_third_person_sees_nothing(self):
        self.alice.send(MARKER, self.bob)
        event = self.next_message(self.bob)
        self.assertEqual((event["body"], event["to"], event["sender"]), ("", "Bob", "Alice"))
        self.assertEqual(self.bob.read(event, self.alice), MARKER)
        mine = self.next_message(self.alice)
        self.assertEqual(self.alice.read(mine, self.alice), MARKER)  # the sender can read their own copy
        self.assertEqual([e for e in self.carol.peer.drain(0.6) if e["t"] == "message"], [])

    def test_the_server_never_holds_the_words(self):
        self.alice.send(MARKER, self.bob)
        self.next_message(self.bob)
        self.alice.peer.send(t="search", q=MARKER, req=3)
        results = self.alice.peer.until(lambda e: e["t"] == "search_results", limit=400)
        self.assertEqual(results["results"], [])
        time.sleep(0.3)
        raw = Path(self.server.store.path).read_bytes()
        self.assertNotIn(MARKER.encode(), raw)
        for table in ("messages", "audit", "key_backups", "user_keys"):
            for row in self.server.store._db.execute(f"SELECT * FROM {table}"):
                self.assertNotIn(MARKER, repr(tuple(row)))
        stored = self.server.store.history_for(1, 10)[-1]
        self.assertEqual(stored.body, "")
        self.assertIsNotNone(stored.enc)

    def test_history_keeps_it_readable_for_its_two_people_after_a_reconnect(self):
        self.alice.send("first secret", self.bob)
        self.next_message(self.bob)
        self.bob.peer.close()
        time.sleep(0.3)
        again = self.v2("Bob")
        encrypted = [m for m in again.history if m.get("enc")]
        self.assertEqual(len(encrypted), 1)
        self.assertEqual(self.bob.read(encrypted[0], self.alice), "first secret")
        carol_late = self.v2("Dave")
        self.assertEqual([m for m in carol_late.history if m.get("enc")], [])

    def test_a_terminal_client_is_told_without_the_text(self):
        legacy = self.connect("Old")
        old = Person.__new__(Person)
        old.name, old.bundle = "Old", lambda: Identity.generate().public()
        self.alice.send("hello terminal", old)
        line = legacy.recv_until(lambda m: "encrypted message" in m)
        self.assertIsNotNone(line)
        self.assertNotIn("hello terminal", line)
        self.assertIn("Alice (private)", line)

    def test_legacy_rendering_never_shows_ciphertext(self):
        event = {"t": "message", "id": 1, "sender": "Alice", "to": "Bob", "body": "", "ts": 0, "enc": {"v": 2}}
        self.assertIn("[encrypted message", legacy_text(event, "Bob"))

    def test_a_reply_to_an_encrypted_message_is_flagged_for_the_window(self):
        self.alice.send("question", self.bob)
        first = self.next_message(self.bob)
        self.bob.send("answer", self.alice, {"reply_to": first["id"]})
        event = self.next_message(self.alice, limit=600)
        reply = self.alice.peer.until(lambda e: e["t"] == "message" and e.get("reply"), limit=600) or event
        self.assertTrue(reply["reply"]["encrypted"])
        self.assertEqual(reply["reply"]["snippet"], "")


@needs_crypto
class ValidationTest(V2TestCase):
    def setUp(self):
        super().setUp()
        self.alice, self.bob, self.carol = (Person(self, n) for n in ("Alice", "Bob", "Carol"))

    def refused(self, **fields):
        self.alice.peer.send(t="send", **fields)
        notice = self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=400)
        self.assertIsNotNone(notice, fields)
        self.assertEqual(self.server.store.history_for(1, 10)[-1:], [])
        return notice["text"]

    def test_only_private_messages_can_be_encrypted_for_now(self):
        self.assertIn("only private", self.refused(enc=self.alice.envelope("x", [self.bob])))

    def test_no_readable_text_alongside(self):
        self.assertIn("must not also", self.refused(to="Bob", body="plain too", enc=self.alice.envelope("x", [self.bob])))

    def test_the_envelope_must_be_for_exactly_the_two_people(self):
        self.assertIn("malformed", self.refused(to="Bob", enc=self.alice.envelope("x", [self.carol])))
        self.assertIn("malformed", self.refused(to="Bob", enc=self.alice.envelope("x", [self.bob, self.carol])))
        self.assertIn("malformed", self.refused(to="Nobody", enc=self.alice.envelope("x", [self.bob])))

    def test_junk_and_oversize_envelopes(self):
        for junk in ({}, {"v": 2}, "text", 5, {"v": 2, "k": {}, "n": "", "ct": "", "sig": ""}):
            self.refused(to="Bob", enc=junk)

    def test_the_server_enforces_the_size_cap(self):
        big = self.alice.envelope("x", [self.bob])
        big["pad"] = "A" * 3200  # still under one frame, over what the server accepts
        self.assertIn("too long", self.refused(to="Bob", enc=big))

    def test_policy_off_refuses_encrypted_messages(self):
        self.server.store.set_setting("e2ee_policy", "off")
        self.assertIn("switched off", self.refused(to="Bob", enc=self.alice.envelope("x", [self.bob])))
        self.alice.peer.send(t="send", to="Bob", body="plain is fine when off")
        self.assertIsNotNone(self.bob.peer.until(lambda e: e["t"] == "message" and e["body"], limit=400))

    def test_policy_required_refuses_plain_private_messages_from_everyone(self):
        self.server.store.set_setting("e2ee_policy", "required")
        self.alice.peer.send(t="send", to="Bob", body="plain")
        self.assertIn("requires end-to-end", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=400)["text"])
        old = self.connect("Old")
        old.send("/msg Bob hello")
        self.assertIsNotNone(old.recv_until(lambda m: "requires end-to-end" in m))
        self.alice.peer.send(t="send", body="the room is still open")  # public chat is not private
        self.assertIsNotNone(self.bob.peer.until(lambda e: e["t"] == "message" and e["body"] == "the room is still open", limit=400))
        self.alice.send("encrypted passes", self.bob)
        self.assertIsNotNone(self.bob.peer.until(lambda e: e["t"] == "message" and e.get("enc"), limit=400))


@needs_crypto
class EditDeleteTest(V2TestCase):
    def setUp(self):
        super().setUp()
        self.alice, self.bob = Person(self, "Alice"), Person(self, "Bob")
        self.alice.send("original", self.bob)
        self.first = self.bob.peer.until(lambda e: e["t"] == "message", limit=400)

    def edit(self, who, **fields):
        who.peer.send(t="edit", id=self.first["id"], **fields)

    def test_the_sender_can_replace_the_ciphertext(self):
        self.edit(self.alice, enc=self.alice.envelope("edited", [self.bob]))
        event = self.bob.peer.until(lambda e: e["t"] == "edited", limit=400)
        self.assertEqual(self.bob.read(event, self.alice), "edited")
        self.assertEqual(event["body"], "")
        stored = self.server.store.get_message(self.first["id"])
        self.assertEqual((stored.body, stored.edited_at is not None), ("", True))

    def test_plain_text_cannot_replace_an_encrypted_message_or_the_other_way_round(self):
        self.edit(self.alice, body="now readable")
        self.assertIn("new encrypted version", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=400)["text"])
        self.alice.peer.send(t="send", to="Bob", body="plain message")
        plain = self.bob.peer.until(lambda e: e["t"] == "message" and e["body"] == "plain message", limit=400)
        self.alice.peer.send(t="edit", id=plain["id"], enc=self.alice.envelope("x", [self.bob]))
        self.assertIsNotNone(self.alice.peer.until(lambda e: e["t"] == "notice" and "new encrypted version" in e["text"], limit=400))

    def test_the_recipient_cannot_edit_it(self):
        self.edit(self.bob, enc=self.bob.envelope("forged", [self.alice]))
        self.assertIn("only edit your own", self.bob.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=400)["text"])

    def test_a_wrong_envelope_in_an_edit_is_refused(self):
        carol = Person(self, "Carol")
        self.edit(self.alice, enc=self.alice.envelope("x", [carol]))
        self.assertIsNotNone(self.alice.peer.until(lambda e: e["t"] == "notice" and "malformed" in e["text"], limit=400))

    def test_delete_wipes_the_ciphertext(self):
        self.alice.peer.send(t="delete", id=self.first["id"])
        self.assertIsNotNone(self.bob.peer.until(lambda e: e["t"] == "deleted", limit=400))
        stored = self.server.store.get_message(self.first["id"])
        self.assertEqual((stored.body, stored.enc), ("", None))

    def test_the_export_holds_ciphertext_for_the_window_to_decrypt_and_never_text(self):
        self.alice.peer.send(t="export", req=5)
        ready = self.alice.peer.until(lambda e: e["t"] == "download_ready", limit=400)
        import os
        import transfer
        path = os.path.join(self.tmp, "export.json")
        transfer.download("127.0.0.1", self.port, None, ready["ticket"], ready["size"], ready["sha256"], path)
        document = json.loads(Path(path).read_text())
        entry = next(m for m in document["messages"] if m["encrypted"])
        self.assertEqual(entry["text"], "")
        self.assertNotIn("original", json.dumps(document))
        data = e2ee.decrypt_message(entry["ciphertext"], self.alice.identity, "Alice", "Alice", self.alice.bundle())
        self.assertEqual(e2ee.decode_payload(data)["b"], "original")


class MigrationColumnTest(unittest.TestCase):
    def test_message_rows_have_the_enc_column(self):
        import tempfile
        from store import Store
        store = Store(Path(tempfile.mkdtemp()) / "s.db")
        user = store.create_user("Alice", "00", "00")
        message_id = store.add_message(user.id, "", enc='{"v":2}')
        self.assertEqual(store.get_message(message_id).enc, '{"v":2}')
        plain = store.add_message(user.id, "hello")
        self.assertIsNone(store.get_message(plain).enc)
        store.close()
        self.assertTrue(sqlite3.connect(store.path).execute("SELECT enc FROM messages").fetchall())


if __name__ == "__main__":
    unittest.main()
