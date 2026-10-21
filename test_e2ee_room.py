"""The end-to-end encrypted group room through a real server."""

import os
import time
import unittest
from pathlib import Path

import e2ee
import transfer
from e2ee import Identity, NoKey
from e2ee_group import RoomKeys
from events import legacy_text
from test_v2 import V2TestCase

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")
MARKER = "ROOM-SECRET-MARKER-5512"


class Member:
    """What the window does for the room, without the window."""

    def __init__(self, case, name, keys=True):
        self.case, self.name = case, name
        self.peer = case.v2(name)
        self.identity = Identity.generate() if keys else None
        self.keys = RoomKeys(self.identity, name) if keys else None
        self.bundles = {}
        self.epoch, self.next = 1, 0
        if keys:
            self.peer.send(t="keys_publish", req=1, **self.identity.public().to_dict())
            self.peer.until(lambda e: e["t"] == "keys_result", limit=500)

    def bundle(self):
        return self.identity.public()

    def lookup(self, names):
        need = [n for n in names if n.lower() not in self.bundles and n.lower() != self.name.lower()]
        if need:
            self.peer.send(t="keys_get", req=2, names=need)
            for name, data in self.peer.until(lambda e: e["t"] == "keys" and e["req"] == 2, limit=500)["keys"].items():
                self.bundles[name.lower()] = e2ee.Bundle.from_dict(data)
        self.bundles[self.name.lower()] = self.bundle()

    def state(self):
        self.peer.send(t="group_state", req=3)
        reply = self.peer.until(lambda e: e["t"] == "room_state" and e.get("req") == 3, limit=800)
        self.epoch, self.next = reply["epoch"], reply["next"]
        return reply

    def distribute(self):
        """Give every member who is missing my chain (and myself a copy), as the window does."""
        for _ in range(5):
            state = self.state()
            if not state["missing"]:
                return state
            self.lookup(state["missing"])
            envelopes = {}
            for name in state["missing"]:
                if name.lower() == self.name.lower():
                    envelopes[name] = self.keys.own_envelope(self.epoch)
                elif name.lower() in self.bundles:
                    envelopes[name] = self.keys.key_envelope(name, self.bundles[name.lower()], self.epoch, self.next)
            self.peer.send(t="group_keys", req=4, epoch=self.epoch, envelopes=envelopes)
            self.peer.until(lambda e: e["t"] == "room_state" and e.get("req") == 4, limit=800)
        return state

    def fetch(self):
        after = 0
        while True:
            self.peer.send(t="group_keys_get", req=5, after=after)
            page = self.peer.until(lambda e: e["t"] == "group_keys_list" and e.get("req") == 5, limit=800)
            for item in page["items"]:
                self.lookup([item["sender"]])
                bundle = self.bundles[item["sender"].lower()]
                self.keys.accept_envelope(item["sender"], [bundle], item["blob"])
                after = item["id"]
            if not page["more"]:
                return

    def envelope(self, text, number=None, file=None):
        self.distribute()
        self.keys.ensure_own_chain(self.epoch)
        return self.keys.encrypt(e2ee.encode_payload(text, file), self.epoch, self.next if number is None else number)

    def say(self, text, **extra):
        env = self.envelope(text)
        self.peer.send(t="send", enc=env, **extra)
        return env

    def message(self, **match):
        return self.peer.until(lambda e: e["t"] == "message" and all(e.get(k) == v for k, v in match.items()), limit=800)

    def read(self, event):
        self.lookup([event["sender"]])
        return e2ee.decode_payload(self.keys.decrypt(event["enc"], event["sender"], [self.bundles[event["sender"].lower()]]))["b"]


@needs_crypto
class RoomCase(V2TestCase):
    def setUp(self):
        super().setUp()
        self.alice, self.bob, self.carol = Member(self, "Alice"), Member(self, "Bob"), Member(self, "Carol")

    def turn_on(self):
        self.server.set_e2ee_room("on")
        for member in (self.alice, self.bob, self.carol):
            member.peer.until(lambda e: e["t"] == "e2ee_room", limit=800)


class ModeTest(RoomCase):
    def test_off_by_default_and_plain_messages_work(self):
        self.assertEqual(self.alice.peer.welcome["e2ee"]["room"], "off")
        self.alice.peer.send(t="send", body="plain hello")
        self.assertIsNotNone(self.bob.message(body="plain hello"))
        self.alice.peer.send(t="send", enc={"v": 3, "e": 1, "n": 0, "nn": "", "ct": "", "sig": ""})
        self.assertIn("not end-to-end", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])

    def test_turning_it_on_is_announced_and_stops_plain_public_messages(self):
        self.turn_on()
        self.alice.peer.send(t="send", body="plain now")
        self.assertIn("end-to-end encrypted", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])
        self.assertEqual([e for e in self.bob.peer.drain(0.4) if e["t"] == "message"], [])
        self.alice.peer.send(t="send", to="Bob", body="private plain still allowed")  # the room is not private chat
        self.assertIsNotNone(self.bob.message(body="private plain still allowed"))

    def test_a_terminal_client_cannot_write_and_sees_placeholders(self):
        self.turn_on()
        old = self.connect("Old")
        old.send("can anyone hear me")
        self.assertIsNotNone(old.recv_until(lambda m: "end-to-end encrypted" in m))
        self.alice.say("hello room")
        line = old.recv_until(lambda m: "encrypted message" in m)
        self.assertIsNotNone(line)
        self.assertNotIn("hello room", line)

    def test_the_setting_is_validated_and_audited(self):
        with self.assertRaises(ValueError):
            self.server.set_e2ee_room("maybe")
        self.server.set_e2ee_room("on", "Alice")
        self.assertIn("room_encryption", [r["action"] for r in self.server.store.audit_rows(limit=20)])


class MessagesTest(RoomCase):
    def setUp(self):
        super().setUp()
        self.turn_on()

    def test_members_read_each_other_and_the_server_cannot(self):
        self.alice.say(f"hello everyone {MARKER}")
        event = self.bob.message(sender="Alice")
        theirs = self.carol.message(sender="Alice")
        mine = self.alice.message(sender="Alice")
        self.assertEqual((event["body"], event["to"]), ("", None))
        self.bob.fetch()
        self.carol.fetch()
        self.assertEqual(self.bob.read(event), f"hello everyone {MARKER}")
        self.assertEqual(self.carol.read(theirs), f"hello everyone {MARKER}")
        self.alice.fetch()
        self.assertEqual(self.alice.read(mine), f"hello everyone {MARKER}")
        time.sleep(0.3)
        raw = Path(self.server.store.path).read_bytes()
        self.assertNotIn(MARKER.encode(), raw)
        chain = self.alice.keys.chains[("alice", 1)][0]
        for needle in (chain, e2ee.b64(chain).encode(), e2ee.chain_message_key(chain)):
            self.assertNotIn(needle, raw)

    def test_numbers_must_increase(self):
        self.alice.distribute()
        first = self.alice.envelope("one", number=0)
        self.alice.peer.send(t="send", enc=first)
        self.bob.message(sender="Alice")
        self.alice.peer.send(t="send", enc=first)  # the same number again
        self.assertIn("already used", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])
        self.alice.peer.send(t="send", enc=self.alice.envelope("far", number=5000))
        self.assertIn("already used", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])
        self.alice.peer.send(t="send", enc=self.alice.envelope("skip ahead a little", number=40))
        self.assertIsNotNone(self.bob.message(sender="Alice"))

    def test_a_wrong_epoch_is_refused_with_the_current_state(self):
        self.alice.distribute()
        env = self.alice.envelope("old", number=0)
        env["e"] = 9
        self.alice.peer.send(t="send", enc=env)
        self.assertIn("new keys", self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])
        self.assertEqual(self.alice.peer.until(lambda e: e["t"] == "room_state", limit=800)["epoch"], 1)

    def test_junk_envelopes_and_text_alongside(self):
        for junk in ({}, {"v": 3}, "x", {"v": 3, "e": 1, "n": 0, "nn": "", "ct": "A" * 3200, "sig": ""}):
            self.alice.peer.send(t="send", enc=junk)
            self.assertIsNotNone(self.alice.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800))
        self.alice.peer.send(t="send", body="plain too", enc=self.alice.envelope("x"))
        self.assertIn("must not also", self.alice.peer.until(lambda e: e["t"] == "notice" and "must not" in e["text"], limit=800)["text"])

    def test_someone_without_keys_cannot_write(self):
        dave = Member(self, "Dave", keys=False)
        dave.peer.send(t="send", enc=self.alice.envelope("hi"))
        self.assertIn("set up your encryption keys", dave.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])

    def test_mentions_and_everyone(self):
        self.alice.say("hi bob", mentions=["Bob", "Nobody"])
        event = self.bob.message(sender="Alice")
        self.assertEqual(event["mentions"], ["Bob"])
        self.bob.say("everyone!", everyone=True)
        self.assertIn("only admins", self.bob.peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)["text"])
        self.alice.say("@everyone meeting", everyone=True)
        self.assertTrue(self.carol.message(sender="Alice", everyone=True))
        self.bob.peer.send(t="send", enc=self.bob.envelope("bad mentions"), mentions="Alice")
        self.assertIsNotNone(self.bob.peer.until(lambda e: e["t"] == "notice" and "mentions" in e["text"], limit=800))

    def test_reply_edit_and_delete(self):
        self.alice.say("question")
        first = self.bob.message(sender="Alice")
        self.bob.say("answer", reply_to=first["id"])
        reply = self.alice.message(sender="Bob")
        self.assertTrue(reply["reply"]["encrypted"])
        self.alice.peer.send(t="edit", id=first["id"], enc=self.alice.envelope("question, edited"))
        edited = self.bob.peer.until(lambda e: e["t"] == "edited", limit=800)
        self.bob.fetch()
        self.assertEqual(self.bob.read({**edited, "sender": "Alice"}), "question, edited")
        self.alice.peer.send(t="edit", id=first["id"], body="plain edit")
        self.assertIn("new encrypted version", self.alice.peer.until(lambda e: e["t"] == "notice" and "new encrypted" in e["text"], limit=800)["text"])
        self.alice.peer.send(t="delete", id=first["id"])
        self.bob.peer.until(lambda e: e["t"] == "deleted", limit=800)
        self.assertIsNone(self.server.store.get_message(first["id"]).enc)

    def test_history_for_a_member_who_signs_in_later(self):
        self.alice.say("before bob returns")
        self.bob.message(sender="Alice")
        self.bob.peer.close()
        time.sleep(0.3)
        again = Member.__new__(Member)
        again.case, again.name = self, "Bob"
        again.peer = self.v2("Bob")
        again.identity, again.keys, again.bundles = self.bob.identity, RoomKeys(self.bob.identity, "Bob"), {}
        again.epoch, again.next = 1, 0
        history = [m for m in again.peer.history if m.get("enc")]
        self.assertEqual(len(history), 1)
        again.fetch()
        self.assertEqual(again.read(history[0]), "before bob returns")


class KeysTest(RoomCase):
    def setUp(self):
        super().setUp()
        self.turn_on()

    def test_missing_lists_shrink_as_keys_are_given(self):
        state = self.alice.state()
        self.assertEqual(sorted(state["missing"]), ["Alice", "Bob", "Carol"])
        self.alice.distribute()
        self.assertEqual(self.alice.state()["missing"], [])
        self.assertEqual(sorted(self.bob.state()["missing"]), ["Alice", "Bob", "Carol"])  # each person's own list

    def test_keys_arrive_live_and_from_storage(self):
        self.alice.distribute()
        pushed = self.bob.peer.until(lambda e: e["t"] == "group_key", limit=800)
        self.assertEqual((pushed["sender"], pushed["epoch"]), ("Alice", 1))
        self.bob.fetch()
        self.assertIn(("alice", 1), self.bob.keys.chains)

    def test_paging_through_many_envelopes(self):
        members = []
        for number in range(8):
            self.server.accounts.create_account(f"Extra{number}", "secret")
            members.append(Member(self, f"Extra{number}"))
        for member in members:
            member.distribute()
        self.bob.fetch()
        self.assertGreaterEqual(len([k for k in self.bob.keys.chains if k[1] == 1]), 8)

    def test_a_late_joiner_reads_only_what_comes_after_their_arrival(self):
        self.alice.distribute()
        self.alice.say("before dave")
        dave = Member(self, "Dave")
        self.alice.next += 1
        self.alice.distribute()  # dave shows up in alice's missing list; she hands him her chain as it stands
        self.alice.say("after dave")
        dave.fetch()
        events = [e for e in dave.peer.drain(0.6) if e["t"] == "message"]
        self.assertEqual(dave.read(events[-1]), "after dave")
        self.assertEqual(len(events), 1)
        history = [m for m in self.v2("Erin").history if m.get("enc") and m["sender"] == "Alice"]
        with self.assertRaises(NoKey):
            dave.read(history[0])

    def test_disabling_someone_starts_a_new_epoch_they_never_receive(self):
        self.alice.distribute()
        self.alice.say("epoch one")
        self.bob.message(sender="Alice")
        self.alice.peer.send(t="admin", req=1, op="disable", user="Bob")
        self.assertTrue(self.alice.peer.until(lambda e: e["t"] == "admin_result", limit=800)["ok"])
        self.assertEqual(self.carol.peer.until(lambda e: e["t"] == "room_epoch", limit=800)["epoch"], 2)
        self.assertEqual(self.server.room_epoch, 2)
        state = self.alice.state()
        self.assertEqual(sorted(state["missing"]), ["Alice", "Carol"])  # not Bob
        self.alice.say("epoch two")
        envelope = self.carol.peer.until(lambda e: e["t"] == "message" and e.get("enc") and e["enc"]["e"] == 2, limit=800)["enc"]
        self.assertEqual(envelope["e"], 2)
        with self.assertRaises(NoKey):
            self.bob.keys.decrypt(envelope, "Alice", [self.alice.bundle()])  # bob only holds epoch one
        self.assertEqual(self.server.store.envelopes_for(self.server.store.get_user("Bob").id, 0, 50).__len__(), 1)

    def test_an_admin_can_rekey_on_request(self):
        self.alice.peer.send(t="admin", req=1, op="rotate_room")
        self.assertTrue(self.alice.peer.until(lambda e: e["t"] == "admin_result", limit=800)["ok"])
        self.assertEqual(self.bob.peer.until(lambda e: e["t"] == "room_epoch", limit=800)["epoch"], 2)
        self.bob.peer.send(t="admin", req=1, op="rotate_room")
        self.assertFalse(self.bob.peer.until(lambda e: e["t"] == "admin_result", limit=800)["ok"])

    def test_a_changed_key_makes_everyone_hand_over_their_chain_again(self):
        self.alice.distribute()
        self.bob.distribute()
        before = len(self.server.store.envelopes_for(self.carol.peer and self.server.store.get_user("Carol").id, 0, 50))
        self.assertGreater(before, 0)
        self.carol.peer.send(t="keys_publish", req=9, **Identity.generate().public().to_dict())
        self.carol.peer.until(lambda e: e["t"] == "keys_result" and e["req"] == 9, limit=800)
        self.assertEqual(self.server.store.envelopes_for(self.server.store.get_user("Carol").id, 0, 50), [])
        self.assertIn("Carol", self.alice.state()["missing"])

    def test_envelope_validation(self):
        self.alice.lookup(["Bob"])
        good = self.alice.keys.key_envelope("Bob", self.alice.bundles["bob"], 1, 0)
        tests = [{"Bob": dict(good, e=2)}, {"Nobody": good}, {"Bob": "text"}, {"Bob": dict(good, pad="A" * 800)}]
        for envelopes in tests:
            self.alice.peer.send(t="group_keys", req=6, epoch=1, envelopes=envelopes)
            self.alice.peer.until(lambda e: e["t"] == "room_state" and e.get("req") == 6, limit=800)
        self.assertEqual(self.server.store.envelopes_for(self.server.store.get_user("Bob").id, 0, 50), [])
        self.alice.peer.send(t="group_keys", req=7, epoch=9, envelopes={"Bob": good})
        self.assertTrue(self.alice.peer.until(lambda e: e["t"] == "room_state" and e.get("req") == 7, limit=800)["rejected"])


class FilesTest(RoomCase):
    server_options = {"max_upload": 200_000, "user_quota": 400_000}

    def setUp(self):
        super().setUp()
        self.turn_on()

    def test_an_encrypted_file_in_the_room(self):
        data = MARKER.encode() * 500
        plain, cipher = os.path.join(self.tmp, "p"), os.path.join(self.tmp, "c")
        Path(plain).write_bytes(data)
        key = e2ee.new_file_key()
        size, digest = e2ee.encrypt_file(plain, cipher, key)
        info = {"name": "map.png", "mime": "image/png", "kind": "image", "size": len(data), "key": e2ee.b64(key)}
        self.alice.distribute()
        self.alice.peer.send(t="upload", req=8, name="", size=size, sha256=digest, enc=self.alice.envelope("the map", file=info))
        ready = self.alice.peer.until(lambda e: e["t"] in ("upload_ready", "upload_denied"), limit=800)
        self.assertEqual(ready["t"], "upload_ready")
        transfer.upload("127.0.0.1", self.port, None, ready["ticket"], cipher)
        event = self.bob.message(sender="Alice")
        self.assertEqual((event["att"]["kind"], event["att"]["name"], event["to"]), ("encrypted", "encrypted file", None))
        self.bob.fetch()
        payload = e2ee.decode_payload(self.bob.keys.decrypt(event["enc"], "Alice", [self.alice.bundle()]))
        self.assertEqual((payload["b"], payload["f"]["name"]), ("the map", "map.png"))
        blob = [p for p in Path(self.server.blobs.root).rglob("*") if p.is_file()][0]
        self.assertNotIn(MARKER.encode(), blob.read_bytes())

    def test_plain_files_are_refused_in_an_encrypted_room(self):
        self.alice.peer.send(t="upload", req=8, name="x.txt", size=3, sha256="a" * 64)
        self.assertIn("end-to-end encrypted", self.alice.peer.until(lambda e: e["t"] == "upload_denied", limit=800)["reason"])


class AdminTest(RoomCase):
    def test_settings_expose_the_room_and_who_would_be_locked_out(self):
        Member(self, "Dave", keys=False)
        self.alice.peer.send(t="admin_settings", req=1)
        snapshot = self.alice.peer.until(lambda e: e["t"] == "admin_settings", limit=800)
        self.assertEqual((snapshot["e2ee_room"], snapshot["room_epoch"], snapshot["without_keys"]), ("off", 1, ["Dave"]))
        self.alice.peer.send(t="admin", req=2, op="set_setting", user="e2ee_room", value="on")
        self.assertTrue(self.alice.peer.until(lambda e: e["t"] == "admin_result", limit=800)["ok"])
        self.assertEqual(self.server.e2ee_room, "on")
        self.alice.peer.send(t="admin", req=3, op="set_setting", user="e2ee_room", value="sometimes")
        self.assertFalse(self.alice.peer.until(lambda e: e["t"] == "admin_result" and e["req"] == 3, limit=800)["ok"])
        self.bob.peer.send(t="admin", req=4, op="set_setting", user="e2ee_room", value="off")
        self.assertFalse(self.bob.peer.until(lambda e: e["t"] == "admin_result", limit=800)["ok"])
        self.assertEqual(self.server.e2ee_room, "on")

    def test_legacy_text_for_room_messages(self):
        event = {"t": "message", "id": 1, "sender": "Alice", "to": None, "body": "", "ts": 0, "enc": {"v": 3}}
        self.assertIn("[encrypted message", legacy_text(event, "Bob"))


class StoreRoomTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        from store import Store
        self.store = Store(Path(tempfile.mkdtemp()) / "s.db")
        self.alice = self.store.create_user("Alice", "00", "00")
        self.bob = self.store.create_user("Bob", "00", "00")
        for user in (self.alice, self.bob):
            self.store.set_user_keys(user.id, "a", "b", "c", f"fp{user.id}")

    def test_epochs(self):
        self.assertEqual(self.store.room_epoch(), 1)
        self.assertEqual(self.store.bump_room_epoch(), 2)
        self.assertEqual(self.store.room_epoch(), 2)

    def test_message_numbers_only_go_up_and_cannot_jump_far(self):
        s = self.store
        self.assertEqual(s.last_group_number(self.alice.id, 1), -1)
        self.assertEqual(s.claim_group_number(self.alice.id, 1, 0), "ok")
        self.assertEqual(s.claim_group_number(self.alice.id, 1, 0), "stale")
        self.assertEqual(s.claim_group_number(self.alice.id, 1, 5), "ok")
        self.assertEqual(s.claim_group_number(self.alice.id, 1, 3), "stale")
        self.assertEqual(s.claim_group_number(self.alice.id, 1, 5 + 1002), "jump")
        self.assertEqual(s.claim_group_number(self.alice.id, 1, 5 + 1001), "ok")
        self.assertEqual(s.claim_group_number(self.alice.id, 2, 0), "ok")  # a new epoch starts again
        self.assertEqual(s.claim_group_number(self.bob.id, 1, 0), "ok")  # and each person has their own

    def test_envelopes_missing_lists_and_cleanup(self):
        s = self.store
        self.assertEqual(s.missing_recipients(self.alice.id, 1), ["Alice", "Bob"])
        s.add_envelope(self.bob.id, self.alice.id, 1, "{}")
        self.assertEqual(s.missing_recipients(self.alice.id, 1), ["Alice"])
        self.assertEqual(s.missing_recipients(self.alice.id, 2), ["Alice", "Bob"])  # per epoch
        self.assertEqual([e["sender"] for e in s.envelopes_for(self.bob.id)], ["Alice"])
        s.set_disabled("Bob", True)
        self.assertEqual(s.missing_recipients(self.alice.id, 2), ["Alice"])  # a removed person is never a recipient
        self.assertEqual(s.delete_envelopes_to(self.bob.id), 1)
        self.assertEqual(s.envelopes_for(self.bob.id), [])

    def test_people_without_keys(self):
        carol = self.store.create_user("Carol", "00", "00")
        self.assertEqual(self.store.active_users_without_keys(), ["Carol"])
        self.store.set_user_keys(carol.id, "a", "b", "c", "fp3")
        self.assertEqual(self.store.active_users_without_keys(), [])

    def test_a_version_6_database_upgrades(self):
        import sqlite3
        import tempfile
        from store import MIGRATIONS, Store
        path = Path(tempfile.mkdtemp()) / "old.db"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        for number, script in enumerate(MIGRATIONS[:6], start=1):
            db.executescript(script)
            db.execute("INSERT INTO schema_version (version) VALUES (?)", (number,))
        db.execute("INSERT INTO users (username, salt, hash, role, created_at) VALUES ('Old','00','00','admin',1)")
        db.commit()
        db.close()
        store = Store(path)
        self.assertEqual(store.schema_version(), 7)
        self.assertEqual(store.claim_group_number(1, 1, 0), "ok")
        self.assertEqual([u.username for u in store.list_users()], ["Old"])
        store.close()


if __name__ == "__main__":
    unittest.main()
