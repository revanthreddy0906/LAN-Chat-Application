"""End-to-end encrypted files through a real server: the server stores ciphertext and learns nothing else."""

import base64
import os
import time
import unittest
from pathlib import Path

import e2ee
import transfer
from e2ee import Identity
from test_e2ee_messages import Person
from test_v2 import V2TestCase

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")
MARKER = b"PLAINTEXT-FILE-MARKER-9921"


class FilePerson(Person):
    def share(self, case, recipient, data, name="holiday.png", kind="image", caption="", **overrides):
        """Encrypt `data` for `to` and upload it the way the window does. Returns the upload reply."""
        plain = os.path.join(case.tmp, "plain.bin")
        cipher = os.path.join(case.tmp, "cipher.bin")
        Path(plain).write_bytes(data)
        key = e2ee.new_file_key()
        cipher_size, digest = e2ee.encrypt_file(plain, cipher, key)
        info = {"name": name, "mime": "image/png", "kind": kind, "size": len(data), "key": e2ee.b64(key)}
        request = dict(t="upload", req=11, name="", size=cipher_size, sha256=digest, to=recipient.name,
                       enc=self.envelope_payload(caption, info, [recipient]))
        request.update(overrides)
        self.peer.send(**request)
        reply = self.peer.until(lambda e: e["t"] in ("upload_ready", "upload_denied"), limit=800)
        self.last = {"key": key, "cipher": cipher, "digest": digest, "size": cipher_size}
        if reply["t"] == "upload_ready":
            transfer.upload("127.0.0.1", case.port, None, reply["ticket"], cipher)
        return reply

    def envelope_payload(self, caption, info, others):
        return e2ee.encrypt_message(e2ee.encode_payload(caption, info), self.identity, self.name,
                                    {o.name: o.bundle() for o in others})

    def open(self, event, sender):
        data = e2ee.decrypt_message(event["enc"], self.identity, self.name, sender.name, sender.bundle())
        return e2ee.decode_payload(data)


@needs_crypto
class EncryptedFileTest(V2TestCase):
    server_options = {"max_upload": 200_000, "user_quota": 300_000}

    def setUp(self):
        super().setUp()
        self.alice, self.bob, self.carol = (FilePerson(self, n) for n in ("Alice", "Bob", "Carol"))

    def fetch(self, person, message_id, destination):
        person.peer.send(t="download", req=4, id=message_id)
        ready = person.peer.until(lambda e: e["t"] in ("download_ready", "transfer_error"), limit=800)
        if ready["t"] == "transfer_error":
            return ready
        transfer.download("127.0.0.1", self.port, None, ready["ticket"], ready["size"], ready["sha256"], destination)
        return ready

    def test_round_trip_for_the_recipient(self):
        data = MARKER + os.urandom(80_000)
        self.assertEqual(self.alice.share(self, self.bob, data, caption="my holiday")["t"], "upload_ready")
        event = self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        self.assertEqual((event["body"], event["att"]["kind"], event["att"]["name"]), ("", "encrypted", "encrypted file"))
        payload = self.bob.open(event, self.alice)
        self.assertEqual((payload["b"], payload["f"]["name"], payload["f"]["size"]), ("my holiday", "holiday.png", len(data)))
        encrypted_path = os.path.join(self.tmp, "got.enc")
        ready = self.fetch(self.bob, event["id"], encrypted_path)
        self.assertEqual(ready["size"], e2ee.encrypted_size(len(data)))
        plain_path = os.path.join(self.tmp, "got.png")
        e2ee.decrypt_file(encrypted_path, plain_path, e2ee.unb64(payload["f"]["key"]), payload["f"]["size"])
        self.assertEqual(Path(plain_path).read_bytes(), data)

    def test_the_sender_can_read_their_own_copy(self):
        self.alice.share(self, self.bob, b"x" * 5000, caption="mine")
        event = self.alice.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        self.assertEqual(self.alice.open(event, self.alice)["f"]["name"], "holiday.png")

    def test_the_server_stores_only_ciphertext_and_no_names(self):
        data = MARKER * 200
        self.alice.share(self, self.bob, data, name="secret-plans.pdf", kind="file", caption="for your eyes")
        self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        time.sleep(0.3)
        blobs = [p for p in Path(self.server.blobs.root).rglob("*") if p.is_file()]
        self.assertEqual(len(blobs), 1)
        self.assertNotIn(MARKER, blobs[0].read_bytes())
        self.assertEqual(blobs[0].stat().st_size, e2ee.encrypted_size(len(data)))
        raw = Path(self.server.store.path).read_bytes()
        for needle in (MARKER, b"secret-plans", b"for your eyes", self.alice.last["key"], base64.b64encode(self.alice.last["key"])):
            self.assertNotIn(needle, raw)
        for row in self.server.store._db.execute("SELECT * FROM audit WHERE action = 'file_shared'"):
            self.assertEqual(row["target"], "(encrypted)")
        stored = self.server.store.attachment_for_message(self.server.store.history_for(1, 5)[-1].id)
        self.assertEqual((stored["name"], stored["mime"], stored["kind"]), ("encrypted file", "application/octet-stream", "encrypted"))

    def test_a_third_person_cannot_fetch_it(self):
        self.alice.share(self, self.bob, b"y" * 4000)
        event = self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        self.assertEqual(self.fetch(self.carol, event["id"], os.path.join(self.tmp, "c"))["t"], "transfer_error")
        self.assertEqual([e for e in self.carol.peer.drain(0.4) if e["t"] == "message"], [])

    def test_a_late_joiner_in_the_conversation_gets_it_from_history(self):
        self.alice.share(self, self.bob, b"z" * 3000)
        self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        self.bob.peer.close()
        time.sleep(0.3)
        again = self.v2("Bob")
        history = [m for m in again.history if m.get("att")]
        self.assertEqual([m["att"]["kind"] for m in history], ["encrypted"])
        self.assertEqual(self.bob.open(history[0], self.alice)["f"]["size"], 3000)

    def test_limits_apply_to_the_ciphertext(self):
        self.assertEqual(self.alice.share(self, self.bob, os.urandom(200_001))["t"], "upload_denied")
        self.assertEqual(self.alice.share(self, self.bob, os.urandom(190_000))["t"], "upload_ready")
        self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        denied = self.alice.share(self, self.bob, os.urandom(150_000))
        self.assertEqual(denied["t"], "upload_denied")
        self.assertIn("file space", denied["reason"])

    def test_the_server_cannot_apply_name_rules_so_the_window_must(self):
        # a hostile sender hides an .exe inside the payload; the server has no way to know
        reply = self.alice.share(self, self.bob, b"MZ" + os.urandom(2000), name="evil.exe", kind="file")
        self.assertEqual(reply["t"], "upload_ready")

    def test_damaged_upload_bytes_are_refused(self):
        self.alice.share(self, self.bob, b"q" * 3000)
        self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        with self.assertRaises(transfer.TransferError) as raised:
            self.alice.share(self, self.bob, b"r" * 3000, sha256="0" * 64)
        self.assertIn("damaged", str(raised.exception))
        self.assertEqual([e for e in self.bob.peer.drain(0.6) if e["t"] == "message" and e.get("att")], [])

    def test_validation(self):
        for overrides in ({"to": None}, {"enc": {"v": 2}}, {"enc": "text"}):
            self.assertEqual(self.alice.share(self, self.bob, b"a" * 100, **overrides)["t"], "upload_denied", overrides)
        other = self.alice.envelope_payload("", {"name": "a", "mime": "x", "kind": "file", "size": 1, "key": e2ee.b64(e2ee.new_file_key())}, [self.carol])
        self.assertEqual(self.alice.share(self, self.bob, b"a" * 100, enc=other)["t"], "upload_denied")

    def test_policy(self):
        self.server.set_e2ee_policy("required")
        plain = dict(t="upload", req=7, name="x.txt", size=3, sha256="a" * 64, to="Bob")
        self.alice.peer.send(**plain)
        denied = self.alice.peer.until(lambda e: e["t"] == "upload_denied", limit=800)
        self.assertIn("requires end-to-end", denied["reason"])
        self.alice.peer.send(**{**plain, "to": None})  # the public room is not private
        self.assertEqual(self.alice.peer.until(lambda e: e["t"] in ("upload_ready", "upload_denied"), limit=800)["t"], "upload_ready")
        self.assertEqual(self.alice.share(self, self.bob, b"b" * 100)["t"], "upload_ready")
        self.server.set_e2ee_policy("off")
        self.assertEqual(self.alice.share(self, self.bob, b"c" * 100)["t"], "upload_denied")

    def test_a_terminal_client_is_told_it_is_encrypted(self):
        legacy = self.connect("Old")
        old = Person.__new__(Person)
        old.name, old.bundle = "Old", lambda: Identity.generate().public()
        self.alice.share(self, old, b"d" * 100)
        line = legacy.recv_until(lambda m: "encrypted file" in m)
        self.assertIsNotNone(line)
        self.assertNotIn("holiday", line)

    def test_deleting_the_message_removes_the_ciphertext(self):
        self.alice.share(self, self.bob, b"e" * 3000)
        event = self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        self.alice.peer.send(t="delete", id=event["id"])
        self.bob.peer.until(lambda e: e["t"] == "deleted", limit=800)
        self.assertEqual([p for p in Path(self.server.blobs.root).rglob("*") if p.is_file()], [])

    def test_edit_keeps_working_with_a_file_message(self):
        info = {"name": "holiday.png", "mime": "image/png", "kind": "image", "size": 3000, "key": e2ee.b64(e2ee.new_file_key())}
        self.alice.share(self, self.bob, b"f" * 3000, caption="before")
        event = self.bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
        self.alice.peer.send(t="edit", id=event["id"], enc=self.alice.envelope_payload("after", info, [self.bob]))
        edited = self.bob.peer.until(lambda e: e["t"] == "edited", limit=800)
        self.assertEqual(self.bob.open(edited, self.alice)["b"], "after")


if __name__ == "__main__":
    unittest.main()
