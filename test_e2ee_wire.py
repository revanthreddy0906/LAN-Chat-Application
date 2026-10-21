"""The server's whole view of the wire: every frame it received and sent, scanned for secrets."""

import os
import unittest
from pathlib import Path
from unittest import mock

import e2ee
import server as server_module
import transfer
from test_e2ee_messages import Person
from test_e2ee_room import Member
from test_v2 import V2TestCase

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")
SECRETS = ["WIRE-PRIVATE-MARKER-3141", "WIRE-ROOM-MARKER-2718", "WIRE-EDIT-MARKER-1618", "WIRE-CAPTION-MARKER-1414"]
FILE_MARKER = b"WIRE-FILE-MARKER-1732" * 100


@needs_crypto
class WireTest(V2TestCase):
    def setUp(self):
        super().setUp()
        self.seen = []
        real_receive, real_send = server_module.receive_message, server_module.send_message

        def receive(connection):
            frame = real_receive(connection)
            if frame is not None:
                self.seen.append(frame)
            return frame

        def send(connection, message):
            self.seen.append(message)
            return real_send(connection, message)

        self.patches = [mock.patch.object(server_module, "receive_message", receive),
                        mock.patch.object(server_module, "send_message", send)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        super().tearDown()

    def test_no_secret_ever_crosses_the_server(self):
        alice, bob = Person(self, "Alice"), Person(self, "Bob")
        room_alice, room_bob = Member.__new__(Member), Member.__new__(Member)
        for member, person in ((room_alice, alice), (room_bob, bob)):
            member.case, member.name, member.peer = self, person.name, person.peer
            member.identity, member.bundles, member.epoch, member.next = person.identity, {}, 1, 0
            member.keys = e2ee_group_keys(person)
        self.server.set_e2ee_room("on")

        alice.send(SECRETS[0], bob)                                  # a private message
        room_alice.say(SECRETS[1])                                   # a room message
        bob_event = bob.peer.until(lambda e: e["t"] == "message" and e.get("to") == "Bob", limit=800)
        edit = alice.envelope(SECRETS[2], [bob])                     # a private edit
        alice.peer.send(t="edit", id=bob_event["id"], enc=edit)
        alice.peer.until(lambda e: e["t"] == "edited", limit=800)

        plain, cipher = os.path.join(self.tmp, "p"), os.path.join(self.tmp, "c")                    # an encrypted file
        Path(plain).write_bytes(FILE_MARKER)
        key = e2ee.new_file_key()
        size, digest = e2ee.encrypt_file(plain, cipher, key)
        info = {"name": "wire-secret-name.pdf", "mime": "application/pdf", "kind": "file",
                "size": len(FILE_MARKER), "key": e2ee.b64(key)}
        envelope = e2ee.encrypt_message(e2ee.encode_payload(SECRETS[3], info), alice.identity, "Alice",
                                        {"Bob": bob.bundle()})
        alice.peer.send(t="upload", req=3, name="", size=size, sha256=digest, to="Bob", enc=envelope)
        ready = alice.peer.until(lambda e: e["t"] == "upload_ready", limit=800)
        transfer.upload("127.0.0.1", self.port, None, ready["ticket"], cipher)
        bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)

        wire = "\\n".join(self.seen).encode()
        self.assertGreater(len(self.seen), 20)  # we really did capture the traffic
        self.assertIn(b'"enc"', wire)
        for secret in SECRETS + ["wire-secret-name", "application/pdf"]:
            self.assertNotIn(secret.encode(), wire, secret)
        self.assertNotIn(e2ee.b64(key).encode(), wire)
        stored = Path(self.server.store.path).read_bytes()
        for secret in SECRETS + ["wire-secret-name"]:
            self.assertNotIn(secret.encode(), stored, secret)
        for blob in Path(self.server.blobs.root).rglob("*"):
            if blob.is_file():
                self.assertNotIn(FILE_MARKER[:30], blob.read_bytes())
                self.assertNotIn(b"WIRE-FILE", blob.read_bytes())
        for secret in (alice.identity.secret_bytes(), bob.identity.secret_bytes()):
            self.assertNotIn(secret, wire)
            self.assertNotIn(secret, stored)
            self.assertNotIn(e2ee.b64(secret).encode(), stored)


def e2ee_group_keys(person):
    from e2ee_group import RoomKeys
    return RoomKeys(person.identity, person.name)


if __name__ == "__main__":
    unittest.main()
