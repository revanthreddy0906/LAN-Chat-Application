"""File and image sharing: tickets, the data connection, limits, safety."""

import hashlib
import json
import os
import socket
import threading
import time
import unittest
from pathlib import Path

import storage
import transfer
from protocol import receive_message, send_message
from test_v2 import V2TestCase


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MediaTestCase(V2TestCase):
    server_options = {"max_upload": 100_000, "user_quota": 150_000}

    def write(self, name, data: bytes) -> str:
        path = os.path.join(self.tmp, name)
        Path(path).write_bytes(data)
        return path

    def request_upload(self, peer, name, data: bytes, **extra):
        peer.send(t="upload", req=1, name=name, size=len(data), sha256=sha(data), **extra)
        return peer.until(lambda e: e["t"] in ("upload_ready", "upload_denied"))

    def share(self, peer, name, data: bytes, **extra):
        ready = self.request_upload(peer, name, data, **extra)
        self.assertEqual(ready["t"], "upload_ready", ready)
        path = self.write("src_" + name.replace("/", "_"), data)
        return transfer.upload("127.0.0.1", self.port, None, ready["ticket"], path)

    def fetch(self, peer, message_id, name="got.bin"):
        peer.send(t="download", req=2, id=message_id)
        ready = peer.until(lambda e: e["t"] in ("download_ready", "transfer_error"))
        if ready["t"] == "transfer_error":
            return ready
        destination = os.path.join(self.tmp, name)
        transfer.download("127.0.0.1", self.port, None, ready["ticket"], ready["size"],
                          ready["sha256"], destination)
        return Path(destination).read_bytes()


class RoundTripTest(MediaTestCase):
    def test_image_is_shared_and_downloaded_intact(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        data = os.urandom(5000)
        message_id = self.share(alice, "holiday.png", data, caption="look at this")
        event = bob.until(lambda e: e["t"] == "message" and e.get("att"))
        self.assertEqual(event["id"], message_id)
        self.assertEqual(event["body"], "look at this")
        self.assertEqual(event["att"]["name"], "holiday.png")
        self.assertEqual((event["att"]["kind"], event["att"]["size"]), ("image", 5000))
        self.assertEqual(self.fetch(bob, message_id), data)

    def test_file_kinds(self):
        self.assertEqual([storage.kind_for(n) for n in ("a.PNG", "b.mp4", "c.wav", "d.pdf", "e")],
                         ["image", "video", "audio", "file", "file"])

    def test_history_carries_the_attachment(self):
        alice = self.v2("Alice")
        self.share(alice, "notes.pdf", b"%PDF-1.4 fake")
        late = self.v2("Bob")
        self.assertEqual([m["att"]["name"] for m in late.history if m.get("att")], ["notes.pdf"])

    def test_terminal_client_is_told_about_the_file(self):
        alice = self.v2("Alice")
        legacy = self.connect("Carol")
        self.share(alice, "song.wav", b"RIFF....")
        line = legacy.recv_until(lambda m: "song.wav" in m)
        self.assertIsNotNone(line)
        self.assertIn("[audio: song.wav]", line)

    def test_same_file_twice_is_stored_once(self):
        alice = self.v2("Alice")
        data = b"same bytes" * 100
        self.share(alice, "one.txt", data)
        self.share(alice, "two.txt", data)
        stored = [p for p in Path(self.server.blobs.root).rglob("*") if p.is_file() and p.parent.name != "tmp"]
        self.assertEqual(len(stored), 1)


class LimitsTest(MediaTestCase):
    def denied(self, peer, name, data, **extra):
        reply = self.request_upload(peer, name, data, **extra)
        self.assertEqual(reply["t"], "upload_denied", reply)
        return reply["reason"]

    def test_blocked_extension(self):
        alice = self.v2("Alice")
        self.assertIn("not allowed", self.denied(alice, "setup.exe", b"MZ"))

    def test_too_large_and_empty(self):
        alice = self.v2("Alice")
        self.assertIn("too large", self.denied(alice, "big.bin", b"x" * 100_001))
        self.assertIn("empty", self.denied(alice, "none.txt", b""))

    def test_quota(self):
        alice = self.v2("Alice")
        self.share(alice, "a.bin", os.urandom(90_000))
        self.assertIn("file space", self.denied(alice, "b.bin", os.urandom(80_000)))

    def test_guests_cannot_share(self):
        self.v2("Alice")
        bob = self.v2("Bob")
        self.server.set_role("Bob", "guest")
        self.assertIn("cannot share", self.denied(bob, "x.txt", b"hi"))

    def test_malformed_requests(self):
        alice = self.v2("Alice")
        for bad in ({"name": 5, "size": 3, "sha256": "x"}, {"name": "a", "size": "3", "sha256": sha(b"a")},
                    {"name": "a", "size": 3, "sha256": "ZZ" * 32}):
            alice.send(t="upload", req=1, **bad)
            reply = alice.until(lambda e: e["t"] == "upload_denied")
            self.assertIsNotNone(reply, bad)

    def test_admin_can_tighten_the_limit_at_runtime(self):
        alice = self.v2("Alice")
        self.server.store.set_setting("max_upload", "1000")
        self.assertIn("too large", self.denied(alice, "a.bin", b"x" * 2000))
        self.server.store.set_setting("blocked_extensions", ".txt")
        self.assertIn("not allowed", self.denied(alice, "a.txt", b"x"))


class SafetyTest(MediaTestCase):
    def test_hostile_names_are_neutralised(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.share(alice, "../../etc/passwd", b"root")
        event = bob.until(lambda e: e["t"] == "message" and e.get("att"))
        self.assertEqual(event["att"]["name"], "passwd")
        root = self.server.blobs.root.resolve()
        for path in Path(self.tmp).rglob("passwd"):
            self.fail(f"file escaped the storage folder: {path}")
        for path in root.rglob("*"):
            self.assertTrue(path.resolve().is_relative_to(root))

    def test_sanitize_name(self):
        self.assertEqual(storage.sanitize_name("C:\\Users\\me\\pic.png"), "pic.png")
        self.assertEqual(storage.sanitize_name("  ..  "), "file")
        self.assertEqual(storage.sanitize_name("a\x00b\nc.txt"), "abc.txt")
        long = storage.sanitize_name("x" * 300 + ".png")
        self.assertLessEqual(len(long), storage.MAX_NAME_CHARS)
        self.assertTrue(long.endswith(".png"))

    def test_wrong_hash_is_rejected_and_nothing_is_posted(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        claimed = b"the file I promised"
        ready = self.request_upload(alice, "doc.txt", claimed)
        sent = self.write("other.txt", b"X" * len(claimed))
        with self.assertRaises(transfer.TransferError) as raised:
            transfer.upload("127.0.0.1", self.port, None, ready["ticket"], sent)
        self.assertIn("damaged", str(raised.exception))
        self.assertIsNone(bob.until(lambda e: e["t"] == "message" and e.get("att"), limit=2))
        self.assertEqual(list(self.server.blobs.tmp.glob("*")), [])

    def test_ticket_works_once_and_junk_tickets_fail(self):
        alice = self.v2("Alice")
        data = b"hello world"
        ready = self.request_upload(alice, "h.txt", data)
        path = self.write("h.txt", data)
        transfer.upload("127.0.0.1", self.port, None, ready["ticket"], path)
        with self.assertRaises(transfer.TransferError):
            transfer.upload("127.0.0.1", self.port, None, ready["ticket"], path)
        with self.assertRaises(transfer.TransferError):
            transfer.upload("127.0.0.1", self.port, None, "not-a-ticket", path)

    def test_an_upload_ticket_cannot_be_used_to_download(self):
        alice = self.v2("Alice")
        ready = self.request_upload(alice, "h.txt", b"abc")
        with self.assertRaises(transfer.TransferError):
            transfer.download("127.0.0.1", self.port, None, ready["ticket"], 3, sha(b"abc"),
                              os.path.join(self.tmp, "x"))

    def test_expired_ticket(self):
        alice = self.v2("Alice")
        ready = self.request_upload(alice, "h.txt", b"abc")
        with self.server._ticket_lock:
            self.server._tickets[ready["ticket"]]["expires"] = time.time() - 1
        with self.assertRaises(transfer.TransferError):
            transfer.upload("127.0.0.1", self.port, None, ready["ticket"], self.write("h.txt", b"abc"))

    def test_cut_off_upload_leaves_nothing_behind(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        data = os.urandom(20_000)
        ready = self.request_upload(alice, "half.bin", data)
        raw = socket.create_connection(("127.0.0.1", self.port), 3)
        self.assertEqual(receive_message(raw), "USERNAME")
        send_message(raw, json.dumps({"v": 2, "data": "up", "ticket": ready["ticket"]}))
        self.assertEqual(receive_message(raw), "READY")
        raw.sendall(data[:5000])
        raw.close()
        self.assertIsNone(bob.until(lambda e: e["t"] == "message" and e.get("att"), limit=2))
        time.sleep(0.3)
        self.assertEqual(list(self.server.blobs.tmp.glob("*")), [])

    def test_private_files_stay_private(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")
        data = b"secret plans" * 50
        message_id = self.share(alice, "plans.txt", data, to="Bob")
        self.assertIsNotNone(bob.until(lambda e: e["t"] == "message" and e.get("att")))
        self.assertEqual(self.fetch(bob, message_id), data)
        denied = self.fetch(carol, message_id)
        self.assertEqual(denied["t"], "transfer_error")
        self.assertEqual(carol.drain(0.3) and [e for e in carol.drain(0.1) if e.get("att")], [])

    def test_sharing_with_an_unknown_person_is_refused(self):
        alice = self.v2("Alice")
        reply = self.request_upload(alice, "a.txt", b"hi", to="Nobody")
        self.assertEqual(reply["t"], "upload_denied")

    def test_deleting_the_message_removes_the_file(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message_id = self.share(alice, "gone.txt", b"bye" * 10)
        alice.send(t="delete", id=message_id)
        self.assertIsNotNone(alice.until(lambda e: e["t"] == "deleted"))
        self.assertEqual(self.fetch(bob, message_id)["t"], "transfer_error")
        files = [p for p in Path(self.server.blobs.root).rglob("*") if p.is_file()]
        self.assertEqual(files, [])

    def test_shared_file_survives_until_every_copy_is_deleted(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        data = b"same" * 100
        first = self.share(alice, "a.txt", data)
        second = self.share(bob, "b.txt", data)
        alice.send(t="delete", id=first)
        alice.until(lambda e: e["t"] == "deleted")
        self.assertEqual(self.fetch(bob, second), data)

    def test_data_connection_cannot_log_in_like_a_chat(self):
        raw = socket.create_connection(("127.0.0.1", self.port), 3)
        receive_message(raw)
        send_message(raw, json.dumps({"v": 2, "data": "up", "ticket": 5}))
        self.assertIn("invalid", receive_message(raw))
        raw.close()


class ConcurrencyTest(MediaTestCase):
    server_options = {"max_upload": 2_000_000, "user_quota": 50_000_000}

    def test_many_uploads_at_once(self):
        names = [f"User{i}" for i in range(6)]
        peers = [self.v2(n) for n in names]
        payloads = {n: os.urandom(300_000) for n in names}
        failures = []

        def work(peer):
            try:
                self.share(peer, f"{peer.name}.bin", payloads[peer.name])
            except Exception as error:  # noqa: BLE001 - report any failure from the thread
                failures.append(error)

        threads = [threading.Thread(target=work, args=(p,)) for p in peers]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(failures, [])
        seen = peers[0].drain(1.0)
        self.assertEqual(len([e for e in seen if e["t"] == "message" and e.get("att")]), 6)

    def test_two_windows_fetching_the_same_file_into_one_cache_path(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")
        data = os.urandom(900_000)
        message_id = self.share(alice, "shared.bin", data)
        target = os.path.join(self.tmp, "cache", "shared.bin")
        errors = []

        def fetch(peer):
            try:
                peer.send(t="download", req=3, id=message_id)
                ready = peer.until(lambda e: e["t"] == "download_ready", limit=500)
                transfer.download("127.0.0.1", self.port, None, ready["ticket"], ready["size"], ready["sha256"], target)
            except Exception as error:  # noqa: BLE001 - collect whatever went wrong in the thread
                errors.append(error)

        threads = [threading.Thread(target=fetch, args=(p,)) for p in (bob, carol)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(Path(target).read_bytes(), data)
        self.assertEqual([p.name for p in Path(target).parent.iterdir()], ["shared.bin"])  # no .part files left


if __name__ == "__main__":
    unittest.main()
