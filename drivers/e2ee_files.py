"""Encrypted pictures, files and audio in the real window."""
import os
os.environ["LANCHAT_DRIVER_DIALOGS"] = "1"

import struct
import threading
import wave
import zlib
from pathlib import Path

from common import *  # noqa: F401,F403
import audio
import e2ee
import gui_media
import transfer
from e2ee import Identity

e2ee.SCRYPT_N = 2**10
PASS = "correct horse battery"
opened, confirms = [], []
audio.open_path = lambda p: opened.append(str(p)) or True
gui_media.audio.open_path = audio.open_path


def make_png(path, w=640, h=480):
    raw = b"".join(b"\x00" + b"".join(bytes([x * 255 // w, y * 255 // h, 90]) for x in range(w)) for y in range(h))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                           + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


class Person:
    def __init__(self, port, name, keys=True):
        self.name, self.port = name, port
        self.peer = V2Peer(port, name, "river-stone-42")
        self.identity = Identity.generate() if keys else None
        if keys:
            self.peer.send(t="keys_publish", req=1, **self.identity.public().to_dict())
        threading.Thread(target=self._ping, daemon=True).start()

    def _ping(self):
        while True:
            time.sleep(5)
            try:
                self.peer.send(t="ping")
            except OSError:
                return

    def bundle(self):
        return self.identity.public()

    def send_file(self, to_bundle_holder, path, name, kind, mime="application/octet-stream", wrong_key=False):
        data = Path(path).read_bytes()
        key = e2ee.new_file_key()
        cipher = path + ".cipher"
        cipher_size, digest = e2ee.encrypt_file(path, cipher, key)
        shown_key = e2ee.new_file_key() if wrong_key else key
        info = {"name": name, "mime": mime, "kind": kind, "size": len(data), "key": e2ee.b64(shown_key)}
        envelope = e2ee.encrypt_message(e2ee.encode_payload("", info), self.identity, self.name,
                                        {to_bundle_holder[0]: to_bundle_holder[1]})
        self.peer.send(t="upload", req=21, name="", size=cipher_size, sha256=digest, to=to_bundle_holder[0], enc=envelope)
        ready = self.peer.until(lambda e: e["t"] in ("upload_ready", "upload_denied"), limit=800)
        assert ready["t"] == "upload_ready", ready
        transfer.upload("127.0.0.1", self.port, None, ready["ticket"], cipher)


server = start_server()
port = server.bound_port
root, app, ok = open_window(server, "Alice")
check("alice signs in", ok)
manager = app.e2ee
wait_until(root, lambda: "setup" in manager.windows)
w = manager.setup_widgets
w["first"].insert(0, PASS); w["second"].insert(0, PASS)
w["create"]()
manager.recovery_widgets["saved"].set(True); manager.recovery_widgets["toggle"](); manager.recovery_widgets["done"].command()
check("alice has keys", wait_until(root, lambda: manager.state == "ready"))
bob = Person(port, "Bob")
carol = Person(port, "Carol", keys=False)
wait_until(root, lambda: {m.name for m in app.members} >= {"Alice", "Bob", "Carol"})
gui_client.messagebox.askyesno = lambda *a, **k: confirms.append(a[0]) or confirms_answer[0]
confirms_answer = [True]

# ---------- alice sends an encrypted picture
png = f"{tmp}/pic.png"
make_png(png)
original = Path(png).read_bytes()
gui_client.filedialog.askopenfilenames = lambda **k: (png,)
app._start_private("Bob")
wait_until(root, lambda: "End-to-end encrypted with Bob" in app.private_label.cget("text"))
app.message_entry.set("look at this")
app.attach_file()


def attachments_on_server():
    return len([m for m in server.store.history_for(1, 300) if server.store.attachment_for_message(m.id)])


check("the upload finishes", wait_until(root, lambda: attachments_on_server() == 1, 15))
event = bob.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
check("the server relays an opaque attachment", event["att"]["kind"] == "encrypted" and event["att"]["name"] == "encrypted file" and event["body"] == "")
alice_view = type("A", (), {"name": "Alice", "bundle": lambda self: manager.identity.public()})()
payload = e2ee.decode_payload(e2ee.decrypt_message(event["enc"], bob.identity, "Bob", "Alice", alice_view.bundle()))
check("bob learns the name, size and caption from the encrypted part", payload["f"]["name"] == "pic.png" and payload["b"] == "look at this" and payload["f"]["size"] == len(original))
bob.peer.send(t="download", req=3, id=event["id"])
ready = bob.peer.until(lambda e: e["t"] == "download_ready", limit=800)
transfer.download("127.0.0.1", port, None, ready["ticket"], ready["size"], ready["sha256"], f"{tmp}/bob.enc")
e2ee.decrypt_file(f"{tmp}/bob.enc", f"{tmp}/bob.png", e2ee.unb64(payload["f"]["key"]), payload["f"]["size"])
check("bob recovers the exact picture", Path(f"{tmp}/bob.png").read_bytes() == original)
blobs = [p for p in Path(server.blobs.root).rglob("*") if p.is_file()]
check("the server's copy is ciphertext", len(blobs) == 1 and b"\x89PNG" not in blobs[0].read_bytes()[:64] and original[100:200] not in blobs[0].read_bytes())
check("the pending row is gone and alice sees her message", wait_until(root, lambda: not any(r.tone == "upload" for r in app.messages.records) and any(r.att and r.mine and r.secure == "e2ee" for r in app.messages.records)))
mine = next(r for r in app.messages.records if r.att and r.mine)
check("alice's copy shows the real file details", mine.att["name"] == "pic.png" and mine.att["kind"] == "image" and mine.text == "look at this")
check("the picture previews inline after decrypting", wait_until(root, lambda: mine.media.get("photo") is not None, 10))
root.update()
row = app.messages._rows[app.messages.index_of(mine.id)]
check("the bubble says end-to-end encrypted", any("End-to-end encrypted" in t for t in texts(row)))
app.on_message_action("att_open", mine)
check("opening it gives the original picture", wait_until(root, lambda: opened) and Path(opened[-1]).read_bytes() == original and opened[-1].endswith("pic.png"))

# ---------- bob sends files to alice
alice_bundle = ("Alice", manager.identity.public())
doc = f"{tmp}/notes.txt"
Path(doc).write_text("meeting notes " * 100)
bob.send_file(alice_bundle, doc, "notes.txt", "file", "text/plain")
check("an incoming encrypted document shows as a card", wait_until(root, lambda: any(r.att and r.att["name"] == "notes.txt" and r.secure == "e2ee" for r in app.messages.records)))
card = next(r for r in app.messages.records if r.att and r.att["name"] == "notes.txt")
root.update()
check("the card offers Open and Save as", {"Open", "Save as…"} <= set(texts(app.messages._rows[app.messages.index_of(card.id)])))
target = f"{tmp}/saved notes.txt"
gui_client.filedialog.asksaveasfilename = lambda **k: target
app.on_message_action("att_save", card)
check("saving decrypts to the original", wait_until(root, lambda: Path(target).exists() and Path(target).read_text() == Path(doc).read_text()))

wav = f"{tmp}/clip.wav"
with wave.open(wav, "wb") as handle:
    handle.setnchannels(1); handle.setsampwidth(2); handle.setframerate(8000); handle.writeframes(b"\x00\x00" * 4000)
bob.send_file(alice_bundle, wav, "clip.wav", "audio", "audio/wav")
check("encrypted audio shows a Play button", wait_until(root, lambda: any(r.att and r.att["kind"] == "audio" and r.secure == "e2ee" for r in app.messages.records)))
root.update()
sound = next(r for r in app.messages.records if r.att and r.att["kind"] == "audio")
check("Play is offered", "▶ Play" in texts(app.messages._rows[app.messages.index_of(sound.id)]))

# a hostile name in the encrypted payload is made harmless
evil = f"{tmp}/x.bin"
Path(evil).write_bytes(b"data" * 50)
bob.send_file(alice_bundle, evil, "../../outside.txt", "file")
check("a path in the file name is reduced to a plain name", wait_until(root, lambda: any(r.att and r.att["name"] == "outside.txt" for r in app.messages.records)))
exe = f"{tmp}/prog.bin"
Path(exe).write_bytes(b"MZ" + b"\x00" * 100)
bob.send_file(alice_bundle, exe, "setup.exe", "file")
check("an executable hidden inside the encrypted part is still recognised", wait_until(root, lambda: any(r.att and r.att["name"] == "setup.exe" for r in app.messages.records)))
program = next(r for r in app.messages.records if r.att and r.att["name"] == "setup.exe")
before = len(opened)
confirms.clear(); confirms_answer[0] = False
app.on_message_action("att_open", program)
root.update()
check("opening it asks first", any("Open this file" in c for c in confirms))
check("declining opens nothing", len(opened) == before and not program.media.get("status"))
confirms_answer[0] = True
app.on_message_action("att_open", program)
check("agreeing opens it", wait_until(root, lambda: len(opened) == before + 1))
check("nothing was written outside the cache", not Path(f"{tmp}/../outside.txt").exists() and not Path(f"{tmp}/outside.txt").exists())

# a tampered file or wrong key is refused, never opened
bad = f"{tmp}/bad.bin"
Path(bad).write_bytes(b"secret" * 100)
bob.send_file(alice_bundle, bad, "wrongkey.txt", "file", wrong_key=True)
wait_until(root, lambda: any(r.att and r.att["name"] == "wrongkey.txt" for r in app.messages.records))
wrong = next(r for r in app.messages.records if r.att and r.att["name"] == "wrongkey.txt")
before = len(opened)
app.on_message_action("att_open", wrong)
check("a file that does not match its key is refused", wait_until(root, lambda: wrong.media.get("status") == "error") and len(opened) == before)

# ---------- editing a caption keeps the file
app.on_message_action("edit", mine)
app.message_entry.set("new caption")
app.send()
check("the caption changes and the file stays", wait_until(root, lambda: mine.text == "new caption" and mine.att and mine.att["name"] == "pic.png" and mine.file))
edited = bob.peer.until(lambda e: e["t"] == "edited", limit=800)
check("bob's copy still describes the file", e2ee.decode_payload(e2ee.decrypt_message(edited["enc"], bob.identity, "Bob", "Alice", alice_view.bundle()))["f"]["name"] == "pic.png")

# ---------- too long a caption
app.message_entry.set("c" * 1100)
before = len(app.messages.records)
app.attach_file()
check("a long caption is refused for encrypted files", wait_until(root, lambda: any("up to 1000 bytes" in r.text for r in app.messages.records[before:])))
app.message_entry.clear()

# ---------- a contact without keys, and the required policy
app._clear_private()
app._start_private("Carol")
wait_until(root, lambda: "no encryption keys yet" in app.private_label.cget("text"))
confirms_answer[0] = True
gui_client.filedialog.askopenfilenames = lambda **k: (doc,)
before_plain = attachments_on_server()
app.attach_file()
wait_until(root, lambda: attachments_on_server() > before_plain, 15)
sent = carol.peer.until(lambda e: e["t"] == "message" and e.get("att"), limit=800)
check("with consent, a file to a keyless contact goes as readable text", sent["att"]["name"] == "notes.txt" and sent["att"]["kind"] == "file")
server.set_e2ee_policy("required")
wait_until(root, lambda: manager.policy == "required")
before_atts = len([m for m in server.store.history_for(1, 200) if server.store.attachment_for_message(m.id)])
before = len(app.messages.records)
app.attach_file()
check("a required policy refuses a readable file", wait_until(root, lambda: any("requires it" in r.text for r in app.messages.records[before:])))
check("nothing was uploaded", len([m for m in server.store.history_for(1, 200) if server.store.attachment_for_message(m.id)]) == before_atts)
server.set_e2ee_policy("optional")
wait_until(root, lambda: manager.policy == "optional")
app._clear_private()

# ---------- the public room is unchanged
gui_client.filedialog.askopenfilenames = lambda **k: (doc,)
app.attach_file()
check("a file in the public room is still an ordinary shared file", wait_until(root, lambda: any(r.att and r.kind == "chat" and r.att["name"] == "notes.txt" and not r.enc for r in app.messages.records), 10))

# ---------- leaving locks the files until the keys are unlocked
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
check("encrypted files wait locked", wait_until(root, lambda: any(r.att and r.att["kind"] == "encrypted" for r in app.messages.records)))
locked = next(r for r in app.messages.records if r.att and r.att["kind"] == "encrypted")
root.update()
check("a locked file shows as an encrypted file with no actions", "Encrypted file" in texts(app.messages._rows[app.messages.index_of(locked.id)]) and "Open" not in texts(app.messages._rows[app.messages.index_of(locked.id)]))
wait_until(root, lambda: "unlock" in manager.windows)
manager.unlock_widgets["entry"].insert(0, PASS)
manager.unlock_widgets["unlock"]()
check("unlocking reveals the file details and previews", wait_until(root, lambda: any(r.att and r.att["name"] == "pic.png" and r.media.get("photo") is not None for r in app.messages.records), 12))
check("no encrypted placeholders remain", not any(r.att and r.att["kind"] == "encrypted" for r in app.messages.records))
finish(app, server, bob.peer, carol.peer)
