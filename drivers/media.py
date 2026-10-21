"""Milestone 5 GUI flows: sharing pictures, documents and audio."""
import hashlib
import struct
import subprocess
import wave
import zlib
from pathlib import Path

from common import *  # noqa: F401,F403
import audio
import gui_media
import transfer


def make_png(path, w, h):
    raw = b"".join(b"\x00" + b"".join(bytes([x * 255 // w, y * 255 // h, 128]) for x in range(w)) for y in range(h))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                           + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


opened, played = [], []
audio.open_path = lambda p: opened.append(str(p)) or True
gui_media.audio.open_path = audio.open_path
gui_client.messagebox.askyesno = lambda *a, **k: True

server = start_server()
port = server.bound_port
root, app, ok = open_window(server)
check("alice signs in", ok)
check("limits arrive in the welcome", app.limits.get("max_upload", 0) > 1000 and ".exe" in app.limits.get("blocked", []))
bob = V2Peer(port, "Bob", "river-stone-42")


def keepalive():  # the server drops silent connections after 30 s
    while True:
        time.sleep(5)
        try:
            bob.send(t="ping")
        except OSError:
            return


import threading
threading.Thread(target=keepalive, daemon=True).start()
check("attach button sits left of the message box",
      app.attach_button.winfo_ismapped() and app.attach_button.winfo_rootx() < app.message_entry.winfo_rootx())


def bob_share(path, **extra):
    data = Path(path).read_bytes()
    bob.send(t="upload", req=7, name=os.path.basename(path), size=len(data),
             sha256=hashlib.sha256(data).hexdigest(), **extra)
    ready = bob.until(lambda e: e["t"] in ("upload_ready", "upload_denied"))
    assert ready["t"] == "upload_ready", ready
    return transfer.upload("127.0.0.1", port, None, ready["ticket"], path)


def row_of(record):
    return app.messages._rows[app.messages.index_of(record.id)]


def find_images(w):
    out = []
    for c in w.winfo_children():
        if isinstance(c, tk.Label) and c.cget("image"):
            out.append(c)
        out += find_images(c)
    return out


# ---------- a picture arrives
png = f"{tmp}/big.png"
make_png(png, 640, 480)
bob_share(png, caption="look!")
check("picture message appears", wait_until(root, lambda: any(r.att and r.att["name"] == "big.png" for r in app.messages.records)))
pic = next(r for r in app.messages.records if r.att and r.att["name"] == "big.png")
check("caption kept", pic.text == "look!")
check("preview loads inline", wait_until(root, lambda: pic.media.get("photo") is not None, 10))
photo = pic.media.get("photo")
check("preview scaled to fit", photo is not None and max(photo.width(), photo.height()) <= 320)
root.update()
check("one image label on screen", len(find_images(row_of(pic))) == 1)
check("name and size line shown", any("big.png" in t for t in texts(row_of(pic))))
app.on_message_action("att_open", pic)
check("clicking the picture opens the cached original",
      wait_until(root, lambda: len(opened) == 1) and Path(opened[0]).read_bytes() == Path(png).read_bytes()
      and opened[0].endswith("big.png"))

# ---------- a document: card, saved on request
doc = f"{tmp}/notes.txt"
Path(doc).write_text("meeting notes " * 50)
bob_share(doc)
check("document card arrives", wait_until(root, lambda: any(r.att and r.att["name"] == "notes.txt" for r in app.messages.records)))
card = next(r for r in app.messages.records if r.att and r.att["name"] == "notes.txt")
root.update()
check("card shows name, size and actions",
      {"notes.txt", "Open", "Save as…"} <= set(texts(row_of(card))) and any("KB" in t or " B" in t for t in texts(row_of(card))))
check("nothing downloaded just by arriving", not card.media.get("status"))
target = f"{tmp}/saved copy.txt"
gui_client.filedialog.asksaveasfilename = lambda **k: target
app.on_message_action("att_save", card)
check("Save as writes the file", wait_until(root, lambda: Path(target).exists() and Path(target).read_text() == Path(doc).read_text()))
check("saved notice shown", any(r.text.startswith("Saved to") for r in app.messages.records))
labels = [i[0] for i in app.menu_for(card)]
check("menu offers Open and Save as", "Open" in labels and "Save as…" in labels)

# ---------- audio
wav = f"{tmp}/hello.wav"
with wave.open(wav, "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(8000)
    w.writeframes(b"\x00\x00" * 4000)
bob_share(wav)
check("audio card arrives", wait_until(root, lambda: any(r.att and r.att["kind"] == "audio" for r in app.messages.records)))
snd = next(r for r in app.messages.records if r.att and r.att["kind"] == "audio")
root.update()
check("audio card has Play", "▶ Play" in texts(row_of(snd)))
app.media.player.play = lambda p: played.append(str(p)) or True
app.media.player.stop = lambda: played.append("stop")
app.on_message_action("att_play", snd)
check("Play fetches then plays", wait_until(root, lambda: played and played[-1].endswith("hello.wav")))
check("card now offers Stop", wait_until(root, lambda: "■ Stop" in texts(row_of(snd))))
app.on_message_action("att_play", snd)
check("Stop stops", wait_until(root, lambda: played[-1] == "stop" and not snd.media.get("playing")))

# ---------- progress and error rendering
card.media.update(status="loading", pct=42)
app.messages.refresh(card)
root.update()
check("progress text shown", any("42%" in t for t in texts(row_of(card))))
card.media.update(status="error", error="boom")
app.messages.refresh(card)
check("error text shown", any("boom" in t for t in texts(row_of(card))))

# ---------- Alice shares
slides = f"{tmp}/slides.pdf"
Path(slides).write_bytes(b"%PDF-1.4 " + os.urandom(3000))
gui_client.filedialog.askopenfilenames = lambda **k: (slides,)
app.message_entry.set("slides for tomorrow")
app.attach_file()
check("my file appears as my message", wait_until(root, lambda: any(r.att and r.att["name"] == "slides.pdf" and r.mine for r in app.messages.records), 10))
check("pending row removed afterwards", wait_until(root, lambda: not any(r.tone == "upload" for r in app.messages.records)))
mine = next(r for r in app.messages.records if r.att and r.att["name"] == "slides.pdf")
check("typed text became the caption", mine.text == "slides for tomorrow" and app.message_entry.get() == "")
ev = bob.until(lambda e: e["t"] == "message" and e.get("att") and e["att"]["name"] == "slides.pdf")
check("bob sees it", ev is not None and ev["body"] == "slides for tomorrow")

# ---------- refused up front, with a reason
exe = f"{tmp}/setup.exe"
Path(exe).write_bytes(b"MZ")
before = len(app.messages.records)
app.media.start_upload(exe, None, None)
check("blocked type explained", any("not allowed" in r.text for r in app.messages.records[before:]))
huge = f"{tmp}/huge.bin"
with open(huge, "wb") as f:
    f.truncate(app.limits["max_upload"] + 1)
app.media.start_upload(huge, None, None)
check("oversize explained", any("allows files up to" in r.text for r in app.messages.records))
empty = f"{tmp}/zero.txt"
Path(empty).write_bytes(b"")
app.media.start_upload(empty, None, None)
check("empty file explained", any("is empty" in r.text for r in app.messages.records))

# ---------- roles
server.set_role("Bob", "admin")
server.set_role("Alice", "guest")
check("role change arrives", wait_until(root, lambda: app.my_role() == "guest"))
before = len(app.messages.records)
app.attach_file()
check("guest told they cannot share", any("cannot share" in r.text for r in app.messages.records[before:]))
server.set_role("Alice", "admin")
wait_until(root, lambda: app.my_role() == "admin")

# ---------- a private file
Path(f"{tmp}/p.txt").write_text("private stuff")
gui_client.filedialog.askopenfilenames = lambda **k: (f"{tmp}/p.txt",)
app._start_private("Bob")
app.attach_file()
check("private file bubble shows for me", wait_until(root, lambda: any(r.att and r.att["name"] == "p.txt" and r.kind == "private" for r in app.messages.records)))
ev = bob.until(lambda e: e["t"] == "message" and e.get("att") and e["att"]["name"] == "p.txt", limit=500)
check("private file goes to bob, flagged private", ev is not None and ev["to"] == "Bob")
app._clear_private()

# ---------- a JPEG (needs Pillow or macOS sips; otherwise a plain card)
if sys.platform == "darwin":
    jpg = f"{tmp}/photo.jpg"
    subprocess.run(["sips", "-s", "format", "jpeg", png, "--out", jpg], capture_output=True)
    if Path(jpg).exists():
        bob_share(jpg)
        wait_until(root, lambda: any(r.att and r.att["name"] == "photo.jpg" for r in app.messages.records))
        jrec = next(r for r in app.messages.records if r.att and r.att["name"] == "photo.jpg")
        check("jpeg preview via sips", wait_until(root, lambda: jrec.media.get("photo") is not None, 10))

# ---------- delete
app.on_message_action("delete", mine)
check("deleting a shared file shows the tombstone", wait_until(root, lambda: mine.deleted))
root.update()
check("tombstone has no file card", "Open" not in texts(row_of(mine)))

app.leave()
check("leaving clears transfers", app.media.requests == {} and app.media._active == 0)
finish(app, server, bob)
