"""Opens the encryption screens one at a time so they can be screenshotted.

    python3 demo/showcase.py          (a small controller window has a Next button)
    python3 demo/showcase.py --auto   (steps through by itself; used to check the script)

It runs its own temporary server with its own accounts under demo/showcase/ and its own
~/.lanchat replacement, so nothing here touches real accounts or keys.
"""
import argparse
import os
import shutil
import struct
import sys
import threading
import time
import tkinter as tk
import wave
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
BASE = ROOT / "demo" / "showcase"
shutil.rmtree(BASE, ignore_errors=True)
BASE.mkdir(parents=True)
os.environ["LANCHAT_HOME"] = str(BASE / "server_home")

import audio  # noqa: E402
import e2ee  # noqa: E402
import gui_client  # noqa: E402
import gui_media  # noqa: E402
import transfer  # noqa: E402
from accounts import AccountStore  # noqa: E402
from chat_core import connect_secure  # noqa: E402
from e2ee import Identity  # noqa: E402
from gui_client import App  # noqa: E402
from server import ChatServer, default_tls_context  # noqa: E402
from settings import Settings  # noqa: E402
from test_v2 import V2Peer  # noqa: E402

e2ee.SCRYPT_N = 2**14  # quick enough to feel real
PASS, PHRASE = "river-stone-42", "correct horse battery"
parser = argparse.ArgumentParser()
parser.add_argument("--auto", action="store_true")
parser.add_argument("--jump", type=int, default=0, help="run steps 1..N straight away and stop at step N")
args = parser.parse_args()

# ---------------------------------------------------------------- server and people
context, _fp = default_tls_context()
server = ChatServer("127.0.0.1", 0, accounts=AccountStore(BASE / "showcase.db"), tls_context=context, quiet=True,
                    display_name="Studio", rate_limit=None, connection_limit=None, enforce_password_policy=False)
server.start()
port = server.bound_port
settings = Settings(BASE / "alice_home")
connect_secure("127.0.0.1", port, "Alice", PASS, settings, confirm_trust=lambda *a: True,
               confirm_plain=lambda *a: False, protocol=2).connection.close()  # pin the certificate: no trust prompt
server.store.delete_user_keys(1)  # keep Alice first (admin) with no keys yet


class Person:
    def __init__(self, name, keys=True):
        self.name = name
        self.peer = _connect(name)
        self.identity = Identity.generate() if keys else None
        if keys:
            self.publish(self.identity)
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self):
        last = time.time()
        while True:
            try:
                self.peer.next()
            except Exception:
                pass
            if time.time() - last > 5:
                last = time.time()
                try:
                    self.peer.send(t="ping")
                except OSError:
                    return

    def publish(self, identity):
        self.identity = identity
        self.peer.send(t="keys_publish", req=1, **identity.public().to_dict())

    def bundle(self):
        return self.identity.public()

    def say(self, text, to=None):
        self.peer.send(t="send", body=text, **({"to": to} if to else {}))

    def secret(self, text, to_name, to_bundle, **extra):
        env = e2ee.encrypt_message(e2ee.encode_payload(text), self.identity, self.name, {to_name: to_bundle})
        self.peer.send(t="send", to=to_name, enc=env, **extra)

    def send_file(self, path, name, kind, mime, to_name, to_bundle, caption=""):
        key = e2ee.new_file_key()
        cipher = str(path) + ".cipher"
        size, digest = e2ee.encrypt_file(str(path), cipher, key)
        info = {"name": name, "mime": mime, "kind": kind, "size": Path(path).stat().st_size, "key": e2ee.b64(key)}
        env = e2ee.encrypt_message(e2ee.encode_payload(caption, info), self.identity, self.name, {to_name: to_bundle})
        self.peer.send(t="upload", req=21, name="", size=size, sha256=digest, to=to_name, enc=env)
        deadline = time.time() + 5
        ticket = None
        while time.time() < deadline and ticket is None:  # the drain thread consumes events, so ask on a private socket
            time.sleep(0.05)
            ticket = READY.pop(self.name, None)
        if ticket:
            transfer.upload("127.0.0.1", port, TLS_CONTEXT, ticket, cipher)


READY: dict = {}
TLS_CONTEXT = None


def _connect(name):
    from chat_core import connect_and_login, fetch_server_certificate, make_tls_context
    global TLS_CONTEXT
    TLS_CONTEXT = make_tls_context(cadata=fetch_server_certificate("127.0.0.1", port))
    peer = V2Peer.__new__(V2Peer)
    peer.sock = connect_and_login("127.0.0.1", port, name, PASS, TLS_CONTEXT, protocol=2)
    peer.sock.settimeout(3)
    peer.name = name
    peer.welcome, peer.history, peer.history_start, peer.pins, peer.members = None, [], None, [], []
    original_next = peer.next

    def next_event():
        event = original_next()
        if event and event.get("t") == "upload_ready":
            READY[name] = event["ticket"]
        return event
    peer.next = next_event
    return peer


# ---------------------------------------------------------------- window
root = tk.Tk()
app = App(root, argparse.Namespace(host=f"127.0.0.1:{port}", username="Alice"), settings=settings)
app.apply_theme()
root.geometry("1000x720+420+50")
manager = app.e2ee
app.confirm = lambda *a, **k: True
opened = []
audio.open_path = lambda p: opened.append(p) or True
gui_media.audio.open_path = audio.open_path


def pump(seconds=0.4):
    end = time.time() + seconds
    while time.time() < end:
        root.update()
        time.sleep(0.02)


def wait(condition, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if condition():
            return True
        time.sleep(0.03)
    return condition()


def sign_in():
    app.address_visible = True
    app.address_entry.set(f"127.0.0.1:{port}")
    app.user_entry.set("Alice")
    app.pass_entry.set(PASS)
    app.join()
    wait(lambda: app.screen == "chat" and app.connection is not None)
    pump(0.6)


def make_png(path, w, h, tint):
    rows = []
    for y in range(h):
        row = b"".join(bytes([min(255, tint[0] + x * 120 // w), min(255, tint[1] + y * 100 // h), tint[2]]) for x in range(w))
        rows.append(b"\x00" + row)

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                           + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))


files = BASE / "files"
files.mkdir()
make_png(files / "campus-map.png", 520, 330, (30, 90, 160))
make_png(files / "whiteboard.png", 520, 330, (150, 60, 90))
(files / "demo-notes.txt").write_text("LAN Chat demo notes\n- end-to-end encrypted\n" * 20)
(files / "setup.exe").write_bytes(b"MZ" + b"\x00" * 200)
with wave.open(str(files / "voice-note.wav"), "wb") as handle:
    handle.setnchannels(1); handle.setsampwidth(2); handle.setframerate(8000); handle.writeframes(b"\x00\x00" * 16000)

bob = carol = None
alice_bundle = None


# ---------------------------------------------------------------- the screens
def s_setup():
    sign_in()
    wait(lambda: "setup" in manager.windows)


def s_recovery():
    w = manager.setup_widgets
    w["first"].insert(0, PHRASE); w["second"].insert(0, PHRASE)
    w["create"]()
    pump(0.5)


def s_unlock():
    global bob, carol, alice_bundle
    r = manager.recovery_widgets
    r["saved"].set(True); r["toggle"](); r["done"].command()
    pump(0.4)
    alice_bundle = manager.identity.public()
    bob, carol = Person("Bob"), Person("Carol", keys=False)
    wait(lambda: {m.name for m in app.members} >= {"Alice", "Bob", "Carol"})
    app.leave()
    pump(0.3)
    sign_in()
    wait(lambda: "unlock" in manager.windows)


def s_encrypted():
    manager.unlock_widgets["entry"].insert(0, PHRASE)
    manager.unlock_widgets["unlock"]()
    wait(lambda: manager.state == "ready")
    wait(lambda: {m.name for m in app.members} >= {"Alice", "Bob", "Carol"})
    bob.say("Morning everyone, the demo is at 3pm")
    pump(0.6)
    bob.secret("Hi Alice, are we still on for the demo this afternoon?", "Alice", alice_bundle)
    pump(0.8)
    app._start_private("Bob")
    wait(lambda: "End-to-end encrypted with Bob" in app.private_label.cget("text"))
    app.message_entry.set("Yes, see you at 3. I will bring the slides and the recovery code demo.")
    app.send()
    pump(1.2)
    bob.secret("Great. Can you send me the campus map too?", "Alice", alice_bundle)
    pump(1.0)


def s_plain():
    app._clear_private()
    app._start_private("Carol")
    wait(lambda: "no encryption keys yet" in app.private_label.cget("text"))
    app.message_entry.set("Hi Carol, welcome to the chat (you have not set up encryption yet)")
    app.send()
    pump(1.0)
    carol.say("Thanks Alice! How do I turn on the lock?", to="Alice")
    pump(1.0)


def s_files():
    app._clear_private()
    app._start_private("Bob")
    wait(lambda: "End-to-end encrypted with Bob" in app.private_label.cget("text"))
    gui_client.filedialog.askopenfilenames = lambda **k: (str(files / "campus-map.png"),)
    app.message_entry.set("Campus map, as asked")
    app.attach_file()
    wait(lambda: any(r.att and r.mine and r.media.get("photo") for r in app.messages.records), 12)
    bob.send_file(files / "whiteboard.png", "whiteboard.png", "image", "image/png", "Alice", alice_bundle, "Photo of the whiteboard")
    bob.send_file(files / "demo-notes.txt", "demo-notes.txt", "file", "text/plain", "Alice", alice_bundle)
    bob.send_file(files / "voice-note.wav", "voice-note.wav", "audio", "audio/wav", "Alice", alice_bundle)
    wait(lambda: sum(1 for r in app.messages.records if r.att and r.secure == "e2ee") >= 4, 12)
    wait(lambda: all(r.media.get("photo") for r in app.messages.records if r.att and r.att["kind"] == "image"), 12)
    pump(0.8)
    app.messages.scroll_to_bottom()


def s_changed():
    bob.publish(Identity.generate())
    wait(lambda: any("new security code" in r.text for r in app.messages.records))
    manager.open_verify("Bob")
    wait(lambda: "verify-bob" in manager.windows)
    pump(0.5)


def s_locked():
    manager.verify_widgets["mark"]()  # accept Bob's new code, as a real user would after checking it
    app.leave()
    pump(0.3)
    sign_in()
    wait(lambda: "unlock" in manager.windows)
    pump(0.8)


def s_prompt():
    manager.unlock_widgets["entry"].insert(0, PHRASE)
    manager.unlock_widgets["unlock"]()
    wait(lambda: manager.state == "ready")
    bob.send_file(files / "setup.exe", "setup.exe", "file", "application/octet-stream", "Alice", alice_bundle)
    wait(lambda: any(r.att and r.att["name"] == "setup.exe" and r.secure == "e2ee" for r in app.messages.records), 12)
    app.messages.scroll_to_bottom()
    pump(0.5)
    target = next(r for r in app.messages.records if r.att and r.att["name"] == "setup.exe")
    del app.confirm  # use the real question this time
    root.after(300, lambda: app.on_message_action("att_open", target))


def s_menus():
    manager.open_keys()
    app.open_admin()
    wait(lambda: app.admin_console is not None)
    app.admin_console.tabs.select(app.admin_console.settings_tab)
    pump(0.8)


STEPS = [
    ("1  SETUP WINDOW", "Screenshot the 'Set up end-to-end encryption' window (first sign-in).", s_setup),
    ("2  RECOVERY CODE", "Screenshot the recovery-code screen ('Done' should look disabled).", s_recovery),
    ("3  UNLOCK WINDOW", "Screenshot the 'Unlock your encryption keys' window (after signing in again).", s_unlock),
    ("4  ENCRYPTED CHAT", "Screenshot the whole window: the chip 'End-to-end encrypted with Bob' and the bubbles.", s_encrypted),
    ("5  PLAIN PRIVATE", "Screenshot the Carol chip ('no encryption keys yet') and her plain private bubble.", s_plain),
    ("6  FILES", "Screenshot the encrypted pictures, the file card and the audio card (scroll if needed).", s_files),
    ("7  KEY CHANGED", "Screenshot the warning notice, the ⚠ next to Bob, and the Verify dialog with digits.", s_changed),
    ("8  LOCKED HISTORY", "Screenshot the unlock window AND the locked bubbles / 'Encrypted file' cards behind it.", s_locked),
    ("9  OPEN-FILE PROMPT", "Screenshot the 'Open this file?' question for setup.exe, then click No.", s_prompt),
    ("10 MENUS AND ADMIN", "Screenshot 'Encryption keys' and the Admin console Settings tab; also click ⋯ for the menu.", s_menus),
]

# ---------------------------------------------------------------- controller
panel = tk.Toplevel(root)
panel.title("Showcase")
panel.geometry("380x230+20+60")
panel.attributes("-topmost", True)
heading = tk.Label(panel, text="", font=("Helvetica", 15, "bold"), anchor="w", justify="left", wraplength=350)
heading.pack(fill="x", padx=12, pady=(12, 4))
detail = tk.Label(panel, text="", anchor="w", justify="left", wraplength=350)
detail.pack(fill="x", padx=12)
state = {"index": -1, "busy": False}


def advance():
    if state["busy"]:
        return
    state["busy"] = True
    state["index"] += 1
    if state["index"] >= len(STEPS):
        heading.configure(text="All screens shown")
        detail.configure(text="Click Quit when you are done.")
        state["busy"] = False
        return
    title, note, action = STEPS[state["index"]]
    heading.configure(text=f"Preparing {title}…")
    detail.configure(text="")
    panel.update()
    try:
        action()
    except Exception as error:  # show it rather than dying silently
        heading.configure(text=f"{title}: problem")
        detail.configure(text=f"{type(error).__name__}: {error}")
        print("STEP FAILED", title, repr(error), flush=True)
        state["busy"] = False
        return
    heading.configure(text=f"Screen {title}")
    detail.configure(text=note + "\n\nWhen you have the screenshot, click Next.")
    print("READY", title, flush=True)
    state["busy"] = False


def quit_all():
    try:
        server.stop()
    finally:
        root.destroy()


tk.Button(panel, text="Next screen ▶", command=advance, width=18).pack(pady=(14, 4))
tk.Button(panel, text="Quit", command=quit_all).pack()
def jump():
    for _ in range(args.jump):
        advance()


root.after(300, jump if args.jump else advance)
if args.auto:
    def auto():
        if state["index"] < len(STEPS):
            advance()
            root.after(1500, auto)
        else:
            print("AUTO DONE", flush=True)
            root.after(500, quit_all)
    root.after(2500, auto)
root.mainloop()
