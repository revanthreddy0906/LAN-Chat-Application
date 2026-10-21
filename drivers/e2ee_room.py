"""The encrypted group room in the real window."""
import os
os.environ["LANCHAT_DRIVER_DIALOGS"] = "1"

import json
import struct
import threading
import zlib
from pathlib import Path

from common import *  # noqa: F401,F403
import e2ee
from e2ee import NoKey
from test_e2ee_room import Member

e2ee.SCRYPT_N = 2**10
PASS = "correct horse battery"
MARKER = "ROOM-DRIVER-MARKER-8820"


class Shim:
    """Lets the test helper `Member` open connections outside a unittest."""
    def v2(self, name):
        peer = V2Peer(server.bound_port, name, "river-stone-42")
        threading.Thread(target=ping, args=(peer,), daemon=True).start()
        return peer


def ping(peer):
    while True:
        time.sleep(5)
        try:
            peer.send(t="ping")
        except OSError:
            return


def make_png(path, w=480, h=300):
    raw = b"".join(b"\x00" + b"".join(bytes([x * 255 // w, y * 255 // h, 60]) for x in range(w)) for y in range(h))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    Path(path).write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                           + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


server = start_server()
root, app, ok = open_window(server, "Alice")
check("alice signs in", ok)
manager = app.e2ee
wait_until(root, lambda: "setup" in manager.windows)
w = manager.setup_widgets
w["first"].insert(0, PASS); w["second"].insert(0, PASS)
w["create"]()
manager.recovery_widgets["saved"].set(True); manager.recovery_widgets["toggle"](); manager.recovery_widgets["done"].command()
check("alice has keys", wait_until(root, lambda: manager.state == "ready"))
shim = Shim()
bob, carol = Member(shim, "Bob"), Member(shim, "Carol")
dave = shim.v2("Dave")  # no keys: a terminal-style member
wait_until(root, lambda: {m.name for m in app.members} >= {"Alice", "Bob", "Carol", "Dave"})


def stored(text_part=None):
    return [m for m in server.store.history_for(1, 300) if m.enc and m.recipient_id is None]


def recs(text):
    return [r for r in app.messages.records if r.text == text and r.kind == "chat"]


# ---------- before the room is encrypted
bob.peer.send(t="send", body="plain before")
check("plain messages work while the room is open", wait_until(root, lambda: recs("plain before")))
check("their bubbles carry no lock", recs("plain before")[0].secure == "")

# ---------- switching it on
server.set_e2ee_room("on")
check("the window learns the room is encrypted", wait_until(root, lambda: manager.room_mode == "on"))
check("a notice explains it", any("now end-to-end encrypted" in r.text for r in app.messages.records))
check("the header says so", "room encrypted" in app.subtitle_label.cget("text"))
root.update()
check("the chip above the box shows the room lock", app.private_chip.winfo_ismapped() and "Group room" in app.private_label.cget("text"))

# ---------- alice writes, with a mention
app.message_entry.set(f"hello room @Bob {MARKER}")
app.send()
check("alice's message appears decrypted with a room lock", wait_until(root, lambda: recs(f"hello room @Bob {MARKER}") and recs(f"hello room @Bob {MARKER}")[0].secure == "e2ee", 10))
mine = recs(f"hello room @Bob {MARKER}")[0]
row = app.messages._rows[app.messages.index_of(mine.id)]
check("the bubble is labelled as the encrypted room", any("Room · end-to-end encrypted" in t for t in texts(row)))
event = bob.message(sender="Alice")
check("the server relayed ciphertext only", event["body"] == "" and event["to"] is None and event["mentions"] == ["Bob"])
bob.fetch()
check("bob can read it", bob.read(event) == f"hello room @Bob {MARKER}")
time.sleep(0.3)
check("no plaintext in the server's database", MARKER.encode() not in Path(server.store.path).read_bytes())
check("alice's chain key never reached the server in the clear", all(chain not in Path(server.store.path).read_bytes() for chain in manager.room.chains[("alice", 1)].values()))

# ---------- bob writes back and alice's window opens it
bob.say("Hi Alice, bob here @Alice", mentions=["Alice"])
check("bob's message is opened in alice's window", wait_until(root, lambda: recs("Hi Alice, bob here @Alice") and recs("Hi Alice, bob here @Alice")[0].secure == "e2ee", 10))
theirs = recs("Hi Alice, bob here @Alice")[0]
check("the mention highlights it", theirs.mentioned)
carol_event = carol.message(sender="Alice")
carol.fetch()
check("carol can read the room too", carol.read(carol_event) == f"hello room @Bob {MARKER}")

# ---------- reply and quote
app.on_message_action("reply", theirs)
app.message_entry.set("welcome bob")
app.send()
check("the reply is quoted from decrypted text", wait_until(root, lambda: recs("welcome bob") and recs("welcome bob")[0].reply and "Hi Alice" in recs("welcome bob")[0].reply.get("snippet", ""), 10))

# ---------- edit
app.on_message_action("edit", mine)
check("editing loads the decrypted text", app.message_entry.get() == f"hello room @Bob {MARKER}")
app.message_entry.set("hello room (edited)")
app.send()
check("the edit shows", wait_until(root, lambda: mine.text == "hello room (edited)" and mine.edited and mine.secure == "e2ee", 10))

# ---------- pin and search
app.on_message_action("pin", theirs, True)
check("the pin bar shows the decrypted text", wait_until(root, lambda: app.pin_bar.winfo_ismapped() and "Hi Alice" in app.pin_label.cget("text"), 10))
app.on_message_action("pin", theirs, False)
wait_until(root, lambda: not app.pins)
app.toggle_search()
app.search_entry.set("edited")
app._run_search()
check("search finds decrypted room messages", wait_until(root, lambda: any(r["id"] == mine.id for r in app.search_results)))
app.close_search()

# ---------- a picture in the room
png = f"{tmp}/room.png"
make_png(png)
gui_client.filedialog.askopenfilenames = lambda **k: (png,)
app.message_entry.set("the map")
app.attach_file()
check("the picture appears with a preview", wait_until(root, lambda: any(r.att and r.mine and r.kind == "chat" and r.media.get("photo") for r in app.messages.records), 15))
picture = next(r for r in app.messages.records if r.att and r.mine and r.kind == "chat")
check("it is an encrypted attachment on the server", all(not (a and a["name"] == "room.png") for a in (server.store.attachment_for_message(m.id) for m in server.store.history_for(1, 300))))
check("its caption is the decrypted text", picture.text == "the map")

# ---------- a member without keys cannot take part
dave.send(t="send", body="can you hear me")
refusal = dave.until(lambda e: e["t"] == "notice" and e["kind"] == "error", limit=800)
check("a plain message from a member without keys is refused", "end-to-end encrypted" in refusal["text"])
dave_view = [m for m in dave.history if m.get("enc")]
check("they see only placeholders", all(m["body"] == "" for m in dave_view))

# ---------- removing someone renews the keys
app._send_event({"t": "admin", "req": 90, "op": "disable", "user": "Carol"})
check("the room moves to a new epoch", wait_until(root, lambda: manager.room_epoch == 2, 10))
check("alice is told the keys were renewed", any("keys were renewed" in r.text for r in app.messages.records))
app.message_entry.set("after carol left")
app.send()
check("the new message is sent in epoch two and readable by alice", wait_until(root, lambda: recs("after carol left") and recs("after carol left")[0].secure == "e2ee", 12))
last = [m for m in stored() if json.loads(m.enc).get("e") == 2]
check("the server holds an epoch-2 message", len(last) == 1)
bob.state()
bob.fetch()
bob.lookup(["Alice"])
check("bob reads it with the key alice gave him for epoch two", e2ee.decode_payload(bob.keys.decrypt(json.loads(last[0].enc), "Alice", [bob.bundles["alice"]]))["b"] == "after carol left")
try:
    carol.keys.decrypt(json.loads(last[0].enc), "Alice", [manager.identity.public()])
    leaked = True
except NoKey:
    leaked = False
check("carol, removed, cannot read epoch two", not leaked)

# ---------- a later joiner
erin = Member(shim, "Erin")
check("alice hands erin her key when erin appears", wait_until(root, lambda: server.store.envelopes_for(server.store.get_user("Erin").id, 0, 20) != [], 15))
app.message_entry.set("welcome erin")
app.send()
wait_until(root, lambda: recs("welcome erin"))
erin.fetch()
newest = [m for m in stored()][-1]
check("erin reads what is sent after she arrives", erin.read({"sender": "Alice", "enc": json.loads(newest.enc)}) == "welcome erin")
oldest = [m for m in stored() if json.loads(m.enc).get("e") == 1 and m.sender == "Alice"][0]
try:
    erin.read({"sender": "Alice", "enc": json.loads(oldest.enc)})
    early = True
except NoKey:
    early = False
check("erin cannot read what was said before she joined", not early)

# ---------- locked history, then unlocked
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
check("room messages wait locked", wait_until(root, lambda: any(r.enc and r.secure in ("pending", "locked") for r in app.messages.records)))
wait_until(root, lambda: "unlock" in manager.windows)
check("the chip says to unlock", wait_until(root, lambda: "unlock" in app.private_label.cget("text")))
app.message_entry.set("typing while locked")
before = len(app.messages.records)
app.send()
check("writing while locked is refused with a reason", wait_until(root, lambda: any("end-to-end encrypted" in r.text for r in app.messages.records[before:])))
manager.unlock_widgets["entry"].insert(0, PASS)
manager.unlock_widgets["unlock"]()
check("unlocking opens the whole history, both epochs", wait_until(root, lambda: recs("after carol left") and recs("after carol left")[0].secure == "e2ee" and recs("welcome erin") and recs("welcome erin")[0].secure == "e2ee" and recs("hello room (edited)") and recs("hello room (edited)")[0].secure == "e2ee", 15))
check("bob's old messages open after a restart", wait_until(root, lambda: recs("Hi Alice, bob here @Alice") and recs("Hi Alice, bob here @Alice")[0].secure == "e2ee", 10))
check("the plain message from before is still plain", recs("plain before") and recs("plain before")[0].secure == "")
app.message_entry.set("back again")
app.send()
check("alice can write again after reconnecting", wait_until(root, lambda: recs("back again") and recs("back again")[0].secure == "e2ee", 12))
nums = [json.loads(m.enc)["n"] for m in stored() if m.sender == "Alice" and json.loads(m.enc)["e"] == 2]
check("message numbers kept counting up across the restart", nums == sorted(nums) and len(set(nums)) == len(nums))

# ---------- turning it off again
server.set_e2ee_room("off")
check("the window learns it is off", wait_until(root, lambda: manager.room_mode == "off"))
app.message_entry.set("plain again")
app.send()
check("plain messages work again", wait_until(root, lambda: recs("plain again") and recs("plain again")[0].secure == ""))
finish(app, server, bob.peer, carol.peer, dave, erin.peer)
