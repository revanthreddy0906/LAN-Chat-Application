"""Key rotation, restoring every identity on a new computer, and the app lock."""
import os
os.environ["LANCHAT_DRIVER_DIALOGS"] = "1"

import threading

from common import *  # noqa: F401,F403
import e2ee
from test_e2ee_room import Member

e2ee.SCRYPT_N = 2**10
PASS = "correct horse battery"


class Shim:
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
bob = Member(Shim(), "Bob")
wait_until(root, lambda: {m.name for m in app.members} >= {"Alice", "Bob"})
first_fingerprint = manager.identity.public().fingerprint()


def recs(text):
    return [r for r in app.messages.records if r.text == text]


def alice_bundle():
    bob.bundles.pop("alice", None)
    bob.lookup(["Alice"])
    return bob.bundles["alice"]


def bob_private(text):
    envelope = e2ee.encrypt_message(e2ee.encode_payload(text), bob.identity, "Bob", {"Alice": alice_bundle()})
    bob.peer.send(t="send", to="Alice", enc=envelope)


# ---------- history before the rotation: a private chat and the room
app._start_private("Bob")
wait_until(root, lambda: "End-to-end encrypted with Bob" in app.private_label.cget("text"))
app.message_entry.set("private one")
app.send()
bob_private("private two")
check("private messages work before rotating", wait_until(root, lambda: recs("private one") and recs("private two") and recs("private two")[0].secure == "e2ee", 10))
app._clear_private()
server.set_e2ee_room("on")
wait_until(root, lambda: manager.room_mode == "on")
app.message_entry.set("room one")
app.send()
wait_until(root, lambda: recs("room one") and recs("room one")[0].secure == "e2ee", 10)
bob.distribute()
bob.say("room two")
check("room messages work before rotating", wait_until(root, lambda: recs("room two") and recs("room two")[0].secure == "e2ee", 10))

# ---------- rotating
manager.open_keys()
wait_until(root, lambda: "keys" in manager.windows)
manager._close("keys")
manager.open_rotate()
wait_until(root, lambda: "rotate" in manager.windows)
r = manager.rotate_widgets
r["entry"].insert(0, "not the passphrase")
r["rotate"]()
check("a wrong passphrase does not rotate", "wrong passphrase" in r["message"].cget("text").lower() and manager.identity.public().fingerprint() == first_fingerprint)
r["entry"].delete(0, "end"); r["entry"].insert(0, PASS)
r["rotate"]()
root.update()
rec_widgets = manager.recovery_widgets
check("a new recovery code is shown", e2ee.valid_recovery_code(rec_widgets["code"]))
new_code = rec_widgets["code"]
rec_widgets["saved"].set(True); rec_widgets["toggle"](); rec_widgets["done"].command()
second_fingerprint = manager.identity.public().fingerprint()
check("the identity changed and the old one is kept", second_fingerprint != first_fingerprint and len(manager.old_identities) == 1)
check("the server holds the new public key", wait_until(root, lambda: server.store.get_user_keys(1)["fingerprint"] == second_fingerprint))
check("the rotation is in the audit log", "keys_rotated" in [row["action"] for row in server.store.audit_rows(limit=40)])
alert = bob.peer.until(lambda e: e["t"] == "key_changed" and e.get("rotated"), limit=800)
check("bob is told it was a rotation", alert is not None and alert["user"] == "Alice")
check("the envelopes sealed to the old key were kept", len(server.store.envelopes_for(1, 0, 20)) >= 1)

# ---------- everything still works
bob_private("private three")
check("a message sealed to the new key opens", wait_until(root, lambda: recs("private three") and recs("private three")[0].secure == "e2ee", 10))
app.message_entry.set("room after rotation")
app.send()
check("alice can still write in the room", wait_until(root, lambda: recs("room after rotation") and recs("room after rotation")[0].secure == "e2ee", 12))
bob.bundles.pop("alice", None)
wait_until(root, lambda: server.store.last_group_number(1, 1) >= 1)

# ---------- signing in again opens the old history with the old identity
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
wait_until(root, lambda: "unlock" in manager.windows)
manager.unlock_widgets["entry"].insert(0, PASS)
manager.unlock_widgets["unlock"]()
check("after a restart the old private message opens", wait_until(root, lambda: recs("private two") and recs("private two")[0].secure == "e2ee", 15))
check("the old room message from bob opens", wait_until(root, lambda: recs("room two") and recs("room two")[0].secure == "e2ee", 15))
check("alice's own old messages open", recs("private one") and recs("private one")[0].secure == "e2ee" and recs("room one")[0].secure == "e2ee")
check("and the new ones", recs("private three")[0].secure == "e2ee" and recs("room after rotation")[0].secure == "e2ee")

# ---------- a new computer restores every identity
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice", home_name="second_computer")
manager = app.e2ee
check("the new computer is asked for the recovery code", wait_until(root, lambda: "restore" in manager.windows))
x = manager.restore_widgets
x["code"].insert(0, new_code)
x["first"].insert(0, PASS + "2"); x["second"].insert(0, PASS + "2")
x["restore"]()
check("restoring works", wait_until(root, lambda: manager.state == "ready"))
check("both identities came back", len(manager.old_identities) == 1 and manager.identity.public().fingerprint() == second_fingerprint)
check("old messages open on the new computer", wait_until(root, lambda: recs("private two") and recs("private two")[0].secure == "e2ee" and recs("room two") and recs("room two")[0].secure == "e2ee", 15))

# ---------- the app lock
manager.open_keys()
wait_until(root, lambda: "keys" in manager.windows)
keys_window = manager.windows["keys"]
check("a dialog is open before locking", keys_window.winfo_viewable())
app.lock_screen()
root.update()
check("locking covers the whole window", app.lock_cover is not None and app.lock_cover.winfo_ismapped())
check("whatever is under the centre of the window is the cover", str(root.winfo_containing(root.winfo_rootx() + 300, root.winfo_rooty() + 200)).startswith(str(app.lock_cover)))
check("open dialogs are hidden too", not keys_window.winfo_viewable())
check("the keys are forgotten", manager.identity is None and manager.state == "locked" and manager.old_identities == [])
bob_private("private while locked")
check("a message that arrives while locked stays locked", wait_until(root, lambda: any(r.enc and r.secure == "locked" for r in app.messages.records)) and not recs("private while locked"))
lock = app.lock_widgets
lock["entry"].insert(0, "nope")
lock["unlock"]()
check("a wrong passphrase keeps it locked", app.lock_cover is not None and "not the right" in lock["message"].cget("text"))
lock["entry"].insert(0, PASS + "2")
lock["unlock"]()
check("the right passphrase unlocks", app.lock_cover is None and manager.state == "ready")
check("the dialog is back", keys_window.winfo_viewable())
check("the waiting message now opens", wait_until(root, lambda: recs("private while locked") and recs("private while locked")[0].secure == "e2ee", 10))
manager._close("keys")

app.set_lock_minutes(1)
check("the auto-lock choice is remembered", app.settings.get("lock_minutes") == 1)
app.last_activity -= 600
app._tick()
root.update()
check("being idle locks it by itself", app.lock_cover is not None and manager.state == "locked")
app.lock_widgets["entry"].insert(0, PASS + "2")
app.lock_widgets["unlock"]()
check("and it unlocks again", app.lock_cover is None and manager.state == "ready")
app.set_lock_minutes(0)
app.last_activity -= 600
app._tick()
check("with auto-lock off an idle window stays open", app.lock_cover is None)
app._start_private("Bob")
app.message_entry.set("after unlocking")
app.send()
check("sending works after the lock", wait_until(root, lambda: recs("after unlocking") and recs("after unlocking")[0].secure == "e2ee", 10))
finish(app, server, bob.peer)
