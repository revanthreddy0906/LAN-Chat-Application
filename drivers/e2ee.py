"""Encryption key lifecycle in the real window: set up, recovery code, unlock, verify, key change, restore, reset."""
import os
os.environ["LANCHAT_DRIVER_DIALOGS"] = "1"

import time

from common import *  # noqa: F401,F403
import e2ee
from e2ee import Identity
from keystore import KeyStore, server_id

e2ee.SCRYPT_N = 2**10  # fast; the real cost is 2**15
PASS = "correct horse battery"

server = start_server()
port = server.bound_port
root, app, ok = open_window(server, "Alice")
check("alice signs in", ok)
manager = app.e2ee
check("the key setup window opens on a first sign-in", wait_until(root, lambda: "setup" in manager.windows and manager.state == "needs_setup"))
check("header says there are no keys yet", "no keys yet" in app.subtitle_label.cget("text"))
w = manager.setup_widgets
w["first"].insert(0, "short")
w["second"].insert(0, "short")
w["create"]()
check("a short passphrase is refused", "at least" in w["message"].cget("text") and manager.state == "needs_setup")
w["first"].delete(0, "end"); w["second"].delete(0, "end")
w["first"].insert(0, PASS); w["second"].insert(0, PASS + "x")
w["create"]()
check("mismatched passphrases are refused", "do not match" in w["message"].cget("text"))
w["second"].delete(0, "end"); w["second"].insert(0, PASS)
w["create"]()
root.update()
r = manager.recovery_widgets
check("the recovery code is shown once", e2ee.valid_recovery_code(r["code"]) and manager.state == "ready")
root.update()
button = r["done"]
check("the Done button is really visible, not hidden behind another widget",
      button.winfo_ismapped() and root.winfo_containing(button.winfo_rootx() + 5, button.winfo_rooty() + 5) is button)
check("Done is locked until the code is confirmed", r["done"].cget("state") == "disabled" or r["done"]._disabled)
r["saved"].set(True); r["toggle"]()
check("ticking the box enables Done", not r["done"]._disabled)
r["done"].command()
root.update()
check("the window closes", "setup" not in manager.windows)
check("header shows keys ready", wait_until(root, lambda: "keys ready" in app.subtitle_label.cget("text")))
key_file = KeyStore(app.settings.home, server_id(app.fingerprint, app.server_host, app.server_port), "Alice").key_path
check("the key file exists with private permissions", key_file.exists() and oct(key_file.stat().st_mode & 0o777) == "0o600")
check("the secret keys are not readable in the file", e2ee.b64(manager.identity.secret_bytes()) not in key_file.read_text())
check("the server holds the public keys", wait_until(root, lambda: server.store.get_user_keys(1) is not None))
check("the server holds a backup", server.store.get_backup(1) is not None)
recovery_code = r["code"]
my_fp = manager.identity.public().fingerprint()

# ---------- other people
bob = V2Peer(port, "Bob", "river-stone-42")
carol = V2Peer(port, "Carol", "river-stone-42")


def keepalive():
    while True:
        time.sleep(5)
        for peer in (bob, carol):
            try:
                peer.send(t="ping")
            except OSError:
                pass


import threading
threading.Thread(target=keepalive, daemon=True).start()
bob_identity = Identity.generate()
bob.send(t="keys_publish", req=1, **bob_identity.public().to_dict())
bob.until(lambda e: e["t"] == "keys_result", limit=300)
check("members arrive", wait_until(root, lambda: {m.name for m in app.members} >= {"Alice", "Bob", "Carol"}))

# ---------- verifying a contact
manager.open_verify("Bob")
check("the verify window opens", wait_until(root, lambda: "verify-bob" in manager.windows and hasattr(manager, "verify_widgets")))
v = manager.verify_widgets
expected = e2ee.safety_number("Alice", manager.identity.public(), "Bob", bob_identity.public())
check("the safety number is the one both sides compute", v["number"] == expected and v["status"] == "new")
check("it is shown as twelve groups of five digits", any(expected.split()[0] in t for t in texts(manager.windows["verify-bob"])))
v["mark"]()
check("marking verified pins the key", manager.store.is_verified("Bob") and manager.store.check_contact("Bob", bob_identity.public()) == "same")
root.update()
check("a tick appears next to Bob", "✔" in texts(app.users_frame))

# ---------- a contact's key changes
new_identity = Identity.generate()
bob.send(t="keys_publish", req=2, **new_identity.public().to_dict())
check("alice is warned in the chat", wait_until(root, lambda: any("new security code" in r.text for r in app.messages.records)))
check("a warning mark replaces the tick", wait_until(root, lambda: "⚠" in texts(app.users_frame) and "✔" not in texts(app.users_frame)))
manager.open_verify("Bob")
check("the dialog says the key is different", wait_until(root, lambda: "verify-bob" in manager.windows and manager.verify_widgets["status"] == "changed"))
check("the pin has not moved yet", manager.store.check_contact("Bob", new_identity.public()) == "changed")
manager.verify_widgets["mark"]()
check("accepting pins the new key and clears the warning", manager.store.check_contact("Bob", new_identity.public()) == "same" and "bob" not in manager.changed)

# ---------- a contact without keys
manager.open_verify("Carol")
check("a contact without keys is explained", wait_until(root, lambda: "verify-carol" in manager.windows and any("not set up" in t for t in texts(manager.windows["verify-carol"]))))
manager._close("verify-carol")

# ---------- a forged key is rejected on lookup
forged = new_identity.public().to_dict()
forged["dh"] = e2ee.b64(Identity.generate().public().dh)
seen = {}
server.store.set_user_keys(2, forged["dh"], forged["sign"], forged["sig"], "x")  # a malicious server swaps Bob's key
manager.lookup(["Bob"], lambda found: seen.update(found))
wait_until(root, lambda: False, 0.6)
check("the window refuses a bundle whose signature does not match", "Bob" not in seen)

# ---------- unlock on the next sign-in
app.leave()
check("leaving locks the keys", manager.identity is None)
root.update()
root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
check("the unlock window opens on the next sign-in", wait_until(root, lambda: "unlock" in manager.windows and manager.state == "locked"))
u = manager.unlock_widgets
u["entry"].insert(0, "not my passphrase")
u["unlock"]()
check("a wrong passphrase is refused", "not the right" in u["message"].cget("text") and manager.state == "locked")
u["entry"].delete(0, "end"); u["entry"].insert(0, PASS)
u["unlock"]()
check("the right passphrase unlocks", manager.state == "ready" and "unlock" not in manager.windows)
check("the same identity came back", manager.identity.public().fingerprint() == my_fp)
check("the contact pins survived the restart", manager.store.contact("Bob") is not None)

# ---------- skipping
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
wait_until(root, lambda: "unlock" in manager.windows)
manager.unlock_widgets["skip"]()
check("skipping carries on without end-to-end encryption", manager.state == "skipped" and "no end-to-end" in app.subtitle_label.cget("text"))

# ---------- restore on a new computer
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice", home_name="second_computer")
manager = app.e2ee
check("a new computer is asked for the recovery code", wait_until(root, lambda: "restore" in manager.windows and manager.state == "needs_restore"))
x = manager.restore_widgets
x["code"].insert(0, e2ee.new_recovery_code())
x["first"].insert(0, PASS + "2"); x["second"].insert(0, PASS + "2")
x["restore"]()
check("a wrong recovery code is refused", wait_until(root, lambda: "wrong passphrase" in x["message"].cget("text").lower() or "damaged" in x["message"].cget("text") or "wrong" in x["message"].cget("text").lower()) and manager.state == "needs_restore")
x["code"].delete(0, "end"); x["code"].insert(0, recovery_code.lower())
x["restore"]()
check("the right code restores the same identity", wait_until(root, lambda: manager.state == "ready") and manager.identity.public().fingerprint() == my_fp)
check("the new computer got its own passphrase", KeyStore(app.settings.home, server_id(app.fingerprint, app.server_host, app.server_port), "Alice").unlock(PASS + "2").public().fingerprint() == my_fp)
check("a restore does not announce a key change for alice", not [row for row in server.store.audit_rows(actor="Alice", limit=60) if row["action"] == "keys_changed"])

# ---------- reset
app.e2ee.open_keys()
check("the keys window shows my fingerprint", wait_until(root, lambda: "keys" in manager.windows and any(my_fp[:4].upper() in t for t in texts(manager.windows["keys"]))))
manager._close("keys")
bob.drain(0.2)
manager.reset_keys()
check("reset removes the keys from the server", wait_until(root, lambda: server.store.get_user_keys(1) is None))
check("reset starts the set-up again", wait_until(root, lambda: manager.state == "needs_setup" and "setup" in manager.windows))
check("the old key file is gone", not manager.store.exists())
check("bob is told", bob.until(lambda e: e["t"] == "key_changed" and e.get("reset"), limit=300) is not None)
check("the reset is in the audit log", "keys_reset" in [row["action"] for row in server.store.audit_rows(limit=60)])

# ---------- without the library
app.leave(); root.update(); root.destroy()
e2ee.AVAILABLE = False
root, app, ok = open_window(server, "Alice", home_name="third_computer")
check("without the package the window says so and still works", wait_until(root, lambda: "install 'cryptography'" in app.subtitle_label.cget("text")) and app.screen == "chat")
e2ee.AVAILABLE = True
finish(app, server, bob, carol)
