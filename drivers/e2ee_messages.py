"""Encrypted private messages in the real window: send, read, reply, edit, search, key change, replay, locked history."""
import os
os.environ["LANCHAT_DRIVER_DIALOGS"] = "1"

import json
import threading
import time
from pathlib import Path

from common import *  # noqa: F401,F403
import e2ee
from e2ee import Identity

e2ee.SCRYPT_N = 2**10
PASS = "correct horse battery"
MARKER = "ZEBRA-MARKER-4471"


class Person:
    """A second person on the other end: a bare connection that does what the window would do."""

    def __init__(self, port, name, keys=True):
        self.name = name
        self.peer = V2Peer(port, name, "river-stone-42")
        self.identity = Identity.generate() if keys else None
        if keys:
            self.publish(self.identity)
        threading.Thread(target=self._ping, daemon=True).start()

    def _ping(self):
        while True:
            time.sleep(5)
            try:
                self.peer.send(t="ping")
            except OSError:
                return

    def publish(self, identity):
        self.identity = identity
        self.peer.send(t="keys_publish", req=1, **identity.public().to_dict())

    def bundle(self):
        return self.identity.public()

    def envelope(self, text, others):
        return e2ee.encrypt_message(e2ee.encode_payload(text), self.identity, self.name, {o.name: o.bundle() for o in others})

    def read(self, event, sender):
        return e2ee.decode_payload(e2ee.decrypt_message(event["enc"], self.identity, self.name, sender.name, sender.bundle()))["b"]

    def next_message(self, **match):
        def wanted(e):
            return e["t"] == "message" and all(e.get(k) == v for k, v in match.items())
        return self.peer.until(wanted, limit=800)


server = start_server()
port = server.bound_port
root, app, ok = open_window(server, "Alice")
check("alice signs in", ok)
manager = app.e2ee
check("setup window opens", wait_until(root, lambda: "setup" in manager.windows))
w = manager.setup_widgets
w["first"].insert(0, PASS); w["second"].insert(0, PASS)
w["create"]()
manager.recovery_widgets["saved"].set(True); manager.recovery_widgets["toggle"](); manager.recovery_widgets["done"].command()
check("alice has keys", wait_until(root, lambda: manager.state == "ready" and server.store.get_user_keys(1) is not None))

bob = Person(port, "Bob")
carol = Person(port, "Carol", keys=False)
check("members arrive", wait_until(root, lambda: {m.name for m in app.members} >= {"Alice", "Bob", "Carol"}))


def private_records(text):
    return [r for r in app.messages.records if r.kind == "private" and r.text == text]


# ---------- the first encrypted message
app._start_private("Bob")
check("the chip says end-to-end encrypted", wait_until(root, lambda: "End-to-end encrypted with Bob" in app.private_label.cget("text")))
app.message_entry.set(f"hello bob {MARKER}")
app.send()
event = bob.next_message(sender="Alice")
check("bob receives ciphertext, not text", event["body"] == "" and event["enc"] and MARKER not in json.dumps(event))
check("bob can read it", bob.read(event, type("A", (), {"name": "Alice", "bundle": lambda self: manager.identity.public()})()) == f"hello bob {MARKER}")
check("alice's own bubble shows the text and the lock", wait_until(root, lambda: private_records(f"hello bob {MARKER}") and private_records(f"hello bob {MARKER}")[0].secure == "e2ee"))
mine = private_records(f"hello bob {MARKER}")[0]
root.update()
row = app.messages._rows[app.messages.index_of(mine.id)]
check("the bubble is labelled end-to-end encrypted", any("End-to-end encrypted" in t for t in texts(row)))
check("the message box cleared", app.message_entry.get() == "")
check("a first-time notice explains verification", any("now end-to-end encrypted" in r.text for r in app.messages.records))
check("bob's key is pinned", manager.store.contact("Bob") is not None)
time.sleep(0.3)
check("the server holds no plaintext (database file)", MARKER.encode() not in Path(server.store.path).read_bytes())
check("the server stored an empty body and an envelope", server.store.get_message(mine.id).body == "" and server.store.get_message(mine.id).enc)

# ---------- incoming
alice_identity = type("A", (), {"name": "Alice", "bundle": lambda self: manager.identity.public()})()
bob.peer.send(t="send", to="Alice", enc=bob.envelope("hi alice, it is bob", [alice_identity]))
check("an incoming encrypted message is opened", wait_until(root, lambda: private_records("hi alice, it is bob") and private_records("hi alice, it is bob")[0].secure == "e2ee"))
theirs = private_records("hi alice, it is bob")[0]
check("it is attributed to bob", theirs.sender == "Bob" and not theirs.mine)

# ---------- replies resolve their quote locally
bob.peer.send(t="send", to="Alice", reply_to=mine.id, enc=bob.envelope("answering your hello", [alice_identity]))
check("a reply to an encrypted message shows the quote", wait_until(root, lambda: private_records("answering your hello") and private_records("answering your hello")[0].reply and "hello bob" in private_records("answering your hello")[0].reply["snippet"]))

# ---------- edit
app.on_message_action("edit", mine)
check("editing loads the decrypted text", app.message_entry.get() == f"hello bob {MARKER}")
app.message_entry.set("hello bob (edited)")
app.send()
check("the edit shows on alice's screen", wait_until(root, lambda: mine.text == "hello bob (edited)" and mine.edited and mine.secure == "e2ee"))
edited = bob.peer.until(lambda e: e["t"] == "edited", limit=800)
check("bob gets a new envelope", edited["body"] == "" and bob.read(edited, alice_identity) == "hello bob (edited)")
check("the server still holds no text", server.store.get_message(mine.id).body == "")

# ---------- local search of decrypted text
app.toggle_search()
app.search_entry.set("edited")
app._run_search()
check("search finds decrypted messages locally", wait_until(root, lambda: any(r["id"] == mine.id for r in app.search_results)))
app.close_search()

# ---------- a contact without keys
app._clear_private()
app._start_private("Carol")
check("the chip says the other side has no keys", wait_until(root, lambda: "no encryption keys yet" in app.private_label.cget("text")))
app.message_entry.set("plain to carol")
app.send()
check("after agreeing, the plain message is sent as readable text", carol.next_message(sender="Alice")["body"] == "plain to carol")
check("its bubble says the server can read it", wait_until(root, lambda: private_records("plain to carol") and private_records("plain to carol")[0].secure == ""))
server.set_e2ee_policy("required")
check("the policy change reaches the window", wait_until(root, lambda: manager.policy == "required"))
app.message_entry.set("another plain")
before = len(app.messages.records)
app.send()
check("a required policy stops plain private messages", wait_until(root, lambda: any("requires it" in r.text for r in app.messages.records[before:])))
check("and the text stays in the box", app.message_entry.get() == "another plain")
app.message_entry.clear()
server.set_e2ee_policy("optional")
wait_until(root, lambda: manager.policy == "optional")
app._clear_private()

# ---------- too long
app._start_private("Bob")
wait_until(root, lambda: "End-to-end encrypted with Bob" in app.private_label.cget("text"))
app.message_entry.set("x" * 1600)
before = len(app.messages.records)
app.send()
check("an over-long encrypted message is refused with a reason", any("up to 1500 bytes" in r.text for r in app.messages.records[before:]))
app.message_entry.clear()

# ---------- replay
envelope = bob.envelope("one-time words", [alice_identity])
bob.peer.send(t="send", to="Alice", enc=envelope)
bob.peer.send(t="send", to="Alice", enc=envelope)
check("the first copy opens", wait_until(root, lambda: len(private_records("one-time words")) == 1))
check("the second copy is flagged as a replay", wait_until(root, lambda: any("possible replay" in r.text for r in app.messages.records)))

# ---------- a forged message (as if the server tampered)
mallory = Identity.generate()
forged = e2ee.encrypt_message(e2ee.encode_payload("send me money"), mallory, "Bob", {"Alice": manager.identity.public()})
bob_row = server.store.get_user("Bob")
message_id = server.store.add_message(bob_row.id, "", recipient_id=1, enc=json.dumps(forged))
message = server.store.get_message(message_id)
server._emit(server._message_events([message])[0], server._targets_for(message))
check("a message not signed by bob's key is rejected", wait_until(root, lambda: any("not signed by the person" in r.text for r in app.messages.records)))
check("the forged text is never shown", not any("send me money" in r.text for r in app.messages.records))

# ---------- bob's key changes
new_bob = Identity.generate()
bob.publish(new_bob)
check("alice is warned", wait_until(root, lambda: any("new security code" in r.text for r in app.messages.records)))
app.message_entry.set("did you change phones?")
before = len(app.messages.records)
app.send()
check("sending is blocked until the new code is accepted", wait_until(root, lambda: any("security code changed" in r.text for r in app.messages.records[before:])))
check("nothing went to the server", not any(m.body == "" and m.enc and "did you" in (m.enc or "") for m in server.store.history_for(1, 50)))
check("the verify window opened", wait_until(root, lambda: "verify-bob" in manager.windows and manager.verify_widgets["status"] == "changed"))
manager.verify_widgets["mark"]()
app.send()
delivered = bob.next_message(sender="Alice", body="")
check("the new envelope is addressed to bob's new key", bob.identity is new_bob and e2ee.decode_payload(e2ee.decrypt_message(delivered["enc"], new_bob, "Bob", "Alice", manager.identity.public()))["b"] == "did you change phones?")
check("after accepting, messages go to the new key", wait_until(root, lambda: private_records("did you change phones?") and private_records("did you change phones?")[0].secure == "e2ee"))
app._clear_private()

# ---------- leaving locks it; unlocking opens the history again
app.leave()
root.update()
root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
check("history arrives while keys are locked", wait_until(root, lambda: any(r.enc for r in app.messages.records)))
check("locked messages show a placeholder, not text", wait_until(root, lambda: all(r.secure in ("locked", "pending") for r in app.messages.records if r.enc) and "hello bob" not in " ".join(r.text for r in app.messages.records)))
check("the unlock window appears", wait_until(root, lambda: "unlock" in manager.windows))
manager.unlock_widgets["entry"].insert(0, PASS)
manager.unlock_widgets["unlock"]()
check("unlocking opens the history", wait_until(root, lambda: any(r.text == "hi alice, it is bob" and r.secure == "e2ee" for r in app.messages.records), 10))
check("alice's own old messages open too", any(r.text == "hello bob (edited)" and r.secure == "e2ee" for r in app.messages.records))
check("the quoted reply is filled in after reopening", wait_until(root, lambda: any(r.reply and "hello bob" in r.reply.get("snippet", "") for r in app.messages.records if r.text == "answering your hello")))

# ---------- skipping keeps the history locked and plain messages working
app.leave(); root.update(); root.destroy()
root, app, ok = open_window(server, "Alice")
manager = app.e2ee
wait_until(root, lambda: "unlock" in manager.windows)
manager.unlock_widgets["skip"]()
check("with keys skipped, encrypted history stays locked", wait_until(root, lambda: all(r.secure == "locked" for r in app.messages.records if r.enc)))
app._start_private("Carol")
app.message_entry.set("still can talk plainly")
app.send()
check("plain messages still work", carol.next_message(sender="Alice", body="still can talk plainly") is not None)
finish(app, server, bob.peer, carol.peer)
