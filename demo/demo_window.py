"""Demo helper: open one LAN Chat window, sign in automatically and play a few scripted messages."""
import argparse, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tkinter as tk
from gui_client import App
from settings import Settings

user, port, slot, t0 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
SCRIPT = [
    (0, "Revanth", "say", "Good morning everyone, this is our LAN Chat demo \U0001F44B"),
    (4, "Saarthak", "say", "Morning! Everything here runs on our own Wi-Fi, no internet needed."),
    (8, "Srujan", "say", "And the connection is encrypted with TLS, right?"),
    (12, "Revanth", "reply", "Srujan", "Yes, TLS plus scrypt-hashed passwords. Check the lock in the header."),
    (16, "Srujan", "react", "Yes, TLS plus scrypt-hashed passwords", "\U0001F44D"),
    (19, "Saarthak", "say", "@Srujan can you show them private messages?"),
    (23, "Srujan", "say", "Sure! Click a name in the member list to message someone privately."),
    (27, "Revanth", "say", "We also have replies, reactions, edit, delete, search and pins."),
    (31, "Saarthak", "pin", "We also have replies, reactions, edit, delete, search and pins."),
    (34, "Srujan", "say", "Try Cmd+F to search history - messages are stored in SQLite."),
    (38, "Revanth", "react", "Try Cmd+F to search history", "\U0001F389"),
]
root = tk.Tk()
settings = Settings(os.environ["LANCHAT_HOME"])
app = App(root, argparse.Namespace(host=f"127.0.0.1:{port}", username=user), settings=settings)
app.apply_theme()
sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
w = sw // 3
root.geometry(f"{w}x{sh - 120}+{slot * w}+30")
root.update()
app.address_visible = True
app.address_entry.set(f"127.0.0.1:{port}")
app.user_entry.set(user)
app.pass_entry.set("demo123")
root.after(500, app.join)

def find(text):
    return next((r for r in app.messages.records if r.id and text in r.text), None)

def run(step):
    kind = step[2]
    if kind == "say":
        app.message_entry.set(step[3]); app.send()
    elif kind == "reply":
        target = next((r for r in app.messages.records if r.id and r.sender == step[3]), None)
        if target:
            app.on_message_action("reply", target)
        app.message_entry.set(step[4]); app.send()
    elif kind == "react":
        r = find(step[3])
        if r: app._send_event({"t": "react", "id": r.id, "emoji": step[4]})
    elif kind == "pin":
        r = find(step[3])
        if r: app._send_event({"t": "pin", "id": r.id, "on": True})

for step in SCRIPT:
    if step[1] == user:
        delay = int((t0 + 8 + step[0] - time.time()) * 1000)
        root.after(max(delay, 0), lambda s=step: run(s))
root.mainloop()
