"""Hosting from inside the window: encrypted by default, with the address and fingerprint on screen."""
import socket
import argparse
import tkinter as tk

from common import *  # noqa: F401,F403
import server as server_module

# Never touch the real accounts.db next to server.py: point the hosted server at a temporary one.
real = server_module.ChatServer
gui_client.ChatServer = lambda *a, **k: real(*a, accounts=AccountStore(f"{tmp}/hosted.json"), **{**k, "discovery": False})

root = tk.Tk()
app = App(root, argparse.Namespace(host=None, username="Revanth"), settings=Settings(f"{tmp}/home_host"))
app.apply_theme()
root.update()
app.user_entry.set("Revanth")
app.pass_entry.set("river-stone-42")
app.host()
check("hosting opens the chat", wait_until(root, lambda: app.screen == "chat" and app.connection is not None, 15))
check("header says encrypted", wait_until(root, lambda: "Encrypted" in app.subtitle_label.cget("text")))
check("host banner shows address and fingerprint", app.host_bar.winfo_ismapped() and "fingerprint" in app.host_label.cget("text") and ":" in app.host_label.cget("text"))
check("leave button says Stop hosting", app.leave_button.cget("text") == "Stop hosting")
check("host is the admin", wait_until(root, lambda: app.my_role() == "admin"))
check("a saved sign-in was issued", bool(app.session_token))
port = app.hosting.bound_port

# a second person joins over TLS with the trust prompt auto-accepted
from chat_core import connect_secure
joined = connect_secure("127.0.0.1", port, "Guest1", "mountain-lake-77", Settings(f"{tmp}/home_guest"),
                        confirm_trust=lambda *a: True, confirm_plain=lambda *a: False, protocol=2)
check("a second person joins over TLS", joined.encrypted and joined.fingerprint is not None)
check("host sees them", wait_until(root, lambda: {m.name for m in app.members} == {"Revanth", "Guest1"}))
joined.connection.close()

app.leave()
check("stop hosting returns home", app.screen == "home")
refused = False
try:
    socket.create_connection(("127.0.0.1", port), 1).close()
except OSError:
    refused = True
check("the port no longer accepts connections", refused)
app.on_close()
import shutil, sys
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
