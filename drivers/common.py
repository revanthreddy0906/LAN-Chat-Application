"""Shared helpers for the scripted GUI drivers: they open the real window and click through it."""
import argparse
import os
import shutil
import sys
import tempfile
import time
import tkinter as tk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
tmp = tempfile.mkdtemp()
os.environ["LANCHAT_HOME"] = f"{tmp}/home"

import gui_client  # noqa: E402
from accounts import AccountStore  # noqa: E402
from gui_client import App  # noqa: E402
from server import ChatServer  # noqa: E402
from settings import Settings  # noqa: E402
from test_v2 import V2Peer  # noqa: E402

gui_client.messagebox.askyesno = lambda *a, **k: True  # answer 'connect without encryption?' etc.
gui_client.messagebox.askokcancel = lambda *a, **k: True

# The encryption set-up windows would pop up on every first sign-in; only the e2ee driver wants them.
if not os.environ.get("LANCHAT_DRIVER_DIALOGS"):
    import gui_e2ee
    gui_e2ee.E2EEManager.open_setup = gui_e2ee.E2EEManager.open_unlock = gui_e2ee.E2EEManager.open_restore = (
        lambda self: None)

results = []


def check(name, ok):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name)


def wait_until(root, predicate, timeout=6):
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if predicate():
            return True
        time.sleep(0.03)
    return predicate()


def texts(widget):
    out = []
    for child in widget.winfo_children():
        if isinstance(child, tk.Label):
            out.append(child.cget("text"))
        out += texts(child)
    return out


def rec(app, text):
    return next((r for r in app.messages.records if r.text == text and r.kind in ("chat", "private")), None)


def start_server(**options):
    relaxed = {} if os.environ.get("LANCHAT_STRICT") else {
        "rate_limit": None, "connection_limit": None, "enforce_password_policy": False}
    server = ChatServer("127.0.0.1", 0, accounts=AccountStore(f"{tmp}/accounts.json"), quiet=True,
                        display_name="Studio", **{**relaxed, **options})
    server.start()
    return server


def open_window(server, username="Alice", password="river-stone-42", home_name=None):
    root = tk.Tk()
    app = App(root, argparse.Namespace(host=f"127.0.0.1:{server.bound_port}", username=username),
              settings=Settings(f"{tmp}/{home_name or "home_" + username}"))
    app.apply_theme()
    root.update()
    app.address_visible = True
    app.address_entry.set(f"127.0.0.1:{server.bound_port}")
    app.user_entry.set(username)
    app.pass_entry.set(password)
    app.join()
    ok = wait_until(root, lambda: app.screen == "chat" and app.connection is not None)
    return root, app, ok


def finish(app, server, *peers):
    app.on_close()
    for peer in peers:
        peer.close()
    server.stop()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)
