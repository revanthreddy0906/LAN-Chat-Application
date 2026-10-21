"""Milestone 4 and 6 GUI flows: account menu, password change, data export, saved sign-in, admin console."""
import json
import threading
from pathlib import Path
from tkinter import messagebox, simpledialog

from common import *  # noqa: F401,F403

shown = []
messagebox.showinfo = lambda *a, **k: shown.append(a)
gui_client.messagebox.showinfo = messagebox.showinfo
import gui_admin
gui_admin.messagebox.showinfo = messagebox.showinfo
gui_admin.messagebox.askyesno = lambda *a, **k: True

server = start_server()
port = server.bound_port
root, app, ok = open_window(server, "Alice", "river-stone-42")
check("alice (admin) signs in", ok)
bob = V2Peer(port, "Bob", "river-stone-42")


def keepalive():
    while True:
        time.sleep(5)
        try:
            bob.send(t="ping")
        except OSError:
            return


threading.Thread(target=keepalive, daemon=True).start()
check("a saved sign-in was issued and the password is not kept", bool(app.session_token) and app.credentials[3] == "")
check("account menu button is visible", app.menu_button.winfo_ismapped())

# ---------- admin console
app.open_admin()
console = app.admin_console
check("console opens", console is not None and console.window.winfo_exists())
check("people list fills in", wait_until(root, lambda: len(console.users_tree.get_children()) == 2))
names = [console.users_tree.item(i)["values"][0] for i in console.users_tree.get_children()]
check("both people are listed", set(names) == {"Alice", "Bob"})


def select(name):
    for item in console.users_tree.get_children():
        if console.users_tree.item(item)["values"][0] == name:
            console.users_tree.selection_set(item)
            root.update()
            return True
    return False


select("Bob")
console.role_choice.set("guest")
console.set_role()
check("role change applied on the server", wait_until(root, lambda: server.store.get_user("Bob").role == "guest"))
check("status line confirms", wait_until(root, lambda: "guest" in console.status.cget("text")))
check("list shows the new role", wait_until(root, lambda: any(console.users_tree.item(i)["values"][:2] == ["Bob", "guest"] for i in console.users_tree.get_children())))

select("Bob")
console.reset_password()
check("reset shows a one-time password", wait_until(root, lambda: bool(shown) and len(shown[-1][1].split()[-1]) >= 8))
check("bob was signed out by the reset", wait_until(root, lambda: server._online("Bob") == []))

console.users_tree.selection_set(())
console.toggle_disabled()
check("no selection asks for a person", "Choose a person" in console.status.cget("text"))
select("Alice")
console.toggle_disabled()
check("cannot disable yourself", wait_until(root, lambda: "your own account" in console.status.cget("text")))

# audit tab
console.tabs.select(console.audit_tab)
check("audit rows load", wait_until(root, lambda: len(console.audit_tree.get_children()) >= 5))
first_actions = {console.audit_tree.item(i)["values"][2] for i in console.audit_tree.get_children()}
check("audit shows role change and reset", {"role_changed", "password_reset"} <= first_actions)
console.audit_action.set("role_changed")
console.load_audit(reset=True)
check("filter narrows the list", wait_until(root, lambda: {console.audit_tree.item(i)["values"][2] for i in console.audit_tree.get_children()} == {"role_changed"}))
console.audit_action.set("")
console.verify()
check("verify says intact", wait_until(root, lambda: "intact" in console.verify_label.cget("text")))
server.store._db.execute("UPDATE audit SET target = 'edited' WHERE id = 2")
server.store._db.commit()
console.verify()
check("verify spots tampering", wait_until(root, lambda: "✗" in console.verify_label.cget("text") and "changed" in console.verify_label.cget("text")))
server.store._db.execute("UPDATE audit SET target = '' WHERE id = 2")
server.store._db.commit()

# paging
for number in range(30):
    server.audit("Alice", "demo_event", f"thing {number}")
console.audit_action.set("demo_event")
console.load_audit(reset=True)
check("first audit page", wait_until(root, lambda: len(console.audit_tree.get_children()) == 12 and console.audit_more))
console.older()
check("older page loads", wait_until(root, lambda: console.audit_stack[-1] is not None and len(console.audit_tree.get_children()) == 12))
console.newer()
check("newer returns", wait_until(root, lambda: len(console.audit_stack) == 1))
console.audit_action.set("")

# settings tab
console.tabs.select(console.settings_tab)
check("settings load", wait_until(root, lambda: console.setting_vars["max_upload_mb"].get() == "25"))
console.setting_vars["max_upload_mb"].set("7")
console.setting_vars["blocked"].set(".exe, .bat")
console.setting_vars["open_registration"].set(False)
console.save_settings()
check("settings applied on the server", wait_until(root, lambda: server.max_upload == 7 * 1024 * 1024 and not server.open_registration and server.blocked_extensions == frozenset({".exe", ".bat"})))
console.setting_vars["max_upload_mb"].set("0")
console.save_settings()
time.sleep(0.5)
wait_until(root, lambda: False, 0.5)
check("a bad value is refused by the server", server.max_upload == 7 * 1024 * 1024)
console.setting_vars["max_upload_mb"].set("7")

# add person
simpledialog.askstring = lambda *a, **k: "Carol" if "Username" in a[1] else "mountain-lake-77"
gui_admin.simpledialog.askstring = simpledialog.askstring
console.add_user()
check("add person works", wait_until(root, lambda: server.store.get_user("Carol") is not None))
console.close()
check("closing clears the handle", app.admin_console is None)

# ---------- members don't get the console
server.set_role("Bob", "admin")
server.set_role("Alice", "member")
check("alice is now a member", wait_until(root, lambda: app.my_role() == "member"))
app.open_admin()
check("members cannot open the console", app.admin_console is None)

# ---------- change password
app.change_password_dialog()
dialog = app._password_dialog
f = dialog["fields"]
f["old"].insert(0, "wrong-old"); f["new"].insert(0, "mountain-lake-77"); f["again"].insert(0, "mountain-lake-77")
app.root.update()
change_button = [b for b in app._buttons if b.cget("text") == "Change"][-1]
change_button.command()
check("wrong current password is explained", wait_until(root, lambda: "wrong" in dialog["message"].cget("text")))
f["old"].delete(0, "end"); f["old"].insert(0, "river-stone-42")
f["again"].delete(0, "end"); f["again"].insert(0, "different")
change_button.command()
check("mismatched confirmation is caught locally", "do not match" in dialog["message"].cget("text"))
f["again"].delete(0, "end"); f["again"].insert(0, "mountain-lake-77")
old_token = app.session_token
change_button.command()
check("password changes and the dialog closes", wait_until(root, lambda: app._password_dialog is None))
check("a fresh saved sign-in replaced the old one", app.session_token and app.session_token != old_token)
check("new password works on the server", server.accounts.authenticate("Alice", "mountain-lake-77")[0] == "ok")

# ---------- export
target = f"{tmp}/mine.json"
gui_client.filedialog.asksaveasfilename = lambda **k: target
app.messages.add(gui_client.Record("notice", "x"))
app._send_event({"t": "send", "body": "something to export"})
wait_until(root, lambda: rec(app, "something to export") is not None)
app.export_data()
check("export file is written", wait_until(root, lambda: Path(target).exists(), 10))
document = json.loads(Path(target).read_text())
check("export holds my account and message", document["account"]["username"] == "Alice" and any(m["text"] == "something to export" for m in document["messages"]))
check("a saved notice is shown", wait_until(root, lambda: any("was saved to" in r.text for r in app.messages.records)))

# ---------- saved sign-in survives a dropped connection
app.connection.close()
check("window notices the disconnect", wait_until(root, lambda: app.connection is None))
app.reconnect()
check("reconnect signs in again with no password", wait_until(root, lambda: app.screen == "chat" and app.connection is not None, 10))
check("history is still there after reconnecting", any(r.text == "something to export" for r in app.messages.records))
check("server saw a resumed session", "session_resumed" in [r["action"] for r in server.store.audit_rows(limit=30)])

# an expired saved sign-in goes back to the sign-in screen with a message
server.store._db.execute("UPDATE sessions SET expires_at = 1")
server.store._db.commit()
app.connection.close()
wait_until(root, lambda: app.connection is None)
app.reconnect()
check("an expired sign-in asks for the password again", wait_until(root, lambda: app.screen == "home" and "expired" in app.home_message.cget("text"), 10))
finish(app, server, bob)
