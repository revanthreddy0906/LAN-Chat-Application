"""Everyday GUI flows: sign in, reply, edit, delete, react, private messages, typing, seen, theme, leave."""
from common import *  # noqa: F401,F403

server = start_server()
port = server.bound_port
root, app, ok = open_window(server)
check("alice (admin) signs in", ok)
check("header names the server and role", wait_until(root, lambda: "Studio" in app.title_label.cget("text") and "(admin)" in app.subtitle_label.cget("text")))
check("a plain test server is flagged as not encrypted", "⚠" in app.subtitle_label.cget("text"))
bob = V2Peer(port, "Bob", "river-stone-42")
check("members arrive", wait_until(root, lambda: {m.name for m in app.members} == {"Alice", "Bob"}))

bob.send(t="send", body="hello alice")
check("incoming bubble has a server id", wait_until(root, lambda: rec(app, "hello alice") and rec(app, "hello alice").id))
theirs = rec(app, "hello alice")

app.on_message_action("reply", theirs)
root.update()
check("reply chip appears above the box", app.context_chip.winfo_ismapped() and "Replying to Bob" in app.context_label.cget("text"))
app.message_entry.set("hi bob")
app.send()
check("reply bubble shows with a quote", wait_until(root, lambda: rec(app, "hi bob") and rec(app, "hi bob").reply is not None))
mine = rec(app, "hi bob")
check("reply chip clears", not app.context_chip.winfo_ismapped() and app.reply_to is None)
check("bob received the reply link", bob.until(lambda e: e["t"] == "message" and e["body"] == "hi bob")["reply_to"] == theirs.id)

app.on_message_action("edit", mine)
check("edit mode starts with the text", app.message_entry.get() == "hi bob" and app.editing is mine)
app.message_entry.set("hi bob!")
app.send()
check("edited text and label", wait_until(root, lambda: mine.text == "hi bob!" and mine.edited))

app.on_message_action("react", theirs, "\U0001F44D")
check("reaction pill appears", wait_until(root, lambda: theirs.reactions == [("\U0001F44D", ["Alice"])]))
app.on_message_action("react", theirs, "\U0001F44D")
check("toggling removes it", wait_until(root, lambda: theirs.reactions == []))

bob.send(t="typing", on=True)
check("typing indicator", wait_until(root, lambda: "Bob is typing" in app.typing_label.cget("text")))

bob.send(t="read", up_to=mine.id)
check("seen by shown under my message", wait_until(root, lambda: "Bob" in " ".join(mine.seen_by) or mine.seen_by == ["Bob"]))

app._start_private("Bob")
root.update()
check("private chip shows", app.private_chip.winfo_ismapped())
app.message_entry.set("psst")
app.send()
check("private bubble is mine and private", wait_until(root, lambda: rec(app, "psst") and rec(app, "psst").kind == "private" and rec(app, "psst").mine))
ev = bob.until(lambda e: e["t"] == "message" and e["body"] == "psst")
check("bob got it flagged private", ev["to"] == "Bob")
app._clear_private()

app.on_message_action("delete", mine)
check("delete leaves a tombstone", wait_until(root, lambda: mine.deleted))

before = app.theme_name
app.toggle_theme()
root.update()
check("theme toggles", app.theme_name != before)
app.toggle_theme()

app.open_emoji()
root.update()
check("emoji picker opens", any(isinstance(w, tk.Toplevel) for w in root.winfo_children()))
for w in root.winfo_children():
    if isinstance(w, tk.Toplevel):
        w.destroy()

server.set_role("Bob", "admin")
server.set_role("Alice", "guest")
check("role change reaches the header", wait_until(root, lambda: "(guest)" in app.subtitle_label.cget("text")))
check("guest menu: reply and react only", [i[0] for i in app.menu_for(theirs)] == ["Reply", "React"])
check("everything fits the window", all(w.winfo_width() > 1 for w in (app.typing_label, app.message_entry, app.messages)))

app.leave()
check("leaving returns home", app.screen == "home")
finish(app, server, bob)
