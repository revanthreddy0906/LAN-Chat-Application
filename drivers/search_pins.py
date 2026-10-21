"""Milestone 3 GUI flows: paging, search, mentions, pins."""
from common import *  # noqa: F401,F403

server = start_server()
port = server.bound_port
bob = V2Peer(port, "Bob", "river-stone-42")
bob_row = server.store.get_user("Bob")
ids = []
for i in range(130):
    text = "banana smoothie recipe" if i == 0 else f"filler message {i}"
    ids.append(server.store.add_message(bob_row.id, text))
bob.close()
bob = V2Peer(port, "Bob", "river-stone-42")

root, app, ok = open_window(server)
check("alice signs in", ok)
check("history loaded", wait_until(root, lambda: any(r.text == "filler message 129" for r in app.messages.records)))
root.update()

check("Load earlier button at the top", app.has_more and app.messages.records[0].tone == "loadmore")
count_before = len(app.messages.records)
app.on_message_action("loadmore", app.messages.records[0])
check("older page arrives", wait_until(root, lambda: len(app.messages.records) > count_before and not app.loading_page))
chat = [r.id for r in app.messages.records if r.id]
check("no duplicate ids after paging", len(chat) == len(set(chat)))
check("ids stay ascending", chat == sorted(chat))
check("still more to load", app.has_more and app.messages.records[0].tone == "loadmore")

check("banana not loaded yet", app.messages.index_of(ids[0]) is None)
app.toggle_search()
root.update()
check("search bar visible above the chat", app.search_bar.winfo_ismapped() and app.search_bar.winfo_rooty() < app.messages.winfo_rooty())
app.search_entry.set("banana")
app._run_search()
check("search result arrives", wait_until(root, lambda: len(app.search_results) == 1 and "banana" in app.search_results[0]["snippet"]))
check("status says 1 result", "1 result" in app.search_status.cget("text"))
app._goto_message(app.search_results[0]["id"])
check("jump loads older pages until found", wait_until(root, lambda: app.messages.index_of(ids[0]) is not None, 10))
check("loadmore removed when everything is loaded", not app.has_more and all(r.tone != "loadmore" for r in app.messages.records))
check("target flashes", wait_until(root, lambda: app.messages.record_for(ids[0]).flash))
chat = [r.id for r in app.messages.records if r.id]
check("still ordered with no duplicates", chat == sorted(chat) and len(chat) == len(set(chat)))
app.search_entry.set("zzzqq")
app._run_search()
check("no results message", wait_until(root, lambda: "No messages" in app.search_status.cget("text")))
app.close_search()
root.update()
check("search closes", not app.search_bar.winfo_ismapped())

server.set_role("Alice", "admin")
check("alice is promoted", wait_until(root, lambda: app.my_role() == "admin"))
app.message_entry.set("hey @bo")
app.message_entry.entry.icursor("end")
app._update_mentions()
root.update()
check("mention chip for Bob", app._mention_names == ["Bob"] and app.mention_row.winfo_ismapped())
check("chips sit above the entry", app.mention_row.winfo_rooty() < app.message_entry.winfo_rooty())
app._on_tab(None)
check("Tab inserts the name", app.message_entry.get() == "hey @Bob " and not app.mention_row.winfo_ismapped())
app.message_entry.set("hi @eve")
app._update_mentions()
check("@everyone offered to admin", "everyone" in app._mention_names)
app.message_entry.set("")
app._hide_mentions()

bob.send(t="send", body="ping @Alice please look")
check("mention is highlighted", wait_until(root, lambda: rec(app, "ping @Alice please look") and rec(app, "ping @Alice please look").mentioned))
app.focused = False
bob.send(t="send", body="again @Alice")
check("unfocused mention marks the title", wait_until(root, lambda: app.mention_unread and "(@" in root.title()))
app.focused = True
app.mention_unread = False

mine = rec(app, "ping @Alice please look")
check("menu offers Pin", "Pin" in [i[0] for i in app.menu_for(mine)])
app.on_message_action("pin", mine, True)
check("pin bar shows", wait_until(root, lambda: app.pin_bar.winfo_ismapped() and "1 pinned" in app.pin_button.cget("text")))
check("menu now offers Unpin", "Unpin" in [i[0] for i in app.menu_for(mine)])
check("pin bar between header and chat", app.pin_bar.winfo_rooty() < app.messages.winfo_rooty())
app._open_pins()
root.update()
check("pins dialog lists it", any("ping @Alice" in t for t in texts(app._pins_window)))
app._pins_window.destroy()
app.toggle_search()
root.update()
check("search bar sits above pin bar", app.search_bar.winfo_rooty() < app.pin_bar.winfo_rooty())
app.close_search()
app.on_message_action("pin", mine, False)
check("unpin hides the bar", wait_until(root, lambda: not app.pins and not app.pin_bar.winfo_ismapped()))
finish(app, server, bob)
