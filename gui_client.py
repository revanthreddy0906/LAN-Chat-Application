"""Tkinter GUI for LAN Chat: find a chat, join it or host one (standard library only)."""

from __future__ import annotations

import argparse
import json
import queue
import socket
import ssl
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from certs import short_fingerprint
from chat_core import (
    CertificateChanged,
    ConnectResult,
    LoginError,
    SafeSender,
    TrustDeclined,
    connect_secure,
    parse_address,
    Member,
    start_heartbeat,
    DEFAULT_PORT,
)
from discovery import FoundServer, discover, lan_address
from events import clock, decode, snippet
from gui_admin import AdminConsole
from gui_e2ee import E2EEManager
from gui_media import MediaManager
from gui_logic import (
    AWAY_AFTER_SECONDS,
    QUICK_REACTIONS,
    apply_mention,
    encryption_label,
    expire_typing,
    has_search_words,
    mention_query,
    mentions_me,
    needs_older_messages,
    pin_bar_text,
    seen_by_users,
    server_subtitle,
    should_go_away,
    should_send_typing,
    snippet_for_chip,
    suggest_mentions,
    typing_label,
    unread_title,
    wrap_fingerprint,
)
from gui_theme import PALETTES, Fonts, detect_system_theme
from gui_widgets import (
    Avatar,
    EmojiPicker,
    FlatButton,
    MessageList,
    PlaceholderEntry,
    Record,
    ScrollFrame,
    bind_click,
)
from permissions import can
from protocol import receive_message
from server import ChatServer, default_tls_context
from settings import Settings

APP_TITLE = "LAN Chat"
HISTORY_HEADER = "--- Earlier messages ---"
POLL_MS = 100
AUTO_REFRESH_MS = 6000


class App:
    def __init__(self, root: tk.Tk, defaults: argparse.Namespace, settings: Settings | None = None) -> None:
        self.root = root
        self.settings = settings or Settings()
        self.theme_name = self.settings.get("theme") or detect_system_theme()
        self.p = PALETTES[self.theme_name]
        self.f = Fonts()

        self.events: queue.Queue = queue.Queue()
        self.session = 0
        self.discovery_gen = 0
        self.searching = False
        self.closing = False
        self.screen = "home"

        self.connection: socket.socket | None = None
        self.sender: SafeSender | None = None
        self.stop = threading.Event()
        self.username = ""
        self.server_title = ""
        self.encrypted = False
        self.fingerprint: str | None = None
        self.credentials: tuple[str, int, str, str] | None = None
        self.keep_history = False
        self.hosting: ChatServer | None = None
        self.host_address = ""
        self.user_names: list[str] = []  # online (or away) members only
        self.members: list[Member] = []
        self.private_to: str | None = None
        self.unread = 0
        self.focused = True
        self.typing: dict[str, float] = {}
        self.reply_to: Record | None = None
        self.editing: Record | None = None
        self.read_marks: dict[str, int] = {}
        self.last_read = 0
        self.latest_id = 0
        self.reported_read = 0
        self.divider_added = False
        self.skip_history_notices = False
        self._members_buffer: list[Member] = []
        self._seen_id: int | None = None
        self.last_activity = time.monotonic()
        self.away = False
        self.away_after = AWAY_AFTER_SECONDS
        self._typing_sent = 0.0
        self._typing_active = False
        self._typing_idle_at = 0.0
        self.pins: list[dict] = []
        self.has_more = False
        self.loading_page = False
        self.page_buffer: list[Record] = []
        self.page_has_more = False
        self.pending_goto: int | None = None
        self.search_open = False
        self.search_req = 0
        self.search_results: list[dict] = []
        self._search_job = None
        self._pins_window: tk.Toplevel | None = None
        self._mention_ctx: tuple[int, int] | None = None
        self._mention_names: list[str] = []
        self.mention_unread = False
        self.limits: dict = {}
        self.server_host = ""
        self.server_port = 0
        self.tls_context = None
        self.media = MediaManager(self)
        self.e2ee = E2EEManager(self)
        self._private_send_busy = False
        self.session_token: str | None = None
        self.admin_console: AdminConsole | None = None
        self._password_dialog: dict | None = None

        self.servers: list[FoundServer] = []
        self.selected: tuple[str, int] | None = None
        self.address_visible = False

        self._themed: list[tuple[tk.Misc, dict[str, str]]] = []
        self._buttons: list[FlatButton] = []
        self._entries: list[PlaceholderEntry] = []

        root.title(APP_TITLE)
        root.geometry("980x660")
        root.minsize(780, 540)
        root.configure(bg=self.p["bg"])
        self._build_home(defaults)
        self._build_chat()
        self._sync_theme_icons()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.bind("<FocusIn>", self._on_focus_in)
        root.bind("<FocusOut>", self._on_focus_out)
        self.show_home()
        root.after(POLL_MS, self._poll)
        root.after(AUTO_REFRESH_MS, self._auto_refresh)
        root.after(1000, self._tick)
        for sequence in ("<Key>", "<Button>", "<Motion>"):
            root.bind_all(sequence, self._note_activity, add="+")
        for sequence in ("<Command-f>", "<Control-f>"):  # Cmd+F on a Mac, Ctrl+F elsewhere
            try:
                root.bind_all(sequence, self._shortcut_search)
            except tk.TclError:
                pass

    # ------------------------------------------------------------ helpers

    def themed(self, widget, **options):
        """Register a widget so its colors follow the theme. Options map to palette keys."""
        self._themed.append((widget, options))
        widget.configure(**{key: self.p[value] for key, value in options.items()})
        return widget

    def frame(self, parent, bg="card", **options) -> tk.Frame:
        return self.themed(tk.Frame(parent, **options), bg=bg)

    def label(self, parent, text="", bg="card", fg="text", font=None, **options) -> tk.Label:
        return self.themed(tk.Label(parent, text=text, font=font or self.f.body, **options), bg=bg, fg=fg)

    def button(self, parent, text, command, kind="primary", **options) -> FlatButton:
        button = FlatButton(parent, text, command, self.p, self.f, kind=kind, **options)
        self._buttons.append(button)
        return button

    def entry(self, parent, placeholder="", show="") -> PlaceholderEntry:
        entry = PlaceholderEntry(parent, self.p, self.f, placeholder=placeholder, show=show)
        self._entries.append(entry)
        return entry

    def card(self, parent, **options) -> tk.Frame:
        card = tk.Frame(parent, highlightthickness=1, **options)
        return self.themed(card, bg="card", highlightbackground="border")

    def apply_theme(self) -> None:
        self.p = PALETTES[self.theme_name]
        self.root.configure(bg=self.p["bg"])
        self._themed = [(w, o) for w, o in self._themed if w.winfo_exists()]
        for widget, options in self._themed:
            widget.configure(**{key: self.p[value] for key, value in options.items()})
        for button in self._buttons:
            button.set_palette(self.p)
        for entry in self._entries:
            entry.set_palette(self.p)
        self.messages.set_palette(self.p)
        self.server_scroll.set_bg(self.p["card"])
        self.users_scroll.set_bg(self.p["panel"])
        icon = "☀" if self.theme_name == "dark" else "☾"
        self.theme_home.set_text(icon)
        self.theme_chat.set_text(icon)
        self._render_servers()
        self._render_users()
        self.search_scroll.set_bg(self.p["panel"])
        self._render_search()
        self._render_pins()

    def toggle_theme(self) -> None:
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self.settings.set("theme", self.theme_name)
        self.apply_theme()

    # ------------------------------------------------------------ home screen

    def _build_home(self, defaults: argparse.Namespace) -> None:
        self.home = self.frame(self.root, bg="bg")
        center = self.frame(self.home, bg="bg")
        center.place(relx=0.5, rely=0.5, anchor="center")

        self.label(center, "LAN Chat", bg="bg", font=self.f.big_title).pack()
        self.label(center, "Chat with anyone on your Wi-Fi. Pick a chat, sign in, done.",
                   bg="bg", fg="muted").pack(pady=(2, 18))

        row = self.frame(center, bg="bg")
        row.pack()

        # left: chats on the network
        left = self.card(row, padx=18, pady=16)
        left.grid(row=0, column=0, padx=(0, 14), sticky="n")
        head = self.frame(left)
        head.pack(fill="x")
        self.label(head, "Chats on your network", font=self.f.bold).pack(side="left")
        self.button(head, "Refresh", self.refresh_servers, kind="ghost", padx=8, pady=3,
                    ghost_bg="card").pack(side="right")
        self.search_label = self.label(left, "Searching…", fg="muted", font=self.f.small)
        self.search_label.pack(anchor="w", pady=(2, 8))
        self.server_scroll = ScrollFrame(left, self.p["card"], width=340, height=240)
        self.server_scroll.pack(fill="x")
        self.server_list = self.server_scroll.inner
        self.address_toggle = self.button(left, "Enter an address instead", self.toggle_address,
                                          kind="ghost", padx=0, pady=2, ghost_bg="card")
        self.address_toggle.pack(anchor="w", pady=(10, 0))
        self.address_box = self.frame(left)
        self.address_entry = self.entry(self.address_box, "192.168.1.5  or  192.168.1.5:5050")
        self.address_entry.pack(fill="x", pady=(6, 0))
        if defaults.host:
            self.address_entry.set(defaults.host)
            self.toggle_address()

        # right: sign in
        right = self.card(row, padx=22, pady=16)
        right.grid(row=0, column=1, sticky="n")
        self.label(right, "Your account", font=self.f.bold).pack(anchor="w")
        self.label(right, "New names are created on first sign-in.", fg="muted",
                   font=self.f.small).pack(anchor="w", pady=(2, 12))
        self.user_entry = self.entry(right, "Username")
        self.user_entry.set(defaults.username or self.settings.get("username", ""))
        self.user_entry.pack(fill="x", pady=(0, 8))
        self.pass_entry = self.entry(right, "Password", show="•")
        self.pass_entry.pack(fill="x", pady=(0, 10))
        self.user_entry.bind_return(lambda _e: self.pass_entry.focus())
        self.pass_entry.bind_return(lambda _e: self.join())
        self.home_message = self.label(right, "", fg="error", font=self.f.small, wraplength=280, justify="left")
        self.home_message.pack(anchor="w", pady=(0, 6))
        self.join_button = self.button(right, "Join chat", self.join, pady=10)
        self.join_button.pack(fill="x")
        self.label(right, "or", fg="muted", font=self.f.small).pack(pady=6)
        self.host_button = self.button(right, "Host a chat", self.host, kind="secondary", pady=10)
        self.host_button.pack(fill="x")
        self.label(right, "Hosting turns this computer into a chat room\nothers on your Wi-Fi can join.",
                   fg="muted", font=self.f.tiny, justify="left").pack(anchor="w", pady=(8, 0))

        self.theme_home = self.button(self.home, "☾", self.toggle_theme, kind="ghost",
                                      padx=10, pady=4, ghost_bg="bg")
        self.theme_home.place(relx=1.0, x=-14, y=10, anchor="ne")
        self._sync_theme_icons()

    def _sync_theme_icons(self) -> None:
        icon = "☀" if self.theme_name == "dark" else "☾"
        self.theme_home.set_text(icon)
        if hasattr(self, "theme_chat"):
            self.theme_chat.set_text(icon)

    def toggle_address(self) -> None:
        self.address_visible = not self.address_visible
        if self.address_visible:
            self.address_box.pack(fill="x")
            self.address_toggle.set_text("Use the list instead")
            self.address_entry.focus()
        else:
            self.address_box.pack_forget()
            self.address_toggle.set_text("Enter an address instead")

    def set_home_message(self, text: str, error: bool = True) -> None:
        self.home_message.configure(text=text)
        self._themed = [(w, o) for w, o in self._themed if w is not self.home_message]
        self.themed(self.home_message, bg="card", fg="error" if error else "muted")

    def set_busy(self, busy: bool) -> None:
        self.join_button.set_disabled(busy)
        self.host_button.set_disabled(busy)

    def show_home(self) -> None:
        self.screen = "home"
        self.chat.pack_forget()
        self.home.pack(fill="both", expand=True)
        self.root.title(APP_TITLE)
        self.set_busy(False)
        (self.pass_entry if self.user_entry.get() else self.user_entry).focus()
        self.refresh_servers()

    # ----- discovery list

    def refresh_servers(self) -> None:
        if self.searching:
            return
        self.searching = True
        self.search_label.configure(text="Searching…")
        generation = self.discovery_gen
        threading.Thread(
            target=lambda: self.events.put(("found", generation, discover())), daemon=True
        ).start()

    def _auto_refresh(self) -> None:
        if self.closing:
            return
        if self.screen == "home":
            self.refresh_servers()
        self.root.after(AUTO_REFRESH_MS, self._auto_refresh)

    def _on_found(self, servers: list[FoundServer]) -> None:
        self.searching = False
        self.servers = servers
        keys = {(s.host, s.port) for s in servers}
        if self.selected not in keys:
            self.selected = (servers[0].host, servers[0].port) if len(servers) == 1 else None
        count = len(servers)
        self.search_label.configure(
            text=(f"{count} chat{'s' if count != 1 else ''} found" if count else "No chats found yet"))
        self._render_servers()

    def _render_servers(self) -> None:
        for child in self.server_list.winfo_children():
            child.destroy()
        p = self.p
        if not self.servers:
            tk.Label(self.server_list, text="Nothing here yet.\n\nAsk a friend to start a chat, or click\n"
                     "“Host a chat” to create your own.", bg=p["card"], fg=p["muted"],
                     font=self.f.small, justify="left").pack(anchor="w", pady=6)
            return
        for server in self.servers:
            chosen = self.selected == (server.host, server.port)
            bg = p["selected"] if chosen else p["card"]
            card = tk.Frame(self.server_list, bg=bg, highlightthickness=1,
                            highlightbackground=p["accent"] if chosen else p["border"], padx=12, pady=8)
            card.pack(fill="x", pady=(0, 6))
            tk.Label(card, text=server.name, bg=bg, fg=p["text"], font=self.f.bold).pack(anchor="w")
            tk.Label(card, text=server_subtitle(server.host, server.port, server.users),
                     bg=bg, fg=p["muted"], font=self.f.small).pack(anchor="w")
            lock = ("\U0001F512 " if server.tls else "⚠ ") + encryption_label(server.tls)
            tk.Label(card, text=lock, bg=bg, fg=p["join"] if server.tls else p["leave"],
                     font=self.f.tiny).pack(anchor="w")
            bind_click(card, lambda _e, s=server: self._select_server(s))
            for widget in (card, *card.winfo_children()):
                widget.bind("<Double-Button-1>", lambda _e, s=server: (self._select_server(s), self.join()))

    def _select_server(self, server: FoundServer) -> None:
        self.selected = (server.host, server.port)
        self._render_servers()

    # ----- sign in / host

    def _read_form(self):
        username, password = self.user_entry.get().strip(), self.pass_entry.get()
        if not username or not password:
            self.set_home_message("Enter a username and password.")
            return None
        return username, password

    def join(self) -> None:
        form = self._read_form()
        if form is None:
            return
        username, password = form
        if self.address_visible and self.address_entry.get().strip():
            host, port = parse_address(self.address_entry.get(), DEFAULT_PORT)
            title = f"{host}:{port}"
        elif self.selected is not None:
            host, port = self.selected
            found = next((s for s in self.servers if (s.host, s.port) == self.selected), None)
            title = found.name if found else f"{host}:{port}"
        else:
            self.set_home_message("Pick a chat from the list, or enter an address.")
            return
        self.server_title = title
        self.connect(host, port, username, password)

    def host(self) -> None:
        form = self._read_form()
        if form is None:
            return
        username, password = form
        tls_context, fingerprint = default_tls_context()
        server = ChatServer(
            "0.0.0.0", None, tls_context=tls_context, quiet=True, discovery=True,
            display_name=f"{username}'s chat",
        )
        try:
            server.start()
        except OSError as error:
            self.set_home_message(f"Could not start hosting: {error.strerror or error}")
            return
        self.hosting = server
        self.fingerprint = fingerprint
        self.host_address = f"{lan_address()}:{server.bound_port}"
        self.server_title = server.display_name
        self.connect("127.0.0.1", server.bound_port, username, password, hosting=True)

    def _stop_hosting(self) -> None:
        server, self.hosting = self.hosting, None
        if server is not None:
            server.stop()

    # ------------------------------------------------------------ connecting

    def connect(self, host, port, username, password, hosting=False, keep_history=False, token=None) -> None:
        self.session += 1
        session = self.session
        self.credentials = (host, port, username, "")  # the password is not kept; a saved sign-in is
        self.e2ee.remember_password(password)  # only until the welcome, to unlock keys that share it
        if not keep_history:
            self.session_token = None
        self.keep_history = keep_history
        self.set_home_message("Connecting…", error=False)
        self.set_busy(True)
        threading.Thread(
            target=self._connect_worker,
            args=(session, host, port, username, password, hosting, token),
            daemon=True,
        ).start()

    def _connect_worker(self, session, host, port, username, password, hosting, token=None) -> None:
        def ask(kind, *args) -> bool:
            answer: queue.Queue = queue.Queue(maxsize=1)
            self.events.put(("confirm", session, (kind, args, answer)))
            try:
                return answer.get(timeout=300)
            except queue.Empty:
                return False

        def fail(message: str) -> None:
            self.events.put(("connect_error", session, message))

        try:
            result = connect_secure(
                host, port, username, password, self.settings,
                confirm_trust=(lambda *_a: True) if hosting else (lambda fp, h, p: ask("trust", fp, h, p)),
                confirm_plain=(lambda *_a: True) if hosting else (lambda h, p: ask("plain", h, p)),
                protocol=2, token=token,
            )
        except TrustDeclined as error:
            fail(str(error))
        except CertificateChanged as error:
            fail(f"WARNING: {error}")
        except LoginError as error:
            fail(f"Sign-in failed: {error}")
        except ssl.SSLError as error:
            fail(f"Secure connection failed: {error}")
        except OSError as error:
            fail(f"Could not connect: {error.strerror or error}")
        else:
            self.events.put(("connected", session, (result, host, port, username)))

    def _handle_confirm(self, kind: str, args: tuple, answer: queue.Queue) -> None:
        if kind == "trust":
            fingerprint, host, port = args
            ok = messagebox.askyesno(
                "Trust this chat server?",
                f"This is your first time connecting to {host}:{port}.\n\n"
                f"Its security fingerprint is:\n\n{wrap_fingerprint(fingerprint)}\n\n"
                "Check that it matches the fingerprint shown on the host's screen.\n\n"
                "Trust it and continue?",
                parent=self.root,
            )
        else:
            host, port = args
            ok = messagebox.askyesno(
                "This chat is not encrypted",
                f"{host}:{port} does not use encryption, so passwords and messages can be "
                "read by anyone on the network.\n\nContinue anyway?",
                icon="warning", parent=self.root,
            )
        answer.put(ok)

    def _on_connect_error(self, message: str) -> None:
        self._stop_hosting()
        self.set_busy(False)
        self.set_home_message(message)

    def _on_connected(self, result: ConnectResult, host: str, port: int, username: str) -> None:
        self.connection = result.connection
        self.sender = SafeSender(result.connection)
        self.username = username
        self.encrypted = result.encrypted
        self.server_host, self.server_port, self.tls_context = host, port, result.context
        self.media.reset()
        if result.fingerprint:
            self.fingerprint = result.fingerprint
        self.stop = threading.Event()
        self.private_to = None
        self.reply_to = None
        self.editing = None
        self.unread = 0
        self.typing.clear()
        self.read_marks = {}
        self.away = False
        self.last_activity = time.monotonic()
        self.settings.set("username", username)
        self.settings.set("last_server", f"{host}:{port}")
        threading.Thread(
            target=self._receiver, args=(self.session, result.connection, self.stop), daemon=True
        ).start()
        start_heartbeat(self.sender, self.stop, message=json.dumps({"t": "ping"}))
        if not self.keep_history:
            self.messages.clear()
        self.pass_entry.clear()
        self.set_home_message("", error=False)
        self.show_chat()
        self.set_composer_enabled(True)
        self.banner.pack_forget()
        self._update_header()
        self._update_private_chip()
        self._update_context_chip()
        self._refresh_typing()

    def _receiver(self, session: int, connection: socket.socket, stop: threading.Event) -> None:
        try:
            while not stop.is_set():
                message = receive_message(connection)
                if message is None:
                    break
                self.events.put(("message", session, message))
        except (OSError, ValueError):
            pass
        finally:
            self.events.put(("closed", session, None))

    # ------------------------------------------------------------ event loop

    def _poll(self) -> None:
        try:
            while True:
                kind, tag, payload = self.events.get_nowait()
                if kind == "found":
                    if tag == self.discovery_gen:
                        self._on_found(payload)
                    continue
                if tag != self.session:
                    if kind == "confirm":
                        payload[2].put(False)
                    elif kind == "connected":
                        payload[0].connection.close()
                    continue
                self._handle_event(kind, payload)
        except queue.Empty:
            pass
        if not self.closing:
            self.root.after(POLL_MS, self._poll)

    def _handle_event(self, kind: str, payload) -> None:
        if kind == "confirm":
            self._handle_confirm(*payload)
        elif kind == "connect_error":
            self._on_connect_error(payload)
        elif kind == "connected":
            self._on_connected(*payload)
        elif kind == "message":
            self._on_message(payload)
        elif kind == "media":
            self.media.handle(payload)
        elif kind == "closed":
            self._on_disconnected()

    # ------------------------------------------------------------ chat screen

    def _build_chat(self) -> None:
        self.chat = self.frame(self.root, bg="bg")

        header = self.frame(self.chat, bg="panel", padx=18, pady=10)
        header.pack(fill="x")
        titles = self.frame(header, bg="panel")
        titles.pack(side="left")
        self.title_label = self.label(titles, "", bg="panel", font=self.f.title)
        self.title_label.pack(anchor="w")
        self.subtitle_label = self.label(titles, "", bg="panel", fg="muted", font=self.f.small)
        self.subtitle_label.pack(anchor="w")
        actions = self.frame(header, bg="panel")
        actions.pack(side="right")
        self.search_button = self.button(actions, "\U0001F50E", self.toggle_search, kind="ghost", padx=10, pady=5)
        self.search_button.pack(side="left", padx=(0, 6))
        self.menu_button = self.button(actions, "⋯", self.show_account_menu, kind="ghost", padx=10, pady=5)
        self.menu_button.pack(side="left", padx=(0, 6))
        self.theme_chat = self.button(actions, "☾", self.toggle_theme, kind="ghost", padx=10, pady=5)
        self.theme_chat.pack(side="left", padx=(0, 6))
        self.leave_button = self.button(actions, "Leave", self.leave, kind="secondary", pady=6)
        self.leave_button.pack(side="left")
        self.header_sep = self.themed(tk.Frame(self.chat, height=1), bg="border")
        self.header_sep.pack(fill="x")

        self.host_bar = self.frame(self.chat, bg="selected", padx=18, pady=6)
        self.host_label = self.label(self.host_bar, "", bg="selected", font=self.f.small)
        self.host_label.pack(side="left")
        self.copy_button = self.button(self.host_bar, "Copy address", self.copy_address, kind="ghost",
                                       padx=10, pady=2, ghost_bg="selected")
        self.copy_button.pack(side="right")

        self.search_bar = self.frame(self.chat, bg="panel", padx=18, pady=8)
        search_top = self.frame(self.search_bar, bg="panel")
        search_top.pack(fill="x")
        self.search_entry = self.entry(search_top, "Search messages  (Cmd/Ctrl+F)")
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.entry.bind("<KeyRelease>", self._on_search_key)
        self.button(search_top, "Close", self.close_search, kind="ghost", padx=10, pady=4).pack(side="left", padx=(8, 0))
        self.search_status = self.label(self.search_bar, "", bg="panel", fg="muted", font=self.f.small, anchor="w")
        self.search_status.pack(fill="x", pady=(4, 0))
        self.search_scroll = ScrollFrame(self.search_bar, self.p["panel"], height=170)

        self.pin_bar = self.frame(self.chat, bg="pill_bg", padx=18, pady=5)
        self.pin_label = self.label(self.pin_bar, "", bg="pill_bg", fg="text", font=self.f.small, anchor="w",
                                    cursor="hand2")
        self.pin_label.pack(side="left", fill="x", expand=True)
        self.pin_label.bind("<Button-1>", lambda _e: self.pins and self._goto_message(self.pins[0]["id"]))
        self.pin_button = self.button(self.pin_bar, "", self._open_pins, kind="ghost", padx=10, pady=2,
                                      ghost_bg="pill_bg")
        self.pin_button.pack(side="right")

        body = self.body_frame = self.frame(self.chat, bg="panel")
        body.pack(fill="both", expand=True)

        side = self.frame(body, bg="panel", padx=14, pady=14, width=230)
        side.pack(side="right", fill="y")
        side.pack_propagate(False)
        self.online_label = self.label(side, "MEMBERS", bg="panel", fg="muted", font=self.f.small_bold)
        self.online_label.pack(anchor="w", pady=(0, 8))
        self.users_scroll = ScrollFrame(side, self.p["panel"])
        self.users_scroll.pack(fill="both", expand=True)
        self.users_frame = self.users_scroll.inner
        self.label(side, "Click a name to send\na private message.", bg="panel", fg="muted",
                   font=self.f.tiny, justify="left").pack(anchor="w", side="bottom")
        self.themed(tk.Frame(body, width=1), bg="border").pack(side="right", fill="y")

        main = self.frame(body, bg="panel")
        main.pack(side="left", fill="both", expand=True)
        self.messages = MessageList(
            main, self.p, self.f, on_action=self.on_message_action, menu_for=self.menu_for,
            me=lambda: self.username, on_bottom=self._report_read,
        )

        self.banner = self.frame(main, bg="leave", padx=14, pady=6)
        self.label(self.banner, "You were disconnected from the chat.", bg="leave", fg="accent_text",
                   font=self.f.small_bold).pack(side="left")
        self.reconnect_button = self.button(self.banner, "Reconnect", self.reconnect, kind="secondary",
                                            padx=10, pady=2)
        self.reconnect_button.pack(side="right")

        composer = self.composer = self.frame(main, bg="panel", padx=14, pady=10)
        composer.pack(side="bottom", fill="x")
        self.typing_label = self.label(composer, " ", bg="panel", fg="muted", font=self.f.small, anchor="w")
        self.typing_label.pack(fill="x")
        self.messages.pack(fill="both", expand=True)
        self.private_chip = self.frame(composer, bg="bubble_private", padx=10, pady=4)
        self.private_label = self.label(self.private_chip, "", bg="bubble_private", fg="bubble_private_text",
                                        font=self.f.small_bold)
        self.private_label.pack(side="left")
        close = self.label(self.private_chip, "  ✕", bg="bubble_private", fg="bubble_private_text",
                           font=self.f.small_bold, cursor="hand2")
        close.pack(side="left")
        close.bind("<Button-1>", lambda _e: self._clear_private())

        self.context_chip = self.frame(composer, bg="selected", padx=10, pady=4)
        self.context_label = self.label(self.context_chip, "", bg="selected", fg="text", font=self.f.small)
        self.context_label.pack(side="left")
        context_close = self.label(self.context_chip, "  ✕", bg="selected", fg="text",
                                   font=self.f.small_bold, cursor="hand2")
        context_close.pack(side="left")
        context_close.bind("<Button-1>", lambda _e: self._cancel_context())

        self.mention_row = self.frame(composer, bg="panel")

        row = self.composer_row = self.frame(composer, bg="panel")
        row.pack(fill="x", pady=(4, 0))
        self.emoji_button = self.button(row, "\U0001F60A", self.open_emoji, kind="ghost", padx=8, pady=4)
        self.emoji_button.pack(side="left", padx=(0, 4))
        self.attach_button = self.button(row, "\U0001F4CE", self.attach_file, kind="ghost", padx=8, pady=4)
        self.attach_button.pack(side="left", padx=(0, 4))
        self.record_button = self.button(row, "\U0001F3A4", self.toggle_recording, kind="ghost", padx=8, pady=4)
        if self.media.recorder is not None:  # voice messages need the optional sounddevice package
            self.record_button.pack(side="left", padx=(0, 4))
        row_gap = self.frame(row, bg="panel", width=4)
        row_gap.pack(side="left")
        self.send_button = self.button(row, "Send", self.send, pady=8)
        self.send_button.pack(side="right", padx=(8, 0))
        self.message_entry = self.entry(row, "Message everyone…   (/help for commands)")
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind_return(self.send)
        self.message_entry.entry.bind("<KeyRelease>", self._on_key)
        self.message_entry.entry.bind("<Escape>", lambda _e: self._cancel_context() or "break")
        self.message_entry.entry.bind("<Up>", self._on_up)
        self.message_entry.entry.bind("<Tab>", self._on_tab)

    def show_chat(self) -> None:
        self.screen = "chat"
        self.home.pack_forget()
        self.chat.pack(fill="both", expand=True)
        self.root.title(unread_title(APP_TITLE, self.unread, self.mention_unread))
        self.message_entry.focus()
        if self.hosting is not None:
            self.host_label.configure(
                text=f"Hosting · others join with {self.host_address} · "
                     f"fingerprint {short_fingerprint(self.fingerprint, 4) if self.fingerprint else 'none'}"
                     f" · leaving ends the chat for everyone")
            self.host_bar.pack(fill="x", after=self.header_sep)
            self.leave_button.set_text("Stop hosting")
        else:
            self.host_bar.pack_forget()
            self.leave_button.set_text("Leave")

    def my_role(self) -> str:
        return next((m.role for m in self.members if m.name.lower() == self.username.lower()), "")

    def _update_header(self) -> None:
        self.title_label.configure(text=self.server_title or "LAN Chat")
        online = len(self.user_names)
        lock = "\U0001F512 " if self.encrypted else "⚠ "
        role = self.my_role()
        self.subtitle_label.configure(
            text=f"{lock}{encryption_label(self.encrypted)} · {online} online · "
                 f"signed in as {self.username}" + (f" ({role})" if role else "")
                 + (f" · {self.e2ee.label()}" if self.e2ee.label() else ""))
        self._update_private_chip()  # the chip above the box shows the room's lock state too

    def set_composer_enabled(self, enabled: bool) -> None:
        self.message_entry.set_enabled(enabled)
        self.send_button.set_disabled(not enabled)
        self.emoji_button.set_disabled(not enabled)
        self.attach_button.set_disabled(not enabled)
        self.record_button.set_disabled(not enabled)

    # ----- users sidebar

    def _set_members(self, members: list[Member]) -> None:
        """Everyone with an account: online (or away) ones first, then offline."""
        self.members = sorted(members, key=lambda m: (not m.online, m.name.lower()))
        self.user_names = [m.name for m in self.members if m.online]
        if self.private_to and self.private_to.lower() not in {m.name.lower() for m in members}:
            self._clear_private()
        self._render_users()
        self._update_header()

    def _render_users(self) -> None:
        for child in self.users_frame.winfo_children():
            child.destroy()
        p = self.p
        online = [m for m in self.members if m.online]
        offline = [m for m in self.members if not m.online]
        for title, group in (("ONLINE", online), ("OFFLINE", offline)):
            if not group:
                continue
            tk.Label(self.users_frame, text=f"{title} · {len(group)}", bg=p["panel"], fg=p["muted"],
                     font=self.f.tiny).pack(anchor="w", pady=(8, 2))
            for member in group:
                self._member_row(member)

    def _member_row(self, member: Member) -> None:
        p = self.p
        mine = member.name.lower() == self.username.lower()
        chosen = self.private_to is not None and member.name.lower() == self.private_to.lower()
        bg = p["selected"] if chosen else p["panel"]
        row = tk.Frame(self.users_frame, bg=bg, padx=6, pady=5)
        row.pack(fill="x", pady=1)
        Avatar(row, member.name, 28, bg, self.f.tiny,
               presence=member.status or ("online" if member.online else "offline")).pack(side="left")
        tk.Label(row, text=member.name, bg=bg, fg=p["text"] if member.online else p["muted"],
                 font=self.f.body).pack(side="left", padx=(8, 0))
        badge = self.e2ee.badge(member.name)
        if badge:
            tk.Label(row, text=badge, bg=bg, fg=p["error"] if badge == "⚠" else p["join"],
                     font=self.f.small_bold).pack(side="left", padx=(4, 0))
        if member.role != "member":
            color = p["accent"] if member.role == "admin" else p["leave"]
            tk.Label(row, text=member.role, bg=bg, fg=color, font=self.f.tiny).pack(side="left", padx=(6, 0))
        if mine:
            tk.Label(row, text="you", bg=bg, fg=p["muted"], font=self.f.tiny).pack(side="left", padx=(6, 0))
        else:
            bind_click(row, lambda _e, n=member.name: self._start_private(n))
            row.configure(cursor="hand2")
            for sequence in ("<Button-2>", "<Button-3>", "<Control-Button-1>"):
                self._bind_tree(row, sequence, lambda event, n=member.name: self._member_menu(event, n))

    def _bind_tree(self, widget: tk.Misc, sequence: str, callback) -> None:
        widget.bind(sequence, callback)
        for child in widget.winfo_children():
            self._bind_tree(child, sequence, callback)

    def _member_menu(self, event, name: str) -> None:
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"Message {name} privately", command=lambda: self._start_private(name))
        menu.add_command(label="Verify security code…", command=lambda: self.e2ee.open_verify(name))
        menu.tk_popup(event.x_root, event.y_root)

    # ----- private mode

    def _start_private(self, name: str) -> None:
        self.private_to = None if (self.private_to or "").lower() == name.lower() else name
        if self.private_to:
            self.e2ee.ensure_contacts([self.private_to], self._update_private_chip)
        self._update_private_chip()
        self._render_users()
        self.message_entry.focus()

    def _clear_private(self) -> None:
        self.private_to = None
        self._update_private_chip()
        self._render_users()

    def _update_private_chip(self) -> None:
        if self.private_to:
            self.private_label.configure(text=self.e2ee.private_label(self.private_to))
            self.private_chip.pack(anchor="w", before=self.composer_row)
        elif self.e2ee.room_active():
            self.private_label.configure(text=self.e2ee.room_label())
            self.private_chip.pack(anchor="w", before=self.composer_row)
        else:
            self.private_chip.pack_forget()

    def _update_context_chip(self) -> None:
        if self.editing is not None:
            self.context_label.configure(text="✎ Editing your message  (Esc to cancel)")
        elif self.reply_to is not None:
            quoted = snippet_for_chip(self.reply_to.text, self.reply_to.deleted)
            self.context_label.configure(text=f"↩ Replying to {self.reply_to.name or 'message'}: {quoted}")
        else:
            self.context_chip.pack_forget()
            return
        self.context_chip.pack(anchor="w", before=self.composer_row)

    def _clear_context(self) -> None:
        self.reply_to = None
        self.editing = None
        self._update_context_chip()

    def _cancel_context(self) -> bool:
        self._hide_mentions()
        had_context = self.editing is not None or self.reply_to is not None
        if self.editing is not None:
            self.message_entry.clear()
        self._clear_context()
        return had_context

    def _start_reply(self, record: Record) -> None:
        if record.id is None or record.deleted:
            return
        self.editing = None
        self.reply_to = record
        self.private_to = record.name if record.kind == "private" else None
        self._update_private_chip()
        self._update_context_chip()
        self._render_users()
        self.message_entry.focus()

    def _start_edit(self, record: Record) -> None:
        if record.id is None or record.deleted or not record.mine:
            return
        self.reply_to = None
        self.editing = record
        self.message_entry.set(record.text)
        self._update_context_chip()
        self.message_entry.focus()

    def _on_up(self, _event) -> str | None:
        if self.message_entry.get() == "" and self.editing is None:
            record = self.messages.last_own()
            if record is not None:
                self._start_edit(record)
                return "break"
        return None

    # ----- search

    def _place_bars(self) -> None:
        """The search and pinned bars sit between the header and the chat, search on top."""
        for bar in (self.search_bar, self.pin_bar):
            bar.pack_forget()
        if self.search_open:
            self.search_bar.pack(fill="x", before=self.body_frame)
        if self.pins:
            self.pin_bar.pack(fill="x", before=self.body_frame)

    def toggle_search(self) -> None:
        if self.search_open:
            self.close_search()
            return
        self.search_open = True
        self._place_bars()
        self.search_entry.focus()

    def close_search(self) -> None:
        if self._search_job is not None:
            self.root.after_cancel(self._search_job)
            self._search_job = None
        self.search_open = False
        self.search_entry.clear()
        self.search_results = []
        self.search_req += 1  # any reply still on its way is now ignored
        self._render_search()
        self._place_bars()
        if self.screen == "chat":
            self.message_entry.focus()

    def _shortcut_search(self, _event=None):
        if self.screen != "chat" or self.sender is None:
            return None
        if self.search_open:
            self.search_entry.focus()
        else:
            self.toggle_search()
        return "break"

    def _on_search_key(self, event) -> None:
        if event.keysym == "Escape":
            self.close_search()
            return
        if self._search_job is not None:
            self.root.after_cancel(self._search_job)
        self._search_job = self.root.after(250, self._run_search)

    def _run_search(self) -> None:
        self._search_job = None
        query = self.search_entry.get().strip()
        self.search_req += 1
        if not has_search_words(query):
            self.search_results = []
            self._render_search()
            return
        self.search_status.configure(text="Searching…")
        self._send_event({"t": "search", "q": query, "req": self.search_req})

    def _render_search(self) -> None:
        for child in self.search_scroll.inner.winfo_children():
            child.destroy()
        query = self.search_entry.get().strip()
        if not has_search_words(query):
            self.search_status.configure(text="")
            self.search_scroll.pack_forget()
            return
        results, p = self.search_results, self.p
        if not results:
            self.search_status.configure(text="No messages found")
            self.search_scroll.pack_forget()
            return
        self.search_status.configure(text=f"{len(results)} result{'' if len(results) == 1 else 's'}")
        self.search_scroll.pack(fill="x", pady=(6, 0))
        for result in results:
            card = tk.Frame(self.search_scroll.inner, bg=p["card"], highlightthickness=1,
                            highlightbackground=p["border"], padx=10, pady=6, cursor="hand2")
            card.pack(fill="x", pady=(0, 4))
            who = result["sender"] + (f" → {result['to']}  \U0001F512" if result.get("to") else "")
            tk.Label(card, text=f"{who} · {clock(result['ts'])}", bg=p["card"], fg=p["muted"],
                     font=self.f.tiny).pack(anchor="w")
            tk.Label(card, text=result["snippet"], bg=p["card"], fg=p["text"], font=self.f.small,
                     justify="left", wraplength=620, anchor="w").pack(anchor="w")
            bind_click(card, lambda _e, i=result["id"]: self._goto_message(i))

    def _ev_search_results(self, event: dict) -> None:
        if event.get("req") != self.search_req:
            return  # an older search that was already replaced
        found = event.get("results", [])
        seen = {r["id"] for r in found}
        local = [r for r in self.e2ee.search_local(self.search_entry.get()) if r["id"] not in seen]
        self.search_results = sorted(found + local, key=lambda r: r["ts"], reverse=True)[:40]
        self._render_search()

    # ----- pinned messages

    def _render_pins(self) -> None:
        if self.pins:
            self.pin_label.configure(text=pin_bar_text([self._pin_view(p) for p in self.pins]))
            self.pin_button.set_text(f"{len(self.pins)} pinned")
        self._place_bars()

    def _pin_view(self, pin: dict) -> dict:
        """A pinned message as shown: encrypted ones have no text on the server, so use what this window decrypted."""
        if pin.get("snippet"):
            return pin
        record = self.messages.record_for(pin["id"])
        if record is not None and record.secure == "e2ee" and record.text:
            return {**pin, "snippet": snippet(record.text)}
        return {**pin, "snippet": "\U0001F512 Encrypted message"}

    def _ev_pins(self, event: dict) -> None:
        self.pins = event.get("pins", [])
        self._render_pins()
        if self._pins_window is not None and self._pins_window.winfo_exists():
            self._fill_pins_window()

    def _can_unpin(self, pin: dict) -> bool:
        role = self.my_role() or "member"
        return can(role, "pin_any") or (pin["sender"].lower() == self.username.lower() and can(role, "pin_own"))

    def _open_pins(self) -> None:
        if self._pins_window is not None and self._pins_window.winfo_exists():
            self._pins_window.lift()
            return
        window = self._pins_window = tk.Toplevel(self.root)
        window.title("Pinned messages")
        window.configure(bg=self.p["bg"])
        window.geometry("480x380")
        window.transient(self.root)
        self._pins_holder = ScrollFrame(window, self.p["bg"], width=460, height=340)
        self._pins_holder.pack(fill="both", expand=True, padx=10, pady=10)
        self._fill_pins_window()

    def _fill_pins_window(self) -> None:
        p = self.p
        for child in self._pins_holder.inner.winfo_children():
            child.destroy()
        if not self.pins:
            tk.Label(self._pins_holder.inner, text="Nothing is pinned.", bg=p["bg"], fg=p["muted"],
                     font=self.f.body).pack(pady=20)
            return
        for pin in self.pins:
            card = tk.Frame(self._pins_holder.inner, bg=p["card"], highlightthickness=1,
                            highlightbackground=p["border"], padx=10, pady=8)
            card.pack(fill="x", pady=(0, 6))
            text = tk.Frame(card, bg=p["card"], cursor="hand2")
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=f"{pin['sender']} · {clock(pin['ts'])}", bg=p["card"], fg=p["muted"],
                     font=self.f.tiny).pack(anchor="w")
            tk.Label(text, text=self._pin_view(pin)["snippet"], bg=p["card"], fg=p["text"], font=self.f.small,
                     justify="left", wraplength=300, anchor="w").pack(anchor="w")
            bind_click(text, lambda _e, i=pin["id"]: self._jump_from_pins(i))
            if self._can_unpin(pin):
                FlatButton(card, "Unpin", lambda i=pin["id"]: self._send_event({"t": "pin", "id": i, "on": False}),
                           p, self.f, kind="ghost", padx=10, pady=3, ghost_bg="card").pack(side="right")

    def _jump_from_pins(self, message_id: int) -> None:
        if self._pins_window is not None and self._pins_window.winfo_exists():
            self._pins_window.destroy()
        self._goto_message(message_id)

    # ----- older messages and jumping to a message

    def _load_older(self) -> None:
        if self.loading_page or not self.has_more or self.sender is None:
            return
        oldest = self.messages.oldest_id()
        if oldest is None:
            return
        self.loading_page = True
        self._send_event({"t": "history", "before": oldest, "limit": 50})

    def _goto_message(self, message_id: int) -> None:
        """Scroll to a message, first loading older pages if it is not on screen yet."""
        if self.messages.index_of(message_id) is not None:
            self.pending_goto = None
            self.messages.scroll_to_record(message_id)
            self.messages.flash_record(message_id)
            return
        if needs_older_messages(message_id, self.messages.oldest_id(), self.has_more):
            self.pending_goto = message_id
            self._load_older()
            return
        self.pending_goto = None
        self.messages.add(Record("notice", "That message is no longer available.", tone="error"))

    def _ev_page_start(self, event: dict) -> None:
        self.page_buffer = []
        self.page_has_more = bool(event.get("has_more"))

    def _ev_page_end(self, event: dict) -> None:
        older, self.page_buffer = self.page_buffer, []
        current = [r for r in self.messages.records if r.tone != "loadmore" and r.text != HISTORY_HEADER]
        had_header = any(r.text == HISTORY_HEADER for r in self.messages.records)
        anchor = self.messages.oldest_id()
        prefix: list[Record] = []
        if self.page_has_more:
            prefix.append(Record("notice", "Load earlier messages", tone="loadmore"))
        if had_header:
            prefix.append(Record("notice", HISTORY_HEADER, tone="system"))
        self.messages.set_records(prefix + older + current, anchor_id=anchor)
        self.has_more = self.page_has_more
        self.loading_page = False
        if self.pending_goto is not None:
            target = self.pending_goto
            self.root.after_idle(lambda: self._goto_message(target))

    # ----- @mentions

    def _hide_mentions(self) -> None:
        self._mention_ctx = None
        self._mention_names = []
        for child in self.mention_row.winfo_children():
            child.destroy()
        self.mention_row.pack_forget()

    def _update_mentions(self) -> None:
        text = self.message_entry.get()
        cursor = self.message_entry.entry.index("insert")
        found = mention_query(text, cursor) if self.editing is None else None
        names: list[str] = []
        if found is not None:
            names = suggest_mentions(
                found[1], [m.name for m in self.members], self.username,
                can(self.my_role() or "member", "mention_everyone"),
            )
        if not names:
            self._hide_mentions()
            return
        self._mention_ctx = (found[0], cursor)
        self._mention_names = names
        for child in self.mention_row.winfo_children():
            child.destroy()
        p = self.p
        tk.Label(self.mention_row, text="Mention (Tab):", bg=p["panel"], fg=p["muted"],
                 font=self.f.small).pack(side="left", padx=(0, 6))
        for name in names:
            chip = tk.Label(self.mention_row, text=f"@{name}", bg=p["selected"], fg=p["accent"],
                            font=self.f.small_bold, padx=8, pady=2, cursor="hand2")
            chip.pack(side="left", padx=(0, 4))
            chip.bind("<Button-1>", lambda _e, n=name: self._insert_mention(n))
        self.mention_row.pack(anchor="w", before=self.composer_row)

    def _insert_mention(self, name: str) -> None:
        if self._mention_ctx is None:
            return
        start, cursor = self._mention_ctx
        text, new_cursor = apply_mention(self.message_entry.get(), start, cursor, name)
        self.message_entry.set(text)
        self.message_entry.entry.icursor(new_cursor)
        self._hide_mentions()
        self.message_entry.focus()

    def _on_tab(self, _event) -> str | None:
        if self._mention_names:
            self._insert_mention(self._mention_names[0])
            return "break"
        return None

    # ----- sending

    def _send_event(self, event: dict) -> bool:
        if self.sender is None:
            return False
        try:
            self.sender.send_event(event)
        except ValueError:
            self.messages.add(Record("notice", "Error: message too long.", tone="error"))
            return False
        except OSError:
            self._on_disconnected()
            return False
        return True

    def send(self, _event=None):
        text = self.message_entry.get().strip()
        if not text or self.sender is None:
            return "break"
        if text.lower() in ("/quit", "/exit"):
            self.message_entry.clear()
            self.leave()
            return "break"
        if self.editing is not None:
            if self.editing.secure == "e2ee" and self.editing.kind == "chat":  # a room message
                if not self._private_send_busy:
                    self._private_send_busy = True
                    self.e2ee.edit_room(self.editing, text, self._private_send_done)
                return "break"
            if self.editing.secure == "e2ee":
                event = self.e2ee.edit_event(self.editing, text)
                if event is None:
                    return "break"
            else:
                event = {"t": "edit", "id": self.editing.id, "body": text}
        elif self.e2ee.room_active() and not self.private_to and not text.startswith("/"):
            if not self._private_send_busy:
                self._private_send_busy = True
                self.e2ee.send_room(text, self.reply_to.id if self.reply_to else None, self._private_send_done)
            return "break"
        elif self.private_to and not text.startswith("/"):
            if not self._private_send_busy:
                self._private_send_busy = True
                self.e2ee.send_private(text, self.private_to, self.reply_to.id if self.reply_to else None,
                                       self._private_send_done)
            return "break"
        else:
            event = {"t": "send", "body": text}
            if not text.startswith("/") and self.reply_to is not None:
                event["reply_to"] = self.reply_to.id
        if self._send_event(event):
            self._after_sent()
        return "break"

    def _after_sent(self) -> None:
        self.message_entry.clear()
        self._stop_typing()
        self._clear_context()
        self._hide_mentions()

    def _private_send_done(self, event: dict | None) -> None:
        """The encryption step finished: `event` is what to send (encrypted or plain), or None if it was refused."""
        self._private_send_busy = False
        if event is not None and self._send_event(event):
            self._after_sent()

    # ----- account menu, password, data export, admin console

    def show_account_menu(self) -> None:
        if self.sender is None:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Change password…", command=self.change_password_dialog)
        menu.add_command(label="Encryption keys…", command=self.e2ee.open_keys)
        menu.add_command(label="Download my data…", command=self.export_data)
        if can(self.my_role() or "member", "manage_users"):
            menu.add_separator()
            menu.add_command(label="Admin console…", command=self.open_admin)
        x = self.menu_button.winfo_rootx()
        y = self.menu_button.winfo_rooty() + self.menu_button.winfo_height()
        menu.tk_popup(x, y)

    def open_admin(self) -> None:
        if not can(self.my_role() or "member", "manage_users"):
            return
        if self.admin_console is not None:
            self.admin_console.lift()
            return
        self.admin_console = AdminConsole(self)

    def _admin_event(self, event: dict) -> None:
        if self.admin_console is not None:
            self.admin_console.handle(event)

    _ev_admin_users = _ev_admin_audit = _ev_admin_verify = _ev_admin_settings = _ev_admin_result = _admin_event

    def export_data(self) -> None:
        name = f"lanchat-export-{self.username}.json"
        destination = filedialog.asksaveasfilename(
            parent=self.root, initialfile=name, defaultextension=".json",
            initialdir=str(Path.home() / "Downloads" if (Path.home() / "Downloads").is_dir() else Path.home()))
        if destination:
            self.media.start_export(destination)

    def change_password_dialog(self) -> None:
        if self._password_dialog is not None:
            self._password_dialog["window"].lift()
            return
        window = tk.Toplevel(self.root)
        window.title("Change password")
        window.configure(bg=self.p["bg"], padx=20, pady=16)
        window.transient(self.root)
        window.resizable(False, False)
        fields = {}
        for key, label in (("old", "Current password"), ("new", "New password"), ("again", "New password again")):
            tk.Label(window, text=label, bg=self.p["bg"], fg=self.p["text"], font=self.f.small, anchor="w").pack(fill="x", pady=(6, 0))
            entry = tk.Entry(window, show="•", width=34, font=self.f.body)
            entry.pack(fill="x")
            fields[key] = entry
        message = tk.Label(window, text="", bg=self.p["bg"], fg=self.p["error"], font=self.f.small, wraplength=300,
                           justify="left", anchor="w")
        message.pack(fill="x", pady=(8, 0))
        self._password_dialog = {"window": window, "fields": fields, "message": message}

        def close() -> None:
            self._password_dialog = None
            window.destroy()

        def submit() -> None:
            old, new, again = (fields[k].get() for k in ("old", "new", "again"))
            if not old or not new:
                message.configure(text="Fill in every box.")
            elif new != again:
                message.configure(text="The two new passwords do not match.")
            else:
                message.configure(text="Working…", fg=self.p["muted"])
                self._send_event({"t": "passwd", "old": old, "new": new})

        buttons = tk.Frame(window, bg=self.p["bg"])
        buttons.pack(fill="x", pady=(12, 0))
        self.button(buttons, "Change", submit, pady=6).pack(side="right")
        self.button(buttons, "Cancel", close, kind="secondary", pady=6).pack(side="right", padx=(0, 8))
        window.protocol("WM_DELETE_WINDOW", close)
        fields["old"].focus_set()

    def _ev_passwd_result(self, event: dict) -> None:
        dialog = self._password_dialog
        if event.get("ok"):
            self.session_token = event.get("token") or self.session_token
            if dialog is not None:
                dialog["window"].destroy()
                self._password_dialog = None
            self.notice("Your password was changed.", tone="join")
        elif dialog is not None:
            dialog["message"].configure(text=f"Not changed: {event.get('reason', 'refused')}", fg=self.p["error"])

    # ----- sharing files

    def attach_file(self) -> None:
        if self.sender is None:
            return
        if not can(self.my_role() or "member", "upload"):
            self.notice("Your role cannot share files.")
            return
        paths = filedialog.askopenfilenames(parent=self.root, title="Choose files or pictures to share")
        for number, path in enumerate(paths):
            caption = self.message_entry.get().strip() if number == 0 and not self.message_entry.get().startswith("/") else ""
            if caption:
                self.message_entry.clear()
            self.media.start_upload(
                path, self.private_to, self.reply_to.id if self.reply_to is not None else None, caption)
        if paths:
            self._clear_context()
            self._hide_mentions()

    def toggle_recording(self) -> None:
        recorder = self.media.recorder
        if recorder is None or self.sender is None:
            return
        if recorder.seconds() == 0.0:
            try:
                recorder.start()
            except Exception as error:  # noqa: BLE001 - a missing microphone or permission, whatever the library says
                self.notice(f"Could not start recording: {error}")
                return
            self._tick_recording()
            return
        self.record_button.set_text("\U0001F3A4")
        path = recorder.stop(str(self.media.cache_dir))
        if path:
            self.media.start_upload(path, self.private_to, None)

    def _tick_recording(self) -> None:
        recorder = self.media.recorder
        seconds = recorder.seconds() if recorder else 0
        if seconds == 0.0:
            return
        if seconds >= 120:
            self.toggle_recording()
            return
        self.record_button.set_text(f"■ {int(seconds) // 60}:{int(seconds) % 60:02d}")
        self.root.after(500, self._tick_recording)

    # ----- typing

    def _on_key(self, event) -> None:
        if event.keysym in ("Return", "Escape", "Up", "Down", "Left", "Right", "Shift_L", "Shift_R",
                            "Control_L", "Control_R", "Meta_L", "Meta_R", "Alt_L", "Alt_R", "Caps_Lock"):
            return
        text = self.message_entry.get()
        now = time.monotonic()
        if not text:
            self._stop_typing()
        elif not text.startswith("/") and self.editing is None:
            self._typing_idle_at = now + 4.0
            if should_send_typing(self._typing_sent, now):
                self._typing_sent = now
                self._typing_active = True
                self._send_event({"t": "typing", "on": True})
        self._update_mentions()

    def _stop_typing(self) -> None:
        if self._typing_active:
            self._typing_active = False
            self._typing_sent = 0.0
            self._send_event({"t": "typing", "on": False})

    def _refresh_typing(self) -> None:
        names = expire_typing(self.typing, time.monotonic())
        self.typing_label.configure(text=typing_label(names) or " ")

    # ----- presence and housekeeping

    def _note_activity(self, _event=None) -> None:
        self.last_activity = time.monotonic()
        if self.away and self.sender is not None:
            self.away = False
            self._send_event({"t": "presence", "status": "online"})

    def _tick(self) -> None:
        if self.closing:
            return
        if self.sender is not None:
            now = time.monotonic()
            self._refresh_typing()
            if self._typing_active and now > self._typing_idle_at:
                self._stop_typing()
            if should_go_away(now - self.last_activity, self.away, self.away_after):
                self.away = True
                self._send_event({"t": "presence", "status": "away"})
        self.root.after(1000, self._tick)

    # ----- message actions (right-click menu, reaction pills, reply quotes)

    def menu_for(self, record: Record) -> list:
        if record.kind == "notice" or record.id is None:
            return []
        role = self.my_role() or "member"
        items: list = []
        if not record.deleted:
            items.append(("Reply", "reply", None))
            if record.att and record.att["kind"] != "encrypted":
                items.append(("Play" if record.att["kind"] == "audio" else "Open", "att_play" if record.att["kind"] == "audio" else "att_open", None))
                items.append(("Save as…", "att_save", None))
            if can(role, "react"):
                items.append(("React", [(emoji, "react", emoji) for emoji in QUICK_REACTIONS]))
            if record.mine and can(role, "edit_own"):
                items.append(("Edit", "edit", None))
            if record.kind == "chat" and (can(role, "pin_any") or (record.mine and can(role, "pin_own"))):
                pinned = any(pin["id"] == record.id for pin in self.pins)
                items.append(("Unpin" if pinned else "Pin", "pin", not pinned))
            if (record.mine and can(role, "delete_own")) or can(role, "delete_any"):
                items.append(("-",))
                items.append(("Delete", "delete", None))
        return items

    def on_message_action(self, action: str, record: Record, arg=None) -> None:
        if action == "reply":
            self._start_reply(record)
        elif action == "react" and record.id is not None:
            self._send_event({"t": "react", "id": record.id, "emoji": arg})
        elif action == "edit":
            self._start_edit(record)
        elif action == "delete" and record.id is not None:
            if messagebox.askyesno("Delete message?", "This removes the message for everyone.", parent=self.root):
                self._send_event({"t": "delete", "id": record.id})
        elif action == "pin" and record.id is not None:
            self._send_event({"t": "pin", "id": record.id, "on": bool(arg)})
        elif action == "att_open":
            self.media.open(record)
        elif action == "att_play":
            self.media.play(record)
        elif action == "att_save" and record.att:
            home = Path.home() / "Downloads"
            destination = filedialog.asksaveasfilename(
                parent=self.root, initialfile=record.att["name"],
                initialdir=str(home if home.is_dir() else Path.home()))
            if destination:
                self.media.save_as(record, destination)
        elif action == "loadmore":
            self._load_older()
        elif action == "goto":
            self._goto_message(arg)

    def _report_read(self) -> None:
        """Tell the server how far you have read, but only when you really can see the newest messages."""
        if self.sender is None or self.screen != "chat" or not self.focused or not self.messages.at_bottom():
            return
        if self.latest_id > self.reported_read:
            self.reported_read = self.latest_id
            self._send_event({"t": "read", "up_to": self.latest_id})

    def _update_seen(self) -> None:
        """Show 'Seen by ...' under my newest public message only."""
        target = next((r for r in reversed(self.messages.records)
                       if r.mine and r.kind == "chat" and r.id and not r.deleted), None)
        names = seen_by_users(self.read_marks, target.id, self.username) if target else []
        if self._seen_id is not None and (target is None or target.id != self._seen_id):
            self.messages.update(self._seen_id, seen_by=[])
        if target is not None and names != target.seen_by:
            self.messages.update(target.id, seen_by=names)
        self._seen_id = target.id if target else None

    def open_emoji(self) -> None:
        EmojiPicker(self.root, self.p, self.f, self.message_entry.insert_text, self.emoji_button)

    # ----- receiving

    def _on_message(self, frame: str) -> None:
        event = decode(frame)
        if event is None:
            return
        handler = getattr(self, f"_ev_{event['t']}", None)
        if handler is not None:
            handler(event)

    def notice(self, text: str, tone: str = "error") -> None:
        self.messages.add(Record("notice", text, tone=tone))

    def _e2ee_event(self, event: dict) -> None:
        self.e2ee.handle(event)

    _ev_keys_result = _ev_keys = _ev_keys_backup = _ev_key_changed = _e2ee_event
    _ev_room_state = _ev_group_key = _ev_group_keys_list = _ev_room_epoch = _ev_e2ee_room = _e2ee_event

    def _ev_e2ee_policy(self, event: dict) -> None:
        self.e2ee.policy = event.get("policy", "optional")
        self._update_private_chip()
        self.notice(f"The end-to-end encryption policy of this chat is now: {self.e2ee.policy}.", tone="system")

    def confirm(self, title: str, text: str) -> bool:
        return messagebox.askyesno(title, text, parent=self.root)

    def _ev_upload_ready(self, event: dict) -> None:
        self.media.on_upload_ready(event)

    def _ev_upload_denied(self, event: dict) -> None:
        self.media.on_upload_denied(event)

    def _ev_download_ready(self, event: dict) -> None:
        self.media.on_download_ready(event)

    def _ev_transfer_error(self, event: dict) -> None:
        self.media.on_transfer_error(event)

    def _record_from_event(self, event: dict) -> Record:
        record = self._build_record(event)
        if record.att:
            self.media.ensure_preview(record)
        return record

    def _build_record(self, event: dict) -> Record:
        mine = event["sender"].lower() == self.username.lower()
        common = dict(
            att=event.get("att"),
            timestamp=clock(event["ts"]), mine=mine, id=event["id"], reply=event.get("reply"),
            edited=bool(event.get("edited")), deleted=bool(event.get("deleted")),
            reactions=[(r["emoji"], list(r["users"])) for r in event.get("reactions", [])],
            mentioned=(not mine) and not event.get("to") and mentions_me(event, self.username),
            sender=event["sender"], ts=event["ts"],
            enc=event.get("enc"), secure="pending" if event.get("enc") else "",
        )
        body = event["body"]
        if event.get("enc"):  # a file message is shown as a card, so it needs no placeholder text
            body = "" if event.get("att") else "\U0001F512 Encrypted message"
        if event.get("to"):
            return Record("private", body, name=event["to"] if mine else event["sender"], **common)
        return Record("chat", body, name=event["sender"], **common)

    def _ev_welcome(self, event: dict) -> None:
        self.limits = event.get("limits") or {}
        if event.get("token"):
            self.session_token = event["token"]
        self.root.after_idle(lambda: self.e2ee.on_welcome(event))
        self.last_read = int(event.get("last_read", 0))
        self.reported_read = self.last_read
        self.latest_id = 0
        self.divider_added = False
        self.read_marks = {}
        self._seen_id = None
        self._members_buffer = []
        self.loading_page = False
        self.pending_goto = None
        self.page_buffer = []
        if not self.keep_history or not self.messages.records:
            self.has_more = False
        if event.get("server"):
            self.server_title = event["server"]
        self._update_header()

    def _ev_history_start(self, event: dict) -> None:
        # After a reconnect the old messages are still on screen, so do not repeat the banner.
        self.skip_history_notices = self.keep_history and bool(self.messages.records)
        if not self.skip_history_notices:
            self.has_more = bool(event.get("has_more"))
            if self.has_more:
                self.messages.add(Record("notice", "Load earlier messages", tone="loadmore"))
            self.messages.add(Record("notice", HISTORY_HEADER, tone="system"))

    def _ev_history_end(self, event: dict) -> None:
        if not self.skip_history_notices:
            self.messages.add(Record("notice", "--- End of earlier messages ---", tone="system"))
        self.skip_history_notices = False
        self._update_seen()
        self.messages.scroll_to_bottom()
        self._report_read()
        self.e2ee.schedule_decrypt()

    def _ev_message(self, event: dict) -> None:
        record = self._record_from_event(event)
        if event.get("page"):  # an older page being loaded: collect it until page_end
            if self.messages.record_for(record.id) is None and all(r.id != record.id for r in self.page_buffer):
                self.page_buffer.append(record)
            return
        existing = self.messages.record_for(record.id)
        if existing is not None:  # already on screen (history replayed after a reconnect)
            if record.enc and existing.secure == "e2ee" and existing.enc == record.enc:
                # keep what was already decrypted, including the file it describes
                record.text, record.secure, record.att, record.file = (
                    existing.text, "e2ee", existing.att, existing.file)
            self.messages.update(record.id, text=record.text, edited=record.edited, deleted=record.deleted,
                                 reactions=record.reactions, enc=record.enc, secure=record.secure,
                                 att=record.att, file=record.file)
            self.e2ee.schedule_decrypt()
            return
        if event.get("history") and not self.divider_added and not record.mine and record.id > self.last_read:
            self.messages.add(Record("notice", "New messages", tone="divider"))
            self.divider_added = True
        self.messages.add(record)
        self.latest_id = max(self.latest_id, record.id)
        self.e2ee.schedule_decrypt()
        self.typing.pop(event["sender"], None)
        if event.get("history"):
            return
        self._refresh_typing()
        if record.mine:
            self._update_seen()
        elif not self.focused:
            self.unread += 1
            if record.mentioned:
                self.mention_unread = True
            self.root.title(unread_title(APP_TITLE, self.unread, self.mention_unread))
            if record.kind == "private" or record.mentioned:
                self.root.bell()
        self.root.after_idle(self._report_read)

    def _ev_notice(self, event: dict) -> None:
        tone = {"shutdown": "leave", "role": "system", "info": "system"}.get(event["kind"], event["kind"])
        self.messages.add(Record("notice", event["text"], tone=tone))

    def _ev_members(self, event: dict) -> None:
        if event.get("page", 0) == 0:
            self._members_buffer = []
        for name, role, status in event.get("members", []):
            self._members_buffer.append(Member(name, role, status != "offline", status))
        if event.get("page", 0) >= event.get("pages", 1) - 1:
            self._set_members(self._members_buffer)
            self._members_buffer = []
            self.e2ee.room_sync_soon()  # someone new may need my room key

    def _ev_presence(self, event: dict) -> None:
        status = event.get("status", "online")
        updated = [
            Member(m.name, m.role, True, status) if m.name.lower() == event.get("user", "").lower() else m
            for m in self.members
        ]
        self._set_members(updated)

    def _ev_typing(self, event: dict) -> None:
        user = event.get("user", "")
        if event.get("on"):
            self.typing[user] = time.monotonic()
        else:
            self.typing.pop(user, None)
        self._refresh_typing()

    def _ev_edited(self, event: dict) -> None:
        if event.get("enc"):
            self.messages.update(event["id"], text="\U0001F512 Encrypted message", enc=event["enc"],
                                 secure="pending", edited=True)
            self.e2ee.schedule_decrypt()
            return
        self.messages.update(event["id"], text=event["body"], edited=True)

    def _ev_deleted(self, event: dict) -> None:
        self.messages.update(event["id"], text="", deleted=True, reactions=[], seen_by=[], enc=None, secure="",
                             att=None, file=None)
        if self.editing is not None and self.editing.id == event["id"]:
            self._cancel_context()
        if self.reply_to is not None and self.reply_to.id == event["id"]:
            self._clear_context()
        self._update_seen()

    def _ev_reactions(self, event: dict) -> None:
        self.messages.update(event["id"], reactions=[(r["emoji"], list(r["users"])) for r in event["reactions"]])

    def _ev_read(self, event: dict) -> None:
        user = event.get("user", "")
        self.read_marks[user] = max(self.read_marks.get(user, 0), int(event.get("up_to", 0)))
        self._update_seen()

    def _on_disconnected(self) -> None:
        if self.connection is None:
            return
        self.stop.set()
        self._close_connection(bump_session=False)
        self.set_composer_enabled(False)
        self._set_members([])
        self.typing.clear()
        self._refresh_typing()
        self.banner.pack(side="bottom", fill="x", after=self.composer)
        self.subtitle_label.configure(text="Disconnected")

    def reconnect(self) -> None:
        if self.credentials is None:
            self.leave()
            return
        host, port, username, _password = self.credentials
        self.show_home()
        self.connect(host, port, username, "", hosting=self.hosting is not None, keep_history=True,
                     token=self.session_token)

    # ------------------------------------------------------------ misc actions

    def copy_address(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.host_address)
        self.copy_button.set_text("Copied ✓")
        self.root.after(1500, lambda: self.copy_button.set_text("Copy address"))

    def leave(self) -> None:
        if self.hosting is not None and not messagebox.askokcancel(
            "Stop hosting?", "You are hosting this chat. Leaving will end it for everyone.\n\nLeave anyway?",
            parent=self.root,
        ):
            return
        if self.sender is not None and self.session_token:
            self._send_event({"t": "logout"})  # revoke the saved sign-in on the server
        self.session_token = None
        self.e2ee.forget()
        if self.admin_console is not None:
            self.admin_console.close()
        self._stop_hosting()
        self._close_connection(bump_session=True)
        self.credentials = None
        self.user_names = []
        self.members = []
        self.private_to = None
        self.reply_to = None
        self.editing = None
        self.typing.clear()
        self.read_marks = {}
        self.pins = []
        self.has_more = False
        self.loading_page = False
        self.pending_goto = None
        self.search_open = False
        self.search_results = []
        self.media.reset()
        self._hide_mentions()
        self.messages.clear()
        self._place_bars()
        self.show_home()

    def on_close(self) -> None:
        self.closing = True
        self._stop_hosting()
        self._close_connection(bump_session=True)
        self.root.destroy()

    def _close_connection(self, bump_session: bool) -> None:
        self.stop.set()
        connection, self.connection, self.sender = self.connection, None, None
        if bump_session:
            self.session += 1  # events from the old connection are now ignored
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except (OSError, ValueError):
                pass
            try:
                connection.close()
            except OSError:
                pass

    def _on_focus_in(self, event) -> None:
        if event.widget is self.root:
            self.focused = True
            self.unread = 0
            self.mention_unread = False
            self.root.title(APP_TITLE)
            self._report_read()

    def _on_focus_out(self, event) -> None:
        if event.widget is self.root:
            self.focused = False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="LAN Chat window")
    parser.add_argument("--host", help="prefill an address to join (host or host:port)")
    parser.add_argument("--username", help="prefill the username")
    args = parser.parse_args(argv)

    root = tk.Tk()
    app = App(root, args)
    app.apply_theme()
    # Without this the window can open behind the terminal on macOS.
    root.lift()
    root.attributes("-topmost", True)
    root.after(400, lambda: root.attributes("-topmost", False))
    root.focus_force()
    root.mainloop()


if __name__ == "__main__":
    main()
