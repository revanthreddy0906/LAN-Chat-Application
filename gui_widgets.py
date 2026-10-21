"""Custom Tkinter widgets for the LAN Chat window (standard library only)."""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Callable

from gui_logic import (
    GroupKey,
    avatar_color,
    initials,
    is_at_bottom,
    seen_label,
    starts_group,
    wrap_width,
)

EMOJIS = (
    "😀 😁 😂 🤣 😊 😍 😘 😎 🤔 😅 😭 😡 👍 👎 👏 🙏 "
    "🙌 💪 🔥 ✨ 🎉 ❤️ 💔 💯 ✅ ❌ ⭐ 🚀 👀 🤝 😴 🤯 "
    "🥳 😇 🙈 ☕ 🍕 🎵 📌 👋"
).split()


def bind_click(widget: tk.Misc, callback: Callable[[tk.Event], None]) -> None:
    """Bind a left click on a widget and everything inside it."""
    widget.bind("<Button-1>", callback, add="+")
    for child in widget.winfo_children():
        bind_click(child, callback)


def wheel_units(event: tk.Event) -> int:
    """Convert a mouse-wheel event to canvas scroll units on macOS, Windows and Linux."""
    if event.num == 4:
        return -2
    if event.num == 5:
        return 2
    delta = event.delta
    return -int(delta / 120) * 2 if abs(delta) >= 120 else -delta


def pointer_inside(container: tk.Misc, event: tk.Event) -> bool:
    widget = container.winfo_containing(event.x_root, event.y_root)
    while widget is not None:
        if widget is container:
            return True
        widget = widget.master
    return False


class ScrollFrame(tk.Frame):
    """A vertically scrolling container; put children in `.inner`."""

    def __init__(self, parent, bg: str, width: int = 1, height: int = 1):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=bg, width=width,
                                height=height, yscrollincrement=20)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self._on_yscroll)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._window, width=e.width))
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(sequence, self._on_wheel, add="+")

    def set_bg(self, bg: str) -> None:
        for widget in (self, self.canvas, self.inner):
            widget.configure(bg=bg)

    def _on_yscroll(self, first, last) -> None:
        self.scrollbar.set(first, last)
        needed = float(first) > 0.0 or float(last) < 1.0
        if needed and not self.scrollbar.winfo_ismapped():
            self.scrollbar.pack(side="right", fill="y", before=self.canvas)
        elif not needed and self.scrollbar.winfo_ismapped():
            self.scrollbar.pack_forget()

    def _on_wheel(self, event) -> None:
        if self.winfo_ismapped() and pointer_inside(self, event):
            self.canvas.yview_scroll(wheel_units(event), "units")


class FlatButton(tk.Label):
    """A colored button. (Native Tk buttons ignore colors on macOS.)"""

    def __init__(self, parent, text, command, palette, fonts, kind="primary",
                 padx=16, pady=8, ghost_bg="panel"):
        super().__init__(parent, text=text, font=fonts.bold, padx=padx, pady=pady, cursor="hand2")
        self.command = command
        self.kind = kind
        self._ghost_bg = ghost_bg
        self._hover = False
        self._disabled = False
        self.p = palette
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", self._click)
        self._paint()

    def set_palette(self, palette) -> None:
        self.p = palette
        self._paint()

    def set_disabled(self, disabled: bool) -> None:
        self._disabled = disabled
        self._paint()

    def set_text(self, text: str) -> None:
        self.configure(text=text)

    def _set_hover(self, hover: bool) -> None:
        self._hover = hover
        self._paint()

    def _click(self, event) -> None:
        inside = 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height()
        if inside and not self._disabled and self.command:
            self.command()

    def _paint(self) -> None:
        p = self.p
        if self.kind == "primary":
            bg, fg = (p["accent_hover"] if self._hover else p["accent"]), p["accent_text"]
        elif self.kind == "secondary":
            bg, fg = (p["button_2_hover"] if self._hover else p["button_2"]), p["text"]
        elif self.kind == "danger":
            bg, fg = p["error"], "#ffffff"
        else:  # ghost
            bg = p["button_2"] if self._hover else p[self._ghost_bg]
            fg = p["text"] if self._hover else p["muted"]
        if self._disabled:
            fg = p["muted"]
            bg = p["button_2"] if self.kind != "ghost" else p[self._ghost_bg]
        self.configure(bg=bg, fg=fg, cursor="arrow" if self._disabled else "hand2")


class PlaceholderEntry(tk.Frame):
    """A single-line input with a border, a placeholder and optional masking."""

    def __init__(self, parent, palette, fonts, placeholder="", show="", width=28):
        super().__init__(parent, highlightthickness=1, bd=0)
        self.p = palette
        self._placeholder = placeholder
        self._mask = show
        self._placeholder_active = False
        self._focused = False
        self.entry = tk.Entry(self, relief="flat", bd=0, highlightthickness=0, font=fonts.body, width=width)
        self.entry.pack(fill="both", expand=True, padx=10, pady=8)
        self.entry.bind("<FocusIn>", self._focus_in)
        self.entry.bind("<FocusOut>", self._focus_out)
        self.set_palette(palette)
        self._show_placeholder()

    def set_palette(self, palette) -> None:
        self.p = palette
        self.configure(bg=palette["input_bg"], highlightbackground=palette["border"],
                       highlightcolor=palette["accent"])
        self.entry.configure(bg=palette["input_bg"], insertbackground=palette["text"],
                             fg=palette["muted"] if self._placeholder_active else palette["text"],
                             disabledbackground=palette["input_bg"])
        self.configure(highlightbackground=palette["accent"] if self._focused else palette["border"])

    def _show_placeholder(self) -> None:
        if self._placeholder_active or self.entry.get():
            return
        self._placeholder_active = True
        self.entry.configure(show="", fg=self.p["muted"])
        self.entry.insert(0, self._placeholder)

    def _hide_placeholder(self) -> None:
        if not self._placeholder_active:
            return
        self._placeholder_active = False
        self.entry.delete(0, "end")
        self.entry.configure(show=self._mask, fg=self.p["text"])

    def _focus_in(self, _event=None) -> None:
        self._focused = True
        self._hide_placeholder()
        self.configure(highlightbackground=self.p["accent"])

    def _focus_out(self, _event=None) -> None:
        self._focused = False
        self.configure(highlightbackground=self.p["border"])
        if not self.entry.get():
            self._show_placeholder()

    def get(self) -> str:
        return "" if self._placeholder_active else self.entry.get()

    def set(self, text: str) -> None:
        self._hide_placeholder()
        self.entry.delete(0, "end")
        self.entry.insert(0, text)
        if not text and not self._focused:
            self._show_placeholder()

    def clear(self) -> None:
        self.set("")

    def insert_text(self, text: str) -> None:
        self._hide_placeholder()
        self.entry.insert("insert", text)

    def focus(self) -> None:
        self.entry.focus_set()

    def bind_return(self, callback) -> None:
        self.entry.bind("<Return>", callback)

    def set_enabled(self, enabled: bool) -> None:
        self.entry.configure(state="normal" if enabled else "disabled")


class Avatar(tk.Canvas):
    """A colored circle with initials; `presence` adds a status dot (online/away/offline)."""

    PRESENCE_COLORS = {"online": "#2da44e", "away": "#d29922", "offline": "#8b949e"}

    def __init__(self, parent, name: str, size: int, bg: str, font, presence=None):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        color = avatar_color(name)
        self.create_oval(1, 1, size - 1, size - 1, fill=color, outline=color)
        self.create_text(size / 2, size / 2, text=initials(name), fill="white", font=font)
        if presence is not None:
            if presence is True:
                presence = "online"
            elif presence is False:
                presence = "offline"
            dot = max(8, size // 3)
            fill = self.PRESENCE_COLORS.get(presence, self.PRESENCE_COLORS["offline"])
            self.create_oval(size - dot, size - dot, size - 1, size - 1, fill=fill, outline=bg, width=2)


@dataclass
class Record:
    kind: str  # "chat", "private" or "notice"
    text: str
    timestamp: str = ""
    name: str = ""  # sender for chat, the other person for private
    mine: bool = False
    tone: str = "system"  # notices: join, leave, error, welcome, system, divider
    id: int | None = None  # the server's message id (None for notices)
    reply: dict | None = None  # {"id", "sender", "snippet", "deleted"}
    edited: bool = False
    deleted: bool = False
    reactions: list = field(default_factory=list)  # [(emoji, [usernames])]
    seen_by: list = field(default_factory=list)  # who has read this (my latest message only)
    mentioned: bool = False  # this message @mentions me (or everyone)
    flash: bool = False  # briefly highlighted after jumping to it
    sender: str = ""  # who actually wrote it (for private messages `name` is the other person)
    ts: float = 0.0  # the server's time stamp, for searching decrypted text
    enc: dict | None = None  # an end-to-end encrypted envelope, until it has been read
    file: dict | None = None  # for an encrypted file message: what the file is and its key (from the payload)
    secure: str = ""  # "", "pending", "e2ee", "locked" or "failed": the state of an encrypted message
    att: dict | None = None  # a shared file: {id, name, mime, size, kind, sha256}
    media: dict = field(default_factory=dict)  # what the window knows about it: status, pct, photo, path...


class MessageList(tk.Frame):
    """Scrollable chat history drawn as bubbles.

    `on_action(action, record, arg)` is called for clicks on reactions and reply quotes,
    and `menu_for(record)` supplies the right-click menu as a list of
    (label, action, arg) / ("-",) / (label, [(label, action, arg), ...]).
    """

    MAX_ROWS = 500
    AVATAR_SIZE = 34

    def __init__(self, parent, palette, fonts, on_action=None, menu_for=None, me=None, on_bottom=None):
        super().__init__(parent, bg=palette["panel"])
        self.p, self.f = palette, fonts
        self._on_action = on_action or (lambda *_a: None)
        self._menu_for = menu_for or (lambda _r: [])
        self._me = me or (lambda: "")
        self._on_bottom = on_bottom or (lambda: None)
        self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=palette["panel"], yscrollincrement=20)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self._on_yscroll)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=palette["panel"])
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.records: list[Record] = []
        self._rows: list[tk.Frame] = []
        self._starts: list[bool] = []
        self._wrappers: list[tk.Label] = []
        self._last_key: GroupKey | None = None
        self._stick = True

        self.new_pill = tk.Label(self, text="New messages  ↓", font=fonts.small_bold,
                                 padx=14, pady=5, cursor="hand2")
        self.new_pill.bind("<Button-1>", lambda _e: self.scroll_to_bottom())
        self._menu_text = ""
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(sequence, self._on_wheel, add="+")
        self._paint_pill()

    # ----- public API -----

    def set_palette(self, palette) -> None:
        self.p = palette
        self.configure(bg=palette["panel"])
        self.canvas.configure(bg=palette["panel"])
        self.inner.configure(bg=palette["panel"])
        self._paint_pill()
        self.rebuild()

    def clear(self) -> None:
        for row in self._rows:
            row.destroy()
        self._rows, self._starts, self._wrappers, self.records = [], [], [], []
        self._last_key = None
        self._stick = True
        self.new_pill.place_forget()

    def add(self, record: Record) -> None:
        was_at_bottom = self._stick
        self.records.append(record)
        self._append_row(record)
        self._trim()
        if was_at_bottom or record.mine:
            self.after_idle(self.scroll_to_bottom)
        else:
            self.new_pill.place(relx=0.5, rely=1.0, anchor="s", y=-12)
            self.new_pill.lift()

    def rebuild(self) -> None:
        records = self.records
        self.clear()
        self.records = []
        for record in records:
            self.records.append(record)
            self._append_row(record)
        self.after_idle(self.scroll_to_bottom)

    def index_of(self, message_id: int) -> int | None:
        for index, record in enumerate(self.records):
            if record.id == message_id:
                return index
        return None

    def record_for(self, message_id: int) -> Record | None:
        index = self.index_of(message_id)
        return self.records[index] if index is not None else None

    def update(self, message_id: int, **changes) -> bool:
        """Change fields of one message and redraw just its row."""
        index = self.index_of(message_id)
        if index is None:
            return False
        record = self.records[index]
        for field_name, value in changes.items():
            setattr(record, field_name, value)
        self._refresh_row(index)
        return True

    def refresh(self, record: Record) -> None:
        """Redraw the row of this exact record object (used for records without a server id)."""
        for index, candidate in enumerate(self.records):
            if candidate is record:
                self._refresh_row(index)
                return

    def remove(self, record: Record) -> None:
        """Take one record out of the list and redraw (used when an upload finishes or fails)."""
        if not any(candidate is record for candidate in self.records):
            return
        self.records = [candidate for candidate in self.records if candidate is not record]
        stick = self._stick
        self.rebuild()
        if not stick:
            self._stick = False

    def last_own(self) -> Record | None:
        for record in reversed(self.records):
            if record.mine and record.kind in ("chat", "private") and not record.deleted and record.id:
                return record
        return None

    def at_bottom(self) -> bool:
        return self._stick

    def oldest_id(self) -> int | None:
        return next((r.id for r in self.records if r.id), None)

    def set_records(self, records: list[Record], anchor_id: int | None = None) -> None:
        """Replace everything (used when older messages are loaded in front).

        With `anchor_id` the view stays on that message instead of jumping to the bottom.
        """
        self.clear()
        if anchor_id is not None:
            self._stick = False
        for record in records:
            self.records.append(record)
            self._append_row(record)
        if anchor_id is not None:
            self.after_idle(lambda: self.scroll_to_record(anchor_id))
        else:
            self.after_idle(self.scroll_to_bottom)

    def flash_record(self, message_id: int, seconds: float = 1.4) -> None:
        if self.update(message_id, flash=True):
            self.after(int(seconds * 1000), lambda: self.update(message_id, flash=False))

    def scroll_to_record(self, message_id: int) -> bool:
        index = self.index_of(message_id)
        if index is None:
            return False
        self.update_idletasks()
        total = max(1, self.inner.winfo_height())
        self.canvas.yview_moveto(max(0.0, (self._rows[index].winfo_y() - 24) / total))
        return True

    def scroll_to_bottom(self) -> None:
        self.update_idletasks()
        self.canvas.yview_moveto(1.0)
        self._stick = True
        self.new_pill.place_forget()

    # ----- internals -----

    def _paint_pill(self) -> None:
        self.new_pill.configure(bg=self.p["accent"], fg=self.p["accent_text"])

    def _on_yscroll(self, first, last) -> None:
        self.scrollbar.set(first, last)
        was_stuck = self._stick
        self._stick = is_at_bottom(float(last))
        if self._stick:
            self.new_pill.place_forget()
            if not was_stuck:
                self._on_bottom()

    def _on_inner_configure(self, _event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        if self._stick:
            self.canvas.yview_moveto(1.0)

    def _on_canvas_configure(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
        wrap = wrap_width(event.width)
        for label in self._wrappers:
            if label.winfo_exists():
                label.configure(wraplength=wrap)

    def _on_wheel(self, event) -> None:
        if self.winfo_ismapped() and pointer_inside(self, event):
            self.canvas.yview_scroll(wheel_units(event), "units")

    def _trim(self) -> None:
        while len(self._rows) > self.MAX_ROWS:
            self._rows.pop(0).destroy()
            self._starts.pop(0)
            self.records.pop(0)
        self._wrappers = [w for w in self._wrappers if w.winfo_exists()]

    @staticmethod
    def _key(record: Record) -> GroupKey:
        return GroupKey(record.name or "You", record.mine, record.kind)

    def _append_row(self, record: Record) -> None:
        if record.kind == "notice":
            starts, self._last_key = True, None
        else:
            key = self._key(record)
            starts = starts_group(self._last_key, key)
            self._last_key = key
        row = tk.Frame(self.inner, bg=self.p["panel"])
        row.pack(fill="x", padx=14, pady=(12 if starts else 2, 0))
        self._rows.append(row)
        self._starts.append(starts)
        self._fill_row(row, record, starts)

    def _refresh_row(self, index: int) -> None:
        row = self._rows[index]
        for child in row.winfo_children():
            child.destroy()
        self._wrappers = [w for w in self._wrappers if w.winfo_exists()]
        self._fill_row(row, self.records[index], self._starts[index])

    def _fill_row(self, row: tk.Frame, record: Record, starts: bool) -> None:
        if record.kind == "notice":
            self._build_notice(row, record)
        else:
            self._build_bubble(row, record, starts)

    def _wrapped_label(self, parent, text, **options) -> tk.Label:
        label = tk.Label(parent, text=text, justify="left", anchor="w",
                         wraplength=wrap_width(self.canvas.winfo_width() or 760), **options)
        self._wrappers.append(label)
        return label

    # ----- right-click menu -----

    def _popup(self, event, record: Record) -> None:
        menu = tk.Menu(self, tearoff=0)
        self._menu_text = record.text
        for item in self._menu_for(record):
            if item[0] == "-":
                menu.add_separator()
            elif isinstance(item[1], list):
                submenu = tk.Menu(menu, tearoff=0)
                for label, action, arg in item[1]:
                    submenu.add_command(label=label, command=lambda a=action, g=arg: self._on_action(a, record, g))
                menu.add_cascade(label=item[0], menu=submenu)
            else:
                label, action, arg = item
                menu.add_command(label=label, command=lambda a=action, g=arg: self._on_action(a, record, g))
        if record.text and not record.deleted:
            if menu.index("end") is not None:
                menu.add_separator()
            menu.add_command(label="Copy text", command=self._copy)
        if menu.index("end") is not None:
            menu.tk_popup(event.x_root, event.y_root)

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._menu_text)

    def _attach_menu(self, widget: tk.Misc, record: Record) -> None:
        for sequence in ("<Button-2>", "<Button-3>", "<Control-Button-1>"):
            widget.bind(sequence, lambda event, r=record: self._popup(event, r))
        for child in widget.winfo_children():
            self._attach_menu(child, record)

    # ----- building rows -----

    def _build_notice(self, row: tk.Frame, record: Record) -> None:
        p = self.p
        color = {"join": p["join"], "leave": p["leave"], "error": p["error"],
                 "welcome": p["accent"], "divider": p["accent"]}.get(record.tone, p["pill_text"])
        if record.tone == "loadmore":
            pill = tk.Label(row, text=record.text, bg=p["pill_bg"], fg=p["accent"], font=self.f.small_bold,
                            padx=14, pady=5, cursor="hand2")
            pill.pack()
            pill.bind("<Button-1>", lambda _e, r=record: self._on_action("loadmore", r, None))
            return
        if record.tone == "divider":
            line = tk.Frame(row, bg=p["panel"])
            line.pack(fill="x")
            tk.Frame(line, height=1, bg=p["accent"]).pack(side="left", fill="x", expand=True, pady=8)
            tk.Label(line, text=f"  {record.text}  ", bg=p["panel"], fg=color, font=self.f.small_bold).pack(side="left")
            tk.Frame(line, height=1, bg=p["accent"]).pack(side="left", fill="x", expand=True, pady=8)
            return
        label = self._wrapped_label(row, record.text, bg=p["pill_bg"], fg=color,
                                    font=self.f.small, padx=12, pady=4)
        label.pack()
        self._attach_menu(label, record)

    def _build_bubble(self, row: tk.Frame, record: Record, starts: bool) -> None:
        p, f = self.p, self.f
        private = record.kind == "private"
        if private:
            bubble_bg = p["bubble_private_mine"] if record.mine else p["bubble_private"]
            text_fg = "#ffffff" if record.mine else p["bubble_private_text"]
            time_fg = "#e4dcff" if record.mine else p["muted"]
        elif record.mine:
            bubble_bg, text_fg, time_fg = p["bubble_mine"], p["bubble_mine_text"], p["bubble_mine_time"]
        else:
            bubble_bg, text_fg, time_fg = p["bubble_other"], p["bubble_other_text"], p["muted"]

        if record.mine:
            body = tk.Frame(row, bg=p["panel"])
            body.pack(side="right")
        else:
            gutter = tk.Frame(row, width=self.AVATAR_SIZE + 8, height=self.AVATAR_SIZE, bg=p["panel"])
            gutter.pack(side="left", anchor="n")
            gutter.pack_propagate(False)
            if starts:
                Avatar(gutter, record.name, self.AVATAR_SIZE, p["panel"], f.tiny).pack()
            body = tk.Frame(row, bg=p["panel"])
            body.pack(side="left")

        if starts and not record.mine:
            tk.Label(body, text=record.name, bg=p["panel"], fg=avatar_color(record.name),
                     font=f.small_bold).pack(anchor="w", pady=(0, 2))

        ring = p["accent"] if record.flash else (p["leave"] if record.mentioned else None)
        bubble = tk.Frame(body, bg=bubble_bg, padx=12, pady=7, highlightthickness=2 if ring else 0,
                          highlightbackground=ring or bubble_bg, highlightcolor=ring or bubble_bg)
        bubble.pack(anchor="e" if record.mine else "w")
        if record.mentioned:
            tk.Label(bubble, text="@ mentioned you", bg=bubble_bg, fg=p["leave"],
                     font=f.tiny).pack(anchor="w")
        if private or record.secure:
            tag = self._private_tag(record)
            tk.Label(bubble, text=tag, bg=bubble_bg, fg=time_fg, font=f.tiny).pack(anchor="w")
        if record.reply:
            self._build_quote(bubble, record, bubble_bg, text_fg, time_fg)
        if record.deleted:
            italic = (f.body[0], f.body[1], "italic")
            tk.Label(bubble, text="This message was deleted", bg=bubble_bg, fg=time_fg, font=italic).pack(anchor="w")
        else:
            if record.att:
                self._build_attachment(bubble, record, bubble_bg, text_fg, time_fg)
            if record.text or not record.att:
                self._wrapped_label(bubble, record.text, bg=bubble_bg, fg=text_fg, font=f.body).pack(anchor="w")
        meta = record.timestamp + (" · edited" if record.edited and not record.deleted else "")
        if meta:
            tk.Label(bubble, text=meta, bg=bubble_bg, fg=time_fg, font=f.tiny).pack(anchor="e")

        if record.reactions and not record.deleted:
            self._build_reactions(body, record)
        if record.mine and record.seen_by:
            seen = tk.Label(body, text=seen_label(record.seen_by), bg=p["panel"], fg=p["muted"], font=f.tiny)
            seen.pack(anchor="e", pady=(2, 0))
        self._attach_menu(body, record)

    def _link(self, parent, text: str, record: Record, action: str, fg: str, bg: str) -> tk.Label:
        underline = (self.f.small[0], self.f.small[1], "underline")
        label = tk.Label(parent, text=text, bg=bg, fg=fg, font=underline, cursor="hand2")
        label.bind("<Button-1>", lambda _e, a=action, r=record: self._on_action(a, r, None))
        return label

    def _build_attachment(self, bubble: tk.Frame, record: Record, bubble_bg, text_fg, time_fg) -> None:
        """A picture shown inline, or a card for any other file, with the actions that make sense."""
        attachment, media, f = record.att, record.media, self.f
        kind = attachment["kind"]
        if kind == "encrypted":  # not opened yet (keys locked) or not openable
            card = tk.Frame(bubble, bg=bubble_bg)
            card.pack(anchor="w", fill="x", pady=(2, 4))
            tk.Label(card, text="\U0001F512", bg=bubble_bg, fg=text_fg, font=(f.body[0], 26)).pack(side="left", padx=(0, 10))
            info = tk.Frame(card, bg=bubble_bg)
            info.pack(side="left")
            tk.Label(info, text="Encrypted file", bg=bubble_bg, fg=text_fg, font=f.small_bold).pack(anchor="w")
            detail = {"failed": "could not be opened", "locked": "unlock your keys to open it"}.get(record.secure, "opening…")
            tk.Label(info, text=f"{self._human_size(attachment['size'])} · {detail}", bg=bubble_bg, fg=time_fg,
                     font=f.tiny).pack(anchor="w")
            return
        size_text = self._human_size(attachment["size"])
        photo = media.get("photo")
        if kind == "image" and photo is not None:
            picture = tk.Label(bubble, image=photo, bg=bubble_bg, bd=0, cursor="hand2")
            picture.pack(anchor="w", pady=(2, 4))
            picture.bind("<Button-1>", lambda _e, r=record: self._on_action("att_open", r, None))
            line = tk.Frame(bubble, bg=bubble_bg)
            line.pack(anchor="w", fill="x")
            tk.Label(line, text=f"{attachment['name']} · {size_text}", bg=bubble_bg, fg=time_fg,
                     font=f.tiny).pack(side="left")
            self._link(line, "Save as…", record, "att_save", text_fg, bubble_bg).pack(side="left", padx=(10, 0))
            return
        card = tk.Frame(bubble, bg=bubble_bg)
        card.pack(anchor="w", fill="x", pady=(2, 4))
        icon = {"image": "\U0001F5BC", "video": "\U0001F3AC", "audio": "\U0001F3B5"}.get(kind, "\U0001F4C4")
        tk.Label(card, text=icon, bg=bubble_bg, fg=text_fg, font=(f.body[0], 26)).pack(side="left", padx=(0, 10))
        info = tk.Frame(card, bg=bubble_bg)
        info.pack(side="left")
        tk.Label(info, text=attachment["name"], bg=bubble_bg, fg=text_fg, font=f.small_bold,
                 anchor="w", justify="left", wraplength=260).pack(anchor="w")
        status = media.get("status")
        if status == "loading":
            detail = f"{size_text} · downloading {media.get('pct', 0)}%"
        elif status == "error":
            detail = f"{size_text} · {media.get('error') or 'failed'}"
        else:
            detail = size_text
        tk.Label(info, text=detail, bg=bubble_bg, fg=time_fg, font=f.tiny).pack(anchor="w")
        actions = tk.Frame(info, bg=bubble_bg)
        actions.pack(anchor="w", pady=(3, 0))
        if status != "loading":
            if kind == "audio":
                label = "■ Stop" if media.get("playing") else "▶ Play"
                self._link(actions, label, record, "att_play", text_fg, bubble_bg).pack(side="left", padx=(0, 10))
            else:
                self._link(actions, "Open", record, "att_open", text_fg, bubble_bg).pack(side="left", padx=(0, 10))
            self._link(actions, "Save as…", record, "att_save", text_fg, bubble_bg).pack(side="left")

    @staticmethod
    def _human_size(size: int) -> str:
        from storage import human_size
        return human_size(size)

    @staticmethod
    def _private_tag(record: Record) -> str:
        to = f" to {record.name}" if record.mine and record.kind == "private" else ""
        if record.kind == "chat":  # the group room
            return {"e2ee": "\U0001F512 Room · end-to-end encrypted",
                    "pending": "\U0001F512 Room · opening…",
                    "locked": "\U0001F512 Room · encrypted, keys locked",
                    "failed": "⚠ Room · could not be opened"}.get(record.secure, "")
        return {
            "e2ee": f"\U0001F512 End-to-end encrypted{to}",
            "pending": f"\U0001F512 Encrypted{to} · opening…",
            "locked": f"\U0001F512 Encrypted{to} · keys locked",
            "failed": f"⚠ Encrypted{to} · could not be opened",
        }.get(record.secure, f"\U0001F513 Private{to} · server can read this")

    def _build_quote(self, bubble: tk.Frame, record: Record, bubble_bg, text_fg, time_fg) -> None:
        reply = record.reply
        quote = tk.Frame(bubble, bg=bubble_bg, cursor="hand2")
        quote.pack(anchor="w", fill="x", pady=(2, 5))
        bar = "#ffffff" if record.mine else self.p["accent"]
        tk.Frame(quote, width=3, bg=bar).pack(side="left", fill="y", padx=(0, 7))
        inner = tk.Frame(quote, bg=bubble_bg)
        inner.pack(side="left")
        if reply.get("deleted"):
            tk.Label(inner, text="Original message deleted", bg=bubble_bg, fg=time_fg,
                     font=(self.f.tiny[0], self.f.tiny[1], "italic")).pack(anchor="w")
        else:
            tk.Label(inner, text=reply.get("sender", ""), bg=bubble_bg, fg=text_fg,
                     font=(self.f.tiny[0], self.f.tiny[1], "bold")).pack(anchor="w")
            tk.Label(inner, text=reply.get("snippet", ""), bg=bubble_bg, fg=time_fg, font=self.f.tiny,
                     justify="left").pack(anchor="w")
        bind_click(quote, lambda _e, r=record, target=reply["id"]: self._on_action("goto", r, target))

    def _build_reactions(self, body: tk.Frame, record: Record) -> None:
        p = self.p
        me = self._me().lower()
        strip = tk.Frame(body, bg=p["panel"])
        strip.pack(anchor="e" if record.mine else "w", pady=(3, 0))
        for emoji, users in record.reactions:
            mine = me in (u.lower() for u in users)
            pill = tk.Label(
                strip, text=f"{emoji} {len(users)}", font=self.f.small, padx=8, pady=1, cursor="hand2",
                bg=p["selected"] if mine else p["pill_bg"], fg=p["accent"] if mine else p["text"],
            )
            pill.pack(side="left", padx=(0, 4))
            pill.bind("<Button-1>", lambda _e, r=record, e=emoji: self._on_action("react", r, e))


class EmojiPicker(tk.Toplevel):
    COLUMNS = 8

    def __init__(self, parent, palette, fonts, on_pick: Callable[[str], None], anchor: tk.Misc):
        super().__init__(parent)
        self.title("Emoji")
        self.resizable(False, False)
        self.configure(bg=palette["card"], padx=6, pady=6)
        self.transient(parent)
        for index, emoji in enumerate(EMOJIS):
            label = tk.Label(self, text=emoji, font=fonts.emoji, bg=palette["card"], cursor="hand2", padx=4, pady=2)
            label.grid(row=index // self.COLUMNS, column=index % self.COLUMNS)
            label.bind("<Button-1>", lambda _e, value=emoji: self._pick(value, on_pick))
            label.bind("<Enter>", lambda _e, w=label: w.configure(bg=palette["selected"]))
            label.bind("<Leave>", lambda _e, w=label: w.configure(bg=palette["card"]))
        self.bind("<Escape>", lambda _e: self.destroy())
        self.update_idletasks()
        x = anchor.winfo_rootx()
        y = max(0, anchor.winfo_rooty() - self.winfo_reqheight() - 8)
        self.geometry(f"+{x}+{y}")

    def _pick(self, emoji: str, on_pick) -> None:
        on_pick(emoji)
        self.destroy()
