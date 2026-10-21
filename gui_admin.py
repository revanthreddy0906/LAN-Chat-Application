"""The admin console: manage people, read the audit log, change server settings.

It is a separate window that talks to the server with the same chat connection
(`admin_*` events). The server checks the role on every request, so this window
is a convenience, not the thing that keeps non-admins out.
"""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from permissions import ROLES

KNOWN_ACTIONS = [
    "", "login", "login_failed", "lockout", "account_created", "role_changed", "user_disabled", "user_enabled",
    "user_kicked", "password_changed", "password_reset", "sessions_revoked", "user_created", "file_shared",
    "message_deleted", "setting_changed", "data_exported", "rate_limited", "denied", "audit_verified",
]


def when(timestamp) -> str:
    return time.strftime("%d %b %H:%M:%S", time.localtime(timestamp)) if timestamp else "never"


class AdminConsole:
    def __init__(self, app) -> None:
        self.app = app
        self.p = app.p
        self.window = tk.Toplevel(app.root)
        self.window.title("Admin console")
        self.window.geometry(f"860x560+{app.root.winfo_rootx() + 40}+{app.root.winfo_rooty() + 40}")
        self.window.minsize(720, 480)
        self.window.configure(bg=self.p["bg"])
        self.window.transient(app.root)  # stay in front of the chat window instead of slipping behind it
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._request = 0
        self.user_page = 0
        self.user_pages = 1
        self.audit_stack: list[int | None] = [None]
        self.audit_rows: list[dict] = []
        self.audit_more = False
        self.setting_vars: dict[str, tk.Variable] = {}

        self.status = tk.Label(self.window, text="", anchor="w", bg=self.p["bg"], fg=self.p["muted"],
                               font=app.f.small, padx=12, pady=6)
        self.status.pack(side="bottom", fill="x")
        self.tabs = ttk.Notebook(self.window)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(10, 0))
        self.users_tab = self._frame()
        self.audit_tab = self._frame()
        self.settings_tab = self._frame()
        self.tabs.add(self.users_tab, text="People")
        self.tabs.add(self.audit_tab, text="Audit log")
        self.tabs.add(self.settings_tab, text="Settings")
        self._build_users()
        self._build_audit()
        self._build_settings()
        self.refresh_users()
        self.load_audit(reset=True)
        self.send({"t": "admin_settings"})

    # ----- plumbing

    def _frame(self) -> tk.Frame:
        return tk.Frame(self.tabs, bg=self.p["bg"], padx=10, pady=10)

    def _button(self, parent, text, command) -> ttk.Button:
        button = ttk.Button(parent, text=text, command=command)
        button.pack(side="left", padx=(0, 6))
        return button

    def send(self, event: dict) -> None:
        self._request += 1
        event["req"] = self._request
        self.app._send_event(event)

    def say(self, text: str, ok: bool = True) -> None:
        self.status.configure(text=text, fg=self.p["join"] if ok else self.p["error"])

    def close(self) -> None:
        self.app.admin_console = None
        self.window.destroy()

    def lift(self) -> None:
        self.window.lift()
        self.window.focus_force()

    # ----- people

    def _build_users(self) -> None:
        columns = ("name", "role", "state", "seen", "sessions")
        self.users_tree = ttk.Treeview(self.users_tab, columns=columns, show="headings", height=11, selectmode="browse")
        for column, title, width in (("name", "Name", 170), ("role", "Role", 90), ("state", "Status", 110),
                                     ("seen", "Last seen", 160), ("sessions", "Saved sign-ins", 110)):
            self.users_tree.heading(column, text=title)
            self.users_tree.column(column, width=width, anchor="w")
        self.users_tree.pack(fill="both", expand=True)
        bar = tk.Frame(self.users_tab, bg=self.p["bg"])
        bar.pack(fill="x", pady=(8, 0))
        self.role_choice = ttk.Combobox(bar, values=list(ROLES), state="readonly", width=9)
        self.role_choice.set("member")
        self.role_choice.pack(side="left", padx=(0, 4))
        self._button(bar, "Set role", self.set_role)
        self._button(bar, "Disable / enable", self.toggle_disabled)
        self._button(bar, "Disconnect", lambda: self.act("kick"))
        self._button(bar, "Sign out everywhere", lambda: self.act("signout"))
        self._button(bar, "Reset password", self.reset_password)
        bar2 = tk.Frame(self.users_tab, bg=self.p["bg"])
        bar2.pack(fill="x", pady=(6, 0))
        self._button(bar2, "Add person…", self.add_user)
        self._button(bar2, "Refresh", self.refresh_users)
        self.users_paging = tk.Label(bar2, text="", bg=self.p["bg"], fg=self.p["muted"], font=self.app.f.small)
        self.users_paging.pack(side="right")
        self._button(bar2, "Next ›", lambda: self.page_users(1)).pack_configure(side="right")
        self._button(bar2, "‹ Previous", lambda: self.page_users(-1)).pack_configure(side="right")

    def refresh_users(self) -> None:
        self.send({"t": "admin_users", "page": self.user_page})

    def page_users(self, step: int) -> None:
        self.user_page = max(0, min(self.user_pages - 1, self.user_page + step))
        self.refresh_users()

    def selected_user(self) -> dict | None:
        selection = self.users_tree.selection()
        if not selection:
            self.say("Choose a person in the list first.", ok=False)
            return None
        return self._users_by_id.get(selection[0])

    _users_by_id: dict = {}

    def act(self, op: str, value=None) -> None:
        user = self.selected_user()
        if user:
            self.send({"t": "admin", "op": op, "user": user["name"], "value": value})

    def set_role(self) -> None:
        self.act("role", self.role_choice.get())

    def toggle_disabled(self) -> None:
        user = self.selected_user()
        if not user:
            return
        if user["disabled"]:
            self.act("enable")
        elif messagebox.askyesno("Disable account?", f"{user['name']} will be signed out and unable to sign in.",
                                 parent=self.window):
            self.act("disable")

    def reset_password(self) -> None:
        user = self.selected_user()
        if user and messagebox.askyesno(
                "Reset password?", f"Give {user['name']} a new temporary password? They will be signed out.",
                parent=self.window):
            self.act("reset_password")

    def add_user(self) -> None:
        name = simpledialog.askstring("Add person", "Username:", parent=self.window)
        if not name:
            return
        password = simpledialog.askstring("Add person", f"Starting password for {name}:", parent=self.window, show="•")
        if password:
            self.send({"t": "admin", "op": "create_user", "user": name.strip(), "value": password})

    def on_users(self, event: dict) -> None:
        self.user_page, self.user_pages = event["page"], event["pages"]
        self.users_tree.delete(*self.users_tree.get_children())
        self._users_by_id = {}
        for user in event["users"]:
            state = "disabled" if user["disabled"] else ("online" if user["online"] else "offline")
            item = self.users_tree.insert("", "end", values=(
                user["name"], user["role"], state, "now" if user["online"] else when(user["last_seen"]),
                user["sessions"]))
            self._users_by_id[item] = user
        self.users_paging.configure(text=f"{event['total']} people · page {self.user_page + 1}/{self.user_pages}")

    # ----- audit log

    def _build_audit(self) -> None:
        bar = tk.Frame(self.audit_tab, bg=self.p["bg"])
        bar.pack(fill="x", pady=(0, 6))
        tk.Label(bar, text="Person:", bg=self.p["bg"], fg=self.p["text"], font=self.app.f.small).pack(side="left")
        self.audit_actor = ttk.Entry(bar, width=14)
        self.audit_actor.pack(side="left", padx=(4, 10))
        tk.Label(bar, text="Action:", bg=self.p["bg"], fg=self.p["text"], font=self.app.f.small).pack(side="left")
        self.audit_action = ttk.Combobox(bar, values=KNOWN_ACTIONS, width=18)
        self.audit_action.pack(side="left", padx=(4, 10))
        self._button(bar, "Filter", lambda: self.load_audit(reset=True))
        self._button(bar, "Verify chain", self.verify)
        columns = ("when", "who", "action", "target", "detail")
        self.audit_tree = ttk.Treeview(self.audit_tab, columns=columns, show="headings", height=11)
        for column, title, width in (("when", "When", 130), ("who", "Who", 110), ("action", "Action", 130),
                                     ("target", "Target", 140), ("detail", "Detail", 230)):
            self.audit_tree.heading(column, text=title)
            self.audit_tree.column(column, width=width, anchor="w")
        self.audit_tree.pack(fill="both", expand=True)
        bottom = tk.Frame(self.audit_tab, bg=self.p["bg"])
        bottom.pack(fill="x", pady=(8, 0))
        self.newer_button = self._button(bottom, "‹ Newer", self.newer)
        self.older_button = self._button(bottom, "Older ›", self.older)
        self.verify_label = tk.Label(bottom, text="", bg=self.p["bg"], fg=self.p["muted"], font=self.app.f.small_bold)
        self.verify_label.pack(side="right")

    def load_audit(self, reset: bool = False) -> None:
        if reset:
            self.audit_stack = [None]
        self.send({"t": "admin_audit", "actor": self.audit_actor.get().strip(),
                   "action": self.audit_action.get().strip(), "before": self.audit_stack[-1]})

    def older(self) -> None:
        if self.audit_more and self.audit_rows:
            self.audit_stack.append(self.audit_rows[-1]["id"])
            self.load_audit()

    def newer(self) -> None:
        if len(self.audit_stack) > 1:
            self.audit_stack.pop()
            self.load_audit()

    def verify(self) -> None:
        self.verify_label.configure(text="Checking…", fg=self.p["muted"])
        self.send({"t": "admin_verify"})

    def on_audit(self, event: dict) -> None:
        self.audit_rows, self.audit_more = event["rows"], event["has_more"]
        self.audit_tree.delete(*self.audit_tree.get_children())
        for row in self.audit_rows:
            self.audit_tree.insert("", "end", values=(when(row["ts"]), row["actor"], row["action"],
                                                      row["target"], row["detail"]))
        self.say(f"{event['total']} entries in the audit log.")

    def on_verify(self, event: dict) -> None:
        if event["ok"]:
            self.verify_label.configure(text=f"✓ {event['message']}", fg=self.p["join"])
        else:
            self.verify_label.configure(text=f"✗ {event['message']}", fg=self.p["error"])

    # ----- settings

    def _build_settings(self) -> None:
        frame = self.settings_tab
        self.setting_vars = {
            "open_registration": tk.BooleanVar(value=True),
            "max_upload_mb": tk.StringVar(), "user_quota_mb": tk.StringVar(),
            "password_min": tk.StringVar(), "blocked": tk.StringVar(), "e2ee_policy": tk.StringVar(value="optional"),
        }

        def row(label: str, widget_factory, hint: str = "") -> None:
            line = tk.Frame(frame, bg=self.p["bg"])
            line.pack(fill="x", pady=5)
            tk.Label(line, text=label, width=30, anchor="w", bg=self.p["bg"], fg=self.p["text"],
                     font=self.app.f.body).pack(side="left")
            widget_factory(line).pack(side="left")
            if hint:
                tk.Label(line, text=hint, bg=self.p["bg"], fg=self.p["muted"], font=self.app.f.small).pack(side="left", padx=8)

        row("Anyone can create an account", lambda f: ttk.Checkbutton(f, variable=self.setting_vars["open_registration"]),
            "off = only admins can add people")
        row("Largest file (MB)", lambda f: ttk.Spinbox(f, from_=1, to=2048, width=8, textvariable=self.setting_vars["max_upload_mb"]))
        row("File space per person (MB)", lambda f: ttk.Spinbox(f, from_=1, to=100000, width=8, textvariable=self.setting_vars["user_quota_mb"]))
        row("Shortest new password", lambda f: ttk.Spinbox(f, from_=4, to=64, width=8, textvariable=self.setting_vars["password_min"]),
            "applies to new accounts and changes")
        row("End-to-end encryption", lambda f: ttk.Combobox(f, values=["off", "optional", "required"], width=10, state="readonly",
                                                         textvariable=self.setting_vars["e2ee_policy"]),
            "required = private messages must be encrypted")
        row("Blocked file types", lambda f: ttk.Entry(f, width=34, textvariable=self.setting_vars["blocked"]),
            "comma separated")
        bar = tk.Frame(frame, bg=self.p["bg"])
        bar.pack(fill="x", pady=(14, 0))
        self._button(bar, "Save settings", self.save_settings)
        self._button(bar, "Reload", lambda: self.send({"t": "admin_settings"}))

    def on_settings(self, event: dict) -> None:
        self.setting_vars["open_registration"].set(bool(event["open_registration"]))
        self.setting_vars["max_upload_mb"].set(str(event["max_upload_mb"]))
        self.setting_vars["user_quota_mb"].set(str(event["user_quota_mb"]))
        self.setting_vars["password_min"].set(str(event["password_min"]))
        self.setting_vars["blocked"].set(", ".join(event["blocked"]))
        self.setting_vars["e2ee_policy"].set(event.get("e2ee_policy", "optional"))

    def save_settings(self) -> None:
        for key, var in self.setting_vars.items():
            self.send({"t": "admin", "op": "set_setting", "user": key, "value": var.get()})

    # ----- replies

    def on_result(self, event: dict) -> None:
        self.say(event.get("message", ""), ok=bool(event.get("ok")))
        if event.get("password"):
            messagebox.showinfo("Temporary password",
                                f"Give this to the person (shown once):\n\n{event['password']}", parent=self.window)
        if event.get("settings"):
            self.on_settings({**event["settings"]})
        if event.get("ok"):
            self.refresh_users()
            self.load_audit(reset=False)

    def handle(self, event: dict) -> None:
        handler = {
            "admin_users": self.on_users, "admin_audit": self.on_audit, "admin_verify": self.on_verify,
            "admin_settings": self.on_settings, "admin_result": self.on_result,
        }.get(event["t"])
        if handler:
            handler(event)
