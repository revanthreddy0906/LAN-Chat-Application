"""Encryption keys in the chat window: setting them up, unlocking, restoring, and verifying contacts.

`E2EEManager` holds the logic and talks to the server; the dialogs only collect input and show
results, so every flow can also be driven without clicking (the scripted tests do that).

States: "unavailable" (no `cryptography` package), "needs_setup", "needs_restore", "locked",
"ready", "skipped" (the person chose to carry on without end-to-end encryption this session).
"""

from __future__ import annotations

import re
import tkinter as tk
from typing import Callable

import e2ee
from e2ee import Bundle, CryptoError, Identity
from events import snippet, snippet_around
from keystore import KeyStore, server_id
from storage import sanitize_name

MIN_PASSPHRASE = 8


def passphrase_problem(passphrase: str, confirm: str | None = None) -> str | None:
    if len(passphrase) < MIN_PASSPHRASE:
        return f"Use at least {MIN_PASSPHRASE} characters for the passphrase."
    if confirm is not None and passphrase != confirm:
        return "The two passphrases do not match."
    return None


class E2EEManager:
    def __init__(self, app) -> None:
        self.app = app
        self.state = "off"
        self.identity: Identity | None = None
        self.store: KeyStore | None = None
        self.policy = "optional"
        self.server_has_keys = False
        self.changed: set[str] = set()  # contacts whose key changed since I pinned it
        self.windows: dict[str, tk.Toplevel] = {}
        self._pending: dict[int, Callable[[dict], None]] = {}
        self._next = 1
        self._login_password = ""
        self._user = ""
        self.bundles: dict[str, Bundle | None] = {}  # verified keys from the server; None = no keys published
        self.seen_mids: dict[str, int] = {}  # message ids already opened this session, to spot replays
        self.plain_ok: set[str] = set()  # people I agreed to message without encryption
        self._decrypt_job = None

    # ----- plumbing

    def available(self) -> bool:
        return e2ee.AVAILABLE

    def _request(self, event: dict, callback: Callable[[dict], None] | None = None) -> bool:
        event["req"] = self._next
        if callback is not None:
            self._pending[self._next] = callback
        self._next += 1
        return self.app._send_event(event)

    def handle(self, event: dict) -> None:
        kind = event["t"]
        if kind == "key_changed":
            self._on_key_changed(event)
            return
        callback = self._pending.pop(event.get("req"), None)
        if callback:
            callback(event)

    def remember_password(self, password: str) -> None:
        """Kept only until the welcome arrives, to unlock silently if it is also the passphrase."""
        self._login_password = password

    def forget(self) -> None:
        """Leaving the chat locks everything."""
        self.identity = None
        self.state = "off" if not e2ee.AVAILABLE else "off"
        self._pending.clear()
        self._login_password = ""
        self._user = ""
        self.changed.clear()
        self.bundles.clear()
        self.seen_mids.clear()
        self.plain_ok.clear()
        self._decrypt_job = None
        for window in list(self.windows.values()):
            try:
                window.destroy()
            except tk.TclError:
                pass
        self.windows.clear()

    def label(self) -> str:
        return {
            "ready": "\U0001F511 keys ready",
            "locked": "\U0001F513 keys locked",
            "needs_setup": "\U0001F513 no keys yet",
            "needs_restore": "\U0001F513 keys not on this computer",
            "skipped": "no end-to-end encryption",
            "unavailable": "no end-to-end encryption (install 'cryptography')",
        }.get(self.state, "")

    # ----- start of a session

    def on_welcome(self, event: dict) -> None:
        info = event.get("e2ee") or {}
        self.policy = info.get("policy", "optional")
        self.server_has_keys = bool(info.get("have_keys"))
        app = self.app
        if not e2ee.AVAILABLE:
            self.state = "unavailable"
            app._update_header()
            return
        if self.identity is not None and self._user == app.username.lower():  # a reconnect: still unlocked
            self.state = "ready"
            self._sync_with_server()
            app._update_header()
            self.schedule_decrypt()
            return
        self._user = app.username.lower()
        self.store = KeyStore(app.settings.home, server_id(app.fingerprint, app.server_host, app.server_port),
                              app.username)
        password, self._login_password = self._login_password, ""
        if self.store.exists():
            self.state = "locked"
            if password and self.try_unlock(password):
                return
            app.root.after_idle(self.open_unlock)
        elif self.server_has_keys:
            self.state = "needs_restore"
            app.root.after_idle(self.open_restore)
        else:
            self.state = "needs_setup"
            app.root.after_idle(self.open_setup)
        app._update_header()

    # ----- key lifecycle (called by the dialogs and by tests)

    def setup(self, passphrase: str) -> str:
        """Create keys, publish the public half plus the recovery backup, return the recovery code."""
        problem = passphrase_problem(passphrase)
        if problem:
            raise CryptoError(problem)
        identity, code, backup = self.store.create(passphrase)
        self.identity, self.state = identity, "ready"
        self._publish(identity, backup)
        self.app._update_header()
        self.schedule_decrypt()
        return code

    def _publish(self, identity: Identity, backup: dict | None = None, callback=None) -> None:
        event = {"t": "keys_publish", **identity.public().to_dict()}
        if backup is not None:
            event["backup"] = backup
        self._request(event, callback or (lambda reply: None if reply.get("ok") else self.app.notice(
            f"Could not publish your encryption keys: {reply.get('reason', 'refused')}")))

    def try_unlock(self, passphrase: str) -> bool:
        try:
            self.identity = self.store.unlock(passphrase)
        except CryptoError:
            return False
        self.state = "ready"
        self._sync_with_server()
        self.app._update_header()
        self.schedule_decrypt()
        return True

    def _sync_with_server(self) -> None:
        """Make sure the server holds the public keys that match this computer's."""
        me = self.app.username
        mine = self.identity.public()

        def compare(reply: dict) -> None:
            theirs = (reply.get("keys") or {}).get(me)
            if theirs is None:
                self._publish(self.identity)  # the server lost them (for example a restored database)
            elif theirs["fingerprint"] != mine.fingerprint():
                self.app.notice("The encryption keys the server holds for you are different from the ones on this "
                                "computer. Open ⋯ → Encryption keys… to choose which to keep.")
        self._request({"t": "keys_get", "names": [me]}, compare)

    def start_restore(self, code: str, passphrase: str, done: Callable[[bool, str], None]) -> None:
        problem = passphrase_problem(passphrase)
        if problem or not e2ee.valid_recovery_code(code):
            done(False, problem or "A recovery code is 24 letters and digits, like ABCD-EFGH-…")
            return

        def got(reply: dict) -> None:
            backup = reply.get("backup")
            if not backup:
                done(False, "The server has no backup for your account. Start over to make new keys.")
                return
            try:
                self.identity = self.store.restore(code, backup, passphrase)
            except CryptoError as error:
                done(False, str(error))
                return
            self.state = "ready"
            self._sync_with_server()
            self.app._update_header()
            self.schedule_decrypt()
            done(True, "")
        self._request({"t": "keys_backup_get"}, got)

    def reset_keys(self) -> None:
        """Throw away my keys everywhere. Contacts will see that my security code changed."""
        self._request({"t": "keys_reset"})
        if self.store is not None:
            self.store.reset()
        self.identity, self.state, self.server_has_keys = None, "needs_setup", False
        self.app._update_header()
        self.app.root.after_idle(self.open_setup)

    def change_passphrase(self, old: str, new: str) -> str | None:
        problem = passphrase_problem(new)
        if problem:
            return problem
        try:
            self.store.change_passphrase(old, new)
        except CryptoError as error:
            return str(error)
        return None

    # ----- contacts

    def lookup(self, names: list[str], done: Callable[[dict[str, Bundle]], None]) -> None:
        """Fetch and verify other people's public keys (the server is not trusted to be honest)."""
        def got(reply: dict) -> None:
            verified = {}
            for name, data in (reply.get("keys") or {}).items():
                try:
                    bundle = Bundle.from_dict(data)
                except CryptoError:
                    continue
                if bundle.verify():
                    verified[name] = bundle
            done(verified)
        self._request({"t": "keys_get", "names": names}, got)

    def contact_status(self, name: str, bundle: Bundle) -> str:
        return self.store.check_contact(name, bundle) if self.store else "new"

    def badge(self, name: str) -> str:
        if self.store is None or name.lower() == self.app.username.lower():
            return ""
        if name.lower() in self.changed:
            return "⚠"
        return "✔" if self.store.is_verified(name) else ""

    def accept_key(self, name: str, bundle: Bundle) -> None:
        self.store.pin_contact(name, bundle)
        self.changed.discard(name.lower())
        self.app._render_users()

    def mark_verified(self, name: str, bundle: Bundle) -> None:
        if self.store.check_contact(name, bundle) == "new":
            self.store.pin_contact(name, bundle)
        self.store.mark_verified(name)
        self.app._render_users()

    def _on_key_changed(self, event: dict) -> None:
        name = event.get("user", "")
        self.bundles.pop(name.lower(), None)  # look it up again next time
        if self.app.private_to and self.app.private_to.lower() == name.lower():
            self.ensure_contacts([name], self.app._update_private_chip)
        if self.store is not None and not event.get("created") and self.store.contact(name):
            self.changed.add(name.lower())
            what = "reset their encryption keys" if event.get("reset") else "has a new security code"
            self.app.notice(f"⚠ {name} {what}. Verify it again before trusting new messages "
                            f"(right-click {name} in the member list).")
            self.app._render_users()

    # ----- private messages: sending, opening, searching

    def ensure_contacts(self, names: list[str], done: Callable[[], None] | None = None) -> None:
        """Make sure I know the public keys (or the lack of them) of these people, then call `done`."""
        me = self.app.username.lower()
        missing = [n for n in names if n.lower() != me and n.lower() not in self.bundles]
        if not missing or not e2ee.AVAILABLE:
            if done:
                done()
            return

        def got(found: dict[str, Bundle]) -> None:
            for name, bundle in found.items():
                self.bundles[name.lower()] = bundle
            for name in missing:
                self.bundles.setdefault(name.lower(), None)
            if done:
                done()
        self.lookup(missing, got)

    def private_label(self, name: str) -> str:
        """The text of the chip above the message box for a private conversation."""
        if not e2ee.AVAILABLE or self.policy == "off":
            return f"\U0001F513 Private to {name} · not end-to-end encrypted"
        if self.state != "ready":
            return f"\U0001F513 Private to {name} · your keys are not unlocked"
        if name.lower() not in self.bundles:
            return f"\U0001F512 Private to {name}"
        bundle = self.bundles[name.lower()]
        if bundle is None:
            return f"\U0001F513 Private to {name} · {name} has no encryption keys yet"
        if self.contact_status(name, bundle) == "changed":
            return f"⚠ Private to {name} · their security code changed"
        return f"\U0001F512 End-to-end encrypted with {name}" + (" ✔" if self.store.is_verified(name) else "")

    def _resolve(self, to: str, plain: Callable[[], None], refuse: Callable[[str], None],
                 secure: Callable[[Bundle], None]) -> None:
        """Decide how to reach `to`: send plain (only if allowed), refuse with a reason, or encrypt for their key."""
        app = self.app
        if not e2ee.AVAILABLE or self.policy == "off":
            plain()
            return
        if self.state != "ready":
            if self.policy == "required":
                refuse("This server requires end-to-end encryption for private messages and files. "
                       "Set up or unlock your keys first (⋯ → Encryption keys…).")
            else:
                plain()
            return

        def go() -> None:
            bundle = self.bundles.get(to.lower())
            if bundle is None:
                if self.policy == "required":
                    refuse(f"{to} has not set up encryption yet, and this server requires it for private messages.")
                    return
                if to.lower() not in self.plain_ok:
                    if not app.confirm(f"{to} has no encryption keys",
                                       f"{to} has not set up end-to-end encryption, so this could be read by "
                                       "the server (it is still protected on the network by TLS). Send it anyway?"):
                        refuse("")
                        return
                    self.plain_ok.add(to.lower())
                plain()
                return
            status = self.contact_status(to, bundle)
            if status == "changed":
                self.changed.add(to.lower())
                app._render_users()
                refuse(f"⚠ {to}'s security code changed, so nothing was sent. Check it with them, then accept "
                       f"the new code (right-click {to} → Verify security code).")
                app.root.after_idle(lambda: self.open_verify(to))
                return
            if status == "new":
                self.store.pin_contact(to, bundle)
                app.notice(f"Messages with {to} are now end-to-end encrypted. To be sure it really is {to}, compare "
                           "security codes (right-click their name → Verify security code).", tone="system")
            secure(bundle)
            app._update_private_chip()

        self.ensure_contacts([to], go)

    def send_private(self, text: str, to: str, reply_id: int | None, done: Callable[[dict | None], None]) -> None:
        """Turn a private message into the event to send: encrypted when possible, plain only if allowed.

        `done(event)` gets the event, or None when the message was refused (the reason is shown)."""
        app = self.app
        extra = {"reply_to": reply_id} if reply_id else {}
        size = len(text.encode("utf-8"))
        if self.state == "ready" and e2ee.AVAILABLE and self.policy != "off" and size > e2ee.MAX_TEXT_BYTES:
            app.notice(f"Encrypted messages can be up to {e2ee.MAX_TEXT_BYTES} bytes; this one is {size}. Please shorten it.")
            done(None)
            return

        def refuse(reason: str) -> None:
            if reason:
                app.notice(reason)
            done(None)

        def secure(bundle: Bundle) -> None:
            envelope = e2ee.encrypt_message(e2ee.encode_payload(text), self.identity, app.username, {to: bundle})
            done({"t": "send", "to": to, "enc": envelope, **extra})

        self._resolve(to, lambda: done({"t": "send", "to": to, "body": text, **extra}), refuse, secure)

    def plan_file(self, to: str, decided: Callable[[object], None]) -> None:
        """How should a file for `to` travel? `decided` gets "plain", "refuse" or the recipient's key bundle."""
        def refuse(reason: str) -> None:
            if reason:
                self.app.notice(reason)
            decided("refuse")

        self._resolve(to, lambda: decided("plain"), refuse, decided)

    def file_envelope(self, to: str, bundle: Bundle, caption: str, description: dict) -> dict | None:
        """The encrypted message that accompanies an encrypted file (its name, type, key and caption)."""
        envelope = e2ee.encrypt_message(e2ee.encode_payload(caption, description), self.identity,
                                        self.app.username, {to: bundle})
        return envelope if e2ee.envelope_size(envelope) <= e2ee.MAX_ENVELOPE_CHARS else None

    def edit_event(self, record, text: str) -> dict | None:
        """The edit event for one of my encrypted messages (a new envelope), or None if it cannot be made."""
        app = self.app
        size = len(text.encode("utf-8"))
        known = self.store.contact(record.name) if self.store else None
        if self.identity is None or known is None:
            app.notice("Unlock your encryption keys to edit this message.")
            return None
        bundle = Bundle.from_dict(known["bundle"])
        fresh = self.bundles.get(record.name.lower())
        if fresh is not None and fresh.fingerprint() != bundle.fingerprint():
            app.notice(f"⚠ {record.name}'s security code changed; verify it before editing this message.")
            return None
        if size > e2ee.MAX_TEXT_BYTES:
            app.notice(f"Encrypted messages can be up to {e2ee.MAX_TEXT_BYTES} bytes; this one is {size}.")
            return None
        envelope = e2ee.encrypt_message(e2ee.encode_payload(text, record.file), self.identity, app.username,
                                        {record.name: bundle})
        if e2ee.envelope_size(envelope) > e2ee.MAX_ENVELOPE_CHARS:
            app.notice("That caption is too long for an encrypted file message.")
            return None
        return {"t": "edit", "id": record.id, "enc": envelope}

    def schedule_decrypt(self) -> None:
        if self._decrypt_job is None:
            self._decrypt_job = self.app.root.after_idle(self._run_decrypt)

    def _undecrypted(self) -> list:
        return [r for r in self.app.messages.records if r.enc and r.secure in ("pending", "locked")]

    def _run_decrypt(self) -> None:
        self._decrypt_job = None
        pending = self._undecrypted()
        if not pending:
            self._fix_replies()
            return
        if self.identity is None or not e2ee.AVAILABLE:
            for record in pending:
                if record.secure != "locked":
                    record.secure = "locked"
                    record.text = "\U0001F512 Encrypted message. Unlock your keys (⋯ → Encryption keys…) to read it."
                    self.app.messages.refresh(record)
            return
        names = {r.sender for r in pending}
        self.ensure_contacts(sorted(names), lambda: self._decrypt(pending))

    def _sender_bundles(self, name: str) -> list[Bundle]:
        """The keys to check a sender against: my own, those I pinned (newest first), or at first sight the server's."""
        if name.lower() == self.app.username.lower():
            return [self.identity.public()]
        fresh = self.bundles.get(name.lower())
        pinned_all = self.store.bundles_for(name)
        if pinned_all:
            pinned = pinned_all[0]
            if fresh is not None and fresh.fingerprint() != pinned.fingerprint() and name.lower() not in self.changed:
                self.changed.add(name.lower())
                self.app.notice(f"⚠ {name} has a new security code. Their messages are checked against the old one "
                                "until you verify the new one (right-click their name).")
                self.app._render_users()
            return pinned_all  # never trust the server's newer key for messages that claim to be from before
        if fresh is not None:
            self.store.pin_contact(name, fresh)
            return [fresh]
        return []

    def _decrypt(self, pending: list) -> None:
        app = self.app
        for record in pending:
            if record.secure not in ("pending", "locked") or not record.enc or self.identity is None:
                continue

            def fail(reason: str, record=record) -> None:
                record.secure = "failed"
                record.text = f"⚠ Could not open this message: {reason}."
                app.messages.refresh(record)

            candidates = self._sender_bundles(record.sender)
            if not candidates:
                fail(f"{record.sender} has no encryption keys on the server")
                continue
            payload, last_error = None, ""
            for bundle in candidates:
                try:
                    payload = e2ee.decode_payload(e2ee.decrypt_message(
                        record.enc, self.identity, app.username, record.sender, bundle))
                    break
                except CryptoError as error:
                    last_error = str(error)
            if payload is None:
                fail(last_error)
                continue
            earlier = self.seen_mids.get(payload["mid"])
            if earlier is not None and earlier != record.id:
                fail("it is a copy of an earlier message (possible replay)")
                continue
            if record.att and record.att.get("kind") == "encrypted" and not payload.get("f"):
                fail("the description of the file is missing")
                continue
            self.seen_mids[payload["mid"]] = record.id
            record.text, record.secure = payload["b"], "e2ee"
            if payload.get("f") and record.att:
                self._attach_file(record, payload["f"])
            app.messages.refresh(record)
            if record.file:
                app.media.ensure_preview(record)
        self._fix_replies()

    @staticmethod
    def _attach_file(record, info: dict) -> None:
        """The message says what the file is: show that, and remember the key that opens it."""
        original = record.att
        record.file = info
        record.att = {"id": original["id"], "name": sanitize_name(info["name"]), "mime": info["mime"],
                      "size": info["size"], "kind": info["kind"], "sha256": original["sha256"],
                      "key": info["key"], "cipher_size": original.get("cipher_size", original["size"])}

    def _fix_replies(self) -> None:
        """Quote encrypted messages in replies, now that this window can read them."""
        messages = self.app.messages
        for record in messages.records:
            reply = record.reply
            if not reply or not reply.get("encrypted"):
                continue
            parent = messages.record_for(reply["id"])
            if parent is not None and parent.secure == "e2ee" and reply.get("snippet") != snippet(parent.text):
                record.reply = {**reply, "snippet": snippet(parent.text)}
                messages.refresh(record)

    def search_local(self, query: str) -> list[dict]:
        """Matches among decrypted messages on screen (the server cannot search what it cannot read)."""
        terms = re.findall(r"\w+", query.lower())[:8]
        if not terms:
            return []
        me = self.app.username
        found = []
        for record in self.app.messages.records:
            if record.secure == "e2ee" and record.id and all(term in record.text.lower() for term in terms):
                found.append({"id": record.id, "sender": record.sender, "ts": record.ts,
                               "to": record.name if record.mine else me,
                               "snippet": snippet_around(record.text, terms)})
        return found

    # ----- dialogs

    def _window(self, key: str, title: str, width: int = 420) -> tuple[tk.Toplevel, tk.Frame] | None:
        existing = self.windows.get(key)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            return None
        app = self.app
        window = tk.Toplevel(app.root)
        window.title(title)
        window.configure(bg=app.p["bg"])
        window.transient(app.root)
        window.resizable(False, False)
        body = tk.Frame(window, bg=app.p["bg"], padx=22, pady=18, width=width)
        body.pack(fill="both", expand=True)
        self.windows[key] = window
        window.protocol("WM_DELETE_WINDOW", lambda: self._close(key))
        return window, body

    def _close(self, key: str) -> None:
        window = self.windows.pop(key, None)
        if window is not None:
            try:
                window.destroy()
            except tk.TclError:
                pass

    def _label(self, parent, text: str, **options) -> tk.Label:
        p, f = self.app.p, self.app.f
        defaults = dict(bg=p["bg"], fg=p["text"], font=f.body, justify="left", anchor="w", wraplength=380)
        defaults.update(options)
        label = tk.Label(parent, text=text, **defaults)
        label.pack(fill="x", pady=(0, 6))
        return label

    def _entry(self, parent, show: str = "•") -> tk.Entry:
        entry = tk.Entry(parent, show=show, width=36, font=self.app.f.body)
        entry.pack(fill="x", pady=(0, 6))
        return entry

    def open_setup(self) -> None:
        made = self._window("setup", "Set up end-to-end encryption")
        if made is None or self.state != "needs_setup":
            return
        window, body = made
        p, f = self.app.p, self.app.f
        self._label(body, "Protect your private conversations", font=f.title)
        self._label(body, "Messages and files you send to a person are locked on your computer and can only be "
                          "opened on theirs. Not even the person hosting this chat can read them.")
        self._label(body, f"Choose a passphrase for the keys on this computer ({MIN_PASSPHRASE}+ characters):",
                    fg=p["muted"])
        first, second = self._entry(body), self._entry(body)
        message = self._label(body, "", fg=p["error"])
        buttons = tk.Frame(body, bg=p["bg"])
        buttons.pack(fill="x", pady=(8, 0))

        def create() -> None:
            problem = passphrase_problem(first.get(), second.get())
            if problem:
                message.configure(text=problem)
                return
            try:
                code = self.setup(first.get())
            except CryptoError as error:
                message.configure(text=str(error))
                return
            self._show_recovery(body, code, window)

        def later() -> None:
            self.state = "skipped"
            self.app._update_header()
            self._close("setup")

        self.app.button(buttons, "Create my keys", create, pady=6).pack(side="right")
        self.app.button(buttons, "Not now", later, kind="secondary", pady=6).pack(side="right", padx=(0, 8))
        window.protocol("WM_DELETE_WINDOW", later)
        first.focus_set()
        self.setup_widgets = {"first": first, "second": second, "message": message, "create": create, "later": later}

    def _show_recovery(self, body: tk.Frame, code: str, window: tk.Toplevel) -> None:
        """Step two: the recovery code, shown once. The window cannot be closed until it is confirmed."""
        p, f = self.app.p, self.app.f
        for child in body.winfo_children():
            child.destroy()
        self._label(body, "Write down your recovery code", font=f.title)
        self._label(body, "If you lose this computer or forget your passphrase, this code is the only way to get "
                          "your keys back. It will not be shown again. Keep it somewhere safe, not in this chat.")
        shown = tk.Label(body, text=code, bg=p["card"], fg=p["text"], font=(f.body[0], 17, "bold"),
                         padx=14, pady=12, relief="flat")
        shown.pack(fill="x", pady=(2, 8))
        saved = tk.BooleanVar(value=False)
        done = self.app.button(body, "Done", lambda: self._close("setup"), pady=6)

        def toggle() -> None:
            done.set_disabled(not saved.get())

        def copy() -> None:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(code)

        check = tk.Checkbutton(body, text="I have saved my recovery code", variable=saved, command=toggle,
                               bg=p["bg"], fg=p["text"], selectcolor=p["card"], activebackground=p["bg"],
                               font=f.body, anchor="w")
        check.pack(fill="x")
        row = tk.Frame(body, bg=p["bg"])
        row.pack(fill="x", pady=(10, 0))
        done.pack(in_=row, side="right")
        self.app.button(row, "Copy", copy, kind="secondary", pady=6).pack(side="right", padx=(0, 8))
        done.set_disabled(True)
        window.protocol("WM_DELETE_WINDOW", lambda: None)  # must confirm first
        self.recovery_widgets = {"code": code, "saved": saved, "done": done, "toggle": toggle}

    def open_unlock(self) -> None:
        made = self._window("unlock", "Unlock your encryption keys")
        if made is None or self.state != "locked":
            return
        window, body = made
        p = self.app.p
        self._label(body, "Unlock your encryption keys", font=self.app.f.title)
        self._label(body, "Enter the passphrase for the keys on this computer.")
        entry = self._entry(body)
        message = self._label(body, "", fg=p["error"])
        buttons = tk.Frame(body, bg=p["bg"])
        buttons.pack(fill="x", pady=(8, 0))

        def unlock(_event=None) -> None:
            if self.try_unlock(entry.get()):
                self._close("unlock")
            else:
                message.configure(text="That is not the right passphrase.")

        def skip() -> None:
            self.state = "skipped"
            self.app._update_header()
            self._close("unlock")

        def forgot() -> None:
            self._close("unlock")
            self.state = "needs_restore"
            self.open_restore()

        entry.bind("<Return>", unlock)
        self.app.button(buttons, "Unlock", unlock, pady=6).pack(side="right")
        self.app.button(buttons, "Skip for now", skip, kind="secondary", pady=6).pack(side="right", padx=(0, 8))
        self.app.button(buttons, "Forgot?", forgot, kind="ghost", pady=6, ghost_bg="bg").pack(side="left")
        window.protocol("WM_DELETE_WINDOW", skip)
        entry.focus_set()
        self.unlock_widgets = {"entry": entry, "message": message, "unlock": unlock, "skip": skip, "forgot": forgot}

    def open_restore(self) -> None:
        made = self._window("restore", "Restore your encryption keys")
        if made is None:
            return
        window, body = made
        p = self.app.p
        self._label(body, "Restore your encryption keys", font=self.app.f.title)
        self._label(body, "This chat already has encryption keys for your account, but they are not on this "
                          "computer. Enter the recovery code you saved when you set them up.")
        code = self._entry(body, show="")
        self._label(body, f"Then choose a passphrase for this computer ({MIN_PASSPHRASE}+ characters):", fg=p["muted"])
        first, second = self._entry(body), self._entry(body)
        message = self._label(body, "", fg=p["error"])
        buttons = tk.Frame(body, bg=p["bg"])
        buttons.pack(fill="x", pady=(8, 0))

        def restore() -> None:
            problem = passphrase_problem(first.get(), second.get())
            if problem:
                message.configure(text=problem)
                return
            message.configure(text="Restoring…", fg=p["muted"])

            def done(ok: bool, reason: str) -> None:
                if ok:
                    self._close("restore")
                    self.app.notice("Your encryption keys were restored on this computer.", tone="join")
                else:
                    message.configure(text=reason, fg=p["error"])
            self.start_restore(code.get(), first.get(), done)

        def start_over() -> None:
            if self.app.confirm("Start over?", "This permanently replaces your encryption keys. People you talked "
                                "to will be warned that your security code changed, and old encrypted messages "
                                "will stay unreadable."):
                self._close("restore")
                self.reset_keys()

        def skip() -> None:
            self.state = "skipped"
            self.app._update_header()
            self._close("restore")

        self.app.button(buttons, "Restore", restore, pady=6).pack(side="right")
        self.app.button(buttons, "Not now", skip, kind="secondary", pady=6).pack(side="right", padx=(0, 8))
        self.app.button(buttons, "Start over", start_over, kind="ghost", pady=6, ghost_bg="bg").pack(side="left")
        window.protocol("WM_DELETE_WINDOW", skip)
        code.focus_set()
        self.restore_widgets = {"code": code, "first": first, "second": second, "message": message,
                                "restore": restore, "start_over": start_over, "skip": skip}

    def open_keys(self) -> None:
        """⋯ → Encryption keys…: status, change passphrase, reset."""
        app = self.app
        if not e2ee.AVAILABLE:
            app.notice("End-to-end encryption needs the 'cryptography' package: pip install cryptography", tone="system")
            return
        if self.state == "needs_setup":
            self.open_setup()
            return
        if self.state == "locked":
            self.open_unlock()
            return
        if self.state == "needs_restore":
            self.open_restore()
            return
        made = self._window("keys", "Encryption keys")
        if made is None:
            return
        window, body = made
        p, f = app.p, app.f
        self._label(body, "Your encryption keys", font=f.title)
        if self.identity is None:
            self._label(body, "Keys are not unlocked in this session.")
            app.button(body, "Unlock…", lambda: (self._close("keys"), self._unlock_from_skipped()), pady=6).pack(anchor="e")
            return
        fingerprint = self.identity.public().fingerprint()
        pretty = " ".join(fingerprint[i:i + 4] for i in range(0, 32, 4))
        self._label(body, "Your key fingerprint (the part of your security code that is yours):", fg=p["muted"])
        self._label(body, pretty.upper(), font=(f.body[0], 12, "bold"), wraplength=380)
        self._label(body, f"Server policy: {self.policy} (end-to-end encryption for private messages).", fg=p["muted"])
        buttons = tk.Frame(body, bg=p["bg"])
        buttons.pack(fill="x", pady=(10, 0))

        def reset() -> None:
            if app.confirm("Reset your keys?", "This creates new keys and a new recovery code. People you talked to "
                           "will be warned that your security code changed, and old encrypted messages will become "
                           "unreadable."):
                self._close("keys")
                self.reset_keys()

        app.button(buttons, "Reset keys…", reset, kind="secondary", pady=6).pack(side="left")
        app.button(buttons, "Close", lambda: self._close("keys"), pady=6).pack(side="right")

    def _unlock_from_skipped(self) -> None:
        if self.store is not None and self.store.exists():
            self.state = "locked"
            self.open_unlock()
        elif self.server_has_keys:
            self.state = "needs_restore"
            self.open_restore()
        else:
            self.state = "needs_setup"
            self.open_setup()

    def open_verify(self, name: str) -> None:
        """Show the safety number shared with `name`, to compare out loud or in person."""
        if self.identity is None:
            self.app.notice("Unlock your encryption keys first (⋯ → Encryption keys…).", tone="system")
            return
        self.lookup([name], lambda found: self._show_verify(name, found.get(name) or next(
            (b for n, b in found.items() if n.lower() == name.lower()), None)))

    def _show_verify(self, name: str, bundle: Bundle | None) -> None:
        made = self._window(f"verify-{name.lower()}", f"Security code with {name}", 440)
        if made is None:
            return
        window, body = made
        p, f = self.app.p, self.app.f
        if bundle is None:
            self._label(body, f"{name} has not set up end-to-end encryption yet.", font=f.title)
            self._label(body, "Until they do, messages with them are protected on the network but readable by the server.")
            self.app.button(body, "Close", lambda: self._close(f"verify-{name.lower()}"), pady=6).pack(anchor="e")
            return
        status = self.contact_status(name, bundle)
        number = e2ee.safety_number(self.app.username, self.identity.public(), name, bundle)
        groups = number.split()
        self._label(body, f"Security code with {name}", font=f.title)
        self._label(body, "Compare these numbers with the ones on their screen, in person or on a call you trust. "
                          "If they match, nobody (including the server) is sitting between you.")
        grid = tk.Frame(body, bg=p["card"], padx=16, pady=12)
        grid.pack(fill="x", pady=(2, 8))
        for row in range(3):
            tk.Label(grid, text="   ".join(groups[row * 4:(row + 1) * 4]), bg=p["card"], fg=p["text"],
                     font=(f.body[0], 14, "bold")).pack(anchor="w")
        note = {"new": "You have not seen this key before.",
                "same": "This matches the key you saw before.",
                "changed": f"⚠ {name}'s key is DIFFERENT from the one you pinned. Compare the numbers again."}[status]
        verified = self.store.is_verified(name) and status == "same"
        self._label(body, "✔ You marked this as verified." if verified else note,
                    fg=p["join"] if verified else (p["error"] if status == "changed" else p["muted"]))
        buttons = tk.Frame(body, bg=p["bg"])
        buttons.pack(fill="x", pady=(8, 0))

        def mark() -> None:
            if status == "changed":
                self.accept_key(name, bundle)
            self.mark_verified(name, bundle)
            self._close(f"verify-{name.lower()}")

        label = "Accept the new key and mark verified" if status == "changed" else "Mark as verified"
        self.app.button(buttons, label, mark, pady=6).pack(side="right")
        self.app.button(buttons, "Close", lambda: self._close(f"verify-{name.lower()}"), kind="secondary",
                        pady=6).pack(side="right", padx=(0, 8))
        self.verify_widgets = {"number": number, "status": status, "mark": mark}
