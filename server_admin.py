"""Account and administration events for the chat server (mixed into ChatServer).

Everyone can change their own password, sign out and export their own data.
Admin-only events manage users, settings and the audit log; each one checks
the role, and every change is written to the audit log.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from events import encode
from permissions import ROLES, can
from security import check_password

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,32}")
USERS_PER_PAGE = 15
AUDIT_PAGE = 12
MAX_ACTIVE_BYTES = 3700  # stay inside one 4096-byte frame with room for the envelope
EXTENSION_PATTERN = re.compile(r"\.[a-z0-9]{1,10}")


def _mb(value) -> int:
    number = int(value)
    if not 1 <= number <= 100_000:
        raise ValueError("enter a size in megabytes between 1 and 100000")
    return number * 1024 * 1024


class AdminMixin:
    """Needs the host class to provide: store, accounts, _clients, _lock, audit(), _emit(), _error(),
    _info(), _remove_client(), _issue_ticket(), set_role(), login_guard, enforce_password_policy,
    password_min, session_lifetime, max_upload, user_quota, blocked_extensions, open_registration."""

    # ----- changing my own account

    def _change_password(self, client, old: str, new: str) -> tuple[bool, str, str | None]:
        """Returns (ok, reason, new sign-in token)."""
        wait = self.login_guard.retry_after(client.ip, client.username)
        if wait > 0:
            return False, f"too many failed attempts, try again in {int(wait) + 1} seconds", None
        if self.enforce_password_policy:
            problem = check_password(new, client.username, self.password_min)
            if problem:
                return False, f"choose a stronger password ({problem})", None
        if not self.accounts.change_password(client.username, old, new):
            self.login_guard.failed(client.ip, client.username)
            self.audit(client.username, "password_change_failed", detail=f"from {client.ip}")
            return False, "the current password is wrong", None
        self.login_guard.succeeded(client.ip, client.username)
        self.store.delete_user_sessions(client.user_id)  # every other sign-in must use the new password
        token = secrets.token_urlsafe(32)
        client.token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.store.create_session(client.user_id, client.token_hash, self.session_lifetime, client.ip)
        self.audit(client.username, "password_changed")
        return True, "", token

    def _on_passwd(self, client, event: dict) -> None:
        old, new = event.get("old"), event.get("new")
        if not isinstance(old, str) or not isinstance(new, str):
            self._emit({"t": "passwd_result", "ok": False, "reason": "malformed request"}, [client])
            return
        ok, reason, token = self._change_password(client, old, new)
        self._emit({"t": "passwd_result", "ok": ok, "reason": reason, "token": token}, [client])

    def _on_logout(self, client, event: dict) -> None:
        if client.token_hash:
            self.store.delete_session(client.token_hash)
            client.token_hash = None
            self.audit(client.username, "logout")

    def _on_export(self, client, event: dict) -> None:
        """Your own data as a JSON file, delivered over the file connection."""
        user = self.store.get_user_by_id(client.user_id)
        rows = self.store.messages_involving(client.user_id)
        document = {
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "account": {"username": user.username, "role": user.role, "created_at": user.created_at},
            "messages": [
                {"id": r["id"], "time": r["created_at"], "from": r["sender"], "to": r["recipient"],
                 "text": "" if r["deleted_at"] else r["body"], "deleted": bool(r["deleted_at"]),
                 "encrypted": bool(r["enc"]), "ciphertext": json.loads(r["enc"]) if r["enc"] else None,
                 "file": r["file_name"], "reply_to": r["reply_to"]}
                for r in rows
            ],
        }
        payload = json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")
        token = self._issue_ticket(client, "down", payload=payload, size=len(payload),
                                   sha256=hashlib.sha256(payload).hexdigest())
        req = event.get("req")
        if token is None:
            self._emit({"t": "transfer_error", "req": req, "reason": "too many transfers at once."}, [client])
            return
        self.audit(client.username, "data_exported", detail=f"{len(rows)} messages")
        self._emit({"t": "download_ready", "req": req, "ticket": token, "id": 0, "size": len(payload),
                    "name": f"lanchat-export-{client.username}.json",
                    "sha256": hashlib.sha256(payload).hexdigest(), "export": True}, [client])

    # ----- admin: shared plumbing

    def _allowed(self, client, permission: str, req=None) -> bool:
        if can(client.role, permission):
            return True
        self.audit(client.username, "denied", detail=permission)
        self._emit({"t": "admin_result", "req": req, "ok": False, "message": "only admins can do that."}, [client])
        return False

    def _result(self, client, req, ok: bool, message: str, **extra) -> None:
        self._emit({"t": "admin_result", "req": req, "ok": ok, "message": message, **extra}, [client])

    def _online(self, username: str) -> list:
        with self._lock:
            return [c for c in self._clients.values() if c.username.lower() == username.lower()]

    # ----- admin: users

    def _on_admin_users(self, client, event: dict) -> None:
        if not self._allowed(client, "manage_users", event.get("req")):
            return
        users = self.store.list_users()
        online = {c.username.lower() for c in self._clients.values()}
        page = event.get("page") if isinstance(event.get("page"), int) and event["page"] >= 0 else 0
        pages = max(1, -(-len(users) // USERS_PER_PAGE))
        page = min(page, pages - 1)
        chunk = users[page * USERS_PER_PAGE:(page + 1) * USERS_PER_PAGE]
        rows = [{"name": u.username, "role": u.role, "disabled": u.disabled, "online": u.username.lower() in online,
                 "last_seen": u.last_seen, "sessions": self.store.session_count(u.id)} for u in chunk]
        self._emit({"t": "admin_users", "req": event.get("req"), "page": page, "pages": pages,
                    "users": rows, "total": len(users)}, [client])

    def _on_admin(self, client, event: dict) -> None:
        req, op = event.get("req"), event.get("op")
        user, value = event.get("user"), event.get("value")
        needs = "manage_settings" if op == "set_setting" else "manage_users"
        if not self._allowed(client, needs, req):
            return
        if not isinstance(op, str) or not (user is None or isinstance(user, str)):
            self._result(client, req, False, "malformed request.")
            return
        handler = getattr(self, f"_admin_{op}", None)
        if handler is None:
            self._result(client, req, False, "unknown action.")
            return
        try:
            handler(client, req, user, value)
        except ValueError as error:
            self._result(client, req, False, str(error))

    def _target(self, user: str | None):
        found = self.store.get_user(user) if user else None
        if found is None:
            raise ValueError(f"no user named '{user}'.")
        return found

    def _admins_left_without(self, target) -> bool:
        admins = [u for u in self.store.list_users() if u.role == "admin" and not u.disabled]
        return target.role == "admin" and not target.disabled and len(admins) <= 1

    def _admin_role(self, client, req, user, value) -> None:
        if value not in ROLES:
            raise ValueError("unknown role.")
        error = self.set_role(self._target(user).username, value, actor=client.username)
        self._result(client, req, error is None, error or f"{user} is now {value}.")

    def _admin_disable(self, client, req, user, value) -> None:
        target = self._target(user)
        if target.id == client.user_id:
            raise ValueError("you cannot disable your own account.")
        if self._admins_left_without(target):
            raise ValueError("cannot disable the last admin.")
        self.store.set_disabled(target.username, True)
        self.store.delete_user_sessions(target.id)
        for other in self._online(target.username):
            self._remove_client(other.connection)
        self.audit(client.username, "user_disabled", target.username)
        self._result(client, req, True, f"{target.username} is disabled and signed out.")

    def _admin_enable(self, client, req, user, value) -> None:
        target = self._target(user)
        self.store.set_disabled(target.username, False)
        self.audit(client.username, "user_enabled", target.username)
        self._result(client, req, True, f"{target.username} can sign in again.")

    def _admin_kick(self, client, req, user, value) -> None:
        target = self._target(user)
        online = self._online(target.username)
        if not online:
            raise ValueError(f"{target.username} is not online.")
        for other in online:
            self._remove_client(other.connection)
        self.audit(client.username, "user_kicked", target.username)
        self._result(client, req, True, f"{target.username} was disconnected.")

    def _admin_signout(self, client, req, user, value) -> None:
        target = self._target(user)
        count = self.store.delete_user_sessions(target.id)
        self.audit(client.username, "sessions_revoked", target.username, f"{count} sessions")
        self._result(client, req, True, f"{count} saved sign-in(s) for {target.username} were revoked.")

    def _admin_reset_password(self, client, req, user, value) -> None:
        target = self._target(user)
        temporary = self.accounts.temporary_password()
        self.accounts.set_password(target.username, temporary)
        self.store.delete_user_sessions(target.id)
        for other in self._online(target.username):
            self._remove_client(other.connection)
        self.audit(client.username, "password_reset", target.username)
        self._result(client, req, True, f"{target.username}'s password was reset.", password=temporary)

    def _admin_create_user(self, client, req, user, value) -> None:
        if not isinstance(user, str) or not USERNAME_PATTERN.fullmatch(user):
            raise ValueError("a username is 1-32 letters, digits, '_', '.' or '-'.")
        if self.store.get_user(user) is not None:
            raise ValueError(f"'{user}' already exists.")
        if not isinstance(value, str):
            raise ValueError("enter a password.")
        problem = check_password(value, user, self.password_min) if self.enforce_password_policy else None
        if problem:
            raise ValueError(f"choose a stronger password ({problem}).")
        created = self.accounts.create_account(user, value, "member")
        self.audit(client.username, "user_created", created.username)
        self._push_members()
        self._result(client, req, True, f"{created.username} was created as a member.")

    # ----- admin: settings

    def settings_snapshot(self) -> dict:
        return {
            "open_registration": self.open_registration,
            "max_upload_mb": self.max_upload // (1024 * 1024),
            "user_quota_mb": self.user_quota // (1024 * 1024),
            "blocked": sorted(self.blocked_extensions),
            "password_min": self.password_min,
            "e2ee_policy": self.e2ee_policy,
        }

    def _on_admin_settings(self, client, event: dict) -> None:
        if self._allowed(client, "manage_settings", event.get("req")):
            self._emit({"t": "admin_settings", "req": event.get("req"), **self.settings_snapshot()}, [client])

    def _admin_set_setting(self, client, req, key, value) -> None:
        if key == "open_registration":
            stored = "1" if value in (True, "1", 1) else "0"
        elif key == "max_upload_mb":
            key, stored = "max_upload", str(_mb(value))
        elif key == "user_quota_mb":
            key, stored = "user_quota", str(_mb(value))
        elif key == "blocked":
            parts = [p.strip().lower() for p in (value if isinstance(value, list) else str(value).split(","))]
            parts = [p if p.startswith(".") else "." + p for p in parts if p]
            if not all(EXTENSION_PATTERN.fullmatch(p) for p in parts):
                raise ValueError("file types look like .exe, .bat (letters and digits only).")
            key, stored = "blocked_extensions", ",".join(sorted(set(parts)))
        elif key == "e2ee_policy":
            self._admin_e2ee_policy(client, req, value, None)
            stored = value
        elif key == "password_min":
            number = int(value)
            if not 4 <= number <= 64:
                raise ValueError("the minimum password length must be between 4 and 64.")
            stored = str(number)
        else:
            raise ValueError("unknown setting.")
        self.store.set_setting(key, stored)
        self.audit(client.username, "setting_changed", key, stored[:100])
        self._result(client, req, True, "Saved.", settings=self.settings_snapshot())

    # ----- admin: audit log

    def _on_admin_audit(self, client, event: dict) -> None:
        req = event.get("req")
        if not self._allowed(client, "view_audit", req):
            return
        actor = event.get("actor") if isinstance(event.get("actor"), str) else None
        action = event.get("action") if isinstance(event.get("action"), str) else None
        before = event.get("before") if isinstance(event.get("before"), int) else None
        rows = self.store.audit_rows(actor or None, action or None, before, AUDIT_PAGE + 1)
        more = len(rows) > AUDIT_PAGE
        rows = rows[:AUDIT_PAGE]
        for row in rows:
            row["detail"] = row["detail"][:90]
            row["target"] = row["target"][:60]
        reply = {"t": "admin_audit", "req": req, "rows": rows, "has_more": more, "total": self.store.audit_count()}
        while len(encode(reply).encode("utf-8")) > MAX_ACTIVE_BYTES and rows:
            rows.pop()
            reply["has_more"] = True
        self._emit(reply, [client])

    def _on_admin_verify(self, client, event: dict) -> None:
        req = event.get("req")
        if not self._allowed(client, "view_audit", req):
            return
        ok, bad_id, message = self.store.verify_audit()
        self.audit(client.username, "audit_verified", detail="intact" if ok else f"BROKEN at {bad_id}")
        self._emit({"t": "admin_verify", "req": req, "ok": ok, "bad_id": bad_id, "message": message,
                    "total": self.store.audit_count()}, [client])

    HANDLERS = {
        "passwd": _on_passwd, "logout": _on_logout, "export": _on_export,
        "admin_users": _on_admin_users, "admin": _on_admin, "admin_settings": _on_admin_settings,
        "admin_audit": _on_admin_audit, "admin_verify": _on_admin_verify,
    }
