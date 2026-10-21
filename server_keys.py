"""Public-key directory for end-to-end encryption (mixed into ChatServer).

The server stores each person's PUBLIC keys and an opaque, recovery-code-wrapped backup of
their secret keys. It cannot read either: it never learns a passphrase or recovery code.
It also cannot be trusted to tell the truth about keys, which is why clients pin keys and
show safety numbers. If `cryptography` is installed here the server also checks that a
published key bundle is properly self-signed; clients verify again regardless.
"""

from __future__ import annotations

import json

import e2ee
from permissions import can

MAX_LOOKUP = 30
MAX_BACKUP_CHARS = 3000
E2EE_POLICIES = ("off", "optional", "required")


class KeysMixin:
    """Needs the host class to provide: store, audit(), _emit(), _error(), _lock, _clients, e2ee_policy."""

    @property
    def e2ee_policy(self) -> str:
        value = self.store.get_setting("e2ee_policy", "optional")
        return value if value in E2EE_POLICIES else "optional"

    def e2ee_state(self, client) -> dict:
        """What the welcome tells a window about encryption on this server."""
        return {"policy": self.e2ee_policy, "have_keys": self.store.get_user_keys(client.user_id) is not None}

    def _keys_reply(self, client, req, ok: bool, **fields) -> None:
        self._emit({"t": "keys_result", "req": req, "ok": ok, **fields}, [client])

    def _on_keys_publish(self, client, event: dict) -> None:
        req = event.get("req")
        try:
            bundle = e2ee.Bundle.from_dict({k: event.get(k) for k in ("dh", "sign", "sig")})
        except e2ee.CryptoError as error:
            self._keys_reply(client, req, False, reason=str(error))
            return
        if e2ee.AVAILABLE and not bundle.verify():
            self._keys_reply(client, req, False, reason="that key bundle is not properly signed")
            return
        backup = event.get("backup")
        if backup is not None:
            encoded = json.dumps(backup) if isinstance(backup, dict) else ""
            if not encoded or len(encoded) > MAX_BACKUP_CHARS:
                self._keys_reply(client, req, False, reason="the key backup is missing or too large")
                return
        status = self.store.set_user_keys(client.user_id, e2ee.b64(bundle.dh), e2ee.b64(bundle.sign),
                                          e2ee.b64(bundle.sig), bundle.fingerprint())
        if backup is not None:
            self.store.set_backup(client.user_id, json.dumps(backup))
        if status != "same":
            self.audit(client.username, f"keys_{status}", detail=f"fingerprint {bundle.fingerprint()[:16]}")
        if status in ("changed", "created"):  # created: people who found no keys for them should look again
            with self._lock:
                others = [c for c in self._clients.values() if c is not client]
            self._emit({"t": "key_changed", "user": client.username, "fingerprint": bundle.fingerprint(),
                        "created": status == "created"}, others)
        self._keys_reply(client, req, True, status=status, fingerprint=bundle.fingerprint())

    def _on_keys_get(self, client, event: dict) -> None:
        names = event.get("names")
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            self._keys_reply(client, event.get("req"), False, reason="malformed request")
            return
        found = self.store.keys_for_names(names[:MAX_LOOKUP])
        self._emit({"t": "keys", "req": event.get("req"), "keys": found}, [client])

    def _on_keys_backup_get(self, client, event: dict) -> None:
        blob = self.store.get_backup(client.user_id)
        self._emit({"t": "keys_backup", "req": event.get("req"),
                    "backup": json.loads(blob) if blob else None,
                    "keys": self.store.get_user_keys(client.user_id)}, [client])

    def _on_keys_reset(self, client, event: dict) -> None:
        had = self.store.delete_user_keys(client.user_id)
        if had:
            self.audit(client.username, "keys_reset")
            with self._lock:
                others = [c for c in self._clients.values() if c is not client]
            self._emit({"t": "key_changed", "user": client.username, "reset": True}, others)
        self._keys_reply(client, event.get("req"), True, status="reset" if had else "none")

    def set_e2ee_policy(self, value: str) -> None:
        """Change the policy and tell every connected window straight away."""
        if value not in E2EE_POLICIES:
            raise ValueError("the policy must be off, optional or required.")
        self.store.set_setting("e2ee_policy", value)
        self._emit({"t": "e2ee_policy", "policy": value})

    def _admin_e2ee_policy(self, client, req, value, _unused) -> None:
        """set_setting helper: only admins reach this through `_admin_set_setting`."""
        if not can(client.role, "manage_settings"):
            raise ValueError("only admins can change the policy.")
        self.set_e2ee_policy(value)

    HANDLERS = {
        "keys_publish": _on_keys_publish, "keys_get": _on_keys_get,
        "keys_backup_get": _on_keys_backup_get, "keys_reset": _on_keys_reset,
    }
