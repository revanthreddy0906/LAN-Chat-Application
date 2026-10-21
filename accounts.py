"""Password hashing and sign-in on top of the SQLite store (standard library only)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import json
import os
import threading
from pathlib import Path

from store import Store, User

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32
SALT_LENGTH = 16


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LENGTH,
    )


class AccountStore:
    """Sign-in over a `Store`.

    Give it `accounts.json` and it keeps its data in `accounts.db` next to it;
    an old accounts.json is imported once and kept as `accounts.json.bak`.
    Give it a `.db` path to use that file directly.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        path = Path(path)
        json_path = path if path.suffix == ".json" else None
        db_path = path.with_suffix(".db") if json_path else path
        self.store = Store(db_path)
        self._lock = threading.Lock()
        if json_path is not None and json_path.exists() and self.store.user_count() == 0:
            self._import_json(json_path)

    def _import_json(self, json_path: Path) -> None:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for record in data.get("users", {}).values():
            self.store.create_user(record["name"], record["salt"], record["hash"])
        os.replace(json_path, json_path.with_name(json_path.name + ".bak"))

    def authenticate(self, username: str, password: str) -> tuple[str, User | None]:
        """Return ("registered" | "ok" | "bad_password", user).

        A username nobody has used yet is registered with this password.
        """
        with self._lock:
            user = self.store.get_user(username)
            if user is None:
                salt = os.urandom(SALT_LENGTH)
                user = self.store.create_user(username, salt.hex(), _hash_password(password, salt).hex())
                return "registered", user
            if hmac.compare_digest(_hash_password(password, bytes.fromhex(user.salt)), bytes.fromhex(user.hash)):
                return "ok", user
            return "bad_password", user

    def verify_or_register(self, username: str, password: str) -> tuple[str, str]:
        """Compatibility wrapper: (status, canonical username)."""
        status, user = self.authenticate(username, password)
        return status, user.username if user else username

    # ----- changing credentials (used by the server and by the offline admin tool) -----

    def change_password(self, username: str, old: str, new: str) -> bool:
        """True if `old` was right and the password is now `new`."""
        with self._lock:
            user = self.store.get_user(username)
            if user is None:
                return False
            if not hmac.compare_digest(_hash_password(old, bytes.fromhex(user.salt)), bytes.fromhex(user.hash)):
                return False
            self._write_password(user.id, new)
            return True

    def set_password(self, username: str, new: str) -> bool:
        with self._lock:
            user = self.store.get_user(username)
            if user is None:
                return False
            self._write_password(user.id, new)
            return True

    def create_account(self, username: str, password: str, role: str | None = None) -> User:
        with self._lock:
            salt = os.urandom(SALT_LENGTH)
            return self.store.create_user(username, salt.hex(), _hash_password(password, salt).hex(), role)

    def _write_password(self, user_id: int, password: str) -> None:
        salt = os.urandom(SALT_LENGTH)
        self.store.update_password(user_id, salt.hex(), _hash_password(password, salt).hex())

    @staticmethod
    def temporary_password() -> str:
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no look-alike characters
        return "".join(secrets.choice(alphabet) for _ in range(10))
