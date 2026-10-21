"""Where one person's encryption keys and pinned contacts live on this computer.

    ~/.lanchat/keys/<server id>/<username>.key        secret keys, wrapped with the passphrase
    ~/.lanchat/keys/<server id>/<username>.contacts   the keys of people you have talked to

The server id is the server certificate's fingerprint, so keys made for one chat are never
offered to another. Contacts are pinned the way certificates are: the first key you see for a
name is remembered, and a different one later is reported instead of silently accepted.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import e2ee
from e2ee import Bundle, CryptoError, Identity

VERSION = 1
MAX_PREVIOUS_KEYS = 5
MAX_PREVIOUS_IDENTITIES = 4


def server_id(fingerprint: str | None, host: str = "", port: int = 0) -> str:
    """A folder name for a server: its certificate fingerprint, or host and port if it has none."""
    if fingerprint:
        return "".join(ch for ch in fingerprint.lower() if ch.isalnum())[:32]
    return f"plain-{host}-{port}".replace("/", "_")


class KeyStore:
    def __init__(self, home: str | os.PathLike[str], server: str, username: str) -> None:
        self.folder = Path(home) / "keys" / server
        stem = username.lower()
        self.key_path = self.folder / f"{stem}.key"
        self.contacts_path = self.folder / f"{stem}.contacts"
        self._lock = threading.Lock()

    # ----- my keys -----

    def exists(self) -> bool:
        return self.key_path.is_file()

    def _write(self, path: Path, data: dict) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _read(self, path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise CryptoError("the key file is missing or damaged") from error
        if not isinstance(data, dict):
            raise CryptoError("the key file is damaged")
        return data

    def save_identities(self, identities: list[Identity], passphrase: str) -> None:
        """Write the current identity (first) and any older ones, all wrapped under the passphrase."""
        with self._lock:
            self._write(self.key_path, {
                "v": VERSION, "bundle": identities[0].public().to_dict(),
                "wrapped": e2ee.wrap(identities[0].secret_bytes(), passphrase),
                "previous": [{"bundle": old.public().to_dict(), "wrapped": e2ee.wrap(old.secret_bytes(), passphrase)}
                             for old in identities[1:1 + MAX_PREVIOUS_IDENTITIES]]})

    def save_identity(self, identity: Identity, passphrase: str) -> None:
        self.save_identities([identity], passphrase)

    def create(self, passphrase: str) -> tuple[Identity, str, dict]:
        """Make new keys. Returns (identity, recovery code to show once, backup to upload)."""
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        self.save_identity(identity, passphrase)
        return identity, code, e2ee.make_backup(identity, code)

    def unlock_all(self, passphrase: str) -> list[Identity]:
        """The current identity, then the older ones kept for opening earlier messages."""
        data = self._read(self.key_path)
        try:
            identities = [Identity.from_secret(e2ee.unwrap(data["wrapped"], passphrase))]
            if identities[0].public().dh != self.public_bundle().dh:
                raise CryptoError("the key file does not match its public keys")
            for entry in data.get("previous", []):
                old = Identity.from_secret(e2ee.unwrap(entry["wrapped"], passphrase))
                if old.public().dh != Bundle.from_dict(entry["bundle"]).dh:
                    raise CryptoError("an old key does not match its public keys")
                identities.append(old)
        except (KeyError, TypeError) as error:
            raise CryptoError("the key file is damaged") from error
        return identities

    def unlock(self, passphrase: str) -> Identity:
        return self.unlock_all(passphrase)[0]

    def rotate(self, passphrase: str) -> tuple[Identity, list[Identity], str, dict]:
        """Replace my identity with a fresh one, keeping the old ones so earlier messages stay readable.

        Returns (new identity, older identities, new recovery code, backup to upload)."""
        current = self.unlock_all(passphrase)
        fresh, code = Identity.generate(), e2ee.new_recovery_code()
        everything = [fresh] + current[:MAX_PREVIOUS_IDENTITIES]
        self.save_identities(everything, passphrase)
        return fresh, everything[1:], code, e2ee.make_backup(everything, code)

    def public_bundle(self) -> Bundle:
        try:
            return Bundle.from_dict(self._read(self.key_path)["bundle"])
        except KeyError as error:
            raise CryptoError("the key file is damaged") from error

    def restore(self, recovery_code: str, backup: dict, new_passphrase: str) -> Identity:
        """Bring keys back on a new computer from the server's backup and your recovery code."""
        identities = e2ee.open_backup_all(backup, recovery_code)
        self.save_identities(identities, new_passphrase)
        return identities[0]

    def change_passphrase(self, old: str, new: str) -> None:
        self.save_identities(self.unlock_all(old), new)

    def reset(self) -> None:
        """Forget my keys and everyone I pinned (their keys stay valid; mine are being replaced)."""
        for path in (self.key_path, self.contacts_path):
            path.unlink(missing_ok=True)

    # ----- pinned contacts -----

    def _contacts(self) -> dict:
        try:
            data = json.loads(self.contacts_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def contact(self, name: str) -> dict | None:
        with self._lock:
            return self._contacts().get(name.lower())

    def bundles_for(self, name: str) -> list[Bundle]:
        """The key I pinned for this person, then the ones it replaced (newest first)."""
        known = self.contact(name)
        if known is None:
            return []
        found = []
        for data in [known["bundle"]] + list(known.get("previous", [])):
            try:
                found.append(Bundle.from_dict(data))
            except CryptoError:
                continue
        return found

    def check_contact(self, name: str, bundle: Bundle) -> str:
        """'new' (never seen), 'same' (matches the pin) or 'changed' (a different key than before)."""
        known = self.contact(name)
        if known is None:
            return "new"
        return "same" if known["fp"] == bundle.fingerprint() else "changed"

    def pin_contact(self, name: str, bundle: Bundle, verified: bool = False) -> None:
        """Remember this key for `name`. Pinning a different key clears the 'verified' mark."""
        with self._lock:
            contacts = self._contacts()
            known = contacts.get(name.lower())
            same = known is not None and known["fp"] == bundle.fingerprint()
            previous = list(known.get("previous", [])) if known else []
            if known is not None and not same:  # keep the old key so earlier messages can still be checked
                previous = ([known["bundle"]] + previous)[:MAX_PREVIOUS_KEYS]
            contacts[name.lower()] = {"name": name, "fp": bundle.fingerprint(), "bundle": bundle.to_dict(),
                                      "previous": previous,
                                      "verified": bool(verified or (same and known.get("verified")))}
            self._write(self.contacts_path, contacts)

    def mark_verified(self, name: str) -> bool:
        with self._lock:
            contacts = self._contacts()
            if name.lower() not in contacts:
                return False
            contacts[name.lower()]["verified"] = True
            self._write(self.contacts_path, contacts)
            return True

    def is_verified(self, name: str) -> bool:
        known = self.contact(name)
        return bool(known and known.get("verified"))
