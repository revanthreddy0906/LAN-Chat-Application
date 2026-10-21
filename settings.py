"""Remembered settings and trusted server certificates, stored in ~/.lanchat."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path


def default_home() -> Path:
    override = os.environ.get("LANCHAT_HOME")
    return Path(override) if override else Path.home() / ".lanchat"


class Settings:
    """A tiny JSON key-value store. Passwords are never saved here."""

    def __init__(self, home: str | os.PathLike[str] | None = None) -> None:
        self.home = Path(home) if home else default_home()
        self.path = self.home / "settings.json"
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)

    def get(self, key: str, default=None):
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        with self._lock:
            self._data[key] = value
            self._save()

    @staticmethod
    def _server_key(host: str, port: int) -> str:
        return f"{host}:{port}"

    def trusted_server(self, host: str, port: int) -> dict | None:
        with self._lock:
            return self._data.get("servers", {}).get(self._server_key(host, port))

    def is_trusted_fingerprint(self, fingerprint: str) -> bool:
        with self._lock:
            servers = self._data.get("servers", {}).values()
            return any(entry.get("fingerprint") == fingerprint for entry in servers)

    def trust_server(self, host: str, port: int, pem: str, fingerprint: str) -> None:
        with self._lock:
            servers = self._data.setdefault("servers", {})
            servers[self._server_key(host, port)] = {"pem": pem, "fingerprint": fingerprint}
            self._save()

    def forget_server(self, host: str, port: int) -> None:
        with self._lock:
            self._data.get("servers", {}).pop(self._server_key(host, port), None)
            self._save()
