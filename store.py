"""SQLite storage for users, messages and settings (standard library only).

One connection guarded by a lock is plenty for a classroom or office-sized
server and keeps the code easy to follow. Schema changes are numbered
migrations, applied in order, so an old database upgrades itself.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from audit import GENESIS, entry_hash, verify_rows
from permissions import is_valid_role

SCHEMA_V1 = """
CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    salt        TEXT NOT NULL,
    hash        TEXT NOT NULL,
    kdf         TEXT NOT NULL DEFAULT 'scrypt-16384-8-1',
    role        TEXT NOT NULL DEFAULT 'member',
    disabled    INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL,
    last_seen   REAL
);
CREATE TABLE messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id    INTEGER NOT NULL DEFAULT 1,
    sender_id     INTEGER NOT NULL REFERENCES users(id),
    recipient_id  INTEGER REFERENCES users(id),
    kind          TEXT NOT NULL DEFAULT 'text',
    body          TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX idx_messages_channel ON messages(channel_id, id);
CREATE INDEX idx_messages_recipient ON messages(recipient_id, id);
CREATE TABLE settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

SCHEMA_V2 = """
ALTER TABLE messages ADD COLUMN reply_to INTEGER REFERENCES messages(id);
ALTER TABLE messages ADD COLUMN edited_at REAL;
ALTER TABLE messages ADD COLUMN deleted_at REAL;
CREATE TABLE reactions (
    message_id  INTEGER NOT NULL REFERENCES messages(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    emoji       TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (message_id, user_id, emoji)
);
CREATE TABLE read_markers (
    user_id       INTEGER NOT NULL REFERENCES users(id),
    channel_id    INTEGER NOT NULL DEFAULT 1,
    last_read_id  INTEGER NOT NULL DEFAULT 0,
    updated_at    REAL NOT NULL,
    PRIMARY KEY (user_id, channel_id)
);
"""

SCHEMA_V4 = """
CREATE TABLE attachments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  INTEGER NOT NULL UNIQUE REFERENCES messages(id),
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    sha256      TEXT NOT NULL,
    name        TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    removed_at  REAL
);
CREATE INDEX idx_attachments_sha ON attachments(sha256);
CREATE INDEX idx_attachments_owner ON attachments(owner_id);
"""

SCHEMA_V5 = """
CREATE TABLE sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    last_used   REAL,
    address     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE TABLE audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX idx_audit_actor ON audit(actor);
CREATE INDEX idx_audit_action ON audit(action);
"""

SCHEMA_V6 = """
CREATE TABLE user_keys (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id),
    dh          TEXT NOT NULL,
    sign        TEXT NOT NULL,
    sig         TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE TABLE key_backups (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id),
    blob        TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
ALTER TABLE messages ADD COLUMN enc TEXT;
CREATE TABLE group_epochs (
    channel_id  INTEGER PRIMARY KEY,
    epoch       INTEGER NOT NULL DEFAULT 1,
    updated_at  REAL NOT NULL
);
CREATE TABLE key_envelopes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id  INTEGER NOT NULL REFERENCES users(id),
    sender_id     INTEGER NOT NULL REFERENCES users(id),
    channel_id    INTEGER NOT NULL DEFAULT 1,
    epoch         INTEGER NOT NULL,
    blob          TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX idx_key_envelopes_recipient ON key_envelopes(recipient_id, channel_id);
"""

# Index + 1 is the schema version. Add new migrations to the end, never edit old ones.
SCHEMA_V3 = """
ALTER TABLE messages ADD COLUMN mention_all INTEGER NOT NULL DEFAULT 0;
CREATE TABLE message_mentions (
    message_id  INTEGER NOT NULL REFERENCES messages(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (message_id, user_id)
);
CREATE TABLE pins (
    message_id  INTEGER PRIMARY KEY REFERENCES messages(id),
    channel_id  INTEGER NOT NULL DEFAULT 1,
    pinned_by   INTEGER NOT NULL REFERENCES users(id),
    pinned_at   REAL NOT NULL
);
"""

# Full-text search is set up separately (and is optional): some SQLite builds lack FTS5.
FTS_SETUP = """
CREATE VIRTUAL TABLE messages_fts USING fts5(body, content='messages', content_rowid='id');
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, body) VALUES (new.id, new.body);
END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, body) VALUES ('delete', old.id, old.body);
END;
CREATE TRIGGER messages_fts_update AFTER UPDATE OF body ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, body) VALUES ('delete', old.id, old.body);
    INSERT INTO messages_fts(rowid, body) VALUES (new.id, new.body);
END;
INSERT INTO messages_fts(messages_fts) VALUES ('rebuild');
"""

MIGRATIONS = [SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6]
MAX_DISTINCT_REACTIONS = 20
MAX_PINS = 20
MAX_PAGE = 50
MAX_SEARCH_RESULTS = 30


@dataclass(frozen=True)
class User:
    id: int
    username: str
    role: str
    disabled: bool
    created_at: float
    last_seen: float | None
    salt: str
    hash: str
    kdf: str


@dataclass(frozen=True)
class StoredMessage:
    id: int
    sender: str
    recipient: str | None  # None = public message
    kind: str
    body: str
    created_at: float
    reply_to: int | None = None
    edited_at: float | None = None
    deleted_at: float | None = None
    sender_id: int = 0
    recipient_id: int | None = None
    mention_all: bool = False
    enc: str | None = None  # an end-to-end encrypted envelope (JSON); the server cannot read it


_MESSAGE_SELECT = (
    "SELECT m.id, s.username AS sender, r.username AS recipient, m.kind, m.body, m.created_at,"
    " m.reply_to, m.edited_at, m.deleted_at, m.sender_id, m.recipient_id, m.mention_all, m.enc"
    " FROM messages m JOIN users s ON s.id = m.sender_id"
    " LEFT JOIN users r ON r.id = m.recipient_id"
)


def _message(row: sqlite3.Row) -> StoredMessage:
    return StoredMessage(
        row["id"], row["sender"], row["recipient"], row["kind"], row["body"], row["created_at"],
        row["reply_to"], row["edited_at"], row["deleted_at"], row["sender_id"], row["recipient_id"],
        bool(row["mention_all"]), row["enc"],
    )


def search_terms(query: str) -> list[str]:
    """The words of a search box entry (letters and digits only, so nothing can break the query)."""
    return re.findall(r"\w+", query.lower())[:8]


def fts_match(terms: list[str]) -> str:
    """An FTS5 MATCH string: every word must appear, and the last one may be a prefix."""
    quoted = [f'"{term}"' for term in terms]
    quoted[-1] += "*"
    return " ".join(quoted)


class Store:
    def __init__(self, path: str | Path, use_fts: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._migrate()
        self.has_fts = self._setup_search() if use_fts else False

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ----- schema -----

    def schema_version(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            return row["v"] or 0

    def _migrate(self) -> None:
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            current = self.schema_version()
            for version, script in enumerate(MIGRATIONS, start=1):
                if version > current:
                    self._db.executescript(script)
                    self._db.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
                    self._db.commit()

    def _setup_search(self) -> bool:
        """Create the full-text index if this SQLite supports it. Searching falls back to LIKE if not."""
        with self._lock:
            try:
                exists = self._db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'messages_fts'").fetchone()
                if not exists:
                    self._db.executescript(FTS_SETUP)
                    self._db.commit()
                return True
            except sqlite3.OperationalError:
                return False

    # ----- users -----

    @staticmethod
    def _user(row: sqlite3.Row | None) -> User | None:
        if row is None:
            return None
        return User(
            id=row["id"], username=row["username"], role=row["role"],
            disabled=bool(row["disabled"]), created_at=row["created_at"],
            last_seen=row["last_seen"], salt=row["salt"], hash=row["hash"], kdf=row["kdf"],
        )

    def user_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]

    def get_user(self, username: str) -> User | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return self._user(row)

    def get_user_by_id(self, user_id: int) -> User | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._user(row)

    def list_users(self) -> list[User]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM users ORDER BY id").fetchall()
            return [self._user(row) for row in rows]

    def create_user(
        self, username: str, salt: str, password_hash: str, role: str | None = None,
        kdf: str = "scrypt-16384-8-1", created_at: float | None = None,
    ) -> User:
        """Add a user. The very first user becomes the admin."""
        with self._lock:
            if role is None:
                role = "admin" if self.user_count() == 0 else "member"
            if not is_valid_role(role):
                raise ValueError(f"unknown role: {role}")
            try:
                self._db.execute(
                    "INSERT INTO users (username, salt, hash, kdf, role, created_at) VALUES (?,?,?,?,?,?)",
                    (username, salt, password_hash, kdf, role, created_at or time.time()),
                )
                self._db.commit()
            except sqlite3.IntegrityError as error:
                raise ValueError(f"username already exists: {username}") from error
            return self.get_user(username)

    def set_role(self, username: str, role: str) -> bool:
        """Change a role. The last admin cannot be demoted."""
        if not is_valid_role(role):
            raise ValueError(f"unknown role: {role}")
        with self._lock:
            user = self.get_user(username)
            if user is None:
                return False
            if user.role == "admin" and role != "admin":
                admins = self._db.execute("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0").fetchone()["n"]
                if admins <= 1:
                    raise ValueError("cannot remove the last admin")
            self._db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user.id))
            self._db.commit()
            return True

    def set_disabled(self, username: str, disabled: bool) -> bool:
        with self._lock:
            user = self.get_user(username)
            if user is None:
                return False
            self._db.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user.id))
            self._db.commit()
            return True

    def touch_last_seen(self, user_id: int, when: float | None = None) -> None:
        with self._lock:
            self._db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (when or time.time(), user_id))
            self._db.commit()

    # ----- messages -----

    def add_message(
        self, sender_id: int, body: str, recipient_id: int | None = None,
        kind: str = "text", channel_id: int = 1, created_at: float | None = None,
        reply_to: int | None = None, mentions: list[int] | None = None, mention_all: bool = False,
        enc: str | None = None,
    ) -> int:
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO messages (channel_id, sender_id, recipient_id, kind, body, created_at, reply_to,"
                " mention_all, enc) VALUES (?,?,?,?,?,?,?,?,?)",
                (channel_id, sender_id, recipient_id, kind, body, created_at or time.time(), reply_to,
                 int(mention_all), enc),
            )
            message_id = cursor.lastrowid
            for user_id in dict.fromkeys(mentions or []):
                self._db.execute(
                    "INSERT OR IGNORE INTO message_mentions (message_id, user_id) VALUES (?, ?)",
                    (message_id, user_id),
                )
            self._db.commit()
            return message_id

    def mentions_for(self, message_ids: list[int]) -> dict[int, list[str]]:
        """{message_id: [usernames mentioned]}"""
        if not message_ids:
            return {}
        marks = ",".join("?" * len(message_ids))
        with self._lock:
            rows = self._db.execute(
                "SELECT mm.message_id, u.username FROM message_mentions mm JOIN users u ON u.id = mm.user_id"
                f" WHERE mm.message_id IN ({marks}) ORDER BY u.username",
                message_ids,
            ).fetchall()
        grouped: dict[int, list[str]] = {}
        for row in rows:
            grouped.setdefault(row["message_id"], []).append(row["username"])
        return grouped

    def get_message(self, message_id: int) -> StoredMessage | None:
        with self._lock:
            row = self._db.execute(_MESSAGE_SELECT + " WHERE m.id = ?", (message_id,)).fetchone()
        return _message(row) if row else None

    def latest_message_id(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COALESCE(MAX(id), 0) AS n FROM messages").fetchone()["n"]

    def history_for(self, user_id: int, limit: int = 50, channel_id: int = 1) -> list[StoredMessage]:
        """The latest public messages plus private ones this user sent or received.

        Deleted messages are included (with an empty body) so replies still make sense.
        """
        with self._lock:
            rows = self._db.execute(
                _MESSAGE_SELECT
                + " WHERE (m.recipient_id IS NULL AND m.channel_id = ?)"
                  "    OR m.sender_id = ? OR m.recipient_id = ?"
                  " ORDER BY m.id DESC LIMIT ?",
                (channel_id, user_id, user_id, limit),
            ).fetchall()
        return [_message(row) for row in reversed(rows)]

    def edit_message(self, message_id: int, user_id: int, new_body: str, when: float | None = None,
                     enc: str | None = None) -> bool:
        """Change a message's text (or its encrypted envelope). Only its author can, and only while it is not deleted."""
        with self._lock:
            cursor = self._db.execute(
                "UPDATE messages SET body = ?, enc = ?, edited_at = ?"
                " WHERE id = ? AND sender_id = ? AND deleted_at IS NULL",
                (new_body, enc, when or time.time(), message_id, user_id),
            )
            self._db.commit()
            return cursor.rowcount > 0

    def delete_message(self, message_id: int, when: float | None = None) -> bool:
        """Soft delete: the text is erased, a tombstone row stays so replies keep working."""
        with self._lock:
            cursor = self._db.execute(
                "UPDATE messages SET body = '', enc = NULL, deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
                (when or time.time(), message_id),
            )
            self._db.execute("DELETE FROM reactions WHERE message_id = ?", (message_id,))
            self._db.execute("DELETE FROM pins WHERE message_id = ?", (message_id,))
            self._db.execute(
                "UPDATE attachments SET removed_at = ? WHERE message_id = ? AND removed_at IS NULL",
                (when or time.time(), message_id),
            )
            self._db.commit()
            return cursor.rowcount > 0

    # ----- attachments -----

    def add_attachment(self, message_id: int, owner_id: int, sha256: str, name: str, mime: str,
                       size: int, kind: str) -> int:
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO attachments (message_id, owner_id, sha256, name, mime, size, kind, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (message_id, owner_id, sha256, name, mime, size, kind, time.time()),
            )
            self._db.commit()
            return cursor.lastrowid

    def attachments_for(self, message_ids: list[int]) -> dict[int, dict]:
        """{message_id: {id, name, mime, size, kind, sha256}} for messages that still have a file."""
        if not message_ids:
            return {}
        marks = ",".join("?" * len(message_ids))
        with self._lock:
            rows = self._db.execute(
                "SELECT id, message_id, name, mime, size, kind, sha256 FROM attachments"
                f" WHERE removed_at IS NULL AND message_id IN ({marks})",
                message_ids,
            ).fetchall()
        return {
            row["message_id"]: {key: row[key] for key in ("id", "name", "mime", "size", "kind", "sha256")}
            for row in rows
        }

    def attachment_for_message(self, message_id: int) -> dict | None:
        return self.attachments_for([message_id]).get(message_id)

    def attachment_usage(self, user_id: int) -> int:
        """Bytes of live files this user has shared."""
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(SUM(size), 0) AS n FROM attachments WHERE owner_id = ? AND removed_at IS NULL",
                (user_id,),
            ).fetchone()
        return row["n"]

    def sha_in_use(self, sha256: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM attachments WHERE sha256 = ? AND removed_at IS NULL LIMIT 1", (sha256,)
            ).fetchone()
        return row is not None

    # ----- paging and search -----

    _VISIBLE = (
        "((m.recipient_id IS NULL AND m.channel_id = ?) OR m.sender_id = ? OR m.recipient_id = ?)"
    )

    def history_before(self, user_id: int, before_id: int, limit: int = MAX_PAGE,
                       channel_id: int = 1) -> list[StoredMessage]:
        """Up to `limit` visible messages older than `before_id`, oldest first."""
        limit = max(1, min(limit, MAX_PAGE))
        with self._lock:
            rows = self._db.execute(
                _MESSAGE_SELECT + f" WHERE m.id < ? AND {self._VISIBLE} ORDER BY m.id DESC LIMIT ?",
                (before_id, channel_id, user_id, user_id, limit),
            ).fetchall()
        return [_message(row) for row in reversed(rows)]

    def has_older(self, user_id: int, oldest_id: int, channel_id: int = 1) -> bool:
        with self._lock:
            row = self._db.execute(
                f"SELECT 1 FROM messages m WHERE m.id < ? AND {self._VISIBLE} LIMIT 1",
                (oldest_id, channel_id, user_id, user_id),
            ).fetchone()
        return row is not None

    def search(self, user_id: int, query: str, limit: int = MAX_SEARCH_RESULTS,
               channel_id: int = 1) -> list[StoredMessage]:
        """Newest-first messages containing every word of `query` that this user may see."""
        terms = search_terms(query)
        if not terms:
            return []
        limit = max(1, min(limit, MAX_SEARCH_RESULTS))
        visible = f"m.deleted_at IS NULL AND {self._VISIBLE}"
        with self._lock:
            if self.has_fts:
                rows = self._db.execute(
                    _MESSAGE_SELECT
                    + f" WHERE m.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)"
                      f" AND {visible} ORDER BY m.id DESC LIMIT ?",
                    (fts_match(terms), channel_id, user_id, user_id, limit),
                ).fetchall()
            else:
                clauses = " AND ".join("m.body LIKE ? ESCAPE '\\'" for _ in terms)
                patterns = ["%" + t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%" for t in terms]
                rows = self._db.execute(
                    _MESSAGE_SELECT + f" WHERE {clauses} AND {visible} ORDER BY m.id DESC LIMIT ?",
                    (*patterns, channel_id, user_id, user_id, limit),
                ).fetchall()
        return [_message(row) for row in rows]

    # ----- pins -----

    def pin_message(self, message_id: int, user_id: int, channel_id: int = 1) -> bool:
        """Pin a message. False if it was already pinned; ValueError past the pin limit."""
        with self._lock:
            if self._db.execute("SELECT 1 FROM pins WHERE message_id = ?", (message_id,)).fetchone():
                return False
            count = self._db.execute(
                "SELECT COUNT(*) AS n FROM pins WHERE channel_id = ?", (channel_id,)).fetchone()["n"]
            if count >= MAX_PINS:
                raise ValueError(f"too many pinned messages (the limit is {MAX_PINS})")
            self._db.execute(
                "INSERT INTO pins (message_id, channel_id, pinned_by, pinned_at) VALUES (?,?,?,?)",
                (message_id, channel_id, user_id, time.time()),
            )
            self._db.commit()
            return True

    def unpin_message(self, message_id: int) -> bool:
        with self._lock:
            cursor = self._db.execute("DELETE FROM pins WHERE message_id = ?", (message_id,))
            self._db.commit()
            return cursor.rowcount > 0

    def is_pinned(self, message_id: int) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM pins WHERE message_id = ?", (message_id,)).fetchone() is not None

    def pinned(self, channel_id: int = 1) -> list[StoredMessage]:
        """Pinned messages, most recently pinned first."""
        with self._lock:
            rows = self._db.execute(
                _MESSAGE_SELECT + " JOIN pins p ON p.message_id = m.id WHERE p.channel_id = ?"
                " ORDER BY p.pinned_at DESC, p.message_id DESC",
                (channel_id,),
            ).fetchall()
        return [_message(row) for row in rows]

    # ----- reactions -----

    def toggle_reaction(self, message_id: int, user_id: int, emoji: str, when: float | None = None) -> bool:
        """Add the reaction, or remove it if this user already added it. True means added."""
        with self._lock:
            existing = self._db.execute(
                "SELECT 1 FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
                (message_id, user_id, emoji),
            ).fetchone()
            if existing:
                self._db.execute(
                    "DELETE FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?",
                    (message_id, user_id, emoji),
                )
                self._db.commit()
                return False
            distinct = self._db.execute(
                "SELECT COUNT(DISTINCT emoji) AS n FROM reactions WHERE message_id = ?", (message_id,)
            ).fetchone()["n"]
            known = self._db.execute(
                "SELECT 1 FROM reactions WHERE message_id = ? AND emoji = ?", (message_id, emoji)
            ).fetchone()
            if distinct >= MAX_DISTINCT_REACTIONS and not known:
                raise ValueError("too many different reactions on this message")
            self._db.execute(
                "INSERT INTO reactions (message_id, user_id, emoji, created_at) VALUES (?,?,?,?)",
                (message_id, user_id, emoji, when or time.time()),
            )
            self._db.commit()
            return True

    def reactions_for(self, message_ids: list[int]) -> dict[int, list[tuple[str, list[str]]]]:
        """{message_id: [(emoji, [usernames]), ...]} with emoji in the order first used."""
        if not message_ids:
            return {}
        marks = ",".join("?" * len(message_ids))
        with self._lock:
            rows = self._db.execute(
                "SELECT r.message_id, r.emoji, u.username FROM reactions r"
                " JOIN users u ON u.id = r.user_id"
                f" WHERE r.message_id IN ({marks}) ORDER BY r.created_at, r.rowid",
                message_ids,
            ).fetchall()
        grouped: dict[int, dict[str, list[str]]] = {}
        for row in rows:
            grouped.setdefault(row["message_id"], {}).setdefault(row["emoji"], []).append(row["username"])
        return {mid: list(emojis.items()) for mid, emojis in grouped.items()}

    # ----- read markers -----

    def set_last_read(self, user_id: int, up_to: int, channel_id: int = 1) -> bool:
        """Move a user's read marker forward. Returns True only if it actually advanced."""
        with self._lock:
            if up_to <= self.get_last_read(user_id, channel_id):
                return False
            self._db.execute(
                "INSERT INTO read_markers (user_id, channel_id, last_read_id, updated_at) VALUES (?,?,?,?)"
                " ON CONFLICT(user_id, channel_id) DO UPDATE SET"
                " last_read_id = excluded.last_read_id, updated_at = excluded.updated_at",
                (user_id, channel_id, up_to, time.time()),
            )
            self._db.commit()
            return True

    def get_last_read(self, user_id: int, channel_id: int = 1) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT last_read_id FROM read_markers WHERE user_id = ? AND channel_id = ?",
                (user_id, channel_id),
            ).fetchone()
            return row["last_read_id"] if row else 0

    def read_markers(self, channel_id: int = 1) -> dict[str, int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT u.username, m.last_read_id FROM read_markers m JOIN users u ON u.id = m.user_id"
                " WHERE m.channel_id = ?",
                (channel_id,),
            ).fetchall()
        return {row["username"]: row["last_read_id"] for row in rows}

    # ----- settings -----

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._db.commit()

    # ----- passwords -----

    def update_password(self, user_id: int, salt: str, password_hash: str, kdf: str = "scrypt-16384-8-1") -> None:
        with self._lock:
            self._db.execute("UPDATE users SET salt = ?, hash = ?, kdf = ? WHERE id = ?",
                             (salt, password_hash, kdf, user_id))
            self._db.commit()

    # ----- sessions (sign-in tokens; only a hash of each token is kept) -----

    def create_session(self, user_id: int, token_hash: str, lifetime: float, address: str = "") -> None:
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used, address)"
                " VALUES (?,?,?,?,?,?)", (token_hash, user_id, now, now + lifetime, now, address))
            self._db.commit()

    def session_user(self, token_hash: str) -> int | None:
        """The user id this token belongs to, if it exists and has not expired."""
        with self._lock:
            row = self._db.execute(
                "SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (token_hash, time.time())).fetchone()
            if row:
                self._db.execute("UPDATE sessions SET last_used = ? WHERE token_hash = ?",
                                 (time.time(), token_hash))
                self._db.commit()
        return row["user_id"] if row else None

    def delete_session(self, token_hash: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            self._db.commit()

    def delete_user_sessions(self, user_id: int) -> int:
        with self._lock:
            cursor = self._db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            self._db.commit()
            return cursor.rowcount

    def session_count(self, user_id: int | None = None) -> int:
        with self._lock:
            if user_id is None:
                row = self._db.execute("SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?", (time.time(),))
            else:
                row = self._db.execute("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?",
                                       (user_id, time.time()))
            return row.fetchone()["n"]

    def messages_involving(self, user_id: int) -> list[dict]:
        """Everything this person wrote, plus private messages they received (for their data export)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT m.id, m.created_at, m.body, m.enc, m.deleted_at, m.edited_at, m.reply_to, r.username AS recipient,"
                " s.username AS sender, a.name AS file_name, a.size AS file_size"
                " FROM messages m JOIN users s ON s.id = m.sender_id LEFT JOIN users r ON r.id = m.recipient_id"
                " LEFT JOIN attachments a ON a.message_id = m.id AND a.removed_at IS NULL"
                " WHERE m.sender_id = ? OR m.recipient_id = ? ORDER BY m.id", (user_id, user_id)).fetchall()
        return [dict(row) for row in rows]

    # ----- audit log -----

    def append_audit(self, actor: str, action: str, target: str = "", detail: str = "",
                     when: float | None = None) -> int:
        entry = {"ts": when or time.time(), "actor": actor, "action": action,
                 "target": target[:200], "detail": detail[:300]}
        with self._lock:
            last = self._db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            previous = last["hash"] if last else GENESIS
            digest = entry_hash(previous, entry)
            cursor = self._db.execute(
                "INSERT INTO audit (ts, actor, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (entry["ts"], actor, action, entry["target"], entry["detail"], previous, digest))
            count = self._db.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]
            self._db.execute(
                "INSERT INTO settings (key, value) VALUES ('audit_head', ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (f"{count}:{digest}",))
            self._db.commit()
            return cursor.lastrowid

    def audit_rows(self, actor: str | None = None, action: str | None = None, before_id: int | None = None,
                   limit: int = 15) -> list[dict]:
        """Newest first, optionally filtered, one page at a time."""
        clauses, params = [], []
        if actor:
            clauses.append("actor = ? COLLATE NOCASE")
            params.append(actor)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if before_id:
            clauses.append("id < ?")
            params.append(before_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._db.execute(
                f"SELECT id, ts, actor, action, target, detail FROM audit{where} ORDER BY id DESC LIMIT ?",
                (*params, max(1, min(limit, 50)))).fetchall()
        return [dict(row) for row in rows]

    def audit_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]

    def verify_audit(self) -> tuple[bool, int | None, str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, actor, action, target, detail, prev_hash, hash FROM audit ORDER BY id").fetchall()
            head = self.get_setting("audit_head")
        return verify_rows(rows, head)

    # ----- public keys for end-to-end encryption (the server never holds a secret key) -----

    def get_user_keys(self, user_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT dh, sign, sig, fingerprint, version, updated_at FROM user_keys WHERE user_id = ?",
                (user_id,)).fetchone()
        return dict(row) if row else None

    def keys_for_names(self, names: list[str]) -> dict[str, dict]:
        """{canonical username: {dh, sign, sig, fingerprint, version}} for those who have published keys."""
        if not names:
            return {}
        marks = ",".join("?" * len(names))
        with self._lock:
            rows = self._db.execute(
                "SELECT u.username, k.dh, k.sign, k.sig, k.fingerprint, k.version FROM user_keys k"
                f" JOIN users u ON u.id = k.user_id WHERE u.username IN ({marks}) COLLATE NOCASE", names).fetchall()
        return {row["username"]: {key: row[key] for key in ("dh", "sign", "sig", "fingerprint", "version")}
                for row in rows}

    def names_with_keys(self) -> set[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT u.username FROM user_keys k JOIN users u ON u.id = k.user_id").fetchall()
        return {row["username"] for row in rows}

    def set_user_keys(self, user_id: int, dh: str, sign: str, sig: str, fingerprint: str) -> str:
        """Publish or replace someone's public keys. Returns 'created', 'same' or 'changed'."""
        now = time.time()
        with self._lock:
            current = self._db.execute("SELECT fingerprint, version FROM user_keys WHERE user_id = ?",
                                       (user_id,)).fetchone()
            if current is None:
                self._db.execute(
                    "INSERT INTO user_keys (user_id, dh, sign, sig, fingerprint, version, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,1,?,?)", (user_id, dh, sign, sig, fingerprint, now, now))
                status = "created"
            elif current["fingerprint"] == fingerprint:
                return "same"
            else:
                self._db.execute(
                    "UPDATE user_keys SET dh=?, sign=?, sig=?, fingerprint=?, version=?, updated_at=? WHERE user_id=?",
                    (dh, sign, sig, fingerprint, current["version"] + 1, now, user_id))
                status = "changed"
            self._db.commit()
        return status

    def delete_user_keys(self, user_id: int) -> bool:
        with self._lock:
            had = self._db.execute("DELETE FROM user_keys WHERE user_id = ?", (user_id,)).rowcount > 0
            self._db.execute("DELETE FROM key_backups WHERE user_id = ?", (user_id,))
            self._db.commit()
        return had

    def get_backup(self, user_id: int) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT blob FROM key_backups WHERE user_id = ?", (user_id,)).fetchone()
        return row["blob"] if row else None

    def set_backup(self, user_id: int, blob: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO key_backups (user_id, blob, updated_at) VALUES (?,?,?)"
                " ON CONFLICT(user_id) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at",
                (user_id, blob, time.time()))
            self._db.commit()
