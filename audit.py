"""A tamper-evident audit log: every row's hash covers the row before it.

Each entry stores `hash = sha256(previous_hash + canonical_json(entry))`. Changing, removing
or inserting a row anywhere breaks the chain from that point on, and `verify` finds where.
Message text is never written here, only who did what to what.
"""

from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def canonical(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(previous: str, entry: dict) -> str:
    return hashlib.sha256((previous + canonical(entry)).encode("utf-8")).hexdigest()


def entry_of(row) -> dict:
    return {"ts": row["ts"], "actor": row["actor"], "action": row["action"],
            "target": row["target"], "detail": row["detail"]}


def verify_rows(rows, head: str | None = None) -> tuple[bool, int | None, str]:
    """Walk the chain. Returns (ok, id of the first bad row or None, explanation)."""
    previous, count = GENESIS, 0
    for row in rows:
        count += 1
        if row["prev_hash"] != previous:
            return False, row["id"], f"row {row['id']} does not follow the one before it (a row was removed or added)"
        if entry_hash(previous, entry_of(row)) != row["hash"]:
            return False, row["id"], f"row {row['id']} was changed after it was written"
        previous = row["hash"]
    if head is not None and head != f"{count}:{previous}":
        return False, None, "the newest rows are missing (the log is shorter than it should be)"
    return True, None, f"{count} entries, chain intact"
