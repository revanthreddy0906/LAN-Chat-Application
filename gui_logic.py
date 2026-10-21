"""Pure helpers for the GUI (no Tkinter), so they can be unit-tested."""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass

AVATAR_COLORS = (
    "#e5534b", "#e08a1e", "#c9a100", "#3fa34d", "#12a594",
    "#2f81f7", "#7c5cff", "#c2409b", "#d9534f", "#5f7c8a",
)


@dataclass(frozen=True)
class GroupKey:
    """Identifies who sent a message, so consecutive ones can be grouped."""

    sender: str
    mine: bool
    kind: str


def initials(name: str) -> str:
    words = [w for w in name.replace("_", " ").replace(".", " ").replace("-", " ").split() if w]
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()


def avatar_color(name: str) -> str:
    """A stable color per name (zlib.crc32, because hash() changes per process)."""
    return AVATAR_COLORS[zlib.crc32(name.lower().encode("utf-8")) % len(AVATAR_COLORS)]


def starts_group(previous: GroupKey | None, current: GroupKey) -> bool:
    return previous != current


def private_parties(name: str) -> tuple[str, bool]:
    """Return (other person, sent_by_me) for a private message's name field.

    The server sends 'Potti (private)' when someone messages you and
    'You -> Potti (private)' as the echo of your own message.
    """
    cleaned = name.removesuffix(" (private)")
    if cleaned.startswith("You -> "):
        return cleaned.removeprefix("You -> "), True
    return cleaned, False


def unread_title(base: str, unread: int, mentioned: bool = False) -> str:
    """'(3) LAN Chat', or '(@3) LAN Chat' when one of the unread messages mentions you."""
    if unread <= 0:
        return base
    return f"(@{unread}) {base}" if mentioned else f"({unread}) {base}"


def is_at_bottom(view_end: float) -> bool:
    return view_end >= 0.999


def wrap_width(canvas_width: int) -> int:
    return max(180, int(canvas_width * 0.64))


def encryption_label(encrypted: bool) -> str:
    return "Encrypted" if encrypted else "Not encrypted"


def server_subtitle(host: str, port: int, users: int) -> str:
    return f"{host}:{port} · {users} online"


def wrap_fingerprint(fingerprint: str, per_line: int = 8) -> str:
    """Split 'AA:BB:...' into lines so it is easy to compare by eye."""
    parts = fingerprint.split(":")
    return "\n".join(":".join(parts[i : i + per_line]) for i in range(0, len(parts), per_line))


QUICK_REACTIONS = ("\U0001F44D", "\u2764\ufe0f", "\U0001F602", "\U0001F389", "\U0001F62E", "\U0001F64F")
AWAY_AFTER_SECONDS = 300
TYPING_EXPIRES_SECONDS = 5.0
TYPING_SEND_INTERVAL = 3.0


def typing_label(names: list[str]) -> str:
    """'Bob is typing...' for the people currently typing, or '' for nobody."""
    names = sorted(names, key=str.lower)
    if not names:
        return ""
    if len(names) == 1:
        return f"{names[0]} is typing\u2026"
    if len(names) == 2:
        return f"{names[0]} and {names[1]} are typing\u2026"
    return f"{len(names)} people are typing\u2026"


def seen_label(names: list[str]) -> str:
    """'Seen by Bob, Carol +2' under your latest message."""
    names = sorted(names, key=str.lower)
    if not names:
        return ""
    shown = names[:3]
    extra = len(names) - len(shown)
    return "Seen by " + ", ".join(shown) + (f" +{extra}" if extra else "")


def expire_typing(typing: dict[str, float], now: float, expires: float = TYPING_EXPIRES_SECONDS) -> list[str]:
    """Drop typing entries older than `expires` seconds and return who is still typing."""
    for name in [n for n, started in typing.items() if now - started > expires]:
        del typing[name]
    return list(typing)


def should_send_typing(last_sent: float, now: float, interval: float = TYPING_SEND_INTERVAL) -> bool:
    return now - last_sent >= interval


def should_go_away(idle_seconds: float, already_away: bool, after: float = AWAY_AFTER_SECONDS) -> bool:
    return idle_seconds >= after and not already_away


def seen_by_users(read_marks: dict[str, int], message_id: int, me: str) -> list[str]:
    """Everyone except me whose read marker has reached this message."""
    return [user for user, up_to in read_marks.items() if up_to >= message_id and user.lower() != me.lower()]


def snippet_for_chip(text: str, deleted: bool = False, limit: int = 60) -> str:
    """A short quote for the 'Replying to ...' chip above the message box."""
    if deleted:
        return "(deleted message)"
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "\u2026"


_MENTION_AT_CURSOR = re.compile(r"(?:^|\s)@([A-Za-z0-9_.-]{0,32})$")


def mention_query(text: str, cursor: int) -> tuple[int, str] | None:
    """If the cursor sits right after '@abc', return (index of the '@', 'abc'); else None."""
    match = _MENTION_AT_CURSOR.search(text[:cursor])
    if not match:
        return None
    return match.start(1) - 1, match.group(1)


def suggest_mentions(prefix: str, names: list[str], me: str, include_everyone: bool, limit: int = 5) -> list[str]:
    """Members whose name starts with `prefix` (in the order given), plus 'everyone' for admins."""
    candidates = [n for n in names if n.lower() != me.lower()]
    if include_everyone:
        candidates.append("everyone")
    return [n for n in candidates if n.lower().startswith(prefix.lower())][:limit]


def apply_mention(text: str, start: int, cursor: int, name: str) -> tuple[str, int]:
    """Replace the '@abc' being typed with '@name ' and return (new text, new cursor)."""
    tail = text[cursor:]
    spacer = "" if tail.startswith(" ") else " "  # reuse a space that is already there
    return text[:start] + "@" + name + spacer + tail, start + len(name) + 2


def mentions_me(event: dict, me: str) -> bool:
    return bool(event.get("everyone")) or me.lower() in (n.lower() for n in event.get("mentions", []))


def pin_bar_text(pins: list[dict]) -> str:
    """The line in the pinned bar: the newest pin."""
    if not pins:
        return ""
    return f"\U0001F4CC {pins[0]['sender']}: {pins[0]['snippet']}"


def needs_older_messages(target_id: int, oldest_loaded_id: int | None, has_more: bool) -> bool:
    """To show an old message we must fetch an earlier page if it is older than what we hold."""
    return has_more and (oldest_loaded_id is None or target_id < oldest_loaded_id)


def has_search_words(query: str) -> bool:
    """True if the search box holds at least one letter or digit worth searching for."""
    return re.search(r"\w", query) is not None
