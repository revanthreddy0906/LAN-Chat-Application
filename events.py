"""Protocol v2 events, and how they are shown to legacy (text) clients.

Every v2 message is one JSON object with a "t" (type) field, sent inside the
same length-prefixed frame as before. Server to client:

  welcome, history_start, history_end, message, notice, members, presence,
  typing, edited, deleted, reactions, read, pins, search_results,
  page_start, page_end, upload_ready, upload_denied, download_ready, transfer_error

Client to server:

  send {body, to?, reply_to?}   edit {id, body}      delete {id}
  react {id, emoji}             typing {on}          presence {status}
  read {up_to}                  members {}           ping {}
  pin {id, on}                  search {q, req}      history {before, limit}
  upload {req, name, size, sha256, to?, caption?, reply_to?}   download {req, id}

Replies to those: pins, search_results, and a page_start / message... / page_end
run for history.

`legacy_text` renders an event as the plain line older clients understand, or
returns None when there is nothing sensible to show (edits, typing, ...).
"""

from __future__ import annotations

import json
import time

from protocol import MAX_MESSAGE_BYTES
from store import StoredMessage

PROTOCOL_VERSION = 2
MAX_BODY_BYTES = 3400  # leaves room in a 4096-byte frame for the JSON around the text
SNIPPET_CHARS = 80
MEMBERS_PER_PAGE = 40


def encode(event: dict) -> str:
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def decode(text: str) -> dict | None:
    """Parse an incoming frame. Returns None if it is not a v2 event."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict) and isinstance(data.get("t"), str):
        return data
    return None


def clock(timestamp: float) -> str:
    return time.strftime("%H:%M", time.localtime(timestamp))


def snippet(text: str, limit: int = SNIPPET_CHARS) -> str:
    """One short line for quoting a message: whitespace collapsed, cut with an ellipsis."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


def message_event(
    message: StoredMessage,
    parent: StoredMessage | None = None,
    reactions: list[tuple[str, list[str]]] | None = None,
    history: bool = False,
    mentions: list[str] | None = None,
    attachment: dict | None = None,
) -> dict:
    reply = None
    if message.reply_to is not None:
        reply = {"id": message.reply_to, "sender": "", "snippet": "", "deleted": True}
        if parent is not None:
            reply = {
                "id": parent.id,
                "sender": parent.sender,
                "snippet": "" if parent.deleted_at else snippet(parent.body),
                "deleted": bool(parent.deleted_at),
                "encrypted": bool(parent.enc),  # the server cannot quote it; the window fills it in
            }
    return {
        "t": "message",
        "id": message.id,
        "sender": message.sender,
        "to": message.recipient,
        "body": message.body,
        "ts": message.created_at,
        "reply_to": message.reply_to,
        "reply": reply,
        "edited": message.edited_at is not None,
        "deleted": message.deleted_at is not None,
        "reactions": [{"emoji": emoji, "users": users} for emoji, users in (reactions or [])],
        "mentions": mentions or [],
        "everyone": message.mention_all,
        "history": history,
        "att": attachment,
        "enc": json.loads(message.enc) if message.enc else None,
    }


def snippet_around(body: str, terms: list[str], width: int = 100) -> str:
    """A short piece of `body` centred on the first search word that appears in it."""
    flat = " ".join(body.split())
    if len(flat) <= width:
        return flat
    lowered = flat.lower()
    hits = [lowered.find(term) for term in terms if term in lowered]
    center = min(hits) if hits else 0
    start = max(0, min(center - width // 3, len(flat) - width))
    piece = flat[start : start + width].strip()
    return ("\u2026" if start > 0 else "") + piece + ("\u2026" if start + width < len(flat) else "")


def pins_event(messages: list[StoredMessage]) -> dict:
    return {
        "t": "pins",
        "pins": [
            {"id": m.id, "sender": m.sender, "snippet": snippet(m.body), "ts": m.created_at}
            for m in messages
        ],
    }


def search_event(request_id, query: str, results: list[dict]) -> dict:
    return {"t": "search_results", "req": request_id, "q": query, "results": results}


def reactions_event(message_id: int, reactions: list[tuple[str, list[str]]]) -> dict:
    return {
        "t": "reactions",
        "id": message_id,
        "reactions": [{"emoji": emoji, "users": users} for emoji, users in reactions],
    }


def fit_frame(event: dict) -> str:
    """Encode an event, trimming the message text if the frame would be too big."""
    text = encode(event)
    while len(text.encode("utf-8")) > MAX_MESSAGE_BYTES and event.get("body"):
        body = event["body"]
        event = {**event, "body": body[: max(0, int(len(body) * 0.9) - 1)] + "…"}
        text = encode(event)
    return text


def legacy_text(event: dict, viewer: str) -> str | None:
    """The plain-text line for a legacy client, or None to send nothing."""
    kind = event["t"]
    if kind == "notice":
        return event["text"]
    if kind != "message" or event.get("deleted"):
        return None
    stamp = clock(event["ts"])
    sender, recipient, body = event["sender"], event.get("to"), event["body"]
    if event.get("enc"):  # a terminal cannot decrypt; say what it is
        body = "[encrypted message: open the chat window to read it]"
    attachment = event.get("att")
    if attachment:  # a terminal client cannot open files; tell it what was shared
        shared = f"[{attachment['kind']}: {attachment['name']}]"
        body = f"{shared} {body}".strip()
    reply = event.get("reply")
    quoted = f" (replying to {reply['sender']})" if reply and reply.get("sender") else ""
    if recipient is None:
        if sender.lower() == viewer.lower() and not event.get("history"):
            return None  # legacy clients already show what they typed
        return f"[{stamp}] {sender}{quoted}: {body}"
    if sender.lower() == viewer.lower():
        return f"[{stamp}] You -> {recipient} (private): {body}"
    return f"[{stamp}] {sender} (private){quoted}: {body}"


def member_pages(members: list[tuple[str, str, str]]) -> list[dict]:
    """Split [(name, role, status)] into 'members' events that each fit a frame."""
    pages = [members[i : i + MEMBERS_PER_PAGE] for i in range(0, len(members), MEMBERS_PER_PAGE)] or [[]]
    return [
        {"t": "members", "page": index, "pages": len(pages), "members": [list(m) for m in page]}
        for index, page in enumerate(pages)
    ]
