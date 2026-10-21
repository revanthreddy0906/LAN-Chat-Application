"""The end-to-end encrypted group room (mixed into ChatServer).

When the room is switched on, public messages must be encrypted by their sender with a chain
key that the other members hold; the server checks the shape, the epoch and the message number,
stores the ciphertext, and relays it. It also stores the sealed key envelopes members give each
other, so people who were offline (or restart) can fetch theirs. It never holds a chain key.
"""

from __future__ import annotations

import json

import e2ee
from permissions import can

ROOM_MODES = ("off", "on")
MAX_ENVELOPES_PER_REQUEST = 40
MAX_ENVELOPE_CHARS = 700
MAX_KEYS_FRAME_CHARS = 3600
ENVELOPES_PER_PAGE = 5
MAX_MENTIONS = 20


class RoomMixin:
    """Needs the host class to provide: store, audit(), _emit(), _error(), _lock, _clients, _online()."""

    @property
    def e2ee_room(self) -> str:
        value = self.store.get_setting("e2ee_room", "off")
        return value if value in ROOM_MODES else "off"

    @property
    def room_epoch(self) -> int:
        return self.store.room_epoch()

    def room_state_for(self, client) -> dict:
        return {"t": "room_state", "mode": self.e2ee_room, "epoch": self.room_epoch,
                "next": self.store.last_group_number(client.user_id, self.room_epoch) + 1,
                "missing": self.store.missing_recipients(client.user_id, self.room_epoch)}

    def set_e2ee_room(self, mode: str, actor: str = "console") -> None:
        if mode not in ROOM_MODES:
            raise ValueError("the room setting must be on or off.")
        self.store.set_setting("e2ee_room", mode)
        self.audit(actor, "room_encryption", detail=mode)
        self._emit({"t": "e2ee_room", "mode": mode, "epoch": self.room_epoch})

    def bump_room_epoch(self, actor: str = "console", reason: str = "") -> int:
        """Move the room to a new key epoch: everyone starts a fresh chain, and removed people never get it."""
        epoch = self.store.bump_room_epoch()
        self.audit(actor, "room_rekeyed", detail=f"epoch {epoch}" + (f", {reason}" if reason else ""))
        self._emit({"t": "room_epoch", "epoch": epoch})
        return epoch

    # ----- sending to the room

    def _validated_group(self, client, enc, claim: bool = True) -> str | None:
        """A group envelope as JSON text if it is acceptable, else None (the sender has been told why)."""
        if self.e2ee_room != "on":
            self._error(client, "the group room is not end-to-end encrypted.")
            return None
        if self.store.get_user_keys(client.user_id) is None:
            self._error(client, "set up your encryption keys before writing in the encrypted room.")
            return None
        try:
            epoch, number = e2ee.group_envelope_fields(enc)
            if e2ee.envelope_size(enc) > e2ee.MAX_ENVELOPE_CHARS:
                raise e2ee.CryptoError("too large")
        except e2ee.CryptoError:
            self._error(client, "that encrypted message is malformed or too long.")
            return None
        if epoch != self.room_epoch:
            self._error(client, "the room moved to new keys; your window will catch up. Please send that again.")
            self._emit(self.room_state_for(client), [client])
            return None
        if claim:
            verdict = self.store.claim_group_number(client.user_id, epoch, number)
            if verdict != "ok":
                self._error(client, "that message number was already used; your window will resynchronise.")
                self._emit(self.room_state_for(client), [client])
                return None
        return json.dumps(enc, separators=(",", ":"))

    def _room_mentions(self, client, event) -> tuple[list[int], bool] | None:
        """Who a room message mentions. The text is unreadable here, so the sender names them."""
        names = event.get("mentions") or []
        if not isinstance(names, list) or len(names) > MAX_MENTIONS or not all(isinstance(n, str) for n in names):
            self._error(client, "malformed mentions.")
            return None
        everyone = bool(event.get("everyone"))
        if everyone and not can(client.role, "mention_everyone"):
            self._error(client, "only admins can mention @everyone.")
            return None
        ids = []
        for name in dict.fromkeys(names):
            user = self.store.get_user(name)
            if user is not None and not user.disabled and user.id != client.user_id:
                ids.append(user.id)
        return ids, everyone

    def _room_send(self, client, event: dict) -> None:
        if event.get("body") not in (None, ""):
            self._error(client, "an encrypted message must not also carry readable text.")
            return
        mentions = self._room_mentions(client, event)
        if mentions is None:
            return
        text = self._validated_group(client, event["enc"])
        if text is not None:
            self._post_message(client, "", reply_to=event.get("reply_to"), enc=text, room_mentions=mentions)

    # ----- keys for the room

    def _on_group_state(self, client, event: dict) -> None:
        self._emit({**self.room_state_for(client), "req": event.get("req")}, [client])

    def _on_group_keys(self, client, event: dict) -> None:
        """Members hand each other their chain keys, sealed; the server files and forwards them."""
        req, epoch, envelopes = event.get("req"), event.get("epoch"), event.get("envelopes")
        if (self.e2ee_room != "on" or not isinstance(envelopes, dict) or not envelopes
                or len(envelopes) > MAX_ENVELOPES_PER_REQUEST or epoch != self.room_epoch):
            self._emit({**self.room_state_for(client), "req": req, "rejected": True}, [client])
            return
        total = 0
        accepted = []
        for name, envelope in envelopes.items():
            text = json.dumps(envelope, separators=(",", ":")) if isinstance(envelope, dict) else ""
            total += len(text)
            recipient = self.store.get_user(name) if isinstance(name, str) else None
            if (not text or len(text) > MAX_ENVELOPE_CHARS or recipient is None or recipient.disabled
                    or envelope.get("e") != epoch or self.store.get_user_keys(recipient.id) is None):
                continue
            accepted.append((recipient, text))
        if total > MAX_KEYS_FRAME_CHARS:
            accepted = []
        for recipient, text in accepted:
            self.store.add_envelope(recipient.id, client.user_id, epoch, text)
            for other in self._online(recipient.username):
                self._emit({"t": "group_key", "sender": client.username, "epoch": epoch,
                            "blob": json.loads(text)}, [other])
        self._emit({**self.room_state_for(client), "req": req}, [client])

    def _on_group_keys_get(self, client, event: dict) -> None:
        after = event.get("after") if isinstance(event.get("after"), int) and event["after"] >= 0 else 0
        items = self.store.envelopes_for(client.user_id, after, ENVELOPES_PER_PAGE + 1)
        more = len(items) > ENVELOPES_PER_PAGE
        items = items[:ENVELOPES_PER_PAGE]
        self._emit({"t": "group_keys_list", "req": event.get("req"), "more": more,
                    "items": [{"id": i["id"], "sender": i["sender"], "epoch": i["epoch"],
                               "blob": json.loads(i["blob"])} for i in items]}, [client])

    HANDLERS = {"group_state": _on_group_state, "group_keys": _on_group_keys, "group_keys_get": _on_group_keys_get}
