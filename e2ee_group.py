"""The key bookkeeping for an end-to-end encrypted group room (no networking, no window).

Every member has a **chain** per epoch: a random starting key that is stepped forward with a
one-way function for each message they send. They give each other member a copy of the chain
*at the point they are now* (sealed to that member's identity key), so a person who joins later
can read what is sent from then on, but cannot step the chain backwards to earlier messages.
When the room moves to a new epoch (someone was removed), everyone starts a fresh chain and the
removed person never receives it.

The server stores the sealed copies, so after a restart each person can fetch theirs again.
"""

from __future__ import annotations

import json
import os

import e2ee
from e2ee import Bundle, CryptoError, Identity, NoKey

MAX_GROUP_JUMP = 1000  # how far ahead of the server's last number a new message may be


class RoomKeys:
    def __init__(self, identity: Identity, name: str) -> None:
        self.identity, self.name = identity, name
        self.chains: dict[tuple[str, int], dict[int, bytes]] = {}  # (sender, epoch) -> {first number: chain key}
        self.seen: dict[tuple[str, int, int], int] = {}  # (sender, epoch, number) -> message id

    # ----- my own chain

    def ensure_own_chain(self, epoch: int) -> bytes:
        """My chain for this epoch, created if I have none. Returns the key at message number 0."""
        slot = self.chains.setdefault((self.name.lower(), epoch), {})
        if 0 not in slot:
            slot[0] = os.urandom(32)
        return slot[0]

    def has_own_chain(self, epoch: int) -> bool:
        return 0 in self.chains.get((self.name.lower(), epoch), {})

    # ----- handing my chain to others

    def key_envelope(self, recipient: str, recipient_bundle: Bundle, epoch: int, from_number: int) -> dict:
        """My chain as of message `from_number`, sealed so only `recipient` can open it.

        The epoch is also left in the clear (the server needs it to file the envelope)."""
        start = e2ee.chain_advance(self.ensure_own_chain(epoch), from_number)
        payload = json.dumps({"e": epoch, "n0": from_number, "ck": e2ee.b64(start)}, separators=(",", ":")).encode()
        sealed = e2ee.seal(payload, self.identity, recipient_bundle.dh, e2ee.group_key_aad(self.name, recipient, epoch))
        return {"e": epoch, **sealed}

    def own_envelope(self, epoch: int) -> dict:
        """A copy for myself from number 0, so my own history stays readable after a restart."""
        return self.key_envelope(self.name, self.identity.public(), epoch, 0)

    def accept_envelope(self, sender: str, sender_bundles: list[Bundle], envelope: dict) -> tuple[int, int]:
        """Store a chain someone gave me. Returns (epoch, first message number it covers)."""
        epoch = envelope.get("e") if isinstance(envelope, dict) else None
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise CryptoError("the key envelope is malformed")
        data, last = None, CryptoError("no key for the sender")
        for bundle in sender_bundles:
            try:
                data = e2ee.open_sealed(envelope, self.identity, bundle, e2ee.group_key_aad(sender, self.name, epoch))
                break
            except CryptoError as error:
                last = error
        if data is None:
            raise last
        try:
            payload = json.loads(data.decode("utf-8"))
            first, key = payload["n0"], e2ee.unb64(payload["ck"])
            if payload["e"] != epoch or not isinstance(first, int) or isinstance(first, bool) or first < 0 or len(key) != 32:
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeError, CryptoError) as error:
            raise CryptoError("the key envelope is malformed") from error
        self.chains.setdefault((sender.lower(), epoch), {}).setdefault(first, key)
        return epoch, first

    # ----- messages

    def key_at(self, sender: str, epoch: int, number: int) -> bytes:
        """The chain key for one message number, or NoKey if I was never given a chain reaching it."""
        slot = self.chains.get((sender.lower(), epoch), {})
        starts = [n0 for n0 in slot if n0 <= number]
        if not starts:
            raise NoKey("sent before you were given this person's key")
        first = max(starts)
        return e2ee.chain_advance(slot[first], number - first)

    def encrypt(self, plaintext: bytes, epoch: int, number: int) -> dict:
        self.ensure_own_chain(epoch)
        return e2ee.encrypt_group(plaintext, self.identity, self.name, epoch, number,
                                  self.key_at(self.name, epoch, number))

    def decrypt(self, envelope: dict, sender: str, sender_bundles: list[Bundle]) -> bytes:
        epoch, number = e2ee.group_envelope_fields(envelope)
        chain_key = self.key_at(sender, epoch, number)
        last: CryptoError = CryptoError("no key for the sender")
        for bundle in sender_bundles:
            try:
                return e2ee.decrypt_group(envelope, sender, bundle, chain_key)
            except CryptoError as error:
                last = error
        raise last

    def first_use(self, sender: str, epoch: int, number: int, message_id: int) -> bool:
        """False if a different message already used this (sender, epoch, number): a replay or a clash."""
        key = (sender.lower(), epoch, number)
        earlier = self.seen.setdefault(key, message_id)
        return earlier == message_id
