"""Length-prefixed message framing shared by the server and client."""

from __future__ import annotations

import socket
import struct

MAX_MESSAGE_BYTES = 4096


def send_message(connection: socket.socket, message: str) -> None:
    payload = message.encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError("message is too large")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def receive_message(connection: socket.socket) -> str | None:
    header = _receive_exactly(connection, 4)
    if header is None:
        return None
    (length,) = struct.unpack("!I", header)
    if length == 0 or length > MAX_MESSAGE_BYTES:
        raise ValueError("invalid message length")
    payload = _receive_exactly(connection, length)
    return None if payload is None else payload.decode("utf-8")


def _receive_exactly(connection: socket.socket, length: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)
