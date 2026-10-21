"""Client side of file sharing: upload and download over a separate data connection.

The chat connection hands out a one-time ticket (see server.py); the bytes then
travel on their own TLS connection, so a big file never blocks the chat.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import tempfile
from pathlib import Path
from typing import Callable

from protocol import receive_message, send_message
from storage import CHUNK

Progress = Callable[[int, int], None]  # (bytes done, bytes total)
TIMEOUT = 15.0


class TransferError(Exception):
    pass


def _open(host: str, port: int, context: ssl.SSLContext | None, kind: str, ticket: str) -> socket.socket:
    connection = socket.create_connection((host, port), TIMEOUT)
    try:
        if context is not None:
            connection = context.wrap_socket(connection)
        connection.settimeout(TIMEOUT)
        if receive_message(connection) != "USERNAME":
            raise TransferError("unexpected reply from server")
        send_message(connection, json.dumps({"v": 2, "data": kind, "ticket": ticket}))
        reply = receive_message(connection)
        if reply != "READY":
            raise TransferError((reply or "server closed the connection").removeprefix("ERROR: "))
        return connection
    except BaseException:
        connection.close()
        raise


def upload(host: str, port: int, context: ssl.SSLContext | None, ticket: str, path: str | os.PathLike[str],
           progress: Progress | None = None, cancelled: Callable[[], bool] | None = None) -> int:
    """Send a file. Returns the id of the chat message the server created."""
    size = os.path.getsize(path)
    connection = _open(host, port, context, "up", ticket)
    try:
        sent = 0
        with open(path, "rb") as handle:
            while chunk := handle.read(CHUNK):
                if cancelled and cancelled():
                    raise TransferError("cancelled")
                connection.sendall(chunk)
                sent += len(chunk)
                if progress:
                    progress(sent, size)
        reply = receive_message(connection)
        if reply is None:
            raise TransferError("server closed the connection")
        if reply.startswith("ERROR: "):
            raise TransferError(reply.removeprefix("ERROR: "))
        return int(json.loads(reply)["id"])
    except (OSError, ValueError, KeyError) as error:
        raise TransferError(str(error) or "connection lost") from error
    finally:
        connection.close()


def download(host: str, port: int, context: ssl.SSLContext | None, ticket: str, size: int, sha256: str,
             destination: str | os.PathLike[str], progress: Progress | None = None,
             cancelled: Callable[[], bool] | None = None) -> Path:
    """Fetch a file to `destination`, checking its SHA-256. A damaged file is never left behind."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # A name of our own, so two windows fetching the same file cannot trample each other.
    handle, partial_name = tempfile.mkstemp(dir=destination.parent, prefix=".download-", suffix=".part")
    os.close(handle)
    partial = Path(partial_name)
    connection = _open(host, port, context, "down", ticket)
    digest = hashlib.sha256()
    try:
        received = 0
        with open(partial, "wb") as handle:
            while received < size:
                if cancelled and cancelled():
                    raise TransferError("cancelled")
                chunk = connection.recv(min(CHUNK, size - received))
                if not chunk:
                    raise TransferError("connection closed during download")
                digest.update(chunk)
                handle.write(chunk)
                received += len(chunk)
                if progress:
                    progress(received, size)
        if digest.hexdigest() != sha256:
            raise TransferError("the file was damaged in transfer")
        os.replace(partial, destination)
        return destination
    except OSError as error:
        raise TransferError(str(error) or "connection lost") from error
    finally:
        connection.close()
        partial.unlink(missing_ok=True)

