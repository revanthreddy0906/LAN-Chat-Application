"""Find LAN Chat servers on the local network (UDP request/response)."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable

DISCOVERY_PORT = 50505
PROBE = b"LANCHAT?"
DEFAULT_TIMEOUT = 1.5


@dataclass(frozen=True)
class FoundServer:
    host: str
    port: int
    name: str
    tls: bool
    users: int


def lan_address() -> str:
    """This machine's LAN IP. A connected UDP socket sends no packets."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


class DiscoveryResponder:
    """Answers 'LANCHAT?' probes with the server's name, port and mode."""

    def __init__(
        self,
        info: Callable[[], dict],
        port: int = DISCOVERY_PORT,
        bind: str = "0.0.0.0",
    ) -> None:
        self._info = info
        self._requested_port = port
        self._bind = bind
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.port = port

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind((self._bind, self._requested_port))
        except OSError:
            sock.close()
            raise
        sock.settimeout(0.3)
        self._socket = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                data, address = self._socket.recvfrom(256)
            except socket.timeout:
                continue
            except OSError:
                return
            if data.strip() != PROBE:
                continue
            try:
                self._socket.sendto(json.dumps(self._info()).encode("utf-8"), address)
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1)


def _is_loopback(host: str) -> bool:
    return host.startswith("127.")


def _dedupe(found: list[FoundServer]) -> list[FoundServer]:
    """Drop the loopback copy of a server that also answered on its LAN address."""
    best: dict[tuple[str, int], FoundServer] = {}
    for server in found:
        key = (server.name, server.port)
        current = best.get(key)
        if current is None or (_is_loopback(current.host) and not _is_loopback(server.host)):
            best[key] = server
    return sorted(best.values(), key=lambda s: (s.name.lower(), s.port))


def discover(
    timeout: float = DEFAULT_TIMEOUT,
    port: int = DISCOVERY_PORT,
    targets: list[tuple[str, int]] | None = None,
) -> list[FoundServer]:
    """Broadcast a probe and collect replies for `timeout` seconds."""
    if targets is None:
        targets = [("255.255.255.255", port), ("127.0.0.1", port)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    found: list[FoundServer] = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 0))
        for target in targets:
            try:
                sock.sendto(PROBE, target)
            except OSError:
                pass
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, (host, _) = sock.recvfrom(2048)
            except (socket.timeout, OSError):
                break
            try:
                info = json.loads(data.decode("utf-8"))
                found.append(
                    FoundServer(
                        host=host,
                        port=int(info["port"]),
                        name=str(info.get("name", host))[:40],
                        tls=bool(info.get("tls", False)),
                        users=int(info.get("users", 0)),
                    )
                )
            except (ValueError, KeyError, TypeError):
                continue
    finally:
        sock.close()
    return _dedupe(found)
