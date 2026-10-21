"""Brute-force and abuse protection: login lockout, rate limits, password rules.

All of it lives in memory (a restart clears the counters, which is fine for a LAN
server) and takes a clock argument so the tests can move time forward instantly.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

Clock = Callable[[], float]

COMMON_PASSWORDS = frozenset({
    "123456", "1234567", "12345678", "123456789", "password", "password1", "qwerty", "qwerty123",
    "111111", "000000", "abc123", "abcdef", "letmein", "welcome", "iloveyou", "admin", "secret",
    "passw0rd", "123123", "654321",
})
DEFAULT_MIN_PASSWORD = 6
MAX_PASSWORD = 128


def check_password(password: str, username: str = "", min_length: int = DEFAULT_MIN_PASSWORD) -> str | None:
    """Why this password is not acceptable for a NEW account or a change, or None if it is fine."""
    if len(password) < min_length:
        return f"use at least {min_length} characters"
    if len(password) > MAX_PASSWORD:
        return f"use at most {MAX_PASSWORD} characters"
    lowered = password.lower()
    if username and lowered == username.lower():
        return "the password must not be your username"
    if lowered in COMMON_PASSWORDS or len(set(password)) == 1:
        return "that password is too easy to guess"
    return None


class LoginGuard:
    """Slows down password guessing.

    After MAX_FAILS wrong passwords for one (address, username) within WINDOW seconds the pair is
    locked, for 30 s the first time, then doubling up to 15 minutes. A whole address that keeps
    failing for many different names is locked the same way. A correct password clears the pair.
    """

    MAX_FAILS = 5
    ADDRESS_MAX_FAILS = 20
    WINDOW = 300.0
    BASE_LOCK = 30.0
    MAX_LOCK = 900.0
    FORGET_AFTER = 3600.0

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self._clock = clock
        self._state: dict[tuple, dict] = {}
        self._lock = threading.Lock()

    def _entry(self, key: tuple) -> dict:
        return self._state.setdefault(key, {"fails": deque(), "locked_until": 0.0, "level": 0, "last": 0.0})

    def retry_after(self, address: str, username: str) -> float:
        """Seconds the caller must still wait (0 when free to try)."""
        now = self._clock()
        with self._lock:
            waits = [0.0]
            for key in ((address, username.lower()), (address,)):
                entry = self._state.get(key)
                if entry and entry["locked_until"] > now:
                    waits.append(entry["locked_until"] - now)
            return max(waits)

    def failed(self, address: str, username: str) -> float:
        """Record a wrong password. Returns the lock time that now applies (0 if none)."""
        now = self._clock()
        applied = 0.0
        with self._lock:
            self._forget_old(now)
            for key, limit in (((address, username.lower()), self.MAX_FAILS), ((address,), self.ADDRESS_MAX_FAILS)):
                entry = self._entry(key)
                entry["last"] = now
                fails = entry["fails"]
                fails.append(now)
                while fails and now - fails[0] > self.WINDOW:
                    fails.popleft()
                if len(fails) >= limit:
                    entry["level"] += 1
                    lock = min(self.BASE_LOCK * 2 ** (entry["level"] - 1), self.MAX_LOCK)
                    entry["locked_until"] = now + lock
                    fails.clear()
                    applied = max(applied, lock)
        return applied

    def succeeded(self, address: str, username: str) -> None:
        with self._lock:
            self._state.pop((address, username.lower()), None)

    def _forget_old(self, now: float) -> None:
        stale = [k for k, e in self._state.items() if now - e["last"] > self.FORGET_AFTER and e["locked_until"] < now]
        for key in stale:
            del self._state[key]


class RateLimiter:
    """A token bucket: `capacity` actions at once, refilled at `per_second`."""

    def __init__(self, capacity: float, per_second: float, clock: Clock = time.monotonic) -> None:
        self.capacity = capacity
        self.per_second = per_second
        self._clock = clock
        self._tokens = capacity
        self._stamp = clock()

    def allow(self, cost: float = 1.0) -> bool:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._stamp) * self.per_second)
        self._stamp = now
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


class SlidingWindow:
    """At most `limit` events per key within `window` seconds (used for connections and sign-ups)."""

    def __init__(self, limit: int, window: float, clock: Clock = time.monotonic) -> None:
        self.limit, self.window, self._clock = limit, window, clock
        self._events: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            events = self._events.setdefault(key, deque())
            while events and now - events[0] > self.window:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            if len(self._events) > 2048:  # keep memory bounded on a busy network
                for stale in [k for k, v in self._events.items() if not v or now - v[-1] > self.window]:
                    self._events.pop(stale, None)
            return True
