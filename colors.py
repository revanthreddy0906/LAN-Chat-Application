"""Minimal ANSI color helpers shared by the server and client CLIs."""

from __future__ import annotations

import sys

RESET = "\033[0m"
BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
MAGENTA = "35"
CYAN = "36"


def supports_color(stream=sys.stdout) -> bool:
    return stream.isatty()


def colorize(code: str, text: str, *, enabled: bool) -> str:
    return f"\033[{code}m{text}{RESET}" if enabled else text
