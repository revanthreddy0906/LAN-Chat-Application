"""Colors and fonts for the LAN Chat window."""

from __future__ import annotations

import subprocess
import sys
import tkinter.font as tkfont

LIGHT = {
    "bg": "#f1f3f6", "panel": "#ffffff", "card": "#ffffff", "border": "#dfe3e8",
    "text": "#1f2328", "muted": "#6b7480", "accent": "#2f6fed", "accent_hover": "#2760d6",
    "accent_text": "#ffffff", "bubble_other": "#eceff3", "bubble_other_text": "#1f2328",
    "bubble_mine": "#2f6fed", "bubble_mine_text": "#ffffff", "bubble_mine_time": "#cfe0ff",
    "bubble_private": "#efe5ff", "bubble_private_text": "#34196b", "bubble_private_mine": "#7c5cff",
    "pill_bg": "#e9ecf0", "pill_text": "#59626d", "join": "#1a7f37", "leave": "#9a6700",
    "error": "#cf222e", "input_bg": "#ffffff", "selected": "#e3edff", "online": "#2da44e",
    "button_2": "#eef1f5", "button_2_hover": "#e1e6ec",
}

DARK = {
    "bg": "#121418", "panel": "#1a1d22", "card": "#21252b", "border": "#30353d",
    "text": "#e7e9ec", "muted": "#8b95a1", "accent": "#4c8dff", "accent_hover": "#6ba0ff",
    "accent_text": "#ffffff", "bubble_other": "#2a2f36", "bubble_other_text": "#e7e9ec",
    "bubble_mine": "#3b78e7", "bubble_mine_text": "#ffffff", "bubble_mine_time": "#c3d8ff",
    "bubble_private": "#382a5a", "bubble_private_text": "#eadcff", "bubble_private_mine": "#6a4fd6",
    "pill_bg": "#262b32", "pill_text": "#98a2ad", "join": "#3fb950", "leave": "#d29922",
    "error": "#ff7b72", "input_bg": "#21252b", "selected": "#2a3a57", "online": "#3fb950",
    "button_2": "#2a2f36", "button_2_hover": "#343a43",
}

PALETTES = {"light": LIGHT, "dark": DARK}


def detect_system_theme() -> str:
    """Follow the macOS appearance; default to light elsewhere."""
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True, timeout=2,
            )
            if result.stdout.strip().lower() == "dark":
                return "dark"
        except (OSError, subprocess.SubprocessError):
            pass
    return "light"


class Fonts:
    """Fonts derived from the system default so they look native."""

    def __init__(self) -> None:
        family = tkfont.nametofont("TkDefaultFont").actual("family")
        self.body = (family, 13)
        self.bold = (family, 13, "bold")
        self.small = (family, 11)
        self.small_bold = (family, 11, "bold")
        self.tiny = (family, 10)
        self.title = (family, 17, "bold")
        self.big_title = (family, 26, "bold")
        self.emoji = (family, 18)
