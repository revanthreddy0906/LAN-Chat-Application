"""Safe handling of shared files: names, types, and where the bytes live on disk.

Files are stored by the SHA-256 of their content (`storage/ab/abcdef...`), never
under a name the sender chose, so a hostile file name cannot escape the folder
or overwrite anything. The server never opens or runs what it stores.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import uuid
from pathlib import Path

MAX_NAME_CHARS = 80
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
CHUNK = 64 * 1024

IMAGE_EXTENSIONS = {".png", ".gif", ".jpg", ".jpeg", ".webp", ".bmp"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".webm", ".avi", ".mkv"}
AUDIO_EXTENSIONS = {".wav", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".aiff"}

# Programs and scripts that run when opened. Receiving them is the risk, not storing them.
BLOCKED_EXTENSIONS = frozenset({
    ".exe", ".bat", ".cmd", ".com", ".scr", ".msi", ".dll", ".vbs", ".ps1",
    ".jar", ".apk", ".lnk", ".pif", ".reg", ".app", ".command",
})

MEDIA_KINDS = ("image", "video", "audio", "file")


def sanitize_name(name: str) -> str:
    """A safe display and save name: no folders, no control characters, bounded length."""
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*')
    name = name.strip(" .")
    if not name:
        return "file"
    stem, dot, ext = name.rpartition(".")
    if len(name) > MAX_NAME_CHARS:
        keep = max(1, MAX_NAME_CHARS - len(ext) - 1) if dot else MAX_NAME_CHARS
        name = (stem[:keep] + "." + ext) if dot else name[:keep]
    return name


def extension(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def is_blocked(name: str, blocked=BLOCKED_EXTENSIONS) -> bool:
    return extension(name) in blocked


def kind_for(name: str) -> str:
    ext = extension(name)
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in VIDEO_EXTENSIONS:
        return "video"
    if ext in AUDIO_EXTENSIONS:
        return "audio"
    return "file"


def mime_for(name: str) -> str:
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def sha256_of_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def unique_path(folder: str | os.PathLike[str], name: str) -> Path:
    """`name` inside `folder`, or `name (2)`, `name (3)` ... if it is taken."""
    folder = Path(folder)
    candidate = folder / sanitize_name(name)
    stem, ext = candidate.stem, candidate.suffix
    number = 2
    while candidate.exists():
        candidate = folder / f"{stem} ({number}){ext}"
        number += 1
    return candidate


class BlobStore:
    """Content-addressed files on disk, with a temp area for uploads in progress."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.clean_temp()

    def clean_temp(self) -> None:
        """Remove half-finished uploads left behind by a crash."""
        for leftover in self.tmp.glob("*"):
            try:
                leftover.unlink()
            except OSError:
                pass

    def path_for(self, sha256: str) -> Path:
        if not SHA256_PATTERN.fullmatch(sha256):
            raise ValueError("not a sha256 digest")
        return self.root / sha256[:2] / sha256

    def exists(self, sha256: str) -> bool:
        return self.path_for(sha256).is_file()

    def new_temp(self) -> Path:
        return self.tmp / uuid.uuid4().hex

    def commit(self, temp: Path, sha256: str) -> Path:
        """Move a verified upload into place (a duplicate upload simply reuses the existing file)."""
        target = self.path_for(sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            temp.unlink(missing_ok=True)
        else:
            os.replace(temp, target)
        return target

    def remove(self, sha256: str) -> None:
        self.path_for(sha256).unlink(missing_ok=True)
