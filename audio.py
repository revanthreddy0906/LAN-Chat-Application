"""Opening files, playing sounds and (optionally) recording voice messages.

Everything here is optional: with no player the file is opened by the system,
and recording only appears when the third-party `sounddevice` package exists.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import wave

SAMPLE_RATE = 16000
MAX_RECORD_SECONDS = 120


def open_path(path: str | os.PathLike[str]) -> bool:
    """Open a file with the system's default program. Returns False if nothing could be started."""
    path = str(path)
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", path])
        return True
    except (OSError, ValueError):
        return False


def reveal_path(path: str | os.PathLike[str]) -> bool:
    """Show a file in the file manager."""
    path = str(path)
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", "-R", path])
        elif sys.platform.startswith("win"):
            subprocess.Popen(["explorer", "/select,", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path)])
        return True
    except OSError:
        return False


def _player_command(path: str) -> list[str] | None:
    if sys.platform == "darwin" and shutil.which("afplay"):
        return ["afplay", path]
    if sys.platform.startswith("linux"):
        for tool, args in (("paplay", []), ("aplay", ["-q"]), ("ffplay", ["-nodisp", "-autoexit", "-loglevel", "quiet"])):
            if shutil.which(tool):
                return [tool, *args, path]
    return None


class Player:
    """Plays one sound at a time through a command-line player."""

    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self.path: str | None = None

    def playing(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def play(self, path: str | os.PathLike[str]) -> bool:
        self.stop()
        path = str(path)
        if sys.platform.startswith("win"):
            try:
                import winsound
                winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
                self.path = path
                return True
            except (ImportError, RuntimeError):
                return False
        command = _player_command(path)
        if command is None:
            return False
        try:
            self._process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            return False
        self.path = path
        return True

    def stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
        self._process = None
        if sys.platform.startswith("win"):
            try:
                import winsound
                winsound.PlaySound(None, winsound.SND_PURGE)
            except (ImportError, RuntimeError):
                pass
        self.path = None


def recorder_available() -> bool:
    try:
        import sounddevice
    except (ImportError, OSError):
        return False
    return sounddevice is not None


class VoiceRecorder:
    """Records the microphone to a WAV file (needs the optional `sounddevice` package)."""

    def __init__(self) -> None:
        self._stream = None
        self._frames: list[bytes] = []
        self._lock = threading.Lock()
        self.started_at = 0.0

    def start(self) -> None:
        import sounddevice

        self._frames = []

        def collect(indata, _frames, _time, _status) -> None:
            with self._lock:
                self._frames.append(bytes(indata))

        self._stream = sounddevice.RawInputStream(
            samplerate=SAMPLE_RATE, channels=1, dtype="int16", callback=collect)
        self._stream.start()
        self.started_at = time.monotonic()

    def seconds(self) -> float:
        return time.monotonic() - self.started_at if self._stream is not None else 0.0

    def stop(self, directory: str | None = None) -> str | None:
        """Finish and return the path of a .wav file, or None if nothing was recorded."""
        if self._stream is None:
            return None
        self._stream.stop()
        self._stream.close()
        self._stream = None
        with self._lock:
            data = b"".join(self._frames)
        if not data:
            return None
        handle, path = tempfile.mkstemp(suffix=".wav", prefix="voice-", dir=directory)
        os.close(handle)
        with wave.open(path, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(SAMPLE_RATE)
            wav.writeframes(data)
        return path
