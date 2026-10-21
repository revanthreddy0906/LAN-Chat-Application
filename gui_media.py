"""Everything the chat window does with shared files, away from the widget code.

Downloads and uploads run in background threads and report back through the
window's event queue, so the interface never freezes. Pictures are fetched
once, kept in a cache folder (named by the file's SHA-256) and shown inline.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import uuid
from pathlib import Path

import audio
import e2ee
import transfer
from gui_widgets import Record
from storage import human_size, is_blocked, kind_for, mime_for, sanitize_name, sha256_of_file

PREVIEW_LIMIT = 8 * 1024 * 1024  # pictures bigger than this show as a file card
THUMB_PIXELS = 320
MAX_FILE_CAPTION = 1000  # bytes; an encrypted file's description shares the message with it
MAX_PARALLEL = 3


def make_thumbnail(source: Path, target: Path) -> Path | None:
    """A small PNG a Tk window can show, made with Pillow or macOS `sips` if either is around."""
    try:
        from PIL import Image  # optional
        with Image.open(source) as image:
            image.thumbnail((THUMB_PIXELS, THUMB_PIXELS))
            image.convert("RGBA").save(target, "PNG")
        return target
    except ImportError:
        pass
    except (OSError, ValueError):
        return None
    if sys.platform == "darwin" and shutil.which("sips"):
        result = subprocess.run(
            ["sips", "-s", "format", "png", "-Z", str(THUMB_PIXELS), str(source), "--out", str(target)],
            capture_output=True, timeout=30)
        if result.returncode == 0 and target.exists():
            return target
    return None


def display_path(path: Path) -> Path | None:
    """The file to hand to Tk for a picture: PNG and GIF directly, anything else through a thumbnail."""
    if path.suffix.lower() in (".png", ".gif"):
        return path
    return make_thumbnail(path, path.with_name(path.stem + ".thumb.png"))


class MediaManager:
    def __init__(self, app) -> None:
        self.app = app
        self.cache_dir = Path(app.settings.home) / "cache"
        self.requests: dict[int, dict] = {}
        self._next = 1
        self._slots = threading.Semaphore(MAX_PARALLEL)
        self._active = 0  # downloads with a ticket request outstanding
        self._waiting: list[tuple[Record, str, str | None]] = []  # previews waiting their turn
        self.player = audio.Player()
        self.recorder = audio.VoiceRecorder() if audio.recorder_available() else None
        self._clear_outgoing()

    def _clear_outgoing(self) -> None:
        """Encrypted copies made for uploading are temporary; remove any left by a crash."""
        for leftover in (self.cache_dir / "outgoing").glob("*"):
            leftover.unlink(missing_ok=True)

    def _forget_temporary(self, info: dict) -> None:
        if info.get("tmp"):
            Path(info["tmp"]).unlink(missing_ok=True)

    # ----- plumbing

    def reset(self) -> None:
        for info in self.requests.values():
            self._forget_temporary(info)
        self.requests.clear()
        self._active = 0
        self._waiting.clear()
        self.player.stop()

    def _new_request(self, **details) -> int:
        request = self._next
        self._next += 1
        self.requests[request] = details
        return request

    def _post(self, **payload) -> None:
        """Called from worker threads: hand a result to the main thread."""
        self.app.events.put(("media", self.app.session, payload))

    def _connection(self) -> tuple[str, int, object]:
        return self.app.server_host, self.app.server_port, self.app.tls_context

    def cache_path(self, attachment: dict) -> Path:
        return self.cache_dir / attachment["sha256"][:16] / attachment["name"]

    def _refresh(self, record: Record) -> None:
        self.app.messages.refresh(record)

    # ----- downloads (also used for picture previews)

    def ensure_preview(self, record: Record) -> None:
        attachment = record.att
        if (not attachment or record.deleted or attachment["kind"] != "image"
                or attachment["size"] > PREVIEW_LIMIT or record.media.get("status")):
            return
        self.fetch(record, "preview")

    def fetch(self, record: Record, then: str, destination: str | None = None) -> None:
        """Get the file into the cache (asking the server only if it is not there), then act on it."""
        attachment = record.att
        if not attachment or record.id is None:
            return
        path = self.cache_path(attachment)
        if path.is_file() and path.stat().st_size == attachment["size"]:
            self._downloaded(record, path, then, destination)
            return
        if record.media.get("status") == "loading" and then != "preview":
            return  # already on its way
        record.media.update(status="loading", pct=0, error="", announce=then != "preview")
        if then == "preview" and self._active >= MAX_PARALLEL:
            self._waiting.append((record, then, destination))  # the server limits open tickets per person
            return
        self._active += 1
        request = self._new_request(op="download", record=record, then=then, destination=destination)
        if not self.app._send_event({"t": "download", "req": request, "id": record.id}):
            self._fail(record, "not connected")
        self._refresh(record)

    def start_export(self, destination: str) -> None:
        request = self._new_request(op="export", destination=destination)
        if not self.app._send_event({"t": "export", "req": request}):
            self.requests.pop(request, None)

    def _export_thread(self, request: int, event: dict, destination: str) -> None:
        host, port, context = self._connection()
        try:
            transfer.download(host, port, context, event["ticket"], event["size"], event["sha256"], destination)
        except transfer.TransferError as error:
            self._post(op="export_failed", request=request, reason=str(error))
            return
        self._post(op="exported", request=request)

    def on_download_ready(self, event: dict) -> None:
        info = self.requests.get(event.get("req"))
        if info and info["op"] == "export":
            threading.Thread(target=self._export_thread, daemon=True,
                             args=(event["req"], event, info["destination"])).start()
            return
        if not info or info["op"] != "download":
            return
        record = info["record"]
        path = self.cache_path(record.att)
        path.parent.mkdir(parents=True, exist_ok=True)
        threading.Thread(target=self._download_thread, daemon=True,
                         args=(event["req"], event["ticket"], record.att, path)).start()

    def _download_thread(self, request: int, ticket: str, attachment: dict, path: Path) -> None:
        host, port, context = self._connection()
        last = [-5]

        def progress(done: int, total: int) -> None:
            percent = int(done * 100 / total) if total else 100
            if percent - last[0] >= 4 or percent == 100:
                last[0] = percent
                self._post(op="progress", request=request, percent=percent)

        key = attachment.get("key")  # present for an end-to-end encrypted file
        target = path.with_name(path.name + ".enc") if key else path
        with self._slots:
            try:
                transfer.download(host, port, context, ticket, attachment["cipher_size"] if key else attachment["size"],
                                  attachment["sha256"], target, progress)
                if key:
                    e2ee.decrypt_file(str(target), str(path), e2ee.unb64(key), attachment["size"])
            except (transfer.TransferError, e2ee.CryptoError, OSError) as error:
                self._post(op="failed", request=request, reason=str(error))
                return
            finally:
                if key:
                    target.unlink(missing_ok=True)
        self._post(op="downloaded", request=request)

    def _release(self) -> None:
        """One download finished (either way): start the next waiting preview."""
        self._active = max(0, self._active - 1)
        while self._waiting and self._active < MAX_PARALLEL:
            record, then, destination = self._waiting.pop(0)
            record.media["status"] = ""
            self.fetch(record, then, destination)

    def on_transfer_error(self, event: dict) -> None:
        info = self.requests.pop(event.get("req"), None)
        if info and info["op"] == "export":
            self.app.notice(f"Could not export your data: {event.get('reason', 'failed')}")
            return
        if info and info["op"] == "download":
            self._release()
            self._fail(info["record"], event.get("reason", "download failed"))

    def _fail(self, record: Record, reason: str) -> None:
        record.media.update(status="error", error=reason)
        self._refresh(record)
        if record.media.get("announce", True):
            self.app.notice(f"Could not get {record.att['name']}: {reason}")

    def _downloaded(self, record: Record, path: Path, then: str, destination: str | None) -> None:
        record.media.update(status="ready", pct=100, path=str(path))
        if then == "preview":
            threading.Thread(target=self._preview_thread, daemon=True, args=(record, path)).start()
            return
        record.media["announce"] = True
        if then == "open":
            if not audio.open_path(path):
                self.app.notice("No program on this computer could open that file.")
        elif then == "play":
            self._toggle_play(record, path)
        elif then == "save" and destination:
            try:
                shutil.copyfile(path, destination)
                self.app.notice(f"Saved to {destination}", tone="join")
            except OSError as error:
                self.app.notice(f"Could not save the file: {error}")
        self._refresh(record)

    def _preview_thread(self, record: Record, path: Path) -> None:
        shown = display_path(path)
        self._post(op="preview", record=record, path=str(shown) if shown else None)

    def _toggle_play(self, record: Record, path: Path) -> None:
        if record.media.get("playing"):
            self.player.stop()
            record.media["playing"] = False
        elif self.player.play(path):
            record.media["playing"] = True
            self.app.root.after(500, lambda: self._watch_player(record))
        elif not audio.open_path(path):
            self.app.notice("No audio player was found on this computer.")

    def _watch_player(self, record: Record) -> None:
        if not record.media.get("playing"):
            return
        if self.player.playing():
            self.app.root.after(500, lambda: self._watch_player(record))
            return
        record.media["playing"] = False
        self._refresh(record)

    # ----- actions chosen from a message

    def open(self, record: Record) -> None:
        attachment = record.att
        if (attachment and attachment.get("key")
                and is_blocked(attachment["name"], frozenset(self.app.limits.get("blocked", [])))):
            # the server could not check the name of an encrypted file, so the window asks
            if not self.app.confirm("Open this file?", f"{attachment['name']} is a kind of file that can run programs. "
                                    "Only open it if you trust the person who sent it."):
                return
        self.fetch(record, "open")

    def play(self, record: Record) -> None:
        if record.media.get("playing"):
            self._toggle_play(record, Path(record.media["path"]))
            self._refresh(record)
        else:
            self.fetch(record, "play")

    def save_as(self, record: Record, destination: str) -> None:
        self.fetch(record, "save", destination)

    # ----- uploads

    def start_upload(self, path: str, to: str | None, reply_to: int | None, caption: str = "") -> None:
        app = self.app
        name = os.path.basename(path)
        limits = app.limits
        try:
            size = os.path.getsize(path)
        except OSError:
            app.notice(f"Could not read {name}.")
            return
        if size == 0:
            app.notice(f"{name} is empty.")
        elif size > limits.get("max_upload", 0):
            app.notice(f"{name} is {human_size(size)}; this chat allows files up to "
                       f"{human_size(limits.get('max_upload', 0))}.")
        elif is_blocked(name, frozenset(limits.get("blocked", []))):
            app.notice(f"{name}: that type of file is not allowed in this chat.")
        else:  # a private file or one for an encrypted room is encrypted when it can be
            def decided(plan) -> None:
                if plan == "plain":
                    self._plain_upload(path, name, size, to, reply_to, caption)
                elif plan != "refuse":
                    self._encrypted_upload(path, name, size, to, reply_to, caption, plan)
            app.e2ee.plan_file(to, decided)

    def _plain_upload(self, path, name, size, to, reply_to, caption) -> None:
        pending = Record("notice", f"⬆ Preparing {name}…", tone="upload")
        request = self._new_request(op="upload", path=path, name=name, to=to, reply_to=reply_to,
                                    caption=caption, size=size, pending=pending)
        self.app.messages.add(pending)
        threading.Thread(target=self._hash_thread, args=(request, path), daemon=True).start()

    def _encrypted_upload(self, path, name, size, to, reply_to, caption, bundle) -> None:
        if len(caption.encode("utf-8")) > MAX_FILE_CAPTION:
            self.app.notice(f"A caption on an encrypted file can be up to {MAX_FILE_CAPTION} bytes.")
            return
        pending = Record("notice", f"\U0001F512 Encrypting {name}…", tone="upload")
        request = self._new_request(op="upload", path=path, name=name, to=to, reply_to=reply_to, caption=caption,
                                    size=size, pending=pending, bundle=bundle)
        self.app.messages.add(pending)
        threading.Thread(target=self._encrypt_thread, args=(request, path), daemon=True).start()

    def _encrypt_thread(self, request: int, path: str) -> None:
        folder = self.cache_dir / "outgoing"
        folder.mkdir(parents=True, exist_ok=True)
        temporary = folder / (uuid.uuid4().hex + ".enc")
        key = e2ee.new_file_key()
        try:
            cipher_size, digest = e2ee.encrypt_file(path, str(temporary), key)
        except (OSError, e2ee.CryptoError) as error:
            temporary.unlink(missing_ok=True)
            self._post(op="upload_failed", request=request, reason=str(error))
            return
        self._post(op="encrypted", request=request, tmp=str(temporary), key=e2ee.b64(key),
                   cipher_size=cipher_size, sha256=digest)

    def _hash_thread(self, request: int, path: str) -> None:
        try:
            digest = sha256_of_file(path)
        except OSError as error:
            self._post(op="upload_failed", request=request, reason=str(error))
            return
        self._post(op="hashed", request=request, sha256=digest)

    def _upload_thread(self, request: int, ticket: str, path: str) -> None:
        host, port, context = self._connection()
        last = [-5]

        def progress(done: int, total: int) -> None:
            percent = int(done * 100 / total) if total else 100
            if percent - last[0] >= 3 or percent == 100:
                last[0] = percent
                self._post(op="upload_progress", request=request, percent=percent)

        with self._slots:
            try:
                transfer.upload(host, port, context, ticket, path, progress)
            except transfer.TransferError as error:
                self._post(op="upload_failed", request=request, reason=str(error))
                return
        self._post(op="uploaded", request=request)

    def on_upload_ready(self, event: dict) -> None:
        info = self.requests.get(event.get("req"))
        if info and info["op"] == "upload":
            threading.Thread(target=self._upload_thread, daemon=True,
                             args=(event["req"], event["ticket"], info.get("tmp") or info["path"])).start()

    def on_upload_denied(self, event: dict) -> None:
        info = self.requests.pop(event.get("req"), None)
        if info and info["op"] == "upload":
            self._forget_temporary(info)
            self.app.messages.remove(info["pending"])
            self.app.notice(f"{info['name']} was not sent: {event.get('reason', 'refused')}")

    # ----- results coming back from threads (run on the main thread)

    def handle(self, payload: dict) -> None:
        op = payload["op"]
        info = self.requests.get(payload.get("request"))
        if op == "hashed" and info:
            info["pending"].text = f"⬆ Sending {info['name']}…"
            self._refresh(info["pending"])
            self.app._send_event({
                "t": "upload", "req": payload["request"], "name": info["name"], "size": info["size"],
                "sha256": payload["sha256"], "to": info["to"], "reply_to": info["reply_to"],
                "caption": info["caption"],
            })
        elif op == "upload_progress" and info:
            info["pending"].text = f"⬆ Sending {info['name']}… {payload['percent']}%"
            self._refresh(info["pending"])
        elif op == "encrypted" and info:
            info["tmp"] = payload["tmp"]
            description = {"name": sanitize_name(info["name"]), "mime": mime_for(info["name"]),
                           "kind": kind_for(info["name"]), "size": info["size"], "key": payload["key"]}
            def sealed(envelope) -> None:
                if payload["request"] not in self.requests:
                    return
                if envelope is None:
                    self.requests.pop(payload["request"], None)
                    self._forget_temporary(info)
                    self.app.messages.remove(info["pending"])
                    self.app.notice(f"{info['name']} was not sent: the caption is too long, or the keys were not ready.")
                    return
                info["pending"].text = f"\U0001F512 Sending {info['name']}…"
                self._refresh(info["pending"])
                self.app._send_event({
                    "t": "upload", "req": payload["request"], "name": "", "size": payload["cipher_size"],
                    "sha256": payload["sha256"], "to": info["to"], "reply_to": info["reply_to"], "enc": envelope,
                })
            self.app.e2ee.file_envelope(info["to"], info["bundle"], info["caption"], description, sealed)
        elif op == "uploaded" and info:
            self.requests.pop(payload["request"], None)
            self._forget_temporary(info)
            self.app.messages.remove(info["pending"])
        elif op == "upload_failed" and info:
            self.requests.pop(payload["request"], None)
            self._forget_temporary(info)
            self.app.messages.remove(info["pending"])
            self.app.notice(f"{info['name']} was not sent: {payload['reason']}")
        elif op == "exported" and info:
            self.requests.pop(payload["request"], None)
            self.app.notice(f"Your data was saved to {info['destination']}", tone="join")
        elif op == "export_failed" and info:
            self.requests.pop(payload["request"], None)
            self.app.notice(f"Could not export your data: {payload['reason']}")
        elif op == "progress" and info:
            info["record"].media.update(status="loading", pct=payload["percent"])
            self._refresh(info["record"])
        elif op == "downloaded" and info:
            self.requests.pop(payload["request"], None)
            self._release()
            self._downloaded(info["record"], self.cache_path(info["record"].att), info["then"],
                             info["destination"])
        elif op == "failed" and info:
            self.requests.pop(payload["request"], None)
            self._release()
            self._fail(info["record"], payload["reason"])
        elif op == "preview":
            record, shown = payload["record"], payload["path"]
            photo = None
            if shown:
                try:
                    photo = tk.PhotoImage(file=shown)
                    scale = -(-max(photo.width(), photo.height()) // THUMB_PIXELS)
                    if scale > 1:
                        photo = photo.subsample(scale)
                except tk.TclError:
                    photo = None
            record.media.update(photo=photo)
            self._refresh(record)
