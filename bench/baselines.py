"""Comparison servers for the benchmarks, all speaking the same 4-byte-length wire protocol.

* SequentialRelay (in slow_receiver.py): thread per client, blocking send to each recipient in turn.
* AsyncioRelay: one asyncio event loop, a bounded queue and a writer task per client (the same
  isolation idea as LANChat-H, without threads). With persist=True every message is also written
  to SQLite first, so the work per message is closer to what LANChat-H does.

They are minimal relays written for the comparison: no accounts check, roles, rate limits or TLS.
"""
import asyncio
import os
import socket
import sqlite3
import struct
import tempfile
import threading

QUEUE_LIMIT = 100


class AsyncioRelay:
    def __init__(self, persist=False, queue_limit=QUEUE_LIMIT):
        self.persist = persist
        self.queue_limit = queue_limit
        self.loop = asyncio.new_event_loop()
        self.clients = {}
        self.dropped = 0
        self._db = None
        if persist:
            self._db = sqlite3.connect(os.path.join(tempfile.mkdtemp(), "relay.db"), check_same_thread=False)
            self._db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
            self._db.execute("PRAGMA journal_mode=WAL")
        started = threading.Event()
        self.port = None

        async def boot():
            self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            started.set()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(boot())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        started.wait(5)

    @staticmethod
    async def _read(reader):
        header = await reader.readexactly(4)
        (length,) = struct.unpack("!I", header)
        if length == 0 or length > 4096:
            raise ValueError("bad length")
        return (await reader.readexactly(length)).decode("utf-8")

    @staticmethod
    def _frame(text):
        payload = text.encode("utf-8")
        return struct.pack("!I", len(payload)) + payload

    async def _writer(self, writer, queue):
        try:
            while True:
                data = await queue.get()
                if data is None:
                    return
                writer.write(data)
                await writer.drain()
        except (OSError, asyncio.CancelledError):
            return

    async def _serve(self, reader, writer):
        sock = writer.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        queue = asyncio.Queue(self.queue_limit)
        task = None
        try:
            writer.write(self._frame("USERNAME"))
            name = await self._read(reader)
            writer.write(self._frame("PASSWORD"))
            await self._read(reader)
            writer.write(self._frame("OK") + self._frame("Connected"))
            await writer.drain()
            self.clients[writer] = queue
            task = asyncio.ensure_future(self._writer(writer, queue))
            while True:
                text = await self._read(reader)
                if self._db is not None:
                    self._db.execute("INSERT INTO messages(sender, body) VALUES (?, ?)", (name, text))
                    self._db.commit()
                data = self._frame(f"[00:00] {name}: {text}")
                for other, q in list(self.clients.items()):
                    if other is writer:
                        continue
                    try:
                        q.put_nowait(data)
                    except asyncio.QueueFull:
                        self.dropped += 1
                        other.close()
                        self.clients.pop(other, None)
        except (asyncio.IncompleteReadError, OSError, ValueError):
            pass
        finally:
            self.clients.pop(writer, None)
            if task:
                task.cancel()
            writer.close()

    def stop(self):
        async def shutdown():
            self.server.close()
            for w in list(self.clients):
                w.close()
            tasks = [t for t in asyncio.all_tasks(self.loop) if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.loop.stop()
        asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
        self.thread.join(3)
