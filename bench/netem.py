"""A small user-space TCP proxy that adds one-way delay and jitter (and optionally a rate limit).

    python3 bench/netem.py --listen 6001 --target 5050 --delay-ms 20 --jitter-ms 4 [--kbps 0]

It stands in for a real network path on one machine. It cannot create packet loss (TCP hides it
from applications anyway: loss shows up as extra delay), so loss is approximated by the jitter.
"""
import argparse
import asyncio
import random
import time


async def pump(reader, writer, delay, jitter, kbps):
    queue = asyncio.Queue()
    last = [0.0]

    async def sender():
        while True:
            release, data = await queue.get()
            if data is None:
                break
            wait = release - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            writer.write(data)
            await writer.drain()
            if kbps:
                await asyncio.sleep(len(data) * 8 / (kbps * 1000))
        writer.close()

    task = asyncio.ensure_future(sender())
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            release = max(last[0], time.monotonic() + max(0.0, random.gauss(delay, jitter)))
            last[0] = release
            await queue.put((release, data))
    except OSError:
        pass
    await queue.put((0, None))
    await task


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, required=True)
    p.add_argument("--target", type=int, required=True)
    p.add_argument("--delay-ms", type=float, default=0)
    p.add_argument("--jitter-ms", type=float, default=0)
    p.add_argument("--kbps", type=float, default=0)
    a = p.parse_args()
    d, j = a.delay_ms / 1000, a.jitter_ms / 1000

    async def handle(cr, cw):
        try:
            sr, sw = await asyncio.open_connection("127.0.0.1", a.target)
        except OSError:
            cw.close()
            return
        await asyncio.gather(pump(cr, sw, d, j, 0), pump(sr, cw, d, j, a.kbps), return_exceptions=True)

    server = await asyncio.start_server(handle, "127.0.0.1", a.listen)
    print("ready", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
