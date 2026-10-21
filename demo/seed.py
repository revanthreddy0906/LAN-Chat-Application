"""Register the three demo users and leave some history in the chat: text, a picture and a document.

    LANCHAT_HOME=demo/home python3 demo/seed.py 5060
"""
import hashlib
import os
import struct
import sys
import tempfile
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import transfer
from chat_core import connect_secure
from events import decode, encode
from protocol import receive_message, send_message
from settings import Settings

port = int(sys.argv[1])
settings = Settings(os.environ["LANCHAT_HOME"])


def make_png(path, w=480, h=300):
    rows = []
    for y in range(h):
        row = b"".join(bytes([40 + x * 150 // w, 90 + y * 120 // h, 200 - x * 100 // w]) for x in range(w))
        rows.append(b"\x00" + row)

    def chunk(tag, data):
        body = struct.pack(">I", len(data)) + tag + data
        return body + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    with open(path, "wb") as handle:
        handle.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))


def sign_in(name):
    return connect_secure("127.0.0.1", port, name, "demo123", settings, confirm_trust=lambda *a: True,
                          confirm_plain=lambda *a: False, protocol=2)


def say(name, text):
    result = sign_in(name)
    send_message(result.connection, encode({"t": "send", "body": text}))
    time.sleep(0.4)
    result.connection.close()


def share(name, path, caption):
    result = sign_in(name)
    connection = result.connection
    data = open(path, "rb").read()
    send_message(connection, encode({"t": "upload", "req": 1, "name": os.path.basename(path), "size": len(data),
                                     "sha256": hashlib.sha256(data).hexdigest(), "caption": caption}))
    connection.settimeout(5)
    while True:
        event = decode(receive_message(connection) or "{}")
        if event and event["t"] == "upload_ready":
            break
    host = "127.0.0.1"
    transfer.upload(host, port, result.context, event["ticket"], path)
    connection.close()


say("Revanth", "Welcome to the class chat room!")
say("Saarthak", "Hi all, ready for the demo.")
folder = tempfile.mkdtemp()
picture = os.path.join(folder, "campus-wifi-map.png")
make_png(picture)
share("Srujan", picture, "Signal strength around the lab")
notes = os.path.join(folder, "demo-notes.txt")
with open(notes, "w") as handle:
    handle.write("LAN Chat demo notes\n- TLS + trust on first use\n- roles and audit log\n- files and pictures\n")
share("Saarthak", notes, "notes for the demo")
say("Srujan", "Joined. Waiting for the professor \U0001F642")
print("seeded")
