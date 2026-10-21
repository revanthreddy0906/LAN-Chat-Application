# Architecture

LAN Chat is one server process and any number of clients, all in Python's standard library (Tkinter, sockets, ssl, sqlite3, threading).

```
 GUI client (gui_client.py)     terminal client (client.py)
        │  JSON events (v2)              │  plain text lines (v1)
        └──────────────┬─────────────────┘
                       │  TCP + TLS, 4-byte length prefix per message
                 ┌─────▼──────┐   one handler thread + one writer thread per client
                 │ server.py  │──── discovery.py  (UDP 50505: "who is hosting?")
                 └─────┬──────┘
          ┌────────────┼──────────────┐
      store.py      storage.py      audit.py / security.py
   SQLite (accounts.db)  files by SHA-256   hash-chained log, lockout, rate limits
```

## Modules

| Module | Job |
|---|---|
| `protocol.py` | Length-prefixed framing (max 4096 bytes per frame). |
| `events.py` | The v2 event shapes, size trimming, and `legacy_text()` which renders any event as a plain line for v1 clients. |
| `server.py` | Accept loop, handshake (password, saved sign-in, file connection), per-client threads and outboxes, message posting, history, search, pins, file tickets. |
| `server_admin.py` | Mixed into the server: change password, sign out, data export, and the admin-only events. |
| `store.py` | SQLite with numbered migrations v1–v5: users, messages, reactions, read markers, mentions, pins, attachments, sessions, audit. FTS5 search with a `LIKE` fallback. |
| `accounts.py` | scrypt hashing, sign-in/registration, password changes. |
| `permissions.py` | The role table and `can(role, action)`. |
| `security.py` | `LoginGuard` (lockout with backoff), `RateLimiter`, `SlidingWindow`, `check_password`. |
| `audit.py` | Canonical entry hashing and chain verification. |
| `storage.py` | File-name sanitising, type classification, blocked types, content-addressed `BlobStore`. |
| `transfer.py` | Client side of uploads and downloads. |
| `chat_core.py` | Login handshake, trust on first use, heartbeat, helpers shared by both clients. |
| `gui_*.py` | The Tkinter window: widgets, theme, pure logic, media manager, admin console. |
| `admin_cli.py` | Offline account and audit tool (`chat.py admin ...`). |

## Concurrency

- **Per client:** one thread reads and handles requests; one writer thread drains a bounded `queue.Queue` to the socket. Delivering a message is `put_nowait` onto each queue, so one slow or frozen client can never delay the others; if its queue fills, it is disconnected (it can reconnect and replay history).
- The welcome and history are written directly before the writer thread starts, so they arrive first and in order.
- **File data** never uses the chat connection. The chat connection hands out a one-time **ticket**; the client opens a second connection and presents it. At most 8 transfers run at once and 5 tickets per person are open at a time.
- **Database:** one SQLite connection behind a lock. Writes are short, which suits classroom or office scale.
- **GUI:** network and transfer threads never touch widgets. They post events to a `queue.Queue` that the Tk main loop polls with `after()`.

## A message's life

1. The window sends `{"t":"send","body":...}`.
2. The server checks the rate limit, the role, the size, the reply target and the mentions, writes the row, and builds a `message` event.
3. Public messages go to every connected client; private ones to the two people involved. v2 clients get the JSON, v1 clients the rendered line.
4. Joiners get the last 50 messages (plus their private ones) from the database; older pages are fetched on request.

## A file's life

1. `upload {name,size,sha256}` on the chat connection. The server checks role, blocked type, size, space, and the conversation, then replies `upload_ready {ticket}`.
2. The client opens a data connection, sends the ticket, then raw bytes. The server streams them to a temp file while hashing, enforces the exact size and a deadline, compares the SHA-256, moves the file to `accounts_files/ab/<sha256>`, writes the attachment row and posts the message.
3. Recipients see a `message` with an `att` object. Pictures are fetched automatically (up to 8 MB, three at a time) into `~/.lanchat/cache/`, everything else on request. Downloads are verified against the SHA-256 and written atomically.
4. Deleting the message removes the file when nothing else uses the same content.

## Design choices worth defending

- **Standard library only** keeps it one folder and one command; optional extras (Pillow, sounddevice) only add previews and recording.
- **Versioned protocol with an adapter** let every feature be added without breaking the terminal client.
- **SQLite instead of a database server** gives persistence, search and migrations with no setup.
- **Tickets and a separate data connection** keep large files from blocking chat or overflowing queues.
- **Content addressing** makes path traversal impossible by construction and deduplicates identical files.
