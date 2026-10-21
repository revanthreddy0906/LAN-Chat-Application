# LAN Chat

A secure team chat for people on the same Wi-Fi or LAN, built with Python's standard library only. Source: https://github.com/revanthreddy0906/LAN-Chat-Application Messages are encrypted, accounts have roles, you can share pictures, files and audio, and other computers find your chat automatically.

More detail lives in [`docs/`](docs): [architecture](docs/ARCHITECTURE.md), [protocol](docs/PROTOCOL.md), [security and its limits](docs/SECURITY.md), and a [runbook](docs/RUNBOOK.md) for whoever hosts the chat.

## Quick start

**1. Host a chat** (on one computer):

```text
python3 chat.py host
```

It prints the address and says "Others on this network can just run: python3 chat.py".

**2. Join** (on every computer, including the host if you like):

```text
python3 chat.py
```

A window opens and lists the chats on your network. Click one, type a username and password, press **Join**. New usernames are created on first sign-in (the password must be at least 6 characters and not an obvious one). You can also click **Host a chat** inside the window, and `python3 chat.py join` joins from the terminal.

Requirements: Python 3.10+ with Tkinter (included with most installs). `openssl` is used once to create the encryption certificate (present on macOS and Linux). Nothing else needs installing.

## In the chat window

**Messages**
- Bubbles show your messages on the right and others on the left, with names, avatars and times.
- **Right-click a message** for Reply, React (👍 ❤️ 😂 🎉 😮 🙏), Edit, Pin, Delete, Copy. Click a reaction pill to add or remove yours; click a reply's quote to jump to the original.
- **Edit** your own message (or press ↑ in an empty box); **Delete** leaves a "This message was deleted" note. Admins can delete anyone's. Esc cancels a reply or edit.
- "Bob is typing…", presence dots (online, **away** after 5 minutes idle, offline), **Seen by** under your newest message, and a **New messages** line where you left off.
- Click a name in the member list to message that person privately; the smiley opens an emoji picker; the moon/sun switches light and dark.

**Sharing pictures, files and audio**
- Click **📎**, choose one or more files, and send. Whatever you typed in the message box becomes the caption. In a private conversation the file goes only to that person.
- **Pictures** show inline (PNG and GIF always; JPEG and others if Pillow is installed, or on a Mac). Click one to open it full size. Everything else appears as a card with the name, size, **Open** and **Save as…**. Audio files have **▶ Play** / **■ Stop**.
- Files up to 25 MB, 500 MB of space per person (an admin can change both). Programs and scripts such as `.exe`, `.bat` and `.app` are blocked. Every file is checked against its SHA-256 on the way in and out, and a damaged one is never delivered.
- Optional voice messages: `pip install sounddevice` adds a 🎤 button that records up to two minutes. Without it the button simply is not there.
- Guests cannot share files; terminal clients see a line like `[image: holiday.png]`.

**Finding things**
- **Search** (Cmd+F, or Ctrl+F elsewhere; or the 🔎 button): type a word, click a result to jump to it, even far back in history.
- **@mentions:** type `@` and a few letters, press Tab to complete. Mentions highlight the bubble and show `(@1) LAN Chat` in the title. Only admins can use `@everyone`.
- **Pins:** admins pin any message, members their own; the pinned bar sits under the header.
- **History:** the last 50 messages load on join; **Load earlier messages** fetches 50 more at a time.

**End-to-end encrypted private messages** (needs `pip install cryptography`)
- The first time you sign in you set a passphrase and are shown a **recovery code** once. Your keys stay on your computer; the server holds only your public key and a backup it cannot open.
- When you message someone who has also set up keys, the chip above the box reads "🔒 End-to-end encrypted with Bob" and the server stores only ciphertext it cannot read. Right-click a name → **Verify security code** to compare a 60-digit code with them. If someone's code ever changes you are warned and sending stops until you accept the new one.
- Replies, edits, reactions and local search of what is on screen all work on encrypted messages. Messages are limited to 1500 bytes. If the other person has no keys you are asked before sending anything readable by the server. An admin can set the policy to off, optional or **required** (⋯ → Admin console → Settings).
- **Files, pictures and audio sent privately are encrypted too**, on your computer, in chunks, before they leave it. The server stores unreadable bytes and never learns the name, type or contents; the recipient's window decrypts, previews and opens them. Programs such as `.exe` hidden inside an encrypted file are still recognised by the receiving window, which asks before opening. Captions on encrypted files can be up to 1000 bytes.
- Not yet encrypted: the group room. See [SECURITY.md](docs/SECURITY.md).

**Your account (the ⋯ button)**
- **Change password…** signs out every other saved sign-in.
- **Download my data…** saves a JSON file of everything you wrote or received privately.
- **Admin console…** (admins only), see below.

Typed commands work too (and are all a terminal client has): `/users`, `/members`, `/msg <name> <text>`, `/search <words>`, `/pins`, `/passwd <old> <new>`, `/help`, `/quit`.

## Accounts, roles and the admin console

- Everything is saved in `accounts.db` next to `server.py` (SQLite): accounts, messages, reactions, pins, the audit log. Shared files live in `accounts_files/` beside it. Messages survive a restart.
- The **first person to register is the admin**. Roles: `admin` (everything), `member` (chat, react, share, edit and delete their own, pin their own), `guest` (chat and react only). The last admin cannot be demoted or disabled.
- The **admin console** has three tabs. **People:** set a role, disable or enable, disconnect, sign out saved sign-ins, reset a password (shown once), add a person. **Audit log:** filter by person or action, page through it, and **Verify chain** to prove nothing was altered. **Settings:** who may create accounts, largest file, space per person, shortest password, blocked file types.
- The same things work from the terminal on the host computer, without the server running:

```text
python3 chat.py admin users
python3 chat.py admin role Bob admin
python3 chat.py admin reset Bob           # prints a temporary password
python3 chat.py admin audit --verify
python3 chat.py admin settings max_upload_mb 50
```

- Upgrading from an older version is automatic: an old `accounts.json` is imported on first start (kept as `.bak`) and older databases gain the new tables without losing anything.

## Security (what to say in the demo)

- **Encryption:** TLS (1.2 or newer) is on by default, with a self-signed certificate made once in `~/.lanchat/`.
- **Trust on first use:** the first time you join, you see the certificate fingerprint and are asked to trust it; compare it with the host's screen. If a known chat later shows a different certificate, the app refuses and warns about impersonation.
- **Passwords:** stored only as salted scrypt hashes; the app does not keep your password after sign-in. It keeps a **saved sign-in** (a random token, stored on the server only as a hash, valid 12 hours) used to reconnect and revoked when you leave or change your password.
- **Brute-force protection:** five wrong passwords lock that name from that address for 30 seconds, doubling up to 15 minutes. Rate limits slow message floods, and new-account creation per address is capped.
- **Roles are checked on the server** for every action; hiding a button in the window is only a convenience.
- **Files:** a one-time ticket from the chat connection opens a separate encrypted connection for the bytes; names are sanitised, files are stored under their SHA-256 (never a sender-chosen path), and size, type and space limits are enforced while streaming.
- **Audit log:** logins, failures, lockouts, role changes, deletions of other people's messages, uploads, resets and settings changes, in a hash chain (each row's hash covers the one before). Message text is never written to it.
- Limits: the very first connection can be fooled if nobody compares the fingerprint; there is **no end-to-end encryption** (the server can read messages and files); files are not encrypted on the host's disk; built for a trusted LAN, not the internet. See [SECURITY.md](docs/SECURITY.md).

## How people find each other

The host answers a UDP "who is hosting?" broadcast on port 50505. Some guest Wi-Fi blocks broadcasts; then use **Enter an address instead**, or `python3 chat.py join 192.168.1.10`.

## Advanced options

| Need | Command |
|---|---|
| Choose a port | `python3 chat.py host --port 6000` (default: first free port from 5050) |
| Name shown in the list | `python3 chat.py host --name "Lab 3"` |
| Turn encryption off | `python3 chat.py host --no-tls` |
| Join by address | `python3 chat.py join 192.168.1.10` or `192.168.1.10:6000` |
| Accounts file | `python3 chat.py host --accounts team.db` |
| Scripted login | `python3 chat.py join ADDRESS --username Ann --password secret` |
| Your own certificate | `./make_cert.sh`, then `python3 server.py --cert server.crt --key server.key` |

Files on your computer: `~/.lanchat/settings.json` (last username, theme, trusted servers), `~/.lanchat/cache/` (pictures and files you opened), `~/.lanchat/server.crt` and `server.key` (host only), and `accounts.db` plus `accounts_files/` (host only). Back up the last two together.

## Tests

```text
python3 -m unittest            # about 280 tests, a minute and a half
python3 drivers/media.py       # scripted runs of the real window: pictures and files
python3 drivers/search_pins.py # paging, search, mentions, pins
python3 drivers/admin.py       # admin console, password change, saved sign-in, data export
python3 drivers/basics.py      # sign in, reply, edit, react, private messages, theme
python3 drivers/hosting.py     # hosting from the window over TLS
python3 drivers/terminal.py    # the real terminal client, with every security default on
LANCHAT_STRICT=1 python3 drivers/media.py   # the same, with rate limits and password rules switched on
```

The unit tests start real servers on free ports and cover framing, TLS and trust, login, the database and its migrations, protocol v1 and v2, search, pins, file transfer (round trips, limits, tampering, traversal names, cut-off uploads, concurrency), lockout and rate limits, tokens, the admin events and the audit chain. The `drivers/` scripts open the actual window and click through it.

Benchmarks used in the paper (`paper/survey_paper.tex`; build it with `tectonic` or `pdflatex`): `python3 bench/fanout.py`, `bench/slow_receiver.py`, `bench/transfer_speed.py`, `bench/crypto_cost.py`. They run a real server on loopback and print the tables; results depend on your machine.

## How it works (short)

- `protocol.py`: each message is a 4-byte length plus UTF-8 text. The window speaks **protocol v2** (JSON events, `events.py`); terminal clients speak plain text and the server translates for them.
- `server.py` (with `server_admin.py`): a handler thread and a bounded outbox with its own writer thread per client, so a slow client is dropped instead of delaying others. `store.py` is the SQLite database with numbered migrations; `accounts.py`, `permissions.py`, `security.py`, `audit.py`, `storage.py` do passwords, roles, limits, the hash chain and file safety.
- `transfer.py` / `gui_media.py`: file uploads and downloads on their own connection, in background threads.
- `gui_client.py`, `gui_widgets.py`, `gui_admin.py`, `gui_theme.py`, `gui_logic.py`: the window. `client.py`: the terminal client. `chat.py`: the single launcher. `admin_cli.py`: offline admin tool.

## Limitations

- Terminal clients show a simpler chat: no edits, deletes, reactions, typing, search, pins or pictures.
- The server can read everything; there is no end-to-end encryption and files are stored unencrypted on the host.
- No inline video playback (videos open in your system player); no drag-and-drop; JPEG previews need Pillow or macOS.
- One chat room plus private messages, one server, one thread per client: right for a class or small office, not hundreds of people.
- Saved sign-ins let one person keep one live connection; there is no multi-device session list.

## Troubleshooting

- **No chats listed:** the host may not be running, or the network blocks broadcasts; use the address option.
- **"The certificate has CHANGED":** the host's certificate was replaced. If expected, delete that entry under `servers` in `~/.lanchat/settings.json`; otherwise do not connect.
- **"too many failed attempts":** wait the number of seconds shown; the lock is per name and address.
- **"choose a stronger password":** at least 6 characters, not your username, not a common password.
- **A file will not send:** the message says why (too large, blocked type, out of space, or your role).
- **Firewall prompt on macOS:** allow Python to accept incoming connections on the host.
- **Window does not appear:** it may be behind the terminal; press Cmd+Tab.
