# Security

## Who we defend against

A curious or hostile person **on the same network** (sniffing, impersonating the server, guessing passwords, flooding), a **member** trying to do more than their role allows, and **hostile file names and contents**. We do not defend against a hostile host: whoever runs the server can read everything.

## Controls

| Threat | Control | Where |
|---|---|---|
| Reading traffic | TLS 1.2+ on every connection, including file transfers | `server.py`, `chat_core.py` |
| Fake server (MITM) | Trust on first use: the certificate fingerprint is shown once, then pinned; a changed certificate is refused | `chat_core.py`, `settings.py` |
| Stolen password database | Salted scrypt hashes (n=16384, r=8, p=1); constant-time compare | `accounts.py` |
| Password guessing | Lockout per (address, name) after 5 failures: 30 s, doubling to 15 min; per-address cap across names; correct password clears the count | `security.py` |
| Weak passwords | New passwords and changes need ≥ 6 characters (admin can raise it), not the username, not a common password | `security.py` |
| Account spam | At most 10 new accounts per address per hour; admins can close registration | `server.py`, settings |
| Flooding | Token bucket per person (30 burst, 10/s); 60 connections per address per minute; frame and message size caps | `server.py` |
| Privilege abuse | `can(role, action)` checked on the server for every action; the last admin is protected | `permissions.py`, `server*.py` |
| Password kept in memory / replayed | The window keeps a **saved sign-in** token (random, 12 h, stored only as a SHA-256 hash, revoked on leave, password change, disable or reset), not the password | `server.py`, `gui_client.py` |
| Hostile file names | Names are reduced to a safe base name; files are stored under their SHA-256, never a sender-chosen path | `storage.py` |
| Hostile files | Blocked executable types; size and space limits enforced while streaming; hash verified both ways; tickets are one-use and expire; transfers capped | `storage.py`, `server.py` |
| Private files leaking | A download is refused unless you could see the message it belongs to | `server.py` |
| Tampering with the record of events | The audit log is a hash chain with a head marker; `Verify chain` finds edits, deletions and insertions | `audit.py`, `store.py` |
| Secrets in logs | Message text, passwords and tokens are never written to the audit log or console | `server_admin.py` |

## Honest limits

- **End-to-end encryption covers private messages, private files and, when an admin switches it on, the group room (text, pictures and files).** With it off, the room is protected by TLS but readable by the server and anyone with the host's files. The room's ratchet is one-way per sender and per epoch but a member's chain is stored sealed on the server for later reading, so there is no forward secrecy against theft of a member's long-term key. For encrypted files the server also cannot apply file-type rules (the name is hidden), so the receiving window warns before opening a program-like file. Private messages between two people who both have keys are ciphertext in the database; the server still sees who talks to whom, when, and how much.
- **Files are stored unencrypted** in `accounts_files/`.
- **First-connection trust** depends on someone comparing the fingerprint. Without that, a person already in the middle on the first connect could be trusted.
- **The audit log detects tampering, it cannot prevent it.** Someone who can rewrite the whole database and the head marker consistently can forge a log; keep an offsite copy of `audit_head` if that matters.
- **Lockout is per address and name.** It slows guessing; it does not stop a determined attacker with many addresses, and a locked-out real user must wait.
- **Self-signed certificates and `check_hostname=False`.** LAN addresses change, so the pinned certificate is what authenticates the server, not its name.
- **One shared secret surface: the host's computer.** Protect it, and the `~/.lanchat/server.key` file in particular.
- Built for a trusted LAN of tens of people, not the public internet. There is no password-reset email; an admin resets passwords.
