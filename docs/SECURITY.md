# Security

This page is the threat model and the list of controls. The end-to-end encryption design has its own page: [E2EE.md](E2EE.md).

## Who we defend against

| Attacker | What they can try | Defended? |
|---|---|---|
| Someone on the same network | Sniff traffic, impersonate the server, guess passwords, flood the server | Yes (TLS, pinning, lockout, limits) |
| A member | Do more than their role allows, send hostile files, replay or forge messages | Yes (server-side roles, file checks, signed messages) |
| **The person hosting the server**, or anyone who steals its disk | Read stored messages and files, watch who talks to whom | **Partly.** Private messages, private files and (if switched on) the group room are ciphertext to the host. Metadata and everything sent while end-to-end encryption is off are not protected. |
| Someone who steals a member's computer while it is unlocked | Read what that person can read | No: lock the window (auto-lock) and use a disk passphrase. |
| A hostile server that lies about keys | Hand out a fake public key to eavesdrop | Detected, not prevented: contacts are pinned and security codes are compared (see E2EE.md). |

## Controls

| Threat | Control | Where |
|---|---|---|
| Reading traffic | TLS 1.2+ on every connection, including file transfers | `server.py`, `chat_core.py` |
| Fake server (MITM) | Trust on first use: the certificate fingerprint is shown once, then pinned; a changed certificate is refused | `chat_core.py`, `settings.py` |
| Stolen account database | Salted scrypt hashes (n=16384, r=8, p=1); constant-time compare | `accounts.py` |
| Password guessing | Lockout per (address, name) after 5 failures: 30 s, doubling to 15 min; per-address cap across names; correct password clears the count | `security.py` |
| Weak passwords | New passwords and changes need ≥ 6 characters (admin can raise it), not the username, not a common password | `security.py` |
| Account spam | At most 10 new accounts per address per hour; admins can close registration | `server.py`, settings |
| Flooding | Token bucket per person (30 burst, 10/s); 240 connections per address per minute; frame and message size caps | `server.py` |
| Privilege abuse | `can(role, action)` checked on the server for every action; the last admin is protected | `permissions.py`, `server*.py` |
| Password kept in memory / replayed | The window keeps a **saved sign-in** token (random, 12 h, stored only as a SHA-256 hash, revoked on leave, password change, disable or reset), not the password | `server.py`, `gui_client.py` |
| Hostile file names | Names are reduced to a safe base name; files are stored under their SHA-256, never a sender-chosen path (also for names inside encrypted messages) | `storage.py`, `gui_e2ee.py` |
| Hostile files | Blocked executable types; size and space limits enforced while streaming; hash verified both ways; tickets are one-use and expire; transfers capped; for encrypted files the receiving window asks before opening a program-like file | `storage.py`, `server.py`, `gui_media.py` |
| Private files leaking | A download is refused unless you could see the message it belongs to | `server.py` |
| The host reading private messages and files | End-to-end encryption: X25519 key agreement, ChaCha20-Poly1305, Ed25519 signatures; the server stores ciphertext only | `e2ee.py`, `gui_e2ee.py` |
| The host reading the group room | One-way sender key chains per epoch, sealed to each member; re-keyed when someone is removed | `e2ee_group.py`, `server_room.py` |
| A fake key from the server | Public keys are self-signed; contacts pinned on first sight; a changed key blocks sending until accepted; 60-digit safety numbers | `keystore.py`, `gui_e2ee.py` |
| Replays and forged senders | Every encrypted message is signed and bound to sender, recipients (or epoch and number); the window flags a reused random id or message number | `e2ee.py`, `gui_e2ee.py` |
| Lost or stolen key file | Secret keys are wrapped under a passphrase (scrypt, ChaCha20-Poly1305); a recovery code restores them on a new computer; keys can be rotated while old messages stay readable | `keystore.py`, `e2ee.py` |
| Someone walks up to an unlocked window | Auto-lock after an idle time (default 15 min): the window is covered, dialogs hidden, keys forgotten until the passphrase is entered | `gui_client.py` |
| Tampering with the record of events | The audit log is a hash chain with a head marker; `Verify chain` finds edits, deletions and insertions | `audit.py`, `store.py` |
| Secrets in logs | Message text, passwords, keys and tokens are never written to the audit log or console | `server_admin.py` |

## What is verified, and how

- `test_e2ee*.py` check the cryptography against published test vectors (RFC 7748, RFC 8032), then tampering, wrong recipients, forged senders, replays, truncated and reordered files, and the room's rules for late joiners and removed members.
- `test_e2ee_wire.py` wraps the server's send and receive functions and records **every frame it sees**, then confirms that none of the secret messages, file names, file contents, file keys or secret keys appear in the traffic, the database file or the stored files. A companion check proves the same capture would show a plaintext message if one were sent.
- The scripted window runs in `drivers/` exercise setup, restore on a second computer, key change, rotation, the room and the lock in the real interface.

## Honest limits

- **Metadata is visible to the server:** who talks to whom, when, message and file sizes, reactions, and who is mentioned. The room's member list and each person's role are visible too.
- **Group room and forward secrecy.** Each member's chain is one-way, so a late joiner cannot read backwards, but the sealed chain copies stay on the server so history can be re-read. Stealing a member's long-term key would expose what they could read. The private-message design has the same limit (no ratchet).
- **Identity is only as good as the comparison.** Until two people compare security codes (or trust the first key they saw), a hostile server could have swapped a key at the very first contact.
- **When end-to-end encryption is off** (policy `off`, room `off`, a contact without keys, or `cryptography` not installed) messages are protected by TLS only and the server can read them. The window always labels which case it is.
- **Terminal clients** cannot read or write encrypted conversations.
- **Search** of encrypted messages covers what is loaded in the window.
- **Plain files** shared in the room before it was encrypted, and any file sent without keys, are stored unencrypted in `accounts_files/`.
- **First-connection trust** (the certificate) depends on someone comparing the fingerprint.
- **The audit log detects tampering, it cannot prevent it.** Someone who can rewrite the whole database and the head marker consistently can forge a log; keep an offsite copy of `audit_head` if that matters.
- **Lockout is per address and name.** It slows guessing; it does not stop a determined attacker with many addresses, and a locked-out real user must wait.
- **The window is not a vault.** Decrypted text lives in memory while the window is open; the lock hides it and drops the keys but a computer that is already compromised is out of scope.
- Built for a trusted LAN of tens of people, not the public internet. There is no password-reset email; an admin resets passwords.
