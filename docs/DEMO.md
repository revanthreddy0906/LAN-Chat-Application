# Demo script (about 10 minutes)

## Set up (before the audience arrives)

```text
pip install cryptography          # once, on every computer that will use encryption
python3 chat.py host --name "Demo"        # on the presenter's computer
python3 chat.py                           # on each computer; click the chat, sign in
```

The first sign-in on each computer shows the encryption set-up window: choose a passphrase, write down the recovery code, tick the box, press Done. For a rehearsal with no second computer, `python3 demo/showcase.py` opens a scripted session you can click through.

## Story

1. **A normal chat (1 min).** Two or three people chat; show replies, reactions, typing, "Seen by", search (Cmd/Ctrl+F), @mentions and pins. Mention that it is the Python standard library only.
2. **Pictures, files and audio (1 min).** Attach a picture with 📎: it appears inline. Show Save as… and Play.
3. **"Who can read this?" (1 min).** Open the header: 🔒 Encrypted means TLS. Say what that protects (the network) and what it does not (the server).
4. **End-to-end encryption (3 min).**
   - Right-click a name → *Verify security code*; read the 60 digits aloud and compare. Mark verified (✔).
   - Send a private message: the chip says "End-to-end encrypted with Bob".
   - On the host computer run `python3 -c "print(open('accounts.db','rb').read().count(b'your secret words'))"` after sending a message with those words: the count is 0.
   - Show a plain private message to someone without keys ("server can read this") for contrast.
5. **Trust and recovery (1 min).** Have a second person *rotate keys*: everyone sees "⚠ new security code" and sending stops until accepted. Show *Lock now* (window covered, keys forgotten).
6. **The group room (2 min).** Admin console → Settings → *Encrypt the group room* → on. Messages now carry a room lock. Disable a member (or *Re-key the room now*): the next messages are in a new epoch they cannot read. A late joiner sees "Sent before you joined".
7. **Proof (1 min).** `python3 -m unittest` (about 450 tests) and `python3 chat.py admin audit --verify`.

## Questions you will probably get

| Question | Short answer |
|---|---|
| Why can the server not read it? | Messages are encrypted on the sender's computer with keys only the participants hold; the server stores ciphertext and public keys. |
| What stops the server swapping someone's key? | Keys are pinned on first sight and a change blocks sending until you compare security codes. |
| What if I forget my passphrase? | Use the recovery code. Lose both and old encrypted messages are gone. |
| Is there forward secrecy? | No. Stealing a long-term key exposes what that person could read; a ratchet would be the upgrade. |
| What does the server still see? | Who talks to whom, when, sizes and mentions. |
| Why not use a library like Signal? | The aim was a readable, dependency-light design; it reuses audited primitives (X25519, Ed25519, ChaCha20-Poly1305) but not a full protocol. |
| How do you know it works? | Known-answer tests, tamper tests, a test that scans every frame and the database for secrets, and scripted runs of the real window. |

## Slide prompt (10 slides)

```text
Create a 10-slide deck for a college project demo titled "LANChat-H: a secure LAN chat with end-to-end encryption" by Revanth and Saarthak. Dark navy and teal, one font, diagrams drawn with native shapes, bullets under 12 words, details in speaker notes, [INSERT SCREENSHOT] placeholders on slides 3, 5, 6 and 8.
1 Title. 2 Problem and goal. 3 Architecture (clients, TLS, threads and outbox queues, SQLite, blob store, discovery) with a screenshot. 4 Protocol: 4-byte length framing, v1 text and v2 JSON events. 5 Security basics: TLS with trust on first use, scrypt, roles, lockout, audit chain (screenshot of the admin console). 6 End-to-end encryption for private chats: keys, safety numbers, recovery code (screenshot of the security code dialog). 7 Files and pictures: tickets, chunked encryption, hash checks. 8 The encrypted group room: key chains, epochs, late joiners (screenshot). 9 Evidence: tests, wire scan, benchmarks (median latency 2.7-5.8 ms up to 100 receivers; a stalled receiver does not block the room). 10 Limits and future work (no forward secrecy, metadata, asyncio comparison) and Q&A.
Output a downloadable .pptx; do not invent features.
```
