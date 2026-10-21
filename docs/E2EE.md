# End-to-end encryption

What it protects: the text and files of **private conversations**, and (when an admin switches it on) the **group room**, so that the server and whoever hosts it hold only ciphertext. It needs the `cryptography` package (`pip install cryptography`); without it the chat works over TLS only and says so.

## Building blocks

All from the audited `cryptography` library; nothing here is a home-made cipher.

| Need | Primitive |
|---|---|
| Agree a secret with a person | X25519 (RFC 7748) |
| Prove who wrote something | Ed25519 (RFC 8032) |
| Derive keys | HKDF-SHA256 (RFC 5869) and HMAC-SHA256 |
| Encrypt and authenticate | ChaCha20-Poly1305 (RFC 8439) |
| Protect keys at rest | scrypt (RFC 7914) with a passphrase |

## Identity and trust

- Each person has an **identity**: an X25519 key pair and an Ed25519 key pair, plus a signature by the second over both public keys, so the two cannot be mixed with someone else's.
- The server stores only the public parts and an **opaque backup** of the secret keys wrapped under a 24-character **recovery code** (about 119 bits). It never learns a passphrase or the code.
- On disk the secret keys are wrapped under the person's **passphrase**: `~/.lanchat/keys/<server>/<name>.key` (permissions 600).
- Contacts are **pinned** the first time their key is seen. If it ever differs, sending to them stops and the window asks you to compare a **security code** (a number of 60 digits computed from both identities, identical on both screens) and accept the new key. Earlier keys of a contact are kept so older messages still verify.
- **Rotating** keys makes a new identity, keeps the old ones for opening earlier messages, produces a new recovery code, and tells contacts.
- **Resetting** keys discards everything: earlier encrypted messages become unreadable.

## Private messages and files

1. The sender picks a random message key and encrypts the text once (ChaCha20-Poly1305, with the sender and recipients bound in as associated data).
2. That key is sealed separately for the recipient and for the sender (an ephemeral X25519 key plus the sender's static key through HKDF), and the whole message is signed.
3. The server checks only the shape and the two names, stores `body = ""` and the envelope, and relays it.
4. A file is encrypted on the sender's computer in 64 KiB chunks with a random file key; the nonce is the chunk number plus a "last chunk" flag, so dropped, reordered or added chunks fail. The file key, real name, type and caption travel inside the encrypted message. The server stores unreadable bytes under an opaque name.

## The group room

- Every member has, for each **epoch**, a random **chain key**. The key for message *n* is derived by running a one-way function *n* times, so whoever holds the chain as of message *n* can read from *n* on and cannot go backwards.
- Each member gives every other member a sealed copy of their chain *as it stands now*. A person who joins later therefore reads only what is sent after they arrive. The server stores these sealed copies so they can be fetched again after a restart; it cannot open them.
- A message is encrypted under the sender's key for its number and signed. Numbers must increase, which the server enforces and the window double-checks.
- When someone is **removed** (disabled) or an admin presses **Re-key the room now**, the room moves to a **new epoch**: everyone starts a fresh chain, and the removed person never receives it. They keep what they could already read, which cannot be undone.
- Mentions are named by the sender (the server cannot read the text); `@everyone` is still admin-only. Pins and quotes of encrypted messages are shown from the text the window has decrypted.

## Policy settings (admin)

| Setting | Values | Effect |
|---|---|---|
| End-to-end encryption (private) | off / optional / required | `required` refuses readable private messages and files |
| Encrypt the group room | off / on | `on` refuses readable public messages and files; people without keys and terminal clients can neither read nor write |

Before switching the room on, the Admin console lists who has not set up keys.

## Operations

- **New computer:** sign in, choose "Restore", enter the recovery code and a new passphrase. Every identity comes back.
- **Forgotten passphrase:** use the recovery code the same way. Lose both and earlier encrypted messages are gone for good; reset the keys to start again.
- **Lost computer:** rotate keys from another computer (or restore on a new one first), then re-key the room.
- **Auto-lock:** ⋯ → Auto-lock sets the idle time; "Lock now" locks at once.

## Limits (also in SECURITY.md)

No forward secrecy; metadata is visible to the server; identity depends on comparing security codes; terminal clients are excluded from encrypted conversations; search covers what is on screen; the server can still delete or withhold messages (it cannot read or forge them).
