# Protocol

## Framing

Every message in both directions is `4-byte big-endian length` + `UTF-8 payload`. A length of 0 or more than 4096 is a protocol error and the connection is closed. File bytes are the one exception: after a data connection's `READY` they are raw (see below).

## Login

```
S: USERNAME
C: <username>                                  (v1)
   {"v":2,"username":"Ann"}                    (v2)
   {"v":2,"username":"Ann","token":"..."}      (v2, saved sign-in)
S: PASSWORD                                    (not sent for a valid token)
C: <password>
S: OK   |   ERROR: <reason>
```

Reasons include: wrong password, locked ("too many failed attempts, try again in N seconds"), disabled account, already logged in (a valid token replaces the old connection instead), expired session, weak password for a new account, closed registration.

After `OK`, v1 clients receive text lines (welcome, history, then chat). v2 clients receive `welcome`, `history_start`, `message`…, `history_end`, `pins`, `members` pages.

## Events (v2)

Every v2 frame is a JSON object with a `"t"` field.

**Server to client**

| t | Meaning |
|---|---|
| `welcome` | `you {name, role}`, `server`, `last_read`, `latest`, `limits {max_upload, blocked}`, `token` (only after a password sign-in) |
| `history_start` / `history_end` | Bracket the replayed messages; `history_start` has `count` and `has_more`. |
| `message` | `id, sender, to, body, ts, reply_to, reply, edited, deleted, reactions, mentions, everyone, history, att` (`att` is `{id, name, mime, size, kind, sha256}` or null). A `page: true` flag marks older pages. |
| `edited`, `deleted`, `reactions`, `read` | Changes to existing messages and read markers. |
| `notice` | `kind` (join, leave, error, role, info…) and `text`. |
| `members`, `presence`, `typing` | Who is here and what they are doing. |
| `pins`, `search_results` | Pinned list; results for a `search` (carries the request's `req`). |
| `page_start` / `page_end` | Bracket an older page requested with `history`. |
| `upload_ready`, `upload_denied`, `download_ready`, `transfer_error` | File transfer control (below). |
| `keys_result`, `keys`, `keys_backup`, `key_changed`, `e2ee_policy` | Public-key directory replies, notices that someone's key appeared or changed, and live policy changes. |
| `passwd_result`, `admin_users`, `admin_audit`, `admin_verify`, `admin_settings`, `admin_result` | Account and admin replies. |

**Client to server**

`send {body, to?, reply_to?}`, `edit {id, body}`, `delete {id}`, `react {id, emoji}`, `typing {on}`, `presence {status}`, `read {up_to}`, `members`, `ping`, `pin {id, on}`, `search {q, req}`, `history {before, limit}`, `upload {req, name, size, sha256, to?, caption?, reply_to?}`, `download {req, id}`, `passwd {old, new}`, `logout`, `export {req}`, `keys_publish {dh, sign, sig, backup?}`, `keys_get {names}`, `keys_backup_get`, `keys_reset`, and for admins `admin_users {page}`, `admin {op, user, value}`, `admin_settings`, `admin_audit {actor?, action?, before?}`, `admin_verify`.

Slash commands typed in a `send` body (`/search`, `/pins`, `/passwd`, `/msg`, `/help`) are handled too, so the same words work in both clients.

Limits: message text 3400 bytes; frames 4096 bytes. `fit_frame` trims an oversize text rather than breaking the frame.

## File transfer

1. Chat connection: `upload` → `upload_ready {req, ticket}` (or `upload_denied {reason}`); or `download {req, id}` → `download_ready {req, ticket, size, name, sha256}` (or `transfer_error`).
2. New connection to the same port. After the usual `USERNAME` frame the client sends `{"v":2,"data":"up"|"down","ticket":"..."}`.
3. Server replies `READY` (or `ERROR: ...`). A ticket works once, for 60 seconds, for the kind it was issued for.
4. **Upload:** client sends exactly `size` raw bytes; the server answers `{"t":"upload_done","id":N}` or `ERROR: ...` (for example "the file was damaged in transfer").
5. **Download:** the server sends exactly `size` raw bytes; the client verifies the SHA-256 from `download_ready`.

## v1 compatibility

`legacy_text(event, viewer)` renders `message` and `notice` events as the familiar `[HH:MM] Name: text` lines (files appear as `[image: name]`) and returns nothing for events a terminal client cannot show.

## End-to-end encrypted messages

A private `send` may carry `enc` instead of `body`: `{"v":2,"n":nonce,"ct":ciphertext,"k":{"alice":sealed key,"bob":sealed key},"sig":signature}`. The text is encrypted once with a random key (ChaCha20-Poly1305); that key is sealed separately for each of the two people (ephemeral and static X25519, HKDF-SHA256) and the whole message is signed with the sender's Ed25519 key. The server checks only the shape: the names in `k` must be exactly the sender and recipient, and the envelope may be at most 3000 characters. It stores the envelope in `messages.enc` with an empty body, and relays it as a `message` event with `"enc"` set. An edit of an encrypted message is another `enc` and never plain text. Terminal clients see `[encrypted message: open the chat window to read it]`.
