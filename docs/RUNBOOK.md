# Runbook (for whoever hosts the chat)

## Start and stop

```text
python3 chat.py host --name "Lab 3"      # or click "Host a chat" in the window
```
Type `quit` and Enter in that terminal (or press Ctrl+C) to stop. In the window, **Stop hosting** ends it for everyone.

## Where things are

| What | Where |
|---|---|
| Accounts, messages, pins, audit log | `accounts.db` next to `server.py` (or `--accounts PATH`) |
| Shared files | `accounts_files/` beside the database (`ab/<sha256>`; `tmp/` is cleared on every start) |
| Certificate and key | `~/.lanchat/server.crt`, `server.key` |
| Each person's settings, trusted servers, picture cache | `~/.lanchat/` |

## Backup and restore

Stop the server, then copy `accounts.db` **and** `accounts_files/` together (and `~/.lanchat/server.*` if you want the same fingerprint). To restore, put them back before starting. If the certificate is lost, everyone is asked to trust a new fingerprint.

## Everyday admin

From the window: ⋯ → **Admin console**. From the terminal (works while the server is stopped):

```text
python3 chat.py admin users
python3 chat.py admin role Bob admin
python3 chat.py admin disable Bob          # also: enable
python3 chat.py admin reset Bob            # prints a temporary password, once
python3 chat.py admin create Carol --role member
python3 chat.py admin settings             # show; or: settings open_registration off
python3 chat.py admin audit --tail 30
python3 chat.py admin audit --verify
```

| Situation | Do this |
|---|---|
| Someone forgot their password | `admin reset NAME`, give them the temporary one, ask them to change it (⋯ → Change password). |
| Locked out after wrong guesses | Wait the time shown (30 s to 15 min). Restarting the server also clears lockouts. |
| Someone should leave | Admin console → Disable (signs them out and blocks sign-in). |
| Close the chat to newcomers | Admin console → Settings → untick "Anyone can create an account", then add people yourself. |
| Disk filling up | Lower "File space per person", ask people to delete files; deleting a message frees its file. |
| Check nobody changed the log | `admin audit --verify` should say "chain intact". |

## Upgrades

Replace the Python files and start the server. The database upgrades itself (numbered migrations, no data lost); an old `accounts.json` is imported once and kept as `.bak`. Take a backup first if the history matters.

## Troubleshooting

- **"Address already in use":** only with an explicit `--port` that is taken; omit it.
- **Nobody sees the chat in the list:** their network blocks broadcasts; give them `ADDRESS:PORT` from the host's banner.
- **"The certificate has CHANGED" on clients:** `~/.lanchat/server.*` was replaced. If that was you, tell people to remove the old entry under `servers` in their `settings.json`.
- **Uploads fail with "damaged in transfer":** the network dropped data; try again.
- **`database is locked`:** two processes are writing at once (for example the admin tool during a busy moment); retry.
