"""Manage a LAN Chat server's accounts and audit log from the terminal (no server needed).

    python3 chat.py admin users
    python3 chat.py admin role Bob admin
    python3 chat.py admin disable Bob        (also: enable)
    python3 chat.py admin reset Bob          (prints a temporary password)
    python3 chat.py admin create Carol --role member
    python3 chat.py admin settings [name value]
    python3 chat.py admin audit [--tail 20] [--verify]

It opens accounts.db directly, so run it on the computer that hosts the chat.
Changes are written to the audit log as `cli:<your login name>`.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

from accounts import AccountStore
from permissions import ROLES
from security import check_password

SETTINGS = {
    "open_registration": ("open_registration", lambda v: "1" if v.lower() in ("1", "yes", "on", "true") else "0"),
    "max_upload_mb": ("max_upload", lambda v: str(int(v) * 1024 * 1024)),
    "user_quota_mb": ("user_quota", lambda v: str(int(v) * 1024 * 1024)),
    "password_min": ("password_min", lambda v: str(int(v))),
    "e2ee_room": ("e2ee_room", lambda v: v if v in ("off", "on") else (_ for _ in ()).throw(ValueError(v))),
    "e2ee_policy": ("e2ee_policy", lambda v: v if v in ("off", "optional", "required") else (_ for _ in ()).throw(ValueError(v))),
    "blocked_extensions": ("blocked_extensions", lambda v: ",".join(
        sorted({p if p.startswith(".") else "." + p for p in (x.strip().lower() for x in v.split(",")) if p}))),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chat.py admin", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--accounts", default=str(Path(__file__).with_name("accounts.db")),
                        help="the accounts database (default: accounts.db next to server.py)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("users", help="list everyone")
    role = commands.add_parser("role", help="change someone's role")
    role.add_argument("name")
    role.add_argument("role", choices=ROLES)
    for name in ("disable", "enable", "reset"):
        commands.add_parser(name, help=f"{name} an account").add_argument("name")
    create = commands.add_parser("create", help="add an account")
    create.add_argument("name")
    create.add_argument("--role", choices=ROLES, default="member")
    create.add_argument("--password", help="prompted if omitted")
    settings = commands.add_parser("settings", help="show or change server settings")
    settings.add_argument("key", nargs="?", choices=sorted(SETTINGS))
    settings.add_argument("value", nargs="?")
    audit = commands.add_parser("audit", help="read the audit log")
    audit.add_argument("--tail", type=int, default=20)
    audit.add_argument("--verify", action="store_true", help="check the hash chain")
    return parser


def stamp(timestamp) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)) if timestamp else "never"


def run(args: argparse.Namespace, out=print) -> int:
    accounts = AccountStore(args.accounts)
    store = accounts.store
    actor = f"cli:{getpass.getuser()}"
    command = args.command

    if command == "users":
        out(f"{'NAME':<20}{'ROLE':<9}{'STATE':<10}LAST SEEN")
        for user in store.list_users():
            out(f"{user.username:<20}{user.role:<9}{'disabled' if user.disabled else 'active':<10}{stamp(user.last_seen)}")
        return 0

    if command == "role":
        try:
            found = store.set_role(args.name, args.role)
        except ValueError as error:
            out(f"Error: {error}")
            return 1
        if not found:
            out(f"Error: no user named '{args.name}'")
            return 1
        store.append_audit(actor, "role_changed", args.name, f"now {args.role}")
        out(f"{args.name} is now {args.role}.")
        return 0

    if command in ("disable", "enable"):
        user = store.get_user(args.name)
        if user is None:
            out(f"Error: no user named '{args.name}'")
            return 1
        if command == "disable" and user.role == "admin" and sum(
                1 for u in store.list_users() if u.role == "admin" and not u.disabled) <= 1:
            out("Error: cannot disable the last admin")
            return 1
        store.set_disabled(args.name, command == "disable")
        if command == "disable":
            store.delete_user_sessions(user.id)
            store.bump_room_epoch()  # the encrypted room moves to new keys the removed person never receives
        store.append_audit(actor, f"user_{command}d", user.username)
        out(f"{user.username} is {'disabled' if command == 'disable' else 'enabled'}.")
        return 0

    if command == "reset":
        user = store.get_user(args.name)
        if user is None:
            out(f"Error: no user named '{args.name}'")
            return 1
        temporary = accounts.temporary_password()
        accounts.set_password(user.username, temporary)
        store.delete_user_sessions(user.id)
        store.append_audit(actor, "password_reset", user.username)
        out(f"{user.username}'s temporary password is: {temporary}")
        out("(shown once; they should change it after signing in)")
        return 0

    if command == "create":
        if store.get_user(args.name) is not None:
            out(f"Error: '{args.name}' already exists")
            return 1
        password = args.password or getpass.getpass(f"Password for {args.name}: ")
        problem = check_password(password, args.name, int(store.get_setting("password_min", "6")))
        if problem:
            out(f"Error: choose a stronger password ({problem})")
            return 1
        accounts.create_account(args.name, password, args.role)
        store.append_audit(actor, "user_created", args.name, f"role {args.role}")
        out(f"{args.name} was created as {args.role}.")
        return 0

    if command == "settings":
        if args.key and args.value is not None:
            try:
                stored_key, convert = SETTINGS[args.key]
                store.set_setting(stored_key, convert(args.value))
            except ValueError:
                out(f"Error: '{args.value}' is not a valid value for {args.key}")
                return 1
            store.append_audit(actor, "setting_changed", stored_key, str(args.value)[:100])
        for key, (stored_key, _convert) in sorted(SETTINGS.items()):
            out(f"{key:<20}{store.get_setting(stored_key, '(default)')}")
        return 0

    if command == "audit":
        if args.verify:
            ok, bad_id, message = store.verify_audit()
            out(("OK: " if ok else "TAMPERING DETECTED: ") + message)
            return 0 if ok else 2
        rows = list(reversed(store.audit_rows(limit=max(1, min(args.tail, 50)))))
        for row in rows:
            out(f"{stamp(row['ts'])}  {row['actor']:<14}{row['action']:<18}{row['target']:<16}{row['detail']}")
        out(f"({store.audit_count()} entries in total)")
        return 0
    return 1


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(build_parser().parse_args(argv)))


if __name__ == "__main__":
    main()
