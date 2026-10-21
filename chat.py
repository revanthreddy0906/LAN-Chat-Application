#!/usr/bin/env python3
"""One command for LAN Chat.

    python3 chat.py host     host a chat for others on this network
    python3 chat.py          open the chat window (find and join a chat)
    python3 chat.py join     join a chat from the terminal
    python3 chat.py admin    manage accounts and the audit log (see: chat.py admin -h)
"""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chat.py",
        description="LAN Chat: with no command, opens the chat window.",
    )
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("gui", help="open the chat window (default)")

    host = commands.add_parser("host", help="host a chat for others on this network")
    host.add_argument("--port", type=int, help="TCP port (default: first free from 5050)")
    host.add_argument("--name", help="name shown to people looking for a chat")
    host.add_argument("--no-tls", action="store_true", help="turn encryption off")
    host.add_argument("--accounts", help="accounts database (default: accounts.db; a .json path means the .db beside it)")

    join = commands.add_parser("join", help="join a chat from the terminal")
    join.add_argument("address", nargs="?", help="server address (omit to search the network)")
    join.add_argument("--username", help="your username")
    join.add_argument("--password", help="your password (prompted if omitted)")
    admin = commands.add_parser("admin", add_help=False, help="manage accounts and the audit log")
    admin.add_argument("rest", nargs=argparse.REMAINDER)
    return parser


def host_arguments(args: argparse.Namespace) -> list[str]:
    forwarded: list[str] = []
    if args.port:
        forwarded += ["--port", str(args.port)]
    if args.name:
        forwarded += ["--name", args.name]
    if args.no_tls:
        forwarded.append("--no-tls")
    if args.accounts:
        forwarded += ["--accounts", args.accounts]
    return forwarded


def join_arguments(args: argparse.Namespace) -> list[str]:
    forwarded: list[str] = [args.address] if args.address else []
    if args.username:
        forwarded += ["--username", args.username]
    if args.password is not None:
        forwarded += ["--password", args.password]
    return forwarded


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    command = args.command or "gui"

    if command == "host":
        import server

        server.main(host_arguments(args))
    elif command == "admin":
        import admin_cli

        admin_cli.main(args.rest)
    elif command == "join":
        import client

        client.main(join_arguments(args))
    else:
        try:
            import gui_client
        except ImportError:
            print("The chat window needs Tkinter, which this Python does not have.")
            print("Falling back to the terminal client.\n")
            import client

            client.main([])
            return
        gui_client.main([])


if __name__ == "__main__":
    main()
