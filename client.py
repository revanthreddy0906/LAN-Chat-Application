"""Interactive TCP chat client for the LAN Chat Application."""

from __future__ import annotations

import argparse
import getpass
import socket
import ssl
import threading
from typing import Callable

from chat_core import (
    DEFAULT_PORT,
    CertificateChanged,
    LoginError,
    SafeSender,
    TrustDeclined,
    connect_secure,
    parse_address,
    parse_message,
    start_heartbeat,
)
from certs import short_fingerprint
from colors import BOLD, CYAN, DIM, GREEN, MAGENTA, RED, YELLOW, colorize, supports_color
from discovery import FoundServer, discover
from protocol import receive_message
from settings import Settings

PROMPT = "> "
QUIT_COMMANDS = {"/quit", "/exit"}

_COLOR = supports_color()


def _style(code: str, text: str) -> str:
    return colorize(code, text, enabled=_COLOR)


def _clear_line() -> str:
    return "\r\033[K" if _COLOR else ""


def _format_incoming(message: str) -> str:
    parsed = parse_message(message)
    stamp = _style(DIM, f"[{parsed.timestamp}] ") if parsed.timestamp else ""
    if parsed.kind == "join":
        return _style(GREEN, parsed.text)
    if parsed.kind in ("leave", "shutdown"):
        return _style(YELLOW, parsed.text)
    if parsed.kind == "welcome":
        return _style(CYAN, parsed.text)
    if parsed.kind == "error":
        return _style(RED, parsed.text)
    if parsed.kind == "private":
        return stamp + _style(MAGENTA, f"{parsed.name}: {parsed.text}")
    if parsed.kind == "chat":
        return f"{stamp}{_style(BOLD, parsed.name)}: {parsed.text}"
    return parsed.text


def receive_loop(connection: socket.socket, disconnected: threading.Event) -> None:
    try:
        while not disconnected.is_set():
            message = receive_message(connection)
            if message is None:
                break
            print(f"{_clear_line()}{_format_incoming(message)}")
            print(PROMPT, end="", flush=True)
    except (ConnectionError, OSError, UnicodeError, ValueError):
        pass
    finally:
        # Only announce the disconnect here if the server closed the
        # connection first; a user-initiated /quit or Ctrl+C already
        # printed its own message from the main thread.
        if not disconnected.is_set():
            print(f"{_clear_line()}{_style(YELLOW, 'Connection closed by server.')}")
        disconnected.set()


def _describe(server: FoundServer) -> str:
    lock = "encrypted" if server.tls else "NOT encrypted"
    people = f"{server.users} online"
    return f"'{server.name}' at {server.host}:{server.port} ({lock}, {people})"


def pick_server(
    find: Callable[[], list[FoundServer]] = discover,
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
) -> tuple[str, int | None]:
    """Find chats on the network and let the user choose one."""
    say(_style(DIM, "Looking for chats on your network..."))
    servers = find()

    def manual() -> tuple[str, int | None]:
        host, port = parse_address(ask("Server address (example 192.168.1.5): "))
        if not host:
            raise SystemExit("A server address is required.")
        return host, port

    if not servers:
        say("No chats found automatically (some Wi-Fi networks block discovery).")
        return manual()
    if len(servers) == 1:
        server = servers[0]
        answer = ask(f"Found {_describe(server)}. Join? [Y/n] ").strip().lower()
        if answer in ("n", "no"):
            return manual()
        return server.host, server.port

    say("Chats on your network:")
    for number, server in enumerate(servers, start=1):
        say(f"  {number}. {_describe(server)}")
    while True:
        answer = ask("Pick a number, or type an address: ").strip()
        if answer.isdigit():
            if 1 <= int(answer) <= len(servers):
                chosen = servers[int(answer) - 1]
                return chosen.host, chosen.port
            say(f"Please pick a number from 1 to {len(servers)}, or type an address.")
        elif answer:
            return parse_address(answer)


def _confirm_trust(fingerprint: str, host: str, port: int) -> bool:
    print(_style(YELLOW, f"First time connecting to {host}:{port}."))
    print(f"Its certificate fingerprint is:\n  {fingerprint}")
    print(_style(DIM, "Check it matches the one shown on the server's screen."))
    return input("Trust this server? [y/N] ").strip().lower() in ("y", "yes")


def _confirm_plain(host: str, port: int) -> bool:
    print(_style(RED, f"{host}:{port} is NOT encrypted: passwords and messages can be read by others."))
    return input("Continue anyway? [y/N] ").strip().lower() in ("y", "yes")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Join a LAN chat from the terminal")
    parser.add_argument("server_ip", nargs="?", help="server address (omit to search the network)")
    parser.add_argument("--port", type=int, help=f"TCP port (default: {DEFAULT_PORT} or the discovered one)")
    parser.add_argument("--username", help="chat username (default: the last one you used)")
    parser.add_argument("--password", help="password (prompted if omitted; avoid on shared machines)")
    parser.add_argument("--tls", action="store_true", help="(compatibility) encryption is detected automatically")
    parser.add_argument("--cafile", help="only trust this certificate file (skips the first-use prompt)")
    args = parser.parse_args(argv)

    settings = Settings()
    try:
        if args.server_ip:
            host, port = parse_address(args.server_ip)
        else:
            host, port = pick_server()
        port = args.port or port or DEFAULT_PORT

        remembered = settings.get("username", "")
        username = args.username
        if not username:
            hint = f" [{remembered}]" if remembered else ""
            username = input(f"Username{hint}: ").strip() or remembered
        if not host or not username:
            raise SystemExit("A server address and a username are required.")
        password = args.password
        if password is None:
            password = getpass.getpass("Password (new users are registered automatically): ")

        result = connect_secure(
            host, port, username, password, settings,
            confirm_trust=_confirm_trust, confirm_plain=_confirm_plain, cafile=args.cafile,
        )
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("\nCancelled.")
    except TrustDeclined as error:
        raise SystemExit(_style(YELLOW, str(error)))
    except CertificateChanged as error:
        raise SystemExit(_style(RED, f"WARNING: {error}"))
    except LoginError as error:
        raise SystemExit(_style(RED, f"Login failed: {error}"))
    except ssl.SSLError as error:
        raise SystemExit(_style(RED, f"Secure connection failed: {error}"))
    except OSError as error:
        raise SystemExit(_style(RED, f"Unable to connect: {error}"))

    settings.set("username", username)
    settings.set("last_server", f"{host}:{port}")

    connection = result.connection
    disconnected = threading.Event()
    sender = SafeSender(connection)
    with connection:
        mode = "encrypted" if result.encrypted else "NOT encrypted"
        print(_style(CYAN, f"Connected to {host}:{port} as {username} ({mode})."))
        if result.fingerprint:
            print(_style(DIM, f"Server certificate {short_fingerprint(result.fingerprint)}"))
        print(_style(DIM, "Type a message and press Enter. /help for commands, /quit or Ctrl+C to leave."))
        print(_style(DIM, "Plain-text mode: replies, reactions, edits, deletes and typing show only in the chat window."))

        threading.Thread(
            target=receive_loop, args=(connection, disconnected), daemon=True
        ).start()
        start_heartbeat(sender, disconnected)
        try:
            while not disconnected.is_set():
                try:
                    message = input(PROMPT).strip()
                except EOFError:
                    break
                except KeyboardInterrupt:
                    print()
                    break
                if not message:
                    continue
                if message.lower() in QUIT_COMMANDS:
                    break
                try:
                    sender.send(message)
                except ValueError:
                    print(_style(RED, "Message too long."))
                except (ConnectionError, OSError):
                    print(_style(RED, "Connection lost."))
                    break
        finally:
            if not disconnected.is_set():
                print(_style(DIM, "Left the chat."))
            disconnected.set()


if __name__ == "__main__":
    main()
