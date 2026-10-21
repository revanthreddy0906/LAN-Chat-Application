"""Who may do what: one table and one function."""

from __future__ import annotations

ROLES = ("admin", "member", "guest")

PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({
        "send_message", "send_private", "react", "upload", "edit_own", "delete_own",
        "delete_any", "pin_any", "mention_everyone", "manage_users", "view_audit",
        "manage_settings",
    }),
    "member": frozenset({
        "send_message", "send_private", "react", "upload", "edit_own", "delete_own", "pin_own",
    }),
    "guest": frozenset({"send_message", "react"}),
}


def is_valid_role(role: str) -> bool:
    return role in PERMISSIONS


def can(role: str, action: str) -> bool:
    return action in PERMISSIONS.get(role, frozenset())
