"""Admin events, role checks, settings, and the tamper-evident audit log."""

import time
import unittest

import audit
from chat_core import LoginError, connect_and_login
from store import Store
from test_v2 import V2TestCase


class AdminTestCase(V2TestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.v2("Admin")
        self.member = self.v2("Member")

    def act(self, peer, op, user=None, value=None, until="admin_result"):
        peer.send(t="admin", req=1, op=op, user=user, value=value)
        return peer.until(lambda e: e["t"] == until and e.get("req") == 1, limit=400)

    def actions(self, **filters):
        return [(r["actor"], r["action"], r["target"]) for r in self.server.store.audit_rows(limit=50, **filters)]


class PermissionsTest(AdminTestCase):
    def test_members_cannot_use_any_admin_event(self):
        for event in ({"t": "admin_users", "req": 1}, {"t": "admin", "req": 1, "op": "role", "user": "Admin", "value": "guest"},
                      {"t": "admin_settings", "req": 1}, {"t": "admin_audit", "req": 1}, {"t": "admin_verify", "req": 1}):
            self.member.send(**event)
            reply = self.member.until(lambda e: e["t"] == "admin_result", limit=100)
            self.assertFalse(reply["ok"], event)
        self.assertEqual(self.server.store.get_user("Admin").role, "admin")
        self.assertGreaterEqual(self.actions(action="denied").count(("Member", "denied", "")), 5)

    def test_unknown_operations_and_junk(self):
        self.assertFalse(self.act(self.admin, "explode")["ok"])
        self.admin.send(t="admin", req=1, op=5, user=[])
        self.assertFalse(self.admin.until(lambda e: e["t"] == "admin_result")["ok"])


class UserManagementTest(AdminTestCase):
    def test_user_list_shows_status(self):
        self.admin.send(t="admin_users", req=1)
        reply = self.admin.until(lambda e: e["t"] == "admin_users")
        by_name = {u["name"]: u for u in reply["users"]}
        self.assertEqual((by_name["Admin"]["role"], by_name["Admin"]["online"]), ("admin", True))
        self.assertEqual(by_name["Member"]["role"], "member")
        self.assertEqual(reply["total"], 2)

    def test_user_list_pages(self):
        for number in range(20):
            self.server.accounts.create_account(f"Extra{number}", "river-stone-42")
        self.admin.send(t="admin_users", req=1, page=1)
        reply = self.admin.until(lambda e: e["t"] == "admin_users")
        self.assertEqual((reply["page"], reply["pages"], len(reply["users"])), (1, 2, 7))

    def test_change_role_is_audited_and_live(self):
        self.assertTrue(self.act(self.admin, "role", "Member", "guest")["ok"])
        self.assertEqual(self.server.store.get_user("Member").role, "guest")
        self.assertIn(("Admin", "role_changed", "Member"), self.actions())
        self.assertFalse(self.act(self.admin, "role", "Member", "emperor")["ok"])
        self.assertFalse(self.act(self.admin, "role", "Nobody", "guest")["ok"])

    def test_last_admin_is_protected(self):
        self.assertFalse(self.act(self.admin, "role", "Admin", "member")["ok"])
        self.assertFalse(self.act(self.admin, "disable", "Admin")["ok"])

    def test_disable_signs_out_and_blocks_login(self):
        reply = self.act(self.admin, "disable", "Member")
        self.assertTrue(reply["ok"], reply)
        time.sleep(0.3)
        with self.assertRaises(LoginError) as raised:
            connect_and_login("127.0.0.1", self.port, "Member", "secret", None, protocol=2)
        self.assertIn("disabled", str(raised.exception))
        self.assertTrue(self.act(self.admin, "enable", "Member")["ok"])
        self.v2("Member")
        self.assertIn(("Admin", "user_disabled", "Member"), self.actions())

    def test_kick(self):
        self.assertTrue(self.act(self.admin, "kick", "Member")["ok"])
        self.assertIsNone(self.member.until(lambda e: e["t"] == "message", limit=3))
        self.assertFalse(self.act(self.admin, "kick", "Member")["ok"])  # not online any more

    def test_reset_password_returns_a_one_time_password(self):
        reply = self.act(self.admin, "reset_password", "Member")
        temporary = reply["password"]
        self.assertGreaterEqual(len(temporary), 8)
        time.sleep(0.3)
        with self.assertRaises(LoginError):
            connect_and_login("127.0.0.1", self.port, "Member", "secret", None, protocol=2)
        connect_and_login("127.0.0.1", self.port, "Member", temporary, None, protocol=2).close()
        entries = " ".join(f"{a} {b} {c}" for a, b, c in self.actions())
        self.assertNotIn(temporary, entries)  # secrets never reach the log

    def test_signout_revokes_saved_sessions(self):
        self.assertEqual(self.server.store.session_count(self.server.store.get_user("Member").id), 1)
        reply = self.act(self.admin, "signout", "Member")
        self.assertTrue(reply["ok"])
        self.assertEqual(self.server.store.session_count(self.server.store.get_user("Member").id), 0)

    def test_create_user_applies_the_password_policy(self):
        self.server.enforce_password_policy = True
        self.assertFalse(self.act(self.admin, "create_user", "Newbie", "abc")["ok"])
        self.assertTrue(self.act(self.admin, "create_user", "Newbie", "river-stone-42")["ok"])
        self.assertFalse(self.act(self.admin, "create_user", "Newbie", "river-stone-42")["ok"])  # exists
        self.assertFalse(self.act(self.admin, "create_user", "bad name!", "river-stone-42")["ok"])
        self.assertEqual(self.server.store.get_user("Newbie").role, "member")


class SettingsTest(AdminTestCase):
    def test_settings_round_trip_and_take_effect(self):
        self.admin.send(t="admin_settings", req=1)
        current = self.admin.until(lambda e: e["t"] == "admin_settings")
        self.assertTrue(current["open_registration"])
        self.assertEqual(current["max_upload_mb"], self.server.max_upload // (1024 * 1024))
        self.assertTrue(self.act(self.admin, "set_setting", "max_upload_mb", 3)["ok"])
        self.assertEqual(self.server.max_upload, 3 * 1024 * 1024)
        self.assertTrue(self.act(self.admin, "set_setting", "blocked", "exe, .Bat,zip")["ok"])
        self.assertEqual(self.server.blocked_extensions, frozenset({".exe", ".bat", ".zip"}))
        self.assertTrue(self.act(self.admin, "set_setting", "open_registration", False)["ok"])
        self.assertFalse(self.server.open_registration)
        self.assertTrue(self.act(self.admin, "set_setting", "password_min", 9)["ok"])
        self.assertEqual(self.server.password_min, 9)
        self.assertEqual(sum(1 for a in self.actions() if a[1] == "setting_changed"), 4)

    def test_bad_values_are_refused(self):
        for key, value in (("max_upload_mb", 0), ("max_upload_mb", "lots"), ("user_quota_mb", -5),
                           ("blocked", ".ex e"), ("password_min", 2), ("nonsense", 1)):
            self.assertFalse(self.act(self.admin, "set_setting", key, value)["ok"], (key, value))


class AuditLogTest(AdminTestCase):
    def test_login_and_account_events_are_recorded(self):
        names = [a for _actor, a, _t in self.actions()]
        self.assertIn("account_created", names)
        self.assertIn("login", names)

    def test_audit_view_filters_and_pages(self):
        for number in range(30):
            self.server.audit("Admin", "demo_event", f"thing {number}")
        self.admin.send(t="admin_audit", req=1, action="demo_event")
        first = self.admin.until(lambda e: e["t"] == "admin_audit")
        self.assertEqual(len(first["rows"]), 12)
        self.assertTrue(first["has_more"])
        self.assertTrue(all(r["action"] == "demo_event" for r in first["rows"]))
        self.admin.send(t="admin_audit", req=2, action="demo_event", before=first["rows"][-1]["id"])
        second = self.admin.until(lambda e: e["t"] == "admin_audit" and e["req"] == 2)
        self.assertLess(second["rows"][0]["id"], first["rows"][-1]["id"])

    def test_oversize_entries_still_fit_a_frame(self):
        for number in range(15):
            self.server.audit("A" * 32, "x" * 30, "T" * 200, "D" * 300)
        self.admin.send(t="admin_audit", req=1)
        reply = self.admin.until(lambda e: e["t"] == "admin_audit")
        self.assertTrue(reply["rows"])

    def test_messages_text_is_never_in_the_log(self):
        self.member.say("my very private words")
        self.server.audit("Admin", "x")
        text = repr(self.server.store._db.execute("SELECT * FROM audit").fetchall() and
                    [tuple(r) for r in self.server.store._db.execute("SELECT * FROM audit")])
        self.assertNotIn("private words", text)


class ChainTest(V2TestCase):
    def fresh(self):
        return self.server.store

    def fill(self, count=6):
        for number in range(count):
            self.fresh().append_audit("tester", "event", f"target {number}", "detail")

    def test_untouched_log_verifies(self):
        self.fill()
        ok, bad, message = self.fresh().verify_audit()
        self.assertTrue(ok, message)
        self.assertIn("6 entries", message)

    def test_empty_log_verifies(self):
        self.assertTrue(self.fresh().verify_audit()[0])

    def test_edited_row_is_found(self):
        self.fill()
        store = self.fresh()
        store._db.execute("UPDATE audit SET actor = 'someone else' WHERE id = 3")
        store._db.commit()
        ok, bad, message = store.verify_audit()
        self.assertFalse(ok)
        self.assertEqual(bad, 3)
        self.assertIn("changed", message)

    def test_deleted_middle_row_is_found(self):
        self.fill()
        store = self.fresh()
        store._db.execute("DELETE FROM audit WHERE id = 3")
        store._db.commit()
        ok, bad, message = store.verify_audit()
        self.assertFalse(ok)
        self.assertEqual(bad, 4)
        self.assertIn("removed", message)

    def test_deleted_newest_rows_are_found_through_the_head_marker(self):
        self.fill()
        store = self.fresh()
        store._db.execute("DELETE FROM audit WHERE id > 4")
        store._db.commit()
        ok, bad, message = store.verify_audit()
        self.assertFalse(ok)
        self.assertIn("missing", message)

    def test_inserted_row_is_found(self):
        self.fill()
        store = self.fresh()
        store._db.execute("INSERT INTO audit (ts, actor, action, target, detail, prev_hash, hash)"
                          " VALUES (1, 'forger', 'x', '', '', ?, ?)", ("f" * 64, "e" * 64))
        store._db.commit()
        self.assertFalse(store.verify_audit()[0])

    def test_canonical_hash_is_stable(self):
        entry = {"ts": 1.0, "actor": "a", "action": "b", "target": "", "detail": ""}
        self.assertEqual(audit.entry_hash(audit.GENESIS, entry), audit.entry_hash(audit.GENESIS, dict(reversed(list(entry.items())))))

    def test_survives_a_restart(self):
        self.fill(3)
        path = self.server.store.path
        self.server.stop()
        reopened = Store(path)
        self.assertTrue(reopened.verify_audit()[0])
        reopened.append_audit("tester", "after restart")
        self.assertTrue(reopened.verify_audit()[0])
        reopened.close()
        from server import ChatServer
        from accounts import AccountStore
        from test_server import RELAXED
        self.server = ChatServer("127.0.0.1", 0, accounts=AccountStore(path), quiet=True, **RELAXED)
        self.server.start()


class VerifyEventTest(AdminTestCase):
    def test_admin_can_verify_and_sees_tampering(self):
        self.admin.send(t="admin_verify", req=1)
        good = self.admin.until(lambda e: e["t"] == "admin_verify")
        self.assertTrue(good["ok"], good)
        store = self.server.store
        store._db.execute("UPDATE audit SET target = 'edited' WHERE id = 1")
        store._db.commit()
        self.admin.send(t="admin_verify", req=2)
        bad = self.admin.until(lambda e: e["t"] == "admin_verify" and e["req"] == 2)
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["bad_id"], 1)


if __name__ == "__main__":
    unittest.main()
