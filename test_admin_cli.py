"""The offline admin tool, run against a real database file."""

import tempfile
import unittest
from pathlib import Path

import admin_cli
import chat
from accounts import AccountStore


class AdminCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = str(Path(self.tmp) / "accounts.db")
        accounts = AccountStore(self.db)
        accounts.create_account("Boss", "river-stone-42")  # the first account is the admin
        accounts.create_account("Worker", "river-stone-42")
        accounts.store.close()

    def run_cli(self, *argv):
        lines = []
        code = admin_cli.run(admin_cli.build_parser().parse_args(["--accounts", self.db, *argv]), lines.append)
        return code, "\n".join(lines)

    def test_users_roles_and_audit(self):
        code, text = self.run_cli("users")
        self.assertEqual(code, 0)
        self.assertIn("Boss", text)
        self.assertIn("admin", text)
        self.assertEqual(self.run_cli("role", "Worker", "guest")[0], 0)
        self.assertEqual(self.run_cli("role", "Nobody", "guest")[0], 1)
        self.assertEqual(self.run_cli("role", "Boss", "member")[0], 1)  # the last admin
        self.assertIn("role_changed", self.run_cli("audit")[1])

    def test_disable_reset_create(self):
        self.assertEqual(self.run_cli("disable", "Worker")[0], 0)
        self.assertEqual(self.run_cli("disable", "Boss")[0], 1)
        self.assertIn("disabled", self.run_cli("users")[1])
        self.assertEqual(self.run_cli("enable", "Worker")[0], 0)
        code, text = self.run_cli("reset", "Worker")
        temporary = text.split("password is: ")[1].split()[0]
        accounts = AccountStore(self.db)
        self.assertEqual(accounts.authenticate("Worker", temporary)[0], "ok")
        accounts.store.close()
        self.assertEqual(self.run_cli("create", "Newbie", "--password", "abc")[0], 1)
        self.assertEqual(self.run_cli("create", "Newbie", "--password", "river-stone-42", "--role", "guest")[0], 0)
        self.assertEqual(self.run_cli("create", "Newbie", "--password", "river-stone-42")[0], 1)
        self.assertNotIn(temporary, self.run_cli("audit", "--tail", "50")[1])

    def test_settings(self):
        self.assertEqual(self.run_cli("settings", "max_upload_mb", "10")[0], 0)
        self.assertIn(str(10 * 1024 * 1024), self.run_cli("settings")[1])
        self.assertEqual(self.run_cli("settings", "max_upload_mb", "lots")[0], 1)
        self.run_cli("settings", "blocked_extensions", "exe, .BAT")
        self.assertIn(".bat,.exe", self.run_cli("settings")[1])

    def test_verify_detects_tampering(self):
        self.run_cli("role", "Worker", "guest")
        self.assertEqual(self.run_cli("audit", "--verify")[0], 0)
        accounts = AccountStore(self.db)
        accounts.store._db.execute("UPDATE audit SET actor = 'mallory' WHERE id = 1")
        accounts.store._db.commit()
        accounts.store.close()
        code, text = self.run_cli("audit", "--verify")
        self.assertEqual(code, 2)
        self.assertIn("TAMPERING", text)

    def test_launcher_has_the_admin_command(self):
        args = chat.build_parser().parse_args(["admin", "users"])
        self.assertEqual((args.command, args.rest), ("admin", ["users"]))


if __name__ == "__main__":
    unittest.main()
