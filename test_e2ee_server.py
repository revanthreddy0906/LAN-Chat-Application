"""The server's public-key directory: publishing, lookups, key changes, backups, policy, migration."""

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

import e2ee
from e2ee import Identity
from store import MIGRATIONS, Store
from test_v2 import V2TestCase

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")


class KeysTestCase(V2TestCase):
    def publish(self, peer, identity, backup=None, req=1):
        message = dict(identity.public().to_dict(), t="keys_publish", req=req)
        if backup is not None:
            message["backup"] = backup
        peer.send(**message)
        return peer.until(lambda e: e["t"] == "keys_result" and e["req"] == req, limit=300)

    def lookup(self, peer, *names):
        peer.send(t="keys_get", req=9, names=list(names))
        return peer.until(lambda e: e["t"] == "keys" and e["req"] == 9, limit=300)["keys"]


@needs_crypto
class DirectoryTest(KeysTestCase):
    def test_welcome_reports_the_policy_and_whether_i_have_keys(self):
        alice = self.v2("Alice")
        self.assertEqual((alice.welcome["e2ee"]["policy"], alice.welcome["e2ee"]["have_keys"]), ("optional", False))
        self.assertEqual((alice.welcome["e2ee"]["room"], alice.welcome["e2ee"]["epoch"], alice.welcome["e2ee"]["next"]),
                         ("off", 1, 0))
        self.publish(alice, Identity.generate())
        alice.close()
        time.sleep(0.3)
        again = self.v2("Alice")
        self.assertTrue(again.welcome["e2ee"]["have_keys"])

    def test_publish_and_lookup(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        identity = Identity.generate()
        reply = self.publish(alice, identity)
        self.assertEqual((reply["ok"], reply["status"]), (True, "created"))
        found = self.lookup(bob, "alice", "Nobody")
        self.assertEqual(list(found), ["Alice"])  # canonical spelling, unknown names left out
        bundle = e2ee.Bundle.from_dict(found["Alice"])
        self.assertEqual(bundle, identity.public())
        self.assertTrue(bundle.verify())

    def test_a_first_publication_tells_others_to_look_again(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.publish(alice, Identity.generate())
        alert = bob.until(lambda e: e["t"] == "key_changed", limit=300)
        self.assertEqual((alert["user"], alert["created"]), ("Alice", True))

    def test_publishing_the_same_keys_again_changes_nothing(self):
        alice = self.v2("Alice")
        identity = Identity.generate()
        self.publish(alice, identity)
        self.assertEqual(self.publish(alice, identity, req=2)["status"], "same")
        self.assertEqual(sum(1 for r in self.server.store.audit_rows(limit=50) if r["action"].startswith("keys_")), 1)

    def test_a_changed_key_is_announced_and_audited(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.publish(alice, Identity.generate())
        new = Identity.generate()
        self.assertEqual(self.publish(alice, new, req=2)["status"], "changed")
        alert = bob.until(lambda e: e["t"] == "key_changed" and not e.get("created"), limit=300)
        self.assertEqual((alert["user"], alert["fingerprint"]), ("Alice", new.public().fingerprint()))
        self.assertIn("keys_changed", [r["action"] for r in self.server.store.audit_rows(limit=50)])
        self.assertEqual(self.server.store.get_user_keys(1)["version"], 2)

    def test_a_rotation_is_marked_audited_and_keeps_envelopes(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.publish(alice, Identity.generate())
        self.server.store.add_envelope(1, 2, 1, "{}")  # an envelope sealed to alice's current key
        rotated = Identity.generate()
        alice.send(t="keys_publish", req=5, rotated=True, **rotated.public().to_dict())
        self.assertEqual(alice.until(lambda e: e["t"] == "keys_result" and e["req"] == 5, limit=300)["status"], "changed")
        alert = bob.until(lambda e: e["t"] == "key_changed" and not e.get("created"), limit=300)
        self.assertTrue(alert["rotated"])
        self.assertEqual(len(self.server.store.envelopes_for(1, 0, 10)), 1)  # kept: she holds her old identity
        self.assertIn("keys_rotated", [r["action"] for r in self.server.store.audit_rows(limit=30)])
        alice.send(t="keys_publish", req=6, **Identity.generate().public().to_dict())  # a plain replacement
        alice.until(lambda e: e["t"] == "keys_result" and e["req"] == 6, limit=300)
        self.assertEqual(self.server.store.envelopes_for(1, 0, 10), [])  # not claimed as a rotation: cleared

    def test_unsigned_or_mismatched_bundles_are_refused(self):
        alice = self.v2("Alice")
        good, other = Identity.generate().public(), Identity.generate().public()
        forged = dict(good.to_dict(), dh=e2ee.b64(other.dh), t="keys_publish", req=3)
        alice.send(**forged)
        reply = alice.until(lambda e: e["t"] == "keys_result" and e["req"] == 3, limit=300)
        self.assertFalse(reply["ok"])
        self.assertIsNone(self.server.store.get_user_keys(1))
        for broken in ({"dh": "AAAA", "sign": "AAAA", "sig": "AAAA"}, {}, {"dh": 5, "sign": 6, "sig": 7}):
            alice.send(t="keys_publish", req=4, **broken)
            self.assertFalse(alice.until(lambda e: e["t"] == "keys_result" and e["req"] == 4, limit=300)["ok"])

    def test_lookup_is_validated_and_capped(self):
        alice = self.v2("Alice")
        alice.send(t="keys_get", req=5, names="Bob")
        self.assertFalse(alice.until(lambda e: e["t"] == "keys_result" and e["req"] == 5, limit=300)["ok"])
        found = self.lookup(alice, *[f"user{i}" for i in range(100)])
        self.assertEqual(found, {})

    def test_reset_removes_keys_and_backup_and_tells_everyone(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        self.publish(alice, identity, e2ee.make_backup(identity, code))
        alice.send(t="keys_reset", req=6)
        self.assertEqual(alice.until(lambda e: e["t"] == "keys_result" and e["req"] == 6, limit=300)["status"], "reset")
        alert = bob.until(lambda e: e["t"] == "key_changed" and e.get("reset"), limit=300)
        self.assertTrue(alert["reset"])
        self.assertEqual(self.lookup(bob, "Alice"), {})
        self.assertIsNone(self.server.store.get_backup(1))
        self.assertIn("keys_reset", [r["action"] for r in self.server.store.audit_rows(limit=50)])


@needs_crypto
class BackupTest(KeysTestCase):
    def test_backup_comes_back_to_a_fresh_sign_in_and_restores(self):
        alice = self.v2("Alice")
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        self.publish(alice, identity, e2ee.make_backup(identity, code))
        alice.close()
        time.sleep(0.3)
        newcomer = self.v2("Alice")
        newcomer.send(t="keys_backup_get", req=7)
        reply = newcomer.until(lambda e: e["t"] == "keys_backup", limit=300)
        restored = e2ee.open_backup(reply["backup"], code)
        self.assertEqual(restored.secret_bytes(), identity.secret_bytes())
        self.assertEqual(reply["keys"]["fingerprint"], identity.public().fingerprint())

    def test_nobody_gets_someone_elses_backup(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        self.publish(alice, identity, e2ee.make_backup(identity, code))
        bob.send(t="keys_backup_get", req=8)
        self.assertIsNone(bob.until(lambda e: e["t"] == "keys_backup", limit=300)["backup"])

    def test_oversize_backups_are_refused(self):
        alice = self.v2("Alice")
        reply = self.publish(alice, Identity.generate(), {"junk": "x" * 3500})
        self.assertFalse(reply["ok"])

    def test_the_server_never_holds_a_secret_key_or_the_recovery_code(self):
        alice = self.v2("Alice")
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        self.publish(alice, identity, e2ee.make_backup(identity, code))
        time.sleep(0.3)
        raw = Path(self.server.store.path).read_bytes()
        secret = identity.secret_bytes()
        for needle in (secret, secret[:32], secret[32:], e2ee.b64(secret).encode(), code.encode(),
                       e2ee.normalize_recovery_code(code).encode()):
            self.assertNotIn(needle, raw)


class PolicyTest(KeysTestCase):
    def test_policy_defaults_and_admin_can_change_it(self):
        admin = self.v2("Admin")
        admin.send(t="admin", req=1, op="set_setting", user="e2ee_policy", value="required")
        self.assertTrue(admin.until(lambda e: e["t"] == "admin_result", limit=300)["ok"])
        self.assertEqual(self.server.e2ee_policy, "required")
        admin.send(t="admin", req=2, op="set_setting", user="e2ee_policy", value="sometimes")
        self.assertFalse(admin.until(lambda e: e["t"] == "admin_result" and e["req"] == 2, limit=300)["ok"])
        self.assertEqual(self.server.e2ee_policy, "required")
        admin.send(t="admin_settings", req=3)
        self.assertEqual(admin.until(lambda e: e["t"] == "admin_settings", limit=300)["e2ee_policy"], "required")
        later = self.v2("Later")
        self.assertEqual(later.welcome["e2ee"]["policy"], "required")

    def test_a_policy_change_reaches_every_connected_client_at_once(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.server.set_e2ee_policy("required")
        for peer in (alice, bob):
            self.assertEqual(peer.until(lambda e: e["t"] == "e2ee_policy", limit=300)["policy"], "required")
        with self.assertRaises(ValueError):
            self.server.set_e2ee_policy("whenever")

    def test_garbage_in_the_database_falls_back_to_optional(self):
        self.server.store.set_setting("e2ee_policy", "nonsense")
        self.assertEqual(self.server.e2ee_policy, "optional")


class MigrationTest(unittest.TestCase):
    def test_a_version_5_database_upgrades_without_losing_anything(self):
        path = Path(tempfile.mkdtemp()) / "old.db"
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        for number, script in enumerate(MIGRATIONS[:5], start=1):
            db.executescript(script)
            db.execute("INSERT INTO schema_version (version) VALUES (?)", (number,))
        db.execute("INSERT INTO users (username, salt, hash, role, created_at) VALUES ('Old','00','00','admin',1)")
        db.execute("INSERT INTO messages (sender_id, body, created_at) VALUES (1, 'kept message', 2)")
        db.commit()
        db.close()
        store = Store(path)
        self.assertEqual(store.schema_version(), 7)
        self.assertEqual([u.username for u in store.list_users()], ["Old"])
        self.assertEqual(store.history_for(1, 10)[0].body, "kept message")
        self.assertEqual(store.set_user_keys(1, "a", "b", "c", "fp"), "created")
        self.assertTrue(store.verify_audit()[0])
        store.close()


if __name__ == "__main__":
    unittest.main()
