"""Key files and pinned contacts on disk."""

import json
import os
import stat
import tempfile
import unittest

import e2ee
import keystore
from e2ee import CryptoError, Identity, WrongPassphrase
from keystore import KeyStore

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")


@needs_crypto
class KeyStoreTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.store = KeyStore(self.home, "abcdef123456", "Alice")

    def test_create_unlock_and_files(self):
        self.assertFalse(self.store.exists())
        identity, code, backup = self.store.create("my passphrase")
        self.assertTrue(self.store.exists())
        self.assertEqual(self.store.unlock("my passphrase").secret_bytes(), identity.secret_bytes())
        self.assertEqual(self.store.public_bundle(), identity.public())
        self.assertTrue(e2ee.valid_recovery_code(code))
        self.assertEqual(e2ee.open_backup(backup, code).secret_bytes(), identity.secret_bytes())

    def test_the_file_is_private_and_holds_no_plain_secrets(self):
        identity, _code, _backup = self.store.create("pw-pw-pw")
        mode = stat.S_IMODE(os.stat(self.store.key_path).st_mode)
        self.assertEqual(mode, 0o600)
        raw = self.store.key_path.read_text()
        self.assertNotIn(e2ee.b64(identity.secret_bytes()), raw)
        self.assertNotIn(identity.secret_bytes().hex(), raw)
        self.assertNotIn("pw-pw-pw", raw)

    def test_wrong_passphrase_and_damage(self):
        self.store.create("right")
        with self.assertRaises(WrongPassphrase):
            self.store.unlock("wrong")
        self.store.key_path.write_text("not json")
        with self.assertRaises(CryptoError):
            self.store.unlock("right")
        with self.assertRaises(CryptoError):
            self.store.public_bundle()

    def test_a_key_file_with_swapped_public_keys_is_refused(self):
        self.store.create("right")
        data = json.loads(self.store.key_path.read_text())
        data["bundle"] = Identity.generate().public().to_dict()
        self.store.key_path.write_text(json.dumps(data))
        with self.assertRaises(CryptoError):
            self.store.unlock("right")

    def test_restore_on_a_new_computer(self):
        identity, code, backup = self.store.create("old passphrase")
        other_home = tempfile.mkdtemp()
        fresh = KeyStore(other_home, "abcdef123456", "Alice")
        restored = fresh.restore(code, backup, "new passphrase")
        self.assertEqual(restored.secret_bytes(), identity.secret_bytes())
        self.assertEqual(fresh.unlock("new passphrase").public(), identity.public())
        with self.assertRaises(WrongPassphrase):
            fresh.unlock("old passphrase")

    def test_restore_needs_the_right_code(self):
        _identity, _code, backup = self.store.create("p")
        with self.assertRaises(WrongPassphrase):
            KeyStore(tempfile.mkdtemp(), "x", "Alice").restore(e2ee.new_recovery_code(), backup, "n")

    def test_rotation_keeps_the_old_identities_and_changes_the_current_one(self):
        first, _code, _backup = self.store.create("one two three")
        fresh, older, code, backup = self.store.rotate("one two three")
        self.assertNotEqual(fresh.public().fingerprint(), first.public().fingerprint())
        self.assertEqual([i.public().fingerprint() for i in older], [first.public().fingerprint()])
        unlocked = self.store.unlock_all("one two three")
        self.assertEqual([i.secret_bytes() for i in unlocked], [fresh.secret_bytes(), first.secret_bytes()])
        self.assertEqual(self.store.unlock("one two three").secret_bytes(), fresh.secret_bytes())
        self.assertEqual(self.store.public_bundle(), fresh.public())
        self.assertEqual(len(e2ee.open_backup_all(backup, code)), 2)
        with self.assertRaises(WrongPassphrase):
            self.store.rotate("wrong passphrase")
        self.assertEqual(len(self.store.unlock_all("one two three")), 2)  # a failed rotation changed nothing

    def test_rotating_many_times_keeps_a_bounded_history(self):
        self.store.create("pass phrase one")
        for _ in range(8):
            self.store.rotate("pass phrase one")
        self.assertLessEqual(len(self.store.unlock_all("pass phrase one")), 1 + keystore.MAX_PREVIOUS_IDENTITIES)

    def test_a_restore_brings_back_every_identity_and_the_passphrase_can_change(self):
        self.store.create("first pass")
        self.store.rotate("first pass")
        fresh, _older, code, backup = self.store.rotate("first pass")
        other = KeyStore(tempfile.mkdtemp(), "x", "Alice")
        other.restore(code, backup, "second pass")
        self.assertEqual(len(other.unlock_all("second pass")), 3)
        other.change_passphrase("second pass", "third pass")
        self.assertEqual(len(other.unlock_all("third pass")), 3)
        with self.assertRaises(WrongPassphrase):
            other.unlock_all("second pass")

    def test_the_key_file_with_old_identities_holds_no_plain_secrets(self):
        first, _c, _b = self.store.create("pass phrase")
        self.store.rotate("pass phrase")
        raw = self.store.key_path.read_text()
        self.assertNotIn(e2ee.b64(first.secret_bytes()), raw)
        self.assertNotIn("pass phrase", raw)

    def test_change_passphrase(self):
        identity, _c, _b = self.store.create("one")
        self.store.change_passphrase("one", "two")
        self.assertEqual(self.store.unlock("two").secret_bytes(), identity.secret_bytes())
        with self.assertRaises(WrongPassphrase):
            self.store.unlock("one")

    def test_keys_are_kept_apart_per_server_and_per_user(self):
        self.store.create("p")
        self.assertFalse(KeyStore(self.home, "someotherserver", "Alice").exists())
        self.assertFalse(KeyStore(self.home, "abcdef123456", "Bob").exists())
        self.assertTrue(KeyStore(self.home, "abcdef123456", "ALICE").exists())  # names are case-insensitive

    def test_reset_forgets_everything(self):
        self.store.create("p")
        self.store.pin_contact("Bob", Identity.generate().public())
        self.store.reset()
        self.assertFalse(self.store.exists())
        self.assertIsNone(self.store.contact("Bob"))

    def test_server_id(self):
        self.assertEqual(keystore.server_id("AA:BB:CC:01", "h", 1), "aabbcc01")
        self.assertEqual(keystore.server_id(None, "10.0.0.2", 5050), "plain-10.0.0.2-5050")
        self.assertNotIn("/", keystore.server_id(None, "a/b", 1))


@needs_crypto
class ContactPinTest(unittest.TestCase):
    def setUp(self):
        self.store = KeyStore(tempfile.mkdtemp(), "srv", "Alice")
        self.bob = Identity.generate().public()

    def test_first_sight_then_same(self):
        self.assertEqual(self.store.check_contact("Bob", self.bob), "new")
        self.store.pin_contact("Bob", self.bob)
        self.assertEqual(self.store.check_contact("bob", self.bob), "same")
        self.assertFalse(self.store.is_verified("Bob"))

    def test_a_different_key_is_reported_not_accepted(self):
        self.store.pin_contact("Bob", self.bob)
        replacement = Identity.generate().public()
        self.assertEqual(self.store.check_contact("Bob", replacement), "changed")
        self.assertEqual(self.store.contact("Bob")["fp"], self.bob.fingerprint())  # still the old pin

    def test_verification_survives_repinning_the_same_key_but_not_a_new_one(self):
        self.store.pin_contact("Bob", self.bob)
        self.assertTrue(self.store.mark_verified("Bob"))
        self.store.pin_contact("Bob", self.bob)
        self.assertTrue(self.store.is_verified("Bob"))
        self.store.pin_contact("Bob", Identity.generate().public())
        self.assertFalse(self.store.is_verified("Bob"))

    def test_old_keys_are_kept_so_earlier_messages_can_still_be_checked(self):
        second, third = Identity.generate().public(), Identity.generate().public()
        self.store.pin_contact("Bob", self.bob)
        self.store.pin_contact("Bob", second)
        self.store.pin_contact("Bob", third)
        self.assertEqual([b.fingerprint() for b in self.store.bundles_for("bob")],
                         [third.fingerprint(), second.fingerprint(), self.bob.fingerprint()])
        self.store.pin_contact("Bob", third)  # re-pinning the same key adds nothing
        self.assertEqual(len(self.store.bundles_for("Bob")), 3)
        for _ in range(8):
            self.store.pin_contact("Bob", Identity.generate().public())
        self.assertLessEqual(len(self.store.bundles_for("Bob")), 1 + keystore.MAX_PREVIOUS_KEYS)
        self.assertEqual(self.store.bundles_for("Nobody"), [])

    def test_unknown_contact_cannot_be_verified(self):
        self.assertFalse(self.store.mark_verified("Nobody"))
        self.assertFalse(self.store.is_verified("Nobody"))

    def test_the_pin_file_survives_a_restart_and_garbage_is_ignored(self):
        self.store.pin_contact("Bob", self.bob)
        again = KeyStore(self.store.folder.parent.parent, "srv", "Alice")
        self.assertEqual(again.check_contact("Bob", self.bob), "same")
        again.contacts_path.write_text("[[[")
        self.assertEqual(again.check_contact("Bob", self.bob), "new")


if __name__ == "__main__":
    unittest.main()
