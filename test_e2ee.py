"""The end-to-end encryption building blocks: known answers, round trips, and everything that must fail."""

import unittest

import e2ee
from e2ee import Bundle, CryptoError, Identity, WrongPassphrase

e2ee.SCRYPT_N = 2**10  # fast for tests; the real value is 2**15

needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")


@needs_crypto
class KnownAnswerTest(unittest.TestCase):
    def test_key_derivation_matches_the_published_vectors(self):
        # RFC 7748 section 6.1 (X25519) and RFC 8032 section 7.1 test 1 (Ed25519)
        dh_secret = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        sign_secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        identity = Identity.from_secret(dh_secret + sign_secret)
        bundle = identity.public()
        self.assertEqual(bundle.dh.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(bundle.sign.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(identity.secret_bytes(), dh_secret + sign_secret)

    def test_diffie_hellman_agrees_with_rfc_7748(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        alice = X25519PrivateKey.from_private_bytes(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        bob_public = X25519PublicKey.from_public_bytes(bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        self.assertEqual(alice.exchange(bob_public).hex(), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


@needs_crypto
class BundleTest(unittest.TestCase):
    def test_bundle_round_trip_and_signature(self):
        bundle = Identity.generate().public()
        again = Bundle.from_dict(bundle.to_dict())
        self.assertEqual(again, bundle)
        self.assertTrue(again.verify())

    def test_a_swapped_key_breaks_the_signature(self):
        mine, other = Identity.generate().public(), Identity.generate().public()
        forged = Bundle(other.dh, mine.sign, mine.sig)
        self.assertFalse(forged.verify())
        forged = Bundle(mine.dh, other.sign, mine.sig)
        self.assertFalse(forged.verify())

    def test_malformed_bundles_are_refused(self):
        good = Identity.generate().public().to_dict()
        for broken in ({}, {"dh": "!!", "sign": good["sign"], "sig": good["sig"]},
                       {"dh": good["dh"][:10], "sign": good["sign"], "sig": good["sig"]}, None):
            with self.assertRaises(CryptoError):
                Bundle.from_dict(broken)

    def test_fingerprint_is_stable_and_distinct(self):
        a, b = Identity.generate().public(), Identity.generate().public()
        self.assertEqual(a.fingerprint(), a.fingerprint())
        self.assertNotEqual(a.fingerprint(), b.fingerprint())


@needs_crypto
class WrappingTest(unittest.TestCase):
    def test_round_trip(self):
        secret = Identity.generate().secret_bytes()
        blob = e2ee.wrap(secret, "correct horse")
        self.assertEqual(e2ee.unwrap(blob, "correct horse"), secret)
        self.assertNotIn(secret.hex(), str(blob))

    def test_wrong_passphrase_and_tampering(self):
        blob = e2ee.wrap(b"x" * 64, "right")
        with self.assertRaises(WrongPassphrase):
            e2ee.unwrap(blob, "wrong")
        flipped = dict(blob, ct=e2ee.b64(bytes([e2ee.unb64(blob["ct"])[0] ^ 1]) + e2ee.unb64(blob["ct"])[1:]))
        with self.assertRaises(WrongPassphrase):
            e2ee.unwrap(flipped, "right")

    def test_each_wrap_uses_fresh_salt_and_nonce(self):
        one, two = e2ee.wrap(b"y" * 64, "p"), e2ee.wrap(b"y" * 64, "p")
        self.assertNotEqual((one["salt"], one["nonce"], one["ct"]), (two["salt"], two["nonce"], two["ct"]))

    def test_a_key_file_cannot_ask_for_absurd_cost(self):
        blob = dict(e2ee.wrap(b"z" * 64, "p"), n=2**30)
        with self.assertRaises(CryptoError):
            e2ee.unwrap(blob, "p")

    def test_damaged_files(self):
        for broken in ({}, {"n": 1}, {"n": "x", "r": 8, "p": 1, "salt": "", "nonce": "", "ct": ""}):
            with self.assertRaises(CryptoError):
                e2ee.unwrap(broken, "p")

    def test_the_purpose_is_bound_in(self):
        blob = e2ee.wrap(b"w" * 64, "p", aad=b"one purpose")
        with self.assertRaises(WrongPassphrase):
            e2ee.unwrap(blob, "p", aad=b"another purpose")


@needs_crypto
class RecoveryTest(unittest.TestCase):
    def test_code_shape_and_entropy(self):
        code = e2ee.new_recovery_code()
        self.assertEqual(len(code), 29)
        self.assertEqual(code.count("-"), 5)
        self.assertTrue(e2ee.valid_recovery_code(code))
        self.assertNotEqual(code, e2ee.new_recovery_code())
        self.assertTrue(set(e2ee.normalize_recovery_code(code)) <= set(e2ee.RECOVERY_ALPHABET))

    def test_typing_it_loosely_still_works(self):
        code = e2ee.new_recovery_code()
        self.assertEqual(e2ee.normalize_recovery_code(code.lower().replace("-", " ")), e2ee.normalize_recovery_code(code))
        self.assertFalse(e2ee.valid_recovery_code("ABCD-EFGH"))

    def test_backup_restores_the_same_identity(self):
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        backup = e2ee.make_backup(identity, code)
        restored = e2ee.open_backup(backup, code.lower())
        self.assertEqual(restored.secret_bytes(), identity.secret_bytes())

    def test_wrong_code_and_swapped_bundle(self):
        identity, code = Identity.generate(), e2ee.new_recovery_code()
        backup = e2ee.make_backup(identity, code)
        with self.assertRaises(WrongPassphrase):
            e2ee.open_backup(backup, e2ee.new_recovery_code())
        with self.assertRaises(WrongPassphrase):
            e2ee.open_backup(backup, "short")
        forged = dict(backup, bundle=Identity.generate().public().to_dict())
        with self.assertRaises(CryptoError):
            e2ee.open_backup(forged, code)
        with self.assertRaises(CryptoError):
            e2ee.open_backup({}, code)


@needs_crypto
class SafetyNumberTest(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = Identity.generate().public(), Identity.generate().public()

    def test_both_sides_see_the_same_number(self):
        a = e2ee.safety_number("Alice", self.alice, "Bob", self.bob)
        b = e2ee.safety_number("bob", self.bob, "ALICE", self.alice)
        self.assertEqual(a, b)
        self.assertEqual(len(a.split()), 12)
        self.assertTrue(all(len(group) == 5 and group.isdigit() for group in a.split()))

    def test_a_substituted_key_changes_it(self):
        honest = e2ee.safety_number("Alice", self.alice, "Bob", self.bob)
        mallory = Identity.generate().public()
        self.assertNotEqual(honest, e2ee.safety_number("Alice", self.alice, "Bob", mallory))
        self.assertNotEqual(honest, e2ee.safety_number("Alice", self.alice, "Carol", self.bob))


@needs_crypto
class SealedMessageTest(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob, self.carol = Identity.generate(), Identity.generate(), Identity.generate()
        self.aad = e2ee.aad_for("text", "Alice", "Bob")

    def seal(self, text=b"meet at noon"):
        return e2ee.seal(text, self.alice, self.bob.public().dh, self.aad)

    def test_round_trip(self):
        envelope = self.seal()
        self.assertEqual(e2ee.open_sealed(envelope, self.bob, self.alice.public(), self.aad), b"meet at noon")

    def test_the_ciphertext_hides_the_text_and_differs_each_time(self):
        one, two = self.seal(), self.seal()
        self.assertNotIn(b"meet", e2ee.unb64(one["ct"]))
        self.assertNotEqual(one["ct"], two["ct"])
        self.assertNotEqual(one["epk"], two["epk"])

    def test_only_the_recipient_can_open_it(self):
        with self.assertRaises(CryptoError):
            e2ee.open_sealed(self.seal(), self.carol, self.alice.public(), self.aad)

    def test_the_sender_cannot_reopen_it_without_the_recipients_key(self):
        with self.assertRaises(CryptoError):
            e2ee.open_sealed(self.seal(), self.alice, self.alice.public(), self.aad)

    def test_tampering_is_detected(self):
        envelope = self.seal()
        ct = e2ee.unb64(envelope["ct"])
        for field, value in (("ct", e2ee.b64(bytes([ct[0] ^ 1]) + ct[1:])), ("n", e2ee.b64(bytes(12))),
                             ("epk", e2ee.b64(bytes(32))), ("sig", e2ee.b64(bytes(64))), ("v", 2)):
            with self.assertRaises(CryptoError, msg=field):
                e2ee.open_sealed(dict(envelope, **{field: value}), self.bob, self.alice.public(), self.aad)
        with self.assertRaises(CryptoError):
            e2ee.open_sealed({"v": 1}, self.bob, self.alice.public(), self.aad)

    def test_the_context_is_bound_so_messages_cannot_be_moved(self):
        envelope = self.seal()
        for other in (e2ee.aad_for("text", "Alice", "Carol"), e2ee.aad_for("text", "Carol", "Bob"),
                      e2ee.aad_for("file", "Alice", "Bob")):
            with self.assertRaises(CryptoError):
                e2ee.open_sealed(envelope, self.bob, self.alice.public(), other)

    def test_a_message_claiming_the_wrong_sender_is_refused(self):
        envelope = self.seal()
        with self.assertRaises(CryptoError):
            e2ee.open_sealed(envelope, self.bob, self.carol.public(), self.aad)

    def test_the_recipient_cannot_forge_a_message_from_the_sender(self):
        # Bob can compute the same shared secret, but he cannot produce Alice's signature.
        forged = e2ee.seal(b"I owe Bob 100", self.bob, self.bob.public().dh, self.aad)
        with self.assertRaises(CryptoError):
            e2ee.open_sealed(forged, self.bob, self.alice.public(), self.aad)

    def test_bad_recipient_keys_are_refused(self):
        with self.assertRaises(CryptoError):
            e2ee.seal(b"x", self.alice, b"short", self.aad)

    def test_empty_and_large_payloads(self):
        for payload in (b"", b"x" * 100_000):
            envelope = e2ee.seal(payload, self.alice, self.bob.public().dh, self.aad)
            self.assertEqual(e2ee.open_sealed(envelope, self.bob, self.alice.public(), self.aad), payload)


@needs_crypto
class MessageEncryptionTest(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob, self.carol = Identity.generate(), Identity.generate(), Identity.generate()

    def encrypt(self, text="meet at noon", sender="Alice", to="Bob"):
        recipients = {to: {"Bob": self.bob, "Carol": self.carol}[to].public()}
        return e2ee.encrypt_message(e2ee.encode_payload(text), self.alice, sender, recipients)

    def open(self, envelope, me, name, sender="Alice", sender_bundle=None):
        data = e2ee.decrypt_message(envelope, me, name, sender, sender_bundle or self.alice.public())
        return e2ee.decode_payload(data)["b"]

    def test_both_the_recipient_and_the_sender_can_read_it(self):
        envelope = self.encrypt()
        self.assertEqual(self.open(envelope, self.bob, "Bob"), "meet at noon")
        self.assertEqual(self.open(envelope, self.alice, "alice"), "meet at noon")
        self.assertEqual(e2ee.envelope_people(envelope), ["alice", "bob"])

    def test_nobody_else_can(self):
        envelope = self.encrypt()
        with self.assertRaises(CryptoError):
            self.open(envelope, self.carol, "Carol")
        with self.assertRaises(CryptoError):  # even with the right name, the wrong key cannot open the sealed key
            self.open(envelope, self.carol, "Bob")

    def test_the_text_is_not_visible_and_each_message_is_different(self):
        one, two = self.encrypt(), self.encrypt()
        self.assertNotIn(b"meet", e2ee.unb64(one["ct"]))
        self.assertNotEqual((one["n"], one["ct"]), (two["n"], two["ct"]))

    def test_tampering_is_detected_everywhere(self):
        envelope = self.encrypt()
        ct = e2ee.unb64(envelope["ct"])
        damaged = [dict(envelope, ct=e2ee.b64(bytes([ct[0] ^ 1]) + ct[1:])), dict(envelope, n=e2ee.b64(bytes(12))),
                   dict(envelope, sig=e2ee.b64(bytes(64))), dict(envelope, v=1)]
        for bad in damaged:
            with self.assertRaises(CryptoError):
                self.open(bad, self.bob, "Bob")

    def test_changing_who_the_message_is_for_breaks_it(self):
        envelope = self.encrypt()
        extra = dict(envelope, k={**envelope["k"], "carol": envelope["k"]["bob"]})
        with self.assertRaises(CryptoError):
            self.open(extra, self.bob, "Bob")
        renamed = dict(envelope, k={"eve": envelope["k"]["bob"], "alice": envelope["k"]["alice"]})
        with self.assertRaises(CryptoError):
            self.open(renamed, self.bob, "Eve")

    def test_a_message_cannot_be_passed_off_as_from_someone_else(self):
        envelope = self.encrypt()
        with self.assertRaises(CryptoError):
            self.open(envelope, self.bob, "Bob", sender="Carol", sender_bundle=self.carol.public())
        with self.assertRaises(CryptoError):
            self.open(envelope, self.bob, "Bob", sender="Alice", sender_bundle=self.carol.public())

    def test_the_recipient_cannot_forge_a_message_from_the_sender(self):
        forged = e2ee.encrypt_message(e2ee.encode_payload("I owe Bob 100"), self.bob, "Alice",
                                      {"Bob": self.bob.public()})
        with self.assertRaises(CryptoError):
            self.open(forged, self.bob, "Bob")  # signed by Bob's key, not Alice's

    def test_malformed_envelopes(self):
        for broken in ({}, {"v": 2}, {"v": 2, "k": {}}, {"v": 2, "k": {"bob": 5}, "n": "", "ct": "", "sig": ""},
                       {"v": 2, "k": {"bob": {}}, "n": 5, "ct": "", "sig": ""}, None, []):
            with self.assertRaises(CryptoError):
                self.open(broken, self.bob, "Bob")

    def test_payload_round_trip_and_ids(self):
        one, two = e2ee.decode_payload(e2ee.encode_payload("hi \u00e9\u4e2d")), e2ee.decode_payload(e2ee.encode_payload("hi"))
        self.assertEqual(one["b"], "hi \u00e9\u4e2d")
        self.assertNotEqual(one["mid"], two["mid"])
        for bad in (b"not json", b"[1]", b'{"b": 5, "mid": "x"}', b"\xff\xfe"):
            with self.assertRaises(CryptoError):
                e2ee.decode_payload(bad)

    def test_the_largest_allowed_message_fits_in_the_size_budget(self):
        names = ("A" * 32, "B" * 32)
        text = "\u00e9" * (e2ee.MAX_TEXT_BYTES // 2)
        envelope = e2ee.encrypt_message(e2ee.encode_payload(text), self.alice, names[0], {names[1]: self.bob.public()})
        self.assertLessEqual(e2ee.envelope_size(envelope), e2ee.MAX_ENVELOPE_CHARS)
        self.assertEqual(e2ee.decode_payload(e2ee.decrypt_message(envelope, self.bob, names[1], names[0],
                                                                 self.alice.public()))["b"], text)

    def test_more_than_two_people_costs_only_a_key_each(self):
        solo = self.encrypt()
        group = e2ee.encrypt_message(e2ee.encode_payload("meet at noon"), self.alice, "Alice",
                                     {"Bob": self.bob.public(), "Carol": self.carol.public()})
        self.assertEqual(self.open(group, self.carol, "Carol"), "meet at noon")
        self.assertLess(e2ee.envelope_size(group) - e2ee.envelope_size(solo), 450)


class WithoutThePackageTest(unittest.TestCase):
    def test_require_explains_what_to_install(self):
        if e2ee.AVAILABLE:
            self.skipTest("the package is installed")
        with self.assertRaises(CryptoError) as raised:
            e2ee.require()
        self.assertIn("pip install cryptography", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
