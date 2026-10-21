"""The group room's key chains: who can read what, and what must fail."""

import unittest

import e2ee
from e2ee import CryptoError, Identity, NoKey
from e2ee_group import RoomKeys

e2ee.SCRYPT_N = 2**10
needs_crypto = unittest.skipUnless(e2ee.AVAILABLE, "the cryptography package is not installed")


class Member:
    def __init__(self, name):
        self.name = name
        self.identity = Identity.generate()
        self.keys = RoomKeys(self.identity, name)

    def bundle(self):
        return self.identity.public()

    def give(self, other, epoch, number):
        """Hand `other` my chain as of `number` (what the window does through the server)."""
        envelope = self.keys.key_envelope(other.name, other.bundle(), epoch, number)
        return other.keys.accept_envelope(self.name, [self.bundle()], envelope)

    def say(self, text, epoch, number):
        return self.keys.encrypt(e2ee.encode_payload(text), epoch, number)

    def hear(self, envelope, sender):
        return e2ee.decode_payload(self.keys.decrypt(envelope, sender.name, [sender.bundle()]))["b"]


@needs_crypto
class ChainTest(unittest.TestCase):
    def test_the_chain_is_one_way_and_deterministic(self):
        start = b"k" * 32
        three = e2ee.chain_advance(start, 3)
        self.assertEqual(three, e2ee.chain_next(e2ee.chain_next(e2ee.chain_next(start))))
        self.assertEqual(e2ee.chain_advance(three, 2), e2ee.chain_advance(start, 5))
        self.assertNotEqual(e2ee.chain_message_key(start), e2ee.chain_message_key(three))
        self.assertEqual(e2ee.chain_advance(start, 0), start)

    def test_limits(self):
        for steps in (-1, e2ee.MAX_CHAIN_STEPS + 1):
            with self.assertRaises(CryptoError):
                e2ee.chain_advance(b"k" * 32, steps)


@needs_crypto
class RoomTest(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob, self.carol = Member("Alice"), Member("Bob"), Member("Carol")

    def test_round_trip_between_members(self):
        self.alice.give(self.bob, 1, 0)
        message = self.alice.say("hello room", 1, 0)
        self.assertEqual(self.bob.hear(message, self.alice), "hello room")
        self.assertEqual(self.alice.hear(message, self.alice), "hello room")  # my own message, from my own chain

    def test_later_messages_follow_the_chain(self):
        self.alice.give(self.bob, 1, 0)
        for number in (0, 1, 2, 7, 500):
            self.assertEqual(self.bob.hear(self.alice.say(f"m{number}", 1, number), self.alice), f"m{number}")

    def test_a_late_joiner_reads_from_their_start_but_not_before(self):
        before = self.alice.say("before carol", 1, 3)
        self.alice.give(self.carol, 1, 5)  # carol is given the chain as it stands at message 5
        after = self.alice.say("after carol", 1, 6)
        self.assertEqual(self.carol.hear(after, self.alice), "after carol")
        with self.assertRaises(NoKey):
            self.carol.hear(before, self.alice)
        exact = self.alice.say("at the join", 1, 5)
        self.assertEqual(self.carol.hear(exact, self.alice), "at the join")

    def test_someone_never_given_a_chain_cannot_read(self):
        self.alice.give(self.bob, 1, 0)
        with self.assertRaises(NoKey):
            self.carol.hear(self.alice.say("secret", 1, 0), self.alice)

    def test_a_new_epoch_needs_a_new_chain(self):
        self.alice.give(self.bob, 1, 0)
        self.alice.give(self.carol, 1, 0)
        self.alice.give(self.bob, 2, 0)  # carol was removed: she is not given epoch 2
        second = self.alice.say("epoch two", 2, 0)
        self.assertEqual(self.bob.hear(second, self.alice), "epoch two")
        with self.assertRaises(NoKey):
            self.carol.hear(second, self.alice)
        self.assertEqual(self.carol.hear(self.alice.say("still epoch one", 1, 1), self.alice), "still epoch one")

    def test_my_own_history_survives_a_restart_through_my_own_envelope(self):
        message = self.alice.say("remember me", 1, 4)
        envelope = self.alice.keys.own_envelope(1)
        restarted = RoomKeys(self.alice.identity, "Alice")
        restarted.accept_envelope("Alice", [self.alice.bundle()], envelope)
        self.assertEqual(e2ee.decode_payload(restarted.decrypt(message, "Alice", [self.alice.bundle()]))["b"], "remember me")

    def test_tampering_and_forgery(self):
        self.alice.give(self.bob, 1, 0)
        message = self.alice.say("real", 1, 0)
        ct = e2ee.unb64(message["ct"])
        for field, value in (("ct", e2ee.b64(bytes([ct[0] ^ 1]) + ct[1:])), ("nn", e2ee.b64(bytes(12))),
                             ("sig", e2ee.b64(bytes(64))), ("n", 1), ("e", 2)):
            with self.assertRaises(CryptoError, msg=field):
                self.bob.hear(dict(message, **{field: value}), self.alice)
        with self.assertRaises(CryptoError):  # claimed to be from Carol
            self.bob.keys.decrypt(message, "Carol", [self.carol.bundle()])
        forged = self.carol.say("I am alice", 1, 0)
        self.bob.keys.chains[("alice", 1)] = {0: self.carol.keys.key_at("Carol", 1, 0)}  # even with the right key...
        with self.assertRaises(CryptoError):  # ...the signature is Carol's, not Alice's
            self.bob.hear(forged, self.alice)

    def test_key_envelopes_are_bound_to_who_they_are_for(self):
        envelope = self.alice.keys.key_envelope("Bob", self.bob.bundle(), 1, 0)
        with self.assertRaises(CryptoError):
            self.carol.keys.accept_envelope("Alice", [self.alice.bundle()], envelope)
        with self.assertRaises(CryptoError):  # a different epoch label breaks the context
            self.bob.keys.accept_envelope("Alice", [self.alice.bundle()], dict(envelope, e=2))
        with self.assertRaises(CryptoError):
            self.bob.keys.accept_envelope("Carol", [self.carol.bundle()], envelope)
        for broken in ({}, {"e": "1"}, {"e": 1}, None):
            with self.assertRaises(CryptoError):
                self.bob.keys.accept_envelope("Alice", [self.alice.bundle()], broken)

    def test_an_old_key_of_the_sender_still_opens_old_envelopes(self):
        newer = Identity.generate().public()
        envelope = self.alice.keys.key_envelope("Bob", self.bob.bundle(), 1, 0)
        self.bob.keys.accept_envelope("Alice", [newer, self.alice.bundle()], envelope)
        self.assertEqual(self.bob.hear(self.alice.say("x", 1, 0), self.alice), "x")

    def test_replay_detection(self):
        keys = self.bob.keys
        self.assertTrue(keys.first_use("Alice", 1, 5, 100))
        self.assertTrue(keys.first_use("alice", 1, 5, 100))  # the same message again is fine
        self.assertFalse(keys.first_use("Alice", 1, 5, 101))  # a different message with the same number is not

    def test_envelope_shape_checks(self):
        message = self.alice.say("x", 1, 0)
        self.assertEqual(e2ee.group_envelope_fields(message), (1, 0))
        for broken in ({}, {"v": 2}, dict(message, e="1"), dict(message, n=-1), dict(message, ct=5), None):
            with self.assertRaises(CryptoError):
                e2ee.group_envelope_fields(broken)

    def test_size_of_a_group_message_and_a_key_envelope(self):
        message = self.alice.say("x" * e2ee.MAX_TEXT_BYTES, 1, 0)
        self.assertLess(e2ee.envelope_size(message), 2400)
        self.assertLess(e2ee.envelope_size(self.alice.keys.key_envelope("Bob", self.bob.bundle(), 1, 0)), 450)


if __name__ == "__main__":
    unittest.main()
