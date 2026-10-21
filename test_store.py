import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from accounts import AccountStore
from permissions import ROLES, can, is_valid_role
from store import (
    MAX_DISTINCT_REACTIONS,
    MAX_PAGE,
    MAX_PINS,
    MIGRATIONS,
    SCHEMA_V1,
    SCHEMA_V2,
    Store,
)


class StoreCase(unittest.TestCase):
    """Gives each test a fresh database."""

    use_fts = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = Path(self.tmp) / "chat.db"
        self.store = Store(self.path, use_fts=self.use_fts)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add(self, name, role=None):
        return self.store.create_user(name, "aa", "bb", role=role)


class StoreTest(StoreCase):

    def test_schema_is_created_and_migration_is_idempotent(self):
        self.assertEqual(self.store.schema_version(), len(MIGRATIONS))
        self.store.close()
        again = Store(self.path)
        self.assertEqual(again.schema_version(), len(MIGRATIONS))
        again.close()
        self.store = Store(self.path)

    def test_first_user_is_admin_then_members(self):
        self.assertEqual(self.add("Alice").role, "admin")
        self.assertEqual(self.add("Bob").role, "member")
        self.assertEqual(self.add("Gus", role="guest").role, "guest")

    def test_usernames_are_unique_and_case_insensitive(self):
        self.add("Alice")
        with self.assertRaises(ValueError):
            self.add("alice")
        self.assertEqual(self.store.get_user("ALICE").username, "Alice")

    def test_roles_validate_and_last_admin_is_protected(self):
        self.add("Alice")
        self.add("Bob")
        with self.assertRaises(ValueError):
            self.store.set_role("Bob", "superuser")
        with self.assertRaises(ValueError):
            self.store.set_role("Alice", "member")  # the only admin
        self.assertTrue(self.store.set_role("Bob", "admin"))
        self.assertTrue(self.store.set_role("Alice", "member"))  # now there is another admin
        self.assertFalse(self.store.set_role("Nobody", "guest"))

    def test_disable_and_last_seen(self):
        user = self.add("Alice")
        self.assertFalse(user.disabled)
        self.assertTrue(self.store.set_disabled("Alice", True))
        self.assertTrue(self.store.get_user("alice").disabled)
        self.store.touch_last_seen(user.id, 123.0)
        self.assertEqual(self.store.get_user("Alice").last_seen, 123.0)

    def test_history_is_chronological_limited_and_persistent(self):
        alice, bob = self.add("Alice"), self.add("Bob")
        for i in range(10):
            self.store.add_message(alice.id if i % 2 == 0 else bob.id, f"m{i}", created_at=1000 + i)
        history = self.store.history_for(alice.id, limit=4)
        self.assertEqual([m.body for m in history], ["m6", "m7", "m8", "m9"])
        self.assertEqual(history[0].sender, "Alice")
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(len(self.store.history_for(alice.id, limit=50)), 10)

    def test_private_messages_are_only_visible_to_the_two_people(self):
        alice, bob, carol = self.add("Alice"), self.add("Bob"), self.add("Carol")
        self.store.add_message(alice.id, "public", created_at=1)
        self.store.add_message(alice.id, "secret for bob", recipient_id=bob.id, created_at=2)
        self.assertEqual([m.body for m in self.store.history_for(alice.id)], ["public", "secret for bob"])
        self.assertEqual([m.body for m in self.store.history_for(bob.id)], ["public", "secret for bob"])
        self.assertEqual([m.body for m in self.store.history_for(carol.id)], ["public"])
        private = self.store.history_for(bob.id)[1]
        self.assertEqual((private.sender, private.recipient), ("Alice", "Bob"))

    def test_settings(self):
        self.assertIsNone(self.store.get_setting("open_registration"))
        self.assertEqual(self.store.get_setting("open_registration", "1"), "1")
        self.store.set_setting("open_registration", "0")
        self.store.set_setting("open_registration", "1")
        self.assertEqual(self.store.get_setting("open_registration"), "1")


class RichMessageStoreTest(StoreCase):
    """Replies, edits, deletes, reactions and read markers (schema v2)."""

    def pair(self):
        return self.add("Alice"), self.add("Bob")

    def test_v1_database_upgrades_in_place_and_keeps_its_data(self):
        old_path = Path(self.tmp) / "old.db"
        db = sqlite3.connect(old_path)
        db.executescript(SCHEMA_V1)
        db.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        db.execute("INSERT INTO schema_version VALUES (1)")
        db.execute("INSERT INTO users (username, salt, hash, role, created_at) VALUES ('Ann','aa','bb','admin',1)")
        db.execute("INSERT INTO messages (sender_id, body, created_at) VALUES (1, 'written long ago', 5)")
        db.commit()
        db.close()
        upgraded = Store(old_path)
        try:
            self.assertEqual(upgraded.schema_version(), len(MIGRATIONS))
            message = upgraded.get_message(1)
            self.assertEqual((message.body, message.reply_to, message.edited_at, message.deleted_at),
                             ("written long ago", None, None, None))
            self.assertEqual(upgraded.history_for(1)[0].sender, "Ann")
            self.assertEqual(upgraded.latest_message_id(), 1)
        finally:
            upgraded.close()

    def test_reply_edit_and_get_message(self):
        alice, bob = self.pair()
        first = self.store.add_message(alice.id, "lunch?")
        second = self.store.add_message(bob.id, "yes!", reply_to=first)
        reply = self.store.get_message(second)
        self.assertEqual((reply.reply_to, reply.sender, reply.sender_id), (first, "Bob", bob.id))
        self.assertTrue(self.store.edit_message(first, alice.id, "lunch at 1?", when=50.0))
        edited = self.store.get_message(first)
        self.assertEqual((edited.body, edited.edited_at), ("lunch at 1?", 50.0))
        self.assertIsNone(self.store.get_message(999))

    def test_only_the_author_can_edit_and_deleted_messages_cannot_be_edited(self):
        alice, bob = self.pair()
        message = self.store.add_message(alice.id, "mine")
        self.assertFalse(self.store.edit_message(message, bob.id, "hacked"))
        self.assertEqual(self.store.get_message(message).body, "mine")
        self.assertTrue(self.store.delete_message(message))
        self.assertFalse(self.store.edit_message(message, alice.id, "zombie"))
        self.assertFalse(self.store.delete_message(message))  # already gone

    def test_delete_leaves_a_tombstone_in_history_and_erases_the_text_and_reactions(self):
        alice, bob = self.pair()
        message = self.store.add_message(alice.id, "regret", created_at=1)
        self.store.toggle_reaction(message, bob.id, "👍")
        self.store.add_message(bob.id, "after", created_at=2)
        self.assertTrue(self.store.delete_message(message, when=9.0))
        history = self.store.history_for(bob.id)
        self.assertEqual([(m.body, m.deleted_at) for m in history], [("", 9.0), ("after", None)])
        self.assertEqual(self.store.reactions_for([message]), {})

    def test_reactions_toggle_group_by_emoji_and_keep_order(self):
        alice, bob = self.pair()
        message = self.store.add_message(alice.id, "party")
        self.assertTrue(self.store.toggle_reaction(message, alice.id, "🎉", when=1))
        self.assertTrue(self.store.toggle_reaction(message, bob.id, "👍", when=2))
        self.assertTrue(self.store.toggle_reaction(message, bob.id, "🎉", when=3))
        self.assertEqual(self.store.reactions_for([message])[message],
                         [("🎉", ["Alice", "Bob"]), ("👍", ["Bob"])])
        self.assertFalse(self.store.toggle_reaction(message, bob.id, "🎉"))  # second click removes it
        self.assertEqual(self.store.reactions_for([message])[message],
                         [("🎉", ["Alice"]), ("👍", ["Bob"])])
        self.assertEqual(self.store.reactions_for([]), {})

    def test_reaction_variety_is_capped(self):
        alice, bob = self.pair()
        message = self.store.add_message(alice.id, "spam target")
        for index in range(MAX_DISTINCT_REACTIONS):
            self.store.toggle_reaction(message, alice.id, f"e{index}")
        with self.assertRaises(ValueError):
            self.store.toggle_reaction(message, alice.id, "one-too-many")
        self.assertTrue(self.store.toggle_reaction(message, bob.id, "e0"))  # existing emoji is fine

    def test_read_markers_only_move_forward(self):
        alice, bob = self.pair()
        self.assertEqual(self.store.get_last_read(alice.id), 0)
        self.assertTrue(self.store.set_last_read(alice.id, 5))
        self.assertFalse(self.store.set_last_read(alice.id, 3))
        self.assertFalse(self.store.set_last_read(alice.id, 5))
        self.assertTrue(self.store.set_last_read(alice.id, 8))
        self.store.set_last_read(bob.id, 2)
        self.assertEqual(self.store.read_markers(), {"Alice": 8, "Bob": 2})


class SearchChecks:
    """Shared by the full-text and the LIKE-fallback runs, so both must agree."""

    def people(self):
        return self.add("Alice"), self.add("Bob"), self.add("Carol")

    def ids(self, user, query, **kwargs):
        return [m.id for m in self.store.search(user.id, query, **kwargs)]

    def test_finds_words_case_insensitively_newest_first(self):
        alice, bob, _ = self.people()
        first = self.store.add_message(alice.id, "Lunch at the Italian place?")
        self.store.add_message(bob.id, "unrelated")
        second = self.store.add_message(bob.id, "italian is great, LUNCH it is")
        self.assertEqual(self.ids(alice, "lunch"), [second, first])
        self.assertEqual(self.ids(alice, "ITALIAN lunch"), [second, first])
        self.assertEqual(self.ids(alice, "lunch pizza"), [])  # every word must match

    def test_the_last_word_may_be_a_prefix(self):
        alice, _, _ = self.people()
        message = self.store.add_message(alice.id, "the meeting starts at noon")
        self.assertEqual(self.ids(alice, "meet"), [message])
        self.assertEqual(self.ids(alice, "starts me"), [message])

    def test_limit_is_respected(self):
        alice, _, _ = self.people()
        for index in range(10):
            self.store.add_message(alice.id, f"needle number {index}")
        self.assertEqual(len(self.ids(alice, "needle", limit=3)), 3)
        self.assertEqual(len(self.ids(alice, "needle", limit=1000)), 10)

    def test_private_messages_are_searchable_only_by_the_two_people(self):
        alice, bob, carol = self.people()
        self.store.add_message(alice.id, "the secret plan", recipient_id=bob.id)
        self.assertEqual(len(self.ids(alice, "secret")), 1)
        self.assertEqual(len(self.ids(bob, "secret")), 1)
        self.assertEqual(self.ids(carol, "secret"), [])

    def test_deleted_messages_disappear_from_search(self):
        alice, _, _ = self.people()
        message = self.store.add_message(alice.id, "regrettable words")
        self.assertEqual(self.ids(alice, "regrettable"), [message])
        self.store.delete_message(message)
        self.assertEqual(self.ids(alice, "regrettable"), [])

    def test_edits_update_the_index(self):
        alice, _, _ = self.people()
        message = self.store.add_message(alice.id, "original wording")
        self.store.edit_message(message, alice.id, "revised phrasing")
        self.assertEqual(self.ids(alice, "original"), [])
        self.assertEqual(self.ids(alice, "revised"), [message])

    def test_hostile_or_odd_queries_never_raise(self):
        alice, _, _ = self.people()
        self.store.add_message(alice.id, "100% sure it's a snake_case thing")
        for query in ('"', "'; DROP TABLE messages; --", "*", "NEAR(", "a OR b", "AND", "(", ")", "^", "",
                      "   ", "\U0001F600", "x" * 5000, "%", "_", "\\", "col:umn", "-flag", "snake_case"):
            self.store.search(alice.id, query)
        self.assertEqual(len(self.ids(alice, "snake_case")), 1)
        self.assertEqual(len(self.ids(alice, "100")), 1)
        self.assertEqual(self.ids(alice, "%"), [])  # punctuation alone is not a search

    def test_unicode_words(self):
        alice, _, _ = self.people()
        message = self.store.add_message(alice.id, "Caf\u00e9 \u0928\u092e\u0938\u094d\u0924\u0947 meeting")
        self.assertEqual(self.ids(alice, "caf\u00e9"), [message])


class SearchFullTextTest(SearchChecks, StoreCase):
    def test_full_text_index_is_in_use_and_backfills_old_messages(self):
        self.assertTrue(self.store.has_fts)
        alice = self.add("Alice")
        self.store.close()
        plain = Store(self.path, use_fts=False)  # a database that never had the index
        plain._db.execute("DROP TRIGGER IF EXISTS messages_fts_insert")
        plain._db.execute("DROP TRIGGER IF EXISTS messages_fts_update")
        plain._db.execute("DROP TRIGGER IF EXISTS messages_fts_delete")
        plain._db.execute("DROP TABLE IF EXISTS messages_fts")
        plain.add_message(alice.id, "written before the index existed")
        plain.close()
        self.store = Store(self.path)
        self.assertTrue(self.store.has_fts)
        self.assertEqual(len(self.store.search(alice.id, "before index")), 1)


class SearchFallbackTest(SearchChecks, StoreCase):
    use_fts = False

    def test_runs_without_the_index(self):
        self.assertFalse(self.store.has_fts)


class PinsMentionsPagingTest(StoreCase):
    def test_v2_database_upgrades_to_v3_keeping_its_data(self):
        old_path = Path(self.tmp) / "v2.db"
        db = sqlite3.connect(old_path)
        db.executescript(SCHEMA_V1)
        db.executescript(SCHEMA_V2)
        db.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        db.execute("INSERT INTO schema_version VALUES (2)")
        db.execute("INSERT INTO users (username, salt, hash, role, created_at) VALUES ('Ann','aa','bb','admin',1)")
        db.execute("INSERT INTO messages (sender_id, body, created_at) VALUES (1, 'from the v2 days', 5)")
        db.commit()
        db.close()
        upgraded = Store(old_path)
        try:
            self.assertEqual(upgraded.schema_version(), len(MIGRATIONS))
            self.assertEqual(upgraded.get_message(1).mention_all, False)
            self.assertEqual(len(upgraded.search(1, "days")), 1)  # old messages are indexed too
            self.assertTrue(upgraded.pin_message(1, 1))
        finally:
            upgraded.close()

    def test_pin_unpin_and_ordering(self):
        alice = self.add("Alice")
        first, second = (self.store.add_message(alice.id, f"m{i}") for i in range(2))
        self.assertTrue(self.store.pin_message(first, alice.id))
        self.assertFalse(self.store.pin_message(first, alice.id))  # already pinned
        self.assertTrue(self.store.pin_message(second, alice.id))
        self.assertTrue(self.store.is_pinned(first))
        self.assertEqual([m.id for m in self.store.pinned()], [second, first])  # newest pin first
        self.assertTrue(self.store.unpin_message(first))
        self.assertFalse(self.store.unpin_message(first))
        self.assertEqual([m.id for m in self.store.pinned()], [second])

    def test_pin_limit_and_delete_unpins(self):
        alice = self.add("Alice")
        ids = [self.store.add_message(alice.id, f"m{i}") for i in range(MAX_PINS + 1)]
        for message_id in ids[:MAX_PINS]:
            self.store.pin_message(message_id, alice.id)
        with self.assertRaises(ValueError):
            self.store.pin_message(ids[-1], alice.id)
        self.store.delete_message(ids[0])
        self.assertFalse(self.store.is_pinned(ids[0]))
        self.assertTrue(self.store.pin_message(ids[-1], alice.id))  # room again

    def test_mentions_are_stored_and_listed_by_name(self):
        alice, bob, carol = self.add("Alice"), self.add("Bob"), self.add("Carol")
        message = self.store.add_message(alice.id, "hi @Bob and @Carol", mentions=[carol.id, bob.id, bob.id])
        plain = self.store.add_message(alice.id, "nobody mentioned")
        everyone = self.store.add_message(alice.id, "@everyone", mention_all=True)
        self.assertEqual(self.store.mentions_for([message, plain, everyone]), {message: ["Bob", "Carol"]})
        self.assertTrue(self.store.get_message(everyone).mention_all)
        self.assertFalse(self.store.get_message(message).mention_all)

    def test_history_pages_walk_backwards_without_gaps_or_overlap(self):
        alice = self.add("Alice")
        ids = [self.store.add_message(alice.id, f"m{i}") for i in range(25)]
        page = self.store.history_before(alice.id, ids[-1] + 1, limit=10)
        self.assertEqual([m.id for m in page], ids[15:])
        self.assertTrue(self.store.has_older(alice.id, page[0].id))
        older = self.store.history_before(alice.id, page[0].id, limit=10)
        self.assertEqual([m.id for m in older], ids[5:15])
        oldest = self.store.history_before(alice.id, older[0].id, limit=10)
        self.assertEqual([m.id for m in oldest], ids[:5])
        self.assertFalse(self.store.has_older(alice.id, oldest[0].id))
        self.assertEqual(self.store.history_before(alice.id, oldest[0].id), [])

    def test_page_size_is_capped_and_private_messages_stay_private(self):
        alice, bob, carol = self.add("Alice"), self.add("Bob"), self.add("Carol")
        for index in range(MAX_PAGE + 20):
            self.store.add_message(alice.id, f"m{index}")
        secret = self.store.add_message(alice.id, "just for bob", recipient_id=bob.id)
        top = secret + 1
        self.assertEqual(len(self.store.history_before(alice.id, top, limit=10_000)), MAX_PAGE)
        self.assertIn(secret, [m.id for m in self.store.history_before(bob.id, top)])
        self.assertNotIn(secret, [m.id for m in self.store.history_before(carol.id, top)])
        self.assertFalse(self.store.has_older(carol.id, 1))


class AccountStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_then_login_and_wrong_password(self):
        accounts = AccountStore(Path(self.tmp) / "accounts.json")
        status, user = accounts.authenticate("Alice", "pw")
        self.assertEqual((status, user.role), ("registered", "admin"))
        self.assertEqual(accounts.authenticate("alice", "pw")[0], "ok")
        self.assertEqual(accounts.authenticate("Alice", "nope")[0], "bad_password")
        self.assertEqual(accounts.authenticate("Bob", "pw")[1].role, "member")
        self.assertEqual(accounts.verify_or_register("ALICE", "pw"), ("ok", "Alice"))

    def test_password_is_hashed_in_the_database(self):
        accounts = AccountStore(Path(self.tmp) / "accounts.json")
        accounts.authenticate("Alice", "correct horse battery staple")
        raw = Path(self.tmp, "accounts.db").read_bytes()
        self.assertNotIn(b"correct horse", raw)
        row = sqlite3.connect(Path(self.tmp, "accounts.db")).execute("SELECT salt, hash FROM users").fetchone()
        self.assertEqual((len(row[0]), len(row[1])), (32, 64))

    def test_old_json_accounts_are_imported_once_and_backed_up(self):
        legacy = Path(self.tmp) / "accounts.json"
        first = AccountStore(Path(self.tmp) / "x" / "accounts.json")
        first.authenticate("Revanth", "pw1")
        first.authenticate("Potti", "pw2")
        users = {u.username.lower(): {"name": u.username, "salt": u.salt, "hash": u.hash}
                 for u in first.store.list_users()}
        legacy.write_text(json.dumps({"users": users}))
        migrated = AccountStore(legacy)
        self.assertFalse(legacy.exists())
        self.assertTrue(Path(self.tmp, "accounts.json.bak").exists())
        self.assertEqual(migrated.authenticate("revanth", "pw1")[0], "ok")
        self.assertEqual(migrated.authenticate("Potti", "pw2")[0], "ok")
        self.assertEqual([u.role for u in migrated.store.list_users()], ["admin", "member"])
        # opening again must not import twice or fail
        again = AccountStore(legacy)
        self.assertEqual(again.store.user_count(), 2)


class PermissionsTest(unittest.TestCase):
    def test_matrix(self):
        self.assertTrue(all(is_valid_role(r) for r in ROLES))
        self.assertFalse(is_valid_role("root"))
        self.assertTrue(can("admin", "manage_users"))
        self.assertFalse(can("member", "manage_users"))
        self.assertTrue(can("member", "send_private"))
        self.assertFalse(can("guest", "send_private"))
        self.assertTrue(can("guest", "react"))
        self.assertFalse(can("guest", "upload"))
        self.assertFalse(can("nonsense", "send_message"))


if __name__ == "__main__":
    unittest.main()
