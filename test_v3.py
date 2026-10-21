"""Milestone 3 over the wire: mentions, pins, search and history paging."""

import time
import unittest

from events import MAX_BODY_BYTES
from store import MAX_PAGE, MAX_PINS
from test_server import ServerTestCase
from test_v2 import V2Peer


class V3TestCase(ServerTestCase):
    def v2(self, name, password="secret"):
        peer = V2Peer(self.port, name, password)
        self.peers.append(peer)
        return peer

    @staticmethod
    def error_of(peer):
        return peer.until(lambda e: e["t"] == "notice" and e["kind"] == "error")["text"]


class MentionsTest(V3TestCase):
    def test_mentions_resolve_to_real_members_with_canonical_names(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        self.connect("Carol")
        message = alice.say("hey @bob and @CAROL, also @nobody and a@bob.com")
        self.assertEqual(message["mentions"], ["Bob", "Carol"])
        self.assertFalse(message["everyone"])
        seen = bob.until(lambda e: e["t"] == "message" and e["sender"] == "Alice")
        self.assertEqual(seen["mentions"], ["Bob", "Carol"])

    def test_trailing_punctuation_and_self_mentions(self):
        alice, _ = self.v2("Alice"), self.v2("Bob")
        message = alice.say("thanks @Bob. and @Bob, also @Alice!")
        self.assertEqual(message["mentions"], ["Bob"])  # one entry, and never yourself

    def test_everyone_is_for_admins_only(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")  # Alice is the admin
        shout = alice.say("meeting at 3 @everyone")
        self.assertTrue(shout["everyone"])
        bob.send(t="send", body="hey @everyone free pizza")
        self.assertIn("only admins", self.error_of(bob))
        self.assertEqual([e for e in alice.drain(0.4) if e["t"] == "message" and e["sender"] == "Bob"], [])

    def test_private_messages_do_not_create_mentions(self):
        alice, _ = self.v2("Alice"), self.v2("Bob")
        message = alice.say("psst @Bob", to="Bob")
        self.assertEqual((message["mentions"], message["everyone"]), ([], False))

    def test_mentions_survive_in_history(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        alice.say("remember @Bob")
        later = self.v2("Carol")
        self.assertEqual(later.history[0]["mentions"], ["Bob"])
        bob.close()

    def test_legacy_clients_just_see_the_text(self):
        alice = self.v2("Alice")
        legacy = self.connect("Bob")
        alice.until(lambda e: e["t"] == "notice" and "Bob joined" in e["text"])
        alice.say("ping @Bob")
        self.assertTrue(legacy.recv_until(lambda m: "ping @Bob" in m).endswith("Alice: ping @Bob"))


class PinsTest(V3TestCase):
    def test_pin_and_unpin_are_announced_and_listed(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message = alice.say("the wifi password is on the board")
        alice.send(t="pin", id=message["id"], on=True)
        for peer in (alice, bob):
            pins = peer.until(lambda e: e["t"] == "pins")
            self.assertEqual([(p["id"], p["sender"]) for p in pins["pins"]], [(message["id"], "Alice")])
            self.assertTrue(pins["pins"][0]["snippet"].startswith("the wifi password"))
        alice.send(t="pin", id=message["id"], on=False)
        self.assertEqual(bob.until(lambda e: e["t"] == "pins" and not e["pins"])["pins"], [])

    def test_new_joiners_get_the_current_pins_in_their_welcome_block(self):
        alice = self.v2("Alice")
        message = alice.say("pin me")
        alice.send(t="pin", id=message["id"])
        alice.until(lambda e: e["t"] == "pins")
        bob = self.v2("Bob")
        self.assertEqual([(p["id"], p["sender"]) for p in bob.pins], [(message["id"], "Alice")])
        self.assertEqual(self.v2("Carol").pins[0]["id"], message["id"])
        alice.send(t="pin", id=message["id"], on=False)
        alice.until(lambda e: e["t"] == "pins" and not e["pins"])
        self.assertEqual(self.v2("Dave").pins, [])

    def test_who_may_pin(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")
        bobs = bob.say("bob's idea")
        alices = alice.say("alice's note")
        carol.send(t="pin", id=bobs["id"])
        self.assertIn("cannot pin", self.error_of(carol))
        bob.send(t="pin", id=alices["id"])
        self.assertIn("cannot pin", self.error_of(bob))
        bob.send(t="pin", id=bobs["id"])  # your own
        self.assertEqual(len(bob.until(lambda e: e["t"] == "pins")["pins"]), 1)
        alice.send(t="pin", id=alices["id"])  # an admin may pin anything
        self.assertEqual(len(alice.until(lambda e: e["t"] == "pins" and len(e["pins"]) == 2)["pins"]), 2)

    def test_private_and_deleted_messages_cannot_be_pinned(self):
        alice, _ = self.v2("Alice"), self.v2("Bob")
        secret = alice.say("secret", to="Bob")
        alice.send(t="pin", id=secret["id"])
        self.assertIn("public", self.error_of(alice))
        gone = alice.say("oops")
        alice.send(t="delete", id=gone["id"])
        alice.until(lambda e: e["t"] == "deleted")
        alice.send(t="pin", id=gone["id"])
        self.assertIn("deleted", self.error_of(alice))
        alice.send(t="pin", id=99999)
        self.assertIn("does not exist", self.error_of(alice))

    def test_deleting_a_pinned_message_unpins_it_for_everyone(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        message = alice.say("temporary")
        alice.send(t="pin", id=message["id"])
        bob.until(lambda e: e["t"] == "pins" and e["pins"])
        alice.send(t="delete", id=message["id"])
        self.assertEqual(bob.until(lambda e: e["t"] == "pins" and not e["pins"])["pins"], [])

    def test_the_pin_limit(self):
        alice = self.v2("Alice")
        stored = self.server.store.get_user("Alice")
        ids = [self.server.store.add_message(stored.id, f"m{i}") for i in range(MAX_PINS + 1)]
        for message_id in ids[:MAX_PINS]:
            self.server.store.pin_message(message_id, stored.id)
        alice.send(t="pin", id=ids[-1])
        self.assertIn("too many pinned", self.error_of(alice))


class SearchTest(V3TestCase):
    def results_for(self, peer, query, req=1):
        peer.send(t="search", q=query, req=req)
        return peer.until(lambda e: e["t"] == "search_results" and e["req"] == req)

    def test_search_finds_old_messages_newest_first_with_snippets(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        alice.say("the quarterly report is due friday")
        bob.say("something else entirely")
        alice.say("Report: numbers look good " + "padding " * 30)
        found = self.results_for(bob, "report")
        self.assertEqual(found["q"], "report")
        self.assertEqual([r["sender"] for r in found["results"]], ["Alice", "Alice"])
        self.assertGreater(found["results"][0]["id"], found["results"][1]["id"])
        self.assertIn("Report", found["results"][0]["snippet"])

    def test_search_never_leaks_private_messages_or_deleted_text(self):
        alice, bob, carol = self.v2("Alice"), self.v2("Bob"), self.v2("Carol")
        alice.say("the launch codes are swordfish", to="Bob")
        public = alice.say("swordfish is also a fish")
        self.assertEqual(len(self.results_for(bob, "swordfish")["results"]), 2)
        self.assertEqual([r["id"] for r in self.results_for(carol, "swordfish", req=2)["results"]], [public["id"]])
        alice.send(t="delete", id=public["id"])
        alice.until(lambda e: e["t"] == "deleted")
        time.sleep(0.25)
        self.assertEqual(self.results_for(carol, "swordfish", req=3)["results"], [])

    def test_bad_queries_are_handled(self):
        alice = self.v2("Alice")
        alice.say("plain text")
        time.sleep(0.25)
        self.assertEqual(self.results_for(alice, '"; DROP TABLE messages; --', req=2)["results"], [])
        time.sleep(0.25)
        self.assertEqual(self.results_for(alice, "", req=3)["results"], [])
        time.sleep(0.25)
        alice.send(t="search", q="x" * 300, req=4)
        self.assertIn("not valid", self.error_of(alice))
        alice.send(t="search", q=123, req=5)
        self.assertIn("not valid", self.error_of(alice))
        self.assertEqual(alice.say("still working")["body"], "still working")

    def test_rapid_searches_are_throttled_to_the_latest(self):
        alice = self.v2("Alice")
        alice.say("alpha")
        for index in range(8):
            alice.send(t="search", q="alpha", req=index)
        replies = [e for e in alice.drain(0.8) if e["t"] == "search_results"]
        self.assertLess(len(replies), 8)
        self.assertGreaterEqual(len(replies), 1)

    def test_search_and_pins_commands_work_for_terminal_clients(self):
        alice = self.v2("Alice")
        legacy = self.connect("Bob")
        alice.until(lambda e: e["t"] == "notice" and "Bob joined" in e["text"])
        message = alice.say("meeting notes about budgets")
        alice.send(t="pin", id=message["id"])
        legacy.send("/search budgets")
        self.assertIn("Alice: meeting notes about budgets", legacy.recv_until(lambda m: m.startswith("Search results")))
        legacy.send("/search zzzz")
        self.assertIn("No messages found", legacy.recv_until(lambda m: "No messages" in m))
        legacy.send("/search")
        self.assertIn("Usage", legacy.recv_until(lambda m: "Usage" in m))
        legacy.send("/pins")
        self.assertIn("Alice: meeting notes about budgets", legacy.recv_until(lambda m: m.startswith("Pinned")))


class HistoryPagingTest(V3TestCase):
    def seed(self, count, sender="Alice"):
        user = self.server.store.get_user(sender)
        return [self.server.store.add_message(user.id, f"old message {i}") for i in range(count)]

    def page(self, peer, before, limit=MAX_PAGE):
        peer.send(t="history", before=before, limit=limit)
        start = peer.until(lambda e: e["t"] == "page_start")
        messages = []
        while True:
            event = peer.next()
            if event is None or event["t"] == "page_end":
                break
            messages.append(event)
        return start, messages

    def test_welcome_says_whether_there_is_more_history(self):
        self.v2("Alice")
        ids = self.seed(70)
        bob = self.v2("Bob")
        self.assertEqual(len(bob.history), 50)
        self.assertEqual(bob.history[0]["id"], ids[-50])
        self.assertEqual((bob.history_start["count"], bob.history_start["has_more"]), (50, True))

    def test_a_short_history_has_nothing_more_to_load(self):
        self.v2("Alice")
        self.seed(10)
        bob = self.v2("Bob")
        self.assertEqual((bob.history_start["count"], bob.history_start["has_more"]), (10, False))

    def test_pages_walk_back_to_the_beginning(self):
        self.v2("Alice")
        ids = self.seed(130)
        bob = self.v2("Bob")
        oldest = bob.history[0]["id"]
        collected = [e["id"] for e in bob.history]
        pages = 0
        while True:
            start, messages = self.page(bob, oldest)
            pages += 1
            self.assertEqual(start["count"], len(messages))
            self.assertTrue(all(m["history"] and m["page"] for m in messages))
            collected = [m["id"] for m in messages] + collected
            if not start["has_more"]:
                break
            oldest = messages[0]["id"]
        self.assertEqual(collected, ids)  # no gaps, no overlap, right order
        self.assertEqual(pages, 2)

    def test_pages_hide_other_peoples_private_messages(self):
        alice, bob = self.v2("Alice"), self.v2("Bob")
        carol = self.v2("Carol")
        self.seed(5)
        alice.say("only for bob", to="Bob")
        newest = self.server.store.latest_message_id() + 1
        for peer, expected in ((bob, True), (carol, False)):
            _, messages = self.page(peer, newest)
            self.assertEqual(any(m["body"] == "only for bob" for m in messages), expected)

    def test_bad_history_requests_get_errors(self):
        alice = self.v2("Alice")
        for bad in ({"before": 0}, {"before": "x"}, {"before": -4}, {"before": 5, "limit": "many"}, {}):
            alice.send(t="history", **bad)
            self.assertIn("not valid", self.error_of(alice))

    def test_page_size_is_capped(self):
        alice = self.v2("Alice")
        self.seed(80)
        _, messages = self.page(alice, self.server.store.latest_message_id() + 1, limit=10_000)
        self.assertEqual(len(messages), MAX_PAGE)

    def test_a_full_page_does_not_overflow_the_outbox(self):
        alice = self.v2("Alice")
        for index in range(60):
            self.server.store.add_message(self.server.store.get_user("Alice").id, "z" * 3000 + str(index))
        start, messages = self.page(alice, self.server.store.latest_message_id() + 1)
        self.assertEqual(len(messages), MAX_PAGE)
        self.assertEqual(alice.say("still connected")["body"], "still connected")
        self.assertLessEqual(MAX_BODY_BYTES, 3400)


if __name__ == "__main__":
    unittest.main()
