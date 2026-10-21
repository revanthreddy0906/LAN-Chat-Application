import unittest

from events import (
    MAX_BODY_BYTES,
    decode,
    encode,
    fit_frame,
    legacy_text,
    member_pages,
    message_event,
    pins_event,
    reactions_event,
    search_event,
    snippet,
    snippet_around,
)
from protocol import MAX_MESSAGE_BYTES
from store import StoredMessage


def stored(**overrides):
    base = dict(id=7, sender="Alice", recipient=None, kind="text", body="hello", created_at=0.0,
                sender_id=1)
    base.update(overrides)
    return StoredMessage(**base)


class EventsTest(unittest.TestCase):
    def test_round_trip_and_rejection_of_non_events(self):
        event = {"t": "typing", "user": "Bob", "on": True}
        self.assertEqual(decode(encode(event)), event)
        for junk in ("hello", "[1, 2]", '{"no_type": 1}', '{"t": 5}', ""):
            self.assertIsNone(decode(junk))

    def test_snippet(self):
        self.assertEqual(snippet("  several\n  lines   of text "), "several lines of text")
        long = snippet("word " * 100, 20)
        self.assertEqual(len(long), 20)
        self.assertTrue(long.endswith("…"))

    def test_message_event_fields(self):
        message = stored(reply_to=3, edited_at=5.0)
        parent = stored(id=3, sender="Bob", body="the original question")
        event = message_event(message, parent, [("\U0001F44D", ["Bob"])], history=True)
        self.assertEqual(event["id"], 7)
        self.assertEqual(event["reply"], {"id": 3, "sender": "Bob", "snippet": "the original question", "deleted": False})
        self.assertTrue(event["edited"] and event["history"] and not event["deleted"])
        self.assertEqual(event["reactions"], [{"emoji": "\U0001F44D", "users": ["Bob"]}])

    def test_reply_to_a_deleted_or_missing_parent_has_no_text(self):
        gone = message_event(stored(reply_to=3), stored(id=3, sender="Bob", body="", deleted_at=1.0))
        self.assertEqual((gone["reply"]["snippet"], gone["reply"]["deleted"]), ("", True))
        missing = message_event(stored(reply_to=3), None)
        self.assertTrue(missing["reply"]["deleted"])

    def test_oversized_text_is_trimmed_to_fit_one_frame(self):
        event = message_event(stored(body="x" * 6000))
        text = fit_frame(event)
        self.assertLessEqual(len(text.encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertTrue(decode(text)["body"].endswith("…"))
        short = fit_frame(message_event(stored(body="fine")))
        self.assertEqual(decode(short)["body"], "fine")

    def test_body_limit_leaves_room_for_the_envelope(self):
        event = message_event(stored(body="é" * (MAX_BODY_BYTES // 2)),
                              stored(id=3, sender="B" * 32, body="q" * 500))
        self.assertLessEqual(len(fit_frame(event).encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertEqual(decode(fit_frame(event))["body"], "é" * (MAX_BODY_BYTES // 2))

    def test_legacy_public_message(self):
        event = message_event(stored(sender="Alice", body="hi all"))
        self.assertTrue(legacy_text(event, "Bob").endswith("] Alice: hi all"))
        self.assertIsNone(legacy_text(event, "alice"))  # the sender already sees their own line

    def test_legacy_history_includes_your_own_public_messages(self):
        event = message_event(stored(sender="Alice", body="from before"), history=True)
        self.assertTrue(legacy_text(event, "alice").endswith("] Alice: from before"))

    def test_legacy_private_message_for_each_side(self):
        event = message_event(stored(sender="Alice", recipient="Bob", body="psst"))
        self.assertTrue(legacy_text(event, "Bob").endswith("] Alice (private): psst"))
        self.assertTrue(legacy_text(event, "Alice").endswith("] You -> Bob (private): psst"))

    def test_legacy_reply_names_who_is_being_answered(self):
        event = message_event(stored(reply_to=3), stored(id=3, sender="Bob", body="q"))
        self.assertIn("Alice (replying to Bob):", legacy_text(event, "Carol"))

    def test_legacy_notice_and_silent_events(self):
        self.assertEqual(legacy_text({"t": "notice", "kind": "join", "text": "Bob joined the chat."}, "x"),
                         "Bob joined the chat.")
        deleted = message_event(stored(body="", deleted_at=1.0))
        self.assertIsNone(legacy_text(deleted, "Bob"))
        for kind in ("typing", "presence", "members", "edited", "deleted", "reactions", "read"):
            self.assertIsNone(legacy_text({"t": kind}, "Bob"))

    def test_member_pages_split_and_always_produce_a_page(self):
        members = [(f"user{i}", "member", "online") for i in range(95)]
        pages = member_pages(members)
        self.assertEqual([p["page"] for p in pages], [0, 1, 2])
        self.assertTrue(all(p["pages"] == 3 for p in pages))
        self.assertEqual(sum(len(p["members"]) for p in pages), 95)
        for page in pages:
            self.assertLessEqual(len(encode(page).encode()), MAX_MESSAGE_BYTES)
        self.assertEqual(member_pages([]), [{"t": "members", "page": 0, "pages": 1, "members": []}])

    def test_reactions_event(self):
        self.assertEqual(reactions_event(4, [("\U0001F389", ["A", "B"])]),
                         {"t": "reactions", "id": 4, "reactions": [{"emoji": "\U0001F389", "users": ["A", "B"]}]})


class SearchPinsEventsTest(unittest.TestCase):
    def test_snippet_is_centred_on_the_first_match(self):
        body = "word " * 40 + "the NEEDLE is here " + "tail " * 40
        piece = snippet_around(body, ["needle"], width=60)
        self.assertIn("NEEDLE", piece)
        self.assertLessEqual(len(piece), 62)
        self.assertTrue(piece.startswith("\u2026") and piece.endswith("\u2026"))

    def test_short_text_and_missing_terms(self):
        self.assertEqual(snippet_around("short  text", ["text"]), "short text")
        long = "abc " * 100
        self.assertTrue(snippet_around(long, ["zzz"], width=40).startswith("abc"))
        self.assertLessEqual(len(snippet_around(long, [], width=40)), 42)

    def test_match_near_the_end_keeps_a_full_window(self):
        body = "x " * 100 + "finale"
        piece = snippet_around(body, ["finale"], width=50)
        self.assertTrue(piece.endswith("finale"))
        self.assertGreaterEqual(len(piece), 40)

    def test_pins_event_carries_short_summaries(self):
        pinned = [stored(id=3, sender="Bob", body="x " * 200), stored(id=2, sender="Alice", body="hi")]
        event = pins_event(pinned)
        self.assertEqual([p["id"] for p in event["pins"]], [3, 2])
        self.assertLessEqual(len(event["pins"][0]["snippet"]), 80)
        self.assertEqual(pins_event([]), {"t": "pins", "pins": []})

    def test_search_event_shape(self):
        event = search_event(7, "lunch", [{"id": 1}])
        self.assertEqual((event["t"], event["req"], event["q"], event["results"]), ("search_results", 7, "lunch", [{"id": 1}]))

    def test_message_event_carries_mentions(self):
        event = message_event(stored(mention_all=True), mentions=["Bob"])
        self.assertEqual((event["mentions"], event["everyone"]), (["Bob"], True))
        plain = message_event(stored())
        self.assertEqual((plain["mentions"], plain["everyone"]), ([], False))


if __name__ == "__main__":
    unittest.main()
