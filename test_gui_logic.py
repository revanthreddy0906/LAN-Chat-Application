import unittest

from gui_logic import (
    AVATAR_COLORS,
    GroupKey,
    apply_mention,
    avatar_color,
    encryption_label,
    expire_typing,
    initials,
    is_at_bottom,
    mention_query,
    mentions_me,
    needs_older_messages,
    pin_bar_text,
    private_parties,
    seen_by_users,
    seen_label,
    server_subtitle,
    should_go_away,
    should_send_typing,
    starts_group,
    suggest_mentions,
    typing_label,
    unread_title,
    wrap_fingerprint,
    wrap_width,
)


class GuiLogicTest(unittest.TestCase):
    def test_initials(self):
        self.assertEqual(initials("Revanth"), "RE")
        self.assertEqual(initials("harish_goud"), "HG")
        self.assertEqual(initials("a"), "A")
        self.assertEqual(initials("   "), "?")

    def test_avatar_color_is_stable_and_case_insensitive(self):
        self.assertEqual(avatar_color("Potti"), avatar_color("potti"))
        self.assertIn(avatar_color("Potti"), AVATAR_COLORS)
        colors = {avatar_color(name) for name in ("a", "b", "c", "d", "e", "f", "g", "h")}
        self.assertGreater(len(colors), 2)

    def test_grouping(self):
        potti = GroupKey("Potti", False, "chat")
        self.assertTrue(starts_group(None, potti))
        self.assertFalse(starts_group(potti, GroupKey("Potti", False, "chat")))
        self.assertTrue(starts_group(potti, GroupKey("Revanth", False, "chat")))
        self.assertTrue(starts_group(potti, GroupKey("Potti", False, "private")))
        self.assertTrue(starts_group(potti, GroupKey("Potti", True, "chat")))

    def test_private_parties(self):
        self.assertEqual(private_parties("Potti (private)"), ("Potti", False))
        self.assertEqual(private_parties("You -> Potti (private)"), ("Potti", True))

    def test_unread_title(self):
        self.assertEqual(unread_title("LAN Chat", 0), "LAN Chat")
        self.assertEqual(unread_title("LAN Chat", 3), "(3) LAN Chat")

    def test_scroll_helpers(self):
        self.assertTrue(is_at_bottom(1.0))
        self.assertFalse(is_at_bottom(0.6))
        self.assertEqual(wrap_width(100), 180)
        self.assertEqual(wrap_width(1000), 640)

    def test_wrap_fingerprint(self):
        fingerprint = ":".join(f"{i:02X}" for i in range(32))
        lines = wrap_fingerprint(fingerprint).split("\n")
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(len(line.split(":")) == 8 for line in lines))
        self.assertEqual(":".join(lines), fingerprint)

    def test_labels(self):
        self.assertEqual(encryption_label(True), "Encrypted")
        self.assertEqual(encryption_label(False), "Not encrypted")
        self.assertEqual(server_subtitle("10.0.0.2", 5050, 3), "10.0.0.2:5050 · 3 online")


class RichMessageLogicTest(unittest.TestCase):
    def test_typing_label(self):
        self.assertEqual(typing_label([]), "")
        self.assertEqual(typing_label(["Bob"]), "Bob is typing\u2026")
        self.assertEqual(typing_label(["carol", "Bob"]), "Bob and carol are typing\u2026")
        self.assertEqual(typing_label(["a", "b", "c"]), "3 people are typing\u2026")

    def test_seen_label(self):
        self.assertEqual(seen_label([]), "")
        self.assertEqual(seen_label(["Bob"]), "Seen by Bob")
        self.assertEqual(seen_label(["Dan", "Bob", "Carol"]), "Seen by Bob, Carol, Dan")
        self.assertEqual(seen_label(["a", "b", "c", "d", "e"]), "Seen by a, b, c +2")

    def test_typing_entries_expire(self):
        typing = {"Bob": 100.0, "Carol": 104.0}
        self.assertEqual(expire_typing(typing, 106.0), ["Carol"])
        self.assertEqual(typing, {"Carol": 104.0})
        self.assertEqual(expire_typing(typing, 200.0), [])

    def test_typing_is_throttled_and_away_needs_idleness(self):
        self.assertFalse(should_send_typing(10.0, 11.0))
        self.assertTrue(should_send_typing(10.0, 13.0))
        self.assertFalse(should_go_away(100, False))
        self.assertTrue(should_go_away(300, False))
        self.assertFalse(should_go_away(900, True))

    def test_seen_by_users(self):
        marks = {"Ann": 9, "Bob": 5, "Carol": 7}
        self.assertEqual(sorted(seen_by_users(marks, 7, "ann")), ["Carol"])
        self.assertEqual(sorted(seen_by_users(marks, 5, "Zed")), ["Ann", "Bob", "Carol"])
        self.assertEqual(seen_by_users(marks, 10, "Zed"), [])


class MentionsPinsLogicTest(unittest.TestCase):
    def test_unread_title_marks_mentions(self):
        self.assertEqual(unread_title("LAN Chat", 3, mentioned=True), "(@3) LAN Chat")
        self.assertEqual(unread_title("LAN Chat", 0, mentioned=True), "LAN Chat")
        self.assertEqual(unread_title("LAN Chat", 2), "(2) LAN Chat")

    def test_mention_query_finds_the_word_being_typed(self):
        self.assertEqual(mention_query("hello @bo", 9), (6, "bo"))
        self.assertEqual(mention_query("@", 1), (0, ""))
        self.assertEqual(mention_query("hi @Bob and @ca", 15), (12, "ca"))
        self.assertEqual(mention_query("mail a@b.com", 12), None)   # an email is not a mention
        self.assertEqual(mention_query("hello @bob there", 16), None)  # cursor is past the word
        self.assertEqual(mention_query("hello @bob ", 11), None)
        self.assertEqual(mention_query("hello @bo", 6), None)  # cursor before the '@' is typed

    def test_suggestions_filter_by_prefix_skip_me_and_add_everyone_for_admins(self):
        names = ["Bob", "Carol", "bella", "Alice"]
        self.assertEqual(suggest_mentions("b", names, "Alice", False), ["Bob", "bella"])
        self.assertEqual(suggest_mentions("", names, "alice", False), ["Bob", "Carol", "bella"])
        self.assertEqual(suggest_mentions("e", names, "Alice", True), ["everyone"])
        self.assertEqual(suggest_mentions("e", names, "Alice", False), [])
        self.assertEqual(len(suggest_mentions("", [f"u{i}" for i in range(20)], "x", True)), 5)

    def test_apply_mention_replaces_only_the_partial_word(self):
        self.assertEqual(apply_mention("hello @bo", 6, 9, "Bob"), ("hello @Bob ", 11))
        self.assertEqual(apply_mention("hi @c there", 3, 5, "Carol"), ("hi @Carol there", 10))
        self.assertEqual(apply_mention("@", 0, 1, "Bob"), ("@Bob ", 5))

    def test_mentions_me(self):
        self.assertTrue(mentions_me({"mentions": ["Bob", "alice"]}, "Alice"))
        self.assertTrue(mentions_me({"mentions": [], "everyone": True}, "Zed"))
        self.assertFalse(mentions_me({"mentions": ["Bob"]}, "Alice"))
        self.assertFalse(mentions_me({}, "Alice"))

    def test_pin_bar_text_shows_the_newest_pin(self):
        pins = [{"sender": "Bob", "snippet": "the plan"}, {"sender": "Ann", "snippet": "older"}]
        self.assertEqual(pin_bar_text(pins), "\U0001F4CC Bob: the plan")
        self.assertEqual(pin_bar_text([]), "")

    def test_older_messages_are_only_fetched_when_needed(self):
        self.assertTrue(needs_older_messages(5, 40, True))
        self.assertFalse(needs_older_messages(50, 40, True))   # already loaded
        self.assertFalse(needs_older_messages(5, 40, False))   # nothing older exists
        self.assertTrue(needs_older_messages(5, None, True))


if __name__ == "__main__":
    unittest.main()
