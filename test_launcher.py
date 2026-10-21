import unittest

import chat
from chat_core import parse_address
from client import pick_server
from discovery import FoundServer


class ParseAddressTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(parse_address("192.168.1.5"), ("192.168.1.5", None))
        self.assertEqual(parse_address("192.168.1.5:5051"), ("192.168.1.5", 5051))
        self.assertEqual(parse_address("  mac.local  ", 5050), ("mac.local", 5050))
        self.assertEqual(parse_address("host:notaport"), ("host:notaport", None))
        self.assertEqual(parse_address(""), ("", None))


def scripted(*answers):
    queue = list(answers)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return queue.pop(0)

    return ask, prompts


A = FoundServer("192.168.1.9", 5050, "Revanth-Mac", True, 2)
B = FoundServer("192.168.1.20", 5051, "Lab-PC", False, 0)


class PickServerTest(unittest.TestCase):
    def pick(self, servers, *answers):
        ask, prompts = scripted(*answers)
        output = []
        result = pick_server(find=lambda: servers, ask=ask, say=output.append)
        return result, prompts, output

    def test_nothing_found_asks_for_address(self):
        result, prompts, output = self.pick([], "10.0.0.7:5055")
        self.assertEqual(result, ("10.0.0.7", 5055))
        self.assertIn("No chats found", " ".join(output))

    def test_single_server_default_yes(self):
        result, prompts, _ = self.pick([A], "")
        self.assertEqual(result, ("192.168.1.9", 5050))
        self.assertIn("Revanth-Mac", prompts[0])

    def test_single_server_declined_falls_back_to_manual(self):
        result, _, _ = self.pick([A], "n", "10.0.0.7")
        self.assertEqual(result, ("10.0.0.7", None))

    def test_menu_by_number_and_bad_input_retries(self):
        result, _, output = self.pick([A, B], "9", "2")
        self.assertEqual(result, ("192.168.1.20", 5051))
        self.assertIn("NOT encrypted", " ".join(output))

    def test_menu_accepts_typed_address(self):
        result, _, _ = self.pick([A, B], "172.16.0.4:6000")
        self.assertEqual(result, ("172.16.0.4", 6000))


class LauncherArgumentsTest(unittest.TestCase):
    def parse(self, *argv):
        return chat.build_parser().parse_args(list(argv))

    def test_no_command_means_gui(self):
        self.assertIsNone(self.parse().command)

    def test_host_arguments_are_forwarded(self):
        args = self.parse("host", "--port", "5055", "--name", "Demo", "--no-tls")
        self.assertEqual(chat.host_arguments(args), ["--port", "5055", "--name", "Demo", "--no-tls"])
        self.assertEqual(chat.host_arguments(self.parse("host")), [])

    def test_join_arguments_are_forwarded(self):
        args = self.parse("join", "10.0.0.2:5050", "--username", "Potti", "--password", "pw")
        self.assertEqual(
            chat.join_arguments(args),
            ["10.0.0.2:5050", "--username", "Potti", "--password", "pw"],
        )
        self.assertEqual(chat.join_arguments(self.parse("join")), [])


if __name__ == "__main__":
    unittest.main()
