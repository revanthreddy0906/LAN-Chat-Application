import socket
import unittest

from protocol import MAX_MESSAGE_BYTES, receive_message, send_message


class ProtocolTest(unittest.TestCase):
    def test_length_prefixed_protocol_round_trip(self) -> None:
        """The framing handles a complete message over a stream socket."""
        left, right = socket.socketpair()
        try:
            send_message(left, "hello")
            self.assertEqual(receive_message(right), "hello")
        finally:
            left.close()
            right.close()

    def test_receive_returns_none_on_closed_connection(self) -> None:
        left, right = socket.socketpair()
        try:
            left.close()
            self.assertIsNone(receive_message(right))
        finally:
            right.close()

    def test_send_rejects_oversized_message(self) -> None:
        left, right = socket.socketpair()
        try:
            with self.assertRaises(ValueError):
                send_message(left, "x" * (MAX_MESSAGE_BYTES + 1))
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
