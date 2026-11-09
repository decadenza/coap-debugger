import socket
import struct
import tempfile
import threading
import time
import tkinter as tk
import unittest
import aiocoap
from pathlib import Path
from unittest.mock import patch

from aiocoap_backend import DebugTuning
from coap_debugger import (
    App, Cancelled, Message, Option, OPTIONS, Settings, exchange, parse_bytes,
    payload_view, resource_options, summarize, validate_options,
)


class WireTests(unittest.TestCase):
    def test_proseccoap_get_known_wire(self):
        request = Message(0, 1, 0x1234, b"\xaa\xbb",
                          [Option(11, b"my-endpoint")])
        raw = bytes.fromhex("42 01 12 34 aa bb bb") + b"my-endpoint"
        self.assertEqual(request.encode(), raw)
        self.assertEqual(Message.decode(raw), request)

    def test_proseccoap_content_known_wire(self):
        raw = bytes.fromhex("62 45 12 34 aa bb c0 ff 34 32")
        message = Message.decode(raw)
        self.assertEqual(message, Message(2, 69, 0x1234, b"\xaa\xbb",
                                         [Option(12, b"")], b"42"))
        self.assertEqual(message.encode(), raw)
        self.assertIn("0 (text/plain", summarize(message, raw))

    def test_uint_zero_is_present_but_empty(self):
        self.assertEqual(parse_bytes("0", "UInt"), b"")
        self.assertEqual(Message(0, 1, 1, options=[Option(12, b"")]).encode(),
                         bytes.fromhex("40 01 00 01 c0"))
        self.assertEqual(Message(0, 1, 1).encode(), bytes.fromhex("40 01 00 01"))

    def test_option_extensions_and_repeated_order(self):
        options = [Option(300, b"x" * 300), Option(11, b"first"),
                   Option(11, b"second"), Option(40, b"x" * 13),
                   Option(65535, b"last")]
        raw = Message(1, 2, 65535, b"12345678", options, b"\x00\xff").encode()
        decoded = Message.decode(raw)
        self.assertEqual(decoded.options, sorted(options, key=lambda opt: opt.number))
        self.assertEqual(decoded.encode(), raw)
        self.assertEqual(decoded.payload, b"\x00\xff")

    def test_all_rfc7252_options_are_present(self):
        base = {1, 3, 4, 5, 7, 8, 11, 12, 14, 15, 17, 20, 35, 39, 60}
        self.assertTrue(base.issubset(OPTIONS))

    def test_binary_and_hex_equal_ascii(self):
        self.assertEqual(parse_bytes("42", "ASCII"), b"42")
        self.assertEqual(parse_bytes("34\n32", "HEX"), b"42")
        self.assertEqual(parse_bytes("00110100 00110010", "Binary"), b"42")
        self.assertEqual(parse_bytes("41 00 FF", "HEX"), b"A\x00\xff")
        self.assertEqual(parse_bytes(r"\n", "ASCII"), b"\\n")
        self.assertEqual(parse_bytes("", "Binary"), b"")

    def test_invalid_payloads(self):
        for text, mode in (("a", "HEX"), ("0x01", "HEX"), ("gg", "HEX"),
                           ("101", "Binary"), ("00000002", "Binary"),
                           ("\u00e9", "ASCII"), ("-1", "UInt"), ("4294967296", "UInt"),
                           ("x", "Empty")):
            with self.subTest(text=text, mode=mode), self.assertRaises(ValueError):
                parse_bytes(text, mode)

    def test_uint_boundaries(self):
        for value in (0, 1, 255, 256, 65535, 16777215, 4294967295):
            self.assertEqual(int.from_bytes(parse_bytes(str(value), "UInt"), "big"), value)
        self.assertEqual(parse_bytes("0x100", "UInt"), b"\x01\x00")

    def test_option_validation(self):
        invalid = [
            [Option(0, b"")], [Option(65536, b"")], [Option(3, b"")],
            [Option(4, b"x" * 9)], [Option(5, b"x")], [Option(12, b"\x00")],
            [Option(12, b"\x01"), Option(12, b"\x02")],
            [Option(11, b"\xff")], [Option(23, b"\x07")],
            [Option(27, b"\x17")], [Option(16, b"\x00")],
            [Option(35, b"coap://test"), Option(11, b"x")],
        ]
        for options in invalid:
            with self.subTest(options=options), self.assertRaises(ValueError):
                validate_options(options)
        validate_options([Option(1, b""), Option(1, b"one"), Option(292, b"")])

    def test_bad_wire(self):
        invalid = [
            b"", b"\x40\x01\x00", bytes.fromhex("80 01 00 00"),
            bytes.fromhex("49 01 00 00"), bytes.fromhex("42 01 00 00 aa"),
            bytes.fromhex("40 00 00 00 ff 00"), bytes.fromhex("40 01 00 00 ff"),
            bytes.fromhex("40 01 00 00 f1 00"), bytes.fromhex("40 01 00 00 1f"),
            bytes.fromhex("40 01 00 00 d0"), bytes.fromhex("40 01 00 00 e0 00"),
            bytes.fromhex("40 01 00 00 b3 41"), bytes.fromhex("40 01 00 00 00"),
            bytes.fromhex("40 01 00 00 e0 ff ff"),  # Option number > 65535.
        ]
        for raw in invalid:
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                Message.decode(raw)

    def test_header_limits_and_empty(self):
        invalid = [Message(4, 1, 0), Message(0, 256, 0), Message(0, 1, -1),
                   Message(0, 1, 65536), Message(0, 1, 0, b"123456789"),
                   Message(0, 0, 0, b"x"), Message(0, 0, 0, payload=b"x"),
                   Message(0, 0, 0, options=[Option(11, b"x")])]
        for msg in invalid:
            with self.subTest(msg=msg), self.assertRaises(ValueError):
                msg.encode()
        self.assertEqual(Message(3, 0, 10).encode(), bytes.fromhex("70 00 00 0a"))

    def test_payload_marker_and_datagram_limit(self):
        self.assertEqual(Message(0, 1, 0, payload=b"\xff").encode(),
                         bytes.fromhex("40 01 00 00 ff ff"))
        Message(0, 2, 0, payload=b"x" * 65502).encode()
        with self.assertRaises(ValueError):
            Message(0, 2, 0, payload=b"x" * 65503).encode()

    def test_opaque_option_ending_in_ff_is_not_payload_marker(self):
        raw = bytes.fromhex("60 45 00 01 41 ff")
        self.assertEqual(Message.decode(raw).options, [Option(4, b"\xff")])
        self.assertEqual(Message.decode(raw).encode(), raw)

    def test_aiocoap_native_option_codec_roundtrip(self):
        values = [Option(1, b"\x00\xff"), Option(5, b""), Option(6, b""),
                  Option(11, b"my-endpoint"), Option(12, b"\x32"),
                  Option(23, b"\x26"), Option(292, b"tag"), Option(65000, b"\xff")]
        message = Message(0, 2, 65535, b"12345678", values, b'{"v":42}')
        native = message.to_aiocoap()
        self.assertIsInstance(native, aiocoap.Message)
        self.assertEqual(native.opt.uri_path, ("my-endpoint",))
        self.assertEqual(native.opt.content_format, 50)
        self.assertEqual(native.opt.block2.block_number, 2)
        self.assertEqual(native.opt.block2.size_exponent, 6)
        self.assertEqual(Message.from_aiocoap(aiocoap.Message.decode(native.encode())), message)

    def test_resource_segments_and_query(self):
        options = resource_options("/a//b/?x=1&y=%2F&z=a+b", [Option(17, b"\x32")])
        self.assertEqual(options, [Option(17, b"\x32"), Option(11, b"a"),
                                   Option(11, b""), Option(11, b"b"), Option(11, b""),
                                   Option(15, b"x=1"), Option(15, b"y=/"),
                                   Option(15, b"z=a+b")])
        self.assertEqual(resource_options("/", options), [Option(17, b"\x32")])
        self.assertEqual(resource_options("/a%2fb", []), [Option(11, b"a/b")])
        self.assertEqual(resource_options("/\u00e9", []), [Option(11, b"\xc3\xa9")])
        self.assertEqual(resource_options("/?", []), [Option(15, b"")])

    def test_invalid_resources(self):
        for resource in ("/bad%", "/bad%g0", "coap://host/x", "/a#frag", "/%ff"):
            with self.subTest(resource=resource), self.assertRaises(ValueError):
                resource_options(resource, [])

    def test_payload_views_preserve_binary(self):
        data = b"A\x00\xff\n"
        self.assertEqual(payload_view(data, "ASCII"), "A\\x00\\xff\n")
        self.assertEqual(payload_view(data, "HEX"), "41 00 ff 0a")
        self.assertEqual(parse_bytes(payload_view(data, "Binary"), "Binary"), data)
        self.assertEqual(payload_view(b"\xc3\xa9\xff", "UTF-8"), "\u00e9\\xff")

    def test_unknown_response_option_is_displayed(self):
        message = Message(2, 132, 42, options=[Option(65000, b"\xaa")])
        text = summarize(message, message.encode())
        self.assertIn("4.04 Not Found", text)
        self.assertIn("65000 Unknown: aa", text)


class SettingsTests(unittest.TestCase):
    def test_defaults(self):
        settings = Settings()
        settings.validate()
        self.assertEqual(settings.message_limit, 128)
        self.assertEqual(settings.max_retransmit, 4)
        # Full wait includes the timeout after the final retransmission.
        self.assertEqual(sum(2 ** i for i in range(settings.max_retransmit + 1)), 31)

    def test_invalid_settings(self):
        bad = ({"ack_timeout": 0}, {"ack_timeout": float("nan")},
               {"ack_random_factor": float("inf")}, {"ack_random_factor": 0.5},
               {"max_retransmit": -1}, {"max_retransmit": 1.5},
               {"max_retransmit": True}, {"message_limit": 3},
               {"local_port": 65536}, {"token_length": 9}, {"response_timeout": 0},
               {"response_timeout": "2"}, {"ack_timeout": 1e308})
        for values in bad:
            with self.subTest(values=values), self.assertRaises(ValueError):
                Settings(**values).validate()

    def test_per_message_aiocoap_tuning_not_global(self):
        original = aiocoap.numbers.constants.TransportTuning()
        tuning = DebugTuning(Settings(ack_timeout=0.2, ack_random_factor=1.1,
                                      max_retransmit=2), True)
        self.assertEqual(tuning.ACK_TIMEOUT, 0.2)
        self.assertEqual(tuning.MAX_RETRANSMIT, 2)
        self.assertAlmostEqual(tuning.MAX_TRANSMIT_WAIT, 0.2 * 7 * 1.1)
        self.assertTrue(tuning.reliability)
        self.assertEqual(original.ACK_TIMEOUT, 2)
        self.assertEqual(original.MAX_RETRANSMIT, 4)
        self.assertFalse(DebugTuning(Settings(), False).reliability)


class UDPFixture:
    def __init__(self, handler, family=socket.AF_INET):
        self.handler = handler
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.ip = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        self.sock.bind((self.ip, 0))
        self.sock.settimeout(2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.errors = []

    def __enter__(self):
        def run():
            try:
                self.handler(self.sock, self.stop)
            except Exception as exc:
                self.errors.append(exc)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.stop.set()
        self.thread.join(3)
        self.sock.close()
        if self.thread.is_alive():
            raise AssertionError("UDP fixture failed to stop.")
        if exc is None and self.errors:
            raise self.errors[0]


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.request = Message(0, 1, 0x1234, b"abcd", [Option(11, b"my-endpoint")])
        self.settings = Settings(ack_timeout=0.025, ack_random_factor=1.0,
                                 max_retransmit=2, response_timeout=0.15)
        self.events = []
        self.cancel = threading.Event()

    def emit(self, kind, value):
        self.events.append((kind, value))

    def invoke(self, fixture, request=None, settings=None):
        exchange(fixture.ip, fixture.port, request or self.request,
                 settings or self.settings, self.cancel, self.emit)

    def responses(self):
        return [value for kind, value in self.events if kind == "response"]

    def test_proseccoap_style_response(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            request = Message.decode(raw)
            self.assertEqual(request.options, [Option(11, b"my-endpoint")])
            response = Message(2, 69, request.mid, request.token, [Option(12, b"")], b"42")
            sock.sendto(response.encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(self.responses()[0][0].payload, b"42")

    def test_aiocoap_owns_retransmission(self):
        from aiocoap.messagemanager import MessageManager
        calls = []
        original = MessageManager._retransmit
        def retransmit(manager, message, timeout, counter):
            calls.append((timeout, counter))
            return original(manager, message, timeout, counter)
        def serve(sock, stop):
            sock.recvfrom(65535)  # Deliberately lose first request.
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token, payload=b"retry").encode(), address)
        with UDPFixture(serve) as fixture, patch.object(MessageManager, "_retransmit", retransmit):
            self.invoke(fixture)
        self.assertEqual(calls, [(0.025, 0)])
        self.assertEqual(self.responses()[0][0].payload, b"retry")

    def test_fixed_local_port_and_explicit_token(self):
        source_ports = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            local_port = reserve.getsockname()[1]
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            source_ports.append(address[1])
            req = Message.decode(raw)
            self.assertEqual(req.token, b"\x00\xaa\xff")
            self.assertEqual(req.mid, 65535)
            sock.sendto(Message(2, 69, req.mid, req.token).encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 1, 65535, b"\x00\xaa\xff"),
                        settings=Settings(local_port=local_port))
        self.assertEqual(source_ports, [local_port])
        # Shutdown releases the selected local socket.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check:
            check.bind(("127.0.0.1", local_port))

    def test_destination_is_independent_of_logical_uri(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            self.assertIn(Option(3, b"logical.example"), req.options)
            self.assertIn(Option(7, b"\x16\x33"), req.options)
            self.assertEqual(req.options[-2:], [Option(11, b"one"), Option(11, b"two")])
            sock.sendto(Message(2, 69, req.mid, req.token).encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 1, 1, b"a", [
                Option(3, b"logical.example"), Option(7, b"\x16\x33"),
                Option(11, b"one"), Option(11, b"two")]))

    def test_retries_identical_and_exponential(self):
        received, timestamps = [], []
        def serve(sock, stop):
            for _ in range(3):
                raw, address = sock.recvfrom(65535)
                received.append(raw)
                timestamps.append(time.monotonic())
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token, payload=b"ok").encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(received, [self.request.encode()] * 3)
        self.assertGreaterEqual(timestamps[1] - timestamps[0], 0.018)
        self.assertGreaterEqual(timestamps[2] - timestamps[1], 0.04)
        self.assertEqual(len(self.responses()), 1)

    def test_no_response_final_timeout(self):
        received = []
        def serve(sock, stop):
            for _ in range(3):
                received.append(sock.recvfrom(65535)[0])
            stop.wait(2)
        start = time.monotonic()
        with UDPFixture(serve) as fixture:
            with self.assertRaisesRegex(TimeoutError, "2 retransmissions"):
                self.invoke(fixture)
        self.assertEqual(len(received), 3)
        self.assertGreaterEqual(time.monotonic() - start, 0.16)

    def test_zero_retries(self):
        received = []
        def serve(sock, stop):
            received.append(sock.recvfrom(65535)[0])
            stop.wait(2)
        with UDPFixture(serve) as fixture:
            with self.assertRaisesRegex(TimeoutError, "0 retransmissions"):
                self.invoke(fixture, settings=Settings(ack_timeout=0.025, ack_random_factor=1,
                                                       max_retransmit=0))
        self.assertEqual(len(received), 1)

    def test_random_initial_interval(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token).encode(), address)
        with UDPFixture(serve) as fixture, patch("aiocoap.messagemanager.random.uniform", return_value=0.025) as uniform:
            self.invoke(fixture, settings=Settings())
        uniform.assert_called_once_with(2.0, 3.0)

    def test_separate_con_response_and_ack(self):
        acknowledgements = []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            ack = Message(2, 0, req.mid).encode()
            sock.sendto(ack, address)
            time.sleep(0.06)  # Past multiple short retry intervals.
            sock.sendto(ack, address)  # Duplicate empty ACK must not reset timeout.
            sock.sendto(Message(0, 69, 0x7777, req.token, payload=b"separate").encode(), address)
            raw_ack, _ = sock.recvfrom(65535)
            acknowledgements.append(Message.decode(raw_ack))
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(acknowledgements, [Message(2, 0, 0x7777)])
        self.assertFalse(any(v.startswith("TX retransmission") for k, v in self.events if k == "log"))

    def test_empty_ack_timeout_does_not_retry(self):
        received = []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            received.append(raw)
            sock.sendto(Message(2, 0, self.request.mid).encode(), address)
            stop.wait(2)
        with UDPFixture(serve) as fixture:
            with self.assertRaisesRegex(TimeoutError, "idle timeout"):
                self.invoke(fixture)
        self.assertEqual(len(received), 1)

    def test_non_never_retries(self):
        received = []
        def serve(sock, stop):
            received.append(sock.recvfrom(65535)[0])
            stop.wait(2)
        request = Message(1, 1, 42, b"abcd")
        with UDPFixture(serve) as fixture:
            with self.assertRaises(TimeoutError):
                self.invoke(fixture, request=request)
        self.assertEqual(received, [request.encode()])
        self.assertFalse(any("retransmission" in v for k, v in self.events if k == "log"))

    def test_non_response_and_proseccoap_ack_to_non(self):
        for response_type in (1, 2):
            with self.subTest(response_type=response_type):
                def serve(sock, stop):
                    raw, address = sock.recvfrom(65535)
                    req = Message.decode(raw)
                    sock.sendto(Message(response_type, 69, req.mid, req.token, payload=b"42").encode(), address)
                with UDPFixture(serve) as fixture:
                    self.invoke(fixture, request=Message(1, 1, 42, b"abcd"))
        self.assertEqual(len(self.responses()), 2)

    def test_mismatched_and_malformed_packets_ignored(self):
        resets = []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            for packet in (
                b"bad",
                Message(2, 69, req.mid + 1, req.token).encode(),
                Message(2, 69, req.mid, b"wrong").encode(),
                Message(1, 69, 777, b"wrong").encode(),
                Message(3, 0, req.mid + 1).encode(),
                Message(0, 69, 777, b"wrong").encode(),
            ):
                sock.sendto(packet, address)
            resets.append(Message.decode(sock.recvfrom(65535)[0]))
            sock.sendto(Message(2, 69, req.mid, req.token, payload=b"correct").encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(resets, [Message(3, 0, 777)])
        self.assertEqual(len(self.responses()), 1)
        self.assertEqual(self.responses()[0][0].payload, b"correct")

    def test_wrong_source_is_filtered(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                other.sendto(Message(2, 69, req.mid, req.token, payload=b"wrong source").encode(), address)
            sock.sendto(Message(2, 69, req.mid, req.token, payload=b"right source").encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(self.responses()[0][0].payload, b"right source")

    def test_application_error_displayed(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 132, req.mid, req.token).encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(self.responses()[0][0].code, 132)

    def test_rst_failure_and_ping_success(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(3, 0, req.mid).encode(), address)
        with UDPFixture(serve) as fixture:
            with self.assertRaisesRegex(ConnectionError, "reset"):
                self.invoke(fixture)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 0, 42))
        self.assertEqual(self.responses()[-1][0], Message(3, 0, 42))

    def test_ping_timeout_is_aiocoap_timeout(self):
        received = []
        def serve(sock, stop):
            received.append(sock.recvfrom(65535)[0])
            stop.wait(2)
        with UDPFixture(serve) as fixture:
            with self.assertRaisesRegex(TimeoutError, "0 retransmissions"):
                self.invoke(fixture, request=Message(0, 0, 42),
                            settings=Settings(ack_timeout=0.025, ack_random_factor=1,
                                              max_retransmit=0))
        self.assertEqual(received, [bytes.fromhex("40 00 00 2a")])

    def test_nonempty_ack_does_not_stop_ping_retry(self):
        received = []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            received.append(raw)
            sock.sendto(Message(2, 69, 42).encode(), address)
            raw, address = sock.recvfrom(65535)
            received.append(raw)
            sock.sendto(Message(3, 0, 42).encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 0, 42))
        self.assertEqual(received, [bytes.fromhex("40 00 00 2a")] * 2)

    def test_busy_local_port_reports_failure_and_next_send_works(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("0.0.0.0", 0))
            with self.assertRaises(OSError):
                exchange("127.0.0.1", 5683, self.request,
                         Settings(local_port=occupied.getsockname()[1]),
                         self.cancel, self.emit)
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token).encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture)
        self.assertEqual(len(self.responses()), 1)

    def test_cancellation_is_prompt(self):
        def serve(sock, stop):
            sock.recvfrom(65535)
            self.cancel.set()
            stop.wait(2)
        start = time.monotonic()
        with UDPFixture(serve) as fixture:
            with self.assertRaises(Cancelled):
                self.invoke(fixture)
        self.assertLess(time.monotonic() - start, 0.5)

    def test_cancel_before_send(self):
        self.cancel.set()
        with self.assertRaises(Cancelled):
            exchange("127.0.0.1", 5683, self.request, self.settings, self.cancel, self.emit)
        self.assertFalse(self.events)

    def test_invalid_destination_and_size(self):
        for ip, port in (("host.name", 5683), ("127.0.0.1", 0), ("127.0.0.1", 65536)):
            with self.subTest(ip=ip, port=port), self.assertRaises(ValueError):
                exchange(ip, port, self.request, self.settings, self.cancel, self.emit)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            exchange("127.0.0.1", 5683, Message(0, 2, 1, payload=b"x" * 124),
                     self.settings, self.cancel, self.emit)

    def test_observe_duplicates_cancel_and_deregister(self):
        acknowledgements, deregistrations = [], []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token, [Option(6, b"")], b"first").encode(), address)
            notification = Message(0, 69, 222, req.token, [Option(6, b"\x01")], b"next").encode()
            for _ in range(2):
                sock.sendto(notification, address)
                acknowledgements.append(Message.decode(sock.recvfrom(65535)[0]))
            self.cancel.set()
            deregistrations.append((Message.decode(sock.recvfrom(65535)[0]), address))
        request = Message(0, 1, 42, b"abcd", [Option(6, b""), Option(11, b"observe")])
        with UDPFixture(serve) as fixture:
            with self.assertRaises(Cancelled):
                self.invoke(fixture, request=request)
        self.assertEqual(acknowledgements, [Message(2, 0, 222)] * 2)
        self.assertEqual(len(self.responses()), 2)
        deregister, _ = deregistrations[0]
        self.assertEqual(deregister.type, 1)
        self.assertEqual(deregister.token, request.token)
        self.assertIn(Option(6, b"\x01"), deregister.options)
        self.assertIn(Option(11, b"observe"), deregister.options)

    def test_observe_not_supported_completes(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token, payload=b"one shot").encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 1, 42, b"abcd", [Option(6, b"")]))
        self.assertEqual(len(self.responses()), 1)

    def test_observe_idle_timeout_deregisters(self):
        deregistrations = []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            initial = Message(2, 69, req.mid, req.token, [Option(6, b"")], b"first").encode()
            sock.sendto(initial, address)
            sock.sendto(initial, address)  # Duplicate piggybacked response, not a new notification.
            raw, _ = sock.recvfrom(65535)
            deregistrations.append(Message.decode(raw))
        with UDPFixture(serve) as fixture:
            with self.assertRaises(TimeoutError):
                self.invoke(fixture, request=Message(0, 1, 42, b"abcd", [Option(6, b"")]))
        self.assertEqual(len(self.responses()), 1)
        self.assertIn(Option(6, b"\x01"), deregistrations[0].options)

    def test_observe_sequence_rollover_and_stale_filtering(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token,
                                [Option(6, b"\xff\xff\xfe")], b"first").encode(), address)
            for mid, seq, payload in ((101, b"", b"rollover"), (102, b"\xff\xff\xfd", b"stale")):
                sock.sendto(Message(0, 69, mid, req.token, [Option(6, seq)], payload).encode(), address)
                self.assertEqual(Message.decode(sock.recvfrom(65535)[0]), Message(2, 0, mid))
            self.cancel.set()
            sock.recvfrom(65535)  # Deregistration.
        with UDPFixture(serve) as fixture:
            with self.assertRaises(Cancelled):
                self.invoke(fixture, request=Message(0, 1, 42, b"abcd", [Option(6, b"")]))
        self.assertEqual([message.payload for message, _ in self.responses()], [b"first", b"rollover"])
        self.assertTrue(any("73 74 61 6c 65" in value for kind, value in self.events if kind == "log"))

    def test_observe_terminal_payload_displayed(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token, [Option(6, b"")], b"first").encode(), address)
            time.sleep(0.01)
            sock.sendto(Message(0, 132, 222, req.token, payload=b"resource gone").encode(), address)
            self.assertEqual(Message.decode(sock.recvfrom(65535)[0]), Message(2, 0, 222))
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 1, 42, b"abcd", [Option(6, b"")]))
        self.assertEqual([message.payload for message, _ in self.responses()], [b"first", b"resource gone"])

    def test_empty_token_response(self):
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, payload=b"empty token works").encode(), address)
        with UDPFixture(serve) as fixture:
            self.invoke(fixture, request=Message(0, 1, 42))
        self.assertEqual(self.responses()[0][0].token, b"")

    def test_ipv6(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable.")
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token).encode(), address)
        try:
            fixture = UDPFixture(serve, socket.AF_INET6)
        except OSError:
            self.skipTest("IPv6 loopback unavailable.")
        with fixture:
            self.invoke(fixture)
        self.assertEqual(len(self.responses()), 1)


class GUITests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("GUI smoke test needs a graphical display.")
        self.root.withdraw()
        self.temp = tempfile.TemporaryDirectory()
        self.settings_path = Path(self.temp.name) / "settings.json"
        self.error_patch = patch("coap_debugger.messagebox.showerror")
        self.errors = self.error_patch.start()
        self.app = App(self.root, self.settings_path)
        self.root.update()

    def tearDown(self):
        if hasattr(self, "app"):
            self.app.cancel.set()
            if self.app.worker:
                self.app.worker.join(1)
            self.app._close()
            self.temp.cleanup()
            self.error_patch.stop()

    def test_defaults_and_preview(self):
        self.assertEqual(self.app.ip.get(), "192.168.0.100")
        self.assertEqual(self.app.port.get(), "5683")
        self.app.options = [Option(11, b"my-endpoint")]
        self.app._refresh_options()
        self.app._summarize()
        self.assertEqual(len(self.app.preview[2].token), 4)
        self.assertIn("my-endpoint", self.app.summary.get("1.0", "end"))
        self.assertFalse(self.errors.called)

    def test_selecting_summary_tab_builds_preview(self):
        self.app.tabs.select(1)
        self.root.update()
        self.assertIsNotNone(self.app.preview)
        self.assertIn("Destination:", self.app.summary.get("1.0", "end"))

    def test_preview_exact_send_and_payload_view_switch(self):
        received = []
        def serve(sock, stop):
            raw, address = sock.recvfrom(65535)
            received.append(raw)
            req = Message.decode(raw)
            sock.sendto(Message(2, 69, req.mid, req.token, [Option(12, b"")], b"42\x00").encode(), address)
        with UDPFixture(serve) as fixture:
            self.app.ip.set("127.0.0.1")
            self.app.port.set(str(fixture.port))
            self.app.options = [Option(11, b"my-endpoint")]
            self.app._summarize()
            expected_raw = self.app.preview[3]
            self.app._send()
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not self.app.responses:
                self.root.update()
                time.sleep(0.01)
            self.root.update()
        self.assertEqual(received, [expected_raw])
        self.assertEqual(len(self.app.responses), 1)
        self.assertIn("42\\x00", self.app.response_payload.get("1.0", "end"))
        self.app.display_mode.set("HEX")
        self.assertIn("34 32 00", self.app.response_payload.get("1.0", "end"))
        self.assertFalse(self.errors.called)

    def test_modified_preview_regenerates(self):
        self.app._summarize()
        fingerprint = self.app.preview_fingerprint
        self.app.method.set("POST")
        self.assertNotEqual(fingerprint, self.app._request_fingerprint())
        self.app._summarize()
        self.assertEqual(self.app.preview[2].code, 2)

    def test_invalid_inputs_reported(self):
        self.app.encoding.set("HEX")
        self.app.payload_input.insert("1.0", "f")
        self.app._summarize()
        self.errors.assert_called_once()
        self.assertIsNone(self.app.preview)

    def test_payload_format_and_duplicate(self):
        self.app.payload_input.insert("1.0", "42")
        self.app.content_format.set("0 - text/plain; charset=utf-8")
        _, _, request, _ = self.app._build_request()
        self.assertEqual(request.payload, b"42")
        self.assertIn(Option(12, b""), request.options)
        self.app.options = [Option(12, b"")]
        with self.assertRaisesRegex(ValueError, "cannot be repeated"):
            self.app._build_request()

    def test_empty_ping(self):
        self.app.method.set("Empty ping")
        _, _, message, raw = self.app._build_request()
        self.assertEqual(len(raw), 4)
        self.assertEqual(message.token, b"")
        self.app.msg_type.set("NON")
        with self.assertRaises(ValueError):
            self.app._build_request()

    def test_manual_mid_and_token(self):
        for text in ("0007", "7", "0x7"):
            self.app.mid.set(text)
            self.app.token.set("aa 00 ff")
            _, _, message, _ = self.app._build_request()
            self.assertEqual(message.mid, 7)
            self.assertEqual(message.token, b"\xaa\x00\xff")
        self.app.token.set("empty")
        self.assertEqual(self.app._build_request()[2].token, b"")

    def test_cancel_button_and_responsive_gui(self):
        received = threading.Event()
        def serve(sock, stop):
            sock.recvfrom(65535)
            received.set()
            stop.wait(2)
        with UDPFixture(serve) as fixture:
            self.app.ip.set("127.0.0.1")
            self.app.port.set(str(fixture.port))
            self.app._send()
            self.assertEqual(str(self.app.send_button["state"]), "disabled")
            self.assertEqual(str(self.app.cancel_button["state"]), "normal")
            self.assertTrue(received.wait(1))
            self.root.update()
            self.app.cancel_button.invoke()
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline and str(self.app.send_button["state"]) != "normal":
                self.root.update()
                time.sleep(0.01)
        self.assertEqual(self.app.status.get(), "Cancelled.")
        self.assertEqual(str(self.app.send_button["state"]), "normal")
        self.assertFalse(self.errors.called)

    def test_settings_persistence_and_invalid_file(self):
        settings = Settings(message_limit=1152, token_length=8)
        self.app._save_settings(settings)
        self.assertTrue(self.settings_path.exists())
        self.app.settings = Settings()
        self.app._load_settings()
        self.assertEqual(self.app.settings, settings)
        self.settings_path.write_text('{"ack_timeout": "bad"}', encoding="utf-8")
        self.app.settings = Settings()
        self.app._load_settings()
        self.errors.assert_called_once()
        self.assertEqual(self.app.settings, Settings())
        self.assertIn("bad", self.settings_path.read_text())

    def test_option_edit_and_settings_dialog_smoke(self):
        self.app.options = [Option(6, b""), Option(11, b"my-endpoint"), Option(65000, b"\xff")]
        self.app._refresh_options()
        for index in range(3):
            self.app.option_table.selection_set(str(index))
            self.app._option_dialog(edit=True)
            self.root.update()
            for child in self.root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    child.destroy()
        self.app._settings_dialog()
        self.root.update()
        self.assertFalse(self.errors.called)


if __name__ == "__main__":
    unittest.main()
