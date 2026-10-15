from __future__ import annotations

import http.client
import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from passd import cli
from passd.client import PassdClient, PassdSession, RpcError
from passd.errors import ValidationError
from passd.gateway import GatewayHandler, PassdGatewayServer
from passd.server import PassdHandler, PassdUnixServer

SECRET = "dummy-secret-in-malformed-http-status"
REQUEST = b'{"op":"capability.list","agent_token":"test-token"}\n'


class MemorySocket:
    """Exercise the stream handlers without requiring socket permissions."""

    def __init__(self, incoming):
        self.reader = io.BytesIO(incoming)
        self.received = bytearray()
        self.timeout = None

    def makefile(self, *args):
        return self.reader

    def sendall(self, data):
        self.received.extend(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class ErrorResponseTests(unittest.TestCase):
    def daemon_response(self, handle):
        connection = MemorySocket(REQUEST)
        PassdHandler(connection, "local", SimpleNamespace(service=SimpleNamespace(handle=handle)))
        self.assertNotIn(SECRET.encode(), connection.received)
        self.assertEqual(json.loads(connection.received), {
            "ok": False, "error": {"code": "internal_error", "message": "internal error"},
        })
        return bytes(connection.received)

    def gateway_response(self, response):
        connection = MemorySocket(REQUEST)
        with patch("passd.gateway.socket.socket", return_value=MemorySocket(response)):
            GatewayHandler(connection, ("127.0.0.1", 1234), SimpleNamespace(socket_path=Path("unused")))
        self.assertNotIn(SECRET.encode(), connection.received)
        self.assertEqual(json.loads(connection.received)["error"]["message"], "internal error")

    def test_malformed_http_status_never_reaches_either_client(self):
        def handle(request):
            response = http.client.HTTPResponse(MemorySocket(f"{SECRET}\r\n".encode()))
            response.begin()

        with self.assertLogs("passd.server", level="ERROR") as logs:
            response = self.daemon_response(handle)
        self.assertEqual(logs.records[0].getMessage(), "BadStatusLine")
        self.assertNotIn(SECRET, "\n".join(logs.output))
        self.gateway_response(response)

    def test_generic_and_urllib_errors_have_fixed_public_messages(self):
        for error in [RuntimeError(SECRET), urllib.error.URLError(SECRET), RpcError("internal_error", SECRET)]:
            with self.subTest(error=type(error).__name__):
                with self.assertLogs("passd.server", level="ERROR") as logs:
                    self.daemon_response(Mock(side_effect=error))
                self.assertEqual(logs.records[0].getMessage(), type(error).__name__)
                self.assertIsNone(logs.records[0].exc_info)
                self.assertNotIn(SECRET, "\n".join(logs.output))

    def test_deliberate_public_errors_are_preserved(self):
        connection = MemorySocket(REQUEST)
        service = SimpleNamespace(handle=Mock(side_effect=ValidationError("invalid request")))
        PassdHandler(connection, "local", SimpleNamespace(service=service))
        self.assertEqual(json.loads(connection.received)["error"], {
            "code": "validation_error", "message": "invalid request",
        })

    def test_gateway_sanitizes_internal_errors_from_older_daemon(self):
        self.gateway_response(json.dumps({
            "ok": False, "error": {"code": "internal_error", "message": SECRET},
        }).encode() + b"\n")

    def test_uncaught_handler_errors_log_only_exception_class(self):
        for server_type in [PassdUnixServer, PassdGatewayServer]:
            with self.subTest(server=server_type.__name__):
                server = server_type.__new__(server_type)
                with self.assertLogs(server_type.__module__, level="ERROR") as logs:
                    try:
                        raise RuntimeError(SECRET)
                    except RuntimeError:
                        server.handle_error(None, ("127.0.0.1", 1234))
                self.assertEqual(logs.records[0].getMessage(), "RuntimeError")
                self.assertIsNone(logs.records[0].exc_info)
                self.assertNotIn(SECRET, "\n".join(logs.output))

    def test_cli_generic_and_internal_errors_do_not_print_exception_text(self):
        errors = [
            http.client.BadStatusLine(SECRET), urllib.error.URLError(SECRET),
            ValueError(SECRET), RuntimeError(SECRET), RpcError("internal_error", SECRET),
        ]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                stderr = io.StringIO()
                with patch("passd.cli.get_client", side_effect=error), redirect_stderr(stderr):
                    with self.assertLogs("passd.cli", level="ERROR") as logs:
                        self.assertEqual(cli.main(["doctor"]), 2)
                self.assertEqual(stderr.getvalue(), "passd: internal_error: internal error\n")
                self.assertEqual(logs.records[0].getMessage(), type(error).__name__)
                self.assertNotIn(SECRET, "\n".join(logs.output))


class RemoteClientTests(unittest.TestCase):
    def test_admin_password_rejected_before_connecting_or_serializing(self):
        requests = [
            {"admin_password": SECRET},
            {"params": {"admin_password": None}},
            {"params": {"nested": [{"deeper": [{"admin_password": SECRET}]}]}},
            {"reason": {"admin_password": SECRET}},
            {"agent_token": [{"admin_password": SECRET}]},
        ]
        for client_type in [PassdClient, PassdSession]:
            for kwargs in requests:
                with self.subTest(client=client_type.__name__, kwargs=kwargs):
                    with patch("passd.client.socket.create_connection", side_effect=AssertionError("connected before validation")) as connect, patch("passd.client._request", side_effect=AssertionError("serialized before validation")) as serialize:
                        with self.assertRaises(RpcError) as caught:
                            client_type(remote="127.0.0.1:1234").call("capability.list", **kwargs)
                        self.assertEqual(caught.exception.code, "forbidden_remote_op")
                        connect.assert_not_called()
                        serialize.assert_not_called()


class ConnectionLimitTests(unittest.TestCase):
    def server(self, **kwargs):
        with patch("socketserver.ThreadingTCPServer.__init__"), patch(
            "passd.gateway.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 1234))],
        ):
            return PassdGatewayServer(("127.0.0.1", 1234), Path("unused"), **kwargs)

    def test_default_limit_rejects_before_starting_worker_and_releases_slot(self):
        server = self.server()
        address = ("127.0.0.1", 1234)
        with patch("socketserver.ThreadingTCPServer.process_request") as spawn, patch.object(server, "shutdown_request") as close:
            for _ in range(32):
                server.process_request(Mock(), address)
            extra = Mock()
            server.process_request(extra, address)
            self.assertEqual(spawn.call_count, 32)
            close.assert_called_once_with(extra)
            with patch("socketserver.ThreadingTCPServer.process_request_thread"):
                server.process_request_thread(Mock(), address)
            server.process_request(Mock(), address)
            self.assertEqual(spawn.call_count, 33)

    def test_custom_limit_and_failed_worker_start_release_slot(self):
        server = self.server(max_connections=1)
        with patch("socketserver.ThreadingTCPServer.process_request", side_effect=RuntimeError("thread start failed")):
            with self.assertRaises(RuntimeError):
                server.process_request(Mock(), ("127.0.0.1", 1234))
        with patch("socketserver.ThreadingTCPServer.process_request") as spawn:
            server.process_request(Mock(), ("127.0.0.1", 1234))
            spawn.assert_called_once()

    def test_failed_worker_releases_slot(self):
        server = self.server(max_connections=1)
        address = ("127.0.0.1", 1234)
        with patch("socketserver.ThreadingTCPServer.process_request") as spawn:
            server.process_request(Mock(), address)
            with patch("socketserver.ThreadingTCPServer.process_request_thread", side_effect=RuntimeError("worker failed")):
                with self.assertRaises(RuntimeError):
                    server.process_request_thread(Mock(), address)
            server.process_request(Mock(), address)
            self.assertEqual(spawn.call_count, 2)

    def test_invalid_limits_rejected(self):
        for limit in [0, -1]:
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "max_connections"):
                self.server(max_connections=limit)

    def test_cli_forwards_connection_limit(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {"PASSD_SOCKET": temp + "/daemon.sock"}), patch("passd.cli.serve_gateway") as serve, patch("passd.cli.logging.basicConfig"):
            self.assertEqual(cli.main(["gateway", "--listen", "127.0.0.1:1234", "--max-connections", "7"]), 0)
            self.assertEqual(serve.call_args.kwargs["max_connections"], 7)


class ReadDeadlineTests(unittest.TestCase):
    def test_deadline_resets_for_each_request(self):
        clock = SimpleNamespace(now=0.0)
        handler = GatewayHandler.__new__(GatewayHandler)
        handler.connection = MemorySocket(b"")
        handler.request_timeout = 0.1

        class SlowReader:
            def read1(self, size):
                clock.now += 0.08
                return b"{}\n"

        handler.rfile = SlowReader()
        with patch("time.monotonic", side_effect=lambda: clock.now):
            for _ in range(3):
                self.assertEqual(handler._read_request(bytearray()), b"{}\n")

    def test_buffered_requests_and_size_limit(self):
        from passd.gateway import MAX_REQUEST

        handler = GatewayHandler.__new__(GatewayHandler)
        handler.connection = MemorySocket(b"{}\n{}\n")
        handler.rfile = handler.connection.reader
        buffer = bytearray()
        self.assertEqual(handler._read_request(buffer), b"{}\n")
        self.assertEqual(handler._read_request(buffer), b"{}\n")
        handler.rfile = io.BytesIO(b" " * (MAX_REQUEST - 1) + b"\n")
        self.assertEqual(len(handler._read_request(buffer)), MAX_REQUEST)
        handler.rfile = io.BytesIO(b" " * (MAX_REQUEST + 2))
        self.assertEqual(len(handler._read_request(buffer)), MAX_REQUEST + 1)

    def test_trickle_cannot_extend_absolute_deadline(self):
        clock = SimpleNamespace(now=0.0)
        connection = MemorySocket(b"")

        class TrickleReader(io.BytesIO):
            def read1(self, size):
                # Each byte arrives faster than the idle timeout.
                delay = min(0.04, connection.timeout)
                clock.now += delay
                if delay < 0.04:
                    raise TimeoutError
                return b" "

            def readline(self, size=-1):
                # The old readline path allows the trickle to outlast 100 ms.
                if clock.now:
                    return b""
                clock.now += 0.4
                return b" \n"

        connection.reader = TrickleReader()
        with patch.object(GatewayHandler, "timeout", 0.05), patch.object(GatewayHandler, "request_timeout", 0.1, create=True), patch("time.monotonic", side_effect=lambda: clock.now):
            GatewayHandler(connection, ("127.0.0.1", 1234), SimpleNamespace())
        self.assertLessEqual(clock.now, 0.100001)
        self.assertEqual(connection.received, b"")


if __name__ == "__main__":
    unittest.main()
