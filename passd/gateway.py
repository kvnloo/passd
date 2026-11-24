from __future__ import annotations

import ipaddress
import json
import logging
import signal
import socket
import socketserver
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from .client import RpcError
from .errors import INTERNAL_ERROR_MESSAGE

MAX_REQUEST = 1024 * 1024
IDLE_TIMEOUT = 60
REQUEST_TIMEOUT = 10
DEFAULT_MAX_CONNECTIONS = 32
DEFAULT_ALLOWED_CIDRS = ("100.64.0.0/10", "fd7a:115c:a1e0::/48", "127.0.0.0/8", "::1/128")
REMOTE_OPS = frozenset({"capability.list", "capability.request", "capability.invoke", "access.request", "access.status"})
logger = logging.getLogger(__name__)


def peer_allowed(peer_ip: str, allowed_cidrs=DEFAULT_ALLOWED_CIDRS) -> bool:
    address = ipaddress.ip_address(peer_ip)
    mapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    networks = (ipaddress.ip_network(cidr) for cidr in allowed_cidrs)
    return any(address in network or mapped is not None and mapped in network for network in networks)


def _agent_object(pairs):
    # Inspect every object, including nested params and duplicate JSON keys.
    if any(key == "admin_password" for key, _ in pairs):
        raise RpcError("forbidden_remote_op", "admin passwords are forbidden on the remote gateway")
    return dict(pairs)


class GatewayHandler(socketserver.StreamRequestHandler):
    timeout = IDLE_TIMEOUT
    request_timeout = REQUEST_TIMEOUT

    def _read_request(self, buffer):
        deadline = time.monotonic() + self.request_timeout
        try:
            while True:
                newline = buffer.find(b"\n")
                if newline >= 0:
                    raw = bytes(buffer[:newline + 1])
                    del buffer[:newline + 1]
                    return raw
                if len(buffer) > MAX_REQUEST:
                    return bytes(buffer)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                self.connection.settimeout(min(self.timeout, remaining))
                chunk = self.rfile.read1(min(65536, MAX_REQUEST + 1 - len(buffer)))
                if not chunk:
                    raw = bytes(buffer)
                    buffer.clear()
                    return raw
                buffer.extend(chunk)
        finally:
            self.connection.settimeout(self.timeout)

    def handle(self):
        with ExitStack() as stack:
            upstream = None
            upstream_file = None
            buffer = bytearray()
            while True:
                op = "-"
                try:
                    raw = self._read_request(buffer)
                    if not raw:
                        return
                    if len(raw) > MAX_REQUEST:
                        self._send_error("request_too_large", "request exceeds 1 MiB", op)
                        return
                    if not raw.endswith(b"\n"):
                        self._send_error("validation_error", "request must end with a newline", op)
                        return
                    try:
                        request = json.loads(raw, object_pairs_hook=_agent_object)
                        if not isinstance(request, dict):
                            raise ValueError("request must be an object")
                        requested_op = request.get("op")
                        if not isinstance(requested_op, str) or requested_op not in REMOTE_OPS:
                            raise RpcError("forbidden_remote_op", "operation is forbidden on the remote gateway")
                        op = requested_op
                        token = request.get("agent_token")
                        if not isinstance(token, str) or not token.strip():
                            raise RpcError("forbidden_remote_op", "remote requests require a non-empty agent_token")
                        if request.get("params") is not None and not isinstance(request["params"], dict):
                            raise ValueError("params must be an object")
                    except RpcError as exc:
                        self._send_error(exc.code, str(exc), op)
                        continue
                    except (ValueError, UnicodeError, RecursionError):
                        self._send_error("validation_error", "invalid JSON request", op)
                        continue

                    if upstream is None:
                        upstream = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                        upstream.settimeout(IDLE_TIMEOUT)
                        upstream.connect(str(self.server.socket_path))
                        upstream_file = stack.enter_context(upstream.makefile("rb"))
                    upstream.sendall(raw)
                    response = upstream_file.readline()
                    if not response.endswith(b"\n"):
                        raise OSError("incomplete daemon response")
                    result = json.loads(response)
                    if not result.get("ok") and result["error"]["code"] == "internal_error":
                        result["error"]["message"] = INTERNAL_ERROR_MESSAGE
                        response = json.dumps(result, separators=(",", ":")).encode("utf-8") + b"\n"
                    self.wfile.write(response)
                    self.wfile.flush()
                    self._log(op, "ok" if result.get("ok") else result["error"]["code"])
                except TimeoutError:
                    return
                except OSError:
                    self._send_error("transport_error", "gateway connection closed or local daemon unavailable", op)
                    return
                except Exception as exc:
                    logger.error("%s", type(exc).__name__)
                    self._send_error("internal_error", INTERNAL_ERROR_MESSAGE, op)
                    return

    def _log(self, op, outcome):
        # Unknown operations use '-' so arbitrary input cannot become log text.
        logger.info("%s %s %s", self.client_address[0], op, outcome)

    def _send_error(self, code, message, op):
        self._log(op, code)
        response = {"ok": False, "error": {"code": code, "message": message}}
        try:
            self.wfile.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
            self.wfile.flush()
        except OSError:
            pass


class PassdGatewayServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, listen: tuple[str, int], socket_path: Path, *, allow_cidrs=None, i_know_what_im_doing: bool = False, max_connections: int = DEFAULT_MAX_CONNECTIONS):
        if max_connections <= 0:
            raise ValueError("max_connections must be positive")
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        self.socket_path = Path(socket_path)
        cidrs = DEFAULT_ALLOWED_CIDRS if allow_cidrs is None else allow_cidrs
        self.allowed_cidrs = tuple(ipaddress.ip_network(cidr) for cidr in cidrs)
        family, _, _, _, address = socket.getaddrinfo(*listen, type=socket.SOCK_STREAM)[0]
        bind_ip = ipaddress.ip_address(address[0])
        if isinstance(bind_ip, ipaddress.IPv6Address) and bind_ip.ipv4_mapped is not None:
            bind_ip = bind_ip.ipv4_mapped
        if bind_ip.is_unspecified and not i_know_what_im_doing:
            raise ValueError("wildcard gateway binds require --i-know-what-im-doing")
        self.address_family = family
        super().__init__(address, GatewayHandler)

    def verify_request(self, request, client_address):
        return peer_allowed(client_address[0], self.allowed_cidrs)

    def process_request(self, request, client_address):
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def handle_error(self, request, client_address):
        # socketserver's default traceback may include caller-controlled data.
        logger.error("%s", type(sys.exception()).__name__)


def serve_gateway(socket_path: Path, listen: tuple[str, int], *, allow_cidrs=None, i_know_what_im_doing: bool = False, max_connections: int = DEFAULT_MAX_CONNECTIONS):
    server = PassdGatewayServer(listen, socket_path, allow_cidrs=allow_cidrs, i_know_what_im_doing=i_know_what_im_doing, max_connections=max_connections)
    stop = threading.Event()

    def handle_signal(signum, frame):
        if not stop.is_set():
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    old_int = signal.signal(signal.SIGINT, handle_signal)
    old_term = signal.signal(signal.SIGTERM, handle_signal)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
        server.server_close()
