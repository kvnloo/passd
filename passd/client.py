from __future__ import annotations

import json
import os
import socket
from pathlib import Path

from .errors import PassdError


class RpcError(PassdError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Parse HOST:PORT, including [IPv6]:PORT."""
    host, sep, port = endpoint.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise ValueError("IPv6 endpoints must use [HOST]:PORT")
    if not sep or not host or not port.isascii() or not port.isdecimal():
        raise ValueError("endpoint must be HOST:PORT")
    number = int(port)
    if not 0 <= number <= 65535:
        raise ValueError("endpoint port must be between 0 and 65535")
    return host, number


def _request(op: str, params: dict | None, admin_password: str | None, agent_token: str | None, reason: str | None) -> bytes:
    req = {"op": op, "params": params or {}}
    if admin_password is not None:
        req["admin_password"] = admin_password
    if agent_token is not None:
        req["agent_token"] = agent_token
    if reason is not None:
        req["reason"] = reason
    return json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def _read_response(sock: socket.socket, buffer: bytearray) -> tuple[object, bytearray]:
    while b"\n" not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer.extend(chunk)
    if b"\n" not in buffer:
        raise RpcError("transport_error", "passd closed the connection without a complete response")
    newline = buffer.index(b"\n")
    raw = bytes(buffer[:newline])
    del buffer[: newline + 1]
    response = json.loads(raw.decode("utf-8"))
    if not response.get("ok"):
        err = response.get("error") or {}
        raise RpcError(err.get("code", "rpc_error"), err.get("message", "unknown RPC error"))
    return response.get("result"), buffer


def _contains_admin_password(value) -> bool:
    pending = [value]
    seen = set()
    while pending:
        value = pending.pop()
        if not isinstance(value, (dict, list, tuple)) or id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, dict):
            if "admin_password" in value:
                return True
            pending.extend(value.values())
        else:
            pending.extend(value)
    return False


class PassdSession:
    """Persistent Unix-socket or remote TCP client for agent/SDK use."""

    def __init__(self, socket_path: Path | None = None, *, remote: str | None = None):
        self.socket_path = Path(socket_path) if socket_path is not None else None
        self.remote = os.environ.get("PASSD_REMOTE") if remote is None else remote
        self.endpoint = parse_endpoint(self.remote) if self.remote else None
        if self.endpoint is None and self.socket_path is None:
            raise ValueError("a Unix socket path or PASSD_REMOTE is required")
        self.sock: socket.socket | None = None
        self.buffer = bytearray()

    def __enter__(self) -> "PassdSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def connect(self):
        if self.sock is None:
            if self.endpoint is not None:
                sock = socket.create_connection(self.endpoint, timeout=60)
            else:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.connect(str(self.socket_path))
                except OSError:
                    sock.close()
                    raise
            self.sock = sock
        return self

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.buffer.clear()

    def call(self, op: str, params: dict | None = None, *, admin_password: str | None = None, agent_token: str | None = None, reason: str | None = None):
        if self.endpoint is not None and (
            admin_password is not None or _contains_admin_password([op, params, agent_token, reason])
        ):
            raise RpcError("forbidden_remote_op", "admin passwords must only use the local Unix socket")
        self.connect()
        assert self.sock is not None
        self.sock.sendall(_request(op, params, admin_password, agent_token, reason))
        result, self.buffer = _read_response(self.sock, self.buffer)
        return result


class PassdClient:
    def __init__(self, socket_path: Path | None = None, *, remote: str | None = None):
        self.socket_path = Path(socket_path) if socket_path is not None else None
        self.remote = (os.environ.get("PASSD_REMOTE") or "") if remote is None else remote

    def session(self) -> PassdSession:
        return PassdSession(self.socket_path, remote=self.remote)

    def call(self, op: str, params: dict | None = None, *, admin_password: str | None = None, agent_token: str | None = None, reason: str | None = None):
        # call() validates before opening the one-shot connection.
        session = self.session()
        try:
            return session.call(op, params, admin_password=admin_password, agent_token=agent_token, reason=reason)
        finally:
            session.close()
