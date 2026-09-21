from __future__ import annotations

import json
import socket
from pathlib import Path

from .errors import PassdError


class RpcError(PassdError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


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


class PassdSession:
    """Persistent Unix-socket client for low-overhead agent/SDK use."""

    def __init__(self, socket_path: Path):
        self.socket_path = Path(socket_path)
        self.sock: socket.socket | None = None
        self.buffer = bytearray()

    def __enter__(self) -> "PassdSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def connect(self):
        if self.sock is None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self.socket_path))
            self.sock = sock
        return self

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.buffer.clear()

    def call(self, op: str, params: dict | None = None, *, admin_password: str | None = None, agent_token: str | None = None, reason: str | None = None):
        self.connect()
        assert self.sock is not None
        self.sock.sendall(_request(op, params, admin_password, agent_token, reason))
        result, self.buffer = _read_response(self.sock, self.buffer)
        return result


class PassdClient:
    def __init__(self, socket_path: Path):
        self.socket_path = Path(socket_path)

    def session(self) -> PassdSession:
        return PassdSession(self.socket_path)

    def call(self, op: str, params: dict | None = None, *, admin_password: str | None = None, agent_token: str | None = None, reason: str | None = None):
        with PassdSession(self.socket_path) as session:
            return session.call(op, params, admin_password=admin_password, agent_token=agent_token, reason=reason)
