from __future__ import annotations

import json
import logging
import socket
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from passd import cli
from passd.client import PassdClient, PassdSession, RpcError, parse_endpoint
from passd.config import Config
from passd.gateway import GatewayHandler, MAX_REQUEST, PassdGatewayServer, peer_allowed
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "gateway-test-master-password"
SECRET = "gateway-dummy-secret-never-on-agent-host"


class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.startswith("/echo/malformed-status"):
            self.wfile.write(f"{SECRET}\r\n\r\n".encode())
            return
        auth = self.headers.get("Authorization")
        self.send_response(200 if auth == f"Bearer {SECRET}" else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"auth": auth, "path": self.path}).encode())

    def log_message(self, fmt, *args):
        pass


def run_server(stack, server):
    stack.callback(server.server_close)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    stack.callback(thread.join, 5)
    stack.callback(server.shutdown)
    return server


@pytest.fixture(scope="module")
def custody(tmp_path_factory):
    cfg = Config.initialize(tmp_path_factory.mktemp("gateway"), MASTER)
    with ExitStack() as stack:
        service = PassdService(cfg, cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        stack.callback(service.close)
        run_server(stack, PassdUnixServer(cfg.socket_path, service))
        local = PassdClient(cfg.socket_path, remote="")
        http = run_server(stack, HTTPServer(("127.0.0.1", 0), EchoHandler))
        local.call("vault.create", {"name": "Personal"}, admin_password=MASTER)
        local.call("item.put", {"vault": "Personal", "title": "Echo", "fields": {"password": SECRET}}, admin_password=MASTER)
        local.call("capability.put", {
            "id": "echo.call", "kind": "http_secret", "backing_uri": "pass://Personal/Echo/password",
            "scheme": "http", "host": "127.0.0.1", "port": http.server_port,
            "methods": ["POST"], "path_prefix": "/echo", "inject_prefix": "Bearer ", "timeout_seconds": 5,
        }, admin_password=MASTER)
        agent = local.call("agent.create", {"name": "remote-agent", "ttl_seconds": 3600}, admin_password=MASTER)
        gateway = run_server(stack, PassdGatewayServer(("127.0.0.1", 0), cfg.socket_path))
        endpoint = f"127.0.0.1:{gateway.server_address[1]}"
        yield SimpleNamespace(
            cfg=cfg, service=service, local=local, token=agent["token"],
            gateway=gateway, endpoint=endpoint, remote=PassdClient(remote=endpoint),
        )


class WireClient:
    def __init__(self, address):
        self.sock = socket.create_connection(address, timeout=5)
        self.file = self.sock.makefile("rb")
        self.received = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.file.close()
        self.sock.close()

    def send(self, raw):
        self.sock.sendall(raw)
        response = self.file.readline()
        self.received.extend(response)
        assert SECRET.encode() not in self.received
        return json.loads(response)

    def call(self, op, params=None, **kwargs):
        return self.send(json.dumps({"op": op, "params": params or {}, **kwargs}).encode() + b"\n")


@pytest.mark.parametrize("op", [
    "agent.create", "access.approve", "capability.put", "item.put", "secret.resolve", "vault.list",
    "access.deny", "access.revoke", "access.pending", "agent.rotate", "audit.list", "broker.http", "health", "unknown",
])
def test_admin_and_other_operations_refused(custody, op, monkeypatch):
    def unexpected(request):
        pytest.fail("forbidden request reached the daemon")

    monkeypatch.setattr(custody.service, "handle", unexpected)
    with WireClient(custody.gateway.server_address) as wire:
        response = wire.call(op, agent_token=custody.token)
    assert response["ok"] is False
    assert response["error"]["code"] == "forbidden_remote_op"


@pytest.mark.parametrize("extra", [
    {"admin_password": MASTER},
    {"admin_password": None},
    {"params": {"admin_password": MASTER}},
    {"params": {"nested": [{"admin_password": MASTER}]}},
])
def test_admin_password_refused(custody, extra):
    with WireClient(custody.gateway.server_address) as wire:
        response = wire.call("capability.list", agent_token=custody.token, **extra)
    assert response["error"]["code"] == "forbidden_remote_op"


def test_duplicate_params_cannot_hide_admin_password(custody):
    raw = (
        b'{"op":"capability.list","agent_token":' + json.dumps(custody.token).encode()
        + b',"params":{"admin_password":"dummy"},"params":{}}\n'
    )
    with WireClient(custody.gateway.server_address) as wire:
        assert wire.send(raw)["error"]["code"] == "forbidden_remote_op"


@pytest.mark.parametrize("token", [None, "", " \t", 123, {}, []])
def test_nonempty_string_token_required(custody, token):
    with WireClient(custody.gateway.server_address) as wire:
        response = wire.call("capability.list", **({} if token is None else {"agent_token": token}))
    assert response["error"]["code"] == "forbidden_remote_op"


def invocation(path):
    return {"capability_id": "echo.call", "method": "POST", "path": path, "body": "{}"}


def request_lease(custody, path):
    return custody.remote.call(
        "capability.request", {**invocation(path), "ttl_seconds": 60, "max_uses": 1},
        agent_token=custody.token, reason="remote gateway test",
    )


def test_full_agent_flow_never_transmits_secret(custody):
    with WireClient(custody.gateway.server_address) as wire:
        catalog = wire.call("capability.list", agent_token=custody.token)
        assert catalog["ok"] is True
        assert [cap["id"] for cap in catalog["result"]] == ["echo.call"]
        assert b"pass://" not in wire.received
        params = invocation("/echo/full-flow")
        denied = wire.call("capability.invoke", params, agent_token=custody.token, reason="before approval")
        assert denied["error"]["code"] == "permission_denied"
        requested = wire.call(
            "capability.request", {**params, "ttl_seconds": 60, "max_uses": 1},
            agent_token=custody.token, reason="remote gateway test",
        )["result"]
        assert requested["status"] == "pending"
        custody.local.call("access.approve", {"request": requested["id"]}, admin_password=MASTER)
        status = wire.call("access.status", {"request": requested["id"]}, agent_token=custody.token)
        assert status["result"]["active"] is True
        response = wire.call("capability.invoke", params, agent_token=custody.token, reason="approved test")
        assert response["ok"] is True
        assert response["result"]["status"] == 200
        assert json.loads(response["result"]["body"])["auth"] == "Bearer <concealed by passd>"
        assert SECRET.encode() not in wire.received


@pytest.mark.parametrize("transport", ["tcp", "unix"])
def test_malformed_upstream_status_never_transmits_secret(custody, transport, caplog):
    path = f"/echo/malformed-status/{transport}"
    requested = request_lease(custody, path)
    custody.local.call("access.approve", {"request": requested["id"]}, admin_password=MASTER)
    raw = json.dumps({
        "op": "capability.invoke", "params": invocation(path),
        "agent_token": custody.token, "reason": "malformed upstream regression",
    }).encode() + b"\n"
    with caplog.at_level(logging.ERROR, logger="passd.server"):
        with ExitStack() as stack:
            if transport == "tcp":
                sock = stack.enter_context(socket.create_connection(custody.gateway.server_address, timeout=5))
            else:
                sock = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                sock.settimeout(5)
                sock.connect(str(custody.cfg.socket_path))
            response_file = stack.enter_context(sock.makefile("rb"))
            sock.sendall(raw)
            response = response_file.readline()
    assert SECRET.encode() not in response
    assert json.loads(response) == {
        "ok": False, "error": {"code": "internal_error", "message": "internal error"},
    }
    assert SECRET not in caplog.text
    assert any(record.getMessage() == "BadStatusLine" for record in caplog.records)


def test_gateway_sanitizes_legacy_daemon_internal_errors(custody, monkeypatch):
    def legacy_response(request):
        raise RpcError("internal_error", SECRET)

    # Bypass the updated daemon's sanitizer to simulate an older daemon.
    def send_legacy_error(handler, value):
        handler.wfile.write(json.dumps({
            "ok": False, "error": {"code": "internal_error", "message": SECRET},
        }).encode() + b"\n")
        handler.wfile.flush()

    monkeypatch.setattr("passd.server.PassdHandler._send", send_legacy_error)
    monkeypatch.setattr(custody.service, "handle", legacy_response)
    with WireClient(custody.gateway.server_address) as wire:
        response = wire.call("capability.list", agent_token=custody.token)
    assert response["error"] == {"code": "internal_error", "message": "internal error"}


@pytest.mark.parametrize("closed", ["deny", "revoke", "expiry", "exhaustion"])
def test_closed_leases_refused_over_tcp(custody, closed, monkeypatch):
    path = f"/echo/{closed}"
    req = request_lease(custody, path)
    if closed == "deny":
        custody.local.call("access.deny", {"request": req["id"]}, admin_password=MASTER)
    else:
        approved = custody.local.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
        if closed == "revoke":
            custody.local.call("access.revoke", {"request": req["id"]}, admin_password=MASTER)
        elif closed == "expiry":
            monkeypatch.setattr("passd.service.now", lambda: approved["expires_at"])
        else:
            assert custody.remote.call(
                "capability.invoke", invocation(path), agent_token=custody.token, reason="last use",
            )["status"] == 200
    with pytest.raises(RpcError, match="no active HITL lease") as exc:
        custody.remote.call("capability.invoke", invocation(path), agent_token=custody.token, reason="closed lease")
    assert exc.value.code == "permission_denied"
    status = custody.remote.call("access.status", {"request": req["id"]}, agent_token=custody.token)
    assert status["active"] is False
    if closed in {"deny", "revoke"}:
        assert status["status"] == {"deny": "denied", "revoke": "revoked"}[closed]
    if closed == "exhaustion":
        assert status["uses_remaining"] == 0


@pytest.mark.parametrize("ip, allowed", [
    ("100.64.0.0", True), ("100.127.255.255", True), ("100.63.255.255", False), ("100.128.0.0", False),
    ("fd7a:115c:a1e0::1", True), ("fd7a:115c:a1e1::1", False), ("127.0.0.2", True), ("::1", True),
    ("192.168.1.2", False), ("8.8.8.8", False), ("::", False),
    ("::ffff:100.64.0.1", True), ("::ffff:192.168.1.2", False),
])
def test_default_source_cidrs(ip, allowed):
    assert peer_allowed(ip) is allowed


def test_custom_cidrs_replace_defaults_and_reject_connection(custody):
    assert not peer_allowed("127.0.0.1", ["192.0.2.0/24"])
    assert peer_allowed("192.0.2.1", ["192.0.2.0/24"])
    with ExitStack() as stack:
        server = run_server(stack, PassdGatewayServer(
            ("127.0.0.1", 0), custody.cfg.socket_path, allow_cidrs=["192.0.2.0/24"],
        ))
        with socket.create_connection(server.server_address, timeout=5) as sock:
            assert sock.recv(1) == b""


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "::ffff:0.0.0.0"])
def test_wildcard_bind_requires_override(tmp_path, host):
    with pytest.raises(ValueError, match="--i-know-what-im-doing"):
        PassdGatewayServer((host, 0), tmp_path / "unused.sock")


def test_explicit_wildcard_bind(custody):
    with PassdGatewayServer(("0.0.0.0", 0), custody.cfg.socket_path, i_know_what_im_doing=True) as server:
        assert server.server_address[0] == "0.0.0.0"


def test_line_limit_closes_connection(custody):
    with WireClient(custody.gateway.server_address) as wire:
        response = wire.send(b" " * MAX_REQUEST + b"\n")
        assert response["error"]["code"] == "request_too_large"
        assert wire.file.read(1) == b""


def test_line_at_limit_is_accepted(custody):
    request = json.dumps({"op": "capability.list", "agent_token": custody.token}).encode()
    raw = request + b" " * (MAX_REQUEST - len(request) - 1) + b"\n"
    with WireClient(custody.gateway.server_address) as wire:
        assert wire.send(raw)["ok"] is True


def test_invalid_json_and_rpc_errors_preserve_session(custody):
    with WireClient(custody.gateway.server_address) as wire:
        for raw in [b"{\n", b"[]\n", b"\xff\n", b'{"op":[]}\n']:
            assert wire.send(raw)["ok"] is False
        assert wire.call("capability.list", agent_token="invalid")["error"]["code"] == "auth_error"
        assert wire.call("capability.list", agent_token=custody.token)["ok"] is True


def test_idle_timeout(custody, monkeypatch):
    assert GatewayHandler.timeout == 60
    monkeypatch.setattr(GatewayHandler, "timeout", 0.05)
    with socket.create_connection(custody.gateway.server_address, timeout=5) as sock:
        sock.sendall(b'{"op":')
        assert sock.recv(1) == b""


def test_absolute_read_deadline_closes_trickling_connection(custody, monkeypatch):
    monkeypatch.setattr(GatewayHandler, "timeout", 1)
    monkeypatch.setattr(GatewayHandler, "request_timeout", 0.15)
    with socket.create_connection(custody.gateway.server_address, timeout=2) as sock:
        sock.sendall(b"{")
        sock.settimeout(0.03)
        started = time.monotonic()
        for _ in range(20):
            try:
                try:
                    received = sock.recv(1)
                except socket.timeout:
                    sock.sendall(b" ")
                    continue
                assert received == b""
            except (BrokenPipeError, ConnectionResetError):
                pass
            assert time.monotonic() - started < 0.7
            break
        else:
            pytest.fail("trickled bytes kept the connection alive beyond the request deadline")


def test_connection_limit_rejects_extra_clients_and_releases_slot(custody, monkeypatch):
    entered = threading.Event()
    released = threading.Event()
    original = GatewayHandler.handle

    def handle(handler):
        entered.set()
        try:
            original(handler)
        finally:
            released.set()

    monkeypatch.setattr(GatewayHandler, "handle", handle)
    with ExitStack() as stack:
        server = run_server(stack, PassdGatewayServer(
            ("127.0.0.1", 0), custody.cfg.socket_path, max_connections=1,
        ))
        with socket.create_connection(server.server_address, timeout=2):
            assert entered.wait(2)
            with socket.create_connection(server.server_address, timeout=2) as extra:
                assert extra.recv(1) == b""
        assert released.wait(2)
        # Synchronize on the worker's final slot release, after handle() returns.
        assert server._connection_slots.acquire(timeout=2)
        server._connection_slots.release()
        with WireClient(server.server_address) as wire:
            assert wire.call("capability.list", agent_token=custody.token)["ok"] is True


def test_logs_contain_only_metadata(custody, caplog):
    marker = "private-request-body"
    with caplog.at_level(logging.INFO, logger="passd.gateway"):
        with WireClient(custody.gateway.server_address) as wire:
            wire.call("capability.list", agent_token=custody.token, reason=marker)
            wire.call(marker + custody.token, admin_password=MASTER)
    records = [record for record in caplog.records if record.name == "passd.gateway"]
    assert records
    for record in records:
        assert record.created > 0
        peer, op, outcome = record.getMessage().split()
        assert peer == "127.0.0.1"
        assert op in {"capability.list", "-"}
        assert outcome in {"ok", "forbidden_remote_op"}
    for private in [marker, custody.token, MASTER, SECRET]:
        assert private not in caplog.text


def test_tcp_clients_and_sessions_use_remote_env(custody, monkeypatch):
    monkeypatch.setenv("PASSD_REMOTE", custody.endpoint)
    assert PassdClient().call("capability.list", agent_token=custody.token)
    with PassdSession() as session:
        with pytest.raises(RpcError) as exc:
            session.call("vault.list", agent_token=custody.token)
        assert exc.value.code == "forbidden_remote_op"
        assert session.call("capability.list", agent_token=custody.token)
    assert custody.local.call("health")["version"] == 3


def test_client_does_not_send_admin_password(custody, monkeypatch):
    with custody.remote.session() as session:
        def unexpected(*args):
            pytest.fail("remote admin password reached serialization")

        monkeypatch.setattr("passd.client._request", unexpected)
        with pytest.raises(RpcError) as exc:
            session.call("capability.list", admin_password=MASTER)
        assert exc.value.code == "forbidden_remote_op"


def test_remote_cli_without_local_config(custody, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PASSD_REMOTE", custody.endpoint)
    monkeypatch.setenv("PASSD_AGENT_TOKEN", custody.token)
    monkeypatch.setenv("PASSD_AGENT_REASON", "remote CLI test")

    def unexpected(**kwargs):
        pytest.fail("agent CLI requested a master password")

    monkeypatch.setattr(cli, "password_from_env", unexpected)

    def command(*args):
        assert cli.main(["--data-dir", str(tmp_path / "uninitialized"), *args]) == 0
        return json.loads(capsys.readouterr().out)

    assert command("capability", "list")[0]["id"] == "echo.call"
    req = command("capability", "request", "echo.call", "--path", "/echo/cli")
    assert command("access", "status", req["id"])["status"] == "pending"
    custody.local.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
    assert command("capability", "invoke", "echo.call", "--path", "/echo/cli")["status"] == 200

    legacy = custody.local.call("agent.create", {
        "name": "remote-legacy", "scopes": ["access.request", "secret.use"], "ttl_seconds": 3600,
    }, admin_password=MASTER)
    monkeypatch.setenv("PASSD_AGENT_TOKEN", legacy["token"])
    req = command("access", "request", "pass://Personal/Echo/password", "--host", "127.0.0.1")
    assert command("access", "status", req["id"])["status"] == "pending"
    assert cli.main(["agent", "create", "blocked"]) == 2
    assert "forbidden_remote_op" in capsys.readouterr().err
    monkeypatch.delenv("PASSD_AGENT_TOKEN")
    assert cli.main(["capability", "list"]) == 2
    assert "forbidden_remote_op" in capsys.readouterr().err


def test_gateway_cli_uses_socket_override_without_unlock(tmp_path, monkeypatch):
    socket_path = tmp_path / "custody.sock"
    monkeypatch.setenv("PASSD_SOCKET", str(socket_path))

    def serve(path, listen, **kwargs):
        assert path == socket_path
        assert listen == ("127.0.0.1", 1234)
        assert kwargs == {"allow_cidrs": ["127.0.0.1/32", "::1/128"], "i_know_what_im_doing": True, "max_connections": 32}

    monkeypatch.setattr(cli, "serve_gateway", serve)
    assert cli.main([
        "--data-dir", str(tmp_path / "uninitialized"), "gateway", "--listen", "127.0.0.1:1234",
        "--allow-cidr", "127.0.0.1/32", "--allow-cidr", "::1/128", "--i-know-what-im-doing",
    ]) == 0


def test_endpoint_parsing():
    assert parse_endpoint("host:1234") == ("host", 1234)
    assert parse_endpoint("[fd7a:115c:a1e0::1]:1234") == ("fd7a:115c:a1e0::1", 1234)
    for endpoint in ["host", ":1234", "host:-1", "host:65536", "::1:1234"]:
        with pytest.raises(ValueError):
            parse_endpoint(endpoint)
