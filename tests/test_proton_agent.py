from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import threading
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from passd import cli
from passd.client import PassdClient, RpcError
from passd.config import Config
from passd.errors import (
    PassdError, PermissionDenied, ProtonAgentAccessDenied, ProtonAgentAuthExpired,
    ProtonAgentDisabled, ProtonAgentItemNotFound, ProtonAgentReasonRequired,
    ProtonAgentUnavailable, ValidationError,
)
from passd.gateway import GatewayHandler, PassdGatewayServer
from passd.proton_agent import PAT_NAME, STATE_NAME, _redact_stderr
from passd.server import PassdHandler, PassdUnixServer
from passd.service import PassdService

MASTER = "proton-agent-test-master"
PAT = "dummy-proton-agent-pat-for-tests"
VALUE = "dummy-live-proton-field-for-tests"
REF = {"vault_name": "agents", "item_title": "API", "field": "password"}

FAKE = r'''
import json
import os
import sys
import time
from pathlib import Path

root = Path(__file__).parent
args = sys.argv[1:]
entry = {"argv": args, "env": dict(os.environ), "stdin_eof": sys.stdin.read() == ""}
fd = os.open(root / "calls.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, (json.dumps(entry) + "\n").encode())
os.close(fd)
plan = json.loads((root / "plan.json").read_text())
op = args[0]
reply = plan.get(op, {})
time.sleep(reply.get("delay", 0))
if reply.get("code", 0):
    sys.stdout.write(reply.get("stdout", ""))
    sys.stderr.write(reply.get("stderr", ""))
    sys.exit(reply["code"])
session = Path(os.environ["PROTON_PASS_SESSION_DIR"]) / "agent-session"
if op == "login":
    if not os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN"):
        sys.stderr.write("invalid token")
        sys.exit(1)
    session.write_text("fake agent session")
elif op == "logout":
    session.unlink(missing_ok=True)
elif not session.exists():
    sys.stderr.write("invalid session")
    sys.exit(1)
elif op == "item":
    if not os.environ.get("PROTON_PASS_AGENT_REASON"):
        sys.stderr.write("reason required")
        sys.exit(1)
    assert "--field" in args and "--show-secrets" not in args
    assert args[-2:] == ["--output", "human"]
    sys.stdout.write(reply.get("stdout", plan["value"] + "\n"))
'''


def run_server(stack, server):
    stack.callback(server.server_close)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    stack.callback(thread.join, 5)
    stack.callback(server.shutdown)
    return server


class ServiceClient:
    """Exercise service policy directly; socket integration uses network_custody."""

    def __init__(self, service):
        self.service = service
        self.remote = ""

    def call(self, op, params=None, **kwargs):
        try:
            return self.service.handle({"op": op, "params": params or {}, **kwargs})
        except PassdError as exc:
            raise RpcError(exc.code, str(exc)) from None


@pytest.fixture
def custody(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="pa-") as temp, ExitStack() as stack:
        root = Path(temp)
        fake_dir = root / "fake"
        fake_dir.mkdir()
        binary = fake_dir / "pass-cli"
        binary.write_text("#!" + sys.executable + "\n" + FAKE)
        binary.chmod(0o700)
        plan = fake_dir / "plan.json"
        plan.write_text(json.dumps({"value": VALUE}))
        cfg = Config.initialize(root / "state", MASTER)
        cfg.proton_agent_binary = str(binary)
        cfg.proton_agent_name = "passd-test-agent"
        service = PassdService(cfg, cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        stack.callback(service.close)
        local = ServiceClient(service)
        service.set_proton_agent_pat(PAT)
        service.proton_agent.login()

        hits = []

        definition = {
            "id": "api.call", "source": "proton-agent", "ref": REF,
            "description": "Scoped API call", "scheme": "http", "host": "127.0.0.1",
            "port": 12345, "methods": ["POST"], "path_prefix": "/api",
            "inject_prefix": "Bearer ",
        }
        service.put_capability(definition)
        agent = local.call("agent.create", {"name": "caller"}, admin_password=MASTER)
        token = agent["token"]

        def approve(uses=3):
            request = local.call("capability.request", {
                "capability_id": "api.call", "method": "POST", "path": "/api/call", "max_uses": uses,
            }, agent_token=token, reason="test live source")
            return local.call("access.approve", {"request": request["id"]}, admin_password=MASTER)

        def invoke(client=None, **overrides):
            return (client or context.local).call("capability.invoke", {
                "capability_id": "api.call", "method": "POST", "path": "/api/call", **overrides,
            }, agent_token=token, reason="approved live call")

        def calls(op=None):
            entries = [json.loads(line) for line in (fake_dir / "calls.jsonl").read_text().splitlines()]
            return [e for e in entries if op is None or e["argv"][0] == op]

        def reply(op, **reply):
            obj = json.loads(plan.read_text())
            obj[op] = reply
            plan.write_text(json.dumps(obj))

        execute_http = service._execute_http

        def inject(url, *, headers, secret_text, **kwargs):
            hits.append((url.rsplit(":12345", 1)[-1], headers.get("Authorization")))
            return {"status": 200, "headers": {}, "body": service._redact(json.dumps({"auth": headers.get("Authorization")}), secret_text)}

        monkeypatch.setattr(service, "_execute_http", inject)
        context = SimpleNamespace(
            root=root, fake=fake_dir, binary=binary, plan=plan, cfg=cfg, service=service,
            source=service.proton_agent, local=local, token=token, definition=definition,
            hits=hits, approve=approve, invoke=invoke, calls=calls, reply=reply, execute_http=execute_http,
        )
        yield context


@pytest.fixture
def network_custody(custody, monkeypatch):
    c = custody
    with ExitStack() as stack:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                auth = self.headers.get("Authorization")
                c.hits.append((self.path, auth))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"auth": auth}).encode())

            def log_message(self, *args):
                pass

        http = run_server(stack, HTTPServer(("127.0.0.1", 0), Handler))
        run_server(stack, PassdUnixServer(c.cfg.socket_path, c.service))
        monkeypatch.setattr(c.service, "_execute_http", c.execute_http)
        c.local = PassdClient(c.cfg.socket_path, remote="")
        c.definition["port"] = http.server_port
        c.service.put_capability(c.definition)
        yield c


@pytest.mark.parametrize("transport", ["service", "network"])
def test_minimal_environment_reason_and_live_injection(custody, request, transport, monkeypatch, caplog):
    c = request.getfixturevalue("network_custody") if transport == "network" else custody
    monkeypatch.setenv("PROTON_PASS_SESSION_DIR", "/bogus-human-session")
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "bogus-parent-pat")
    monkeypatch.setenv("PROTON_PASS_AGENT_REASON", "bogus-parent-reason")
    monkeypatch.setenv("PROTON_PASS_OTHER", "bogus-parent-setting")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/bogus-human-home")
    monkeypatch.setenv("PASSD_MASTER_PASSWORD", MASTER)
    c.source.login()
    lease = c.approve()
    assert len(c.calls("item")) == 0  # Approval never fetches live credentials.
    result = c.invoke()
    assert c.hits == [("/api/call", "Bearer " + VALUE)]
    assert VALUE not in json.dumps(result)
    assert "<concealed by passd>" in result["body"]
    for entry in c.calls():
        env, argv = entry["env"], entry["argv"]
        assert entry["stdin_eof"]
        assert env["PROTON_PASS_SESSION_DIR"] == str(c.cfg.data_dir / "proton-agent/session")
        assert env["HOME"] == str(c.cfg.data_dir / "proton-agent")
        # Python may add LC_CTYPE itself when started without locale settings.
        assert set(env) <= {"PATH", "HOME", "LANG", "LC_CTYPE", "PROTON_PASS_SESSION_DIR",
                            "PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PROTON_PASS_AGENT_REASON"}
        assert PAT not in json.dumps(argv)
        assert "--show-secrets" not in argv
        if argv[0] == "login":
            assert env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == PAT
        else:
            assert "PROTON_PASS_PERSONAL_ACCESS_TOKEN" not in env
        if argv[0] == "item":
            assert "--field" in argv
            assert "capability=api.call" in env["PROTON_PASS_AGENT_REASON"]
            assert "lease=" + lease["id"] in env["PROTON_PASS_AGENT_REASON"]
            assert "agent=passd-test-agent" in env["PROTON_PASS_AGENT_REASON"]
            assert "purpose=Scoped API call" in env["PROTON_PASS_AGENT_REASON"]
        else:
            assert "PROTON_PASS_AGENT_REASON" not in env
    audit = c.service.list_audit()
    invocation = next(a for a in audit if a["operation"] == "capability.invoke")
    assert invocation["detail"]["source"] == "proton-agent"
    assert invocation["detail"]["lease_id"] == lease["id"]
    assert invocation["detail"]["outcome"] == "allowed"
    for secret in (PAT, VALUE):
        assert secret not in json.dumps(audit)
        assert secret not in caplog.text
        for file in c.cfg.data_dir.glob("vault.sqlite3*"):
            assert secret.encode() not in file.read_bytes()


def test_no_cache_and_revocation_prevents_resolution(custody):
    c = custody
    lease = c.approve(uses=3)
    c.invoke()
    obj = json.loads(c.plan.read_text())
    obj["value"] = "dummy-rotated-live-field"
    c.plan.write_text(json.dumps(obj))
    c.invoke()
    assert c.hits[-1][1] == "Bearer dummy-rotated-live-field"
    assert len(c.calls("item")) == 2
    c.local.call("access.revoke", {"request": lease["id"]}, admin_password=MASTER)
    with pytest.raises(RpcError) as error:
        c.invoke()
    assert error.value.code == "permission_denied"
    assert len(c.calls("item")) == 2


def test_live_one_use_budget_is_atomic(custody):
    c = custody
    c.approve(uses=1)
    barrier = threading.Barrier(8)
    outcomes = []

    def invoke():
        barrier.wait()
        try:
            c.invoke()
            outcomes.append("ok")
        except RpcError as error:
            outcomes.append(error.code)

    threads = [threading.Thread(target=invoke) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert outcomes.count("ok") == 1
    assert outcomes.count("permission_denied") == 7
    assert len(c.calls("item")) == 1


@pytest.mark.parametrize("check", ["unapproved", "expiry", "budget", "path", "method", "identity", "destination"])
def test_authority_checks_precede_live_resolution(custody, monkeypatch, check):
    c = custody
    if check != "unapproved":
        lease = c.approve(uses=1)
    if check == "expiry":
        monkeypatch.setattr("passd.service.now", lambda: lease["expires_at"])
    elif check == "budget":
        c.invoke()
    elif check == "identity":
        c.local.call("agent.revoke", {"agent": "caller"}, admin_password=MASTER)
    elif check == "destination":
        monkeypatch.setattr(c.service, "_validate_target", lambda *a, **kw: (_ for _ in ()).throw(PermissionDenied("blocked target")))
    before = len(c.calls("item"))
    overrides = {"path": "/elsewhere"} if check == "path" else {"method": "GET"} if check == "method" else {}
    with pytest.raises(RpcError):
        c.invoke(**overrides)
    assert len(c.calls("item")) == before


@pytest.mark.parametrize("stderr,denial", [
    ("PAT expired", ProtonAgentAuthExpired), ("session expired", ProtonAgentAuthExpired),
    ("unauthorized 401", ProtonAgentAuthExpired), ("invalid token", ProtonAgentAuthExpired),
    ("invalid session", ProtonAgentAuthExpired), ("forbidden 403", ProtonAgentAccessDenied),
    ("no access", ProtonAgentAccessDenied), ("permission denied", ProtonAgentAccessDenied),
    ("not granted", ProtonAgentAccessDenied), ("item not found 404", ProtonAgentItemNotFound),
    ("no item", ProtonAgentItemNotFound), ("reason is mandatory", ProtonAgentReasonRequired),
    ("network failure", ProtonAgentUnavailable), ("unrecognized failure", ProtonAgentUnavailable),
])
def test_error_mapping_scrubs_output(custody, stderr, denial, caplog):
    c = custody
    c.reply("item", code=1, stderr=stderr + " " + PAT + " " + VALUE, stdout=VALUE + "\n")
    with pytest.raises(denial) as error:
        c.source.resolve("api.call", "req_fake", REF)
    assert PAT not in str(error.value) and VALUE not in str(error.value)
    assert PAT not in caplog.text and VALUE not in caplog.text
    audit = json.dumps(c.service.list_audit())
    assert PAT not in audit and VALUE not in audit
    if denial is ProtonAgentAuthExpired:
        alerts = (c.cfg.data_dir / "alerts.log").read_text()
        assert "proton_agent.auth_expired" in alerts
        assert '"severity":"alert"' in alerts
        assert PAT not in alerts and VALUE not in alerts


@pytest.mark.parametrize("transport", ["service", "network"])
def test_expiry_alert_hook_no_fallback_and_typed_rpc_gateway(custody, request, transport):
    c = request.getfixturevalue("network_custody") if transport == "network" else custody
    c.service.create_vault("agents")
    c.service.put_item("agents", "API", {"password": "dummy-legacy-fallback"}, source={"kind": "proton", "id": "legacy"})
    hook = c.fake / "alert.py"
    hook.write_text("import os\nfrom pathlib import Path\nPath(__file__).with_suffix('.out').write_text(os.environ['PASSD_ALERT_EVENT'])\n")
    c.cfg.alert_command = [sys.executable, str(hook)]
    c.reply("item", code=1, stderr="expired PAT " + PAT, stdout=VALUE)
    c.approve(uses=2)
    with ExitStack() as stack:
        remote = c.local
        if transport == "network":
            gateway = run_server(stack, PassdGatewayServer(("127.0.0.1", 0), c.cfg.socket_path))
            remote = PassdClient(remote=f"127.0.0.1:{gateway.server_address[1]}")
        for client in (c.local, remote):
            with pytest.raises(RpcError) as error:
                c.invoke(client=client)
            assert error.value.code == "proton_agent_auth_expired"
            assert PAT not in str(error.value) and VALUE not in str(error.value)
    assert len(c.calls("login")) == 1  # Never retry login automatically.
    assert len(c.calls("item")) == 2
    assert c.hits == []
    assert hook.with_suffix(".out").read_text() == "proton_agent.auth_expired"
    audit = c.service.list_audit()
    assert any(a["operation"] == "proton_agent.auth_expired" and a["detail"]["severity"] == "alert" for a in audit)
    assert any(a["detail"].get("denial_type") == "ProtonAgentAuthExpired" for a in audit)
    for secret in (PAT, VALUE, "dummy-legacy-fallback"):
        assert secret not in json.dumps(audit)
        assert secret not in (c.cfg.data_dir / "alerts.log").read_text()


@pytest.mark.parametrize("stderr,code", [
    ("expired PAT", "proton_agent_auth_expired"),
    ("forbidden", "proton_agent_access_denied"),
])
def test_typed_denials_on_rpc_and_gateway_wire_without_sockets(custody, monkeypatch, stderr, code):
    c = custody
    c.approve()
    c.reply("item", code=1, stderr=stderr + " " + PAT, stdout=VALUE)

    class MemorySocket:
        def __init__(self, incoming):
            self.reader = io.BytesIO(incoming)
            self.received = bytearray()

        def makefile(self, *args):
            return self.reader

        def sendall(self, data):
            self.received.extend(data)

        def settimeout(self, timeout):
            pass

        def connect(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    request = json.dumps({"op": "capability.invoke", "agent_token": c.token,
                          "params": {"capability_id": "api.call", "method": "POST", "path": "/api/call"},
                          "reason": "test denial wire"}).encode() + b"\n"
    local = MemorySocket(request)
    PassdHandler(local, "local", SimpleNamespace(service=c.service))
    assert json.loads(local.received)["error"]["code"] == code
    remote = MemorySocket(request)
    monkeypatch.setattr("passd.gateway.socket.socket", lambda *a, **kw: MemorySocket(bytes(local.received)))
    GatewayHandler(remote, ("127.0.0.1", 1234), SimpleNamespace(socket_path=c.cfg.socket_path))
    assert json.loads(remote.received)["error"]["code"] == code
    for wire in (local, remote):
        assert PAT.encode() not in wire.received and VALUE.encode() not in wire.received


@pytest.mark.parametrize("failure", ["timeout", "missing"])
def test_timeout_and_missing_binary(custody, failure):
    c = custody
    if failure == "timeout":
        c.source.timeout = 0.05
        c.reply("item", delay=1, stdout=VALUE, stderr=PAT)
    else:
        c.source.binary = str(c.fake / "nonexistent-pass-cli")
    with pytest.raises(ProtonAgentUnavailable) as error:
        c.source.resolve("api.call", "req_fake", REF)
    assert PAT not in str(error.value) and VALUE not in str(error.value)
    assert error.value.__suppress_context__ or error.value.__context__ is None


def test_disable_wipes_session_persists_and_enable_requires_login(custody):
    c = custody
    c.approve(uses=3)
    session = c.source.session_dir
    (session / "extra").write_text("dummy-session-data")
    c.local.call("proton-agent.disable", admin_password=MASTER)
    assert not session.exists()
    assert c.calls("logout")[-1]["argv"] == ["logout", "--force"]
    before = len(c.calls())
    with pytest.raises(RpcError) as error:
        c.invoke()
    assert error.value.code == "proton_agent_disabled"
    assert len(c.calls()) == before
    other = PassdService(c.cfg, c.cfg.derive_and_verify(MASTER))
    try:
        with pytest.raises(ProtonAgentDisabled):
            other.proton_agent.resolve("api.call", "req_fake", REF)
    finally:
        other.close()
    c.local.call("proton-agent.enable", admin_password=MASTER)
    with pytest.raises(RpcError) as expired:
        c.invoke()
    assert expired.value.code == "proton_agent_auth_expired"
    c.local.call("proton-agent.login", admin_password=MASTER)
    assert c.invoke()["status"] == 200


def test_disable_still_wipes_when_logout_fails(custody):
    c = custody
    c.reply("logout", code=1, stderr="network failed")
    assert c.source.disable()["disabled"] is True
    assert not c.source.session_dir.exists()
    with pytest.raises(ProtonAgentDisabled):
        c.source.resolve("api.call", "req_fake", REF)


@pytest.mark.parametrize("mode", [0o750, 0o707, 0o777])
def test_insecure_session_permissions_refused(custody, mode):
    c = custody
    assert stat.S_IMODE(c.source.session_dir.stat().st_mode) == 0o700
    c.source.session_dir.chmod(mode)
    before = len(c.calls())
    with pytest.raises(ProtonAgentUnavailable, match="owner-only"):
        c.source.resolve("api.call", "req_fake", REF)
    assert len(c.calls()) == before


def test_wrong_session_owner_and_symlink_refused(custody, monkeypatch):
    c = custody
    monkeypatch.setattr("passd.proton_agent.os.getuid", lambda: c.source.session_dir.stat().st_uid + 1)
    with pytest.raises(ProtonAgentUnavailable, match="current uid"):
        c.source.resolve("api.call", "req_fake", REF)
    monkeypatch.undo()
    c.source.logout()
    c.source.session_dir.rmdir()
    external = c.root / "outside"
    external.mkdir(mode=0o700)
    c.source.session_dir.symlink_to(external, target_is_directory=True)
    with pytest.raises(ProtonAgentUnavailable):
        c.source.resolve("api.call", "req_fake", REF)
    c.source.disable()
    assert external.is_dir()
    assert not c.source.session_dir.is_symlink()


def test_disable_does_not_follow_replaced_parent(custody):
    c = custody
    external = c.root / "external"
    (external / "session").mkdir(parents=True)
    sentinel = external / "session" / "sentinel"
    sentinel.write_text("dummy-file-must-survive")
    c.source.state_dir.rename(c.root / "original-session")
    c.source.state_dir.symlink_to(external, target_is_directory=True)
    before = len(c.calls())
    with pytest.raises(ProtonAgentUnavailable, match="safely wipe"):
        c.source.disable()
    assert sentinel.read_text() == "dummy-file-must-survive"
    assert len(c.calls()) == before
    with pytest.raises(ProtonAgentDisabled):
        c.source.resolve("api.call", "req_fake", REF)


def test_pat_unreachable_through_catalogs_capabilities_and_rpc(custody):
    c = custody
    for name in (PAT_NAME, STATE_NAME):
        for uri in (f"pass://internal/{name}/password", f"pass://{name}/PAT/password"):
            with pytest.raises(RpcError):
                c.local.call("secret.resolve", {"uri": uri}, admin_password=MASTER)
            with pytest.raises(ValidationError, match="internal"):
                c.service.put_capability({**c.definition, "source": "stored", "ref": None, "backing_uri": uri})
        with pytest.raises(ValidationError, match="internal"):
            c.service.put_capability({**c.definition, "ref": {**REF, "item_title": name}})
    for op in ("vault.list", "capability.list", "audit.list", "proton-agent.status"):
        assert PAT not in json.dumps(c.local.call(op, admin_password=MASTER))
    assert c.local.call("vault.list", admin_password=MASTER) == []
    for op in ("proton-agent.status", "proton-agent.login", "proton-agent.set-pat", "proton-agent.enable"):
        with pytest.raises(RpcError) as error:
            c.local.call(op, {"pat": "dummy-overwrite"}, agent_token=c.token)
        assert error.value.code == "permission_denied"
    with pytest.raises(RpcError):
        c.local.call("proton-agent.get-pat", admin_password=MASTER)
    assert c.service._get_internal_secret(PAT_NAME) == PAT


def test_legacy_reveal_and_use_leases_cannot_reach_pat(custody):
    c = custody
    legacy = c.local.call("agent.create", {
        "name": "legacy", "scopes": ["access.request", "metadata.read", "secret.use", "secret.reveal"],
    }, admin_password=MASTER)
    uri = f"pass://internal/{PAT_NAME}/password"
    for capability in ("secret.use", "secret.reveal"):
        params = {"uri": uri, "capability": capability}
        if capability == "secret.use":
            params["target_host"] = "127.0.0.1"
        pending = c.local.call("access.request", params, agent_token=legacy["token"], reason="test internal isolation")
        with pytest.raises(RpcError) as error:
            c.local.call("access.approve", {"request": pending["id"]}, admin_password=MASTER)
        assert error.value.code == "not_found"
    assert c.local.call("vault.list", agent_token=legacy["token"]) == []
    assert c.local.call("item.list", {"vault": "internal"}, agent_token=legacy["token"]) == []
    with pytest.raises(RpcError):
        c.local.call("secret.resolve", {"uri": uri}, agent_token=legacy["token"], reason="test reveal")
    before = len(c.calls())
    with pytest.raises(RpcError):
        c.local.call("broker.http", {"uri": uri, "url": "http://127.0.0.1/"},
                     agent_token=legacy["token"], reason="test use")
    assert len(c.calls()) == before


def test_no_ambient_pat_and_default_binary_resolves_to_fake(custody, monkeypatch):
    c = custody
    monkeypatch.setenv("PATH", str(c.fake))
    c.source.binary = "pass-cli"
    assert c.source.resolve("api.call", "req_fake", REF) == VALUE
    c.service.db.execute("DELETE FROM internal_secrets WHERE name=?", (PAT_NAME,))
    c.service.db.commit()
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "dummy-parent-pat")
    before = len(c.calls())
    with pytest.raises(ProtonAgentUnavailable, match="PAT is not set"):
        c.source.login()
    assert len(c.calls()) == before


def test_ref_changes_invalidate_lease_and_are_private(custody):
    c = custody
    lease = c.approve()
    catalog = c.local.call("capability.list", agent_token=c.token)
    assert "ref" not in catalog[0] and "agents" not in json.dumps(catalog)
    definition = {**c.definition, "ref": {"share_id": "share-test", "item_id": "item-test", "field": "password"}}
    changed = c.service.put_capability(definition)
    assert changed["version"] != lease["capability_version"]
    with pytest.raises(RpcError):
        c.invoke()
    assert c.calls("item") == []
    c.approve()
    c.invoke()
    argv = c.calls("item")[-1]["argv"]
    assert argv[argv.index("--share-id") + 1] == "share-test"
    assert argv[argv.index("--item-id") + 1] == "item-test"


def test_stored_capability_approval_and_rotation_remain_compatible(custody):
    c = custody
    c.service.create_vault("Stored")
    source = {"kind": "test", "id": "stored-credential"}
    c.service.put_item("Stored", "API", {"password": "dummy-stored-value"}, source=source)
    definition = {**c.definition, "source": "stored", "backing_uri": "pass://Stored/API/password"}
    del definition["ref"]
    before = c.service.put_capability(definition)
    lease = c.approve(uses=3)
    assert c.invoke()["status"] == 200
    private = c.service.get_capability("api.call", include_definition=True)["definition"]
    assert c.service.put_capability(private)["version"] == before["version"]
    c.service.put_item("Stored", "API", {"password": "dummy-stored-value"}, source=source, note="metadata edit")
    assert c.invoke()["status"] == 200
    c.service.put_item("Stored", "API", {"password": "dummy-stored-rotation"}, source=source)
    with pytest.raises(RpcError) as error:
        c.invoke()
    assert error.value.code == "permission_denied"
    assert c.local.call("access.status", {"request": lease["id"]}, agent_token=c.token)["status"] == "stale"
    assert c.calls("item") == []


def test_single_newline_and_reason_sanitization(custody):
    c = custody
    c.reply("item", stdout="  dummy-value\n\n")
    value = c.source.resolve("api.call", "req_fake", REF, purpose="line one\r\nline two\x00" + "x" * 500)
    assert value == "  dummy-value\n"
    reason = c.calls("item")[-1]["env"]["PROTON_PASS_AGENT_REASON"]
    assert not any(char in reason for char in "\r\n\x00")
    assert len(reason) <= 240
    assert PAT not in _redact_stderr(("expired " + PAT + VALUE).encode(), PAT, VALUE)


def test_cli_stdin_pat_status_management_and_source_definition(custody, monkeypatch, capsys):
    c = custody
    monkeypatch.setattr(cli, "get_client", lambda *args: c.local)
    monkeypatch.setattr(cli, "password_from_env", lambda **kw: MASTER)
    monkeypatch.setattr(sys, "stdin", io.StringIO("dummy-rotated-pat-from-stdin\n"))
    monkeypatch.setenv("PROTON_PASS_PERSONAL_ACCESS_TOKEN", "dummy-parent-token-must-not-be-used")
    prefix = ["--data-dir", str(c.cfg.data_dir)]
    for command in ("set-pat", "login", "status", "logout", "disable", "enable"):
        assert cli.main([*prefix, "proton-agent", command]) == 0
        output = json.loads(capsys.readouterr().out)
        assert "dummy-rotated-pat-from-stdin" not in json.dumps(output)
        if command == "status":
            assert output["agent_name"] == "passd-test-agent"
            assert output["pat_set"] is True and output["session_ok"] is True
            assert output["last_login_time"] and output["expires_at"] is None
    assert c.calls("login")[-1]["env"]["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "dummy-rotated-pat-from-stdin"
    assert cli.main([*prefix, "capability", "put-http", "cli.call", "--source", "proton-agent",
                     "--vault-name", "agents", "--item-title", "API", "--field", "password",
                     "--host", "example.com", "--path-prefix", "/v1"]) == 0
    assert json.loads(capsys.readouterr().out)["id"] == "cli.call"
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["proton-agent", "set-pat", PAT])


def test_stdin_terminal_echo_is_disabled_and_restored(monkeypatch):
    import termios

    class Terminal(io.StringIO):
        def isatty(self):
            return True

        def fileno(self):
            return 7

    flags = [0, 0, 0, termios.ECHO | termios.ICANON, 0, 0, []]
    updates = []
    monkeypatch.setattr(sys, "stdin", Terminal("dummy-tty-token\n"))
    monkeypatch.setattr(termios, "tcgetattr", lambda fd: list(flags))
    monkeypatch.setattr(termios, "tcsetattr", lambda fd, when, attrs: updates.append((fd, when, attrs)))
    assert cli.read_pat_stdin() == "dummy-tty-token"
    assert updates[0][0] == 7
    assert not updates[0][2][3] & termios.ECHO
    assert updates[-1][2] == flags


def test_config_override_and_zip_deprecation(custody, monkeypatch, capsys):
    c = custody
    monkeypatch.setattr(cli, "get_client", lambda *args: c.local)
    obj = json.loads(c.cfg.path.read_text())
    obj["proton_agent"] = {"binary": str(c.binary), "name": "configured-agent", "timeout_seconds": 2}
    obj["alert_command"] = [sys.executable, "alert.py"]
    c.cfg.path.write_text(json.dumps(obj))
    loaded = Config.load(c.cfg.data_dir)
    assert loaded.proton_agent_binary == str(c.binary)
    assert loaded.proton_agent_name == "configured-agent"
    assert loaded.proton_agent_timeout == 2
    assert loaded.alert_command == [sys.executable, "alert.py"]
    export = c.root / "export.json"
    export.write_text('{"vaults":{}}')
    monkeypatch.setattr(cli, "password_from_env", lambda **kw: MASTER)
    assert cli.main(["--data-dir", str(c.cfg.data_dir), "sync", "import-proton", str(export)]) == 0
    assert "deprecated" in capsys.readouterr().err
