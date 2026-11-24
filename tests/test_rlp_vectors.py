"""Replay portable RLP cases through real RPC dispatch and a loopback sink."""

import hashlib
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import passd.service
from passd.config import Config
from passd.errors import PassdError
from passd.service import PassdService

VECTORS = Path(__file__).resolve().parents[1] / "spec" / "vectors"
CASES = sorted(VECTORS.glob("*.json"))


def test_vector_manifest():
    manifest = (VECTORS / "SHA256SUMS").read_text().splitlines()
    assert manifest == [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in CASES
    ]


@pytest.fixture
def broker(tmp_path, monkeypatch):
    clock = [1000]
    monkeypatch.setattr(passd.service, "now", lambda: clock[0])
    password = secrets.token_urlsafe(24)
    credential = secrets.token_urlsafe(24)
    hits = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append((self.command, self.path, self.headers.get("Authorization")))
            self.send_response(204)
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *args):
            pass

    config = Config.initialize(tmp_path, password)
    service = PassdService(config, config.derive_and_verify(password), allow_private_broker_targets=True)

    def admin(op, params):
        return service.handle({"op": op, "params": params, "admin_password": password})

    def put_item(revision=1, note=""):
        fields = {"password": f"{credential}-{revision}"}
        admin("item.put", {
            "vault": "agents", "title": "Fixture", "fields": fields, "note": note,
            "source": {"kind": "fixture", "id": "credential"},
        })

    try:
        with HTTPServer(("127.0.0.1", 0), Sink) as http:
            thread = threading.Thread(target=http.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                admin("vault.create", {"name": "agents"})
                put_item()
                admin("capability.put", {
                    "id": "fixture.use", "backing_uri": "pass://agents/Fixture/password",
                    "kind": "http_secret", "scheme": "http", "host": "127.0.0.1",
                    "port": http.server_port, "methods": ["POST", "GET"], "path_prefix": "/v1",
                    "inject_header": "Authorization", "inject_prefix": "Bearer ",
                })
                agent = admin("agent.create", {"name": "fixture"})
                yield clock, service, admin, agent, put_item, hits, credential
            finally:
                http.shutdown()
                thread.join()
    finally:
        service.close()


@pytest.mark.parametrize("path", CASES, ids=lambda path: path.stem)
def test_rlp_vector(path, broker):
    clock, service, admin, agent, put_item, hits, credential = broker
    vector = json.loads(path.read_text())
    assert vector["version"] == 1
    request_id = None

    def call(op, params):
        return service.handle({
            "op": op, "params": params, "agent_token": agent["token"], "reason": "Fixture run",
        })

    def invoke(**inputs):
        params = {"capability_id": "fixture.use", "method": "POST", "path": "/v1/use", **inputs}
        try:
            return {"status": call("capability.invoke", params)["status"]}
        except PassdError as exc:
            return {"error": exc.code}

    for step in vector["steps"]:
        clock[0] = step["now"]
        operation, inputs, expected = step["operation"], step["inputs"], step["expect"]
        before = len(hits)
        try:
            if operation == "request":
                result = call("capability.request", {
                    "capability_id": "fixture.use", "method": "POST", "path": "/v1/use",
                    "ttl_seconds": 60, "max_uses": 1, **inputs,
                })
                request_id = result["id"]
            elif operation == "approve":
                result = admin("access.approve", {"request": request_id, **inputs})
            elif operation == "status":
                result = call("access.status", {"request": request_id})
            elif operation == "invoke":
                result = invoke(**inputs)
            elif operation == "concurrent_invoke":
                count = inputs["count"]
                barrier = threading.Barrier(count, timeout=5)

                def contender(_):
                    barrier.wait()
                    return invoke()

                with ThreadPoolExecutor(max_workers=count) as pool:
                    result = list(pool.map(contender, range(count)))
            elif operation == "update_item":
                put_item(**inputs)
                result = {}
            elif operation == "revoke_token":
                admin("agent.revoke", {"agent": agent["id"]})
                result = {}
            else:
                pytest.fail(f"Unknown vector operation {operation}")
        except PassdError as exc:
            result = {"error": exc.code}

        if isinstance(expected, list):
            assert sorted(result, key=json.dumps) == sorted(expected, key=json.dumps)
            successful_invokes = sum("status" in outcome for outcome in expected)
        else:
            assert {key: result[key] for key in expected} == expected
            successful_invokes = int(operation == "invoke" and "status" in expected)
        assert hits[before:] == [("POST", "/v1/use", f"Bearer {credential}-1")] * successful_invokes
