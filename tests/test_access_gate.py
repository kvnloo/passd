from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from passd.client import PassdClient, PassdSession, RpcError
from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "correct horse battery staple"
SECRET = "sk-hitl-secret"


class AuthHandler(BaseHTTPRequestHandler):
    hits = 0
    lock = threading.Lock()

    def do_GET(self):
        with self.lock:
            type(self).hits += 1
        auth = self.headers.get("Authorization")
        if auth != f"Bearer {SECRET}":
            self.send_response(401)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.path == "/echo":
            self.wfile.write(json.dumps({"authorization": auth}).encode())
        else:
            self.wfile.write(json.dumps({"ok": True}).encode())

    def log_message(self, fmt, *args):
        pass


class AccessGateTest(unittest.TestCase):
    def setUp(self):
        AuthHandler.hits = 0
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = Config.initialize(self.root, MASTER)
        self.service = PassdService(self.cfg, self.cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        self.server = PassdUnixServer(self.cfg.socket_path, self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = PassdClient(self.cfg.socket_path)
        self.vault = self.client.call("vault.create", {"name": "Personal"}, admin_password=MASTER)
        self.item = self.client.call(
            "item.put",
            {"vault": self.vault["id"], "title": "Critical API", "type": "login", "fields": {"password": SECRET}},
            admin_password=MASTER,
        )
        self.agent = self.client.call(
            "agent.create",
            {
                "name": "hermes",
                "scopes": ["access.request", "metadata.read", "secret.use"],
                "ttl_seconds": 3600,
            },
            admin_password=MASTER,
        )
        self.token = self.agent["token"]
        self.http = HTTPServer(("127.0.0.1", 0), AuthHandler)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.http_thread.start()
        self.host = "127.0.0.1"
        self.url = f"http://{self.host}:{self.http.server_port}/check"
        self.uri = "pass://Personal/Critical%20API/password"

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.server.shutdown()
        self.server.server_close()
        self.service.close()
        self.tmp.cleanup()

    def request_use(self, *, uses=1, ttl=300):
        return self.client.call(
            "access.request",
            {
                "uri": self.uri,
                "capability": "secret.use",
                "target_host": self.host,
                "ttl_seconds": ttl,
                "max_uses": uses,
            },
            agent_token=self.token,
            reason="Need the exact API credential for this task",
        )

    def approve(self, request_id: str, *, uses=None, ttl=None):
        params = {"request": request_id}
        if uses is not None:
            params["max_uses"] = uses
        if ttl is not None:
            params["ttl_seconds"] = ttl
        return self.client.call("access.approve", params, admin_password=MASTER)

    def broker(self):
        return self.client.call(
            "broker.http",
            {"uri": self.uri, "url": self.url, "header": "Authorization", "prefix": "Bearer "},
            agent_token=self.token,
            reason="Execute the approved API call",
        )

    def test_machine_key_authenticates_but_empty_until_hitl_approval(self):
        self.assertEqual(self.client.call("vault.list", agent_token=self.token), [])
        self.assertEqual(self.client.call("item.list", {"vault": "Personal"}, agent_token=self.token), [])

        req = self.request_use()
        self.assertEqual(req["status"], "pending")
        self.assertEqual(self.client.call("vault.list", agent_token=self.token), [])

        approved = self.approve(req["id"])
        self.assertTrue(approved["active"])
        vaults = self.client.call("vault.list", agent_token=self.token)
        self.assertEqual([v["name"] for v in vaults], ["Personal"])
        items = self.client.call("item.list", {"vault": "Personal"}, agent_token=self.token)
        self.assertEqual([i["title"] for i in items], ["Critical API"])

    def test_pending_request_does_not_probe_vault_existence(self):
        bad = self.client.call(
            "access.request",
            {
                "uri": "pass://DoesNotExist/DefinitelyNotReal/password",
                "capability": "secret.use",
                "target_host": self.host,
                "ttl_seconds": 300,
                "max_uses": 1,
            },
            agent_token=self.token,
            reason="Request a credential by exact selector",
        )
        self.assertEqual(bad["status"], "pending")
        with self.assertRaises(RpcError) as ctx:
            self.approve(bad["id"])
        self.assertEqual(ctx.exception.code, "not_found")
        status = self.client.call("access.status", {"request": bad["id"]}, agent_token=self.token)
        self.assertEqual(status["status"], "pending")

    def test_unapproved_or_wrong_selector_is_indistinguishable_permission_denied(self):
        for uri in (self.uri, "pass://Personal/NotARealItem/password"):
            with self.assertRaises(RpcError) as ctx:
                self.client.call(
                    "secret.resolve",
                    {"uri": uri},
                    agent_token=self.token,
                    reason="Try reveal without approval",
                )
            self.assertEqual(ctx.exception.code, "permission_denied")

    def test_use_only_token_cannot_request_reveal(self):
        with self.assertRaises(RpcError) as ctx:
            self.client.call(
                "access.request",
                {"uri": self.uri, "capability": "secret.reveal", "ttl_seconds": 300, "max_uses": 1},
                agent_token=self.token,
                reason="Would like plaintext",
            )
        self.assertEqual(ctx.exception.code, "permission_denied")

    def test_approval_is_exact_field_capability_host_and_use_budget(self):
        req = self.request_use(uses=1)
        approved = self.approve(req["id"])
        self.assertEqual(approved["uses_remaining"], 1)

        wrong_host_url = f"http://localhost:{self.http.server_port}/check"
        with self.assertRaises(RpcError) as ctx:
            self.client.call(
                "broker.http",
                {"uri": self.uri, "url": wrong_host_url, "header": "Authorization", "prefix": "Bearer "},
                agent_token=self.token,
                reason="Wrong host must not inherit permission",
            )
        self.assertEqual(ctx.exception.code, "permission_denied")

        ok = self.broker()
        self.assertEqual(ok["status"], 200)
        self.assertNotIn(SECRET, json.dumps(ok))
        with self.assertRaises(RpcError) as ctx:
            self.broker()
        self.assertEqual(ctx.exception.code, "permission_denied")
        self.assertEqual(AuthHandler.hits, 1)


    def test_broker_redacts_secret_if_upstream_echoes_it(self):
        req = self.request_use(uses=1)
        self.approve(req["id"])
        result = self.client.call(
            "broker.http",
            {"uri": self.uri, "url": f"http://127.0.0.1:{self.http.server_port}/echo", "header": "Authorization", "prefix": "Bearer "},
            agent_token=self.token,
            reason="upstream echo redaction test",
        )
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIn("<concealed by passd>", result["body"])

    def test_human_can_shorten_but_not_expand_requested_lease(self):
        req = self.request_use(uses=2, ttl=600)
        approved = self.approve(req["id"], uses=1, ttl=120)
        self.assertEqual(approved["max_uses"], 1)
        self.assertLessEqual(approved["expires_at"] - int(time.time()), 120)

        req2 = self.request_use(uses=2, ttl=120)
        approved2 = self.approve(req2["id"], uses=99, ttl=9999)
        self.assertEqual(approved2["max_uses"], 2)
        self.assertLessEqual(approved2["expires_at"] - int(time.time()), 120)

    def test_deny_revoke_and_expiry_remove_authorization(self):
        denied_req = self.request_use()
        self.client.call("access.deny", {"request": denied_req["id"], "note": "not for this task"}, admin_password=MASTER)
        self.assertEqual(self.client.call("access.status", {"request": denied_req["id"]}, agent_token=self.token)["status"], "denied")

        req = self.request_use(uses=2)
        self.approve(req["id"])
        self.client.call("access.revoke", {"request": req["id"]}, admin_password=MASTER)
        with self.assertRaises(RpcError):
            self.broker()

        req2 = self.request_use(uses=2, ttl=60)
        base = int(time.time())
        with mock.patch("passd.service.now", return_value=base):
            self.approve(req2["id"])
        with mock.patch("passd.service.now", return_value=base + 61):
            with self.assertRaises(RpcError) as ctx:
                self.broker()
            self.assertEqual(ctx.exception.code, "permission_denied")
            self.assertEqual(self.client.call("vault.list", agent_token=self.token), [])

    def test_one_use_grant_is_atomic_under_concurrency(self):
        req = self.request_use(uses=1)
        self.approve(req["id"])
        barrier = threading.Barrier(8)
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker():
            c = PassdClient(self.cfg.socket_path)
            barrier.wait()
            try:
                c.call(
                    "broker.http",
                    {"uri": self.uri, "url": self.url, "header": "Authorization", "prefix": "Bearer "},
                    agent_token=self.token,
                    reason="Concurrent one-shot lease test",
                )
                result = "ok"
            except RpcError as exc:
                result = exc.code
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(outcomes.count("permission_denied"), 7, outcomes)
        self.assertEqual(AuthHandler.hits, 1)

    def test_persistent_session_supports_many_requests_on_one_socket(self):
        with PassdSession(self.cfg.socket_path) as session:
            for _ in range(50):
                self.assertEqual(session.call("health")["version"], 3)


    def test_persistent_session_recovers_after_rpc_error(self):
        with PassdSession(self.cfg.socket_path) as session:
            with self.assertRaises(RpcError):
                session.call("does.not.exist")
            self.assertEqual(session.call("health")["version"], 3)

    def test_reveal_capable_key_still_needs_separate_hitl_lease(self):
        reveal_agent = self.client.call(
            "agent.create",
            {"name": "reveal-agent", "scopes": ["access.request", "metadata.read", "secret.reveal"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        token = reveal_agent["token"]
        with self.assertRaises(RpcError) as ctx:
            self.client.call("secret.resolve", {"uri": self.uri}, agent_token=token, reason="need plaintext")
        self.assertEqual(ctx.exception.code, "permission_denied")
        req = self.client.call(
            "access.request",
            {"uri": self.uri, "capability": "secret.reveal", "ttl_seconds": 300, "max_uses": 1},
            agent_token=token,
            reason="human-approved interactive login",
        )
        self.client.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
        self.assertEqual(self.client.call("secret.resolve", {"uri": self.uri}, agent_token=token, reason="human-approved interactive login"), SECRET)
        with self.assertRaises(RpcError):
            self.client.call("secret.resolve", {"uri": self.uri}, agent_token=token, reason="second attempt")

    def test_host_ceiling_is_additional_defense_in_depth(self):
        bounded = self.client.call(
            "agent.create",
            {"name": "bounded", "scopes": ["access.request", "secret.use"], "allowed_hosts": ["example.com"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        with self.assertRaises(RpcError) as ctx:
            self.client.call(
                "access.request",
                {"uri": self.uri, "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 1},
                agent_token=bounded["token"],
                reason="host outside machine-key ceiling",
            )
        self.assertEqual(ctx.exception.code, "permission_denied")

    def test_approved_lease_isolated_to_requesting_machine_identity(self):
        other = self.client.call(
            "agent.create",
            {"name": "other", "scopes": ["access.request", "metadata.read", "secret.use"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        req = self.client.call(
            "access.request",
            {"uri": self.uri, "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 2},
            agent_token=self.token,
            reason="owner isolation",
        )
        self.client.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
        self.assertEqual(self.client.call("vault.list", agent_token=other["token"]), [])
        with self.assertRaises(RpcError) as cm:
            self.client.call("access.status", {"request": req["id"]}, agent_token=other["token"])
        self.assertEqual(cm.exception.code, "not_found")
        with self.assertRaises(RpcError) as cm:
            self.client.call(
                "broker.http",
                {"uri": self.uri, "url": self.url, "header": "Authorization", "prefix": "Bearer "},
                agent_token=other["token"],
                reason="attempt cross-agent use",
            )
        self.assertEqual(cm.exception.code, "permission_denied")

    def test_approved_lease_is_bound_to_reviewed_item_version(self):
        self.service.put_item(
            self.vault["id"], "Rotating API", {"password": "version-one"},
            source={"kind": "test", "id": "rotating-1"},
        )
        uri = "pass://Personal/Rotating%20API/password"
        req = self.client.call(
            "access.request",
            {"uri": uri, "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 2},
            agent_token=self.token,
            reason="approve version one",
        )
        self.client.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
        self.service.put_item(
            self.vault["id"], "Rotating API", {"password": "version-two"},
            source={"kind": "test", "id": "rotating-1"},
        )
        with self.assertRaises(RpcError) as cm:
            self.client.call(
                "broker.http",
                {"uri": uri, "url": self.url, "header": "Authorization", "prefix": "Bearer "},
                agent_token=self.token,
                reason="attempt after rotation",
            )
        self.assertEqual(cm.exception.code, "permission_denied")
        status = self.client.call("access.status", {"request": req["id"]}, agent_token=self.token)
        self.assertEqual(status["status"], "stale")
        self.assertFalse(status["active"])

    def test_duplicate_pending_request_is_idempotent(self):
        params = {"uri": self.uri, "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 1}
        a = self.client.call("access.request", params, agent_token=self.token, reason="same request")
        b = self.client.call("access.request", params, agent_token=self.token, reason="same request")
        self.assertEqual(a["id"], b["id"])
        pending = self.client.call("access.status", {}, agent_token=self.token)
        self.assertEqual(len([x for x in pending if x["status"] == "pending"]), 1)

    def test_pending_hitl_queue_is_bounded_per_machine_identity(self):
        for i in range(32):
            self.client.call(
                "access.request",
                {"uri": f"pass://Personal/Unknown-{i}/password", "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 1},
                agent_token=self.token,
                reason=f"bounded request {i}",
            )
        with self.assertRaises(RpcError) as cm:
            self.client.call(
                "access.request",
                {"uri": "pass://Personal/Unknown-overflow/password", "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 1},
                agent_token=self.token,
                reason="overflow",
            )
        self.assertEqual(cm.exception.code, "conflict")

    def test_machine_api_key_rotation_preserves_identity_and_invalidates_old_key(self):
        rotated = self.client.call("agent.rotate", {"agent": self.agent["id"]}, admin_password=MASTER)
        self.assertEqual(rotated["id"], self.agent["id"])
        self.assertTrue(rotated["token"].startswith(self.agent["id"] + "."))
        with self.assertRaises(RpcError) as cm:
            self.client.call("vault.list", agent_token=self.token)
        self.assertEqual(cm.exception.code, "auth_error")
        self.assertEqual(self.client.call("vault.list", agent_token=rotated["token"]), [])

    def test_concurrent_hitl_approval_has_exactly_one_winner(self):
        req = self.client.call(
            "access.request",
            {"uri": self.uri, "capability": "secret.use", "target_host": self.host, "ttl_seconds": 300, "max_uses": 2},
            agent_token=self.token,
            reason="approval race",
        )
        outcomes = []
        lock = threading.Lock()

        def approve():
            try:
                self.client.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
                value = "ok"
            except RpcError as exc:
                value = exc.code
            with lock:
                outcomes.append(value)

        threads = [threading.Thread(target=approve) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(outcomes.count("conflict"), 7, outcomes)

    def test_agent_revocation_invalidates_api_key_immediately(self):
        self.client.call("agent.revoke", {"agent": "hermes"}, admin_password=MASTER)
        with self.assertRaises(RpcError) as ctx:
            self.client.call("vault.list", agent_token=self.token)
        self.assertEqual(ctx.exception.code, "auth_error")


if __name__ == "__main__":
    unittest.main()
