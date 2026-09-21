from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from passd.client import PassdClient, RpcError
from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "correct horse battery staple"
SECRET = "sk-capability-secret"


class CapabilityHandler(BaseHTTPRequestHandler):
    hits = 0

    def do_POST(self):
        type(self).hits += 1
        auth = self.headers.get("Authorization")
        content_type = self.headers.get("Content-Type")
        if auth != f"Bearer {SECRET}" or content_type != "application/json":
            self.send_response(401)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "echo_auth": auth, "path": self.path}).encode())

    def log_message(self, fmt, *args):
        pass


class CapabilityModelTest(unittest.TestCase):
    def setUp(self):
        CapabilityHandler.hits = 0
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
            {"vault": self.vault["id"], "title": "OpenRouter", "type": "login", "fields": {"password": SECRET}},
            admin_password=MASTER,
        )
        self.agent = self.client.call(
            "agent.create",
            {"name": "hermes-cap", "scopes": ["capability.request", "capability.invoke"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        self.token = self.agent["token"]

        self.http = HTTPServer(("127.0.0.1", 0), CapabilityHandler)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.http_thread.start()
        self.port = self.http.server_port
        self.put_capability()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.server.shutdown()
        self.server.server_close()
        self.service.close()
        self.tmp.cleanup()

    def put_capability(self, *, description="OpenRouter inference", path_prefix="/api/v1/chat/completions", static_headers=None):
        return self.client.call(
            "capability.put",
            {
                "id": "openrouter.infer",
                "description": description,
                "kind": "http_secret",
                "backing_uri": "pass://Personal/OpenRouter/password",
                "scheme": "http",
                "host": "127.0.0.1",
                "port": self.port,
                "methods": ["POST"],
                "path_prefix": path_prefix,
                "inject_header": "Authorization",
                "inject_prefix": "Bearer ",
                "static_headers": static_headers or {"Content-Type": "application/json"},
                "timeout_seconds": 5,
            },
            admin_password=MASTER,
        )

    def request(self, *, path="/api/v1/chat/completions", method="POST", uses=1):
        return self.client.call(
            "capability.request",
            {
                "capability_id": "openrouter.infer",
                "method": method,
                "path": path,
                "ttl_seconds": 300,
                "max_uses": uses,
            },
            agent_token=self.token,
            reason="Run the current inference task",
        )

    def approve(self, request_id):
        return self.client.call("access.approve", {"request": request_id}, admin_password=MASTER)

    def invoke(self, *, path="/api/v1/chat/completions", method="POST", body='{"model":"test"}'):
        return self.client.call(
            "capability.invoke",
            {"capability_id": "openrouter.infer", "method": method, "path": path, "body": body},
            agent_token=self.token,
            reason="Execute approved inference",
        )

    def test_public_catalog_hides_vault_item_and_backing_uri(self):
        catalog = self.client.call("capability.list", agent_token=self.token)
        self.assertEqual([c["id"] for c in catalog], ["openrouter.infer"])
        raw = json.dumps(catalog, sort_keys=True)
        self.assertNotIn("pass://", raw)
        self.assertNotIn("Personal", raw)
        cap = catalog[0]
        self.assertEqual(cap["kind"], "http_secret")
        self.assertEqual(cap["methods"], ["POST"])
        self.assertEqual(cap["path_prefix"], "/api/v1/chat/completions")
        self.assertTrue(cap["version"].startswith("cv1_"))

    def test_legacy_secret_token_cannot_enumerate_capability_catalog(self):
        legacy = self.client.call(
            "agent.create",
            {"name": "legacy-only", "scopes": ["access.request", "secret.use"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        with self.assertRaises(RpcError) as cm:
            self.client.call("capability.list", agent_token=legacy["token"])
        self.assertEqual(cm.exception.code, "permission_denied")


    def test_machine_identity_has_no_capability_authority_until_hitl(self):
        with self.assertRaises(RpcError) as cm:
            self.invoke()
        self.assertEqual(cm.exception.code, "permission_denied")
        req = self.request()
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["capability_id"], "openrouter.infer")
        self.assertTrue(req["authority_digest"].startswith("ad1_"))
        approved = self.approve(req["id"])
        self.assertTrue(approved["approval_digest"].startswith("ad1_"))
        result = self.invoke()
        self.assertEqual(result["status"], 200)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIn("<concealed by passd>", result["body"])

    def test_lease_is_exact_method_and_path(self):
        req = self.request(uses=3)
        self.approve(req["id"])
        for method, path in [
            ("GET", "/api/v1/chat/completions"),
            ("POST", "/api/v1/other"),
        ]:
            with self.assertRaises(RpcError) as cm:
                self.invoke(method=method, path=path)
            self.assertEqual(cm.exception.code, "permission_denied")
        ok = self.invoke()
        self.assertEqual(ok["status"], 200)

    def test_one_use_capability_lease_is_atomic_under_concurrency(self):
        req = self.request(uses=1)
        self.approve(req["id"])
        barrier = threading.Barrier(8)
        outcomes = []
        lock = threading.Lock()

        def worker():
            c = PassdClient(self.cfg.socket_path)
            barrier.wait()
            try:
                c.call(
                    "capability.invoke",
                    {"capability_id": "openrouter.infer", "method": "POST", "path": "/api/v1/chat/completions", "body": "{}"},
                    agent_token=self.token,
                    reason="concurrent exact capability",
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
        self.assertEqual(CapabilityHandler.hits, 1)

    def test_duplicate_capability_request_is_idempotent(self):
        a = self.request(uses=2)
        b = self.request(uses=2)
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(a["authority_digest"], b["authority_digest"])


    def test_noop_capability_rewrite_preserves_version_and_active_lease(self):
        req = self.request(uses=2)
        approved = self.approve(req["id"])
        before = self.client.call("capability.get", {"id": "openrouter.infer"}, admin_password=MASTER)
        rewritten = self.service.put_capability(before["definition"])
        self.assertEqual(rewritten["version"], before["version"])
        self.assertEqual(approved["capability_version"], rewritten["version"])
        self.assertEqual(self.invoke()["status"], 200)


    def test_capability_update_invalidates_approved_lease(self):
        req = self.request(uses=2)
        approved = self.approve(req["id"])
        old_version = approved["capability_version"]
        updated = self.put_capability(description="same id, changed contract", static_headers={"Content-Type": "application/json", "X-Contract": "v2"})
        self.assertNotEqual(updated["version"], old_version)
        with self.assertRaises(RpcError) as cm:
            self.invoke()
        self.assertEqual(cm.exception.code, "permission_denied")
        status = self.client.call("access.status", {"request": req["id"]}, agent_token=self.token)
        self.assertEqual(status["status"], "stale")

    def test_capability_change_between_request_and_approval_cannot_be_approved(self):
        req = self.request()
        self.put_capability(description="changed before human approval")
        with self.assertRaises(RpcError) as cm:
            self.approve(req["id"])
        self.assertEqual(cm.exception.code, "conflict")
        status = self.client.call("access.status", {"request": req["id"]}, agent_token=self.token)
        self.assertEqual(status["status"], "stale")

    def test_capability_version_is_root_keyed_not_plain_sha256_of_definition(self):
        cap = self.client.call("capability.get", {"id": "openrouter.infer"}, admin_password=MASTER)
        private = cap["definition"]
        raw_sha = hashlib.sha256(json.dumps(private, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertNotIn(raw_sha, cap["version"])

        # Same semantic definition under a different passd root key produces a
        # different opaque public version, preventing offline backing-selector guesses.
        tmp2 = tempfile.TemporaryDirectory()
        try:
            cfg2 = Config.initialize(Path(tmp2.name), "different-master")
            svc2 = PassdService(cfg2, cfg2.derive_and_verify("different-master"), allow_private_broker_targets=True)
            try:
                svc2.create_vault("Personal")
                svc2.put_item("Personal", "OpenRouter", {"password": SECRET})
                cap2 = svc2.put_capability(private)
                self.assertNotEqual(cap2["version"], cap["version"])
            finally:
                svc2.close()
        finally:
            tmp2.cleanup()

    def test_nonsecret_item_metadata_change_does_not_invalidate_credential_lease(self):
        req = self.request(uses=2)
        self.approve(req["id"])
        row = self.service.find_item("Personal", "OpenRouter")
        payload = self.service._item_payload(row)
        vrow = self.service.db.execute("SELECT * FROM vaults WHERE id=?", (row["vault_id"],)).fetchone()
        vkey = self.service._vault_key(vrow)
        ikey = self.service._item_key(row, vkey)
        from passd.crypto import seal_json
        changed = dict(payload)
        changed["note"] = "metadata changed after approval"
        changed["urls"] = ["https://example.com/new-metadata"]
        self.service.db.execute(
            "UPDATE items SET payload=? WHERE id=?",
            (seal_json(ikey, changed, aad=f"passd/item/{row['id']}/payload".encode()), row["id"]),
        )
        self.service.db.commit()
        self.assertEqual(self.invoke()["status"], 200)


    def test_same_item_content_rewrite_does_not_invalidate_lease_but_real_change_does(self):
        req = self.request(uses=3)
        self.approve(req["id"])
        # Re-encrypt identical semantic content. The lease must survive.
        row = self.service.find_item("Personal", "OpenRouter")
        before = self.service._item_version(row)
        payload = self.service._item_payload(row)
        # Force a fresh encryption envelope with identical plaintext.
        vrow = self.service.db.execute("SELECT * FROM vaults WHERE id=?", (row["vault_id"],)).fetchone()
        vkey = self.service._vault_key(vrow)
        ikey = self.service._item_key(row, vkey)
        from passd.crypto import seal_json
        self.service.db.execute("UPDATE items SET payload=? WHERE id=?", (seal_json(ikey, payload, aad=f"passd/item/{row['id']}/payload".encode()), row["id"]))
        self.service.db.commit()
        row2 = self.service.db.execute("SELECT * FROM items WHERE id=?", (row["id"],)).fetchone()
        self.assertEqual(before, self.service._item_version(row2))
        self.assertEqual(self.invoke()["status"], 200)

        # A real secret change must stale the remaining lease.
        changed = dict(payload)
        changed["fields"] = dict(payload["fields"])
        changed["fields"]["password"] = "sk-rotated"
        self.service.db.execute("UPDATE items SET payload=? WHERE id=?", (seal_json(ikey, changed, aad=f"passd/item/{row['id']}/payload".encode()), row["id"]))
        self.service.db.commit()
        with self.assertRaises(RpcError) as cm:
            self.invoke()
        self.assertEqual(cm.exception.code, "permission_denied")


if __name__ == "__main__":
    unittest.main()
