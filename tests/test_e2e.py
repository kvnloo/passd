from __future__ import annotations

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
SECRET = "sk-test-super-secret"


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization")
        if auth != f"Bearer {SECRET}":
            self.send_response(401); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"authenticated": True}).encode())

    def log_message(self, format, *args):
        pass


class PassdE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = Config.initialize(self.root, MASTER)
        self.service = PassdService(self.cfg, self.cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        self.server = PassdUnixServer(self.cfg.socket_path, self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.client = PassdClient(self.cfg.socket_path)
        self.http = HTTPServer(("127.0.0.1", 0), EchoHandler)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True); self.http_thread.start()

    def tearDown(self):
        self.http.shutdown(); self.http.server_close()
        self.server.shutdown(); self.server.server_close(); self.service.close(); self.tmp.cleanup()

    def test_hitl_use_only_agent_brokers_but_cannot_reveal(self):
        vault = self.client.call("vault.create", {"name": "Agents"}, admin_password=MASTER)
        self.client.call("item.put", {"vault": vault["id"], "title": "OpenRouter", "type": "login", "fields": {"password": SECRET}}, admin_password=MASTER)
        agent = self.client.call("agent.create", {"name": "hermes", "scopes": ["access.request", "metadata.read", "secret.use"], "ttl_seconds": 3600}, admin_password=MASTER)
        token = agent["token"]
        uri = "pass://Agents/OpenRouter/password"

        self.assertEqual(self.client.call("vault.list", agent_token=token), [])
        req = self.client.call("access.request", {"uri": uri, "capability": "secret.use", "target_host": "127.0.0.1", "ttl_seconds": 300, "max_uses": 1}, agent_token=token, reason="test API call")
        self.client.call("access.approve", {"request": req["id"]}, admin_password=MASTER)

        with self.assertRaises(RpcError) as ctx:
            self.client.call("secret.resolve", {"uri": uri}, agent_token=token, reason="trying direct reveal")
        self.assertEqual(ctx.exception.code, "permission_denied")

        result = self.client.call("broker.http", {"uri": uri, "url": f"http://127.0.0.1:{self.http.server_port}/check", "method": "GET", "header": "Authorization", "prefix": "Bearer "}, agent_token=token, reason="test authenticated API call")
        self.assertEqual(result["status"], 200)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_admin_can_reveal(self):
        self.client.call("vault.create", {"name": "Personal"}, admin_password=MASTER)
        self.client.call("item.put", {"vault": "Personal", "title": "Example", "fields": {"password": SECRET}}, admin_password=MASTER)
        value = self.client.call("secret.resolve", {"uri": "pass://Personal/Example/password"}, admin_password=MASTER)
        self.assertEqual(value, SECRET)


if __name__ == "__main__":
    unittest.main()
