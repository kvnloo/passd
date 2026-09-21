from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from passd.client import PassdClient, RpcError
from passd.config import Config
from passd.server import MAX_REQUEST, PassdUnixServer
from passd.service import PassdService

MASTER = "master-password"


class SecurityPropertiesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "state"
        self.cfg = Config.initialize(self.root, MASTER)
        self.service = PassdService(self.cfg, self.cfg.derive_and_verify(MASTER))
        self.server = PassdUnixServer(self.cfg.socket_path, self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = PassdClient(self.cfg.socket_path)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.service.close()
        self.tmp.cleanup()

    def test_state_and_socket_permissions_are_owner_only(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg.path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg.db_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg.socket_path).st_mode), 0o600)

    def test_agent_can_exist_with_zero_resource_grants(self):
        agent = self.client.call(
            "agent.create",
            {"name": "empty", "scopes": ["access.request", "metadata.read", "secret.use"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        self.assertEqual(agent["vault_ids"], [])
        self.assertEqual(agent["item_ids"], [])
        self.assertEqual(self.client.call("vault.list", agent_token=agent["token"]), [])

    def test_static_resource_grants_are_rejected_in_v2(self):
        self.client.call("vault.create", {"name": "Personal"}, admin_password=MASTER)
        with self.assertRaises(RpcError) as ctx:
            self.client.call(
                "agent.create",
                {"name": "legacy", "vaults": ["Personal"], "scopes": ["secret.use"], "ttl_seconds": 3600},
                admin_password=MASTER,
            )
        self.assertEqual(ctx.exception.code, "validation_error")

    def test_access_request_requires_explicit_field_and_reason(self):
        self.client.call("vault.create", {"name": "Personal"}, admin_password=MASTER)
        agent = self.client.call(
            "agent.create",
            {"name": "a", "scopes": ["access.request", "secret.use"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        for uri, reason in (("pass://Personal/Foo", "reason"), ("pass://Personal/Foo/password", "")):
            with self.assertRaises(RpcError):
                self.client.call(
                    "access.request",
                    {"uri": uri, "capability": "secret.use", "target_host": "example.com", "ttl_seconds": 300, "max_uses": 1},
                    agent_token=agent["token"],
                    reason=reason,
                )


if __name__ == "__main__":
    unittest.main()
