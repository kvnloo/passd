from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from passd.client import PassdClient
from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "persistence-master"
SECRET = "persistent-secret"


class PersistenceTest(unittest.TestCase):
    def test_v1_state_upgrades_and_approved_lease_survives_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "state"
            cfg = Config.initialize(root, MASTER)
            service = PassdService(cfg, cfg.derive_and_verify(MASTER))
            server = PassdUnixServer(cfg.socket_path, service)
            t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
            client = PassdClient(cfg.socket_path)
            client.call("vault.create", {"name": "Personal"}, admin_password=MASTER)
            client.call("item.put", {"vault": "Personal", "title": "X", "fields": {"password": SECRET}}, admin_password=MASTER)
            agent = client.call("agent.create", {"name": "a", "scopes": ["access.request", "metadata.read", "secret.reveal"], "ttl_seconds": 3600}, admin_password=MASTER)
            req = client.call("access.request", {"uri": "pass://Personal/X/password", "capability": "secret.reveal", "ttl_seconds": 300, "max_uses": 2}, agent_token=agent["token"], reason="restart test")
            client.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
            server.shutdown(); server.server_close(); service.close()

            # Reopen the exact same encrypted state, as a daemon restart would.
            service2 = PassdService(cfg, cfg.derive_and_verify(MASTER))
            server2 = PassdUnixServer(cfg.socket_path, service2)
            t2 = threading.Thread(target=server2.serve_forever, daemon=True); t2.start()
            client2 = PassdClient(cfg.socket_path)
            self.assertEqual(client2.call("secret.resolve", {"uri": "pass://Personal/X/password"}, agent_token=agent["token"], reason="restart test"), SECRET)
            status = client2.call("access.status", {"request": req["id"]}, agent_token=agent["token"])
            self.assertEqual(status["uses_remaining"], 1)
            server2.shutdown(); server2.server_close(); service2.close()


    def test_missing_v2_access_table_is_migrated_without_data_loss(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "state"
            cfg = Config.initialize(root, MASTER)
            service = PassdService(cfg, cfg.derive_and_verify(MASTER))
            vault = service.create_vault("Legacy")
            item = service.put_item(vault["id"], "Legacy Secret", {"password": SECRET})
            agent = service.create_agent("legacy-agent", scopes=["access.request", "metadata.read", "secret.use"], vault_refs=[], item_refs=[], allowed_hosts=[], ttl_seconds=3600)
            service.close()

            # Simulate a pre-v2 database: preserve all existing records but remove
            # the v2-only approval table. Reopening must add it in place.
            conn = sqlite3.connect(cfg.db_path)
            conn.execute("DROP TABLE access_requests")
            conn.commit()
            conn.close()

            service2 = PassdService(cfg, cfg.derive_and_verify(MASTER))
            self.assertIsNotNone(service2.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='access_requests'").fetchone())
            self.assertEqual(service2.find_vault(vault["id"])["id"], vault["id"])
            self.assertEqual(service2.find_item(vault["id"], item["id"])["id"], item["id"])
            auth = service2.authenticate_agent(agent["token"])
            self.assertEqual(auth["id"], agent["id"])
            service2.close()

    def test_audit_reason_and_request_selector_are_encrypted_at_rest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "state"
            cfg = Config.initialize(root, MASTER)
            service = PassdService(cfg, cfg.derive_and_verify(MASTER))
            service.create_vault("Personal")
            service.put_item("Personal", "Audit Sensitive Item", {"password": SECRET})
            agent = service.create_agent("audit-agent", scopes=["access.request", "metadata.read", "secret.use"], vault_refs=[], item_refs=[], allowed_hosts=[], ttl_seconds=3600)
            # Go through the RPC-independent service API to generate both the
            # encrypted pending request payload and its audit record.
            auth = service.authenticate_agent(agent["token"])
            service.request_access(
                auth,
                uri="pass://Personal/Audit%20Sensitive%20Item/password",
                capability="secret.use",
                target_host="example.com",
                reason="private rationale 918273",
                ttl_seconds=300,
                max_uses=1,
            )
            service.close()
            raw = cfg.db_path.read_bytes()
            self.assertNotIn(b"Audit Sensitive Item", raw)
            self.assertNotIn(b"private rationale 918273", raw)

    def test_sensitive_values_are_not_plaintext_in_sqlite_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "state"
            cfg = Config.initialize(root, MASTER)
            service = PassdService(cfg, cfg.derive_and_verify(MASTER))
            service.create_vault("Personal")
            service.put_item("Personal", "Super Secret Account Name", {"password": "VERY-SECRET-VALUE-123"})
            agent = service.create_agent("agent", scopes=["access.request", "secret.use"], vault_refs=[], item_refs=[], allowed_hosts=[], ttl_seconds=3600)
            service.close()
            raw = cfg.db_path.read_bytes()
            self.assertNotIn(b"VERY-SECRET-VALUE-123", raw)
            self.assertNotIn(b"Super Secret Account Name", raw)
            self.assertNotIn(agent["token"].encode(), raw)


if __name__ == "__main__": unittest.main()


class CapabilityPersistenceTest(unittest.TestCase):
    def test_capability_backing_selector_is_encrypted_at_rest_and_schema_migrates(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            cfg = Config.initialize(root, MASTER)
            svc = PassdService(cfg, cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
            try:
                svc.create_vault("Personal")
                svc.put_item("Personal", "OpenRouter", {"password": "sk-hidden"})
                svc.put_capability({
                    "id": "openrouter.infer",
                    "description": "Inference",
                    "kind": "http_secret",
                    "backing_uri": "pass://Personal/OpenRouter/password",
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": 12345,
                    "methods": ["POST"],
                    "path_prefix": "/api/v1/chat/completions",
                    "inject_header": "Authorization",
                    "inject_prefix": "Bearer ",
                    "static_headers": {"Content-Type": "application/json"},
                })
            finally:
                svc.close()
            raw = cfg.db_path.read_bytes()
            self.assertNotIn(b"pass://Personal/OpenRouter/password", raw)
            self.assertNotIn(b"sk-hidden", raw)

            # Simulate an older v0.2 database by dropping only the v0.3 table.
            import sqlite3
            con = sqlite3.connect(cfg.db_path)
            con.execute("DROP TABLE capabilities")
            con.commit(); con.close()
            migrated = PassdService(cfg, cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
            try:
                self.assertEqual(migrated.list_capabilities(), [])
                self.assertEqual(migrated.list_vaults()[0]["name"], "Personal")
            finally:
                migrated.close()
        finally:
            tmp.cleanup()
