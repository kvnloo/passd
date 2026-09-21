from __future__ import annotations

import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from passd.client import PassdClient
from passd.config import Config
from passd.proton_import import import_export
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "master-password"


class ProtonImportTest(unittest.TestCase):
    def test_imports_login_from_export_zip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "passd"
            cfg = Config.initialize(root, MASTER)
            service = PassdService(cfg, cfg.derive_and_verify(MASTER))
            server = PassdUnixServer(cfg.socket_path, service)
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            client = PassdClient(cfg.socket_path)

            export = Path(td) / "Proton Pass_export.zip"
            data = {
                "version": "1",
                "userId": "user",
                "vaults": {
                    "pvault": {
                        "name": "Agents",
                        "description": "",
                        "display": {"color": 0, "icon": 0},
                        "items": [
                            {
                                "state": 1,
                                "modifyTime": 123,
                                "data": {
                                    "type": "login",
                                    "metadata": {"name": "OpenRouter", "itemUuid": "uuid-1", "note": ""},
                                    "content": {"itemUsername": "bot", "password": "sk-proton", "urls": ["https://openrouter.ai"]},
                                },
                            }
                        ],
                    }
                },
            }
            with zipfile.ZipFile(export, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("Proton Pass/data.json", json.dumps(data))

            summary = import_export(client, export, admin_password=MASTER)
            self.assertEqual(summary["imported_or_updated"], 1)
            value = client.call("secret.resolve", {"uri": "pass://Agents/OpenRouter/password"}, admin_password=MASTER)
            self.assertEqual(value, "sk-proton")

            # Idempotent upsert by Proton vault/item UUID.
            import_export(client, export, admin_password=MASTER)
            items = client.call("item.list", {"vault": "Agents"}, admin_password=MASTER)
            self.assertEqual(len(items), 1)

            server.shutdown(); server.server_close(); service.close()

    def test_same_named_proton_vaults_remain_distinct_by_source_id(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "passd"
            cfg = Config.initialize(root, MASTER)
            service = PassdService(cfg, cfg.derive_and_verify(MASTER))
            server = PassdUnixServer(cfg.socket_path, service)
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            client = PassdClient(cfg.socket_path)

            data = {
                "version": "1",
                "userId": "user",
                "vaults": {
                    "pvault-a": {
                        "name": "Agents",
                        "description": "a",
                        "items": [{
                            "state": 1,
                            "data": {
                                "type": "login",
                                "metadata": {"name": "A", "itemUuid": "uuid-a"},
                                "content": {"password": "secret-a"},
                            },
                        }],
                    },
                    "pvault-b": {
                        "name": "Agents",
                        "description": "b",
                        "items": [{
                            "state": 1,
                            "data": {
                                "type": "login",
                                "metadata": {"name": "B", "itemUuid": "uuid-b"},
                                "content": {"password": "secret-b"},
                            },
                        }],
                    },
                },
            }
            export = Path(td) / "export.json"
            export.write_text(json.dumps(data))
            import_export(client, export, admin_password=MASTER)
            vaults = client.call("vault.list", admin_password=MASTER)
            agents = [v for v in vaults if v["name"] == "Agents"]
            self.assertEqual(len(agents), 2)
            source_ids = {v["source"]["id"] for v in agents}
            self.assertEqual(source_ids, {"pvault-a", "pvault-b"})
            counts = [len(client.call("item.list", {"vault": v["id"]}, admin_password=MASTER)) for v in agents]
            self.assertEqual(sorted(counts), [1, 1])

            server.shutdown(); server.server_close(); service.close()


if __name__ == "__main__":
    unittest.main()
