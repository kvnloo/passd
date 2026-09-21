from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MASTER = "process-e2e-master"


class CliProcessE2E(unittest.TestCase):
    def run_cli(self, state: Path, *args: str, env: dict | None = None, ok: bool = True):
        e = {**os.environ, "PYTHONPATH": str(ROOT), "PASSD_MASTER_PASSWORD": MASTER}
        if env:
            e.update(env)
        cp = subprocess.run(
            [sys.executable, "-m", "passd", "--data-dir", str(state), *args],
            cwd=ROOT,
            env=e,
            text=True,
            capture_output=True,
            timeout=10,
        )
        if ok and cp.returncode != 0:
            self.fail(f"command failed: {args}\nstdout={cp.stdout}\nstderr={cp.stderr}")
        return cp

    def test_real_daemon_and_cli_zero_grant_hitl_flow(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            self.run_cli(state, "init")
            env = {**os.environ, "PYTHONPATH": str(ROOT), "PASSD_MASTER_PASSWORD": MASTER}
            daemon = subprocess.Popen(
                [sys.executable, "-m", "passd", "--data-dir", str(state), "serve"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for _ in range(100):
                    if (state / "passd.sock").exists():
                        break
                    if daemon.poll() is not None:
                        self.fail(f"daemon exited early: {daemon.stderr.read()}")
                    time.sleep(0.02)
                else:
                    self.fail("daemon socket did not appear")

                self.run_cli(state, "vault", "create", "Personal")
                self.run_cli(state, "item", "put-login", "--vault", "Personal", "--title", "API", "--password", "process-secret")
                agent = json.loads(self.run_cli(state, "agent", "create", "cli-agent", "--scope", "access.request", "--scope", "metadata.read", "--scope", "secret.use", "--expiration", "1h").stdout)
                token = agent["token"]
                agent_env = {"PASSD_AGENT_TOKEN": token, "PASSD_AGENT_REASON": "process e2e"}
                self.assertEqual(json.loads(self.run_cli(state, "vault", "list", env=agent_env).stdout), [])
                self.assertEqual(json.loads(self.run_cli(state, "item", "list", "Personal", env=agent_env).stdout), [])

                req = json.loads(
                    self.run_cli(
                        state,
                        "access", "request", "pass://Personal/API/password",
                        "--host", "example.com", "--uses", "1", "--expiration", "5m",
                        env=agent_env,
                    ).stdout
                )
                pending = json.loads(self.run_cli(state, "access", "pending").stdout)
                self.assertEqual([p["id"] for p in pending], [req["id"]])
                self.assertEqual(pending[0]["uri"], "pass://Personal/API/password")
                self.run_cli(state, "access", "approve", req["id"], "--uses", "1")
                visible = json.loads(self.run_cli(state, "vault", "list", env=agent_env).stdout)
                self.assertEqual([v["name"] for v in visible], ["Personal"])

                denied = self.run_cli(state, "resolve", "pass://Personal/API/password", env=agent_env, ok=False)
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn("permission_denied", denied.stderr)

                rotated = json.loads(self.run_cli(state, "agent", "rotate", agent["id"]).stdout)
                old = self.run_cli(state, "vault", "list", env=agent_env, ok=False)
                self.assertIn("auth_error", old.stderr)
                self.assertEqual(rotated["id"], agent["id"])
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill(); daemon.wait(timeout=5)
                if daemon.stdout is not None:
                    daemon.stdout.close()
                if daemon.stderr is not None:
                    daemon.stderr.close()


class _CapHandler(BaseHTTPRequestHandler):
    secret = "process-cap-secret"
    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {self.secret}":
            self.send_response(401); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "auth": self.headers.get("Authorization")}).encode())
    def log_message(self, fmt, *args):
        pass


def _test_capability_cli_process(self):
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state"
        self.run_cli(state, "init")
        http = HTTPServer(("127.0.0.1", 0), _CapHandler)
        ht = threading.Thread(target=http.serve_forever, daemon=True); ht.start()
        env = {**os.environ, "PYTHONPATH": str(ROOT), "PASSD_MASTER_PASSWORD": MASTER}
        daemon = subprocess.Popen(
            [sys.executable, "-m", "passd", "--data-dir", str(state), "serve", "--allow-private-broker-targets"],
            cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            for _ in range(100):
                if (state / "passd.sock").exists(): break
                if daemon.poll() is not None: self.fail(f"daemon exited early: {daemon.stderr.read()}")
                time.sleep(0.02)
            else: self.fail("daemon socket did not appear")

            self.run_cli(state, "vault", "create", "Personal")
            self.run_cli(state, "item", "put-login", "--vault", "Personal", "--title", "OpenRouter", "--password", _CapHandler.secret)
            cap = json.loads(self.run_cli(
                state, "capability", "put-http", "openrouter.infer",
                "--description", "Inference", "--backing-uri", "pass://Personal/OpenRouter/password",
                "--scheme", "http", "--host", "127.0.0.1", "--port", str(http.server_port),
                "--method", "POST", "--path-prefix", "/api/v1/chat/completions",
                "--static-header", "Content-Type=application/json",
            ).stdout)
            self.assertTrue(cap["version"].startswith("cv1_"))
            agent = json.loads(self.run_cli(state, "agent", "create", "cap-agent", "--expiration", "1h").stdout)
            agent_env = {"PASSD_AGENT_TOKEN": agent["token"], "PASSD_AGENT_REASON": "process capability e2e"}
            catalog = json.loads(self.run_cli(state, "capability", "list", env=agent_env).stdout)
            self.assertEqual([x["id"] for x in catalog], ["openrouter.infer"])
            self.assertNotIn("pass://", json.dumps(catalog))

            denied = self.run_cli(
                state, "capability", "invoke", "openrouter.infer", "--method", "POST", "--path", "/api/v1/chat/completions", "--body", "{}",
                env=agent_env, ok=False,
            )
            self.assertIn("permission_denied", denied.stderr)
            req = json.loads(self.run_cli(
                state, "capability", "request", "openrouter.infer", "--method", "POST", "--path", "/api/v1/chat/completions", "--uses", "1",
                env=agent_env,
            ).stdout)
            self.assertTrue(req["authority_digest"].startswith("ad1_"))
            self.run_cli(state, "access", "approve", req["id"])
            result = json.loads(self.run_cli(
                state, "capability", "invoke", "openrouter.infer", "--method", "POST", "--path", "/api/v1/chat/completions", "--body", "{}",
                env=agent_env,
            ).stdout)
            self.assertEqual(result["status"], 200)
            self.assertNotIn(_CapHandler.secret, json.dumps(result))
        finally:
            http.shutdown(); http.server_close()
            daemon.terminate()
            try: daemon.wait(timeout=5)
            except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(timeout=5)
            if daemon.stdout is not None: daemon.stdout.close()
            if daemon.stderr is not None: daemon.stderr.close()


CliProcessE2E.test_capability_cli_process = _test_capability_cli_process


if __name__ == "__main__":
    unittest.main()
