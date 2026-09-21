#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from passd.client import PassdClient
from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import NoRedirect, PassdService

MASTER = "capability-benchmark-master"
SECRET = "bench-capability-secret"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {SECRET}":
            self.send_response(401); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, fmt, *args):
        pass


def timed(fn, n: int) -> list[int]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter_ns(); fn(); out.append(time.perf_counter_ns() - t0)
    return out


def summary(name: str, ns: list[int]) -> dict:
    us = sorted(x / 1000 for x in ns)
    def pct(p): return us[min(len(us)-1, max(0, int(round((len(us)-1)*p))))]
    return {
        "name": name, "n": len(us), "median_us": statistics.median(us),
        "p95_us": pct(.95), "p99_us": pct(.99), "mean_us": statistics.fmean(us),
    }


def main():
    ap = argparse.ArgumentParser(description="passd v0.3 capability latency decomposition")
    ap.add_argument("--local", type=int, default=1000, help="iterations for local auth/policy microbenchmarks")
    ap.add_argument("--network", type=int, default=100, help="iterations for loopback full invocation")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "state"
        cfg = Config.initialize(root, MASTER)
        service = PassdService(cfg, cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        server = PassdUnixServer(cfg.socket_path, service)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        http = HTTPServer(("127.0.0.1", 0), Handler)
        ht = threading.Thread(target=http.serve_forever, daemon=True); ht.start()
        client = PassdClient(cfg.socket_path)
        try:
            service.create_vault("Personal")
            service.put_item("Personal", "OpenRouter", {"password": SECRET})
            service.put_capability({
                "id": "openrouter.infer", "description": "Inference", "kind": "http_secret",
                "backing_uri": "pass://Personal/OpenRouter/password", "scheme": "http",
                "host": "127.0.0.1", "port": http.server_port, "methods": ["POST"],
                "path_prefix": "/api/v1/chat/completions", "inject_header": "Authorization",
                "inject_prefix": "Bearer ", "static_headers": {"Content-Type": "application/json"},
                "timeout_seconds": 5,
            })
            created = service.create_agent(
                "bench", scopes=["capability.request", "capability.invoke"], vault_refs=[], item_refs=[], allowed_hosts=[], ttl_seconds=3600,
            )
            token = created["token"]
            agent = service.authenticate_agent(token)
            req = service.request_capability(
                agent, capability_id="openrouter.infer", method="POST", path="/api/v1/chat/completions",
                reason="benchmark", ttl_seconds=3600, max_uses=100,
            )
            service.approve_access(req["id"], ttl_seconds=3600, max_uses=100)
            # Benchmark-only expansion. Production API caps leases at 100 uses.
            service.db.execute("UPDATE access_requests SET max_uses=1000000,uses=0 WHERE id=?", (req["id"],)); service.db.commit()

            cap_row = service.get_capability_row("openrouter.infer")
            definition = service._capability_payload(cap_row)
            item_row, _ = service.resolve_item_ref(definition["backing_uri"])

            # warm
            for _ in range(50):
                service.authenticate_agent(token)
                service._validate_capability_invocation(definition, "POST", "/api/v1/chat/completions")
            with client.session() as session:
                for _ in range(50): session.call("capability.list", agent_token=token)

            results = []
            results.append(summary("direct token auth", timed(lambda: service.authenticate_agent(token), args.local)))
            results.append(summary(
                "direct capability load+validate",
                timed(lambda: service._validate_capability_invocation(service._capability_payload(cap_row), "POST", "/api/v1/chat/completions"), args.local),
            ))
            results.append(summary("direct item decrypt+version", timed(lambda: service._item_version(item_row), args.local)))
            results.append(summary(
                "direct lease claim+version checks",
                timed(lambda: service._consume_capability_grant(agent, "openrouter.infer", "POST", "/api/v1/chat/completions", "benchmark"), args.local),
            ))
            with client.session() as session:
                results.append(summary("persistent capability.list RPC", timed(lambda: session.call("capability.list", agent_token=token), args.local)))
                results.append(summary("persistent access.status RPC", timed(lambda: session.call("access.status", {"request": req["id"]}, agent_token=token), args.local)))

            # Isolate the cost that v0.2 accidentally paid on every invocation.
            results.append(summary("build urllib opener (avoided)", timed(lambda: urllib.request.build_opener(NoRedirect), min(args.local, 200))))

            # Reset budget after direct claims and measure the full broker path.
            service.db.execute("UPDATE access_requests SET max_uses=1000000,uses=0 WHERE id=?", (req["id"],)); service.db.commit()
            with client.session() as session:
                results.append(summary(
                    "full capability.invoke loopback",
                    timed(lambda: session.call(
                        "capability.invoke",
                        {"capability_id": "openrouter.infer", "method": "POST", "path": "/api/v1/chat/completions", "body": "{}"},
                        agent_token=token, reason="benchmark",
                    ), args.network),
                ))

            if args.json:
                print(json.dumps({"schema": "passd-capability-bench-v1", "results": results}, indent=2))
            else:
                for r in results:
                    print(f"{r['name']:38} n={r['n']:5d} median={r['median_us']:9.1f}us p95={r['p95_us']:9.1f}us p99={r['p99_us']:9.1f}us")
        finally:
            http.shutdown(); http.server_close(); server.shutdown(); server.server_close(); service.close()


if __name__ == "__main__":
    main()
