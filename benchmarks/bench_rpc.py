#!/usr/bin/env python3
from __future__ import annotations

import argparse
import statistics
import tempfile
import threading
import time
from pathlib import Path

from passd.client import PassdClient
from passd.config import Config
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "benchmark-master-password"


def summarize(name: str, samples_ns: list[int]) -> dict:
    values_us = sorted(v / 1000.0 for v in samples_ns)
    def pct(p: float) -> float:
        if not values_us:
            return 0.0
        idx = min(len(values_us) - 1, max(0, int(round((len(values_us) - 1) * p))))
        return values_us[idx]
    result = {
        "name": name,
        "n": len(values_us),
        "median_us": statistics.median(values_us),
        "p95_us": pct(0.95),
        "p99_us": pct(0.99),
        "mean_us": statistics.fmean(values_us),
    }
    print(
        f"{name:32} n={result['n']:6d}  median={result['median_us']:9.1f} us  "
        f"p95={result['p95_us']:9.1f} us  p99={result['p99_us']:9.1f} us  mean={result['mean_us']:9.1f} us"
    )
    return result


def timed(fn, n: int) -> list[int]:
    out: list[int] = []
    for _ in range(n):
        start = time.perf_counter_ns()
        fn()
        out.append(time.perf_counter_ns() - start)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Microbench passd local RPC/auth/policy overhead")
    ap.add_argument("--persistent", type=int, default=5000)
    ap.add_argument("--oneshot", type=int, default=500)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "state"
        cfg = Config.initialize(root, MASTER)
        service = PassdService(cfg, cfg.derive_and_verify(MASTER), allow_private_broker_targets=True)
        server = PassdUnixServer(cfg.socket_path, service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = PassdClient(cfg.socket_path)

        empty_agent = client.call(
            "agent.create",
            {"name": "bench-empty", "scopes": ["access.request", "metadata.read", "secret.use"], "ttl_seconds": 3600},
            admin_password=MASTER,
        )
        empty_token = empty_agent["token"]

        # Seed one approved item directly. This is setup only and does not
        # affect the RPC timings below.
        vault = service.create_vault("Bench")
        service.put_item(vault["id"], "API", {"password": "bench-secret"})
        agent = service.create_agent(
            "bench-approved", scopes=["access.request", "metadata.read", "secret.use"],
            vault_refs=[], item_refs=[], allowed_hosts=[], ttl_seconds=3600,
        )
        token = agent["token"]
        auth = service.authenticate_agent(token)
        access = service.request_access(
            auth, uri="pass://Bench/API/password", capability="secret.use", target_host="example.com",
            reason="benchmark", ttl_seconds=3600, max_uses=100,
        )
        service.approve_access(access["id"], ttl_seconds=3600, max_uses=100)

        # Warm caches, socket code paths, SQLite page cache, and Python imports.
        for _ in range(100):
            client.call("health")
        with client.session() as session:
            for _ in range(100):
                session.call("health")
                session.call("vault.list", agent_token=empty_token)

        results = []
        with client.session() as session:
            results.append(summarize("persistent health", timed(lambda: session.call("health"), args.persistent)))
            results.append(
                summarize(
                    "persistent auth+empty policy",
                    timed(lambda: session.call("vault.list", agent_token=empty_token), args.persistent),
                )
            )
            results.append(
                summarize(
                    "persistent approved vault view",
                    timed(lambda: session.call("vault.list", agent_token=token), args.persistent),
                )
            )
            results.append(
                summarize(
                    "persistent approved item view",
                    timed(lambda: session.call("item.list", {"vault": "Bench"}, agent_token=token), args.persistent),
                )
            )
            results.append(
                summarize(
                    "persistent access status",
                    timed(lambda: session.call("access.status", {"request": access["id"]}, agent_token=token), args.persistent),
                )
            )

        results.append(summarize("one-shot health", timed(lambda: client.call("health"), args.oneshot)))
        results.append(
            summarize(
                "one-shot auth+empty policy",
                timed(lambda: client.call("vault.list", agent_token=empty_token), args.oneshot),
            )
        )

        # Direct service measurement isolates Unix socket + JSON framing from auth.
        results.append(summarize("direct token authentication", timed(lambda: service.authenticate_agent(token), args.persistent)))

        print("\nThe persistent auth+policy figure is the closest estimate of passd's local machine-key gate overhead.")
        server.shutdown()
        server.server_close()
        service.close()


if __name__ == "__main__":
    main()
