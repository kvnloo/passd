#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_METRICS = [
    "direct token auth",
    "direct lease claim+version checks",
    "persistent capability.list RPC",
    "full capability.invoke loopback",
]


def load(path: Path) -> dict[str, dict]:
    doc = json.loads(path.read_text())
    if doc.get("schema") != "passd-capability-bench-v1":
        raise SystemExit(f"unsupported benchmark schema in {path}")
    return {r["name"]: r for r in doc["results"]}


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare passd capability benchmark receipts on the same host")
    ap.add_argument("baseline", type=Path)
    ap.add_argument("candidate", type=Path)
    ap.add_argument("--max-regression-pct", type=float, default=20.0)
    ap.add_argument("--metric", action="append", default=[])
    args = ap.parse_args()
    base, cand = load(args.baseline), load(args.candidate)
    metrics = args.metric or DEFAULT_METRICS
    failed = []
    rows = []
    for name in metrics:
        if name not in base or name not in cand:
            failed.append(f"missing metric: {name}")
            continue
        b = float(base[name]["median_us"]); c = float(cand[name]["median_us"])
        pct = ((c / b) - 1.0) * 100.0 if b else 0.0
        rows.append((name, b, c, pct))
        if pct > args.max_regression_pct:
            failed.append(f"{name}: {pct:.1f}% > {args.max_regression_pct:.1f}%")
    for name, b, c, pct in rows:
        print(f"{name:38} baseline={b:9.1f}us candidate={c:9.1f}us delta={pct:+7.1f}%")
    if failed:
        print("latency regression gate: FAIL", file=sys.stderr)
        for reason in failed: print(f"  - {reason}", file=sys.stderr)
        return 1
    print("latency regression gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
