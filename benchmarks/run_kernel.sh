#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/benchmarks/candidate.json}"
PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python "$ROOT/benchmarks/bench_capability.py" --local "${PASSD_BENCH_LOCAL:-1000}" --network "${PASSD_BENCH_NETWORK:-100}" --json > "$OUT"
echo "wrote $OUT"
if [[ -n "${PASSD_BENCH_BASELINE:-}" ]]; then
  python "$ROOT/benchmarks/compare.py" "$PASSD_BENCH_BASELINE" "$OUT" --max-regression-pct "${PASSD_BENCH_MAX_REGRESSION_PCT:-20}"
fi
