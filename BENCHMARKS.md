# passd v0.3 latency kernel

The benchmark is intentionally local and decomposes the authority hot path. It is not a claim about Internet/API latency.

Run:

```bash
./benchmarks/run_kernel.sh
```

To gate a candidate against a same-host baseline:

```bash
PASSD_BENCH_BASELINE=benchmarks/baseline-20260918.json \
  ./benchmarks/run_kernel.sh benchmarks/candidate.json
```

`compare.py` fails if any sealed metric regresses more than 20% by default. Override with `PASSD_BENCH_MAX_REGRESSION_PCT` only for an explicit experiment.

## Frozen v0.3 baseline

Environment: this ChatGPT execution container, 2026-09-18. 1,000 iterations for local microbenchmarks and 100 loopback capability invocations.

| Metric | Median | p95 |
| --- | ---: | ---: |
| direct machine-token authentication | **11.4 µs** | 13.2 µs |
| capability load + contract validation | **19.4 µs** | 26.3 µs |
| credential decrypt + keyed version | **58.7 µs** | 129.2 µs |
| atomic lease claim + version checks | **216.5 µs** | 476.1 µs |
| persistent `capability.list` RPC | **160.5 µs** | 306.1 µs |
| persistent `access.status` RPC | **186.6 µs** | 321.7 µs |
| full `capability.invoke` against loopback HTTP | **1.56 ms** | 2.44 ms |

The complete machine-readable receipt is `benchmarks/baseline-20260918.json`.

## Optimization found during v0.3

Constructing a fresh Python `urllib` opener cost **10.12 ms median** in the same run. v0.3 creates the no-redirect transport once per custody process instead. That avoided local setup cost is roughly 47x the median lease-claim/security-policy cost and about 6.5x the entire current loopback invocation.

A second hot-path cut removed duplicate item decryption. The approved secret is decrypted once, version-checked, and passed to the invocation path for that call. Secrets are not cached across calls.

## What is allowed to evolve

`z0intelligence` / Evolution Lab may optimize implementation mechanics under this benchmark, for example transport reuse, SQLite query plans, framing, serialization, and crypto allocations. The following are sealed and are not optimization variables:

- machine identity is not resource authority;
- exact capability version and exact credential-field version bind a lease;
- HITL/pre-existing deterministic policy is the only grant source;
- use budgets are atomically claimed before the privileged action;
- agent-selected host/header/backing secret is forbidden on the typed path;
- secret values never appear in benchmark/evidence payloads.

Performance candidates must pass the full security/TDD suite before benchmark comparisons count.
