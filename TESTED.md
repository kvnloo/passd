# v0.3.1 test evidence

Validated on 2026-09-20 in the build container. Tests were deliberately run in bounded groups because the execution harness terminates long combined shell commands; no truncated run is counted as success.

## Backend: 50 tests

All 50 tests passed across the following modules:

| Module | Tests | Result |
| --- | ---: | --- |
| `tests.test_access_gate` | 20 | PASS, split into 10 + 10 |
| `tests.test_capabilities` | 12 | PASS, 11 completed in the bounded suite and the final long case rerun independently |
| `tests.test_persistence` | 5 | PASS |
| `tests.test_security_properties` | 4 | PASS |
| `tests.test_proton_import` | 2 | PASS |
| `tests.test_e2e` | 2 | PASS |
| `tests.test_cli_process` | 2 | PASS independently as real daemon + real CLI subprocess flows |
| `tests.test_vulnerability_regressions` | 3 | PASS |

Security/correctness cases include:

- machine API key authenticates identity but grants zero resource authority;
- normal agent catalog exposes typed capability IDs, never Proton vault/item/backing URI;
- legacy secret token cannot enumerate the typed capability catalog;
- request digest binds machine, capability version, method/path, reason, TTL and use budget;
- approval digest binds request digest, capability version, exact credential-field version and narrowed lease;
- changing a capability after request prevents approval;
- changing a capability after approval invalidates the lease;
- changing unrelated item metadata does not invalidate a credential lease;
- rotating the exact credential does invalidate it;
- rewriting/re-encrypting semantically identical item content does not burn a lease;
- exact method/path contract enforcement;
- 8 concurrent callers racing a one-use capability lease produce exactly one winner;
- 8 concurrent callers racing a one-use legacy lease produce exactly one winner;
- concurrent HITL approvals produce exactly one winner;
- cross-machine lease isolation;
- API-key rotation invalidates the old key without changing machine identity;
- revocation/deny/expiry remove authority;
- pending-request deduplication and 32-request per-machine queue bound;
- no pre-approval vault/item existence oracle;
- broker output redacts the exact injected secret if an upstream echoes it;
- capability definitions, selectors, reasons, and sensitive audit details are encrypted at rest;
- migration creates the v0.3 capability table without losing pre-existing vault data;
- owner-only state/socket permissions;
- Proton export import preserves same-named vaults by source ID;
- persistent socket sessions recover from RPC errors.


Additional v0.3.1 vulnerability regressions prove:

- unauthenticated `secret.resolve` returns the same authentication failure for existing and nonexistent selectors, closing the same-UID vault/item existence oracle;
- unauthenticated admin `broker.http` fails before DNS resolution, so it cannot be abused as a local DNS-work oracle;
- inherited `HTTP_PROXY` / `HTTPS_PROXY` values are ignored by the custody transport, so injected credentials cannot be diverted through an ambient process proxy.

## Fork adapter: 5 tests

`proton-pass-cli-selfhosted-fork-v0.3` passed:

- 2 adapter framing/TTL tests;
- machine API-key rotation contract against a real temporary `passd`;
- v0.3 typed capability request → HITL approval → secret-use invocation contract;
- legacy zero-grant request → approve → broker compatibility contract.

The typed contract verifies that the adapter never receives the private Proton backing selector.

## Performance receipt

`benchmarks/baseline-20260918.json` was generated with 1,000 local iterations and 100 full loopback invocations. `benchmarks/compare.py` passes when comparing the baseline to itself, proving the regression-gate format is consumable.

See `BENCHMARKS.md` for measured medians and the sealed optimization boundary.

## Packaging/install proof

A wheel was built offline with the already-installed build toolchain:

```text
passd_local-0.3.1-py3-none-any.whl
SHA-256 9010aa27820934d61123995bd257b583f76655bbfb1b53a084074713105b4ffd
```

It was installed with `--no-deps --no-index` into a fresh `--system-site-packages` virtual environment; `import passd` reported `0.3.1` and the installed `passd --help` exposed the expected command surface.
