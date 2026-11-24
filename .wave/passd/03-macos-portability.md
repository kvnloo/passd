# Make the passd test suite portable on macOS

## Why

macOS injects __CF_USER_TEXT_ENCODING into subprocess environments and socket concurrency can surface ECONNRESET. The reported baseline also shows both classes on unmodified main.

## Files and functions

`tests/test_proton_agent.py`, `tests/test_vulnerability_regressions.py`, `tests/test_access_gate.py`, `tests/test_capabilities.py`, `tests/test_gateway.py`, `passd/server.py:PassdHandler.handle`, and `passd/client.py:PassdClient.call`.

## Specification

1. Reproduce both classes on unchanged code and record platform, Python version and test names.
2. Account for macOS-injected __CF_USER_TEXT_ENCODING in test expectations while continuing to reject inherited secrets and proxy variables.
3. Diagnose Unix-socket ECONNRESET under concurrency and make close/backlog handling reliable. Never auto-retry an invocation whose consume result is unknown.

## Acceptance tests

- [ ] Run environment allowlist tests on macOS and Linux with ambient secret and proxy sentinels excluded.
- [ ] Repeat one-use concurrent tests and assert one upstream injection and all other contenders receive protocol denials.
- [ ] Run the full suite on macOS and Linux.

## Delivery

- Branch `agent-vault/macos-portability`.
- Base and PR target `integration/agent-vault`.
- PR title `Make the passd test suite portable on macOS`.
