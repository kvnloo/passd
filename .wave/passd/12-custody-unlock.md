# Implement bounded owner custody unlock and re-lock

## Why

The current serve process holds the root key for its lifetime. The owner wants fingerprint-assisted Proton Pass autofill in Hermes mobile.

## Files and functions

`passd/cli.py:password_from_env`, `passd/config.py:Config.derive_and_verify`, `passd/server.py:serve`, and `spec/CUSTODY-UNLOCK.md`.

## Specification

1. Use the owner-only intake selected after the W3 receipt. The owner generates and saves the custody passphrase in the MAIN Proton vault.
2. Preserve the existing scrypt store and define a bounded monotonic unlock lifetime, explicit re-lock and restart behavior.
3. On lock, refuse new injections, bound in-flight shutdown and clear the isolated provider session. Keep approval separate from unlock.

## Acceptance tests

- [ ] A dummy owner passphrase unlocks and a wrong, expired or replayed challenge fails.
- [ ] Expiry, re-lock and restart deny injection until a new owner unlock.
- [ ] Agent logs, tool results, files and process arguments contain no passphrase.

## Delivery

- Branch `agent-vault/custody-unlock`.
- Base and PR target `integration/agent-vault`.
- PR title `Implement bounded owner custody unlock and re-lock`.
