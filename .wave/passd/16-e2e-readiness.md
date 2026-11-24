# Add an end-to-end agent vault readiness script

## Why

Owner testing depends on proving the real broker boundary with disposable credentials.

## Files and functions

Readiness script under `scripts/`, `spec/PROTON-ENROLLMENT.md`, `spec/CUSTODY-UNLOCK.md`, and passd gateway and local admin paths.

## Specification

1. Gate live runs on explicit owner approval, Proton entitlement, the dedicated service and verified singleton grants.
2. Use only a dummy item in `agents` and an owner-created dummy reference in MAIN. Confirm denial before approval, one injected upstream request after approval, and no credential in the agent receipt.
3. Prove MAIN-vault refusal at provider resolution, deny replay, revoke the lease and machine token, and prove source disable and Proton deletion with a disposable identity. Clean fixtures and emit only sanitized results.

## Acceptance tests

- [ ] The dummy agents item succeeds only after owner approval, and the upstream observes exactly the expected injection.
- [ ] A dummy MAIN-vault selector is refused without reading or returning any genuine personal item.
- [ ] Lease, token and provider revocation each block subsequent use and cleanup leaves no live test grant.

## Delivery

- Branch `agent-vault/e2e-readiness`.
- Base and PR target `integration/agent-vault`.
- PR title `Add an end-to-end agent vault readiness script`.
