# GAP-3: Enforce typed-only agent execution

## Why

Legacy local agent scopes can reveal raw values or use a host-bound lease with caller-selected endpoint details.

## Files and functions

`passd/service.py:handle`, `passd/service.py:reveal_secret`, `passd/service.py:broker_http`, `passd/service.py:_consume_exact_grant`, and `passd/gateway.py:REMOTE_OPS`.

## Specification

1. Define and enforce a production agent policy that permits only typed execution and associated catalog and request operations.
2. Handle existing tokens and legacy leases at the policy boundary so old credentials cannot keep deprecated authority. Keep owner-only maintenance behind local admin auth.
3. Document compatibility and migration for deployments with legacy operations.

## Acceptance tests

- [ ] A legacy agent token cannot reveal a value or broker against a caller-selected method, port or path in production.
- [ ] A valid typed lease still invokes only its exact destination.
- [ ] The remote surface refuses administration and legacy execution.

## Delivery

- Branch `agent-vault/gap-3-typed-only`.
- Base and PR target `integration/agent-vault`.
- PR title `GAP-3: Enforce typed-only agent execution`.
