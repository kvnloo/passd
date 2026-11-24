# GAP-4: Prevent secret disclosure in agent receipts

## Why

Literal redaction cannot make upstream-controlled response data safe for an untrusted agent.

## Files and functions

`passd/service.py:_execute_http`, `passd/service.py:_redact`, and `passd/service.py:invoke_capability`.

## Specification

1. Define a minimal broker-generated receipt for production. Ensure upstream-controlled fields, including status where needed, cannot carry credentials back.
2. Require separate owner review for any capability-specific response schema and its threat model.
3. Keep internal errors and audit reporting free of raw or transformed credential data.

## Acceptance tests

- [ ] A test upstream that reflects raw, encoded or transformed sentinels produces only the allowed broker-generated receipt.
- [ ] Upstream errors and redirects expose no response payload to the agent.
- [ ] The local owner can correlate the receipt with an audit outcome without retrieving the credential.

## Delivery

- Branch `agent-vault/gap-4-receipts`.
- Base and PR target `integration/agent-vault`.
- PR title `GAP-4: Prevent secret disclosure in agent receipts`.
