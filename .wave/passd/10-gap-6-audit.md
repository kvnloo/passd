# GAP-6: Record durable terminal invocation outcomes

## Why

A use can be committed before transport or process failure, leaving audit without a correlated terminal record.

## Files and functions

`passd/service.py:audit`, `passd/service.py:_consume_capability_grant`, `passd/service.py:invoke_capability`, and `passd/db.py:SCHEMA`.

## Specification

1. Assign a correlation ID and durably record admission with consumption in one transaction.
2. Finalize bounded, credential-free outcome records for denial, transport/source failure or completed injection. Distinguish unknown completion at restart from a confirmed denial.
3. Define safe unauthenticated audit metadata with rate bounds and preserve readability of existing rows.

## Acceptance tests

- [ ] A source or transport failure after consume leaves a correlated terminal audit record and does not refund the use.
- [ ] A worker interruption leaves recoverable durable admission evidence without replaying egress.
- [ ] Concurrent contenders produce distinguishable outcomes and only one spend for a one-use lease.

## Delivery

- Branch `agent-vault/gap-6-audit`.
- Base and PR target `integration/agent-vault`.
- PR title `GAP-6: Record durable terminal invocation outcomes`.
