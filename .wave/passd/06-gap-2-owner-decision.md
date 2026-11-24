# GAP-2: Verify owner approvals against reviewed authority

## Why

The current admin request-ID transition does not verify a phone decision or the digest the approver actually saw.

## Files and functions

`passd/service.py:request_capability`, `passd/service.py:approve_access`, `passd/authority.py:authority_digest`, and the owner approval adapter.

## Specification

1. Define a signed or equivalently authenticated owner decision over request and agent IDs, reviewed digest, action, approved TTL/budget, and replay protection.
2. Verify the decision before any state change. Keep owner approval isolated from the agent gateway and enforce one use for the initial owner policy.
3. Expose an owner-facing review showing exact destination, purpose and requested limits without secret material.

## Acceptance tests

- [ ] A valid owner decision for the displayed digest approves once.
- [ ] A changed digest, wrong owner, reused decision or agent-only credential cannot approve.
- [ ] The owner phone receipt names the request and exact destination.

## Delivery

- Branch `agent-vault/gap-2-owner-decision`.
- Base and PR target `integration/agent-vault`.
- PR title `GAP-2: Verify owner approvals against reviewed authority`.
