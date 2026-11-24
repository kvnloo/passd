# GAP-1: Bind live Proton leases to an approved credential revision

## Why

passd fingerprints the Proton selector and configured agent name. A rotation at that selector can silently change the injected value.

## Files and functions

`passd/service.py:approve_access`, `passd/service.py:_live_source_version`, `passd/service.py:_consume_capability_grant`, and `passd/proton_agent.py:ProtonAgentSource.resolve`.

## Specification

1. Establish an entitled Proton API or CLI revision signal tied to the exact resolved value. Confirm it can be verified without fetching plaintext during approval.
2. Bind its opaque revision to the approval and the value fetched after consume. Fail closed if it is absent, unverifiable or changed. Avoid logging revision material that leaks credential values.
3. Preserve stored-source behavior and add portable revision cases when the live contract is settled.

## Acceptance tests

- [ ] A live credential rotated after approval produces no egress under that lease.
- [ ] A metadata-only update with the same credential revision leaves the lease usable.
- [ ] A provider lacking a verifiable revision denies the invocation.

## Delivery

- Branch `agent-vault/gap-1-live-revision`.
- Base and PR target `integration/agent-vault`.
- PR title `GAP-1: Bind live Proton leases to an approved credential revision`.
