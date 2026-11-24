# Draft Bend laws for agent credential access

## Why

The owner requested enforceable broker rules with review before activation.

## Files and functions

Draft policy document, `spec/RLP-v1.md`, deployment guard hooks, and owner approval path.

## Specification

1. Draft rules requiring typed broker actions, owner approval for each use, agents-vault-only provider scope, and an entitlement-respecting owner login.
2. Define enforcement points, failure behavior, audit evidence, exceptions with explicit owner review, and rollback.
3. Submit the draft for owner approval and leave enforcement off until explicit approval.

## Acceptance tests

- [ ] A policy review maps every law to a control and a reproducible dummy test.
- [ ] Drafting changes no running guard, service setting or approval rule.
- [ ] The proposed activation procedure verifies explicit owner approval first.

## Delivery

- Branch `agent-vault/bend-laws`.
- Base and PR target `integration/agent-vault`.
- PR title `Draft Bend laws for agent credential access`.
