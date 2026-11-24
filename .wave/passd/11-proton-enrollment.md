# Implement passd enroll proton

## Why

Owner enrollment needs a repeatable, fail-closed process that handles token transfer and verifies the exact grant set.

## Files and functions

`passd/cli.py:build_parser`, `passd/cli.py:read_pat_stdin`, `passd/service.py:set_proton_agent_pat`, `passd/proton_agent.py`, and `spec/PROTON-ENROLLMENT.md`.

## Specification

1. Add `passd enroll proton` on the trusted owner OS path with a fresh isolated session. Require stock Proton login entitlement before mutation.
2. Ensure exactly one `agents` vault and create `passd-<host>` with a one-week viewer PAT. Pipe the JSON token into custody via stdin without logging it.
3. Verify the singleton share grant, logout and wipe the owner session, then verify the broker PAT session. Keep the broker disabled on partial failure and support renewal/deletion recovery.

## Acceptance tests

- [ ] An entitlement refusal prints an actionable error, never creates a token and cleans temporary state.
- [ ] A fake entitled CLI yields exactly one agents viewer grant and a successful broker session without leaking the dummy PAT into output, argv or files.
- [ ] A malformed or extra grant and a failed handoff keep the source disabled and invoke cleanup.

## Delivery

- Branch `agent-vault/proton-enrollment`.
- Base and PR target `integration/agent-vault`.
- PR title `Implement passd enroll proton`.
