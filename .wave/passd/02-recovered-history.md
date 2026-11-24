# Integrate recovered passd branches and W1 specs

## Why

The Proton source branch already contains the remote gateway. Preserve that ancestry so the integration lane starts with both recovered features.

## Files and functions

`passd/gateway.py`, `passd/proton_agent.py`, `passd/service.py`, `spec/`, `tests/test_rlp_vectors.py`, and `.wave/passd/`.

## Specification

1. Verify that `1ddb161` is an ancestor of `e356555` and that `b97df87` is on the same history.
2. Bootstrap an absent `integration/agent-vault` at `e356555`. If the base already exists, preserve its work and merge recovered history in the topic branch.
3. Bring in the W1 spec and vector commits once and open the integration PR. Keep main out of the wave.

## Acceptance tests

- [ ] Assert both recovered commits occur in the integration result's ancestry.
- [ ] Run the full tests and the vector manifest check on the integration result.
- [ ] Verify the PR base is integration/agent-vault and the diff contains both specs and vectors relative to the recovered code.

## Delivery

- Branch `agent-vault/recovered-history`.
- Base and PR target `integration/agent-vault`.
- PR title `Integrate recovered passd branches and W1 specs`.
