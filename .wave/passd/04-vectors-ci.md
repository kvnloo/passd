# Run RLP conformance vectors in CI

## Why

A shared protocol needs byte-pinned scenarios and an executable decision check on every integration change.

## Files and functions

`spec/vectors/*.json`, `spec/vectors/SHA256SUMS`, `tests/test_rlp_vectors.py`, and the repository CI configuration.

## Specification

1. Check manifest coverage and digests and replay every vector through the real broker on pull requests into integration.
2. Use explicit per-step time and no external services. Expose the failing vector name in CI output.
3. Document the command and checksum update procedure for companion implementations.

## Acceptance tests

- [ ] A modified vector with an old checksum fails CI.
- [ ] A deliberately wrong expectation with an updated checksum fails replay.
- [ ] An untouched checkout passes all vectors and lists them by case.

## Delivery

- Branch `agent-vault/vectors-ci`.
- Base and PR target `integration/agent-vault`.
- PR title `Run RLP conformance vectors in CI`.
