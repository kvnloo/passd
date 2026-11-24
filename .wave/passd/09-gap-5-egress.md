# GAP-5: Bind broker connections to validated addresses

## Why

Destination checks use a separate DNS lookup from the HTTP connection, so the checked answer may differ from the address used.

## Files and functions

`passd/service.py:_validate_target`, `passd/service.py:_execute_http`, and the outbound transport.

## Specification

1. Carry a validated address from policy evaluation into connection setup and preserve hostname-based TLS checks and authority.
2. Keep redirect and proxy restrictions. Apply the same address policy to any retry or alternate address.
3. Fail closed on validation, TLS or connection mismatch before any credential is sent to an unapproved address.

## Acceptance tests

- [ ] An injected resolver and recording transport verify only the validated address is dialed even when later resolution changes.
- [ ] Certificate hostname verification still uses the approved origin.
- [ ] Private answers under production defaults and redirect targets receive no credential.

## Delivery

- Branch `agent-vault/gap-5-egress`.
- Base and PR target `integration/agent-vault`.
- PR title `GAP-5: Bind broker connections to validated addresses`.
