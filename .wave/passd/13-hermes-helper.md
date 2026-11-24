# Add the Hermes command-helper secret-source adapter

## Why

Hermes needs an owner-approved broker action while its agent runtime stays credential-blind.

## Files and functions

Hermes command-helper integration, passd client `capability.request`, `access.status` and `capability.invoke`, and GAP-2's owner-decision endpoint.

## Specification

1. Implement the Hermes seam as an action request and receipt exchange. If the helper contract returns a raw credential, extend the seam for brokered actions.
2. Present a phone approval card with exact digest, destination, purpose and one-use scope. Route the owner's response to the owner approval path.
3. Invoke only after approval, handle denial, expiry and transport ambiguity, and keep the custody unlock value on the W3-selected path.

## Acceptance tests

- [ ] Hermes can request and execute one approved dummy capability without seeing the injected field.
- [ ] Deny, timeout, digest mismatch and lease reuse result in no injection.
- [ ] Owner approval material never traverses the agent gateway.

## Delivery

- Branch `agent-vault/hermes-helper`.
- Base and PR target `integration/agent-vault`.
- PR title `Add the Hermes command-helper secret-source adapter`.
