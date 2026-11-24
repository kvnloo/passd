# Deploy passd under a dedicated broker system account

## Why

An agent running under the custody UID could access local sockets, session files and process state.

## Files and functions

Deployment unit, service and guard hooks, `passd/server.py:PassdUnixServer`, `passd/gateway.py:PassdGatewayServer`, and `REMOTE_CUSTODY.md`.

## Specification

1. Provision a dedicated system user `passd` with owner-only data directories and a system service outside the agent cluster. Owner supplies the masked privileged authorization for deployment.
2. Allow only agent operations on the tailnet gateway with restrictive ACLs. Give owner admin access through a narrow local path and preserve independent session storage.
3. Install guard hooks for direct credential tools, store access and privilege escalation as defense in depth. Document service stop and provider disable.

## Acceptance tests

- [ ] An agent UID cannot read the DB, provider session, key material or local admin socket.
- [ ] Only permitted peers reach the named gateway and administration is refused there.
- [ ] Service restart requires the defined custody unlock and kill-switch checks pass.

## Delivery

- Branch `agent-vault/broker-deploy`.
- Base and PR target `integration/agent-vault`.
- PR title `Deploy passd under a dedicated broker system account`.
