# Authority contract v1

The shared abstraction across credential use, sudo/root actions, signing, browser actions, and future privileged operations is:

```text
identity != authority

principal
  -> requests one typed operation
  -> immutable request digest
  -> independent decision
  -> short lease
  -> provider consumes lease atomically
  -> receipt
```

## Request digest

Typed `passd` capability requests generate an `ad1_...` digest over canonical JSON containing:

```json
{
  "schema": "passd-authority-v1",
  "request_id": "req_...",
  "agent_id": "pda_...",
  "action": "capability.invoke",
  "authority_kind": "capability",
  "capability_id": "openrouter.infer",
  "capability_version": "cv1_...",
  "method": "POST",
  "path": "/api/v1/chat/completions",
  "reason": "...",
  "requested_ttl": 300,
  "requested_uses": 1
}
```

The capability version is already root-keyed/opaque, so the digest does not disclose the backing vault selector.

## Approval digest

At approval, `passd` resolves the current backing credential and stores a second digest binding:

- request ID / principal;
- request authority digest;
- capability ID + version;
- root-keyed credential-field version;
- narrowed TTL;
- narrowed use budget.

This is the shape a future phone/hardware signer should sign. v0.3 still uses trusted admin/HITL command authentication; signature transport is deliberately deferred.

## Provider isolation

A provider owns custody/execution, not policy invention.

Examples:

```text
credential provider: passd
  owns encrypted vault + outbound broker

root provider: hermes-privilege-broker
  owns root-only typed executable catalog + spawn

signing provider: future SSH/Git signer
  owns private signing key + sign operation
```

Providers may share the request/lease/receipt contract. They must not share secret/root key material merely to reduce code duplication.

## Mapping to hermes-privilege-broker

`kvnloo/hermes-privilege-broker` already follows the same core idea:

```text
{request_id, operation_id, slots, reason}
-> canonical digest
-> separate operator decision
-> CSPRNG/TTL/one-use grant
-> durable reserve
-> execution receipt
```

The simplification target is a common schema/renderer/receipt vocabulary, not a common privileged process.

## AI boundary

A learned model may:

- predict likely capability needs;
- prebuild a pending request;
- choose a lower-cost provider implementation;
- optimize latency of policy evaluation;
- rank requests for the human.

It may never:

- mint its own grant;
- change TTL/use budget upward;
- change a capability backing selector;
- weaken a provider's validation rules;
- convert confidence into authority.
