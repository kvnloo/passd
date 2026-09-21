# passd local protocol v3

Transport: newline-delimited JSON over an owner-only Unix socket. Use a persistent socket for latency-sensitive agent SDK integration.

## Machine identity

```json
{
  "op": "capability.list",
  "params": {},
  "agent_token": "pda_MACHINE.SECRET"
}
```

Authentication proves a stable machine identity. It grants no capability lease.

## Admin defines a typed capability

```json
{
  "op": "capability.put",
  "admin_password": "...",
  "params": {
    "id": "openrouter.infer",
    "description": "OpenRouter inference",
    "kind": "http_secret",
    "backing_uri": "pass://Personal/OpenRouter/password",
    "scheme": "https",
    "host": "openrouter.ai",
    "port": 443,
    "methods": ["POST"],
    "path_prefix": "/api/v1/chat/completions",
    "inject_header": "Authorization",
    "inject_prefix": "Bearer ",
    "static_headers": {"Content-Type": "application/json"},
    "timeout_seconds": 20
  }
}
```

The definition is encrypted at rest. The response exposes only its public contract plus opaque `cv1_...` version.

## Agent catalog

```json
{"op":"capability.list","params":{},"agent_token":"pda_..."}
```

Example result:

```json
[
  {
    "id": "openrouter.infer",
    "version": "cv1_...",
    "kind": "http_secret",
    "description": "OpenRouter inference",
    "target_host": "openrouter.ai",
    "methods": ["POST"],
    "path_prefix": "/api/v1/chat/completions"
  }
]
```

No vault/item/backing URI is returned.

## Agent requests exact invocation authority

```json
{
  "op": "capability.request",
  "agent_token": "pda_...",
  "reason": "Current coding task needs inference",
  "params": {
    "capability_id": "openrouter.infer",
    "method": "POST",
    "path": "/api/v1/chat/completions",
    "ttl_seconds": 300,
    "max_uses": 1
  }
}
```

Result contains `status=pending`, `capability_version`, and an `ad1_...` authority digest. Exact retries while pending return the same request ID/digest.

## Human queue / approval

```json
{"op":"access.pending","admin_password":"...","params":{"limit":100}}
```

Approve:

```json
{
  "op": "access.approve",
  "admin_password": "...",
  "params": {
    "request": "req_...",
    "ttl_seconds": 120,
    "max_uses": 1,
    "note": "Approved for this task"
  }
}
```

Approval fails stale/closed if the capability version changed since request creation. It resolves the backing credential and stores a root-keyed exact credential-field version.

## Invoke

```json
{
  "op": "capability.invoke",
  "agent_token": "pda_...",
  "reason": "Execute approved inference",
  "params": {
    "capability_id": "openrouter.infer",
    "method": "POST",
    "path": "/api/v1/chat/completions",
    "body": "{...}"
  }
}
```

Invocation succeeds only if an active lease matches:

```text
agent ID
capability ID/version
method/path
credential-field version
expiry
remaining use count
```

One use is atomically claimed before outbound execution.

## Status / revoke

Agent:

```json
{"op":"access.status","agent_token":"pda_...","params":{"request":"req_..."}}
```

Human:

```json
{"op":"access.revoke","admin_password":"...","params":{"request":"req_..."}}
```

## Legacy exact-secret RPCs

The following v0.2 RPCs remain available for migration/backward compatibility:

```text
access.request
broker.http
secret.resolve
vault.list / item.list with metadata.read
```

Default v0.3 machine identities do not receive their required legacy scopes.

## Versioning semantics

- `cv1_...`: root-keyed opaque capability-definition version.
- `sv1_...`: root-keyed credential-field version, stored only inside encrypted request state.
- `ad1_...`: canonical request/approval digest.

`health` reports protocol version `3`.
