# Request-Lease Protocol v1

passd at `e356555` is the reference implementation. RLP v1 defines the typed
capability flow over passd's v3 RPC. Uppercase requirements describe enforced
behavior with implementation references. Numbered gaps identify requirements
that need implementation or deployment work.

## Principals and transport

- Machine operations MUST authenticate an unexpired, unrevoked `pda_<id>.<secret>`
  bearer token against its stored SHA-256 secret hash
  (`passd/service.py:authenticate_agent`, `passd/service.py:_token_hash`).
  A default token has capability request and invoke scopes, zero approved
  leases, and no secret access (`passd/service.py:handle`,
  `passd/service.py:create_agent`, `passd/service.py:_consume_capability_grant`).
- Capability definitions, approval, denial, revocation, and the full audit
  view MUST require local admin authentication
  (`passd/service.py:handle`, `passd/service.py:verify_admin_password`,
  `passd/gateway.py:GatewayHandler.handle`). The admin password identifies
  the admin principal. A human holds it under the deployment policy.
- Local RPC uses newline-delimited UTF-8 JSON over an owner-only Unix socket.
  Requests carry `op`, `params`, and the applicable `agent_token` or
  `admin_password`, plus `reason` for agent operations that require it.
  Remote RPC MUST allow only `capability.list/request/invoke` and
  `access.request/status`, require an agent token, and reject admin-password
  keys even inside nested objects or repeated fields
  (`passd/gateway.py:_agent_object`, `passd/gateway.py:GatewayHandler.handle`).
  The TCP gateway SHOULD run only on a protected tailnet with ACLs and a
  dedicated custody account. It has no application-layer TLS.

## Capability → request → approval

1. The broker MUST validate and normalize the admin-defined `http_secret`
   contract. The definition fixes a scheme, host, port, allowed methods, path
   prefix, header injection rules, timeout, and one stored field or Proton
   selector. The public catalog omits the backing selector and injection
   details (`passd/service.py:_normalize_capability_definition`,
   `passd/service.py:put_capability`, `passd/service.py:_public_capability`).
2. `capability.request` MUST require both capability scopes, a nonblank reason
   of at most 300 characters, a 60–86,400 second TTL and 1–100 uses
   (defaults 300 seconds and one use). Method is trimmed and uppercased.
   Path is an absolute path without authority, query, fragment or decoded
   parent traversal. The decoded path must fit the contract prefix, and the
   host must fit any configured agent ceiling. The request stores the exact
   method and parsed path, capability ID/version, and requesting agent.
   An identical pending request returns the existing row. Each agent can
   have at most 32 pending requests
   (`passd/service.py:handle`, `passd/service.py:request_capability`,
   `passd/service.py:_validate_capability_invocation`).
3. `access.approve` MUST transition only a pending request, validate the
   current capability version against the request, bind the credential version
   at approval, and cap approved TTL and budget at the requested values.
   Overrides are clamped to a minimum of 60 seconds and one use. Expiry is
   the broker's integer approval time plus approved TTL. A changed or removed
   capability makes the request stale and approval returns `conflict`
   (`passd/service.py:approve_access`). `access.deny` transitions pending
   requests to denied (`passd/service.py:deny_access`).

Approval binds the stored credential version as it exists at review time.
The request digest itself binds the capability contract, which includes the
backing selector. Invocation accepts an optional body, and the approval
binds the destination and method but does not bind the body or invocation
reason.

| Operation | RPC parameters |
| --- | --- |
| `capability.list` | None |
| `capability.request` | `capability_id`, `method`, `path`, `ttl_seconds`, `max_uses` |
| `access.pending` | Optional `status` and `limit` |
| `access.approve` | `request` ID, optional `ttl_seconds`, `max_uses` and `note` |
| `access.deny` | `request` ID and optional `note` |
| `capability.invoke` | `capability_id`, `method`, `path`, optional `body` |
| `access.status` | Optional `request` ID. Omit for the caller's queue |
| `access.revoke` | `request` ID |

The wire defaults for method and path are POST and `/` for both typed
request and invoke. See `passd/service.py:handle` for RPC dispatch.
This scope excludes the compatibility semantics of legacy `access.request`,
`broker.http`, `secret.resolve`, and metadata calls. The gateway still
allows legacy `access.request`, which cannot authorize typed invocation.

The request and lease share one request ID. `access.status` is scoped to the
authenticated requester and reports state, expiry, and remaining uses
(`passd/service.py:access_status`, `passd/service.py:_access_public`).
Expired or exhausted rows can still report `status: "approved"` and
`active: false`. Version staleness is evaluated in the decision path.

### Version and digest representation

The reference serializes digest material as compact UTF-8 JSON with sorted
object keys and non-ASCII characters emitted directly
(`passd/authority.py:canonical_json`). Treat versions and digests as opaque
across implementations. The capability version is `cv1_` plus hex
HMAC-SHA-256 over the normalized definition, domain-separated with
`passd/capability/version/v1` and a zero byte. Stored credential version is
`sv1_` with domain `passd/credential/version/v1` over item ID, field and
value. Both use the custody root key
(`passd/authority.py:keyed_version`, `passd/authority.py:credential_version`).
The authority and approval digests are `ad1_` plus hex SHA-256 of their
respective objects. Authority covers schema, request and agent IDs, action,
capability ID/version, exact method/path, reason, requested TTL and uses.
Approval covers its schema, request and agent IDs, authority digest,
capability action and ID/version, credential version, approved TTL and uses
(`passd/service.py:request_capability`, `passd/service.py:approve_access`,
`passd/authority.py:authority_digest`).

## Consume → inject → receipt

- Invocation MUST require invoke scope, a nonblank reason, and a matching
  approved lease for the authenticated agent. Exact method/path and capability
  ID/version bind the destination, including the scheme, host and port in the
  versioned contract. At consume, `now < expires_at` and
  `uses < max_uses` are required. Eligible leases are considered in expiry
  and then request-ID order. Use accounting MUST atomically increment a
  guarded row and confirm that it was updated before injection. A failed
  destination check, source fetch or HTTP execution after consume spends the
  use (`passd/service.py:_consume_capability_grant`,
  `passd/service.py:invoke_capability`).
- A stored credential's bound field value and item identity MUST match the
  approval. Changing the field value stales the lease. Re-encryption and
  non-secret item metadata changes preserve the version
  (`passd/service.py:_consume_capability_grant`,
  `passd/authority.py:credential_version`). Live Proton instead binds the
  source, selector and configured Proton agent name
  (`passd/service.py:_live_source_version`).
- The broker MUST build the typed destination from the contract, reject
  userinfo and check host ceilings and public DNS answers under default
  policy. It rejects plaintext HTTP outside explicit development mode.
  It fetches a Proton field only after consumption and target validation,
  uses a purpose and capability/lease reason for that read, and injects the
  scalar in the configured HTTP header
  (`passd/service.py:_validate_target`, `passd/service.py:invoke_capability`,
  `passd/proton_agent.py:ProtonAgentSource.resolve`).
- The HTTP client MUST disable ambient proxies and redirects, limit response
  bodies to 1 MiB, and redact literal credential occurrences from returned
  body and allowlisted header values. The receipt carries HTTP status,
  filtered response headers and UTF-8-decoded body, including for upstream
  HTTP errors (`passd/service.py:PassdService.__init__`,
  `passd/service.py:NoRedirect.redirect_request`,
  `passd/service.py:_execute_http`, `passd/service.py:_redact`).
- The typed flow MUST record accepted requests, admin decisions, successful
  exchanges, no-lease refusals and typed Proton source denials. Audit
  payloads are encrypted and audit retrieval is admin-only
  (`passd/service.py:request_capability`, `passd/service.py:approve_access`,
  `passd/service.py:deny_access`, `passd/service.py:revoke_access`,
  `passd/service.py:_consume_capability_grant`,
  `passd/service.py:invoke_capability`, `passd/service.py:audit`,
  `passd/service.py:handle`).

## Revocation and failures

An approved lease revoked by request ID MUST become ineligible for subsequent
consumes. Agent revocation MUST reject subsequent token authentications.
Rotation replaces the token secret under the same principal ID, so existing
leases can still match the replacement token. The Proton disable switch
MUST block subsequent source resolution and attempt logout and session cleanup.
Proton `agent delete` is the separate provider-side kill switch
(`passd/service.py:revoke_access`, `passd/service.py:_consume_capability_grant`,
`passd/service.py:revoke_agent`, `passd/service.py:authenticate_agent`,
`passd/service.py:rotate_agent`, `passd/proton_agent.py:ProtonAgentSource.disable`,
`passd/proton_agent.py:ProtonAgentSource._require_enabled`).

| Code | Meaning |
| --- | --- |
| `auth_error` | Missing, invalid, expired or revoked bearer, or failed admin auth |
| `permission_denied` | Scope/target denial or no eligible exact lease, including expiry, exhaustion and version mismatch |
| `not_found` | Missing referenced resource where the caller may learn it |
| `conflict` | Decision on a closed request, stale approval, pending limit or ambiguous reference |
| `validation_error` | Invalid contract or arguments, gateway framing/JSON errors, oversized HTTP response |
| `proton_agent_denial` | Unclassified Proton source denial |
| `proton_agent_auth_expired`, `proton_agent_access_denied`, `proton_agent_item_not_found` | Provider authentication, grant or selector failure |
| `proton_agent_reason_required`, `proton_agent_unavailable`, `proton_agent_disabled` | Provider reason, CLI/session availability or local disable state |
| `forbidden_remote_op` | Gateway field, credential or operation restriction |
| `request_too_large` | RPC frame exceeds 2 MiB locally or 1 MiB remotely |
| `transport_error` | Gateway cannot complete local relay |
| `internal_error` | Unexpected failure with sanitized text |
| `passd_error` | Base error code |

Wire replies use `{"ok":true,"result":…}` or
`{"ok":false,"error":{"code":"…","message":"…"}}`. Clients SHOULD branch on
codes. The exception classes and transports implement the mapping
(`passd/errors.py:PassdError`, `passd/server.py:PassdHandler.handle`,
`passd/gateway.py:GatewayHandler.handle`).

## Gaps against intended deployment

| ID | Unenforced requirement | Current behavior |
| --- | --- | --- |
| GAP-1 | Live Proton leases MUST bind to the approved credential revision. | `_live_source_version` fingerprints selector and agent name. The provider value can change under that selector. |
| GAP-2 | Approval MUST carry a verifiable owner decision bound to the reviewed request digest. | `handle` verifies the local admin password. `approve_access` takes a request ID and generates its own approval digest. There is no phone signature or reviewed-digest input. |
| GAP-3 | Agent-facing surfaces MUST prevent raw secret delivery and require an exact typed destination. | Local legacy `reveal_secret` can return values for explicitly scoped leases. Legacy `broker_http` binds the hostname and accepts caller-supplied method, port and path. |
| GAP-4 | Production receipts MUST prevent disclosure through an untrusted upstream response. | `_execute_http` returns upstream-derived data with literal redaction. Transformed echoes and other upstream-controlled data can survive. |
| GAP-5 | The network connection MUST use an address that passed target validation. | `_validate_target` checks DNS answers separately from the HTTP client's connection resolution. |
| GAP-6 | Each invocation MUST produce a durable terminal audit outcome correlated to its lease when selected. | `invoke_capability` audits selected outcomes. Authentication, some validation and transport failures can exit unaudited, and the use transaction commits separately. |

Revocation does not recall a credential used by work already admitted. In
particular, agent authentication precedes consume, so the current kill
boundary for agent tokens is subsequent authentications. Rejecting new work
and draining or interrupting existing calls are distinct operational actions.

## Conformance vectors

Each JSON file in [vectors](vectors/) is an independent `version: 1`
scenario. Begin with a fresh broker, admin, default agent and stored scalar
credential revision 1. Configure capability `fixture.use` for that field and
a test sink accepting POST and GET under `/v1`. An accepted POST to
`/v1/use` receives HTTP 204. Values are generated by the runner. Each step
sets integer broker time `now` before `operation`. No step waits for time.

`request` defaults to POST `/v1/use`, TTL 60 and one use, and saves the returned
request ID for `approve` and `status`. `invoke` shares the default method and
path and may override them. Supply a fixed nonblank reason on agent calls.
`update_item` updates the same item identity using the indicated revision
(default 1) and note (default empty). `revoke_token` revokes the fixture
principal. `concurrent_invoke` starts `count` simultaneous default invocations
after all preceding steps and joins them before the next step. Compare the
result as an unordered multiset. An `expect` object projects result fields
or identifies an RPC failure with `error`. Successful invokes also require
one matching injected request at the sink. Verify `SHA256SUMS` against the
raw JSON bytes.
