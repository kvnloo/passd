# Security model v0.3

## Threat model

The intended adversary is an AI/automation process that may be buggy, prompt-injected, malicious, or fully compromised. Its machine API key may also be stolen.

For the strongest deployment, additionally assume the **entire agent host, including root, is compromised**. That requires remote credential custody; see [`REMOTE_CUSTODY.md`](REMOTE_CUSTODY.md).

## Identity is not authority

A `pda_...` token authenticates a stable machine identity and stores only capability ceilings. Default v0.3 machine identities receive:

```text
capability.request
capability.invoke
```

They receive no vault/item assignment and no raw reveal capability.

## Imported secrets are unreachable by default

Importing all Proton credentials does not expose them to agents. The new agent API has no automatic mapping from vault items to operations.

An administrator must explicitly define a typed capability such as `openrouter.infer`. The capability definition is encrypted and privately names its backing `pass://.../field`.

## Capability definition integrity

Each definition receives:

```text
cv1_HMAC(root_key, canonical_private_definition)
```

The version changes when any private/public contract field changes, but an attacker lacking the root key cannot use the public version as a dictionary oracle for hidden vault selectors.

## Authority request

A capability request binds:

- machine identity;
- capability ID;
- capability version;
- exact method;
- exact path;
- reason;
- requested TTL;
- requested use count.

Canonical content is hashed into an `ad1_...` request digest.

Exact pending retries are idempotent. Each machine can have at most 32 distinct pending requests.

## Approval

Human approval can only reduce TTL/use count. The approval resolves the backing secret on the trusted custody side and binds the lease to a root-keyed version of the **exact credential field**.

This means:

- credential rotation -> lease becomes `stale`;
- capability change -> lease becomes `stale`;
- note/title/URL metadata change -> lease remains valid if the approved credential value is unchanged;
- randomized at-rest re-encryption -> lease remains valid.

The approval record stores a second digest binding request digest + capability version + credential version + narrowed budget.

## Atomic use budgets

A use is claimed through a conditional SQLite update before the provider operation runs. One-use concurrency tests assert exactly one winner across eight simultaneous callers.

No network request is held under the SQLite policy lock.

## Typed HTTP capability constraints

Agent-controlled invocation supplies only:

```text
capability_id
method
path
body
reason
```

The agent cannot choose:

- destination scheme/host/port;
- secret selector;
- injection header/prefix;
- static headers;
- redirect policy;
- capability timeout ceiling.

Those are admin-side capability definition fields.

`passd` validates method/path against the frozen capability contract, disables redirects, validates the destination on the custody host, injects the secret there, and redacts exact secret echoes from the response.

## Legacy surface

v0.2 `pass://` leases and `broker.http` remain for compatibility. They are not granted by default to v0.3 machine identities. New automation should use typed capabilities.

## At-rest encryption

Encrypted with AES-256-GCM under the passd root-key hierarchy:

- vault metadata;
- item contents;
- capability private definitions/backing selectors;
- pending request private fields/reasons;
- HITL notes;
- audit reason/detail payloads.

Machine-token plaintext secrets are never stored, only SHA-256 verifiers of high-entropy random token material.

Indexed plaintext is limited to operational metadata such as opaque IDs, timestamps, status, operation class, destination host, use counters, and opaque versions/digests.

## Same-host root limitation

A same-host root process can generally inspect/tamper with ordinary process memory. Process boundaries, Unix socket permissions, Rust, or Python do not change that fundamental property.

Therefore this claim is **not** made:

> "root on the same machine cannot extract the vault key."

To make agent-host root compromise unable to decrypt the vault, keep passd/root key on another trust domain. Root on the agent host then has only a machine token and the network/IPC capability surface.

## Residual authority under full agent-host compromise

A fully compromised agent host can steal the machine token and act as that machine. It can submit requests and consume already-approved exact leases.

It still cannot, through the v0.3 typed API:

- decrypt unrelated vault items;
- create/update capabilities;
- approve its own requests;
- convert a capability lease to raw vault access;
- choose a different credential/header/host;
- extend TTL/use budget;
- access the remote custody root key.

## Custody-host compromise

If root/kernel on the **custody host** is compromised while the root key is in memory, normal software isolation cannot protect the vault. Stronger protection there requires hardware-backed key release/HSM/TEE and is outside v0.3.

## Python memory

Python immutable values cannot guarantee deterministic memory zeroization. v0.3 minimizes secret lifetime and persistence, but a future native custody core may be justified for memory hygiene. The current latency results do not require a Rust port for speed.

## v0.3.1 hardening

Three bypass-oriented regressions are part of the test suite:

- **Auth-before-lookup:** admin secret resolution authenticates before parsing/resolving the `pass://` selector. Existing and nonexistent selectors are therefore indistinguishable to an unauthenticated same-UID caller.
- **Auth-before-DNS:** admin HTTP broker calls authenticate before any caller-controlled hostname resolution.
- **No ambient proxies:** the custody HTTP transport installs an explicit empty `ProxyHandler`, ignoring inherited `HTTP_PROXY`, `HTTPS_PROXY`, and related environment configuration. An approved secret therefore cannot be silently diverted through an ambient process proxy.

These fixes do not change the typed capability/HITL authority model.

