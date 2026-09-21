# passd-local v0.3.1

`passd` is a small encrypted credential-custody service for AI agents. The v0.3 design is intentionally narrower than a password-manager API:

- agents authenticate as stable machine identities;
- machine identity grants **no credential authority**;
- agents request named **typed capabilities**, not vault items;
- a human approves an exact, short-lived/use-limited lease;
- `passd` uses the backing credential without returning it whenever possible.

The full Proton vault can be imported, but importing a credential does **not** make it agent-accessible. A secret becomes requestable only when an administrator explicitly maps it to a capability.

## The v0.3 invariant

```text
Proton / human vault
        |
        | one-way snapshot import
        v
  encrypted passd custody
        |
        | admin-only mapping
        v
  capability: openrouter.infer
        |
        | machine requests exact method/path + TTL/use budget
        v
  pending authority request
        |
        | human approve / deny
        v
  ephemeral lease
        |
        | secret stays inside custody process
        v
  provider API response -> agent
```

The normal agent path never needs `pass://Personal/OpenRouter/password` and never needs vault enumeration.

## Why capabilities instead of vault access

A password manager is organized around *where a secret is stored*. An agent should be organized around *what operation it is allowed to perform*.

Bad agent-facing primitive:

```text
pass://Personal/OpenRouter/password
```

Preferred primitive:

```text
openrouter.infer
```

The capability definition privately binds:

- exact backing credential field;
- destination scheme/hostname/port;
- allowed HTTP method(s);
- path prefix;
- secret-injection header/prefix;
- static headers;
- timeout.

Only the capability ID and non-secret public contract are visible to the agent.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

Python 3.11+ and `cryptography` are required.

## Initialize / serve

```bash
export PASSD_MASTER_PASSWORD='use-a-real-secret-source-in-production'
passd init
passd serve
```

The local daemon uses an owner-only Unix socket (`0600`). Data directory is `0700`; config/database are `0600`.

For high-assurance use, do **not** colocate custody with coding agents. See [`REMOTE_CUSTODY.md`](REMOTE_CUSTODY.md).

## Import credentials

```bash
passd sync import-proton 'Proton Pass_export_....zip'
```

The Proton bridge is one-way/upsert-only. It does not call Proton's paid CLI service or bypass Proton production entitlement checks.

Manual local example:

```bash
passd vault create Personal
passd item put-login \
  --vault Personal \
  --title OpenRouter \
  --password-file /secure/path/openrouter-key
```

Vault/item commands are admin/migration surfaces. New agent integrations should use capabilities.

## Define one requestable capability

Admin side:

```bash
passd capability put-http openrouter.infer \
  --description 'OpenRouter inference' \
  --backing-uri 'pass://Personal/OpenRouter/password' \
  --host openrouter.ai \
  --method POST \
  --path-prefix /api/v1/chat/completions \
  --static-header 'Content-Type=application/json'
```

A capability version is a root-keyed HMAC over its complete private definition. The public `cv1_...` version therefore changes whenever the contract/backing changes, but it cannot be used offline to confirm guesses about hidden vault selectors.

## Create an AI machine identity

```bash
passd agent create hermes --expiration 1d
```

v0.3 defaults to:

```text
capability.request
capability.invoke
```

It does not default to vault metadata, `secret.use`, or `secret.reveal`.

The returned `pda_...` token authenticates the machine only. No capability is approved by possession of the token.

## Agent workflow

```bash
export PASSD_AGENT_TOKEN='pda_...'
export PASSD_AGENT_REASON='Current coding task needs one OpenRouter inference call'
```

Discover intentionally requestable operations:

```bash
passd capability list
```

The catalog contains the capability ID and public contract, not `pass://` backing selectors.

Before approval, invocation fails:

```bash
passd capability invoke openrouter.infer \
  --method POST \
  --path /api/v1/chat/completions \
  --body '{"model":"...","messages":[]}'
# permission_denied
```

Request exact authority:

```bash
passd capability request openrouter.infer \
  --method POST \
  --path /api/v1/chat/completions \
  --expiration 5m \
  --uses 1
```

The request receives an immutable `ad1_...` authority digest binding machine identity, capability ID/version, method, path, reason, requested TTL, and requested use budget.

## Human gate

Trusted side:

```bash
passd access pending
passd access approve req_... --expiration 2m --uses 1
# or
passd access deny req_... --note 'Not needed for this task'
```

Approval can only narrow the requested TTL/use budget.

The resulting approval record binds:

```text
machine identity
+ request digest
+ capability version
+ exact credential-field version
+ exact method/path
+ expiration
+ atomic use budget
```

A capability-definition change or actual credential rotation makes the lease `stale`. Editing unrelated item metadata does not.

## Invoke without revealing the credential

```bash
passd capability invoke openrouter.infer \
  --method POST \
  --path /api/v1/chat/completions \
  --body @request.json
```

(`passd` CLI uses `--body-file request.json`; `@...` above is conceptual.)

Actual CLI:

```bash
passd capability invoke openrouter.infer \
  --method POST \
  --path /api/v1/chat/completions \
  --body-file request.json
```

`passd` injects the credential on the custody side and returns the provider response. The secret is never returned as a separate field, redirects are disabled, and exact secret echoes are redacted.

## Legacy compatibility

v0.2 exact-selector APIs remain available for migration/tests:

- `access request pass://...`
- `broker-http`
- `secret.resolve`
- optional `metadata.read`, `secret.use`, `secret.reveal` machine scopes.

They are not the recommended AI-native interface. A default v0.3 agent lacks those scopes.

## Authority kernel alignment

The important reusable object is not a vault. It is:

```text
principal -> immutable request digest -> human decision -> bounded lease -> receipt
```

That contract should also back privileged local actions such as your `hermes-privilege-broker`. Do **not** merge root execution and credential custody into one process. See [`AUTHORITY_CONTRACT.md`](AUTHORITY_CONTRACT.md) and [`INTEGRATION_MAP.md`](INTEGRATION_MAP.md).

## Latency optimization kernel

```bash
PYTHONPATH=. python benchmarks/bench_capability.py --json
```

Same-host regression comparison:

```bash
python benchmarks/compare.py baseline.json candidate.json --max-regression-pct 20
```

or:

```bash
PASSD_BENCH_BASELINE=baseline.json benchmarks/run_kernel.sh candidate.json
```

The benchmark receipt is deliberately separate from the security ledger. z0intelligence/Evolution Lab may optimize implementation mechanics, but benchmark automation has no authority to weaken capability meaning, TTLs, use budgets, or HITL requirements.

See [`BENCHMARKS.md`](BENCHMARKS.md).

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite includes legacy v0.2 regressions plus typed-capability TDD, concurrency, migrations, encrypted-at-rest checks, process-level CLI tests, and exact version invalidation.

## High-assurance deployment

The strongest practical boundary for your use case is physical/process separation:

```text
AGENT HOST (assume root compromise)      CUSTODY HOST
Hermes / OMP / Codex                     passd
sudo privilege broker                    encrypted vault + root key
machine API key                          outbound secret-use broker
NO vault root key              --->      NO coding-agent execution
```

If the agent host is fully compromised, the attacker can impersonate that machine and abuse currently active leases. It still cannot decrypt unrelated vault contents because those keys never exist on the compromised host.

Same-host `sudo/root` cannot be made cryptographically unable to inspect a same-host userspace vault process. If root-compromise resistance matters, remote custody is not optional.

## v0.3.1 hardening

The first bypass-focused review after v0.3 closed two local attack surfaces without widening the architecture: admin authentication now happens before selector/DNS work, and the custody HTTP client ignores inherited proxy environment variables. See `TESTED.md` and `SECURITY.md`.
