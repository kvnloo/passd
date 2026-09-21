# Integration map for Kevin's automation stack

The goal is one authority vocabulary, not another orchestration platform.

## Hermes / OMP / Firstmate

Normal agents receive only:

```text
PASSD_AGENT_TOKEN
capability list/request/invoke
```

Harness skills should ask for a capability ID, never a vault selector. A task that needs OpenRouter requests `openrouter.infer`; it does not ask for `OPENROUTER_API_KEY`.

Use a persistent `PassdSession` for in-process integrations. Shelling out to the CLI is convenient but not the latency-critical path.

## Sensitive-data / private execution zone

The broader PII architecture does **not** make `passd` a document store.

Keep three things separate:

```text
passd
  credentials + destination-bound secret use + HITL authority

external document system
  PDFs / statements / tax documents / OCR / metadata

private executor
  local-only model or deterministic domain engine that may consume raw PII
  and returns only a typed sanitized receipt
```

The frontier Hermes model should not receive the underlying document bytes, browser cookies, SSN, account numbers, or credentials.

Decision order for sensitive workflows:

```text
API before browser
deterministic engine before LLM
local/private model before redaction
frontier model only after sanitization
```

Example:

```text
Hermes: financial.statement.acquire(checking.primary, 2026-01)
  -> institution API if available
  -> otherwise private browser worker
       -> passd/model-blind vault supplies login
       -> local worker downloads statement
  -> external document system stores/OCRs it
  -> Hermes receives {stored, period, opaque_handle}
```

Later:

```text
Hermes: tax.prepare(2026)
  -> private executor resolves approved document handles
  -> local extraction / local model as needed
  -> deterministic tax engine computes authoritative values
  -> Hermes receives missing-fields / validation / ready-to-file state
```

No PDF storage, OCR pipeline, tax engine, or PII corpus belongs in `passd`.

See `PRIVATE_EXECUTION.md`.

## AODL

AODL remains the intent/graph IR. Authority belongs in the intent constraints / Gamma layer as capability IDs and budgets, for example conceptually:

```text
requires: openrouter.infer
maxUses: 3
maxTTL: 5m
humanGate: required
```

AODL must not embed password-manager selectors, document-store identifiers that reveal sensitive metadata, or machine-token secrets.

## z0intelligence

z0intelligence may learn:

- which capability a workflow usually needs;
- when to pre-submit a request;
- which requests humans routinely deny;
- expected lease duration/use count;
- latency regressions and provider routing.

It must remain advisory. Model confidence never becomes grant authority.

For sensitive workflows it may learn that a task usually needs a private operation such as `tax.prepare`, but it must not learn raw SSNs, account numbers, or document contents into model weights.

The benchmark JSON in `benchmarks/` is suitable for Evolution Lab/z0int candidate evaluation because it contains timing, not secret material.

## Evolution Lab

Evolve implementation mechanics against frozen invariants:

```text
objective: lower latency / memory / CPU
constraints: all security tests green
sealed: authority digest semantics, scope rules, one-use atomicity, HITL boundaries
```

Promotion should require TDD + latency receipt + adversarial security suite.

## Kerdoios

Kerdoios currently has work around a Bitwarden/vault resolver for provider keys. The cleaner target is a `CapabilityInvoker` abstraction:

```text
need Groq -> groq.infer
need Cerebras -> cerebras.infer
need paid OpenRouter overflow -> openrouter.infer
```

Kerdoios can plan whether a provider is available without ever resolving its API key into the Hermes process.

Public/free provider discovery remains keyless and bypasses `passd` entirely.

## hermes-privilege-broker

Do not merge it with `passd`.

Share:

- request IDs;
- typed operation/capability IDs;
- canonical digest rules;
- TTL/use-budget language;
- HITL renderer;
- receipt schema.

Keep separate:

- root executor/process memory;
- credential vault/root key;
- sockets/service users;
- provider-specific validation.

## Document systems (Paperless-ngx / equivalent)

Use an existing document-management system for:

- PDFs/statements/tax documents;
- OCR and full-text indexing;
- metadata/tags;
- static user/group/document permissions;
- retention and backup.

Do not duplicate those features in `passd`.

Dynamic task authority should sit outside the DMS: the private executor receives a bounded operation and approved opaque document handles, then returns a sanitized receipt.

## PII middleware (Presidio / PAW / equivalent)

PII detection/redaction is defense-in-depth at the **private -> frontier/provider** boundary.

It is not the primary custody mechanism and should not be used to justify sending arbitrary raw tax/bank documents to a remote model.

## Dash / Company OS

These are good HITL surfaces, but they should render immutable authority requests rather than receive vault credentials or raw PII.

The UI should show:

```text
agent identity
capability ID
operation
reason
resource count/class, not secret values
destination
TTL / use budget
request digest
```

Approval should ultimately become a narrow signed decision, not distribution of the passd master password.

## AgentTrace

Ingest redacted authority receipts for performance/governance analysis:

- capability/operation ID;
- allowed/denied;
- request -> decision latency;
- policy evaluation latency;
- provider call latency;
- lease exhaustion/staleness.

Do not ingest decrypted credential values, private selectors/reasons, raw PII, or document contents by default.

## frontier-kb

Use frontier-kb for research/protocol evidence. It should not be runtime authority, credential storage, or raw sensitive-document storage.

## Overall critical path

```text
Natural-language work
   -> AODL intent/constraints
   -> z0int predicts likely capability/private-operation need
   -> Hermes requests typed authority
   -> HITL / standing deterministic policy
   -> passd (credentials) OR privilege broker OR private executor
   -> only bounded receipt returns
   -> AgentTrace measures
   -> Evolution Lab optimizes implementation
```

No component except the authority provider can turn a prediction into privilege.
