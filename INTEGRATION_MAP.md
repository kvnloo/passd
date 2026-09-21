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

## AODL

AODL remains the intent/graph IR. Authority belongs in the intent constraints / Gamma layer as capability IDs and budgets, for example conceptually:

```text
requires: openrouter.infer
maxUses: 3
maxTTL: 5m
humanGate: required
```

AODL must not embed password-manager selectors or machine-token secrets.

## z0intelligence

z0intelligence may learn:

- which capability a workflow usually needs;
- when to pre-submit a request;
- which requests humans routinely deny;
- expected lease duration/use count;
- latency regressions and provider routing.

It must remain advisory. Model confidence never becomes grant authority.

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

## Dash / Company OS

These are good HITL surfaces, but they should render immutable authority requests rather than receive vault credentials.

The UI should show:

```text
agent identity
capability ID
operation method/path or typed slots
reason
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

Do not ingest decrypted credential values or private selector/reason payloads by default.

## frontier-kb

Use frontier-kb for research/protocol evidence. It should not be runtime authority or secret storage.

## Overall critical path

```text
Natural-language work
   -> AODL intent/constraints
   -> z0int predicts likely capability need
   -> Hermes/OMP requests typed capability
   -> authority HITL
   -> passd OR privilege-broker provider executes
   -> AgentTrace/receipts measure
   -> Evolution Lab optimizes latency implementation
```

No component except the authority provider can turn a prediction into privilege.
