# Private execution boundary

This document defines how `passd` participates in workflows involving raw PII and sensitive documents without becoming a document-management system.

## Scope

`passd` owns:

- credential custody;
- model-blind / destination-bound secret use;
- machine identity;
- immutable authority requests;
- HITL approval leases;
- redacted receipts.

`passd` does **not** own:

- PDFs or arbitrary document blobs;
- OCR/search/indexing;
- tax calculations;
- bank transaction history;
- a generic PII database;
- authenticated browser state;
- local-model orchestration.

Those live in specialized systems beside `passd`.

## Trust zones

```text
FRONTIER ZONE
Hermes / remote model
  - intent
  - planning
  - generic reasoning
  - no raw PII

        |
        | typed request / sanitized receipt
        v

PRIVATE EXECUTION ZONE
  passd credentials
  external document system
  private browser worker
  local-only SLM/VLM when needed
  deterministic domain engines
  outbound PII sanitizer
```

For hostile-root resistance, place the private execution zone on a different host from the agent/frontier runtime.

## Acquisition policy

Prefer the least-privileged path:

1. institution/API adapter;
2. deterministic local client;
3. private browser worker as fallback.

Browser login should use model-blind credential fill. Downloaded files should be intercepted into the document system rather than copied into an agent-visible Downloads directory.

## Reasoning policy

Use the least expressive component capable of the task:

1. deterministic parser/rules engine;
2. local/private model;
3. sanitized frontier escalation.

A local model may see raw PII if it runs inside the private zone with network egress denied and local-only logging. A frontier model should receive only the minimum structured facts required to answer the unresolved question.

## Egress policy

Anything crossing private -> frontier/provider should pass:

1. explicit output-schema allowlist;
2. PII detector/redactor;
3. secret/canary scanner;
4. size/logging bounds.

Redaction is defense-in-depth, not permission to export arbitrary raw files.

## Example: bank statement

```text
Hermes
  -> financial.statement.acquire(checking.primary, 2026-01)
  -> API if available, otherwise private browser
  -> passd supplies destination-bound login
  -> statement bytes go directly to document store
  -> private worker classifies/OCRs locally
  -> Hermes receives:
       {stored: true, period: "2026-01", handle: "opaque"}
```

## Example: tax preparation

```text
Hermes
  -> tax.prepare(2026)
  -> HITL authorizes exact document set/classes
  -> private executor loads real documents
  -> local extraction / local SLM handles ambiguity
  -> deterministic tax engine computes authoritative values
  -> Hermes receives:
       {missing_fields: [...], validation: "...", ready_to_file: true}
  -> tax.submit is a separate consequential-action approval
```

The frontier model does not need the SSN, W-2 PDF, bank account number, password, cookie jar, or completed tax return.

## Non-goal: universal authority broker

Do not turn `passd` into a generic arbitrary-RPC proxy. Typed capability kinds should be added only when a concrete credential-use path requires them.

Document/private-worker authority can reuse the same request/lease/receipt vocabulary without sharing storage or cryptographic root keys.
