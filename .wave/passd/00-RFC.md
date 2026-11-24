# RFC: passd RLP v1 and Proton-backed custody

Status: draft for owner and integration review. passd is the reference
implementation for the shared RLP v1 vectors. The TypeScript implementation
can replay them independently. Start from recovered passd history through
`e356555`, which already includes gateway commit `1ddb161`.

## Design

An agent authenticates with a machine token and requests an exact capability
invocation. The owner approves that reviewed authority. The custody broker
checks the credential version and destination and atomically spends a lease
use before injecting a credential into an upstream request. The agent
receives a receipt. passd keeps custody outside the agent account and exposes
only its agent RPC allowlist over the restricted tailnet.

Enrollment requires an entitled stock Proton CLI and a trusted owner OS
account. The only Proton grant is a viewer grant to the `agents` vault.
Transfer the one-week PAT over stdin into encrypted passd custody. The MAIN
vault retains the owner-generated custody passphrase and is unreachable from
the broker's Proton identity. The Hermes mobile intake design is pending the
W3 receipt. Until the owner changes the operating policy, require owner
approval for each use.

## Gap table

| ID | Acceptance target | Current limit |
| --- | --- | --- |
| GAP-1 | Verify live credential revision at execution | Live approval fingerprints selector and agent name |
| GAP-2 | Verify the owner's decision over the reviewed digest | Local password and request ID authorize review |
| GAP-3 | Agent API supports exact destination-bound typed operations only | Legacy local reveal and hostname-bound broker paths exist |
| GAP-4 | Upstream-derived receipts cannot disclose credentials | Literal redaction only |
| GAP-5 | Connect only to the validated egress address | Address validation and connection resolution are separate |
| GAP-6 | Durable terminal invocation audit | Audit covers selected outcomes and follows the use commit |

## Acceptance tests

- [ ] Replay every checksum-pinned RLP vector through passd and the companion implementation.
- [ ] Verify an unapproved, expired, exhausted, mismatched or revoked invocation produces no injection.
- [ ] Verify the owner path fails closed when Proton refuses CLI login and grants exactly `agents` when entitled.
- [ ] Verify owner unlock, one approval per use, injected dummy request, MAIN-vault refusal and revocation end to end.
- [ ] Demonstrate the agent OS user cannot access the custody socket, provider session or unlock material.

Use integration PRs into `integration/agent-vault`. Keep production and
`main` out of the issue wave. Use dummy values for acceptance. Owner approval
is required before enforcing draft Bend laws. See the ordered queue in
[START HERE](01-START-HERE.md) and [RLP v1](../../spec/RLP-v1.md).
