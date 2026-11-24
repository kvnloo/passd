# Start here: passd agent-vault issue wave

Status: W1 specification and vectors ready for integration review. Implementation
issues below are queued. W3 intake evidence and the owner's Proton entitlement
are outstanding readiness gates. The companion implementation consumes the
same JSON vectors through its own integration lane.

## Ordered queue and lanes

| Order | Lane | Issue bodies | Status |
| --- | --- | --- | --- |
| 1 | Integration | 02 recovered history and W1 | Queued, first dependency |
| 2 | Verification | 03 macOS portability and 04 vector CI | Queued after 02, can proceed in parallel |
| 3 | Protocol | 05–10, GAP-1 through GAP-6 | Queued after 02, coordinate overlapping service edits |
| 4 | Enrollment and custody | 11 enrollment, 12 unlock, 13 Hermes seam | Enrollment can start after 02. Unlock intake depends on W3. Hermes approval depends on GAP-2 |
| 5 | Operations and governance | 14 broker deploy, 15 Bend laws | Prepare in parallel. Deployment needs owner privilege. Enforcement needs owner approval |
| 6 | Readiness | 16 end-to-end script | Script can be drafted with fixtures. Run live after entitlement, deployment, enrollment, unlock and applicable gaps |

## Working rules

Branch each implementation task from `integration/agent-vault` and target
the same branch in its PR. The integration issue bootstraps the base from
the recovered history before opening its review PR. Never target or merge
to `main` in this wave. Use stock Proton CLI with entitlement enforcement
and fail closed on refusal. Entitlement bypass is prohibited. Keep secrets,
owner session artifacts and real host details out of issue bodies and tests.
Use the RFC, its numbered gaps and the SHA-256-pinned vectors as the shared
contract. Run full local tests and report exact failures by name.

The program is ready for owner testing after entitlement is confirmed, the
isolated broker service runs under `passd`, and the end-to-end readiness
checks pass. Draft Bend laws await separate owner approval.
