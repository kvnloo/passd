# Remote custody for root-compromise resistance

## Why it is necessary

A same-host root process can generally inspect or tamper with ordinary userspace processes, files, IPC, and memory. Therefore no same-host Python/Rust password daemon can honestly promise that a hostile root process is cryptographically unable to recover its in-memory vault key.

For the stated threat model, move credential custody off the coding/agent host.

## Recommended trust split

```text
A. Agent/compute host                         B. Credential-custody host
----------------------------------------      ---------------------------------
Hermes / OMP / Codex / Cursor                 passd only
Kerdoios / z0int runtime                      encrypted Proton mirror
hermes-privilege-broker (root actions)        root key / master unlock
PASSD_AGENT_TOKEN only                        outbound provider connections
NO passd master password                      NO general coding agents
NO passd database/root key                    NO agent-controlled sudo

C. Human approval device / admin path
----------------------------------------
review request digest + reason + budgets
approve/deny
no routine secret reveal
```

## What an agent-host root compromise can do

Assume the attacker obtains the machine API token and full control of the agent host.

It can:

- impersonate that machine identity;
- submit pending capability requests;
- invoke capabilities while an exact lease is active;
- read whatever normal provider response the approved capability returns.

It cannot, from the `passd` protocol alone:

- enumerate the backing Proton vault;
- derive `pass://` backing selectors from capability versions;
- change capability definitions;
- approve its own requests;
- request raw reveal unless such a legacy/reveal surface was explicitly enabled;
- decrypt unrelated credentials;
- read the custody host's root key or encrypted database.

## Sudo broker relationship

Keep `hermes-privilege-broker` on the agent host because it must perform local root actions. It should never receive the `passd` root key or master password.

A root action like `service.restart` and a credential action like `openrouter.infer` may share authority-contract semantics, but each provider enforces its own typed operation.

This means even `sudo` on the agent host is not automatically a vault decryption capability: the vault key is physically elsewhere.

## Human gate placement

Do not place `PASSD_MASTER_PASSWORD` in an agent-readable environment, repo, shell history, or service config on the agent host.

v0.3 approvals still use the trusted admin path. Run approval from the custody host or a separate administrative path. A future step is a narrow operator signer that signs the approval digest without possessing vault-decryption authority.

## Custody-host hardening

Prefer:

- dedicated OS user;
- encrypted disk;
- no coding-agent runtime;
- minimal installed services;
- explicit outbound network policy;
- manual or hardware-backed unlock when practical;
- separate backups of encrypted vault state;
- audit export that never includes secret/reason plaintext unless intentionally decrypted by the administrator.

The next high-assurance improvement should be hardware-backed root-key release or an external signer, not more agent-side policy code.
