# Remote custody for root-compromise resistance

## Why it is necessary

A same-host root process can generally inspect or tamper with ordinary userspace processes, files, IPC, and memory. Therefore no same-host Python/Rust password daemon can honestly promise that a hostile root process is cryptographically unable to recover its in-memory vault key.

For the stated threat model, move credential custody off the coding/agent host.

## Recommended trust split

```text
A. Agent/compute host                         B. Credential-custody host
----------------------------------------      ---------------------------------
Hermes / OMP / Codex / Cursor                 passd only
Kerdoios / z0int runtime                      scoped Proton AGENT session
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

The custody host stores the Proton agent PAT in passd's encrypted internal store
and owns `<data dir>/proton-agent/session` with mode 0700. Deliver and rotate the
PAT through the human local admin path only; the agent gateway cannot manage or
read it. Use item-level viewer grants and the persistent `passd proton-agent
disable` kill switch. See [PROTON_AGENT.md](PROTON_AGENT.md). An encrypted imported
mirror remains optional legacy storage; ZIP import is deprecated and never a
fallback when a live-source read fails.

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

## Remote gateway

Run the daemon on the custody host, then bind the gateway to its Tailscale IP:

```bash
# Custody host:
passd gateway --listen 100.101.102.103:9473

# Agent host, without local vault state or a master password:
export PASSD_REMOTE=100.101.102.103:9473
export PASSD_AGENT_TOKEN='pda_...'
export PASSD_AGENT_REASON='Current task needs one approved API call'
passd capability list
passd capability request openrouter.infer --path /api/v1/chat/completions --uses 1
```

Approve on the custody host through the local Unix socket, with `PASSD_REMOTE`
unset. The agent can then use `passd capability invoke` and `passd access status`.
The gateway forwards only `capability.list`, `capability.request`,
`capability.invoke`, `access.request`, and `access.status`. Every request needs an
agent token. Admin passwords and all other operations are refused.

The gateway forwards to `Config.socket_path` or `PASSD_SOCKET` without unlocking
the vault. Default source CIDRs are
`100.64.0.0/10`, `fd7a:115c:a1e0::/48`, `127.0.0.0/8`, and `::1/128`.
Repeat `--allow-cidr CIDR` to replace that list. Use `[IPv6]:PORT` for IPv6.
Wildcard binds require
`--i-know-what-im-doing`. The gateway accepts at most 32 concurrent connections;
set `--max-connections N` to change the limit. Extra connections close before a
worker starts. Request lines are limited to 1 MiB and must arrive within 10 seconds,
even if bytes keep arriving. The socket idle timeout is 60 seconds. Logs contain
timestamp, peer IP, operation, and success/error code; unrecognized operations are
logged as `-`. Unexpected exceptions log only their class name, and internal error
responses use the fixed message `internal error`.

The gateway is plain TCP. Tailscale provides WireGuard transport encryption and
device identity; passd provides agent authentication and lease enforcement.
CIDRs alone do not establish device identity. Bind to the tailnet IP and restrict
reachability with tailnet policy. The agent-host root-compromise property requires
a custody host with no coding agents or agent-controlled sudo. A stolen agent
token can still consume that machine's active leases.

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
