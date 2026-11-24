# Proton enrollment and rotation

Run the stock, entitlement-enforcing Proton CLI on a trusted owner OS account.
The agent OS account never performs owner login. The owner account and the
broker service account have separate Proton session directories. Run the
procedure at a trusted terminal on the custody host, with a local
owner-authorized path to the broker socket. If the socket belongs to the
dedicated `passd` account, use the deployment's narrowly authorized local
command wrapper to run enrollment and the recovery admin operations as that
account. Use the controlling terminal for authentication. Never route custody
administration through the agent gateway.

Use a trusted PATH and a temporary filesystem for the owner session where
available. Keep shell tracing, terminal recording and CLI debug logging off.
The broker must already be initialized and unlocked. Set the broker config's
`proton_agent.name` to `passd-<host>`, using the custody host's chosen label.
Restart the broker to load the updated name.

## Enroll once

Run from the trusted local owner admin path:

```bash
passd enroll proton
```

Authenticate at the printed Proton web login URL. The command checks
entitlement in a fresh owner-only session before attempting any enrollment
changes. It creates the `agents` vault if needed and requires a single vault
with that name. If the configured agent already exists, use the renewal or
deletion procedure.

The command disables the broker source before creating a one-week viewer
agent. Stock `pass-cli agent create` emits JSON automatically. Its output
travels through a private child-process pipe, and passd extracts the PAT in
memory and hands it to encrypted custody over the local admin socket. The
command checks the grant type, role, vault name and share ID against the
single expected grant. A failed grant check or custody handoff triggers an
attempt to delete the agent while the owner session is still available.

The command logs out and removes the isolated owner session before testing
the broker session. If broker verification fails, the source stays disabled.
Revoke the agent from a fresh entitled owner session before retrying, using
the kill switch below. A successful command exits with status zero after
the broker session check.

## Renew

Start stock `pass-cli login` with a fresh 0700 `PROTON_PASS_SESSION_DIR` and
`PROTON_PASS_KEY_PROVIDER=fs`. Require successful owner login and confirm
that the configured agent exists and has exactly one viewer grant on the
expected `agents` share ID. Disable the broker source first, then pipe the
renewal output into custody. Set `agent_name` to the configured agent name
and enable shell `pipefail` before running the pipeline.

```bash
pass-cli agent renew "$agent_name" --expiration 1w --output json 2>/dev/null |
  jq -er '.token | select(type == "string") |
    select(test("^(PROTON_PASS_PERSONAL_ACCESS_TOKEN=)?pst_[^[:space:]]+::[^[:space:]]+$")) |
    sub("^PROTON_PASS_PERSONAL_ACCESS_TOKEN="; "")' 2>/dev/null |
  passd proton-agent set-pat
```

Once renewal is attempted, treat the previous PAT as unusable. Leave the
source disabled on failure and delete the identity if its replacement cannot
be verified. Check the exact grant again after renewal. Always run `pass-cli logout --force`
and remove the owner session directory, including if renewal fails. After owner
cleanup, enable the broker source, log in with the new PAT, and
require `session_ok: true`. Disable the source if verification fails. Confirm
Proton's read audit with `pass-cli agent monitor "$agent_name"` during a trusted
owner session.
The one-week token lifetime and the roughly two-hour PAT session lifetime
are separate. Session expiry requires broker reauthentication while the
PAT is valid. Schedule owner renewal before token expiry.

## Kill switch

On the broker's local admin path run `passd proton-agent disable`. This
blocks source resolution and removes its isolated session. In a fresh
entitled owner session run `pass-cli agent delete "$agent_name"`, confirm
absence in `pass-cli agent list --output json`, then log out and wipe the
owner session. Revoke affected passd leases and machine principals separately.
If owner login is unavailable, leave the broker disabled and escalate
provider revocation through the trusted owner account. A partially failed
handoff can leave an encrypted PAT record, so provider deletion is important.

## Threat table

| Threat | Control | Verification |
| --- | --- | --- |
| CLI entitlement refusal | Clean stock login and fail closed on any error | No creation or custody write after refusal |
| Owner session exposure | Trusted OS account, 0700 isolated directory, logout and removal | Agent UID cannot access owner files or local admin socket |
| PAT exposure | Private child-process pipe and encrypted custody | No token in argv, transcript, shell history, files or command output |
| Main vault access | Exactly one viewer grant matched by share ID | Grant list equals the singleton `agents`; readiness probes a dummy main-vault selector for refusal |
| Partial create or renewal | Disable before mutation, attempt provider cleanup on error | Failure keeps broker disabled and provides actionable cleanup status |
| Stolen or expired PAT | One-week expiry, rotation, local disable and provider deletion | Old PAT denied, monitor shows reason, agent absent after delete |
