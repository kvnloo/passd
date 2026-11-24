# Proton enrollment and rotation

Run the stock, entitlement-enforcing Proton CLI on a trusted owner OS account.
The agent OS account never performs owner login. The owner account and the
broker service account have separate Proton session directories. Run the
procedure at a trusted terminal on the custody host, with a local
owner-authorized path to the broker socket. If the socket belongs to the
dedicated `passd` account, use the deployment's narrowly authorized local
command wrapper to run the three documented passd admin operations as that
account. Preserve stdin for the PAT pipe and use the controlling terminal for
authentication. Never route custody administration through the agent gateway.

Use a fresh Bash process, trusted absolute binaries or a trusted PATH, and
a temporary filesystem for the session directory where available. Keep shell
tracing, terminal recording and CLI debug logging off. The broker must already
be initialized and unlocked. Set the broker config's `proton_agent.name` to
`passd-<host>`, using the custody host's chosen label. Stopping and restarting
with updated config loads the new name.

## Enroll once

The sequence assumes `passd` resolves to the trusted local admin path and
targets the correct store. The owner enters the passd master passphrase at
the masked controlling-terminal prompts. The Proton account login has its
own separate prompts. Start with a fresh Proton agent name. A pre-existing
name requires the renewal or recovery procedure.

```bash
set +x
set -euo pipefail
umask 077
read -r -p 'Custody host label: ' host_label </dev/tty
[[ "$host_label" =~ ^[a-z0-9][a-z0-9-]*$ ]]
agent_name="passd-${host_label}"

unset PASSD_REMOTE PASSD_AGENT_TOKEN PASSD_MASTER_PASSWORD PASSD_MASTER_PASSWORD_FILE
while IFS= read -r variable; do
  unset "$variable"
done < <(compgen -v PROTON_PASS_ || true)
unset RUST_LOG RUST_BACKTRACE
session_dir=$(mktemp -d "${TMPDIR:-/tmp}/proton-enroll.XXXXXXXX")
export PROTON_PASS_SESSION_DIR="$session_dir"
export PROTON_PASS_KEY_PROVIDER=fs
created=0
cleanup() {
  local status=$?
  trap - EXIT
  if (( status != 0 && created == 1 )); then
    pass-cli agent delete "$agent_name" >/dev/null 2>&1 ||
      printf '%s\n' 'Check and revoke the new Proton agent from a trusted owner session.' >&2
  fi
  if ! pass-cli logout --force >/dev/null 2>&1; then
    printf '%s\n' 'Owner logout was not confirmed; verify session revocation in Proton.' >&2
    status=1
  fi
  rm -rf -- "$session_dir" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if ! pass-cli login; then
  printf '%s\n' 'Enrollment stopped: Proton CLI login or entitlement failed. Check account entitlement with Proton before retrying.' >&2
  exit 1
fi

count_agents_vault() {
  pass-cli vault list --output json |
    jq -er '.vaults | select(type == "array") | map(select(.name == "agents")) | length'
}
if [[ $(count_agents_vault) == 0 ]]; then
  pass-cli vault create --name agents
fi
share_id=$(pass-cli vault list --output json |
  jq -er '[.vaults[] | select(.name == "agents")] |
    select(length == 1) | .[0].share_id | select(type == "string" and length > 0)')

pass-cli agent list --output json |
  jq -e --arg name "$agent_name" 'type == "array" and all(.[]; .name != $name)' >/dev/null
passd proton-agent disable

# Creation can succeed server-side before the CLI finishes. Arm cleanup first.
created=1
if ! pass-cli agent create "$agent_name" --expiration 1w --vault agents 2>/dev/null |
  jq -er '.token | select(type == "string") |
    select(test("^(PROTON_PASS_PERSONAL_ACCESS_TOKEN=)?pst_[^[:space:]]+::[^[:space:]]+$")) |
    sub("^PROTON_PASS_PERSONAL_ACCESS_TOKEN="; "")' 2>/dev/null |
  passd proton-agent set-pat; then
  printf '%s\n' 'Enrollment stopped: token creation or custody transfer failed.' >&2
  exit 1
fi

# Read authoritative grants while the owner session is still available.
grants=$(pass-cli pat access list-access --pat-name "$agent_name" --output json)
# Check before abandoning the owner session so failure can delete the agent.
check_grants() {
  jq -e --arg share "$share_id" '
    type == "array" and length == 1 and
    .[0].type == "vault" and .[0].vault_name == "agents" and
    .[0].share_id == $share and .[0].role == "Viewer"
  ' <<<"$grants" >/dev/null
}
if ! check_grants; then
  printf '%s\n' 'Enrollment stopped: expected exactly one agents vault viewer grant.' >&2
  exit 1
fi

pass-cli logout --force
rm -rf -- "$session_dir"
trap - EXIT HUP INT TERM
check_grants
unset grants PROTON_PASS_SESSION_DIR PROTON_PASS_KEY_PROVIDER

passd proton-agent enable
if ! passd proton-agent login ||
   ! passd proton-agent status | jq -e '.session_ok == true' >/dev/null; then
  passd proton-agent disable
  printf '%s\n' 'Broker session verification failed. Revoke the Proton agent from a fresh trusted owner session.' >&2
  exit 1
fi
```

Successful login in the clean directory is the entitlement gate. Stock
`login.rs:after_login` calls `can_use_cli()` and exits on refusal. A refusal
or unconfirmed login ends the procedure before vault or PAT operations.
`no-login-restriction` and every other entitlement bypass are prohibited.

Proton prints a JSON object to the pipe. The filter extracts the raw PAT from
its `token` field and strips the environment-assignment prefix. The PAT stays
in pipes, process memory and encrypted passd custody. `set-pat` reads stdin and
returns only a boolean status. The exact grant check excludes item, folder
and other vault grants and verifies the share ID independently of the display
name. Removing a session directory unlinks its contents. Use encrypted or
temporary storage where media remanence matters.

## Renew

Use the same owner session setup, entitlement gate, vault/share lookup,
grant check, and logout/wipe sequence. Require the existing agent name and
verify its exact grant set before renewal. Disable the source first. Replace
the create pipeline with the following, keeping its failure handling and
post-renewal grant check. Once renewal is attempted, treat the previous PAT
as unusable. Leave the source disabled on failure and delete the identity
if its replacement cannot be verified.

```bash
pass-cli agent renew "$agent_name" --expiration 1w --output json 2>/dev/null |
  jq -er '.token | select(type == "string") |
    select(test("^(PROTON_PASS_PERSONAL_ACCESS_TOKEN=)?pst_[^[:space:]]+::[^[:space:]]+$")) |
    sub("^PROTON_PASS_PERSONAL_ACCESS_TOKEN="; "")' 2>/dev/null |
  passd proton-agent set-pat
```

After owner cleanup, enable the broker source, log in with the new PAT, and
require `session_ok: true`. Confirm Proton's read audit with
`pass-cli agent monitor "$agent_name"` during a trusted owner session.
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
| PAT exposure | JSON-to-stdin pipe, no debug or capture, encrypted custody | No token in argv, transcript, shell history, files or command output |
| Main vault access | Exactly one viewer grant matched by share ID | Grant list equals the singleton `agents`; readiness probes a dummy main-vault selector for refusal |
| Partial create or renewal | Disable before mutation, attempt provider cleanup on error | Failure keeps broker disabled and provides actionable cleanup status |
| Stolen or expired PAT | One-week expiry, rotation, local disable and provider deletion | Old PAT denied, monitor shows reason, agent absent after delete |
