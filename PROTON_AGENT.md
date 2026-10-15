# Live Proton agent credentials

`passd` can fetch one granted Proton Pass field at injection time using a Proton
Pass AGENT identity. The human account session is never used. Item-level viewer
grants limit what this identity can read, an expiring personal access token limits
its lifetime, and Proton's server audit records each reason. Agents cannot use
`--show-secrets`; passd always requests one `--field`.

This integration targets pass-cli 2.4.2 agent mode. Install the CLI on the custody
host. The coding host needs only its passd machine token and the gateway.

## Create the identity as the human

Run these commands in your trusted human terminal, outside passd's isolated
session. If needed, create a dedicated vault, then move only the required items
into it using your human password-manager workflow:

```bash
pass-cli vault create --name agents
```

Prefer creating the agent without a broad vault grant where supported, then grant
viewer access separately for each required item:

```bash
pass-cli agent create passd-groot --expiration 1m
pass-cli agent access grant passd-groot --vault-name agents --item-title "<item>" --role viewer
```

If your setup requires a vault-wide grant, the broader alternative is:

```bash
pass-cli agent create passd-groot --vault agents --expiration 1m
```

Choose one creation approach. Prefer item grants and viewer only. Keep the PAT
returned by creation on the human administrative path. Never paste it into a
coding agent, an agent-host environment, command arguments, or shell history.

## Configure the custody host

Optional settings in the existing passd `config.json`, alongside its existing
version, salt, and root check:

```json
{
  "proton_agent": {
    "binary": "/opt/proton/bin/pass-cli",
    "name": "passd-groot",
    "timeout_seconds": 20
  },
  "alert_command": ["/usr/local/sbin/passd-alert"]
}
```

The defaults are `pass-cli` resolved through PATH, agent name `passd-groot`, and a
20-second timeout. Restart the daemon after changing config. `alert_command` is
an optional argv list, executed without a shell, with a five-second timeout.
The hook receives `PASSD_ALERT_EVENT=proton_agent.auth_expired`, a minimal
environment, and no credentials or subprocess output. Hook failure does not
change the denial.

On the custody host, deliver the PAT over stdin from a human terminal. This
example prompts without echo and keeps the PAT out of shell history:

```bash
python3 -c 'import getpass; print(getpass.getpass("Agent PAT: "))' | passd proton-agent set-pat
passd proton-agent login
passd proton-agent status
```

These are local admin commands requiring the master password through the normal
trusted path. The gateway rejects them. `set-pat` accepts stdin only, disables
echo when stdin is a terminal, and accepts no PAT argument or environment input.
Do not run the delivery command from an AI agent process. Do not save the PAT in
an unencrypted scratch file.

The PAT is encrypted using passd's existing AES-GCM custody encryption under the
reserved internal name `__proton_agent_pat__`. Internal records live outside the
vault/item namespace. There is no PAT read, list, export, reveal, or capability
RPC. `status` reports `pat_set`, agent name, session directory, last successful
login time, expiry if known, disabled state, and the result of `pass-cli info`.
Expiry is currently unknown and reported as null; passd does not decode the PAT
or persist CLI output to infer it.

The session directory is `<data dir>/proton-agent/session`, created with mode
0700. Both it and its parent must be owned by passd's uid with no group/world
access; symlinks are refused. Session files are authentication material. Keep
them on the custody host with restricted disk and backup access.

Every CLI subprocess has only PATH, HOME pointing to `<data dir>/proton-agent`,
LANG, and the isolated `PROTON_PASS_SESSION_DIR`. The PAT is added only to
`login`; the reason is added only to `item view`. Ambient `PROTON_PASS_*`, XDG,
proxy, and other human settings are excluded. All invocations use argument lists,
closed stdin, and a timeout.

## Define a capability

On the trusted admin path:

```bash
passd capability put-http provider.call \
  --description 'Approved provider request' \
  --source proton-agent \
  --vault-name agents --item-title '<item>' --field password \
  --host api.example.com --method POST --path-prefix /v1/request
```

Use `--share-id S --item-id I --field F` instead of names when stable IDs are
available. The private capability definition uses:

```json
{
  "source": "proton-agent",
  "ref": {"share_id": "S", "item_id": "I", "field": "F"}
}
```

The alternative ref contains exactly `vault_name`, `item_title`, and `field`.
The source and entire ref participate in the encrypted definition and its
root-keyed version. Public catalogs hide the ref. Stored `backing_uri`
capabilities continue to work separately.

Agents follow the existing capability request, human approval, and invocation
flow. Live-source approval binds the source/ref and configured Proton agent name,
without reading Proton. Each invocation validates identity, approval, capability
version, exact method/path, expiry, atomic use budget, host ceiling, and destination
before running `item view`. A failed resolution still consumes the claimed use.

Unlike stored-secret leases, a live-source lease intentionally reads the current
field value each time. Proton-side credential rotation therefore takes effect on
the next invocation. Changing the source/ref makes the lease stale. No credential
is cached, including across multiple uses of the same lease.

The field is injected only into the configured destination header. Exact secret
echoes are redacted from responses. Temporary references are dropped after the
call; Python cannot guarantee memory zeroization. Legacy raw reveal and
`broker.http` APIs cannot select this live source.

## Rotate and revoke

Renew as the human:

```bash
pass-cli agent renew passd-groot --expiration 1m --output json
```

Deliver the renewed PAT using `set-pat`, then run `login` again. Rotate before
expiry, for example after two thirds of the token's validity period, leaving time
to recover from a failed renewal. Record the expiry reported by Proton on the
human administrative path. Setting a PAT alone does not refresh the session.

For the local kill switch:

```bash
passd proton-agent disable
```

Disable persists first, attempts `logout --force`, and wipes the isolated session
directory even when logout fails. All further resolutions are denied until
`passd proton-agent enable`; then run `passd proton-agent login`. A call that has
already resolved its credential may already be in flight. `logout` alone clears
the session without setting the persistent kill switch.

For server-side revocation, use the human `pass-cli agent access revoke` command
with the appropriate item/vault selector, or delete the identity:

```bash
pass-cli agent delete passd-groot
```

## Audit and failures

As the human, inspect server records:

```bash
pass-cli agent monitor passd-groot --output json
```

Cross-check each structured reason against passd audit capability and lease IDs:

```text
passd capability=<id> lease=<id> agent=<name> purpose=<description>
```

Reasons have control characters removed and are length limited. Passd audits
source, capability, lease, outcome, and denial class, never field values or PATs.
CLI stdout/stderr never enters public errors or audits. Stderr is redacted and
truncated for classification only.

| CLI failure | Denial class / RPC code |
| --- | --- |
| Expired PAT/session, invalid token/session, unauthorized, 401 | `ProtonAgentAuthExpired` / `proton_agent_auth_expired` |
| Forbidden, permission, no access, not granted, 403 | `ProtonAgentAccessDenied` / `proton_agent_access_denied` |
| Missing item, not found, 404 | `ProtonAgentItemNotFound` / `proton_agent_item_not_found` |
| Missing mandatory reason | `ProtonAgentReasonRequired` / `proton_agent_reason_required` |
| Missing binary, timeout, network, unrecognized nonzero exit, unsafe session directory | `ProtonAgentUnavailable` / `proton_agent_unavailable` |
| Persistent local kill switch | `ProtonAgentDisabled` / `proton_agent_disabled` |

Auth expiry emits `proton_agent.auth_expired` with severity `alert` in passd audit,
appends a credential-free alert to `<data dir>/alerts.log`, and attempts the
configured hook. Alert delivery is best effort. There is no automatic login
retry. The operator runs `passd proton-agent login` after fixing the token/session.
There is never a fallback to the human session, an imported ZIP credential, or a
different source.

## Legacy ZIP imports

`passd sync import-proton` is deprecated and remains available as an optional
legacy migration/snapshot bridge. Existing stored-secret capabilities and import
tests remain supported. Imported items never serve as live-source fallbacks.
