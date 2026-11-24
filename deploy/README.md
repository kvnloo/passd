# Deploy passd on a Linux broker host

Run these commands from a trusted, root-controlled passd checkout on a systemd
host with Python 3.11+, its venv module, and an assigned Tailscale address.
Replace `broker-admin`, `broker`, and `100.64.10.20:8765` with the administrator
account, SSH host alias, and the broker's tailnet address and port.

```sh
sudo ./deploy/install.sh broker-admin 100.64.10.20:8765
```

Log in again to pick up membership in `passd-admin`. Initialize the store once
from the orchestrator. Capture the value via the Hermes in-app secret prompt
into an unexported shell variable and pipe it directly. Authenticate sudo
separately or authorize the exact command ahead of time. `sudo -n` keeps sudo
from consuming the custody line.

```sh
printf '%s\n' "$PASSD_MASTER" | ssh -T broker 'sudo -n -u passd /opt/passd/bin/passd --data-dir /var/lib/passd init --master-password-stdin'
```

Unlock after installation and after every daemon restart. Capture a fresh
Hermes prompt value for each unlock.

```sh
printf '%s\n' "$PASSD_MASTER" | ssh -T broker 'sudo -n /opt/passd/bin/passd-unlock'
```

The unlock helper starts the broker if needed and sends the line to a root-only
FIFO under `/run/passd-unlock`. systemd opens the FIFO as the service's stdin
before switching to the passd identity. The daemon verifies the master password,
disconnects stdin, and keeps the derived key in process memory. A wrong password
fails startup. Retry the same unlock command with a fresh input line. The helper
checks the broker socket before starting the gateway. Check both units with
`systemctl status passd.service passd-gateway.service`. For intentional re-lock,
stop the units as shown below. Unlock validates custody separately from access
approval.

Clear any transient Hermes sudo-style stub and its profile entry after use,
following the same secret-prompt cleanup workflow. Disable shell tracing while
handling the values. Keep sudo authentication and passd inputs on separate
channels.

## Local administration

Use the local Unix socket from the administrator account on the broker. For
example, with `PASSD_MASTER` and `ITEM_SECRET` supplied by the Hermes prompt:

```sh
export PASSD_SOCKET=/run/passd/passd.sock
printf '%s\n' "$PASSD_MASTER" | /opt/passd/bin/passd vault create agents --master-password-stdin
printf '%s\n' "$PASSD_MASTER" "$ITEM_SECRET" |
  /opt/passd/bin/passd item put-login --vault agents --title example --master-password-stdin --password-stdin
unset PASSD_MASTER ITEM_SECRET
```

When both inputs use stdin, line 1 contains the master password and line 2
contains the login password. Each repeated `--field-stdin NAME` consumes another
line in argument order. Each line preserves surrounding spaces. For existing
Proton PAT tooling, `proton-agent set-pat` reads the PAT after the master line.
This deployment uses the local encrypted store. For local file-based login
input, `--password-file` requires a regular file with mode `0600`. Agent CLI
authentication uses `PASSD_AGENT_TOKEN`.

## Host and network boundaries

The broker account owns `/var/lib/passd` (0700). Root owns the installed venv.
The admin socket is 0660 under a 0750 directory. Keep agent operating-system
accounts out of `passd-admin` and off the broker host. The gateway runs as a
separate service user with socket access and forwards only the agent RPCs. It
binds the configured tailnet address and accepts peers in the two Tailscale
address ranges. Configure tailnet ACLs to limit the gateway port to intended
agent devices. Use Tailscale for transport encryption.

A host root account can access process memory, and the broker UID can access its
loaded custody material. Treat them as trusted. Hold deployment and unlock
privileges on a separate administrator account. Only place agent credentials in
the broker store and expose them through explicitly approved typed capabilities.

## Readiness

Run the self-contained check on the broker host after installation.

```sh
/opt/passd/readiness/e2e-readiness.sh
```

This starts a disposable broker and loopback echo server, checks stdin unlock,
owner approval, injection and redaction, out-of-scope requests, budget exhaustion,
and revocation. It removes the temporary store on exit. To target an existing
disposable broker on the same host, start it with
`serve --master-password-stdin --allow-private-broker-targets` and pass its socket
to the driver. Use a dummy master password and a disposable store. The driver
revokes its agent but the dummy item and capability remain in that store.

```sh
printf '%s\n' "$DUMMY_MASTER" |
  /opt/passd/readiness/e2e-readiness.sh --socket /tmp/disposable-passd/passd.sock
```

Add `--gateway 100.64.10.20:8765` to route agent calls through a gateway
configured for the disposable broker. The production broker runs with the
default private-target restrictions.

## Kill switch and removal

Stop both units immediately. Disable both units as well if the stop must survive
reboot. To revoke an agent, regain custody with the gateway stopped, then send
the master password over stdin to the local admin socket and revoke the agent
ID. For example:

```sh
sudo systemctl stop passd-gateway.service passd.service
printf '%s\n' "$PASSD_MASTER" | sudo -n /opt/passd/bin/passd-unlock --broker-only
printf '%s\n' "$PASSD_MASTER" |
  PASSD_SOCKET=/run/passd/passd.sock /opt/passd/bin/passd agent revoke "$AGENT_ID" --master-password-stdin
sudo ./deploy/uninstall.sh
```

Uninstall stops and removes both units, the runtime paths and the venv. It
preserves encrypted data and system identities for reinstallation.
