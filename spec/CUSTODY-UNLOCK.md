# Custody unlock from Hermes mobile

Kevin opens the official Hermes Android app on his phone and accepts an
owner-only, masked custody prompt. In the prompt he uses Proton Pass autofill
with fingerprint verification to generate a fresh custody passphrase and
saves the entry in his MAIN Proton vault. On subsequent unlocks he selects
that entry and authenticates with his fingerprint to autofill it. The
fingerprint authorizes Proton Pass autofill. The generated passphrase is
the input to passd's custody key derivation. It differs from the Proton
account password, the Proton agent PAT, and the credentials in `agents`.

The prompt must be bound to a specific owner action, broker and one-shot
challenge. Submission must be routed to the custody process without entering
chat, agent context, tool arguments, logs, crash reports, clipboard or
agent-readable storage. Display a success/failure receipt without the value.
Masking by itself does not establish the transport or storage boundary.
Android generation, save and autofill in this prompt remain unverified.

## Store and key lifetime

Current passd derives a 32-byte root key with scrypt over the UTF-8 passphrase
and a 16-byte random per-store salt. Parameters are N = 32768, r = 8, p = 1.
The config holds that salt and an AES-256-GCM-encrypted root check.
Per-vault and per-item keys are randomly generated and wrapped in the
custody hierarchy. The PAT is encrypted under the root key as a reserved
internal record. See `passd/crypto.py:derive_root_key`,
`passd/config.py:Config.initialize`, `passd/config.py:Config.derive_and_verify`,
and `passd/service.py:_put_internal_secret`. Preserve existing KDF parameters
and store compatibility. There is a KDF today, so no fallback parameters
are required.

Today `passd init` accepts the master password and verifies confirmation on
interactive input. `passd serve` derives and verifies the key at startup
and retains it in the process for its lifetime. The CLI accepts a masked
terminal prompt, a password file or an environment value. There is no
runtime lock RPC, timed unlock, or guaranteed Python memory zeroization.
Stopping the daemon closes the database and removes the local socket.
The isolated Proton PAT session is separate and may persist unless explicitly
logged out and cleared.

For the owner unlock implementation, propose a 15-minute absolute window,
subject to owner review. Use monotonic elapsed time and require explicit
re-authorization to extend access. Provide an immediate owner re-lock and
deny new requests for injection at expiry, re-lock or restart until fresh
owner unlock. Drain or abort in-flight work under a defined bound and stop
the custody worker to discard live key material. Tear down the isolated
provider session when locking. Never assume memory erasure can undo an
already transmitted credential. Unlock enables the broker to process
approved work. It conveys no lease to an agent and does not replace approval.

## Intake paths

Chosen path is **pending W3 receipt**.

| Option | Flow | Trade-off and gate |
| --- | --- | --- |
| A | Hermes masked secret prompt → profile `.env` → immediate privileged move to custody and deletion | Can reuse existing prompt delivery. Even a short-lived `.env` write is exposed to same-UID observers, sync, backups and crash residue. Consider only if the staging profile is owner-only and agent-inaccessible throughout. Test failure, cleanup and concurrent file access. |
| B | Hermes command-helper/secret-source seam → owner-only helper stdin or private IPC → custody | Can reuse Hermes integration points. Confirm that this seam can accept owner input without returning the plaintext to Hermes model/tool or writing profile state. A helper that returns secrets over stdout is unsuitable for this flow. |
| C | passd-owned one-shot loopback/Tailscale intake page → authenticated custody process | Keeps the value under the broker's control. Broker loopback is reachable only locally unless securely forwarded. For the phone, require an owner-only authenticated HTTPS origin, single-use challenge, expiry and replay/CSRF protection. Android autofill and save behavior, origin binding and tailnet access require verification. |

W3 should demonstrate fingerprint, generation, save and later autofill with
a dummy value. Its receipt needs the actual Android prompt and data path,
storage and logging evidence, behavior across cancel, expiry, replay and
restart, and a confirmation that the agent user cannot reach the unlock path.
