# Google credential minter: every new Google key is a sudo prompt

Goal: agents can create the Google credentials they need (API keys, enabled
APIs, service-account keys) without ever holding a Google admin credential.
Each call is a passd capability request that a human approves, like `sudo`.

```
agent ──capability.request──▶ passd (pending: "create API key 'yt' restricted to youtube.googleapis.com in project X")
human ──access approve──────▶ passd (lease: exact host/method/path/body hash, TTL, use budget)
agent ──capability.invoke───▶ passd ── JWT(RS256, SA key) ─▶ oauth2.googleapis.com/token
                                     ── Bearer <token> ────▶ apikeys.googleapis.com
                              passd ◀── {"keyString": "AIza..."}   (moved into custody)
agent ◀── {"keyString": "passd-redacted:pass://Google/itm_.../keyString"}
```

The service-account private key, the OAuth access token, and (by default) any
minted secret stay inside the passd custody process.

## 1. One-time GCP setup (human, Cloud Console or gcloud)

1. Create a dedicated project for minting, e.g. `kvn-credential-minter`. Do
   not reuse a project that runs workloads.
2. Create a service account `credential-minter@<project>.iam.gserviceaccount.com`.
3. Grant it **project-scoped** roles only, on the project(s) it may mint in:

   | Role | ID | Why |
   | --- | --- | --- |
   | Service Usage Admin | `roles/serviceusage.serviceUsageAdmin` | enable/disable APIs |
   | API Keys Admin | `roles/serviceusage.apiKeysAdmin` | create/restrict/read API keys |
   | Service Account Admin | `roles/iam.serviceAccountAdmin` | create service accounts |
   | Service Account Key Admin | `roles/iam.serviceAccountKeyAdmin` | create service-account keys |

   Do not grant Owner/Editor, org-level, or `roles/resourcemanager.projectIamAdmin`
   (that would let an approved call grant itself more power).
4. Enable on the minter project: `apikeys.googleapis.com`,
   `serviceusage.googleapis.com`, `iam.googleapis.com`,
   `cloudresourcemanager.googleapis.com`.
5. Create one JSON key for `credential-minter`, import it, then delete the file:

```bash
passd vault create Google
passd item import-google-sa --vault Google --title credential-minter --key-file ~/Downloads/minter.json
shred -u ~/Downloads/minter.json   # or rm -P on macOS
```

Import validates `type=service_account`, `client_email`, an RSA (>=2048)
`private_key`, and `token_uri == https://oauth2.googleapis.com/token`; it
returns only metadata (email, key id) and the backing URI
`pass://Google/credential-minter/service_account_json`.

## 2. The three recommended capabilities (admin)

Replace `PID` with the project the agent may mint in.

```bash
SA='pass://Google/credential-minter/service_account_json'
CP='https://www.googleapis.com/auth/cloud-platform'

# API keys: create (POST), poll the long-running operation, read the key string.
passd capability put-google-sa gcp.apikeys.create \
  --description 'Create restricted API keys in PID' \
  --backing-uri "$SA" --scope "$CP" \
  --host apikeys.googleapis.com \
  --method POST --method GET \
  --path-prefix /v2/projects/PID/locations/global/keys \
  --path-prefix /v2/operations \
  --response-secret-field keyString

# Enable APIs in PID.
passd capability put-google-sa gcp.serviceusage.enable \
  --description 'Enable Google APIs in PID' \
  --backing-uri "$SA" --scope "$CP" \
  --host serviceusage.googleapis.com \
  --method POST \
  --path-prefix /v1/projects/PID/services

# Service-account keys in PID.
passd capability put-google-sa gcp.iam.sakeys.create \
  --description 'Create service-account keys in PID' \
  --backing-uri "$SA" --scope "$CP" \
  --host iam.googleapis.com \
  --method POST \
  --path-prefix /v1/projects/PID/serviceAccounts \
  --response-secret-field privateKeyData
```

Defaults: `--response-secret-field` defaults to `keyString` + `privateKeyData`;
minted values are stored as new items in the backing vault (override with
`--response-secret-vault`) and replaced in the agent's response by
`passd-redacted:pass://VAULT/itm_.../FIELD`. `--reveal-response-secrets` stores
**and** returns them (only use for capabilities whose outputs the agent must
hold). Hosts must be `*.googleapis.com`; `oauth2.googleapis.com` is reserved for
the token exchange and never receives agent traffic.

## 3. Agent flow

```bash
export PASSD_AGENT_TOKEN='pda_...'
export PASSD_AGENT_REASON='YouTube uploader needs a Data API key'

cat > key.json <<'EOF'
{"displayName":"youtube-uploader","restrictions":{"apiTargets":[{"service":"youtube.googleapis.com"}]}}
EOF

passd capability request gcp.apikeys.create \
  --method POST --path /v2/projects/PID/locations/global/keys \
  --body-file key.json --expiration 5m --uses 1
```

Google leases are **body-bound**: the lease stores the SHA-256 of the exact
body, so invoke must send byte-identical content.

## 4. Human gate (the sudo prompt)

```bash
passd access pending
```

shows, per request:

```json
{
  "id": "req_...",
  "agent_name": "hermes",
  "capability_id": "gcp.apikeys.create",
  "summary": "create API key 'youtube-uploader' restricted to youtube.googleapis.com in project PID",
  "method": "POST",
  "url": "https://apikeys.googleapis.com/v2/projects/PID/locations/global/keys",
  "body_preview": "{\"displayName\":\"youtube-uploader\",...}",
  "body_sha256": "…",
  "reason": "YouTube uploader needs a Data API key",
  "requested_ttl": 300, "requested_uses": 1,
  "authority_digest": "ad1_…"
}
```

A key without `apiTargets` is summarized as `UNRESTRICTED` and a
service-account key request as `create a NEW PRIVATE KEY for service account …`
so the dangerous cases read as dangerous. The summary is advisory; the binding
authority is the exact host/method/path/body hash.

```bash
passd access approve req_... --uses 1 --expiration 2m
# or
passd access deny req_... --note 'use the existing key'
```

## 5. Invoke

```bash
passd capability invoke gcp.apikeys.create \
  --method POST --path /v2/projects/PID/locations/global/keys --body-file key.json
```

`keys.create` returns a long-running operation. To fetch the key string the
agent requests (and you approve) a second, separate call:

```bash
passd capability request gcp.apikeys.create --method GET \
  --path /v2/projects/PID/locations/global/keys/KEY_ID/keyString
```

The response contains `"keyString": "passd-redacted:pass://Google/itm_…/keyString"`
plus `custody_refs`. The agent can use the minted key through an `http_secret`
capability you define over that reference, or request `secret.reveal` for it
(another approval). Every call, including minted references, is in
`passd agent monitor`.

## Notes / limits

- Query strings are not allowed in capability paths (passd-wide rule), so
  `keys.create?keyId=…` is unavailable; Google assigns the key id.
- The access token is cached in memory only, per lease, until the earlier of
  token expiry (minus 60s) and lease expiry; it is dropped on revoke or when the
  use budget is exhausted. Restarting passd forgets it.
- Rotating the minter key (re-importing into the same item) stales all leases.
