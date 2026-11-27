"""Google service-account custody helpers.

Everything in this module runs inside the passd custody process. The service
account private key and the OAuth access tokens minted from it never leave
this process: they are not logged, audited, or returned over RPC.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.parse
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import PermissionDenied, ValidationError

GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_TOKEN_HOST = "oauth2.googleapis.com"
GOOGLE_SCOPE_PREFIX = "https://www.googleapis.com/auth/"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
MAX_ASSERTION_LIFETIME = 3600
# Refresh a cached token this many seconds before Google says it expires.
TOKEN_EXPIRY_SKEW = 60
MAX_TOKEN_RESPONSE = 64 * 1024
DEFAULT_RESPONSE_SECRET_FIELDS = ("keyString", "privateKeyData")
REDACTED_PREFIX = "passd-redacted:"

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------- key validation ----------

def parse_service_account_key(value: Any) -> dict:
    """Validate a Google service-account JSON key and return the parsed dict.

    Accepts the raw JSON text (as downloaded from GCP) or an already-parsed
    dict. Error messages never echo key material.
    """
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except json.JSONDecodeError:
            raise ValidationError("service-account key must be JSON") from None
    elif isinstance(value, dict):
        data = value
    else:
        raise ValidationError("service-account key must be a JSON object")
    if not isinstance(data, dict):
        raise ValidationError("service-account key must be a JSON object")
    if data.get("type") != "service_account":
        raise ValidationError("service-account key must have type=service_account")
    email = data.get("client_email")
    if not isinstance(email, str) or not _EMAIL_RE.fullmatch(email):
        raise ValidationError("service-account key must carry a valid client_email")
    if data.get("token_uri") != GOOGLE_TOKEN_URI:
        raise ValidationError(f"service-account key token_uri must be exactly {GOOGLE_TOKEN_URI}")
    pem = data.get("private_key")
    if not isinstance(pem, str) or "PRIVATE KEY" not in pem:
        raise ValidationError("service-account key must carry a PEM private_key")
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception:
        raise ValidationError("service-account private_key is not a loadable unencrypted PEM key") from None
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValidationError("service-account private_key must be an RSA key of at least 2048 bits")
    kid = data.get("private_key_id")
    if kid is not None and (not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", kid)):
        raise ValidationError("service-account private_key_id is malformed")
    return data


def public_key_summary(data: dict) -> dict:
    """Non-secret metadata safe to show an admin (never the private key)."""
    return {
        "client_email": data.get("client_email"),
        "project_id": data.get("project_id"),
        "private_key_id": data.get("private_key_id"),
        "token_uri": data.get("token_uri"),
    }


# ---------- definition validation ----------

def normalize_scopes(raw: Any) -> list[str]:
    if isinstance(raw, str):
        raw = raw.split()
    scopes = sorted({str(s).strip() for s in (raw or []) if str(s).strip()})
    if not scopes:
        raise ValidationError("google_service_account capabilities require at least one OAuth scope")
    for scope in scopes:
        if not scope.startswith(GOOGLE_SCOPE_PREFIX) or any(c.isspace() for c in scope) or len(scope) > 256:
            raise ValidationError(f"OAuth scope must start with {GOOGLE_SCOPE_PREFIX}")
    return scopes


def normalize_google_host(host: str) -> str:
    h = str(host).strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*", h):
        raise ValidationError("google_service_account hosts must be bare hostnames")
    if not h.endswith(".googleapis.com"):
        # The bearer token is a Google credential: never send it elsewhere.
        raise ValidationError("google_service_account hosts must be *.googleapis.com API hosts")
    if h == GOOGLE_TOKEN_HOST:
        raise ValidationError("the OAuth token endpoint is not a forwardable API host")
    return h


def normalize_response_secret_fields(raw: Any) -> list[str]:
    if raw is None:
        return list(DEFAULT_RESPONSE_SECRET_FIELDS)
    if isinstance(raw, str):
        raw = [raw]
    out = sorted({str(f).strip() for f in raw if str(f).strip()})
    for f in out:
        if not _FIELD_RE.fullmatch(f):
            raise ValidationError("response_secret_fields entries must be JSON field names")
    return out


# ---------- JWT + token exchange ----------

def build_assertion(key_data: dict, scopes: list[str], *, issued_at: int | None = None, lifetime: int = MAX_ASSERTION_LIFETIME) -> str:
    """Build an RS256-signed JWT bearer assertion (RFC 7523) for Google OAuth."""
    if lifetime <= 0 or lifetime > MAX_ASSERTION_LIFETIME:
        raise ValidationError("JWT assertion lifetime must be >0 and <=3600 seconds")
    iat = int(time.time()) if issued_at is None else int(issued_at)
    header = {"alg": "RS256", "typ": "JWT"}
    if key_data.get("private_key_id"):
        header["kid"] = key_data["private_key_id"]
    claims = {
        "iss": key_data["client_email"],
        "sub": key_data["client_email"],
        "aud": key_data["token_uri"],
        "scope": " ".join(scopes),
        "iat": iat,
        "exp": iat + lifetime,
    }
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    key = serialization.load_pem_private_key(key_data["private_key"].encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValidationError("service-account private_key must be an RSA key")
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + b64url(signature)


def token_request_body(assertion: str) -> bytes:
    return urllib.parse.urlencode({"grant_type": JWT_BEARER_GRANT, "assertion": assertion}).encode("ascii")


def parse_token_response(status: int, raw: bytes) -> tuple[str, int]:
    """Return (access_token, expires_in). Errors never include response text,
    since an error body could echo request material."""
    if status != 200:
        raise PermissionDenied(f"Google token exchange failed with HTTP {status}")
    if len(raw) > MAX_TOKEN_RESPONSE:
        raise ValidationError("Google token response too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ValidationError("Google token response is not JSON") from None
    token = data.get("access_token") if isinstance(data, dict) else None
    if not isinstance(token, str) or not token or any(c in token for c in "\r\n"):
        raise ValidationError("Google token response did not include an access_token")
    if str(data.get("token_type", "Bearer")).lower() != "bearer":
        raise ValidationError("Google token response is not a bearer token")
    try:
        expires_in = int(data.get("expires_in", 3600))
    except (TypeError, ValueError):
        expires_in = 3600
    return token, max(0, min(expires_in, MAX_ASSERTION_LIFETIME))


class TokenCache:
    """In-memory, per-lease access-token cache. Never persisted."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._entries: dict[tuple, tuple[str, float]] = {}

    def get(self, key: tuple) -> str | None:
        self.purge()
        hit = self._entries.get(key)
        return hit[0] if hit else None

    def put(self, key: tuple, token: str, expires_in: int) -> None:
        expires_at = self._clock() + expires_in - TOKEN_EXPIRY_SKEW
        if expires_at > self._clock():
            self._entries[key] = (token, expires_at)

    def drop_lease(self, lease_id: str) -> None:
        for k in [k for k in self._entries if k and k[0] == lease_id]:
            del self._entries[k]

    def purge(self) -> None:
        t = self._clock()
        for k in [k for k, (_, exp) in self._entries.items() if exp <= t]:
            del self._entries[k]

    def __len__(self) -> int:
        return len(self._entries)


# ---------- human-readable approval digest ----------

def _project_of(path: str) -> str | None:
    m = re.search(r"/projects/([^/]+)", path)
    return urllib.parse.unquote(m.group(1)) if m else None


def summarize_request(host: str, method: str, path: str, body: str | None) -> str:
    """One-line, sudo-prompt style description of a Google admin call.

    Heuristic and advisory only: the authority is the exact host/method/path
    and body hash that the lease binds, which are shown alongside it.
    """
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        parsed = {}
    project = _project_of(path)
    in_proj = f" in project {project}" if project else ""
    decoded = urllib.parse.unquote(path)

    if host == "apikeys.googleapis.com":
        if method == "POST" and re.search(r"/keys/?$", decoded):
            name = parsed.get("displayName") or "(no display name)"
            restrictions = parsed.get("restrictions") or {}
            targets = [t.get("service") for t in restrictions.get("apiTargets") or [] if isinstance(t, dict)]
            targets = [t for t in targets if t]
            app = [k for k in ("browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions") if k in restrictions]
            if targets:
                scope = "restricted to " + ", ".join(targets)
            else:
                scope = "UNRESTRICTED (no apiTargets: usable against every enabled API)"
            if app:
                scope += " + " + ", ".join(app)
            return f"create API key {name!r} {scope}{in_proj}"
        if method == "GET" and decoded.endswith("/keyString"):
            key = decoded.rsplit("/", 2)[-2]
            return f"read secret key string of API key {key}{in_proj} (stored into passd custody)"
        if method == "DELETE" and "/keys/" in decoded:
            return f"DELETE API key {decoded.rsplit('/', 1)[-1]}{in_proj}"
        if method == "GET" and decoded.startswith("/v2/operations/"):
            return f"poll API-key operation {decoded.rsplit('/', 1)[-1]} (minted secrets are stored into passd custody)"
    if host == "serviceusage.googleapis.com":
        m = re.search(r"/services/([^/:]+):(enable|disable)$", decoded)
        if method == "POST" and m:
            return f"{m.group(2)} API {m.group(1)}{in_proj}"
        if method == "POST" and decoded.endswith("/services:batchEnable"):
            ids = parsed.get("serviceIds") or []
            return f"enable APIs {', '.join(map(str, ids)) or '(none listed)'}{in_proj}"
    if host == "iam.googleapis.com":
        m = re.search(r"/serviceAccounts/([^/]+)/keys$", decoded)
        if method == "POST" and m:
            return f"create a NEW PRIVATE KEY for service account {m.group(1)}{in_proj} (stored into passd custody)"
        if method == "POST" and re.search(r"/serviceAccounts$", decoded):
            acct = parsed.get("accountId") or "(unnamed)"
            return f"create service account {acct!r}{in_proj}"
        m = re.search(r"/serviceAccounts/([^/]+)/keys/([^/]+)$", decoded)
        if method == "DELETE" and m:
            return f"DELETE key {m.group(2)} of service account {m.group(1)}{in_proj}"
    if host == "cloudresourcemanager.googleapis.com" and decoded.endswith(":setIamPolicy"):
        return f"REPLACE the IAM policy of {decoded.rsplit(':', 1)[0].lstrip('/')}"
    if body:
        fields = sorted(parsed.keys())[:12] if parsed else []
        detail = f"body {len(body.encode('utf-8'))} bytes" + (f", fields {fields}" if fields else "")
    else:
        detail = "no body"
    return f"{method} https://{host}{path} ({detail})"


def body_sha256(body: str | None) -> str | None:
    if body is None:
        return None
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def body_preview(body: str | None, limit: int = 600) -> str | None:
    if body is None:
        return None
    return body if len(body) <= limit else body[:limit] + f"... (+{len(body) - limit} chars)"


# ---------- response hygiene ----------

def extract_response_secrets(value: Any, fields: set[str], store: Callable[[str, str, dict], str], *, reveal: bool, _ctx: dict | None = None) -> Any:
    """Walk a decoded JSON response; hand every string under a secret field to
    ``store(field, value, context)`` and replace it with the returned
    reference unless ``reveal`` is set. Returns the rewritten structure."""
    if isinstance(value, dict):
        ctx = dict(_ctx or {})
        for k in ("name", "uid", "displayName", "keyAlgorithm", "validBeforeTime"):
            if isinstance(value.get(k), str):
                ctx[k] = value[k]
        out = {}
        for k, v in value.items():
            if k in fields and isinstance(v, str) and v:
                ref = store(k, v, ctx)
                out[k] = v if reveal else REDACTED_PREFIX + ref
            else:
                out[k] = extract_response_secrets(v, fields, store, reveal=reveal, _ctx=ctx)
        return out
    if isinstance(value, list):
        return [extract_response_secrets(v, fields, store, reveal=reveal, _ctx=_ctx) for v in value]
    return value
