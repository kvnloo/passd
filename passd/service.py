from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from .authority import CAPABILITY_ID_RE, authority_digest, capability_version, credential_version, item_version
from .config import Config
from .crypto import open_json, open_sealed, random_key, seal, seal_json
from .db import connect
from .errors import AuthError, Conflict, NotFound, PermissionDenied, ValidationError
from .refs import parse_pass_ref

MAX_REASON_LENGTH = 300
MAX_ACCESS_TTL = 24 * 3600
MAX_ACCESS_USES = 100
MAX_PENDING_PER_AGENT = 32
DEFAULT_ACCESS_TTL = 5 * 60


def now() -> int:
    return int(time.time())


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def public_agent(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "scopes": json.loads(row["scopes_json"]),
        # Kept in the v1 schema for backwards-readable databases. v2 does not
        # use static vault/item grants; HITL access_requests are authoritative.
        "vault_ids": json.loads(row["vault_ids_json"]),
        "item_ids": json.loads(row["item_ids_json"]),
        "allowed_hosts": json.loads(row["allowed_hosts_json"]),
        "expires_at": row["expires_at"],
        "revoked": bool(row["revoked"]),
        "created_at": row["created_at"],
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PassdService:
    def __init__(self, config: Config, root_key: bytes, *, allow_private_broker_targets: bool = False):
        self.config = config
        self.root_key = root_key
        self.db = connect(config.db_path)
        self.allow_private_broker_targets = allow_private_broker_targets
        self._db_lock = threading.RLock()
        # Reuse one transport. Building urllib opener/handlers per invocation
        # dominated local policy latency by orders of magnitude.
        self._http_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)

    def close(self):
        self.db.close()

    # ---------- auth ----------
    def verify_admin_password(self, password: str | None) -> None:
        if not password:
            raise AuthError("admin operation requires the master password")
        candidate = self.config.derive_and_verify(password)
        if not hmac.compare_digest(candidate, self.root_key):
            raise AuthError("invalid master password")

    @staticmethod
    def _token_hash(secret: str) -> bytes:
        # Machine-token secrets are generated with >250 bits of entropy, so a
        # fast hash is appropriate: DB compromise does not create a practical
        # offline guessing attack, while hot-path authentication stays cheap.
        return hashlib.sha256(secret.encode("utf-8")).digest()

    def authenticate_agent(self, token: str | None):
        if not token or not token.startswith("pda_") or "." not in token:
            raise AuthError("a valid PASSD_AGENT_TOKEN is required")
        token_id, secret = token.split(".", 1)
        with self._db_lock:
            row = self.db.execute("SELECT * FROM agents WHERE id=?", (token_id,)).fetchone()
            if not row:
                raise AuthError("unknown agent token")
            if row["revoked"]:
                raise AuthError("agent token has been revoked")
            if row["expires_at"] <= now():
                raise AuthError("agent token has expired")
            if not hmac.compare_digest(row["token_hash"], self._token_hash(secret)):
                raise AuthError("invalid agent token")
            return row

    # ---------- crypto hierarchy ----------
    def _vault_key(self, row) -> bytes:
        return open_sealed(self.root_key, row["wrapped_key"], aad=f"passd/vault/{row['id']}/key".encode())

    def _vault_payload(self, row) -> dict:
        key = self._vault_key(row)
        return open_json(key, row["payload"], aad=f"passd/vault/{row['id']}/payload".encode())

    def _item_key(self, row, vault_key: bytes) -> bytes:
        return open_sealed(vault_key, row["wrapped_key"], aad=f"passd/item/{row['id']}/key".encode())

    def _item_payload(self, row) -> dict:
        vrow = self.db.execute("SELECT * FROM vaults WHERE id=?", (row["vault_id"],)).fetchone()
        if not vrow:
            raise NotFound("item's vault no longer exists")
        vkey = self._vault_key(vrow)
        ikey = self._item_key(row, vkey)
        return open_json(ikey, row["payload"], aad=f"passd/item/{row['id']}/payload".encode())

    def _item_version(self, row) -> str:
        # Version semantic plaintext, not the randomized AEAD envelope. This
        # survives harmless re-encryption while still invalidating real changes.
        return item_version(self.root_key, self._item_payload(row))

    def _credential_version(self, row, field: str) -> str:
        payload = self._item_payload(row)
        value = self._extract_field(payload, field)
        return credential_version(self.root_key, item_id=row["id"], field=field, value=value)

    def _capability_payload(self, row) -> dict:
        return open_json(self.root_key, row["payload"], aad=f"passd/capability/{row['id']}/payload".encode())

    def _access_payload(self, row) -> dict:
        return open_json(self.root_key, row["payload"], aad=f"passd/access/{row['id']}/payload".encode())

    def _seal_access_payload(self, request_id: str, payload: dict) -> str:
        return seal_json(self.root_key, payload, aad=f"passd/access/{request_id}/payload".encode())

    # ---------- vaults ----------
    def create_vault(self, name: str, description: str = "", *, source: dict | None = None) -> dict:
        name = name.strip()
        if not name:
            raise ValidationError("vault name must not be empty")
        source = source or {}
        source_kind = source.get("kind")
        source_id = source.get("id")
        if source_kind and source_id:
            existing = self.db.execute(
                "SELECT * FROM vaults WHERE source_kind=? AND source_id=?", (source_kind, source_id)
            ).fetchone()
            if existing:
                key = self._vault_key(existing)
                payload = {"name": name, "description": description, "source": source}
                self.db.execute(
                    "UPDATE vaults SET payload=?,updated_at=? WHERE id=?",
                    (seal_json(key, payload, aad=f"passd/vault/{existing['id']}/payload".encode()), now(), existing["id"]),
                )
                self.db.commit()
                return {"id": existing["id"], **payload}
        else:
            for row in self.db.execute("SELECT * FROM vaults"):
                if self._vault_payload(row).get("name") == name:
                    return {"id": row["id"], **self._vault_payload(row)}
        vault_id = "vlt_" + uuid.uuid4().hex
        key = random_key()
        payload = {"name": name, "description": description, "source": source}
        ts = now()
        self.db.execute(
            "INSERT INTO vaults(id,wrapped_key,payload,source_kind,source_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (
                vault_id,
                seal(self.root_key, key, aad=f"passd/vault/{vault_id}/key".encode()),
                seal_json(key, payload, aad=f"passd/vault/{vault_id}/payload".encode()),
                source_kind,
                source_id,
                ts,
                ts,
            ),
        )
        self.db.commit()
        return {"id": vault_id, **payload}

    def list_vaults(self) -> list[dict]:
        return [{"id": r["id"], **self._vault_payload(r)} for r in self.db.execute("SELECT * FROM vaults ORDER BY created_at,id")]

    def find_vault(self, ref: str):
        row = self.db.execute("SELECT * FROM vaults WHERE id=?", (ref,)).fetchone()
        if row:
            return row
        matches = [r for r in self.db.execute("SELECT * FROM vaults") if self._vault_payload(r).get("name") == ref]
        if not matches:
            raise NotFound(f"vault not found: {ref}")
        if len(matches) > 1:
            raise Conflict(f"vault name is ambiguous: {ref}")
        return matches[0]

    # ---------- items ----------
    def put_item(
        self,
        vault_ref: str,
        title: str,
        fields: dict[str, Any],
        *,
        item_type: str = "login",
        urls: list[str] | None = None,
        note: str = "",
        source: dict | None = None,
        proton_raw: dict | None = None,
    ) -> dict:
        vrow = self.find_vault(vault_ref)
        vkey = self._vault_key(vrow)
        title = title.strip()
        if not title:
            raise ValidationError("item title must not be empty")
        source = source or {}
        source_kind = source.get("kind")
        source_id = source.get("id")
        existing = None
        if source_kind and source_id:
            existing = self.db.execute("SELECT * FROM items WHERE source_kind=? AND source_id=?", (source_kind, source_id)).fetchone()
        payload = {
            "type": item_type,
            "title": title,
            "fields": fields,
            "urls": urls or [],
            "note": note,
            "source": source,
            "proton_raw": proton_raw,
        }
        ts = now()
        if existing:
            item_id = existing["id"]
            if existing["vault_id"] != vrow["id"]:
                ikey = random_key()
                wrapped = seal(vkey, ikey, aad=f"passd/item/{item_id}/key".encode())
            else:
                ikey = self._item_key(existing, vkey)
                wrapped = existing["wrapped_key"]
            sealed_payload = seal_json(ikey, payload, aad=f"passd/item/{item_id}/payload".encode())
            self.db.execute(
                "UPDATE items SET vault_id=?,wrapped_key=?,payload=?,source_kind=?,source_id=?,updated_at=? WHERE id=?",
                (vrow["id"], wrapped, sealed_payload, source_kind, source_id, ts, item_id),
            )
        else:
            item_id = "itm_" + uuid.uuid4().hex
            ikey = random_key()
            self.db.execute(
                "INSERT INTO items(id,vault_id,wrapped_key,payload,source_kind,source_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    item_id,
                    vrow["id"],
                    seal(vkey, ikey, aad=f"passd/item/{item_id}/key".encode()),
                    seal_json(ikey, payload, aad=f"passd/item/{item_id}/payload".encode()),
                    source_kind,
                    source_id,
                    ts,
                    ts,
                ),
            )
        self.db.commit()
        return {"id": item_id, "vault_id": vrow["id"], **payload}

    def list_items(self, vault_ref: str) -> list[dict]:
        vrow = self.find_vault(vault_ref)
        result = []
        for row in self.db.execute("SELECT * FROM items WHERE vault_id=? ORDER BY created_at,id", (vrow["id"],)):
            p = self._item_payload(row)
            result.append({"id": row["id"], "vault_id": row["vault_id"], "type": p.get("type"), "title": p.get("title"), "urls": p.get("urls", [])})
        return result

    def find_item(self, vault_ref: str, item_ref: str):
        vrow = self.find_vault(vault_ref)
        row = self.db.execute("SELECT * FROM items WHERE id=? AND vault_id=?", (item_ref, vrow["id"])).fetchone()
        if row:
            return row
        matches = [r for r in self.db.execute("SELECT * FROM items WHERE vault_id=?", (vrow["id"],)) if self._item_payload(r).get("title") == item_ref]
        if not matches:
            raise NotFound(f"item not found: {item_ref}")
        if len(matches) > 1:
            raise Conflict(f"item title is ambiguous: {item_ref}")
        return matches[0]

    def resolve_item_ref(self, uri: str):
        vault, item, field = parse_pass_ref(uri)
        row = self.find_item(vault, item)
        return row, field

    @staticmethod
    def _extract_field(payload: dict, field: str | None):
        if field is None:
            return payload
        fields = payload.get("fields") or {}
        if field not in fields:
            raise NotFound(f"field not found: {field}")
        return fields[field]

    # ---------- typed agent capabilities ----------
    @staticmethod
    def _validate_header_name(name: str) -> str:
        name = str(name).strip()
        if not name or any(c in name for c in "\r\n:"):
            raise ValidationError("invalid HTTP header name")
        return name

    @staticmethod
    def _validate_header_value(value: str) -> str:
        value = str(value)
        if any(c in value for c in "\r\n"):
            raise ValidationError("invalid HTTP header value")
        return value

    def _normalize_capability_definition(self, raw: dict) -> dict:
        capability_id = str(raw.get("id") or "").strip().lower()
        if not CAPABILITY_ID_RE.fullmatch(capability_id):
            raise ValidationError("capability id must match [a-z0-9][a-z0-9._-]{0,127}")
        kind = str(raw.get("kind") or "http_secret").strip()
        if kind != "http_secret":
            raise ValidationError("v0.3 supports only kind=http_secret")
        description = str(raw.get("description") or "").strip()
        if len(description) > 300:
            raise ValidationError("capability description must be <= 300 characters")

        backing_uri = str(raw.get("backing_uri") or "").strip()
        _, _, field = parse_pass_ref(backing_uri)
        if not field:
            raise ValidationError("capability backing_uri must name one exact field")

        scheme = str(raw.get("scheme") or "https").strip().lower()
        if scheme not in {"http", "https"}:
            raise ValidationError("capability scheme must be http or https")
        if scheme == "http" and not self.allow_private_broker_targets:
            raise PermissionDenied("plaintext HTTP capabilities require explicit private-target development mode")
        host = self._normalize_host(str(raw.get("host") or ""))
        default_port = 443 if scheme == "https" else 80
        port = int(raw.get("port") or default_port)
        if port < 1 or port > 65535:
            raise ValidationError("capability port must be between 1 and 65535")

        methods = sorted({str(m).strip().upper() for m in (raw.get("methods") or [])})
        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE"}
        if not methods or not set(methods) <= allowed_methods:
            raise ValidationError(f"capability methods must be drawn from {sorted(allowed_methods)}")

        path_prefix = str(raw.get("path_prefix") or "/").strip()
        if not path_prefix.startswith("/") or path_prefix.startswith("//") or any(c in path_prefix for c in "\r\n?#"):
            raise ValidationError("capability path_prefix must be an absolute path without query/fragment")
        decoded_prefix = urllib.parse.unquote(path_prefix)
        if any(part == ".." for part in decoded_prefix.split("/")):
            raise ValidationError("capability path_prefix must not contain parent traversal")
        if len(path_prefix) > 2048:
            raise ValidationError("capability path_prefix is too long")

        inject_header = self._validate_header_name(str(raw.get("inject_header") or "Authorization"))
        inject_prefix = self._validate_header_value(str(raw.get("inject_prefix") or ""))
        static_headers = {}
        for k, v in dict(raw.get("static_headers") or {}).items():
            key = self._validate_header_name(k)
            value = self._validate_header_value(v)
            static_headers[key] = value
        lower = {k.lower() for k in static_headers}
        if inject_header.lower() in lower:
            raise ValidationError("static headers must not override the injected secret header")
        if lower & {"host", ":authority", "proxy-authorization"}:
            raise ValidationError("static headers must not override routing/authentication headers")

        timeout_seconds = float(raw.get("timeout_seconds", 20.0))
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValidationError("capability timeout_seconds must be >0 and <=60")

        return {
            "id": capability_id,
            "description": description,
            "kind": kind,
            "backing_uri": backing_uri,
            "scheme": scheme,
            "host": host,
            "port": port,
            "methods": methods,
            "path_prefix": path_prefix,
            "inject_header": inject_header,
            "inject_prefix": inject_prefix,
            "static_headers": static_headers,
            "timeout_seconds": timeout_seconds,
        }

    def _public_capability(self, row) -> dict:
        definition = self._capability_payload(row)
        return {
            "id": row["id"],
            "version": row["version"],
            "kind": definition["kind"],
            "description": definition.get("description", ""),
            "target_host": definition["host"],
            "methods": list(definition["methods"]),
            "path_prefix": definition["path_prefix"],
        }

    def put_capability(self, raw: dict) -> dict:
        definition = self._normalize_capability_definition(raw)
        capability_id = definition["id"]
        version = capability_version(self.root_key, definition)
        ts = now()
        payload = seal_json(self.root_key, definition, aad=f"passd/capability/{capability_id}/payload".encode())
        with self._db_lock:
            existing = self.db.execute("SELECT * FROM capabilities WHERE id=?", (capability_id,)).fetchone()
            if existing:
                self.db.execute(
                    "UPDATE capabilities SET version=?,payload=?,updated_at=? WHERE id=?",
                    (version, payload, ts, capability_id),
                )
            else:
                self.db.execute(
                    "INSERT INTO capabilities(id,version,payload,created_at,updated_at) VALUES(?,?,?,?,?)",
                    (capability_id, version, payload, ts, ts),
                )
            self.db.commit()
            row = self.db.execute("SELECT * FROM capabilities WHERE id=?", (capability_id,)).fetchone()
        return self._public_capability(row)

    def get_capability_row(self, capability_id: str):
        row = self.db.execute("SELECT * FROM capabilities WHERE id=?", (str(capability_id).strip().lower(),)).fetchone()
        if not row:
            raise NotFound(f"capability not found: {capability_id}")
        return row

    def get_capability(self, capability_id: str, *, include_definition: bool = False) -> dict:
        row = self.get_capability_row(capability_id)
        result = self._public_capability(row)
        if include_definition:
            result["definition"] = self._capability_payload(row)
        return result

    def list_capabilities(self) -> list[dict]:
        return [self._public_capability(r) for r in self.db.execute("SELECT * FROM capabilities ORDER BY id")]

    @staticmethod
    def _path_in_capability(path: str, prefix: str) -> bool:
        if prefix == "/":
            return True
        base = prefix.rstrip("/")
        return path == base or path.startswith(base + "/")

    def _validate_capability_invocation(self, definition: dict, method: str, path: str) -> tuple[str, str]:
        method = str(method or "").strip().upper()
        if method not in set(definition["methods"]):
            raise PermissionDenied("requested HTTP method exceeds capability contract")
        path = str(path or "").strip()
        if not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n"):
            raise ValidationError("capability path must be one absolute path")
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise ValidationError("capability path must not contain scheme, authority, query, or fragment")
        decoded = urllib.parse.unquote(parsed.path)
        if any(part == ".." for part in decoded.split("/")):
            raise ValidationError("capability path must not contain parent traversal")
        decoded_prefix = urllib.parse.unquote(definition["path_prefix"])
        if not self._path_in_capability(decoded, decoded_prefix):
            raise PermissionDenied("requested path exceeds capability contract")
        return method, parsed.path

    # ---------- machine accounts / API keys ----------
    def create_agent(
        self,
        name: str,
        *,
        scopes: list[str],
        vault_refs: list[str],
        item_refs: list[str],
        allowed_hosts: list[str],
        ttl_seconds: int,
    ) -> dict:
        name = name.strip()
        if not name:
            raise ValidationError("agent name must not be empty")
        valid_scopes = {"access.request", "metadata.read", "secret.use", "secret.reveal", "capability.request", "capability.invoke"}
        scopes = sorted(set(scopes))
        if not scopes or not set(scopes) <= valid_scopes:
            raise ValidationError(f"scopes must be drawn from {sorted(valid_scopes)}")
        if ttl_seconds < 60 or ttl_seconds > 365 * 24 * 3600:
            raise ValidationError("agent TTL must be between 60 seconds and 1 year")
        if vault_refs or item_refs:
            raise ValidationError("v2 machine keys never carry static resource grants; use access request + HITL approval")
        normalized_hosts = sorted({self._normalize_host(h) for h in allowed_hosts})
        if self.db.execute("SELECT 1 FROM agents WHERE name=? AND revoked=0", (name,)).fetchone():
            raise Conflict(f"an active agent named {name!r} already exists")
        token_id = "pda_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")
        secret = secrets.token_urlsafe(32)
        token = token_id + "." + secret
        ts = now()
        self.db.execute(
            "INSERT INTO agents(id,name,token_hash,scopes_json,vault_ids_json,item_ids_json,allowed_hosts_json,expires_at,revoked,created_at) VALUES(?,?,?,?,?,?,?,?,0,?)",
            (token_id, name, self._token_hash(secret), json_dumps(scopes), "[]", "[]", json_dumps(normalized_hosts), ts + ttl_seconds, ts),
        )
        self.db.commit()
        return {"token": token, **public_agent(self.db.execute("SELECT * FROM agents WHERE id=?", (token_id,)).fetchone())}

    def list_agents(self) -> list[dict]:
        return [public_agent(r) for r in self.db.execute("SELECT * FROM agents ORDER BY created_at DESC")]

    def rotate_agent(self, ref: str) -> dict:
        """Rotate a machine API key without changing its identity or leases."""
        with self._db_lock:
            rows = list(self.db.execute("SELECT * FROM agents WHERE id=? OR name=?", (ref, ref)))
            if not rows:
                raise NotFound(f"agent not found: {ref}")
            if len(rows) > 1:
                raise Conflict(f"agent reference is ambiguous: {ref}")
            row = rows[0]
            if row["revoked"]:
                raise Conflict("cannot rotate a revoked agent")
            secret = secrets.token_urlsafe(32)
            self.db.execute("UPDATE agents SET token_hash=? WHERE id=?", (self._token_hash(secret), row["id"]))
            self.db.commit()
            fresh = self.db.execute("SELECT * FROM agents WHERE id=?", (row["id"],)).fetchone()
            return {"token": row["id"] + "." + secret, **public_agent(fresh)}

    def revoke_agent(self, ref: str) -> dict:
        rows = list(self.db.execute("SELECT * FROM agents WHERE id=? OR name=?", (ref, ref)))
        if not rows:
            raise NotFound(f"agent not found: {ref}")
        if len(rows) > 1:
            raise Conflict(f"agent reference is ambiguous: {ref}")
        self.db.execute("UPDATE agents SET revoked=1 WHERE id=?", (rows[0]["id"],))
        self.db.commit()
        return {"revoked": rows[0]["id"]}

    @staticmethod
    def _normalize_host(host: str) -> str:
        raw = str(host).strip().lower().rstrip(".")
        if not raw or "/" in raw or "@" in raw or raw.startswith("."):
            raise ValidationError("target host must be a bare hostname")
        parsed = urllib.parse.urlsplit("//" + raw)
        if not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("",):
            raise ValidationError("target host must be a bare hostname")
        if parsed.port is not None:
            raise ValidationError("target host must not include a port")
        return parsed.hostname.lower().rstrip(".")

    def _host_allowed(self, host: str, patterns: list[str]) -> bool:
        h = host.lower().rstrip(".")
        for p in patterns:
            p = p.lower().rstrip(".")
            if p.startswith("*."):
                suffix = p[1:]
                if h.endswith(suffix) and h != suffix[1:]:
                    return True
            elif h == p:
                return True
        return False

    # ---------- HITL access request / lease model ----------
    def _require_agent_scope(self, agent, scope: str) -> None:
        if scope not in set(json.loads(agent["scopes_json"])):
            raise PermissionDenied(f"agent API key does not permit capability: {scope}")

    def _require_any_agent_scope(self, agent, scopes: set[str]) -> None:
        held = set(json.loads(agent["scopes_json"]))
        if not held.intersection(scopes):
            raise PermissionDenied("agent API key does not permit this capability catalog")

    def request_access(
        self,
        agent,
        *,
        uri: str,
        capability: str,
        target_host: str | None,
        reason: str | None,
        ttl_seconds: int,
        max_uses: int,
    ) -> dict:
        self._require_agent_scope(agent, "access.request")
        if capability not in {"secret.use", "secret.reveal"}:
            raise ValidationError("capability must be secret.use or secret.reveal")
        self._require_agent_scope(agent, capability)
        if not reason or not reason.strip():
            raise PermissionDenied("access requests require a non-empty reason")
        if len(reason) > MAX_REASON_LENGTH:
            raise ValidationError(f"reason must be <= {MAX_REASON_LENGTH} characters")
        vault, item, field = parse_pass_ref(uri)
        if not field:
            raise ValidationError("agent access requests must name an exact field: pass://VAULT/ITEM/FIELD")
        ttl_seconds = int(ttl_seconds)
        max_uses = int(max_uses)
        if ttl_seconds < 60 or ttl_seconds > MAX_ACCESS_TTL:
            raise ValidationError(f"requested access TTL must be between 60 and {MAX_ACCESS_TTL} seconds")
        if max_uses < 1 or max_uses > MAX_ACCESS_USES:
            raise ValidationError(f"requested use budget must be between 1 and {MAX_ACCESS_USES}")
        if capability == "secret.use":
            if not target_host:
                raise ValidationError("secret.use requests require an exact target_host")
            target_host = self._normalize_host(target_host)
            ceiling = json.loads(agent["allowed_hosts_json"])
            if ceiling and not self._host_allowed(target_host, ceiling):
                raise PermissionDenied("requested host exceeds this agent API key's host ceiling")
        elif target_host:
            raise ValidationError("secret.reveal requests do not take target_host")

        ts = now()
        payload = {
            "selector": [vault, item, field],
            "reason": reason.strip(),
            "requested_ttl": ttl_seconds,
            "requested_uses": max_uses,
        }
        with self._db_lock:
            pending = list(
                self.db.execute(
                    "SELECT * FROM access_requests WHERE agent_id=? AND status='pending' ORDER BY created_at,id",
                    (agent["id"],),
                )
            )
            # Exact retries are idempotent. This keeps agents from creating a
            # new HITL card just because an RPC response was lost/retried.
            for existing in pending:
                if existing["capability"] != capability or existing["target_host"] != target_host:
                    continue
                if self._access_payload(existing) == payload:
                    return self._access_public(existing)
            if len(pending) >= MAX_PENDING_PER_AGENT:
                raise Conflict(f"agent already has {MAX_PENDING_PER_AGENT} pending access requests")

            request_id = "req_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")
            self.db.execute(
                "INSERT INTO access_requests(id,agent_id,capability,target_host,payload,status,item_id,expires_at,max_uses,uses,created_at,reviewed_at) VALUES(?,?,?,?,?,'pending',NULL,NULL,NULL,0,?,NULL)",
                (request_id, agent["id"], capability, target_host, self._seal_access_payload(request_id, payload), ts),
            )
            self.db.commit()
            result = self._access_public(self.db.execute("SELECT * FROM access_requests WHERE id=?", (request_id,)).fetchone())
        self.audit(agent["id"], "access.request", None, target_host, reason, True, {"request_id": request_id, "capability": capability})
        return result

    def request_capability(
        self,
        agent,
        *,
        capability_id: str,
        method: str,
        path: str,
        reason: str | None,
        ttl_seconds: int,
        max_uses: int,
    ) -> dict:
        self._require_agent_scope(agent, "capability.request")
        self._require_agent_scope(agent, "capability.invoke")
        if not reason or not reason.strip():
            raise PermissionDenied("capability requests require a non-empty reason")
        if len(reason) > MAX_REASON_LENGTH:
            raise ValidationError(f"reason must be <= {MAX_REASON_LENGTH} characters")
        ttl_seconds = int(ttl_seconds)
        max_uses = int(max_uses)
        if ttl_seconds < 60 or ttl_seconds > MAX_ACCESS_TTL:
            raise ValidationError(f"requested access TTL must be between 60 and {MAX_ACCESS_TTL} seconds")
        if max_uses < 1 or max_uses > MAX_ACCESS_USES:
            raise ValidationError(f"requested use budget must be between 1 and {MAX_ACCESS_USES}")

        cap_row = self.get_capability_row(capability_id)
        definition = self._capability_payload(cap_row)
        method, path = self._validate_capability_invocation(definition, method, path)
        ceiling = json.loads(agent["allowed_hosts_json"])
        if ceiling and not self._host_allowed(definition["host"], ceiling):
            raise PermissionDenied("capability target exceeds this agent API key's host ceiling")

        base_payload = {
            "authority_kind": "capability",
            "capability_id": cap_row["id"],
            "capability_version": cap_row["version"],
            "method": method,
            "path": path,
            "reason": reason.strip(),
            "requested_ttl": ttl_seconds,
            "requested_uses": max_uses,
        }
        ts = now()
        with self._db_lock:
            pending = list(
                self.db.execute(
                    "SELECT * FROM access_requests WHERE agent_id=? AND status='pending' ORDER BY created_at,id",
                    (agent["id"],),
                )
            )
            for existing in pending:
                if existing["capability"] != "capability.invoke":
                    continue
                ep = self._access_payload(existing)
                compare = dict(ep)
                compare.pop("authority_digest", None)
                if compare == base_payload:
                    return self._access_public(existing)
            if len(pending) >= MAX_PENDING_PER_AGENT:
                raise Conflict(f"agent already has {MAX_PENDING_PER_AGENT} pending access requests")

            request_id = "req_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")
            digest_material = {
                "schema": "passd-authority-v1",
                "request_id": request_id,
                "agent_id": agent["id"],
                "action": "capability.invoke",
                **base_payload,
            }
            payload = dict(base_payload)
            payload["authority_digest"] = authority_digest(digest_material)
            self.db.execute(
                "INSERT INTO access_requests(id,agent_id,capability,target_host,payload,status,item_id,expires_at,max_uses,uses,created_at,reviewed_at) VALUES(?,?,?,?,?,'pending',NULL,NULL,NULL,0,?,NULL)",
                (
                    request_id,
                    agent["id"],
                    "capability.invoke",
                    definition["host"],
                    self._seal_access_payload(request_id, payload),
                    ts,
                ),
            )
            self.db.commit()
            result = self._access_public(self.db.execute("SELECT * FROM access_requests WHERE id=?", (request_id,)).fetchone())
        self.audit(
            agent["id"],
            "capability.request",
            None,
            definition["host"],
            reason,
            True,
            {"request_id": request_id, "capability_id": cap_row["id"], "authority_digest": payload["authority_digest"]},
        )
        return result

    def _access_public(self, row, *, include_selector: bool = True) -> dict:
        payload = self._access_payload(row)
        remaining = None
        if row["max_uses"] is not None:
            remaining = max(0, int(row["max_uses"]) - int(row["uses"]))
        active = bool(
            row["status"] == "approved"
            and row["expires_at"] is not None
            and row["expires_at"] > now()
            and remaining is not None
            and remaining > 0
        )
        out = {
            "id": row["id"],
            "agent_id": row["agent_id"],
            "capability": row["capability"],
            "target_host": row["target_host"],
            "status": row["status"],
            "active": active,
            "expires_at": row["expires_at"],
            "max_uses": row["max_uses"],
            "uses": row["uses"],
            "uses_remaining": remaining,
            "created_at": row["created_at"],
            "reviewed_at": row["reviewed_at"],
            "requested_ttl": payload.get("requested_ttl"),
            "requested_uses": payload.get("requested_uses"),
            "reason": payload.get("reason"),
        }
        if payload.get("authority_kind") == "capability":
            out.update({
                "capability_id": payload.get("capability_id"),
                "capability_version": payload.get("capability_version"),
                "method": payload.get("method"),
                "path": payload.get("path"),
                "authority_digest": payload.get("authority_digest"),
            })
        elif include_selector:
            v, i, f = payload.get("selector", ["", "", ""])
            out["uri"] = f"pass://{urllib.parse.quote(v, safe='')}/{urllib.parse.quote(i, safe='')}/{urllib.parse.quote(f, safe='')}"
        if payload.get("approval_digest"):
            out["approval_digest"] = payload["approval_digest"]
        if payload.get("decision_note"):
            out["decision_note"] = payload["decision_note"]
        return out

    def get_access_request(self, request_id: str):
        row = self.db.execute("SELECT * FROM access_requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            raise NotFound(f"access request not found: {request_id}")
        return row

    def access_status(self, agent, request_id: str | None = None) -> list[dict] | dict:
        if request_id:
            row = self.get_access_request(request_id)
            if row["agent_id"] != agent["id"]:
                raise NotFound("access request not found")
            return self._access_public(row)
        return [self._access_public(r) for r in self.db.execute("SELECT * FROM access_requests WHERE agent_id=? ORDER BY created_at DESC", (agent["id"],))]

    def pending_access(self, *, status: str | None = "pending", limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        if status:
            rows = self.db.execute(
                "SELECT ar.*,a.name AS agent_name FROM access_requests ar JOIN agents a ON a.id=ar.agent_id WHERE ar.status=? ORDER BY ar.created_at LIMIT ?",
                (status, limit),
            )
        else:
            rows = self.db.execute(
                "SELECT ar.*,a.name AS agent_name FROM access_requests ar JOIN agents a ON a.id=ar.agent_id ORDER BY ar.created_at DESC LIMIT ?",
                (limit,),
            )
        out = []
        for row in rows:
            item = self._access_public(row)
            item["agent_name"] = row["agent_name"]
            out.append(item)
        return out

    def approve_access(self, request_id: str, *, ttl_seconds: int | None, max_uses: int | None, decision_note: str | None = None) -> dict:
        # One state machine backs both legacy exact-secret leases and v0.3 typed
        # capabilities. The human approves the immutable request digest, never
        # a mutable vault selector supplied at invocation time.
        with self._db_lock:
            row = self.get_access_request(request_id)
            if row["status"] != "pending":
                raise Conflict(f"access request is already {row['status']}")
            payload = self._access_payload(row)

            if payload.get("authority_kind") == "capability":
                try:
                    cap_row = self.get_capability_row(payload["capability_id"])
                except NotFound:
                    self.db.execute(
                        "UPDATE access_requests SET status='stale',reviewed_at=? WHERE id=? AND status='pending'",
                        (now(), request_id),
                    )
                    self.db.commit()
                    raise Conflict("capability changed or was removed; request again")
                if not hmac.compare_digest(str(payload.get("capability_version") or ""), str(cap_row["version"])):
                    self.db.execute(
                        "UPDATE access_requests SET status='stale',reviewed_at=? WHERE id=? AND status='pending'",
                        (now(), request_id),
                    )
                    self.db.commit()
                    self.audit(row["agent_id"], "access.stale", None, row["target_host"], payload.get("reason"), False, {"request_id": request_id, "why": "capability_version_changed"})
                    raise Conflict("capability changed after request; request again")
                definition = self._capability_payload(cap_row)
                self._validate_capability_invocation(definition, payload["method"], payload["path"])
                item_row, field = self.resolve_item_ref(definition["backing_uri"])
                self._extract_field(self._item_payload(item_row), field)
                payload["approved_credential_version"] = self._credential_version(item_row, field)
                payload["approved_capability_version"] = cap_row["version"]
                audit_detail = {
                    "request_id": request_id,
                    "capability_id": cap_row["id"],
                    "authority_digest": payload.get("authority_digest"),
                }
            else:
                vault, item, field = payload["selector"]
                item_row = self.find_item(vault, item)
                self._extract_field(self._item_payload(item_row), field)
                payload["approved_credential_version"] = self._credential_version(item_row, field)
                # Preserve old key name for readable pre-v0.3 payloads but stop
                # generating envelope hashes for new approvals.
                payload.pop("approved_item_fingerprint", None)
                payload.pop("approved_item_version", None)
                audit_detail = {"request_id": request_id}

            requested_ttl = int(payload["requested_ttl"])
            requested_uses = int(payload["requested_uses"])
            approved_ttl = requested_ttl if ttl_seconds is None else min(requested_ttl, max(60, int(ttl_seconds)))
            approved_uses = requested_uses if max_uses is None else min(requested_uses, max(1, int(max_uses)))
            payload["decision_note"] = (decision_note or "").strip() or None
            payload["approval_digest"] = authority_digest({
                "schema": "passd-approval-v1",
                "request_id": request_id,
                "agent_id": row["agent_id"],
                "authority_digest": payload.get("authority_digest"),
                "capability": row["capability"],
                "capability_id": payload.get("capability_id"),
                "capability_version": payload.get("capability_version"),
                "credential_version": payload.get("approved_credential_version"),
                "approved_ttl": approved_ttl,
                "approved_uses": approved_uses,
            })
            reviewed = now()
            cur = self.db.execute(
                "UPDATE access_requests SET payload=?,status='approved',item_id=?,expires_at=?,max_uses=?,uses=0,reviewed_at=? WHERE id=? AND status='pending'",
                (
                    self._seal_access_payload(request_id, payload),
                    item_row["id"],
                    reviewed + approved_ttl,
                    approved_uses,
                    reviewed,
                    request_id,
                ),
            )
            if cur.rowcount != 1:
                self.db.rollback()
                raise Conflict("access request was already reviewed")
            self.db.commit()
            audit_detail.update({"ttl": approved_ttl, "uses": approved_uses})
            self.audit(row["agent_id"], "access.approve", item_row, row["target_host"], payload.get("reason"), True, audit_detail)
            return self._access_public(self.get_access_request(request_id))

    def deny_access(self, request_id: str, note: str | None = None) -> dict:
        with self._db_lock:
            row = self.get_access_request(request_id)
            if row["status"] != "pending":
                raise Conflict(f"access request is already {row['status']}")
            payload = self._access_payload(row)
            payload["decision_note"] = (note or "").strip() or None
            cur = self.db.execute(
                "UPDATE access_requests SET payload=?,status='denied',reviewed_at=? WHERE id=? AND status='pending'",
                (self._seal_access_payload(request_id, payload), now(), request_id),
            )
            if cur.rowcount != 1:
                self.db.rollback()
                raise Conflict("access request was already reviewed")
            self.db.commit()
            self.audit(row["agent_id"], "access.deny", None, row["target_host"], payload.get("reason"), False, {"request_id": request_id})
            return self._access_public(self.get_access_request(request_id))

    def revoke_access(self, request_id: str) -> dict:
        with self._db_lock:
            row = self.get_access_request(request_id)
            if row["status"] != "approved":
                raise Conflict("only an approved access lease can be revoked")
            cur = self.db.execute(
                "UPDATE access_requests SET status='revoked',reviewed_at=? WHERE id=? AND status='approved'",
                (now(), request_id),
            )
            if cur.rowcount != 1:
                self.db.rollback()
                raise Conflict("access lease was already changed")
            self.db.commit()
            item_row = self.db.execute("SELECT * FROM items WHERE id=?", (row["item_id"],)).fetchone() if row["item_id"] else None
            self.audit(row["agent_id"], "access.revoke", item_row, row["target_host"], None, False, {"request_id": request_id})
            return self._access_public(self.get_access_request(request_id))

    def _active_grant_rows(self, agent_id: str):
        ts = now()
        return list(
            self.db.execute(
                "SELECT * FROM access_requests WHERE agent_id=? AND status='approved' AND expires_at>? AND max_uses IS NOT NULL AND uses<max_uses ORDER BY expires_at,id",
                (agent_id, ts),
            )
        )

    def _consume_exact_grant(self, agent, capability: str, uri: str, target_host: str | None, reason: str | None):
        if not reason or not reason.strip():
            self.audit(agent["id"], capability, None, target_host, reason, False, {"why": "missing_reason"})
            raise PermissionDenied("agent secret operations require a non-empty reason")
        self._require_agent_scope(agent, capability)
        selector = list(parse_pass_ref(uri))
        if not selector[2]:
            raise PermissionDenied("no active HITL grant for this exact credential scope")
        if capability == "secret.use":
            if not target_host:
                raise PermissionDenied("secret.use requires a target host")
            target_host = self._normalize_host(target_host)
        else:
            target_host = None

        ts = now()
        with self._db_lock:
            candidates = list(
                self.db.execute(
                    "SELECT * FROM access_requests WHERE agent_id=? AND capability=? AND status='approved' AND expires_at>? AND max_uses IS NOT NULL AND uses<max_uses AND target_host IS ? ORDER BY expires_at,id",
                    (agent["id"], capability, ts, target_host),
                )
            )
            for row in candidates:
                payload = self._access_payload(row)
                if payload.get("selector") != selector:
                    continue
                item_row = self.db.execute("SELECT * FROM items WHERE id=?", (row["item_id"],)).fetchone()
                item_payload = self._item_payload(item_row) if item_row else None
                approved_credential = payload.get("approved_credential_version")
                if approved_credential and item_payload is not None:
                    value = self._extract_field(item_payload, selector[2])
                    current_credential = credential_version(self.root_key, item_id=item_row["id"], field=selector[2], value=value)
                    version_ok = hmac.compare_digest(approved_credential, current_credential)
                elif payload.get("approved_item_version") and item_payload is not None:
                    # Compatibility with early v0.3 development snapshots.
                    approved_version = payload.get("approved_item_version")
                    current_version = item_version(self.root_key, item_payload)
                    version_ok = hmac.compare_digest(approved_version, current_version)
                else:
                    # Read-only compatibility with v0.2 approved leases, which
                    # bound to the randomized encrypted envelope.
                    approved_fp = payload.get("approved_item_fingerprint")
                    current_fp = hashlib.sha256(item_row["payload"].encode("utf-8")).hexdigest() if item_row else None
                    version_ok = bool(item_row and approved_fp and current_fp and hmac.compare_digest(approved_fp, current_fp))
                if not version_ok:
                    self.db.execute(
                        "UPDATE access_requests SET status='stale',reviewed_at=? WHERE id=? AND status='approved'",
                        (ts, row["id"]),
                    )
                    self.db.commit()
                    continue
                # Atomic budget claim. The short lock only covers SQLite and
                # crypto bookkeeping, never the outbound network request.
                cur = self.db.execute(
                    "UPDATE access_requests SET uses=uses+1 WHERE id=? AND status='approved' AND expires_at>? AND uses<max_uses",
                    (row["id"], ts),
                )
                self.db.commit()
                if cur.rowcount != 1:
                    continue
                return row, item_row, selector[2], item_payload

        self.audit(agent["id"], capability, None, target_host, reason, False, {"why": "no_active_hitl_grant"})
        raise PermissionDenied("no active HITL grant for this exact credential scope")

    def _consume_capability_grant(self, agent, capability_id: str, method: str, path: str, reason: str | None):
        if not reason or not reason.strip():
            self.audit(agent["id"], "capability.invoke", None, None, reason, False, {"why": "missing_reason"})
            raise PermissionDenied("capability invocation requires a non-empty reason")
        self._require_agent_scope(agent, "capability.invoke")
        try:
            cap_row = self.get_capability_row(capability_id)
        except NotFound:
            raise PermissionDenied("no active HITL lease for this exact capability request") from None
        definition = self._capability_payload(cap_row)
        method, path = self._validate_capability_invocation(definition, method, path)
        ceiling = json.loads(agent["allowed_hosts_json"])
        if ceiling and not self._host_allowed(definition["host"], ceiling):
            raise PermissionDenied("capability target exceeds this agent API key's host ceiling")

        ts = now()
        with self._db_lock:
            candidates = list(
                self.db.execute(
                    "SELECT * FROM access_requests WHERE agent_id=? AND capability='capability.invoke' AND status='approved' AND expires_at>? AND max_uses IS NOT NULL AND uses<max_uses ORDER BY expires_at,id",
                    (agent["id"], ts),
                )
            )
            for row in candidates:
                payload = self._access_payload(row)
                if payload.get("authority_kind") != "capability":
                    continue
                if payload.get("capability_id") != cap_row["id"] or payload.get("method") != method or payload.get("path") != path:
                    continue
                if not hmac.compare_digest(str(payload.get("capability_version") or ""), str(cap_row["version"])):
                    self.db.execute(
                        "UPDATE access_requests SET status='stale',reviewed_at=? WHERE id=? AND status='approved'",
                        (ts, row["id"]),
                    )
                    self.db.commit()
                    continue
                item_row = self.db.execute("SELECT * FROM items WHERE id=?", (row["item_id"],)).fetchone() if row["item_id"] else None
                field = parse_pass_ref(definition["backing_uri"])[2]
                item_payload = self._item_payload(item_row) if item_row else None
                approved_credential_version = payload.get("approved_credential_version")
                if item_payload is not None:
                    secret_value = self._extract_field(item_payload, field)
                    current_credential_version = credential_version(self.root_key, item_id=item_row["id"], field=field, value=secret_value)
                else:
                    current_credential_version = None
                if not item_row or not approved_credential_version or not current_credential_version or not hmac.compare_digest(approved_credential_version, current_credential_version):
                    self.db.execute(
                        "UPDATE access_requests SET status='stale',reviewed_at=? WHERE id=? AND status='approved'",
                        (ts, row["id"]),
                    )
                    self.db.commit()
                    continue
                cur = self.db.execute(
                    "UPDATE access_requests SET uses=uses+1 WHERE id=? AND status='approved' AND expires_at>? AND uses<max_uses",
                    (row["id"], ts),
                )
                self.db.commit()
                if cur.rowcount != 1:
                    continue
                return row, cap_row, definition, item_row, field, item_payload

        self.audit(agent["id"], "capability.invoke", None, definition["host"], reason, False, {"capability_id": cap_row["id"], "why": "no_active_hitl_lease"})
        raise PermissionDenied("no active HITL lease for this exact capability request")

    def list_authorized_vaults(self, agent) -> list[dict]:
        self._require_agent_scope(agent, "metadata.read")
        vault_ids: set[str] = set()
        for grant in self._active_grant_rows(agent["id"]):
            if not grant["item_id"]:
                continue
            item = self.db.execute("SELECT vault_id FROM items WHERE id=?", (grant["item_id"],)).fetchone()
            if item:
                vault_ids.add(item["vault_id"])
        result = []
        for vault_id in sorted(vault_ids):
            row = self.db.execute("SELECT * FROM vaults WHERE id=?", (vault_id,)).fetchone()
            if row:
                payload = self._vault_payload(row)
                result.append({"id": row["id"], "name": payload.get("name")})
        return result

    def list_authorized_items(self, agent, vault_ref: str) -> list[dict]:
        self._require_agent_scope(agent, "metadata.read")
        item_ids = {g["item_id"] for g in self._active_grant_rows(agent["id"]) if g["item_id"]}
        result = []
        for item_id in sorted(item_ids):
            row = self.db.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if not row:
                continue
            vrow = self.db.execute("SELECT * FROM vaults WHERE id=?", (row["vault_id"],)).fetchone()
            if not vrow:
                continue
            vp = self._vault_payload(vrow)
            if vault_ref not in {vrow["id"], vp.get("name")}:
                continue
            p = self._item_payload(row)
            result.append({"id": row["id"], "vault_id": row["vault_id"], "type": p.get("type"), "title": p.get("title"), "urls": p.get("urls", [])})
        return result

    # ---------- audit ----------
    def audit(self, agent_id: str | None, operation: str, item_row, target: str | None, reason: str | None, allowed: bool, detail: dict | None = None):
        # Reason/detail may contain sensitive task context. Encrypt them with
        # the root key while retaining only indexable metadata in plaintext.
        payload = {"reason": reason, "detail": detail or {}}
        sealed = "enc:" + seal_json(self.root_key, payload, aad=b"passd/audit/payload")
        with self._db_lock:
            self.db.execute(
                "INSERT INTO audit(ts,agent_id,operation,vault_id,item_id,target,reason,allowed,detail_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (now(), agent_id, operation, item_row["vault_id"] if item_row else None, item_row["id"] if item_row else None, target, None, 1 if allowed else 0, sealed),
            )
            self.db.commit()

    def _open_audit_payload(self, row) -> dict:
        raw = row["detail_json"] or "{}"
        if isinstance(raw, str) and raw.startswith("enc:"):
            return open_json(self.root_key, raw[4:], aad=b"passd/audit/payload")
        # Backwards compatibility for v1/v2.0 plaintext audit rows.
        try:
            detail = json.loads(raw)
        except Exception:
            detail = {}
        return {"reason": row["reason"], "detail": detail}

    def list_audit(self, *, agent_ref: str | None = None, limit: int = 100) -> list[dict]:
        limit = max(1, min(limit, 1000))
        if agent_ref:
            rows = list(self.db.execute("SELECT * FROM agents WHERE id=? OR name=?", (agent_ref, agent_ref)))
            if not rows:
                raise NotFound(f"agent not found: {agent_ref}")
            agent_id = rows[0]["id"]
            q = list(self.db.execute("SELECT * FROM audit WHERE agent_id=? ORDER BY id DESC LIMIT ?", (agent_id, limit)))
        else:
            q = list(self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)))
        out = []
        for r in q:
            private = self._open_audit_payload(r)
            out.append({
                "id": r["id"], "ts": r["ts"], "agent_id": r["agent_id"], "operation": r["operation"],
                "vault_id": r["vault_id"], "item_id": r["item_id"], "target": r["target"],
                "reason": private.get("reason"), "allowed": bool(r["allowed"]), "detail": private.get("detail") or {},
            })
        return out

    # ---------- secret operations ----------
    def reveal_secret(self, uri: str, *, agent_token: str | None, admin_password: str | None, reason: str | None):
        if agent_token:
            agent = self.authenticate_agent(agent_token)
            grant, item_row, field, payload = self._consume_exact_grant(agent, "secret.reveal", uri, None, reason)
            value = self._extract_field(payload, field)
            self.audit(agent["id"], "secret.reveal", item_row, None, reason, True, {"request_id": grant["id"]})
            return value
        # Authenticate before resolving the selector so an unauthenticated
        # same-UID caller cannot use error differences as a vault/item oracle.
        self.verify_admin_password(admin_password)
        item_row, field = self.resolve_item_ref(uri)
        payload = self._item_payload(item_row)
        return self._extract_field(payload, field)

    def _validate_target(self, url: str, *, agent) -> urllib.parse.SplitResult:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValidationError("broker URL must be http(s) with a hostname")
        if parsed.scheme != "https" and not self.allow_private_broker_targets:
            raise PermissionDenied("broker refuses plaintext HTTP; use HTTPS")
        if parsed.username or parsed.password:
            raise ValidationError("broker URL must not contain userinfo")
        host = parsed.hostname.lower()
        if agent is not None:
            ceiling = json.loads(agent["allowed_hosts_json"])
            if ceiling and not self._host_allowed(host, ceiling):
                raise PermissionDenied(f"agent API key host ceiling blocks: {host}")
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValidationError(f"unable to resolve broker host: {host}") from exc
        if not self.allow_private_broker_targets:
            for info in infos:
                ip = ipaddress.ip_address(info[4][0])
                if not ip.is_global:
                    raise PermissionDenied(f"broker target resolves to non-public address: {ip}")
        return parsed

    @staticmethod
    def _redact(value: str, secret_value: str) -> str:
        if not secret_value:
            return value
        return value.replace(secret_value, "<concealed by passd>")

    def _execute_http(self, url: str, *, method: str, headers: dict[str, str], body: str | None, secret_text: str, timeout: float) -> dict:
        data = None if body is None else body.encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with self._http_opener.open(req, timeout=timeout) as resp:
                response_body = resp.read(1024 * 1024 + 1)
                if len(response_body) > 1024 * 1024:
                    raise ValidationError("broker response exceeded 1 MiB")
                return {
                    "status": resp.status,
                    "headers": {
                        k: self._redact(v, secret_text)
                        for k, v in resp.headers.items()
                        if k.lower() in {"content-type", "content-length", "date", "etag", "location"}
                    },
                    "body": self._redact(response_body.decode("utf-8", errors="replace"), secret_text),
                }
        except urllib.error.HTTPError as exc:
            response_body = exc.read(1024 * 1024 + 1)
            if len(response_body) > 1024 * 1024:
                raise ValidationError("broker response exceeded 1 MiB")
            return {
                "status": exc.code,
                "headers": {
                    k: self._redact(v, secret_text)
                    for k, v in exc.headers.items()
                    if k.lower() in {"content-type", "content-length", "date", "etag", "location"}
                },
                "body": self._redact(response_body.decode("utf-8", errors="replace"), secret_text),
            }

    def invoke_capability(
        self,
        capability_id: str,
        *,
        method: str,
        path: str,
        body: str | None,
        agent_token: str | None,
        reason: str | None,
    ) -> dict:
        agent = self.authenticate_agent(agent_token)
        grant, cap_row, definition, item_row, field, item_payload = self._consume_capability_grant(
            agent, capability_id, method, path, reason
        )
        secret_value = self._extract_field(item_payload, field)
        if not isinstance(secret_value, (str, int, float)):
            raise ValidationError("capability secret field must be a scalar value")
        secret_text = str(secret_value)
        method, path = self._validate_capability_invocation(definition, method, path)

        default_port = 443 if definition["scheme"] == "https" else 80
        port_suffix = "" if int(definition["port"]) == default_port else f":{int(definition['port'])}"
        url = f"{definition['scheme']}://{definition['host']}{port_suffix}{path}"
        self._validate_target(url, agent=agent)

        headers = dict(definition.get("static_headers") or {})
        headers[definition["inject_header"]] = definition.get("inject_prefix", "") + secret_text
        result = self._execute_http(
            url,
            method=method,
            headers=headers,
            body=body,
            secret_text=secret_text,
            timeout=float(definition.get("timeout_seconds", 20.0)),
        )
        self.audit(
            agent["id"],
            "capability.invoke",
            item_row,
            definition["host"],
            reason,
            True,
            {
                "request_id": grant["id"],
                "capability_id": cap_row["id"],
                "capability_version": cap_row["version"],
                "method": method,
                "path": path,
                "status": result["status"],
            },
        )
        return result

    def broker_http(
        self,
        uri: str,
        url: str,
        *,
        method: str,
        header: str,
        prefix: str,
        body: str | None,
        extra_headers: dict[str, str] | None,
        agent_token: str | None,
        admin_password: str | None,
        reason: str | None,
        timeout: float = 20.0,
    ) -> dict:
        agent = self.authenticate_agent(agent_token) if agent_token else None
        # Admin-only broker calls authenticate before parsing/resolving any
        # caller-controlled destination. Agent calls authenticate above.
        if agent is None:
            self.verify_admin_password(admin_password)
        parsed = self._validate_target(url, agent=agent)
        if agent:
            grant, item_row, field, payload = self._consume_exact_grant(agent, "secret.use", uri, parsed.hostname.lower(), reason)
        else:
            item_row, field = self.resolve_item_ref(uri)
            grant = None
            payload = self._item_payload(item_row)
        secret_value = self._extract_field(payload, field)
        if not isinstance(secret_value, (str, int, float)):
            raise ValidationError("broker secret field must be a scalar value")
        secret_text = str(secret_value)
        header = header.strip()
        if not header or any(c in header for c in "\r\n:"):
            raise ValidationError("invalid injection header name")
        headers = {str(k): str(v) for k, v in (extra_headers or {}).items()}
        for key, value in headers.items():
            if not key or any(c in key for c in "\r\n:") or any(c in value for c in "\r\n"):
                raise ValidationError("invalid extra HTTP header")
        lower = {k.lower() for k in headers}
        if header.lower() in lower:
            raise ValidationError("extra headers must not override the injected secret header")
        if lower & {"host", ":authority", "proxy-authorization"}:
            raise ValidationError("extra headers must not override routing/authentication headers")
        headers[header] = prefix + secret_text
        result = self._execute_http(
            url, method=method, headers=headers, body=body, secret_text=secret_text, timeout=timeout
        )
        if agent:
            self.audit(agent["id"], "secret.use", item_row, parsed.hostname.lower(), reason, True, {"request_id": grant["id"], "method": method.upper(), "status": result["status"]})
        return result

    # ---------- RPC dispatch ----------
    def handle(self, request: dict) -> Any:
        op = request.get("op")
        p = request.get("params") or {}
        admin = request.get("admin_password")
        token = request.get("agent_token")
        reason = request.get("reason")

        if op == "health":
            return {"ok": True, "version": 3}

        if op == "vault.list":
            if token:
                return self.list_authorized_vaults(self.authenticate_agent(token))
            self.verify_admin_password(admin)
            return self.list_vaults()
        if op == "vault.create":
            self.verify_admin_password(admin)
            return self.create_vault(p["name"], p.get("description", ""), source=p.get("source"))

        if op == "item.list":
            if token:
                return self.list_authorized_items(self.authenticate_agent(token), p["vault"])
            self.verify_admin_password(admin)
            return self.list_items(p["vault"])
        if op == "item.put":
            self.verify_admin_password(admin)
            return self.put_item(
                p["vault"], p["title"], p.get("fields") or {}, item_type=p.get("type", "login"),
                urls=p.get("urls") or [], note=p.get("note", ""), source=p.get("source"), proton_raw=p.get("proton_raw"),
            )
        if op == "secret.resolve":
            return self.reveal_secret(p["uri"], agent_token=token, admin_password=admin, reason=reason)

        if op == "capability.put":
            self.verify_admin_password(admin)
            return self.put_capability(p)
        if op == "capability.get":
            self.verify_admin_password(admin)
            return self.get_capability(p["id"], include_definition=True)
        if op == "capability.list":
            if token:
                agent = self.authenticate_agent(token)
                self._require_any_agent_scope(agent, {"capability.request", "capability.invoke"})
            else:
                self.verify_admin_password(admin)
            return self.list_capabilities()
        if op == "capability.request":
            agent = self.authenticate_agent(token)
            return self.request_capability(
                agent,
                capability_id=p["capability_id"],
                method=p.get("method", "POST"),
                path=p.get("path", "/"),
                reason=reason,
                ttl_seconds=int(p.get("ttl_seconds", DEFAULT_ACCESS_TTL)),
                max_uses=int(p.get("max_uses", 1)),
            )
        if op == "capability.invoke":
            return self.invoke_capability(
                p["capability_id"],
                method=p.get("method", "POST"),
                path=p.get("path", "/"),
                body=p.get("body"),
                agent_token=token,
                reason=reason,
            )

        if op == "agent.create":
            self.verify_admin_password(admin)
            return self.create_agent(
                p["name"],
                scopes=p.get("scopes") or ["capability.request", "capability.invoke"],
                vault_refs=p.get("vaults") or [],
                item_refs=p.get("items") or [],
                allowed_hosts=p.get("allowed_hosts") or [],
                ttl_seconds=int(p.get("ttl_seconds", 3600)),
            )
        if op == "agent.list":
            self.verify_admin_password(admin)
            return self.list_agents()
        if op == "agent.rotate":
            self.verify_admin_password(admin)
            return self.rotate_agent(p["agent"])
        if op == "agent.revoke":
            self.verify_admin_password(admin)
            return self.revoke_agent(p["agent"])

        if op == "access.request":
            agent = self.authenticate_agent(token)
            return self.request_access(
                agent,
                uri=p["uri"],
                capability=p.get("capability", "secret.use"),
                target_host=p.get("target_host"),
                reason=reason,
                ttl_seconds=int(p.get("ttl_seconds", DEFAULT_ACCESS_TTL)),
                max_uses=int(p.get("max_uses", 1)),
            )
        if op == "access.status":
            agent = self.authenticate_agent(token)
            return self.access_status(agent, p.get("request"))
        if op == "access.pending":
            self.verify_admin_password(admin)
            return self.pending_access(status=p.get("status", "pending"), limit=int(p.get("limit", 100)))
        if op == "access.approve":
            self.verify_admin_password(admin)
            return self.approve_access(p["request"], ttl_seconds=p.get("ttl_seconds"), max_uses=p.get("max_uses"), decision_note=p.get("note"))
        if op == "access.deny":
            self.verify_admin_password(admin)
            return self.deny_access(p["request"], p.get("note"))
        if op == "access.revoke":
            self.verify_admin_password(admin)
            return self.revoke_access(p["request"])

        if op == "audit.list":
            self.verify_admin_password(admin)
            return self.list_audit(agent_ref=p.get("agent"), limit=int(p.get("limit", 100)))
        if op == "broker.http":
            return self.broker_http(
                p["uri"], p["url"], method=p.get("method", "GET"), header=p.get("header", "Authorization"),
                prefix=p.get("prefix", "Bearer "), body=p.get("body"), extra_headers=p.get("headers") or {},
                agent_token=token, admin_password=admin, reason=reason, timeout=float(p.get("timeout", 20)),
            )
        raise ValidationError(f"unknown operation: {op}")
