"""google_service_account capability kind: no network, throwaway RSA key."""
from __future__ import annotations

import base64
import io
import json
import logging
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from email.message import Message
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from passd import google_sa
from passd.cli import build_parser
from passd.client import PassdClient, RpcError
from passd.config import Config
from passd.errors import PermissionDenied, ValidationError
from passd.server import PassdUnixServer
from passd.service import PassdService

MASTER = "correct horse battery staple"
PROJECT = "kvn-minter-test"
SA_EMAIL = f"credential-minter@{PROJECT}.iam.gserviceaccount.com"

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _PRIVATE.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()
PUBLIC = _PRIVATE.public_key()


def sa_key(**overrides) -> dict:
    key = {
        "type": "service_account",
        "project_id": PROJECT,
        "private_key_id": "0123456789abcdef0123456789abcdef01234567",
        "private_key": PRIVATE_PEM,
        "client_email": SA_EMAIL,
        "client_id": "100000000000000000001",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    key.update(overrides)
    return key


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_jwt(assertion: str) -> tuple[dict, dict]:
    head, claims, sig = assertion.split(".")
    PUBLIC.verify(b64d(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return json.loads(b64d(head)), json.loads(b64d(claims))


class FakeResponse:
    def __init__(self, status: int, body: bytes, content_type: str = "application/json"):
        self.status = status
        self._body = io.BytesIO(body)
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = str(len(body))

    def read(self, n=-1):
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeGoogle:
    """Stands in for oauth2/apikeys/iam/serviceusage. Records every request."""

    def __init__(self):
        self.token_calls = 0
        self.api_calls: list[dict] = []
        self.issued: list[str] = []
        self.token_status = 200
        self.api_responses: dict[str, tuple[int, object]] = {}
        self.lock = threading.Lock()

    def open(self, req, timeout=None):
        url = req.full_url
        if url == google_sa.GOOGLE_TOKEN_URI:
            with self.lock:
                self.token_calls += 1
                n = self.token_calls
            form = urllib.parse.parse_qs(req.data.decode())
            assert form["grant_type"] == [google_sa.JWT_BEARER_GRANT], form
            header, claims = verify_jwt(form["assertion"][0])
            assert header["alg"] == "RS256" and claims["iss"] == SA_EMAIL, (header, claims)
            if self.token_status != 200:
                body = json.dumps({"error": "invalid_grant", "error_description": "echo " + form["assertion"][0]}).encode()
                raise urllib.error.HTTPError(url, self.token_status, "bad", Message(), io.BytesIO(body))
            token = f"ya29.FAKE-ACCESS-TOKEN-{n}-" + "x" * 40
            self.issued.append(token)
            return FakeResponse(200, json.dumps({"access_token": token, "expires_in": 3599, "token_type": "Bearer"}).encode())
        parsed = urllib.parse.urlsplit(url)
        with self.lock:
            self.api_calls.append({
                "host": parsed.hostname,
                "path": parsed.path,
                "method": req.get_method(),
                "auth": req.get_header("Authorization"),
                "body": req.data.decode() if req.data else None,
            })
        status, body = self.api_responses.get(parsed.path, (200, {"ok": True, "echo_auth": req.get_header("Authorization")}))
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status >= 400:
            raise urllib.error.HTTPError(url, status, "err", Message(), io.BytesIO(raw))
        return FakeResponse(status, raw)


def public_dns(host, port, *a, **kw):
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.72.10", port))]


KEYS_PREFIX = f"/v2/projects/{PROJECT}/locations/global/keys"
CREATE_BODY = json.dumps({
    "displayName": "youtube-data",
    "restrictions": {"apiTargets": [{"service": "youtube.googleapis.com"}]},
})


class GoogleCapabilityBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config.initialize(Path(self.tmp.name), MASTER)
        self.service = PassdService(self.cfg, self.cfg.derive_and_verify(MASTER))
        self.fake = FakeGoogle()
        self.service._http_opener = self.fake
        self.dns = mock.patch("passd.service.socket.getaddrinfo", side_effect=public_dns)
        self.dns.start()
        self.service.create_vault("Google")
        self.imported = self.service.import_google_service_account("Google", "credential-minter", json.dumps(sa_key()))
        self.agent = self.service.create_agent(
            "hermes-google", scopes=["capability.request", "capability.invoke"], vault_refs=[], item_refs=[],
            allowed_hosts=[], ttl_seconds=3600,
        )
        self.agent_row = self.service.authenticate_agent(self.agent["token"])
        self.put_apikeys()

    def tearDown(self):
        self.dns.stop()
        self.service.close()
        self.tmp.cleanup()

    def put_apikeys(self, **extra):
        definition = {
            "id": "gcp.apikeys.create",
            "kind": "google_service_account",
            "description": "Create restricted API keys",
            "backing_uri": self.imported["backing_uri"],
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "hosts": ["apikeys.googleapis.com"],
            "methods": ["POST", "GET"],
            "path_prefixes": [KEYS_PREFIX, "/v2/operations"],
            "timeout_seconds": 5,
        }
        definition.update(extra)
        return self.service.put_capability(definition)

    def request(self, *, path=KEYS_PREFIX, method="POST", body=CREATE_BODY, uses=1, ttl=300, host=None, cap="gcp.apikeys.create"):
        return self.service.request_capability(
            self.agent_row, capability_id=cap, method=method, path=path, reason="mint a YouTube key for the uploader",
            ttl_seconds=ttl, max_uses=uses, host=host, body=body,
        )

    def approve(self, req):
        return self.service.approve_access(req["id"], ttl_seconds=None, max_uses=None)

    def invoke(self, *, path=KEYS_PREFIX, method="POST", body=CREATE_BODY, host=None, cap="gcp.apikeys.create"):
        return self.service.invoke_capability(
            cap, method=method, path=path, body=body, agent_token=self.agent["token"], reason="approved mint", host=host,
        )


class JwtAndKeyValidationTest(unittest.TestCase):
    def test_jwt_is_rs256_signed_with_service_account_key(self):
        assertion = google_sa.build_assertion(sa_key(), ["https://www.googleapis.com/auth/cloud-platform"], issued_at=1_800_000_000)
        header, claims = verify_jwt(assertion)  # raises InvalidSignature if wrong
        self.assertEqual(header, {"alg": "RS256", "typ": "JWT", "kid": sa_key()["private_key_id"]})
        self.assertEqual(claims["iss"], SA_EMAIL)
        self.assertEqual(claims["sub"], SA_EMAIL)
        self.assertEqual(claims["aud"], "https://oauth2.googleapis.com/token")
        self.assertEqual(claims["scope"], "https://www.googleapis.com/auth/cloud-platform")
        self.assertEqual(claims["iat"], 1_800_000_000)
        self.assertLessEqual(claims["exp"] - claims["iat"], 3600)

    def test_tampered_jwt_fails_verification(self):
        assertion = google_sa.build_assertion(sa_key(), ["https://www.googleapis.com/auth/cloud-platform"])
        head, claims, sig = assertion.split(".")
        forged = json.loads(b64d(claims))
        forged["scope"] = "https://www.googleapis.com/auth/admin"
        forged_claims = google_sa.b64url(json.dumps(forged).encode())
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            verify_jwt(f"{head}.{forged_claims}.{sig}")

    def test_assertion_lifetime_capped_at_one_hour(self):
        with self.assertRaises(ValidationError):
            google_sa.build_assertion(sa_key(), ["https://www.googleapis.com/auth/cloud-platform"], lifetime=3601)

    def test_invalid_key_json_rejected(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        bad = [
            "not json",
            json.dumps([1, 2]),
            json.dumps(sa_key(type="authorized_user")),
            json.dumps(sa_key(client_email="nope")),
            json.dumps(sa_key(token_uri="https://evil.example/token")),
            json.dumps(sa_key(token_uri="http://oauth2.googleapis.com/token")),
            json.dumps(sa_key(private_key="-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")),
            json.dumps(sa_key(private_key=small)),
            json.dumps({k: v for k, v in sa_key().items() if k != "private_key"}),
        ]
        for value in bad:
            with self.assertRaises(ValidationError, msg=value[:40]) as cm:
                google_sa.parse_service_account_key(value)
            self.assertNotIn("PRIVATE KEY", str(cm.exception))

    def test_scope_and_host_validation(self):
        with self.assertRaises(ValidationError):
            google_sa.normalize_scopes([])
        with self.assertRaises(ValidationError):
            google_sa.normalize_scopes(["https://evil.example/auth"])
        for host in ("evil.example", "googleapis.com.evil.example", "oauth2.googleapis.com", "a/b.googleapis.com"):
            with self.assertRaises(ValidationError, msg=host):
                google_sa.normalize_google_host(host)
        self.assertEqual(google_sa.normalize_google_host("IAM.googleapis.com."), "iam.googleapis.com")

    def test_summaries_read_like_sudo_prompts(self):
        s = google_sa.summarize_request("apikeys.googleapis.com", "POST", KEYS_PREFIX, CREATE_BODY)
        self.assertEqual(s, f"create API key 'youtube-data' restricted to youtube.googleapis.com in project {PROJECT}")
        s = google_sa.summarize_request("apikeys.googleapis.com", "POST", KEYS_PREFIX, json.dumps({"displayName": "x"}))
        self.assertIn("UNRESTRICTED", s)
        s = google_sa.summarize_request("serviceusage.googleapis.com", "POST", f"/v1/projects/{PROJECT}/services/youtube.googleapis.com:enable", None)
        self.assertEqual(s, f"enable API youtube.googleapis.com in project {PROJECT}")
        s = google_sa.summarize_request("iam.googleapis.com", "POST", f"/v1/projects/{PROJECT}/serviceAccounts/uploader@{PROJECT}.iam.gserviceaccount.com/keys", "{}")
        self.assertIn("NEW PRIVATE KEY for service account uploader@", s)


class GoogleCapabilityFlowTest(GoogleCapabilityBase):
    def test_import_returns_metadata_only(self):
        blob = json.dumps(self.imported)
        self.assertNotIn("PRIVATE KEY", blob)
        self.assertEqual(self.imported["client_email"], SA_EMAIL)
        self.assertTrue(self.imported["backing_uri"].startswith("pass://Google/credential-minter/service_account_json"))

    def test_capability_rejects_non_service_account_backing_and_bad_hosts(self):
        self.service.put_item("Google", "plain", {"password": "hunter2"})
        base = {
            "id": "gcp.bad", "kind": "google_service_account", "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "hosts": ["apikeys.googleapis.com"], "methods": ["POST"], "path_prefixes": [KEYS_PREFIX],
            "backing_uri": "pass://Google/plain/password",
        }
        with self.assertRaises(ValidationError):
            self.service.put_capability(base)
        for override in (
            {"hosts": ["evil.example"]},
            {"hosts": ["oauth2.googleapis.com"]},
            {"scopes": []},
            {"path_prefixes": ["/"]},
            {"path_prefixes": []},
            {"methods": ["TRACE"]},
        ):
            with self.assertRaises(ValidationError, msg=override):
                self.service.put_capability({**base, "backing_uri": self.imported["backing_uri"], **override})

    def test_public_catalog_hides_backing_and_key(self):
        catalog = self.service.list_capabilities()
        blob = json.dumps(catalog)
        self.assertNotIn("pass://", blob)
        self.assertNotIn("PRIVATE KEY", blob)
        cap = catalog[0]
        self.assertEqual(cap["kind"], "google_service_account")
        self.assertEqual(cap["target_hosts"], ["apikeys.googleapis.com"])
        self.assertEqual(cap["response_secret_fields"], ["keyString", "privateKeyData"])
        self.assertFalse(cap["response_secret_reveal"])

    def test_no_authority_until_human_approves(self):
        with self.assertRaises(PermissionDenied):
            self.invoke()
        req = self.request()
        self.assertEqual(req["status"], "pending")
        with self.assertRaises(PermissionDenied):
            self.invoke()
        self.assertEqual(self.fake.token_calls, 0)
        self.assertEqual(self.fake.api_calls, [])

    def test_pending_request_shows_human_readable_digest(self):
        req = self.request()
        pending = self.service.pending_access()
        self.assertEqual(len(pending), 1)
        card = pending[0]
        self.assertEqual(card["id"], req["id"])
        self.assertEqual(card["summary"], f"create API key 'youtube-data' restricted to youtube.googleapis.com in project {PROJECT}")
        self.assertEqual(card["url"], f"https://apikeys.googleapis.com{KEYS_PREFIX}")
        self.assertEqual(card["method"], "POST")
        self.assertEqual(card["body_preview"], CREATE_BODY)
        self.assertEqual(len(card["body_sha256"]), 64)
        self.assertTrue(card["authority_digest"].startswith("ad1_"))
        self.assertEqual(card["agent_name"], "hermes-google")

    def test_approved_call_injects_bearer_and_hides_token(self):
        self.approve(self.request())
        result = self.invoke()
        self.assertEqual(result["status"], 200)
        self.assertEqual(self.fake.token_calls, 1)
        call = self.fake.api_calls[0]
        token = self.fake.issued[0]
        self.assertEqual(call["auth"], "Bearer " + token)
        self.assertEqual(call["host"], "apikeys.googleapis.com")
        self.assertEqual(call["body"], CREATE_BODY)
        blob = json.dumps(result)
        self.assertNotIn(token, blob)  # Google echoing auth is concealed
        self.assertIn("<concealed by passd>", blob)

    def test_token_and_private_key_never_in_audit_db_logs_or_rpc(self):
        records: list[str] = []

        class Grab(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        root = logging.getLogger()
        handler = Grab(level=logging.DEBUG)
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            self.approve(self.request(uses=2))
            outputs = [self.invoke(), self.invoke()]
            outputs.append(self.service.list_audit(limit=1000))
            outputs.append(self.service.pending_access(status=None))
            outputs.append(self.service.access_status(self.agent_row))
            outputs.append(self.service.list_capabilities())
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        token = self.fake.issued[0]
        pem_body = PRIVATE_PEM.splitlines()[1]
        haystacks = [json.dumps(o) for o in outputs] + records
        for path in Path(self.tmp.name).rglob("*"):
            if path.is_file():
                haystacks.append(path.read_bytes().decode("latin-1"))
        for hay in haystacks:
            self.assertNotIn(token, hay)
            self.assertNotIn(pem_body, hay)

    def test_token_cached_in_memory_per_lease_only(self):
        self.approve(self.request(uses=3))
        self.invoke(); self.invoke()
        self.assertEqual(self.fake.token_calls, 1)
        self.assertEqual(len(self.fake.issued), 1)
        self.assertEqual(self.fake.api_calls[0]["auth"], self.fake.api_calls[1]["auth"])
        # A separate lease never reuses another lease's token.
        other_body = json.dumps({"displayName": "maps", "restrictions": {"apiTargets": [{"service": "maps.googleapis.com"}]}})
        self.approve(self.request(body=other_body))
        self.invoke(body=other_body)
        self.assertEqual(self.fake.token_calls, 2)
        # Exhausting the second lease evicts its token.
        self.assertEqual(len(self.service._google_tokens), 1)

    def test_revoke_drops_cached_token(self):
        req = self.request(uses=3)
        self.approve(req)
        self.invoke()
        self.assertEqual(len(self.service._google_tokens), 1)
        self.service.revoke_access(req["id"])
        self.assertEqual(len(self.service._google_tokens), 0)
        with self.assertRaises(PermissionDenied):
            self.invoke()

    def test_host_path_method_and_body_enforcement(self):
        with self.assertRaises(PermissionDenied):
            self.request(path=f"/v2/projects/other-project/locations/global/keys")
        with self.assertRaises(PermissionDenied):
            self.request(method="DELETE")
        with self.assertRaises(PermissionDenied):
            self.request(host="iam.googleapis.com")
        with self.assertRaises(ValidationError):
            self.request(path=KEYS_PREFIX + "/../../../other/keys")
        with self.assertRaises(ValidationError):
            self.request(path=KEYS_PREFIX + "?keyId=x")
        self.approve(self.request(uses=5))
        # Approved body/path/method/host are exact.
        with self.assertRaises(PermissionDenied):
            self.invoke(body=json.dumps({"displayName": "youtube-data"}))  # restriction removed
        with self.assertRaises(PermissionDenied):
            self.invoke(body=None)
        with self.assertRaises(PermissionDenied):
            self.invoke(method="GET")
        with self.assertRaises(PermissionDenied):
            self.invoke(path=KEYS_PREFIX + "/abc")
        with self.assertRaises(PermissionDenied):
            self.invoke(host="iam.googleapis.com")
        self.assertEqual(self.fake.api_calls, [])
        self.assertEqual(self.invoke()["status"], 200)

    def test_agent_host_ceiling_applies(self):
        narrow = self.service.create_agent(
            "narrow", scopes=["capability.request", "capability.invoke"], vault_refs=[], item_refs=[],
            allowed_hosts=["iam.googleapis.com"], ttl_seconds=3600,
        )
        with self.assertRaises(PermissionDenied):
            self.service.request_capability(
                self.service.authenticate_agent(narrow["token"]), capability_id="gcp.apikeys.create", method="POST",
                path=KEYS_PREFIX, reason="x", ttl_seconds=300, max_uses=1, body=CREATE_BODY,
            )

    def test_use_budget_enforced(self):
        self.approve(self.request(uses=1))
        self.invoke()
        with self.assertRaises(PermissionDenied):
            self.invoke()
        self.assertEqual(len(self.fake.api_calls), 1)

    def test_lease_expiry_enforced(self):
        req = self.request(uses=5)
        self.approve(req)
        self.invoke()
        self.service.db.execute("UPDATE access_requests SET expires_at=? WHERE id=?", (1, req["id"]))
        self.service.db.commit()
        with self.assertRaises(PermissionDenied):
            self.invoke()
        self.assertEqual(len(self.fake.api_calls), 1)

    def test_token_cache_never_outlives_lease(self):
        cache = google_sa.TokenCache(clock=lambda: 1000.0)
        cache.put(("lease",), "tok", 30)  # shorter than expiry skew -> not cached
        self.assertIsNone(cache.get(("lease",)))
        t = [1000.0]
        cache = google_sa.TokenCache(clock=lambda: t[0])
        cache.put(("lease",), "tok", 3599)
        self.assertEqual(cache.get(("lease",)), "tok")
        t[0] += 3600
        self.assertIsNone(cache.get(("lease",)))

    def test_key_string_redacted_and_stored_in_custody(self):
        key_name = f"projects/{PROJECT}/locations/global/keys/k123"
        self.fake.api_responses[f"/v2/{key_name}/keyString"] = (200, {"keyString": "AIzaSyFAKE-minted-key-string-000000000"})
        path = f"/v2/{key_name}/keyString"
        self.approve(self.request(method="GET", path=path, body=None))
        result = self.invoke(method="GET", path=path, body=None)
        self.assertNotIn("AIzaSyFAKE", json.dumps(result))
        body = json.loads(result["body"])
        self.assertTrue(body["keyString"].startswith("passd-redacted:pass://Google/"))
        ref = body["keyString"][len("passd-redacted:"):]
        self.assertEqual(result["custody_refs"], [ref])
        # Admin can read it back; the agent cannot without a separate lease.
        self.assertEqual(self.service.reveal_secret(ref, agent_token=None, admin_password=MASTER, reason=None), "AIzaSyFAKE-minted-key-string-000000000")
        with self.assertRaises(PermissionDenied):
            self.service.reveal_secret(ref, agent_token=self.agent["token"], admin_password=None, reason="peek")

    def test_nested_operation_key_string_and_sa_private_key_data(self):
        self.fake.api_responses[KEYS_PREFIX] = (200, {
            "name": "operations/akmf.p7-1", "done": True,
            "response": {"@type": "type.googleapis.com/google.api.apikeys.v2.Key", "name": f"projects/{PROJECT}/locations/global/keys/k9",
                         "uid": "k9", "keyString": "AIzaSyNESTED-secret"},
        })
        self.approve(self.request())
        result = self.invoke()
        self.assertNotIn("AIzaSyNESTED-secret", json.dumps(result))
        self.assertEqual(json.loads(result["body"])["response"]["uid"], "k9")

        sa_path = f"/v1/projects/{PROJECT}/serviceAccounts/uploader@{PROJECT}.iam.gserviceaccount.com/keys"
        self.service.put_capability({
            "id": "gcp.iam.sakeys.create", "kind": "google_service_account", "backing_uri": self.imported["backing_uri"],
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"], "hosts": ["iam.googleapis.com"],
            "methods": ["POST"], "path_prefixes": [f"/v1/projects/{PROJECT}/serviceAccounts"],
        })
        self.fake.api_responses[sa_path] = (200, {"name": f"{sa_path[4:]}/abc", "privateKeyData": "eyJ0eXBlIjoic2VydmljZV9hY2NvdW50In0="})
        self.approve(self.request(cap="gcp.iam.sakeys.create", path=sa_path, body="{}"))
        result = self.invoke(cap="gcp.iam.sakeys.create", path=sa_path, body="{}")
        self.assertNotIn("eyJ0eXBlIjoic2VydmljZV9hY2NvdW50In0=", json.dumps(result))
        ref = result["custody_refs"][0]
        self.assertTrue(ref.endswith("/privateKeyData"))
        audit = self.service.list_audit(limit=5)
        self.assertIn(ref, audit[0]["detail"]["minted_refs"])

    def test_reveal_option_returns_secret_but_still_stores_it(self):
        self.put_apikeys(response_secret_reveal=True)
        self.fake.api_responses[KEYS_PREFIX] = (200, {"keyString": "AIzaSyREVEALED"})
        self.approve(self.request())
        result = self.invoke()
        self.assertEqual(json.loads(result["body"])["keyString"], "AIzaSyREVEALED")
        self.assertEqual(len(result["custody_refs"]), 1)

    def test_non_json_response_withheld_when_secret_fields_declared(self):
        self.fake.api_responses[KEYS_PREFIX] = (200, b"keyString=AIzaSyRAW")
        self.approve(self.request())
        result = self.invoke()
        self.assertTrue(result["body_withheld"])
        self.assertNotIn("AIzaSyRAW", json.dumps(result))

    def test_token_exchange_failure_does_not_echo_body(self):
        self.fake.token_status = 400
        self.approve(self.request())
        with self.assertRaises(PermissionDenied) as cm:
            self.invoke()
        self.assertEqual(str(cm.exception), "Google token exchange failed with HTTP 400")
        self.assertEqual(self.fake.api_calls, [])

    def test_backing_key_rotation_stales_lease(self):
        self.approve(self.request(uses=3))
        self.invoke()
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        rotated = self.service.import_google_service_account("Google", "credential-minter", json.dumps(sa_key(private_key=other)))
        self.assertEqual(rotated["id"], self.imported["id"])  # rotated in place
        self.assertEqual(self.service.db.execute("SELECT COUNT(*) FROM items").fetchone()[0], 1)
        with self.assertRaises(PermissionDenied):
            self.invoke()
        self.assertEqual(len(self.fake.api_calls), 1)
        self.assertEqual(len(self.service._google_tokens), 0)  # stale lease's token dropped

    def test_import_refuses_to_shadow_unrelated_item(self):
        self.service.put_item("Google", "other", {"password": "x"})
        from passd.errors import Conflict
        with self.assertRaises(Conflict):
            self.service.import_google_service_account("Google", "other", json.dumps(sa_key()))


class GoogleCapabilityRpcTest(unittest.TestCase):
    """Same flow over the real Unix-socket RPC surface."""

    def test_rpc_flow_and_cli_parser(self):
        tmp = tempfile.TemporaryDirectory()
        cfg = Config.initialize(Path(tmp.name), MASTER)
        service = PassdService(cfg, cfg.derive_and_verify(MASTER))
        fake = FakeGoogle()
        service._http_opener = fake
        server = PassdUnixServer(cfg.socket_path, service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch("passd.service.socket.getaddrinfo", side_effect=public_dns):
                c = PassdClient(cfg.socket_path)
                c.call("vault.create", {"name": "Google"}, admin_password=MASTER)
                with self.assertRaises(RpcError) as cm:
                    c.call("google_sa.import", {"vault": "Google", "title": "bad", "key_json": "{}"}, admin_password=MASTER)
                self.assertEqual(cm.exception.code, "validation_error")
                with self.assertRaises(RpcError):
                    c.call("google_sa.import", {"vault": "Google", "title": "m", "key_json": json.dumps(sa_key())})
                imp = c.call("google_sa.import", {"vault": "Google", "title": "m", "key_json": json.dumps(sa_key())}, admin_password=MASTER)
                c.call("capability.put", {
                    "id": "gcp.serviceusage.enable", "kind": "google_service_account", "backing_uri": imp["backing_uri"],
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"], "hosts": ["serviceusage.googleapis.com"],
                    "methods": ["POST"], "path_prefixes": [f"/v1/projects/{PROJECT}/services"],
                }, admin_password=MASTER)
                agent = c.call("agent.create", {"name": "a", "ttl_seconds": 3600}, admin_password=MASTER)
                path = f"/v1/projects/{PROJECT}/services/youtube.googleapis.com:enable"
                req = c.call("capability.request", {"capability_id": "gcp.serviceusage.enable", "method": "POST", "path": path, "max_uses": 1},
                             agent_token=agent["token"], reason="enable YouTube Data API")
                pending = c.call("access.pending", {}, admin_password=MASTER)
                self.assertEqual(pending[0]["summary"], f"enable API youtube.googleapis.com in project {PROJECT}")
                c.call("access.approve", {"request": req["id"]}, admin_password=MASTER)
                out = c.call("capability.invoke", {"capability_id": "gcp.serviceusage.enable", "method": "POST", "path": path},
                             agent_token=agent["token"], reason="go")
                self.assertEqual(out["status"], 200)
                self.assertNotIn(fake.issued[0], json.dumps(out))
                self.assertEqual(fake.api_calls[0]["auth"], "Bearer " + fake.issued[0])
        finally:
            server.shutdown()
            server.server_close()
            service.close()
            tmp.cleanup()

        args = build_parser().parse_args([
            "capability", "put-google-sa", "gcp.apikeys.create", "--backing-uri", "pass://Google/m/service_account_json",
            "--scope", "https://www.googleapis.com/auth/cloud-platform", "--host", "apikeys.googleapis.com",
            "--method", "POST", "--method", "GET", "--path-prefix", KEYS_PREFIX, "--path-prefix", "/v2/operations",
            "--response-secret-field", "keyString",
        ])
        self.assertEqual(args.host, ["apikeys.googleapis.com"])
        self.assertEqual(args.path_prefix, [KEYS_PREFIX, "/v2/operations"])
        self.assertEqual(args.response_secret_field, ["keyString"])


if __name__ == "__main__":
    unittest.main()
