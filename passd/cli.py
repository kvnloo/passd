from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .client import PassdClient, RpcError
from .config import Config, default_data_dir
from .db import connect
from .errors import PassdError
from .proton_import import import_export
from .server import serve
from .service import DEFAULT_ACCESS_TTL, PassdService


def password_from_env(*, confirm: bool = False, prompt: str = "Master password: ") -> str:
    if os.environ.get("PASSD_MASTER_PASSWORD_FILE"):
        return Path(os.environ["PASSD_MASTER_PASSWORD_FILE"]).expanduser().read_text().strip()
    if os.environ.get("PASSD_MASTER_PASSWORD"):
        return os.environ["PASSD_MASTER_PASSWORD"]
    first = getpass.getpass(prompt)
    if confirm:
        second = getpass.getpass("Confirm master password: ")
        if first != second:
            raise ValueError("passwords do not match")
    return first


def agent_token(args) -> str | None:
    return getattr(args, "agent_token", None) or os.environ.get("PASSD_AGENT_TOKEN")


def reason(args) -> str | None:
    return getattr(args, "reason", None) or os.environ.get("PASSD_AGENT_REASON")


def parse_ttl(value: str) -> int:
    value = value.strip().lower()
    if not value:
        raise ValueError("empty expiration")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if value[-1:] in units:
        return int(value[:-1]) * units[value[-1]]
    return int(value)


def output(value, *, raw: bool = False):
    if raw and isinstance(value, (str, int, float)):
        print(value)
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2))


def get_client(data_dir: Path) -> PassdClient:
    cfg = Config.load(data_dir)
    return PassdClient(cfg.socket_path)


def add_common(p):
    p.add_argument("--data-dir", type=Path, default=default_data_dir(), help="passd data directory")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="passd", description="Local encrypted secret capability broker")
    add_common(p)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize encrypted storage")
    x = sub.add_parser("serve", help="run the local Unix-socket daemon")
    x.add_argument("--allow-private-broker-targets", action="store_true", help="allow broker requests to private/loopback IPs (development only)")
    sub.add_parser("doctor", help="check configuration and daemon")

    v = sub.add_parser("vault", help="vault operations")
    vs = v.add_subparsers(dest="vault_command", required=True)
    vl = vs.add_parser("list")
    vl.add_argument("--agent-token")
    c = vs.add_parser("create")
    c.add_argument("name")
    c.add_argument("--description", default="")

    i = sub.add_parser("item", help="item operations")
    ins = i.add_subparsers(dest="item_command", required=True)
    l = ins.add_parser("list")
    l.add_argument("vault")
    l.add_argument("--agent-token")
    c = ins.add_parser("put-login")
    c.add_argument("--vault", required=True)
    c.add_argument("--title", required=True)
    c.add_argument("--username")
    c.add_argument("--email")
    c.add_argument("--password")
    c.add_argument("--password-file", type=Path)
    c.add_argument("--url", action="append", default=[])
    c.add_argument("--field", action="append", default=[], metavar="NAME=VALUE")
    c.add_argument("--note", default="")
    vw = ins.add_parser("view")
    vw.add_argument("uri")
    vw.add_argument("--agent-token")
    vw.add_argument("--reason")
    vw.add_argument("--raw", action="store_true")

    a = sub.add_parser("agent", help="machine-account API keys")
    ags = a.add_subparsers(dest="agent_command", required=True)
    c = ags.add_parser("create")
    c.add_argument("name")
    c.add_argument("--scope", action="append", choices=["access.request", "metadata.read", "secret.use", "secret.reveal", "capability.request", "capability.invoke"], default=[])
    c.add_argument("--allow-host", action="append", default=[], help="optional hard ceiling; HITL grants are always exact-host")
    c.add_argument("--expiration", default="1d")
    ags.add_parser("list")
    rot = ags.add_parser("rotate", help="rotate a machine API key while preserving identity and leases")
    rot.add_argument("agent")
    r = ags.add_parser("revoke")
    r.add_argument("agent")
    m = ags.add_parser("monitor")
    m.add_argument("agent", nargs="?")
    m.add_argument("--limit", type=int, default=100)

    cp = sub.add_parser("capability", help="typed agent capabilities; backing secrets remain admin-only")
    cps = cp.add_subparsers(dest="capability_command", required=True)
    cl = cps.add_parser("list", help="list requestable capability contracts without secret selectors")
    cl.add_argument("--agent-token")
    cg = cps.add_parser("get", help="admin: inspect one capability including encrypted backing selector after daemon decrypt")
    cg.add_argument("capability_id")
    put = cps.add_parser("put-http", help="admin: create/update an HTTP capability backed by one secret field")
    put.add_argument("capability_id")
    put.add_argument("--description", default="")
    put.add_argument("--backing-uri", required=True, help="admin-only pass://VAULT/ITEM/FIELD backing selector")
    put.add_argument("--scheme", choices=["http", "https"], default="https")
    put.add_argument("--host", required=True)
    put.add_argument("--port", type=int)
    put.add_argument("--method", action="append", default=[], help="allowed HTTP method; repeatable")
    put.add_argument("--path-prefix", required=True)
    put.add_argument("--inject-header", default="Authorization")
    put.add_argument("--inject-prefix", default="Bearer ")
    put.add_argument("--static-header", action="append", default=[], metavar="NAME=VALUE")
    put.add_argument("--timeout", type=float, default=20.0)
    cr = cps.add_parser("request", help="agent: request a short-lived lease for one exact capability invocation")
    cr.add_argument("capability_id")
    cr.add_argument("--method", default="POST")
    cr.add_argument("--path", required=True)
    cr.add_argument("--expiration", default="5m")
    cr.add_argument("--uses", type=int, default=1)
    cr.add_argument("--agent-token")
    cr.add_argument("--reason")
    ci = cps.add_parser("invoke", help="agent: invoke an already approved exact capability")
    ci.add_argument("capability_id")
    ci.add_argument("--method", default="POST")
    ci.add_argument("--path", required=True)
    ci.add_argument("--body")
    ci.add_argument("--body-file", type=Path)
    ci.add_argument("--agent-token")
    ci.add_argument("--reason")

    ac = sub.add_parser("access", help="HITL access requests and short-lived leases")
    acs = ac.add_subparsers(dest="access_command", required=True)
    rq = acs.add_parser("request", help="agent requests one exact credential scope")
    rq.add_argument("uri", help="exact pass://VAULT/ITEM/FIELD selector")
    rq.add_argument("--capability", choices=["secret.use", "secret.reveal"], default="secret.use")
    rq.add_argument("--host", help="exact destination hostname required for secret.use")
    rq.add_argument("--expiration", default="5m")
    rq.add_argument("--uses", type=int, default=1)
    rq.add_argument("--agent-token")
    rq.add_argument("--reason")
    st = acs.add_parser("status", help="agent checks its own requests")
    st.add_argument("request", nargs="?")
    st.add_argument("--agent-token")
    pe = acs.add_parser("pending", help="HITL: list pending requests")
    pe.add_argument("--limit", type=int, default=100)
    ap = acs.add_parser("approve", help="HITL: approve a pending request")
    ap.add_argument("request")
    ap.add_argument("--expiration", help="may only shorten the agent-requested TTL")
    ap.add_argument("--uses", type=int, help="may only lower the agent-requested use budget")
    ap.add_argument("--note")
    de = acs.add_parser("deny", help="HITL: deny a pending request")
    de.add_argument("request")
    de.add_argument("--note")
    rv = acs.add_parser("revoke", help="HITL: revoke an approved lease")
    rv.add_argument("request")

    r = sub.add_parser("resolve", help="resolve a pass:// secret reference; agents require an approved secret.reveal lease")
    r.add_argument("uri")
    r.add_argument("--agent-token")
    r.add_argument("--reason")
    r.add_argument("--raw", action="store_true")

    b = sub.add_parser("broker-http", help="use a secret in an outbound HTTP request without returning the secret")
    b.add_argument("uri")
    b.add_argument("url")
    b.add_argument("--method", default="GET")
    b.add_argument("--header", default="Authorization")
    b.add_argument("--prefix", default="Bearer ")
    b.add_argument("--body")
    b.add_argument("--header-extra", action="append", default=[], metavar="NAME=VALUE")
    b.add_argument("--agent-token")
    b.add_argument("--reason")
    b.add_argument("--timeout", type=float, default=20)

    s = sub.add_parser("sync", help="snapshot import/export bridges")
    ss = s.add_subparsers(dest="sync_command", required=True)
    imp = ss.add_parser("import-proton", help="upsert an unencrypted Proton Pass ZIP/data.json export")
    imp.add_argument("path", type=Path)
    return p


def kv_pairs(values: list[str]) -> dict[str, str]:
    out = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"expected NAME=VALUE, got: {value}")
        k, v = value.split("=", 1)
        if not k:
            raise ValueError("field/header name must not be empty")
        out[k] = v
    return out


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    data_dir = args.data_dir.expanduser()
    try:
        if args.command == "init":
            password = password_from_env(confirm=not (os.environ.get("PASSD_MASTER_PASSWORD") or os.environ.get("PASSD_MASTER_PASSWORD_FILE")), prompt="New master password: ")
            cfg = Config.initialize(data_dir, password)
            conn = connect(cfg.db_path); conn.close()
            print(f"Initialized passd at {cfg.data_dir}")
            return 0

        if args.command == "serve":
            cfg = Config.load(data_dir)
            key = cfg.derive_and_verify(password_from_env())
            service = PassdService(cfg, key, allow_private_broker_targets=args.allow_private_broker_targets or os.environ.get("PASSD_ALLOW_PRIVATE_BROKER_TARGETS") == "1")
            print(f"passd listening on {cfg.socket_path}", file=sys.stderr)
            serve(cfg.socket_path, service)
            return 0

        client = get_client(data_dir)
        if args.command == "doctor":
            cfg = Config.load(data_dir)
            output({"data_dir": str(cfg.data_dir), "socket": str(cfg.socket_path), "daemon": client.call("health")})
            return 0

        if args.command == "vault":
            if args.vault_command == "list":
                token = agent_token(args)
                output(client.call("vault.list", agent_token=token) if token else client.call("vault.list", admin_password=password_from_env()))
            else:
                output(client.call("vault.create", {"name": args.name, "description": args.description}, admin_password=password_from_env()))
            return 0

        if args.command == "item":
            if args.item_command == "list":
                token = agent_token(args)
                output(client.call("item.list", {"vault": args.vault}, agent_token=token) if token else client.call("item.list", {"vault": args.vault}, admin_password=password_from_env()))
            elif args.item_command == "put-login":
                fields = kv_pairs(args.field)
                if args.username is not None: fields["username"] = args.username
                if args.email is not None: fields["email"] = args.email
                password = args.password_file.read_text().strip() if args.password_file else args.password
                if password is None: password = getpass.getpass("Secret password/API key: ")
                fields["password"] = password
                output(client.call("item.put", {"vault": args.vault, "title": args.title, "type": "login", "fields": fields, "urls": args.url, "note": args.note}, admin_password=password_from_env()))
            else:
                token = agent_token(args)
                kwargs = {"agent_token": token, "reason": reason(args)} if token else {"admin_password": password_from_env()}
                output(client.call("secret.resolve", {"uri": args.uri}, **kwargs), raw=args.raw)
            return 0

        if args.command == "agent":
            admin = password_from_env()
            if args.agent_command == "create":
                scopes = args.scope or ["capability.request", "capability.invoke"]
                output(client.call("agent.create", {"name": args.name, "scopes": scopes, "allowed_hosts": args.allow_host, "ttl_seconds": parse_ttl(args.expiration)}, admin_password=admin))
            elif args.agent_command == "list": output(client.call("agent.list", admin_password=admin))
            elif args.agent_command == "rotate": output(client.call("agent.rotate", {"agent": args.agent}, admin_password=admin))
            elif args.agent_command == "revoke": output(client.call("agent.revoke", {"agent": args.agent}, admin_password=admin))
            else: output(client.call("audit.list", {"agent": args.agent, "limit": args.limit}, admin_password=admin))
            return 0

        if args.command == "capability":
            if args.capability_command == "list":
                token = agent_token(args)
                output(client.call("capability.list", agent_token=token) if token else client.call("capability.list", admin_password=password_from_env()))
            elif args.capability_command == "get":
                output(client.call("capability.get", {"id": args.capability_id}, admin_password=password_from_env()))
            elif args.capability_command == "put-http":
                params = {
                    "id": args.capability_id,
                    "description": args.description,
                    "kind": "http_secret",
                    "backing_uri": args.backing_uri,
                    "scheme": args.scheme,
                    "host": args.host,
                    "methods": args.method or ["POST"],
                    "path_prefix": args.path_prefix,
                    "inject_header": args.inject_header,
                    "inject_prefix": args.inject_prefix,
                    "static_headers": kv_pairs(args.static_header),
                    "timeout_seconds": args.timeout,
                }
                if args.port is not None:
                    params["port"] = args.port
                output(client.call("capability.put", params, admin_password=password_from_env()))
            elif args.capability_command == "request":
                output(client.call(
                    "capability.request",
                    {
                        "capability_id": args.capability_id,
                        "method": args.method,
                        "path": args.path,
                        "ttl_seconds": parse_ttl(args.expiration),
                        "max_uses": args.uses,
                    },
                    agent_token=agent_token(args),
                    reason=reason(args),
                ))
            else:
                body = args.body_file.read_text() if args.body_file else args.body
                output(client.call(
                    "capability.invoke",
                    {"capability_id": args.capability_id, "method": args.method, "path": args.path, "body": body},
                    agent_token=agent_token(args),
                    reason=reason(args),
                ))
            return 0

        if args.command == "access":
            if args.access_command == "request":
                token = agent_token(args)
                output(client.call("access.request", {"uri": args.uri, "capability": args.capability, "target_host": args.host, "ttl_seconds": parse_ttl(args.expiration), "max_uses": args.uses}, agent_token=token, reason=reason(args)))
            elif args.access_command == "status":
                output(client.call("access.status", {"request": args.request} if args.request else {}, agent_token=agent_token(args)))
            elif args.access_command == "pending":
                output(client.call("access.pending", {"limit": args.limit}, admin_password=password_from_env()))
            elif args.access_command == "approve":
                params = {"request": args.request, "note": args.note}
                if args.expiration: params["ttl_seconds"] = parse_ttl(args.expiration)
                if args.uses is not None: params["max_uses"] = args.uses
                output(client.call("access.approve", params, admin_password=password_from_env()))
            elif args.access_command == "deny":
                output(client.call("access.deny", {"request": args.request, "note": args.note}, admin_password=password_from_env()))
            else:
                output(client.call("access.revoke", {"request": args.request}, admin_password=password_from_env()))
            return 0

        if args.command == "resolve":
            token = agent_token(args)
            kwargs = {"agent_token": token, "reason": reason(args)} if token else {"admin_password": password_from_env()}
            output(client.call("secret.resolve", {"uri": args.uri}, **kwargs), raw=args.raw)
            return 0

        if args.command == "broker-http":
            token = agent_token(args)
            kwargs = {"agent_token": token, "reason": reason(args)} if token else {"admin_password": password_from_env()}
            output(client.call("broker.http", {"uri": args.uri, "url": args.url, "method": args.method, "header": args.header, "prefix": args.prefix, "body": args.body, "headers": kv_pairs(args.header_extra), "timeout": args.timeout}, **kwargs))
            return 0

        if args.command == "sync":
            result = import_export(client, args.path, admin_password=password_from_env())
            output(result)
            return 0
        return 2
    except (PassdError, RpcError, ValueError, OSError, json.JSONDecodeError) as exc:
        code = getattr(exc, "code", "error")
        print(f"passd: {code}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
