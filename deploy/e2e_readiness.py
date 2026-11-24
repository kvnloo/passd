"""Exercise the owner-approved flow using disposable credentials."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from passd.cli import read_secret_line


class CheckFailed(Exception):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise CheckFailed


@contextmanager
def step(label: str):
    try:
        yield
    except Exception:
        print(f"FAIL {label}", flush=True)
        raise
    print(f"PASS {label}", flush=True)


def cli_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if not key.startswith("PASSD_") and key not in {"PYTHONINSPECT", "PYTHONSTARTUP"}}


def exercise(socket_path: Path, master: str, *, state: Path | None, gateway: str | None) -> None:
    env = cli_env()
    command = [sys.executable, "-m", "passd"]
    if state is not None:
        command.extend(["--data-dir", str(state)])
    env["PASSD_SOCKET"] = str(socket_path)
    suffix = uuid.uuid4().hex
    secret = f"readiness-dummy-secret-{suffix}"
    token = None
    agent = None
    daemon = None

    def call(*args, admin=False, extra_input="", denied=None, agent_call=False):
        child_env = env.copy()
        if agent_call:
            child_env["PASSD_AGENT_TOKEN"] = token
            child_env["PASSD_AGENT_REASON"] = "disposable broker readiness check"
            if gateway:
                child_env["PASSD_REMOTE"] = gateway
        if admin:
            args = ("--master-password-stdin", *args)
        result = subprocess.run(
            [*command, *args], input=(master + "\n" if admin else "") + extra_input,
            env=child_env, capture_output=True, text=True, timeout=15,
        )
        for value in (master, secret, token):
            if value:
                require(value not in result.stdout and value not in result.stderr)
        if denied:
            require(result.returncode != 0 and f"passd: {denied}:" in result.stderr)
            return None
        require(result.returncode == 0)
        if result.stdout.strip().startswith(("{", "[")):
            return json.loads(result.stdout)
        return None

    received = []

    class Echo(BaseHTTPRequestHandler):
        def do_POST(self):
            header = self.headers.get("Authorization")
            received.append(header)
            body = json.dumps({"echo": header}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with HTTPServer(("127.0.0.1", 0), Echo) as echo:
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        try:
            if state is not None:
                with step("initialize encrypted store via stdin"):
                    call("init", admin=True)
                with step("unlock daemon via stdin"):
                    daemon = subprocess.Popen(
                        [*command, "serve", "--master-password-stdin", "--allow-private-broker-targets"],
                        env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        text=True,
                    )
                    with daemon.stdin:
                        daemon.stdin.write(master + "\n")
                    deadline = time.monotonic() + 10
                    while not socket_path.exists():
                        require(daemon.poll() is None and time.monotonic() < deadline)
                        time.sleep(0.025)
            with step("authenticate to running broker"):
                vaults = call("vault", "list", admin=True)
            with step("provision dummy agents login via stdin"):
                if not any(vault["name"] == "agents" for vault in vaults):
                    call("vault", "create", "agents", admin=True)
                title = f"readiness-{suffix}"
                call("item", "put-login", "--vault", "agents", "--title", title,
                     "--password-stdin", admin=True, extra_input=secret + "\n")
            with step("create one-use HTTP capability and scoped agent key"):
                cap = f"readiness.{suffix}"
                call("capability", "put-http", cap, "--scheme", "http", "--host", "127.0.0.1",
                     "--port", str(echo.server_port), "--method", "POST", "--path-prefix", "/echo",
                     "--backing-uri", f"pass://agents/{title}/password", admin=True)
                agent = call("agent", "create", title, "--expiration", "5m",
                             "--allow-host", "127.0.0.1", admin=True)
                token = agent["token"]
            with step("deny invocation before approval"):
                call("capability", "invoke", cap, "--path", "/echo", agent_call=True,
                     denied="permission_denied")
                require(not received)
            with step("request one use and verify pending"):
                request = call("capability", "request", cap, "--path", "/echo", "--uses", "1",
                               agent_call=True)
                pending = call("access", "status", request["id"], agent_call=True)
                require(pending["status"] == "pending")
            with step("approve one use via stdin"):
                approved = call("access", "approve", request["id"], "--uses", "1", admin=True)
                require(approved["status"] == "approved")
            with step("inject secret at echo server and redact agent output"):
                result = call("capability", "invoke", cap, "--path", "/echo", agent_call=True)
                require(result["status"] == 200 and received == ["Bearer " + secret])
            with step("deny invocation after budget exhaustion"):
                call("capability", "invoke", cap, "--path", "/echo", agent_call=True,
                     denied="permission_denied")
                require(len(received) == 1)
            with step("deny direct item request outside agents"):
                call("access", "request", f"pass://Personal/{title}/password", "--host", "127.0.0.1",
                     agent_call=True, denied="permission_denied")
                call("capability", "request", cap, "--path", "/outside", agent_call=True,
                     denied="permission_denied")
            with step("revoke agent and deny further requests"):
                call("agent", "revoke", agent["id"], admin=True)
                agent = None
                call("capability", "request", cap, "--path", "/echo", agent_call=True, denied="auth_error")
        finally:
            try:
                if agent is not None:
                    with step("revoke disposable agent during cleanup"):
                        call("agent", "revoke", agent["id"], admin=True)
            finally:
                if daemon is not None:
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait(timeout=5)
                echo.shutdown()
                thread.join()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, help="socket of a running disposable broker; reads its master password on stdin")
    parser.add_argument("--gateway", help="optional agent-only gateway for the running disposable broker")
    args = parser.parse_args()
    if args.gateway and not args.socket:
        parser.error("--gateway requires --socket")
    try:
        if args.socket:
            with step("read disposable master password via stdin"):
                master = read_secret_line()
            exercise(args.socket, master, state=None, gateway=args.gateway)
        else:
            # Keep the Unix socket path short on macOS.
            with tempfile.TemporaryDirectory(prefix="passd-ready-", dir="/tmp") as directory:
                state = Path(directory)
                exercise(state / "passd.sock", "readiness-dummy-master-" + uuid.uuid4().hex,
                         state=state, gateway=None)
    except Exception:
        print("FAIL readiness", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
