from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import subprocess
import tempfile
import time

from .errors import PassdError

LOGIN_URL = re.compile(rb"https://account\.proton\.me/desktop/login\?app=pass#payload=[A-Za-z0-9%_-]+")
ENTITLEMENT_REFUSAL = b"not yet allowed to use our cli"
PAT_FORMAT = re.compile(r"pst_[^\s:]+::[^\s:]+")
JSON_OUTPUT = ("--output", "json")


class EnrollmentError(PassdError):
    code = "proton_enrollment_failed"


class StockProtonRunner:
    def __init__(self, binary: str = "pass-cli"):
        self.binary = shutil.which(binary)
        if self.binary is None:
            raise EnrollmentError("Install the stock Proton pass-cli and put it on the trusted PATH.")

    def __call__(self, args, env, *, login_url=None) -> bytes:
        try:
            if login_url is not None:
                self._login(env, login_url)
                return b""
            result = subprocess.run(
                [self.binary, *args], env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            # TimeoutExpired may retain bytes from a partially completed create.
            pass
        else:
            if result.returncode == 0:
                return result.stdout
            del result
            raise EnrollmentError("Proton CLI operation failed. Check the owner account and retry.")
        raise EnrollmentError("Proton CLI could not complete the requested operation.")

    def _login(self, env, show_url):
        deadline = time.monotonic() + 660
        shown = refused = False
        pending = b""
        with subprocess.Popen(
            [self.binary, "login"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        ) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while selector.select(max(0, deadline - time.monotonic())):
                        chunk = os.read(child.stdout.fileno(), 4096)
                        if not chunk:
                            break
                        lines = (pending + chunk).split(b"\n")
                        pending = lines.pop()[-8192:]
                        for line in lines:
                            refused |= ENTITLEMENT_REFUSAL in line.lower()
                            if not shown and LOGIN_URL.fullmatch(line.strip()):
                                show_url(line.strip().decode("ascii"))
                                shown = True
                    status = child.wait(timeout=max(0, deadline - time.monotonic()))
            finally:
                if child.poll() is None:
                    child.kill()
        if status != 0 or not shown or refused or ENTITLEMENT_REFUSAL in pending.lower():
            raise EnrollmentError(
                "Proton CLI login or entitlement failed. Confirm this account has CLI access with Proton before retrying."
            )


def _decode(raw):
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        del raw
    raise EnrollmentError("Proton CLI returned invalid JSON.")


def _named_entries(rows, name):
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]
        for row in rows
    ):
        raise EnrollmentError("Proton CLI returned an invalid inventory.")
    return [row for row in rows if row["name"] == name]


def enroll_proton(client, admin_password: str, *, runner, show_url) -> None:
    """Enroll using a stock CLI runner and the existing local custody RPCs."""
    if client.remote:
        raise EnrollmentError("Proton enrollment requires the local owner admin socket.")

    def broker(operation, message, params=None):
        try:
            return client.call("proton-agent." + operation, params, admin_password=admin_password)
        except Exception:
            del params
        raise EnrollmentError(message)

    status = broker("status", "Cannot inspect the local Proton broker. Check the socket and master password.")
    name = status.get("agent_name", "")
    if not isinstance(name, str) or not re.fullmatch(r"passd-[a-z0-9][a-z0-9-]*", name):
        raise EnrollmentError("Configure the broker agent name as passd-<host> before enrolling.")

    with tempfile.TemporaryDirectory(prefix="proton-enroll-") as directory:
        # Give the filesystem key provider and alternate config paths the same
        # lifetime as the owner session.
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": directory,
            "LANG": "C.UTF-8",
            "PROTON_PASS_SESSION_DIR": directory,
            "PROTON_PASS_KEY_PROVIDER": "fs",
        }

        def run(*args):
            return runner(args, env)

        def agents_vaults():
            inventory = _decode(run("vault", "list", *JSON_OUTPUT))
            return _named_entries(inventory.get("vaults") if isinstance(inventory, dict) else None, "agents")

        def named_agents():
            return _named_entries(_decode(run("agent", "list", *JSON_OUTPUT)), name)

        created = False
        verified = False
        try:
            try:
                runner(("login",), env, login_url=show_url)
            except EnrollmentError:
                raise EnrollmentError(
                    "Proton CLI login or entitlement failed. Confirm this account has CLI access with Proton before retrying."
                ) from None
            vaults = agents_vaults()
            if not vaults:
                run("vault", "create", "--name", "agents")
                vaults = agents_vaults()
            share_id = vaults[0].get("share_id") if len(vaults) == 1 else None
            if not isinstance(share_id, str) or not share_id.strip():
                raise EnrollmentError("Expected exactly one agents vault with a valid share ID.")
            if named_agents():
                raise EnrollmentError("This Proton agent already exists. Follow the renewal or deletion procedure.")

            broker("disable", "Cannot disable the local Proton source. Check broker access before retrying.")
            # Stock agent create always emits JSON. Arm revocation before the
            # call because the remote create can succeed before JSON is written.
            created = True
            response = _decode(run("agent", "create", name, "--expiration", "1w", "--vault", "agents"))
            token = response.get("token") if isinstance(response, dict) else None
            del response
            if isinstance(token, str):
                token = token.removeprefix("PROTON_PASS_PERSONAL_ACCESS_TOKEN=")
            try:
                if not isinstance(token, str) or not PAT_FORMAT.fullmatch(token):
                    raise EnrollmentError("Proton CLI did not return a valid agent token.")
                handoff = broker("set-pat", "Proton token custody transfer failed.", {"pat": token})
                if handoff != {"pat_set": True}:
                    raise EnrollmentError("Proton token custody transfer was not confirmed.")
            finally:
                del token

            agents = named_agents()
            pat_id = agents[0].get("pat_id") if len(agents) == 1 else None
            if not isinstance(pat_id, str) or not pat_id or pat_id.startswith("-"):
                raise EnrollmentError("Could not identify exactly one newly created Proton agent.")
            grants = _decode(run("pat", "access", "list-access", "--pat-id", pat_id, *JSON_OUTPUT))
            expected = {"type": "vault", "vault_name": "agents", "share_id": share_id, "role": "Viewer"}
            if (
                not isinstance(grants, list) or len(grants) != 1 or not isinstance(grants[0], dict)
                or grants[0].keys() - (expected.keys() | {"expire_time"})
                or any(grants[0].get(key) != value for key, value in expected.items())
            ):
                raise EnrollmentError("Expected exactly one agents vault viewer grant.")
            verified = True
        finally:
            try:
                if created and not verified:
                    try:
                        run("agent", "delete", name)
                    except EnrollmentError:
                        raise EnrollmentError(
                            "Enrollment failed and revocation was unconfirmed. Revoke the new agent in Proton."
                        ) from None
            finally:
                try:
                    run("logout", "--force")
                except EnrollmentError:
                    message = "Owner logout was unconfirmed. Verify session revocation in Proton."
                    if created:
                        message += " Confirm the new agent is revoked before retrying."
                    raise EnrollmentError(message) from None

    ready = False
    try:
        failure = "Broker session verification failed. Revoke the new agent from a fresh trusted Proton owner session."
        broker("enable", failure)
        broker("login", failure)
        if broker("status", failure).get("session_ok") is not True:
            raise EnrollmentError(failure)
        ready = True
    finally:
        if not ready:
            broker("disable", "Broker disable was unconfirmed. Disable the local source and revoke the new agent in Proton.")
