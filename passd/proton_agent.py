from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .errors import (
    ProtonAgentAccessDenied, ProtonAgentAuthExpired, ProtonAgentDenial,
    ProtonAgentDisabled, ProtonAgentItemNotFound, ProtonAgentReasonRequired,
    ProtonAgentUnavailable, ValidationError,
)

PAT_NAME = "__proton_agent_pat__"
STATE_NAME = "__proton_agent_state__"


def validate_ref(ref: dict) -> dict[str, str]:
    if not isinstance(ref, dict):
        raise ValidationError("proton-agent ref must be an object")
    keys = set(ref)
    if keys not in ({"share_id", "item_id", "field"}, {"vault_name", "item_title", "field"}):
        raise ValidationError("proton-agent ref requires share_id/item_id/field or vault_name/item_title/field")
    if any(not isinstance(v, str) or not v.strip() or "\x00" in v or v.startswith("-") for v in ref.values()):
        raise ValidationError("proton-agent ref values must be nonempty strings without NUL or leading options")
    if PAT_NAME in ref.values() or STATE_NAME in ref.values():
        raise ValidationError("internal custody records cannot back capabilities")
    return dict(ref)


def _redact_stderr(stderr: bytes, *values: str) -> str:
    text = stderr.decode("utf-8", errors="replace")
    for value in values:
        if value:
            text = text.replace(value, "<redacted>")
    return text[:4096].lower()


def _classify(stderr: str) -> type[ProtonAgentDenial]:
    if re.search(r"reason.*(required|mandatory|missing)|(required|missing).*reason", stderr):
        return ProtonAgentReasonRequired
    if re.search(r"expired|unauthori[sz]ed|\b401\b|invalid (token|session)|session.*(stale|invalid)|not logged in", stderr):
        return ProtonAgentAuthExpired
    if re.search(r"forbidden|no access|access denied|denied access|permission|\b403\b|not granted", stderr):
        return ProtonAgentAccessDenied
    if re.search(r"not found|\b404\b|no item", stderr):
        return ProtonAgentItemNotFound
    return ProtonAgentUnavailable


class ProtonAgentSource:
    """An isolated agent session. Custody callbacks never expose PATs via RPC."""

    def __init__(
        self, state_dir: Path, *, binary: str = "pass-cli", agent_name: str = "passd-groot",
        get_pat: Callable[[], str | None], get_state: Callable[[], dict],
        set_state: Callable[[dict], None], alert: Callable[[dict], None],
        timeout: float = 20.0,
    ):
        self.state_dir = Path(state_dir).absolute()
        self.session_dir = self.state_dir / "session"
        self.binary = binary
        self.agent_name = agent_name
        self._get_pat = get_pat
        self._get_state = get_state
        self._set_state = set_state
        self._alert = alert
        self.timeout = float(timeout)
        if not 0 < self.timeout <= 60:
            raise ValidationError("proton-agent timeout must be >0 and <=60")
        self._lock = threading.RLock()

    def _prepare_session(self):
        for path in (self.state_dir, self.session_dir):
            try:
                path.mkdir(mode=0o700, exist_ok=True)
                info = path.lstat()
            except OSError:
                raise ProtonAgentUnavailable("cannot prepare isolated Proton agent session") from None
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ProtonAgentUnavailable("Proton agent session must be an owner-only directory owned by the current uid")

    def _environment(self) -> dict[str, str]:
        # Copy only PATH. All ambient PROTON_PASS_* and XDG settings are excluded.
        env = {
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.state_dir),
            "LANG": "C.UTF-8", "PROTON_PASS_SESSION_DIR": str(self.session_dir),
        }
        assert {k for k in env if k.startswith("PROTON_PASS_")} == {"PROTON_PASS_SESSION_DIR"}
        return env

    def _require_enabled(self):
        if self._get_state().get("disabled", False):
            raise ProtonAgentDisabled("Proton agent source is disabled")

    def _auth_expired(self, context: dict):
        try:
            self._alert({"source": "proton-agent", "severity": "alert", **context})
        except Exception:
            # Notification delivery must not replace the typed source denial.
            pass

    def _run(self, args: list[str], *, pat: str | None = None, reason: str | None = None, context: dict | None = None) -> bytes:
        self._prepare_session()
        env = self._environment()
        if pat is not None:
            assert args == ["login"]
            env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = pat
        if reason is not None:
            assert args[:2] == ["item", "view"]
            env["PROTON_PASS_AGENT_REASON"] = reason
        binary = shutil.which(self.binary, path=env["PATH"])
        if binary is None:
            raise ProtonAgentUnavailable("Proton agent executable is unavailable")
        try:
            cp = subprocess.run(
                [binary, *args], env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            # TimeoutExpired may carry partial secret output. Never chain it.
            raise ProtonAgentUnavailable("Proton agent process failed or timed out") from None
        finally:
            env.pop("PROTON_PASS_PERSONAL_ACCESS_TOKEN", None)
        if cp.returncode:
            returned = cp.stdout.decode("utf-8", errors="replace").removesuffix("\n")
            stderr = _redact_stderr(cp.stderr, pat or self._get_pat() or "", returned)
            denial = _classify(stderr)
            del returned, stderr, cp
            if denial is ProtonAgentAuthExpired:
                self._auth_expired(context or {})
            raise denial("Proton agent denied operation: " + denial.code)
        value = cp.stdout
        del cp
        return value

    def login(self) -> dict:
        with self._lock:
            self._require_enabled()
            pat = self._get_pat()
            if not pat:
                raise ProtonAgentUnavailable("Proton agent PAT is not set")
            try:
                self._run(["login"], pat=pat)
            finally:
                del pat
            state = self._get_state()
            state["last_login_time"] = int(time.time())
            self._set_state(state)
            return self.status(check_session=False)

    def status(self, *, check_session: bool = True) -> dict:
        with self._lock:
            state = self._get_state()
            out = {
                "agent_name": self.agent_name, "session_dir": str(self.session_dir),
                "pat_set": bool(self._get_pat()), "disabled": state.get("disabled", False),
                "last_login_time": state.get("last_login_time"), "expires_at": state.get("expires_at"),
            }
            if check_session and not out["disabled"]:
                try:
                    self._run(["info"])
                    out["session_ok"] = True
                except ProtonAgentDenial as exc:
                    out.update(session_ok=False, denial=exc.code)
            return out

    def logout(self) -> dict:
        with self._lock:
            self._run(["logout", "--force"])
            return self.status(check_session=False)

    def disable(self) -> dict:
        with self._lock:
            state = self._get_state()
            state["disabled"] = True
            self._set_state(state)
            try:
                self._run(["logout", "--force"])
            except ProtonAgentDenial:
                pass
            finally:
                # Never follow a replaced session symlink while wiping.
                try:
                    parent = self.state_dir.lstat()
                except FileNotFoundError:
                    parent = None
                if parent is not None:
                    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid():
                        raise ProtonAgentUnavailable("cannot safely wipe Proton agent session")
                    if self.session_dir.is_symlink():
                        self.session_dir.unlink()
                    elif self.session_dir.exists():
                        shutil.rmtree(self.session_dir)
            return self.status(check_session=False)

    def enable(self) -> dict:
        with self._lock:
            self._prepare_session()
            state = self._get_state()
            state["disabled"] = False
            self._set_state(state)
            return self.status(check_session=False)

    def resolve(self, capability_id: str, lease_id: str, ref: dict, *, purpose: str = "") -> str:
        with self._lock:
            self._require_enabled()
            ref = validate_ref(ref)
            if not capability_id or not lease_id:
                raise ProtonAgentReasonRequired("Proton agent requires capability and lease identifiers")

            def clean(value):
                return re.sub(r"[\x00-\x20\x7f-\x9f\u2028\u2029]+", " ", str(value)).strip()

            # Reserve room for both opaque identifiers before optional labels.
            reason = (
                f"passd capability={clean(capability_id)} lease={clean(lease_id)} "
                f"agent={clean(self.agent_name)[:40]} purpose={clean(purpose)[:80]}"
            )[:240]
            args = ["item", "view"]
            for key in ("share_id", "item_id", "vault_name", "item_title"):
                if key in ref:
                    args.extend(["--" + key.replace("_", "-"), ref[key]])
            args.extend(["--field", ref["field"], "--output", "human"])
            value = self._run(args, reason=reason, context={"capability_id": capability_id, "lease_id": lease_id})
            try:
                return value.removesuffix(b"\n").decode("utf-8")
            except UnicodeError:
                raise ProtonAgentUnavailable("Proton agent returned an invalid field encoding") from None
            finally:
                del value
