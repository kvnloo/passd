from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .crypto import b64d, b64e, derive_root_key, open_sealed, seal
from .errors import AuthError, Conflict, NotFound

ROOT_CHECK = b"passd-root-check-v1"
ROOT_CHECK_AAD = b"passd/config/root-check/v1"


def default_data_dir() -> Path:
    value = os.environ.get("PASSD_DATA_DIR")
    if value:
        return Path(value).expanduser()
    return Path.home() / ".local" / "share" / "passd"


@dataclass
class Config:
    data_dir: Path
    salt: bytes
    root_check: str

    @property
    def path(self) -> Path:
        return self.data_dir / "config.json"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "vault.sqlite3"

    @property
    def socket_path(self) -> Path:
        override = os.environ.get("PASSD_SOCKET")
        return Path(override).expanduser() if override else self.data_dir / "passd.sock"

    def derive_and_verify(self, password: str) -> bytes:
        key = derive_root_key(password, self.salt)
        try:
            value = open_sealed(key, self.root_check, aad=ROOT_CHECK_AAD)
        except Exception as exc:
            raise AuthError("invalid master password") from exc
        if value != ROOT_CHECK:
            raise AuthError("invalid master password")
        return key

    @classmethod
    def initialize(cls, data_dir: Path, password: str) -> "Config":
        data_dir = data_dir.expanduser().resolve()
        if (data_dir / "config.json").exists():
            raise Conflict(f"passd is already initialized at {data_dir}")
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(data_dir, 0o700)
        salt = os.urandom(16)
        root_key = derive_root_key(password, salt)
        check = seal(root_key, ROOT_CHECK, aad=ROOT_CHECK_AAD)
        cfg = cls(data_dir=data_dir, salt=salt, root_check=check)
        tmp = cfg.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "salt": b64e(salt), "root_check": check}, indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(cfg.path)
        return cfg

    @classmethod
    def load(cls, data_dir: Path | None = None) -> "Config":
        data_dir = (data_dir or default_data_dir()).expanduser().resolve()
        path = data_dir / "config.json"
        if not path.exists():
            raise NotFound(f"passd is not initialized at {data_dir}; run `passd init`")
        obj = json.loads(path.read_text())
        if obj.get("version") != 1:
            raise ValueError("unsupported passd config version")
        return cls(data_dir=data_dir, salt=b64d(obj["salt"]), root_check=obj["root_check"])
