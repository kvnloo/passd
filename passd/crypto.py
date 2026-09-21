from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_root_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("master password must not be empty")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def random_key() -> bytes:
    return os.urandom(32)


@dataclass(frozen=True)
class Envelope:
    nonce: bytes
    ciphertext: bytes

    def dumps(self) -> str:
        return json.dumps({"v": 1, "n": b64e(self.nonce), "c": b64e(self.ciphertext)}, separators=(",", ":"))

    @classmethod
    def loads(cls, raw: str) -> "Envelope":
        obj = json.loads(raw)
        if obj.get("v") != 1:
            raise ValueError("unsupported encryption envelope version")
        return cls(b64d(obj["n"]), b64d(obj["c"]))


def seal(key: bytes, plaintext: bytes, *, aad: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return Envelope(nonce, ciphertext).dumps()


def open_sealed(key: bytes, envelope: str, *, aad: bytes) -> bytes:
    env = Envelope.loads(envelope)
    return AESGCM(key).decrypt(env.nonce, env.ciphertext, aad)


def seal_json(key: bytes, value: dict, *, aad: bytes) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return seal(key, raw, aad=aad)


def open_json(key: bytes, envelope: str, *, aad: bytes) -> dict:
    return json.loads(open_sealed(key, envelope, aad=aad).decode("utf-8"))
