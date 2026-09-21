from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

CAPABILITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def canonical_json(value: Any) -> str:
    """Stable UTF-8 JSON representation used only for version/digest material."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def keyed_version(root_key: bytes, domain: bytes, value: Any, *, prefix: str) -> str:
    material = domain + b"\x00" + canonical_json(value).encode("utf-8")
    digest = hmac.new(root_key, material, hashlib.sha256).hexdigest()
    return prefix + digest


def capability_version(root_key: bytes, definition: dict) -> str:
    return keyed_version(root_key, b"passd/capability/version/v1", definition, prefix="cv1_")


def item_version(root_key: bytes, payload: dict) -> str:
    return keyed_version(root_key, b"passd/item/version/v1", payload, prefix="iv1_")


def credential_version(root_key: bytes, *, item_id: str, field: str, value: Any) -> str:
    return keyed_version(
        root_key,
        b"passd/credential/version/v1",
        {"item_id": item_id, "field": field, "value": value},
        prefix="sv1_",
    )


def authority_digest(value: dict) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return "ad1_" + digest
