from __future__ import annotations

from urllib.parse import unquote, urlsplit

from .errors import ValidationError


def parse_pass_ref(value: str) -> tuple[str, str, str | None]:
    if not value.startswith("pass://"):
        raise ValidationError("secret reference must start with pass://")
    parsed = urlsplit(value)
    vault = unquote(parsed.netloc)
    parts = [unquote(p) for p in parsed.path.split("/") if p]
    if not vault or not parts:
        raise ValidationError("secret reference must be pass://VAULT/ITEM[/FIELD]")
    item = parts[0]
    field = "/".join(parts[1:]) if len(parts) > 1 else None
    return vault, item, field
