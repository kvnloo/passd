from __future__ import annotations

import json
import uuid
import zipfile
from pathlib import Path

from .client import PassdClient


def load_export(path: Path) -> dict:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith("data.json")]
            if not names:
                raise ValueError("Proton export ZIP does not contain data.json; encrypted PGP exports must be decrypted first")
            with zf.open(names[0]) as f:
                return json.load(f)
    return json.loads(path.read_text())


def map_fields(idata: dict) -> dict:
    content = idata.get("content") or {}
    typ = idata.get("type")
    fields = {}
    if typ == "login":
        mapping = {
            "username": content.get("itemUsername"),
            "email": content.get("itemEmail"),
            "password": content.get("password"),
            "totp": content.get("totpUri"),
        }
        fields.update({k: v for k, v in mapping.items() if v is not None})
    elif typ == "creditCard":
        mapping = {
            "cardholder_name": content.get("cardholderName"),
            "number": content.get("number"),
            "expiration_date": content.get("expirationDate"),
            "cvv": content.get("verificationNumber"),
            "pin": content.get("pin"),
        }
        fields.update({k: v for k, v in mapping.items() if v is not None})
    elif typ == "identity":
        fields.update({k: v for k, v in content.items() if v not in (None, "", [], {})})
    elif typ == "note":
        # Proton note content can vary by schema version; metadata note is handled separately.
        fields.update({k: v for k, v in content.items() if v not in (None, "", [], {})})
    else:
        fields.update({k: v for k, v in content.items() if v not in (None, "", [], {})})

    for extra in idata.get("extraFields") or []:
        data = extra.get("data") or {}
        value = data.get("content")
        if value is None:
            value = data.get("totpUri")
        if value is not None:
            fields[extra.get("fieldName") or "field"] = value
    return fields


def import_export(client: PassdClient, path: Path, *, admin_password: str) -> dict:
    data = load_export(path)
    imported = updated = skipped = 0
    for proton_vault_id, vault in (data.get("vaults") or {}).items():
        vault_name = vault.get("name") or "Imported"
        local_vault = client.call(
            "vault.create",
            {"name": vault_name, "description": vault.get("description") or "", "source": {"kind": "proton", "id": proton_vault_id}},
            admin_password=admin_password,
        )
        for item in vault.get("items") or []:
            if item.get("state", 1) != 1:
                skipped += 1
                continue
            idata = item.get("data") or {}
            meta = idata.get("metadata") or {}
            title = meta.get("name") or "Untitled"
            item_uuid = meta.get("itemUuid") or item.get("itemUuid") or item.get("id")
            if not item_uuid:
                item_uuid = str(uuid.uuid4())
            source_id = f"{proton_vault_id}:{item_uuid}"
            client.call(
                "item.put",
                {
                    "vault": local_vault["id"],
                    "title": title,
                    "type": idata.get("type") or "custom",
                    "fields": map_fields(idata),
                    "urls": (idata.get("content") or {}).get("urls") or [],
                    "note": meta.get("note") or "",
                    "source": {"kind": "proton", "id": source_id},
                    "proton_raw": item,
                },
                admin_password=admin_password,
            )
            imported += 1
    return {"imported_or_updated": imported, "skipped_trashed": skipped, "vaults": len(data.get("vaults") or {})}
