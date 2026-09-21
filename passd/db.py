from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA temp_store=MEMORY;

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    wrapped_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    source_kind TEXT,
    source_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(source_kind, source_id)
);
CREATE INDEX IF NOT EXISTS idx_vaults_source ON vaults(source_kind, source_id);

CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    wrapped_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    source_kind TEXT,
    source_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(source_kind, source_id)
);
CREATE INDEX IF NOT EXISTS idx_items_vault ON items(vault_id);

CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capabilities_updated ON capabilities(updated_at, id);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash BLOB NOT NULL,
    scopes_json TEXT NOT NULL,
    vault_ids_json TEXT NOT NULL,
    item_ids_json TEXT NOT NULL,
    allowed_hosts_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(name);

CREATE TABLE IF NOT EXISTS access_requests (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    target_host TEXT,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    item_id TEXT REFERENCES items(id) ON DELETE CASCADE,
    expires_at INTEGER,
    max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_access_agent_status ON access_requests(agent_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_access_item ON access_requests(agent_id, item_id, capability, target_host, status);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    agent_id TEXT,
    operation TEXT NOT NULL,
    vault_id TEXT,
    item_id TEXT,
    target TEXT,
    reason TEXT,
    allowed INTEGER NOT NULL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit(agent_id, ts DESC);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existed = path.exists()
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    conn.commit()
    if not existed:
        os.chmod(path, 0o600)
    return conn
