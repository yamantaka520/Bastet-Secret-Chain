//! SQLite schema. Version 1.

pub const SCHEMA_VERSION: i64 = 1;

pub const CREATE: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One row per item. Anything sensitive is a Sealed blob; the clear columns
-- are what the UI may show for a sealed vault.
CREATE TABLE IF NOT EXISTS item (
    id                TEXT PRIMARY KEY,
    item_type         TEXT NOT NULL,
    env               TEXT,
    created           INTEGER NOT NULL,
    updated           INTEGER NOT NULL,
    expires_at        INTEGER,
    approval_required INTEGER NOT NULL,
    current_version   INTEGER NOT NULL,
    path_ct           BLOB NOT NULL,
    name_ct           BLOB NOT NULL,
    tags_ct           BLOB NOT NULL
);

-- Append-only per item. The body is under a per-version DEK, itself wrapped
-- by the KEK; the wrap and the body both bind (item id, n).
CREATE TABLE IF NOT EXISTS version (
    item_id     TEXT NOT NULL REFERENCES item(id) ON DELETE CASCADE,
    n           INTEGER NOT NULL,
    wrapped_dek BLOB NOT NULL,
    body_ct     BLOB NOT NULL,
    size        INTEGER NOT NULL,
    created     INTEGER NOT NULL,
    note_ct     BLOB,
    PRIMARY KEY (item_id, n)
);

-- Blind index: keyed token hashes over name, path, and tags.
CREATE TABLE IF NOT EXISTS blind_index (
    item_id TEXT NOT NULL REFERENCES item(id) ON DELETE CASCADE,
    field   TEXT NOT NULL,
    tag     BLOB NOT NULL,
    PRIMARY KEY (item_id, field, tag)
);
CREATE INDEX IF NOT EXISTS blind_index_tag ON blind_index(tag);

-- Hash-chained ledger. Deliberately in the clear so it can be verified while
-- the vault is sealed; subjects are opaque item ids, never names.
CREATE TABLE IF NOT EXISTS audit (
    n         INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    subject   TEXT,
    outcome   TEXT NOT NULL,
    meta      TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
);
"#;
