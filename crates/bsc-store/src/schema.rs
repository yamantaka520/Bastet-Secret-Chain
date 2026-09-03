//! SQLite schema. Version 1.
//!
//! Pre-release: until the first tagged release, the schema may change without
//! a migration and existing test vaults are simply recreated.

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
    local_approval_only INTEGER NOT NULL DEFAULT 0,
    use_ct            BLOB,
    rotation_days     INTEGER,
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

-- Agent bearer tokens. Only a hash of the value is kept. Label and scope are
-- Sealed blobs: scope paths would otherwise leak the item hierarchy.
CREATE TABLE IF NOT EXISTS token (
    id                 TEXT PRIMARY KEY,
    hash               BLOB NOT NULL UNIQUE,
    label_ct           BLOB NOT NULL,
    scope_ct           BLOB NOT NULL,
    created            INTEGER NOT NULL,
    lifetime           INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    max_lifetime_until INTEGER NOT NULL,
    max_reads          INTEGER,
    reads_used         INTEGER NOT NULL DEFAULT 0,
    rate_limit_per_min INTEGER NOT NULL,
    created_by         TEXT NOT NULL,
    revoked_at         INTEGER
);

-- Task sessions (ADR 0005 §1). Never renewed; closing early sets closed_at.
CREATE TABLE IF NOT EXISTS session (
    id         TEXT PRIMARY KEY,
    scope_ct   BLOB NOT NULL,
    opened     INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    closed_at  INTEGER,
    opened_by  TEXT NOT NULL
);

-- Pending / decided approval requests (ADR 0005 §2–3). Deliberately no
-- foreign key on item_id: an approval is history and must outlive the item
-- it was about (items can be deleted; approvals, like the ledger, are not).
CREATE TABLE IF NOT EXISTS approval (
    id           TEXT PRIMARY KEY,
    token_id     TEXT NOT NULL REFERENCES token(id),
    item_id      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    status       TEXT NOT NULL,
    decided_at   INTEGER,
    decided_by   TEXT,
    consumed_at  INTEGER,
    escalation   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS approval_pending ON approval(status, expires_at);

-- Trust-on-first-use grants: an approved (token, item) pair reads without a
-- prompt until expires_at.
CREATE TABLE IF NOT EXISTS access_grant (
    token_id    TEXT NOT NULL REFERENCES token(id),
    item_id     TEXT NOT NULL REFERENCES item(id) ON DELETE CASCADE,
    approval_id TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (token_id, item_id)
);
"#;
