//! Hash-chained audit ledger (`docs/adr/0004-hash-chained-audit-ledger.md`).
//!
//! Record *n* commits to `hash(n-1)`. The genesis predecessor is 32 zero
//! bytes. Fields are length-prefixed before hashing so no two distinct
//! records can encode to the same bytes.

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::Result;

/// SHA-256 output length.
pub const HASH_LEN: usize = 32;

/// One ledger record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Sequence number, starting at 1.
    pub n: u64,
    /// Unix seconds.
    pub ts: i64,
    /// Who: `human:<session>`, `token:<id>`, or `system`.
    pub actor: String,
    /// What: `vault_created`, `unseal`, `seal`, `item_created`,
    /// `version_added`, `secret_read`, `search`, …
    pub action: String,
    /// Opaque item id when applicable.
    pub subject: Option<String>,
    /// `ok`, `denied`, `error`.
    pub outcome: String,
    /// JSON object with action-specific detail (never secret material).
    pub meta: String,
    /// Hash of the previous record.
    pub prev_hash: [u8; HASH_LEN],
    /// This record's hash.
    pub hash: [u8; HASH_LEN],
}

/// Result of walking the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
    /// Every record's hash recomputes and links to its predecessor.
    Intact {
        /// Number of records.
        len: u64,
        /// Hash of the last record; anchor this outside the vault.
        head: [u8; HASH_LEN],
    },
    /// Verification failed at this record.
    Broken {
        /// First record that did not verify.
        at: u64,
    },
}

fn push(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_le_bytes());
    h.update(bytes);
}

/// Compute the hash a record with these fields must carry.
///
/// The fields are spelled out rather than bundled into a struct so that the
/// exact set of bytes committed to the chain is visible at the call site.
#[allow(clippy::too_many_arguments)]
pub fn compute_hash(
    n: u64,
    ts: i64,
    actor: &str,
    action: &str,
    subject: Option<&str>,
    outcome: &str,
    meta: &str,
    prev_hash: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    push(&mut h, b"bsc-audit/1");
    h.update(n.to_le_bytes());
    h.update(ts.to_le_bytes());
    push(&mut h, actor.as_bytes());
    push(&mut h, action.as_bytes());
    match subject {
        Some(s) => {
            h.update([1u8]);
            push(&mut h, s.as_bytes());
        }
        None => h.update([0u8]),
    }
    push(&mut h, outcome.as_bytes());
    push(&mut h, meta.as_bytes());
    h.update(prev_hash);
    h.finalize().into()
}

fn head(conn: &Connection) -> Result<(u64, [u8; HASH_LEN])> {
    let row: Option<(u64, Vec<u8>)> = conn
        .query_row(
            "SELECT n, hash FROM audit ORDER BY n DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((n, h)) => {
            let mut hash = [0u8; HASH_LEN];
            hash.copy_from_slice(&h);
            (n, hash)
        }
        None => (0, [0u8; HASH_LEN]),
    })
}

/// Append a record. Must run inside the caller's transaction so that the
/// audit write and the operation it describes commit or fail together.
pub(crate) fn append(
    conn: &Connection,
    ts: i64,
    actor: &str,
    action: &str,
    subject: Option<&str>,
    outcome: &str,
    meta: &str,
) -> Result<u64> {
    let (prev_n, prev_hash) = head(conn)?;
    let n = prev_n + 1;
    let hash = compute_hash(n, ts, actor, action, subject, outcome, meta, &prev_hash);
    conn.execute(
        "INSERT INTO audit (n, ts, actor, action, subject, outcome, meta, prev_hash, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            n,
            ts,
            actor,
            action,
            subject,
            outcome,
            meta,
            prev_hash.as_slice(),
            hash.as_slice()
        ],
    )?;
    Ok(n)
}

/// Walk the whole chain and recompute every hash.
pub fn verify(conn: &Connection) -> Result<ChainStatus> {
    let mut stmt = conn.prepare(
        "SELECT n, ts, actor, action, subject, outcome, meta, prev_hash, hash
         FROM audit ORDER BY n ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut expected_n: u64 = 1;
    let mut expected_prev = [0u8; HASH_LEN];
    let mut len = 0u64;
    while let Some(row) = rows.next()? {
        let n: u64 = row.get(0)?;
        let ts: i64 = row.get(1)?;
        let actor: String = row.get(2)?;
        let action: String = row.get(3)?;
        let subject: Option<String> = row.get(4)?;
        let outcome: String = row.get(5)?;
        let meta: String = row.get(6)?;
        let prev: Vec<u8> = row.get(7)?;
        let hash: Vec<u8> = row.get(8)?;

        if n != expected_n || prev.as_slice() != expected_prev.as_slice() {
            return Ok(ChainStatus::Broken { at: n });
        }
        let want = compute_hash(
            n,
            ts,
            &actor,
            &action,
            subject.as_deref(),
            &outcome,
            &meta,
            &expected_prev,
        );
        if hash.as_slice() != want.as_slice() {
            return Ok(ChainStatus::Broken { at: n });
        }
        expected_prev = want;
        expected_n += 1;
        len = n;
    }
    Ok(ChainStatus::Intact {
        len,
        head: expected_prev,
    })
}

/// Read records in `[from, from+limit)` for display.
pub fn read(conn: &Connection, from: u64, limit: u64) -> Result<Vec<AuditRecord>> {
    read_where(conn, "n >= ?1", params![from, limit], from, limit)
}

/// Records about one subject (an item, token, or session id), newest last.
pub fn read_subject(
    conn: &Connection,
    subject: &str,
    from: u64,
    limit: u64,
) -> Result<Vec<AuditRecord>> {
    let mut stmt = conn.prepare(
        "SELECT n, ts, actor, action, subject, outcome, meta, prev_hash, hash
         FROM audit WHERE subject = ?1 AND n >= ?2 ORDER BY n ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![subject, from, limit], row_to_record)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn read_where(
    conn: &Connection,
    cond: &str,
    p: impl rusqlite::Params,
    _from: u64,
    _limit: u64,
) -> Result<Vec<AuditRecord>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT n, ts, actor, action, subject, outcome, meta, prev_hash, hash
         FROM audit WHERE {cond} ORDER BY n ASC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(p, row_to_record)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    {
        let prev: Vec<u8> = row.get(7)?;
        let hash: Vec<u8> = row.get(8)?;
        let mut p = [0u8; HASH_LEN];
        let mut h = [0u8; HASH_LEN];
        p.copy_from_slice(&prev);
        h.copy_from_slice(&hash);
        Ok(AuditRecord {
            n: row.get(0)?,
            ts: row.get(1)?,
            actor: row.get(2)?,
            action: row.get(3)?,
            subject: row.get(4)?,
            outcome: row.get(5)?,
            meta: row.get(6)?,
            prev_hash: p,
            hash: h,
        })
    }
}
