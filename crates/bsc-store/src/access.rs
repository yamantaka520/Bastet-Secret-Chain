//! Agent tokens, task sessions, approvals, and grants.
//!
//! Policy that must be atomic with the ledger lives here; policy that is
//! purely about the current request (rate limiting, HTTP shape) lives in the
//! daemon. Time is always taken from the vault clock so tests can move it.
//!
//! Design authority: `docs/adr/0005-approval-and-reminder-model.md`,
//! `docs/API_CONTRACT.md` §1, §5, §6.

use base64::Engine as _;
use bsc_crypto::envelope::{self, Aad, Sealed};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    audit,
    vault::{hex_id, random_bytes, Actor, Vault},
    Result, StoreError,
};

/// What a token or session may reach. An item is in scope if its path equals
/// a `paths` entry or lies beneath one, **or** it carries any `tags` entry.
/// An empty scope covers nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Path prefixes, matched on segment boundaries.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Tags, any of which matches.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Scope {
    /// A scope entry as a bare prefix. People write `prod/gcp/*`, `prod/gcp/`
    /// or `prod/gcp` and mean the same subtree; only the last form is what
    /// the matcher wants. Keeps a lone `*` meaning "everything".
    pub fn normalize_prefix(p: &str) -> &str {
        let t = p.trim().trim_end_matches('/');
        if t == "*" {
            return "";
        }
        t.trim_end_matches('*').trim_end_matches('/')
    }

    /// Whether an item with this path and these tags is covered.
    pub fn covers(&self, path: &str, tags: &[String]) -> bool {
        let path_hit = self.paths.iter().any(|raw| {
            let p = Self::normalize_prefix(raw);
            if p.is_empty() {
                // A bare `*` (or `/`) was written: everything is in scope.
                return raw.trim().trim_end_matches('/') == "*";
            }
            path == p || path.starts_with(p) && path[p.len()..].starts_with('/')
        });
        let tag_hit = self.tags.iter().any(|t| tags.iter().any(|it| it == t));
        path_hit || tag_hit
    }

    /// Whether this scope is entirely inside `outer`: every path prefix here
    /// is covered by `outer`, and every tag here appears in `outer`.
    pub fn within(&self, outer: &Scope) -> bool {
        self.paths
            .iter()
            .all(|p| outer.covers(Self::normalize_prefix(p), &[]))
            && self.tags.iter().all(|t| outer.tags.contains(t))
    }
}

/// Input for minting a token.
#[derive(Clone, Debug)]
pub struct NewToken {
    /// Human label, encrypted at rest.
    pub label: String,
    /// What the token may read.
    pub scope: Scope,
    /// Seconds until expiry. Renewal extends by this amount.
    pub lifetime: i64,
    /// Hard cap on total lifetime through renewals, seconds from mint.
    pub max_lifetime: i64,
    /// Total reads allowed; `None` is unlimited.
    pub max_reads: Option<u32>,
    /// Requests per minute the daemon should allow.
    pub rate_limit_per_min: u32,
}

/// A token as stored. `label` and `scope` are `None` while the vault is sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecord {
    /// `tok_…`, safe to log.
    pub id: String,
    /// Decrypted label, if unsealed.
    pub label: Option<String>,
    /// Decrypted scope, if unsealed.
    pub scope: Option<Scope>,
    /// Unix seconds.
    pub created: i64,
    /// Seconds; the renewal increment.
    pub lifetime: i64,
    /// Unix seconds.
    pub expires_at: i64,
    /// Renewals cannot push `expires_at` past this.
    pub max_lifetime_until: i64,
    /// Read cap.
    pub max_reads: Option<u32>,
    /// Reads consumed so far.
    pub reads_used: u32,
    /// Per-minute limit for the daemon to enforce.
    pub rate_limit_per_min: u32,
    /// Actor label that minted it.
    pub created_by: String,
    /// Unix seconds, if revoked.
    pub revoked_at: Option<i64>,
}

impl TokenRecord {
    /// Grace after expiry during which renewal is still allowed.
    pub const RENEWAL_GRACE: i64 = 5 * 60;

    /// Whether the token may be used to read right now.
    pub fn is_live(&self, now: i64) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    /// `now ≥ expires_at − 25 % × lifetime` and `now ≤ expires_at + grace`
    /// (API contract §5).
    pub fn is_renewable(&self, now: i64) -> bool {
        self.revoked_at.is_none()
            && now >= self.expires_at - self.lifetime / 4
            && now <= self.expires_at + Self::RENEWAL_GRACE
            && self.expires_at < self.max_lifetime_until
    }

    /// Reads left, if capped.
    pub fn reads_remaining(&self) -> Option<u32> {
        self.max_reads.map(|m| m.saturating_sub(self.reads_used))
    }
}

/// A freshly minted token: the record plus the value, which is shown once.
pub struct MintedToken {
    /// Stored record.
    pub record: TokenRecord,
    /// `bsct_…`. Zeroized on drop; the store keeps only its hash.
    pub value: Zeroizing<String>,
}

/// An open or closed task session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// `ses_…`.
    pub id: String,
    /// Decrypted scope, if unsealed.
    pub scope: Option<Scope>,
    /// Unix seconds.
    pub opened: i64,
    /// Unix seconds.
    pub expires_at: i64,
    /// Unix seconds, if ended early.
    pub closed_at: Option<i64>,
    /// Actor label.
    pub opened_by: String,
}

impl SessionRecord {
    /// Longest permitted window, seconds (8 h).
    pub const MAX_DURATION: i64 = 8 * 3600;

    /// Open right now.
    pub fn is_active(&self, now: i64) -> bool {
        self.closed_at.is_none() && now < self.expires_at
    }
}

/// A live trust-on-first-use or pre-authorized grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRecord {
    /// Token that may read without a prompt.
    pub token_id: String,
    /// Item it may read.
    pub item_id: String,
    /// `apr_…` that created it, or `"pre"` for pre-authorization.
    pub approval_id: String,
    /// Unix seconds.
    pub expires_at: i64,
}

/// Approval lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Waiting for a human.
    Pending,
    /// Approved; a grant exists.
    Approved,
    /// Human said no.
    Denied,
    /// Nobody answered in time.
    Timeout,
}

impl ApprovalStatus {
    /// Storage / wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Timeout => "timeout",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "pending" => ApprovalStatus::Pending,
            "approved" => ApprovalStatus::Approved,
            "denied" => ApprovalStatus::Denied,
            "timeout" => ApprovalStatus::Timeout,
            _ => return Err(StoreError::Format(format!("bad approval status {s:?}"))),
        })
    }
}

/// One approval request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// `apr_…`.
    pub id: String,
    /// Requesting token.
    pub token_id: String,
    /// Item asked for.
    pub item_id: String,
    /// Agent-stated reason, verbatim.
    pub reason: String,
    /// Unix seconds.
    pub requested_at: i64,
    /// Auto-deny deadline.
    pub expires_at: i64,
    /// Current state.
    pub status: ApprovalStatus,
    /// Unix seconds.
    pub decided_at: Option<i64>,
    /// Actor label.
    pub decided_by: Option<String>,
    /// Set when the approved value was handed over through the poll once.
    pub consumed_at: Option<i64>,
    /// Highest escalation step already recorded.
    pub escalation: u32,
}

fn hash_token(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn scope_aad<'a>(id: &'a str, field: &'a str) -> Aad<'a> {
    Aad {
        item_id: id,
        version: 0,
        field,
    }
}

impl Vault {
    fn open_string(&self, id: &str, field: &str, ct: &[u8]) -> Result<Option<String>> {
        let Ok((kek, _)) = self.keys() else {
            return Ok(None);
        };
        let pt = envelope::open_field(kek, &scope_aad(id, field), &Sealed::from_slice(ct)?)?;
        Ok(Some(String::from_utf8(pt.to_vec()).map_err(|_| {
            StoreError::Format("field not utf-8".into())
        })?))
    }

    fn open_scope(&self, id: &str, ct: &[u8]) -> Result<Option<Scope>> {
        match self.open_string(id, "scope", ct)? {
            Some(s) => {
                Ok(Some(serde_json::from_str(&s).map_err(|_| {
                    StoreError::Format("scope not JSON".into())
                })?))
            }
            None => Ok(None),
        }
    }

    // ------------------------------------------------------------ tokens

    /// Mint a scoped token. Requires an unsealed vault because the label and
    /// scope are encrypted. The value is returned exactly once.
    pub fn mint_token(&mut self, new: NewToken, actor: &Actor) -> Result<MintedToken> {
        if new.lifetime <= 0 || new.max_lifetime < new.lifetime {
            return Err(StoreError::Invalid("token lifetime out of range"));
        }
        if new.label.trim().is_empty() {
            return Err(StoreError::Invalid("empty token label"));
        }
        if new.scope.paths.is_empty() && new.scope.tags.is_empty() {
            return Err(StoreError::Invalid("empty scope"));
        }
        let (kek, _) = self.keys()?;
        let id = hex_id("tok")?;
        let value = Zeroizing::new(format!(
            "bsct_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>()?)
        ));
        let hash = hash_token(&value);
        let now = self.now();
        let label_ct = envelope::seal_field(kek, &scope_aad(&id, "label"), new.label.as_bytes())?;
        let scope_json = serde_json::to_string(&new.scope)
            .map_err(|_| StoreError::Invalid("scope not serializable"))?;
        let scope_ct = envelope::seal_field(kek, &scope_aad(&id, "scope"), scope_json.as_bytes())?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO token (id, hash, label_ct, scope_ct, created, lifetime, expires_at,
                                max_lifetime_until, max_reads, reads_used, rate_limit_per_min,
                                created_by, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, NULL)",
            params![
                id,
                hash.as_slice(),
                label_ct.to_vec(),
                scope_ct.to_vec(),
                now,
                new.lifetime,
                now + new.lifetime,
                now + new.max_lifetime,
                new.max_reads,
                new.rate_limit_per_min,
                actor.label(),
            ],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "token_minted",
            Some(&id),
            "ok",
            &serde_json::json!({
                "lifetime": new.lifetime,
                "max_lifetime": new.max_lifetime,
                "max_reads": new.max_reads,
                "rate_limit_per_min": new.rate_limit_per_min,
                "scope_paths": new.scope.paths.len(),
                "scope_tags": new.scope.tags.len(),
            })
            .to_string(),
        )?;
        tx.commit()?;
        let record = self.token(&id)?;
        Ok(MintedToken { record, value })
    }

    fn token_from_row(&self, row: &rusqlite::Row<'_>) -> Result<TokenRecord> {
        let id: String = row.get(0)?;
        let label_ct: Vec<u8> = row.get(1)?;
        let scope_ct: Vec<u8> = row.get(2)?;
        Ok(TokenRecord {
            label: self.open_string(&id, "label", &label_ct)?,
            scope: self.open_scope(&id, &scope_ct)?,
            id,
            created: row.get(3)?,
            lifetime: row.get(4)?,
            expires_at: row.get(5)?,
            max_lifetime_until: row.get(6)?,
            max_reads: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            reads_used: row.get::<_, i64>(8)? as u32,
            rate_limit_per_min: row.get::<_, i64>(9)? as u32,
            created_by: row.get(10)?,
            revoked_at: row.get(11)?,
        })
    }

    const TOKEN_SELECT: &'static str = "SELECT id, label_ct, scope_ct, created, lifetime, expires_at,
                max_lifetime_until, max_reads, reads_used, rate_limit_per_min, created_by, revoked_at
         FROM token";

    /// Look a token up by its id.
    pub fn token(&self, id: &str) -> Result<TokenRecord> {
        let mut stmt = self
            .conn
            .prepare(&format!("{} WHERE id = ?1", Self::TOKEN_SELECT))?;
        let mut rows = stmt.query([id])?;
        match rows.next()? {
            Some(row) => self.token_from_row(row),
            None => Err(StoreError::NotFound),
        }
    }

    /// Look a token up by its presented value. Constant-time on the hash
    /// comparison is unnecessary: the hash is a random-looking 256-bit key
    /// into a unique index, so a lookup miss leaks nothing usable.
    pub fn token_by_value(&self, value: &str) -> Result<Option<TokenRecord>> {
        let hash = hash_token(value);
        let mut stmt = self
            .conn
            .prepare(&format!("{} WHERE hash = ?1", Self::TOKEN_SELECT))?;
        let mut rows = stmt.query([hash.as_slice()])?;
        match rows.next()? {
            Some(row) => Ok(Some(self.token_from_row(row)?)),
            None => Ok(None),
        }
    }

    /// Every token, newest first.
    pub fn list_tokens(&self) -> Result<Vec<TokenRecord>> {
        let mut stmt = self
            .conn
            .prepare(&format!("{} ORDER BY created DESC, id", Self::TOKEN_SELECT))?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(self.token_from_row(row)?);
        }
        Ok(out)
    }

    /// Revoke. Idempotent; a second revoke is not an error and not a record.
    pub fn revoke_token(&mut self, id: &str, actor: &Actor) -> Result<TokenRecord> {
        let t = self.token(id)?;
        if t.revoked_at.is_some() {
            return Ok(t);
        }
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE token SET revoked_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "token_revoked",
            Some(id),
            "ok",
            "{}",
        )?;
        tx.commit()?;
        self.token(id)
    }

    /// Extend a token inside its renewal window (API contract §5). Never
    /// widens scope, never changes the value, never passes `max_lifetime_until`.
    pub fn renew_token(&mut self, id: &str, actor: &Actor) -> Result<TokenRecord> {
        let t = self.token(id)?;
        let now = self.now();
        if !t.is_renewable(now) {
            self.audit_now(
                actor,
                "token_renewed",
                Some(id),
                "denied",
                serde_json::json!({ "expires_at": t.expires_at, "max_lifetime_until": t.max_lifetime_until }),
            )?;
            return Err(StoreError::Invalid("token not renewable"));
        }
        let new_expiry = (t.expires_at + t.lifetime).min(t.max_lifetime_until);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE token SET expires_at = ?2 WHERE id = ?1",
            params![id, new_expiry],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "token_renewed",
            Some(id),
            "ok",
            &serde_json::json!({ "from": t.expires_at, "to": new_expiry }).to_string(),
        )?;
        tx.commit()?;
        self.token(id)
    }

    /// Count one read against the token's quota. Returns reads remaining, or
    /// `None` if uncapped. Refuses when the cap is already spent.
    pub fn consume_read(&mut self, id: &str) -> Result<Option<u32>> {
        let t = self.token(id)?;
        if let Some(rem) = t.reads_remaining() {
            if rem == 0 {
                return Err(StoreError::Invalid("read quota exhausted"));
            }
        }
        self.conn.execute(
            "UPDATE token SET reads_used = reads_used + 1 WHERE id = ?1",
            [id],
        )?;
        Ok(t.reads_remaining().map(|r| r - 1))
    }

    // ---------------------------------------------------------- sessions

    /// Open a task session (ADR 0005 §1). Requires an unsealed vault.
    pub fn open_session(
        &mut self,
        scope: Scope,
        duration: i64,
        actor: &Actor,
    ) -> Result<SessionRecord> {
        if duration <= 0 || duration > SessionRecord::MAX_DURATION {
            return Err(StoreError::Invalid("session duration out of range"));
        }
        if scope.paths.is_empty() && scope.tags.is_empty() {
            return Err(StoreError::Invalid("empty scope"));
        }
        let (kek, _) = self.keys()?;
        let id = hex_id("ses")?;
        let now = self.now();
        let scope_json = serde_json::to_string(&scope)
            .map_err(|_| StoreError::Invalid("scope not serializable"))?;
        let scope_ct = envelope::seal_field(kek, &scope_aad(&id, "scope"), scope_json.as_bytes())?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO session (id, scope_ct, opened, expires_at, closed_at, opened_by)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![id, scope_ct.to_vec(), now, now + duration, actor.label()],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "session_opened",
            Some(&id),
            "ok",
            &serde_json::json!({ "duration": duration, "scope_paths": scope.paths.len(), "scope_tags": scope.tags.len() }).to_string(),
        )?;
        tx.commit()?;
        self.session(&id)
    }

    fn session_from_row(&self, row: &rusqlite::Row<'_>) -> Result<SessionRecord> {
        let id: String = row.get(0)?;
        let scope_ct: Vec<u8> = row.get(1)?;
        Ok(SessionRecord {
            scope: self.open_scope(&id, &scope_ct)?,
            id,
            opened: row.get(2)?,
            expires_at: row.get(3)?,
            closed_at: row.get(4)?,
            opened_by: row.get(5)?,
        })
    }

    const SESSION_SELECT: &'static str =
        "SELECT id, scope_ct, opened, expires_at, closed_at, opened_by FROM session";

    /// One session.
    pub fn session(&self, id: &str) -> Result<SessionRecord> {
        let mut stmt = self
            .conn
            .prepare(&format!("{} WHERE id = ?1", Self::SESSION_SELECT))?;
        let mut rows = stmt.query([id])?;
        match rows.next()? {
            Some(row) => self.session_from_row(row),
            None => Err(StoreError::NotFound),
        }
    }

    /// Sessions open at the vault's current time.
    pub fn active_sessions(&self) -> Result<Vec<SessionRecord>> {
        let now = self.now();
        let mut stmt = self.conn.prepare(&format!(
            "{} WHERE closed_at IS NULL AND expires_at > ?1 ORDER BY opened",
            Self::SESSION_SELECT
        ))?;
        let mut rows = stmt.query([now])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(self.session_from_row(row)?);
        }
        Ok(out)
    }

    /// End a session early. Idempotent.
    pub fn close_session(&mut self, id: &str, actor: &Actor) -> Result<SessionRecord> {
        let s = self.session(id)?;
        if s.closed_at.is_some() {
            return Ok(s);
        }
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE session SET closed_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "session_closed",
            Some(id),
            "ok",
            "{}",
        )?;
        tx.commit()?;
        self.session(id)
    }

    // --------------------------------------------------------- approvals

    /// Create an approval request, or return the existing pending one for the
    /// same token and item so a polling agent does not pile up duplicates.
    pub fn request_approval(
        &mut self,
        token_id: &str,
        item_id: &str,
        reason: &str,
        ttl: i64,
        actor: &Actor,
    ) -> Result<ApprovalRecord> {
        let now = self.now();
        if let Some(existing) = self.pending_for(token_id, item_id, now)? {
            return Ok(existing);
        }
        self.token(token_id)?;
        self.meta(item_id)?;
        let id = hex_id("apr")?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO approval (id, token_id, item_id, reason, requested_at, expires_at, status,
                                   decided_at, decided_by, consumed_at, escalation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, NULL, 0)",
            params![id, token_id, item_id, reason, now, now + ttl],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "approval_requested",
            Some(item_id),
            "ok",
            &serde_json::json!({ "approval_id": id, "token_id": token_id, "reason": reason, "ttl": ttl }).to_string(),
        )?;
        tx.commit()?;
        self.approval(&id)
    }

    fn approval_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(ApprovalRecord, String)> {
        let status_str: String = row.get(6)?;
        Ok((
            ApprovalRecord {
                id: row.get(0)?,
                token_id: row.get(1)?,
                item_id: row.get(2)?,
                reason: row.get(3)?,
                requested_at: row.get(4)?,
                expires_at: row.get(5)?,
                status: ApprovalStatus::Pending,
                decided_at: row.get(7)?,
                decided_by: row.get(8)?,
                consumed_at: row.get(9)?,
                escalation: row.get::<_, i64>(10)? as u32,
            },
            status_str,
        ))
    }

    const APPROVAL_SELECT: &'static str =
        "SELECT id, token_id, item_id, reason, requested_at, expires_at, status,
                decided_at, decided_by, consumed_at, escalation FROM approval";

    fn approvals_where(
        &self,
        where_sql: &str,
        p: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<ApprovalRecord>> {
        let mut stmt = self.conn.prepare(&format!(
            "{} {} ORDER BY requested_at, id",
            Self::APPROVAL_SELECT,
            where_sql
        ))?;
        let rows = stmt.query_map(p, Self::approval_from_row)?;
        let mut out = Vec::new();
        for r in rows {
            let (mut rec, status) = r?;
            rec.status = ApprovalStatus::parse(&status)?;
            out.push(rec);
        }
        Ok(out)
    }

    /// One approval.
    pub fn approval(&self, id: &str) -> Result<ApprovalRecord> {
        self.approvals_where("WHERE id = ?1", &[&id])?
            .pop()
            .ok_or(StoreError::NotFound)
    }

    fn pending_for(
        &self,
        token_id: &str,
        item_id: &str,
        now: i64,
    ) -> Result<Option<ApprovalRecord>> {
        Ok(self
            .approvals_where(
                "WHERE token_id = ?1 AND item_id = ?2 AND status = 'pending' AND expires_at > ?3",
                &[&token_id, &item_id, &now],
            )?
            .pop())
    }

    /// Everything still waiting for a human.
    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRecord>> {
        let now = self.now();
        self.approvals_where("WHERE status = 'pending' AND expires_at > ?1", &[&now])
    }

    /// Human decision. On approve, a grant is written so the token can read
    /// the item without another prompt until `grant_ttl` elapses (capped at
    /// the token's expiry).
    pub fn decide_approval(
        &mut self,
        id: &str,
        approve: bool,
        grant_ttl: i64,
        actor: &Actor,
    ) -> Result<ApprovalRecord> {
        let a = self.approval(id)?;
        if a.status != ApprovalStatus::Pending {
            return Err(StoreError::Invalid("approval already decided"));
        }
        let now = self.now();
        if now >= a.expires_at {
            return Err(StoreError::Invalid("approval already timed out"));
        }
        let status = if approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Denied
        };
        let token = self.token(&a.token_id)?;
        let grant_until = (now + grant_ttl).min(token.expires_at);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE approval SET status = ?2, decided_at = ?3, decided_by = ?4 WHERE id = ?1",
            params![id, status.as_str(), now, actor.label()],
        )?;
        if approve {
            tx.execute(
                "INSERT INTO access_grant (token_id, item_id, approval_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(token_id, item_id) DO UPDATE SET approval_id = excluded.approval_id,
                                                              expires_at = excluded.expires_at",
                params![a.token_id, a.item_id, id, grant_until],
            )?;
        }
        audit::append(
            &tx,
            now,
            &actor.label(),
            "approval_decided",
            Some(&a.item_id),
            status.as_str(),
            &serde_json::json!({ "approval_id": id, "token_id": a.token_id, "grant_until": approve.then_some(grant_until) }).to_string(),
        )?;
        tx.commit()?;
        self.approval(id)
    }

    /// Move every overdue pending approval to `timeout`, recording each.
    /// Returns the ids that changed.
    pub fn timeout_approvals(&mut self) -> Result<Vec<String>> {
        let now = self.now();
        let due = self.approvals_where("WHERE status = 'pending' AND expires_at <= ?1", &[&now])?;
        let mut ids = Vec::new();
        for a in due {
            let tx = self.conn.unchecked_transaction()?;
            tx.execute(
                "UPDATE approval SET status = 'timeout', decided_at = ?2 WHERE id = ?1",
                params![a.id, now],
            )?;
            audit::append(
                &tx,
                now,
                "system",
                "approval_timeout",
                Some(&a.item_id),
                "timeout",
                &serde_json::json!({ "approval_id": a.id, "token_id": a.token_id }).to_string(),
            )?;
            tx.commit()?;
            ids.push(a.id);
        }
        Ok(ids)
    }

    /// Record escalation steps that are now due (ADR 0005 §3). `ladder` is
    /// the list of offsets in seconds from `requested_at`; step *k* is
    /// recorded once, when `now ≥ requested_at + ladder[k]`. Returns
    /// `(approval_id, step)` pairs newly recorded so the daemon can notify.
    pub fn escalate_approvals(&mut self, ladder: &[i64]) -> Result<Vec<(String, u32)>> {
        let now = self.now();
        let pending = self.pending_approvals()?;
        let mut out = Vec::new();
        for a in pending {
            let due_step = ladder
                .iter()
                .filter(|&&off| now >= a.requested_at + off)
                .count() as u32;
            if due_step > a.escalation {
                let tx = self.conn.unchecked_transaction()?;
                tx.execute(
                    "UPDATE approval SET escalation = ?2 WHERE id = ?1",
                    params![a.id, due_step],
                )?;
                audit::append(
                    &tx,
                    now,
                    "system",
                    "approval_escalated",
                    Some(&a.item_id),
                    "ok",
                    &serde_json::json!({ "approval_id": a.id, "step": due_step }).to_string(),
                )?;
                tx.commit()?;
                out.push((a.id, due_step));
            }
        }
        Ok(out)
    }

    /// Mark an approved request as having delivered its value through the
    /// poll. Returns `true` the first time only.
    pub fn consume_approval(&mut self, id: &str) -> Result<bool> {
        let now = self.now();
        let n = self.conn.execute(
            "UPDATE approval SET consumed_at = ?2
             WHERE id = ?1 AND status = 'approved' AND consumed_at IS NULL",
            params![id, now],
        )?;
        Ok(n == 1)
    }

    /// Pre-authorize: a human grants a token access to an item ahead of any
    /// request (ADR 0005 §1, pre-authorization). Same grant row an approval
    /// would create, with `approval_id = "pre"`; capped at the token's expiry.
    pub fn grant_direct(
        &mut self,
        token_id: &str,
        item_id: &str,
        ttl: i64,
        actor: &Actor,
    ) -> Result<i64> {
        if ttl <= 0 {
            return Err(StoreError::Invalid("grant ttl must be positive"));
        }
        let token = self.token(token_id)?;
        self.meta(item_id)?;
        let now = self.now();
        let until = (now + ttl).min(token.expires_at);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO access_grant (token_id, item_id, approval_id, expires_at) VALUES (?1, ?2, 'pre', ?3)
             ON CONFLICT(token_id, item_id) DO UPDATE SET approval_id = 'pre', expires_at = excluded.expires_at",
            params![token_id, item_id, until],
        )?;
        audit::append(
            &tx,
            now,
            &actor.label(),
            "grant_issued",
            Some(item_id),
            "ok",
            &serde_json::json!({ "token_id": token_id, "until": until }).to_string(),
        )?;
        tx.commit()?;
        Ok(until)
    }

    /// Revoke a grant (pre-authorized or from an approval) before it expires.
    pub fn revoke_grant(&mut self, token_id: &str, item_id: &str, actor: &Actor) -> Result<bool> {
        let now = self.now();
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "DELETE FROM access_grant WHERE token_id = ?1 AND item_id = ?2",
            params![token_id, item_id],
        )?;
        if n > 0 {
            audit::append(
                &tx,
                now,
                &actor.label(),
                "grant_revoked",
                Some(item_id),
                "ok",
                &serde_json::json!({ "token_id": token_id }).to_string(),
            )?;
        }
        tx.commit()?;
        Ok(n > 0)
    }

    /// Live grants, soonest expiry first.
    pub fn active_grants(&self) -> Result<Vec<GrantRecord>> {
        let now = self.now();
        let mut stmt = self.conn.prepare(
            "SELECT token_id, item_id, approval_id, expires_at FROM access_grant WHERE expires_at > ?1 ORDER BY expires_at",
        )?;
        let rows = stmt.query_map([now], |r| {
            Ok(GrantRecord {
                token_id: r.get(0)?,
                item_id: r.get(1)?,
                approval_id: r.get(2)?,
                expires_at: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Whether an unexpired grant exists for this token and item.
    pub fn has_grant(&self, token_id: &str, item_id: &str) -> Result<bool> {
        let now = self.now();
        let hit: Option<i64> = self
            .conn
            .query_row(
                "SELECT expires_at FROM access_grant WHERE token_id = ?1 AND item_id = ?2 AND expires_at > ?3",
                params![token_id, item_id, now],
                |r| r.get(0),
            )
            .optional()?;
        Ok(hit.is_some())
    }
}
