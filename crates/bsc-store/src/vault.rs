//! The vault: lifecycle, items, versions, search, and the audit hooks that
//! make every one of those accountable.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bsc_crypto::{
    blind_index::IndexKey,
    envelope::{self, Aad, Sealed, WrappedDek},
    kdf::{KdfParams, Kek, SALT_LEN},
    FORMAT,
};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::{
    audit::{self, AuditRecord, ChainStatus},
    model::{ItemDetail, ItemMeta, ItemType, NewItem},
    schema, Result, StoreError,
};

/// Source of "now" in Unix seconds. Injectable so tests can move time.
pub type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Who is performing an operation. Rendered into the audit ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Actor {
    /// A human through the UI, identified by session id.
    Human {
        /// Opaque session id.
        session: String,
    },
    /// An agent through a scoped token.
    Token {
        /// Token id (never the token value).
        id: String,
    },
    /// The daemon itself.
    System,
}

impl Actor {
    pub(crate) fn label(&self) -> String {
        match self {
            Actor::Human { session } => format!("human:{session}"),
            Actor::Token { id } => format!("token:{id}"),
            Actor::System => "system".to_string(),
        }
    }
}

enum State {
    Sealed,
    Unsealed { kek: Kek, index: IndexKey },
}

/// A sealed or unsealed vault backed by one SQLite file.
pub struct Vault {
    pub(crate) conn: Connection,
    params: KdfParams,
    verifier: Sealed,
    state: State,
    clock: Clock,
}

fn system_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Random bytes or a `Randomness` error; never a silent zero id.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| bsc_crypto::CryptoError::Randomness)?;
    Ok(b)
}

/// `prefix_` + 16 hex characters (64 random bits). For ids that appear in the
/// ledger and logs.
pub(crate) fn hex_id(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}_{}", hex::encode(random_bytes::<8>()?)))
}

/// Item reference: `sref_` + 22 base64url characters (128 random bits). This
/// is the value the UI's copy button yields; it identifies and grants nothing.
fn new_sref() -> Result<String> {
    use base64::Engine as _;
    Ok(format!(
        "sref_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<16>()?)
    ))
}

fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

fn require_meta(conn: &Connection, key: &str) -> Result<String> {
    get_meta(conn, key)?.ok_or_else(|| StoreError::Format(format!("missing meta {key}")))
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn parse_u32(s: &str, what: &str) -> Result<u32> {
    s.parse()
        .map_err(|_| StoreError::Format(format!("bad {what}: {s:?}")))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

impl Vault {
    /// Create a new vault file with production KDF parameters and leave it
    /// unsealed. Fails if the path already exists.
    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Vault> {
        Self::create_with_params(path, passphrase, KdfParams::recommended()?)
    }

    /// Create with explicit KDF parameters. Exists so tests can use
    /// [`KdfParams::insecure_for_tests`]; production callers want
    /// [`Vault::create`].
    pub fn create_with_params(path: &Path, passphrase: &[u8], params: KdfParams) -> Result<Vault> {
        if path.exists() {
            return Err(StoreError::Invalid("vault path already exists"));
        }
        if passphrase.is_empty() {
            return Err(StoreError::Invalid("empty passphrase"));
        }
        let conn = Connection::open(path)?;
        restrict_permissions(path)?;
        conn.execute_batch(schema::CREATE)?;

        let kek = Kek::derive(passphrase, &params)?;
        let verifier = envelope::make_verifier(&kek)?;

        let tx = conn.unchecked_transaction()?;
        set_meta(&tx, "format", FORMAT)?;
        set_meta(&tx, "schema_version", &schema::SCHEMA_VERSION.to_string())?;
        set_meta(&tx, "kdf_m_cost_kib", &params.m_cost_kib.to_string())?;
        set_meta(&tx, "kdf_t_cost", &params.t_cost.to_string())?;
        set_meta(&tx, "kdf_p_cost", &params.p_cost.to_string())?;
        set_meta(&tx, "kdf_salt", &hex::encode(params.salt))?;
        set_meta(&tx, "verifier", &hex::encode(verifier.to_vec()))?;
        audit::append(
            &tx,
            system_now(),
            &Actor::System.label(),
            "vault_created",
            None,
            "ok",
            &serde_json::json!({
                "format": FORMAT,
                "kdf": { "m_cost_kib": params.m_cost_kib, "t_cost": params.t_cost, "p_cost": params.p_cost }
            })
            .to_string(),
        )?;
        tx.commit()?;

        let index = IndexKey::derive(&kek);
        Ok(Vault {
            conn,
            params,
            verifier,
            state: State::Unsealed { kek, index },
            clock: Box::new(system_now),
        })
    }

    /// Open an existing vault, sealed.
    pub fn open(path: &Path) -> Result<Vault> {
        if !path.exists() {
            return Err(StoreError::Format("no such file".into()));
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;",
        )?;

        let format = require_meta(&conn, "format")?;
        if format != FORMAT {
            return Err(StoreError::Format(format!(
                "format {format:?}, expected {FORMAT:?}"
            )));
        }
        let schema_version = require_meta(&conn, "schema_version")?;
        if schema_version != schema::SCHEMA_VERSION.to_string() {
            return Err(StoreError::Format(format!(
                "schema version {schema_version}"
            )));
        }

        let salt_hex = require_meta(&conn, "kdf_salt")?;
        let salt_vec = hex::decode(&salt_hex).map_err(|_| StoreError::Format("bad salt".into()))?;
        if salt_vec.len() != SALT_LEN {
            return Err(StoreError::Format("bad salt length".into()));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);
        let params = KdfParams {
            m_cost_kib: parse_u32(&require_meta(&conn, "kdf_m_cost_kib")?, "m_cost")?,
            t_cost: parse_u32(&require_meta(&conn, "kdf_t_cost")?, "t_cost")?,
            p_cost: parse_u32(&require_meta(&conn, "kdf_p_cost")?, "p_cost")?,
            salt,
        };

        let verifier_hex = require_meta(&conn, "verifier")?;
        let verifier_bytes =
            hex::decode(&verifier_hex).map_err(|_| StoreError::Format("bad verifier".into()))?;
        let verifier = Sealed::from_slice(&verifier_bytes)?;

        Ok(Vault {
            conn,
            params,
            verifier,
            state: State::Sealed,
            clock: Box::new(system_now),
        })
    }

    /// Replace the time source. Tests use this to expire tokens and time out
    /// approvals without sleeping; production leaves the default.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// Current time from the vault's clock, in Unix seconds.
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Whether encrypted content is currently unreadable.
    pub fn is_sealed(&self) -> bool {
        matches!(self.state, State::Sealed)
    }

    /// KDF parameters stored in the header.
    pub fn kdf_params(&self) -> &KdfParams {
        &self.params
    }

    /// Derive the KEK and check it against the header verifier. Both outcomes
    /// are recorded; a rejected passphrase is exactly the kind of event the
    /// ledger exists for.
    pub fn unseal(&mut self, passphrase: &[u8], actor: &Actor) -> Result<()> {
        let kek = Kek::derive(passphrase, &self.params)?;
        let ok = envelope::check_verifier(&kek, &self.verifier);
        let outcome = if ok { "ok" } else { "denied" };
        self.audit_now(actor, "unseal", None, outcome, serde_json::json!({}))?;
        if !ok {
            return Err(StoreError::BadPassphrase);
        }
        let index = IndexKey::derive(&kek);
        self.state = State::Unsealed { kek, index };
        Ok(())
    }

    /// Check a passphrase against the header without changing seal state.
    /// Used for login to an already-unsealed vault and for re-authentication
    /// before revealing approval-required items. Both outcomes are recorded
    /// as `login`.
    pub fn verify_passphrase(&self, passphrase: &[u8], actor: &Actor) -> Result<bool> {
        let kek = Kek::derive(passphrase, &self.params)?;
        let ok = envelope::check_verifier(&kek, &self.verifier);
        self.audit_now(
            actor,
            "login",
            None,
            if ok { "ok" } else { "denied" },
            serde_json::json!({}),
        )?;
        Ok(ok)
    }

    /// Drop the KEK. Zeroization happens in `Kek`'s `Drop`.
    pub fn seal(&mut self, actor: &Actor) -> Result<()> {
        let was_sealed = self.is_sealed();
        self.state = State::Sealed;
        if !was_sealed {
            self.audit_now(actor, "seal", None, "ok", serde_json::json!({}))?;
        }
        Ok(())
    }

    pub(crate) fn audit_now(
        &self,
        actor: &Actor,
        action: &str,
        subject: Option<&str>,
        outcome: &str,
        meta: serde_json::Value,
    ) -> Result<u64> {
        audit::append(
            &self.conn,
            self.now(),
            &actor.label(),
            action,
            subject,
            outcome,
            &meta.to_string(),
        )
    }

    pub(crate) fn keys(&self) -> Result<(&Kek, &IndexKey)> {
        match &self.state {
            State::Unsealed { kek, index } => Ok((kek, index)),
            State::Sealed => Err(StoreError::Sealed),
        }
    }

    /// Store a new item with its first version. Returns the item id.
    pub fn put(
        &mut self,
        new: NewItem,
        body: &[u8],
        actor: &Actor,
        reason: &str,
    ) -> Result<String> {
        if new.name.trim().is_empty() {
            return Err(StoreError::Invalid("empty name"));
        }
        if new.path.trim().is_empty() {
            return Err(StoreError::Invalid("empty path"));
        }
        let (kek, index) = self.keys()?;
        let id = new_sref()?;
        let ts = self.now();
        let approval_required = new
            .approval_required
            .unwrap_or_else(|| new.item_type.approval_required_by_default());

        let field = |f: &'static str| Aad {
            item_id: &id,
            version: 0,
            field: f,
        };
        let path_ct = envelope::seal_field(kek, &field("path"), new.path.as_bytes())?;
        let name_ct = envelope::seal_field(kek, &field("name"), new.name.as_bytes())?;
        let tags_json = serde_json::to_string(&new.tags)
            .map_err(|_| StoreError::Invalid("tags not serializable"))?;
        let tags_ct = envelope::seal_field(kek, &field("tags"), tags_json.as_bytes())?;

        let body_aad = Aad {
            item_id: &id,
            version: 1,
            field: "body",
        };
        let (wrapped, body_ct) = envelope::seal_body(kek, &body_aad, body)?;

        let mut index_rows: Vec<(&str, [u8; bsc_crypto::blind_index::TAG_LEN])> = Vec::new();
        for t in index.tags("name", &new.name) {
            index_rows.push(("name", t));
        }
        for t in index.tags("path", &new.path) {
            index_rows.push(("path", t));
        }
        for tag in &new.tags {
            for t in index.tags("tags", tag) {
                index_rows.push(("tags", t));
            }
        }

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO item (id, item_type, env, created, updated, expires_at, approval_required,
                               local_approval_only, current_version, path_ct, name_ct, tags_ct)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, 0, 1, ?7, ?8, ?9)",
            params![
                id,
                new.item_type.as_str(),
                new.env,
                ts,
                new.expires_at,
                approval_required as i64,
                path_ct.to_vec(),
                name_ct.to_vec(),
                tags_ct.to_vec(),
            ],
        )?;
        tx.execute(
            "INSERT INTO version (item_id, n, wrapped_dek, body_ct, size, created, note_ct)
             VALUES (?1, 1, ?2, ?3, ?4, ?5, NULL)",
            params![
                id,
                wrapped.as_bytes(),
                body_ct.to_vec(),
                body.len() as i64,
                ts
            ],
        )?;
        for (f, t) in &index_rows {
            tx.execute(
                "INSERT OR IGNORE INTO blind_index (item_id, field, tag) VALUES (?1, ?2, ?3)",
                params![id, f, t.as_slice()],
            )?;
        }
        audit::append(
            &tx,
            ts,
            &actor.label(),
            "item_created",
            Some(&id),
            "ok",
            &serde_json::json!({
                "type": new.item_type.as_str(),
                "size": body.len(),
                "approval_required": approval_required,
                "reason": reason,
            })
            .to_string(),
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Append a new version of an item's body. Returns the new version number.
    pub fn add_version(
        &mut self,
        id: &str,
        body: &[u8],
        note: Option<&str>,
        actor: &Actor,
        reason: &str,
    ) -> Result<u32> {
        let (kek, _) = self.keys()?;
        let current: u32 = self
            .conn
            .query_row(
                "SELECT current_version FROM item WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let n = current + 1;
        let ts = self.now();
        let aad = Aad {
            item_id: id,
            version: n,
            field: "body",
        };
        let (wrapped, body_ct) = envelope::seal_body(kek, &aad, body)?;
        let note_ct = match note {
            Some(text) => Some(
                envelope::seal_field(
                    kek,
                    &Aad {
                        item_id: id,
                        version: n,
                        field: "note",
                    },
                    text.as_bytes(),
                )?
                .to_vec(),
            ),
            None => None,
        };

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO version (item_id, n, wrapped_dek, body_ct, size, created, note_ct)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                n,
                wrapped.as_bytes(),
                body_ct.to_vec(),
                body.len() as i64,
                ts,
                note_ct
            ],
        )?;
        tx.execute(
            "UPDATE item SET current_version = ?2, updated = ?3 WHERE id = ?1",
            params![id, n, ts],
        )?;
        audit::append(
            &tx,
            ts,
            &actor.label(),
            "version_added",
            Some(id),
            "ok",
            &serde_json::json!({ "version": n, "size": body.len(), "reason": reason }).to_string(),
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// Decrypt the current version of an item's body.
    ///
    /// Order matters and is the point of this function: the read is written
    /// to the ledger **before** any plaintext exists. If decryption then
    /// fails, the optimistic record is rolled back and an `error` record is
    /// written instead, so the ledger never claims a release that did not
    /// happen and never omits an attempt that did.
    pub fn read(&mut self, id: &str, actor: &Actor, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.read_version(id, None, actor, reason)
    }

    /// Decrypt a specific version. `None` means the current one.
    pub fn read_version(
        &mut self,
        id: &str,
        version: Option<u32>,
        actor: &Actor,
        reason: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let kek = match &self.state {
            State::Unsealed { kek, .. } => kek,
            State::Sealed => {
                self.audit_now(
                    actor,
                    "secret_read",
                    Some(id),
                    "denied",
                    serde_json::json!({ "reason": reason, "cause": "vault_sealed" }),
                )?;
                return Err(StoreError::Sealed);
            }
        };

        let n: u32 = match version {
            Some(n) => n,
            None => self
                .conn
                .query_row(
                    "SELECT current_version FROM item WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(StoreError::NotFound)?,
        };
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT wrapped_dek, body_ct FROM version WHERE item_id = ?1 AND n = ?2",
                params![id, n],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (wrapped, body_ct) = row.ok_or(StoreError::NotFound)?;

        let ts = self.now();
        let actor_label = actor.label();
        let meta = serde_json::json!({ "version": n, "reason": reason });

        let tx = self.conn.unchecked_transaction()?;
        audit::append(
            &tx,
            ts,
            &actor_label,
            "secret_read",
            Some(id),
            "ok",
            &meta.to_string(),
        )?;

        let aad = Aad {
            item_id: id,
            version: n,
            field: "body",
        };
        let result = envelope::open_body(
            kek,
            &aad,
            &WrappedDek::from_bytes(wrapped),
            &Sealed::from_slice(&body_ct)?,
        );
        match result {
            Ok(pt) => {
                tx.commit()?;
                Ok(pt)
            }
            Err(e) => {
                tx.rollback()?;
                audit::append(
                    &self.conn,
                    ts,
                    &actor_label,
                    "secret_read",
                    Some(id),
                    "error",
                    &serde_json::json!({ "version": n, "reason": reason, "cause": "decrypt_failed" })
                        .to_string(),
                )?;
                Err(e.into())
            }
        }
    }

    fn meta_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ItemMeta> {
        let type_str: String = row.get(1)?;
        let item_type = ItemType::parse(&type_str).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                format!("unknown item type {type_str:?}").into(),
            )
        })?;
        Ok(ItemMeta {
            id: row.get(0)?,
            item_type,
            env: row.get(2)?,
            created: row.get(3)?,
            updated: row.get(4)?,
            expires_at: row.get(5)?,
            approval_required: row.get::<_, i64>(6)? != 0,
            local_approval_only: row.get::<_, i64>(9)? != 0,
            current_version: row.get(7)?,
            size: row.get::<_, i64>(8)? as u64,
        })
    }

    const META_SELECT: &'static str =
        "SELECT i.id, i.item_type, i.env, i.created, i.updated, i.expires_at,
                i.approval_required, i.current_version, v.size, i.local_approval_only
         FROM item i JOIN version v ON v.item_id = i.id AND v.n = i.current_version";

    /// Clear metadata for every item. Works while sealed.
    pub fn list(&self) -> Result<Vec<ItemMeta>> {
        let mut stmt = self.conn.prepare(&format!(
            "{} ORDER BY i.created ASC, i.id ASC",
            Self::META_SELECT
        ))?;
        let rows = stmt.query_map([], Self::meta_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Clear metadata for one item. Works while sealed.
    pub fn meta(&self, id: &str) -> Result<ItemMeta> {
        self.conn
            .query_row(
                &format!("{} WHERE i.id = ?1", Self::META_SELECT),
                [id],
                Self::meta_from_row,
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// Decrypted path, name, and tags. Requires an unsealed vault.
    pub fn detail(&self, id: &str) -> Result<ItemDetail> {
        let (kek, _) = self.keys()?;
        let meta = self.meta(id)?;
        let (path_ct, name_ct, tags_ct): (Vec<u8>, Vec<u8>, Vec<u8>) = self.conn.query_row(
            "SELECT path_ct, name_ct, tags_ct FROM item WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let open = |f: &'static str, ct: &[u8]| -> Result<String> {
            let pt = envelope::open_field(
                kek,
                &Aad {
                    item_id: id,
                    version: 0,
                    field: f,
                },
                &Sealed::from_slice(ct)?,
            )?;
            String::from_utf8(pt.to_vec()).map_err(|_| StoreError::Format("field not utf-8".into()))
        };
        let path = open("path", &path_ct)?;
        let name = open("name", &name_ct)?;
        let tags: Vec<String> = serde_json::from_str(&open("tags", &tags_ct)?)
            .map_err(|_| StoreError::Format("tags not a JSON array".into()))?;
        Ok(ItemDetail {
            meta,
            path,
            name,
            tags,
        })
    }

    /// Exact-token search over names, paths, and tags via the blind index.
    /// Every token in `query` must match (AND). Returns item ids. Requires
    /// an unsealed vault, because the index key derives from the KEK.
    pub fn search(&self, query: &str, actor: &Actor) -> Result<Vec<String>> {
        let (_, index) = self.keys()?;
        let tokens = bsc_crypto::blind_index::tokens(query);
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let mut result: Option<Vec<String>> = None;
        for tok in &tokens {
            let tags = ["name", "path", "tags"].map(|f| index.tag(f, tok));
            let mut stmt = self
                .conn
                .prepare("SELECT DISTINCT item_id FROM blind_index WHERE tag IN (?1, ?2, ?3)")?;
            let ids: Vec<String> = stmt
                .query_map(
                    params![tags[0].as_slice(), tags[1].as_slice(), tags[2].as_slice()],
                    |r| r.get(0),
                )?
                .collect::<std::result::Result<_, _>>()?;
            result = Some(match result {
                None => ids,
                Some(prev) => prev.into_iter().filter(|i| ids.contains(i)).collect(),
            });
            if result.as_ref().is_some_and(|r| r.is_empty()) {
                break;
            }
        }
        let mut ids = result.unwrap_or_default();
        ids.sort();
        self.audit_now(
            actor,
            "search",
            None,
            "ok",
            serde_json::json!({ "tokens": tokens.len(), "hits": ids.len() }),
        )?;
        Ok(ids)
    }

    /// Update clear metadata flags. Each `Some` is applied; `None` leaves the
    /// column alone. `expires_at: Some(None)` clears the expiry.
    pub fn set_item_flags(
        &mut self,
        id: &str,
        approval_required: Option<bool>,
        local_approval_only: Option<bool>,
        expires_at: Option<Option<i64>>,
        env: Option<Option<String>>,
        actor: &Actor,
    ) -> Result<ItemMeta> {
        self.meta(id)?;
        let ts = self.now();
        let tx = self.conn.unchecked_transaction()?;
        if let Some(v) = approval_required {
            tx.execute(
                "UPDATE item SET approval_required = ?2, updated = ?3 WHERE id = ?1",
                params![id, v as i64, ts],
            )?;
        }
        if let Some(v) = local_approval_only {
            tx.execute(
                "UPDATE item SET local_approval_only = ?2, updated = ?3 WHERE id = ?1",
                params![id, v as i64, ts],
            )?;
        }
        if let Some(v) = expires_at {
            tx.execute(
                "UPDATE item SET expires_at = ?2, updated = ?3 WHERE id = ?1",
                params![id, v, ts],
            )?;
        }
        if let Some(v) = &env {
            tx.execute(
                "UPDATE item SET env = ?2, updated = ?3 WHERE id = ?1",
                params![id, v, ts],
            )?;
        }
        audit::append(
            &tx,
            ts,
            &actor.label(),
            "item_updated",
            Some(id),
            "ok",
            &serde_json::json!({
                "approval_required": approval_required,
                "local_approval_only": local_approval_only,
                "expires_at": expires_at,
                "env": env,
            })
            .to_string(),
        )?;
        tx.commit()?;
        self.meta(id)
    }

    /// Recompute the whole audit chain. Works while sealed.
    pub fn audit_verify(&self) -> Result<ChainStatus> {
        audit::verify(&self.conn)
    }

    /// Read ledger records for display. Works while sealed.
    pub fn audit_read(&self, from: u64, limit: u64) -> Result<Vec<AuditRecord>> {
        audit::read(&self.conn, from, limit)
    }

    /// Ledger records about one subject id. Works while sealed.
    pub fn audit_read_subject(
        &self,
        subject: &str,
        from: u64,
        limit: u64,
    ) -> Result<Vec<AuditRecord>> {
        audit::read_subject(&self.conn, subject, from, limit)
    }
}
