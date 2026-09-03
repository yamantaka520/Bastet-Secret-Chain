//! Break-glass export and import.
//!
//! An export is every item — metadata, tags, use binding, and **every
//! version's plaintext** — as JSON, sealed under a passphrase that is not the
//! vault's (`bsc_crypto::bundle`). Tokens, sessions, approvals, grants, and
//! the ledger are *not* exported: they are bound to this vault's identity and
//! its chain. Import recreates the items in another vault as new items with
//! new `sref`s and a fresh ledger trail; it never merges into existing items.

use bsc_crypto::{bundle, kdf::KdfParams};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    model::{ItemType, NewItem, UseBinding},
    vault::{Actor, Vault},
    Result, StoreError,
};

/// Bundle format version.
pub const FORMAT: u32 = 1;

/// One version of one item, plaintext body included.
#[derive(Serialize, Deserialize)]
pub struct ExportedVersion {
    /// Version number.
    pub n: u32,
    /// Unix seconds.
    pub created: i64,
    /// Rotation note, if any.
    pub note: Option<String>,
    /// Base64 body.
    pub body_b64: String,
}

/// One item with all of its metadata and versions.
#[derive(Serialize, Deserialize)]
pub struct ExportedItem {
    /// The source vault's id, for the operator's reference only.
    pub sref: String,
    /// Path.
    pub path: String,
    /// Name.
    pub name: String,
    /// Storage string of the type.
    pub item_type: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Environment label.
    pub env: Option<String>,
    /// Approval flag.
    pub approval_required: bool,
    /// Local-approval-only flag.
    pub local_approval_only: bool,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    /// Rotation cadence.
    pub rotation_days: Option<u32>,
    /// `use_secret` binding.
    pub use_binding: Option<UseBinding>,
    /// Every version, oldest first.
    pub versions: Vec<ExportedVersion>,
}

/// The whole export.
#[derive(Serialize, Deserialize)]
pub struct Bundle {
    /// [`FORMAT`].
    pub format: u32,
    /// Unix seconds.
    pub exported_at: i64,
    /// Hex head of the source vault's ledger at export time.
    pub source_head: String,
    /// Items.
    pub items: Vec<ExportedItem>,
}

impl Vault {
    /// Serialize every item with every version's plaintext. Requires an
    /// unsealed vault; records `vault_exported` with the item count.
    pub fn export_all(&mut self, actor: &Actor, reason: &str) -> Result<Bundle> {
        self.keys()?;
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut items = Vec::new();
        for m in self.list()? {
            let d = self.detail(&m.id)?;
            let mut versions = Vec::new();
            for n in 1..=m.current_version {
                let body =
                    self.read_version(&m.id, Some(n), actor, &format!("export: {reason}"))?;
                let (created, note): (i64, Option<Vec<u8>>) = self.conn.query_row(
                    "SELECT created, note_ct FROM version WHERE item_id = ?1 AND n = ?2",
                    rusqlite::params![m.id, n],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let note = match note {
                    Some(ct) => {
                        let (kek, _) = self.keys()?;
                        let pt = bsc_crypto::envelope::open_field(
                            kek,
                            &bsc_crypto::envelope::Aad {
                                item_id: &m.id,
                                version: n,
                                field: "note",
                            },
                            &bsc_crypto::envelope::Sealed::from_slice(&ct)?,
                        )?;
                        Some(String::from_utf8_lossy(&pt).to_string())
                    }
                    None => None,
                };
                versions.push(ExportedVersion {
                    n,
                    created,
                    note,
                    body_b64: b64.encode(&*body),
                });
            }
            items.push(ExportedItem {
                sref: m.id.clone(),
                path: d.path,
                name: d.name,
                item_type: m.item_type.as_str().to_string(),
                tags: d.tags,
                env: m.env,
                approval_required: m.approval_required,
                local_approval_only: m.local_approval_only,
                expires_at: m.expires_at,
                rotation_days: m.rotation_days,
                use_binding: d.use_binding,
                versions,
            });
        }
        let head = match self.audit_verify()? {
            crate::audit::ChainStatus::Intact { head, .. } => hex::encode(head),
            crate::audit::ChainStatus::Broken { at } => return Err(StoreError::ChainBroken(at)),
        };
        self.audit_event(
            actor,
            "vault_exported",
            None,
            "ok",
            serde_json::json!({ "items": items.len(), "reason": reason }),
        )?;
        Ok(Bundle {
            format: FORMAT,
            exported_at: self.now(),
            source_head: head,
            items,
        })
    }

    /// Recreate every item in the bundle as a new item here. Returns the new
    /// `sref`s in bundle order. Records `vault_imported`.
    pub fn import_all(
        &mut self,
        bundle: &Bundle,
        actor: &Actor,
        reason: &str,
    ) -> Result<Vec<String>> {
        if bundle.format != FORMAT {
            return Err(StoreError::Format(format!(
                "bundle format {} not supported",
                bundle.format
            )));
        }
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut created = Vec::new();
        for it in &bundle.items {
            let ty = ItemType::parse(&it.item_type)?;
            let mut versions = it.versions.iter().collect::<Vec<_>>();
            versions.sort_by_key(|v| v.n);
            let first = versions
                .first()
                .ok_or(StoreError::Format("item without versions".into()))?;
            let body = Zeroizing::new(
                b64.decode(&first.body_b64)
                    .map_err(|_| StoreError::Format("bad body_b64".into()))?,
            );
            let id = self.put(
                NewItem {
                    path: it.path.clone(),
                    name: it.name.clone(),
                    item_type: ty,
                    tags: it.tags.clone(),
                    env: it.env.clone(),
                    approval_required: Some(it.approval_required),
                    expires_at: it.expires_at,
                    rotation_days: it.rotation_days,
                },
                &body,
                actor,
                &format!("import: {reason}"),
            )?;
            for v in versions.iter().skip(1) {
                let body = Zeroizing::new(
                    b64.decode(&v.body_b64)
                        .map_err(|_| StoreError::Format("bad body_b64".into()))?,
                );
                self.add_version(
                    &id,
                    &body,
                    v.note.as_deref(),
                    actor,
                    &format!("import: {reason}"),
                )?;
            }
            if it.local_approval_only {
                self.set_item_flags(&id, None, Some(true), None, None, None, actor)?;
            }
            if let Some(b) = &it.use_binding {
                self.set_item_use(&id, Some(b), false, actor)?;
            }
            created.push(id);
        }
        self.audit_event(actor, "vault_imported", None, "ok", serde_json::json!({ "items": created.len(), "source_head": bundle.source_head, "reason": reason }))?;
        Ok(created)
    }
}

/// Serialize and seal a bundle under an export passphrase.
pub fn seal(bundle: &Bundle, passphrase: &[u8], params: &KdfParams) -> Result<Vec<u8>> {
    let json = Zeroizing::new(
        serde_json::to_vec(bundle)
            .map_err(|_| StoreError::Format("bundle not serializable".into()))?,
    );
    Ok(bundle::seal_bundle(passphrase, params, &json)?)
}

/// Open and parse a sealed bundle.
pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Bundle> {
    let json = bundle::open_bundle(passphrase, bytes)?;
    serde_json::from_slice(&json).map_err(|_| StoreError::Format("bundle is not valid JSON".into()))
}
