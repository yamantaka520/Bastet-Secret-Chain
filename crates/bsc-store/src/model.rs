//! Item types and records.

use crate::StoreError;

/// First-class credential classes. The string form is stored in the clear
/// so the UI can render a sealed vault's shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ItemType {
    /// 🔐 account/password pairs, TOTP seeds
    Login,
    /// 🔑 provider API keys, signing secrets
    ApiKey,
    /// ☁️ AWS/GCP/Azure keys
    CloudKey,
    /// 🔥 Google/Firebase service-account JSON, deploy credentials
    ServiceAccount,
    /// 🎫 OAuth client secrets, refresh tokens
    OAuth,
    /// 🖥️ SSH key pairs
    SshKey,
    /// 📜 TLS and signing certificates
    Certificate,
    /// 🗂️ any other credential-bearing blob
    File,
}

impl ItemType {
    /// Stable storage string.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemType::Login => "login",
            ItemType::ApiKey => "api_key",
            ItemType::CloudKey => "cloud_key",
            ItemType::ServiceAccount => "service_account",
            ItemType::OAuth => "oauth",
            ItemType::SshKey => "ssh_key",
            ItemType::Certificate => "certificate",
            ItemType::File => "file",
        }
    }

    /// Parse the storage string.
    pub fn parse(s: &str) -> Result<ItemType, StoreError> {
        Ok(match s {
            "login" => ItemType::Login,
            "api_key" => ItemType::ApiKey,
            "cloud_key" => ItemType::CloudKey,
            "service_account" => ItemType::ServiceAccount,
            "oauth" => ItemType::OAuth,
            "ssh_key" => ItemType::SshKey,
            "certificate" => ItemType::Certificate,
            "file" => ItemType::File,
            _ => return Err(StoreError::Format(format!("unknown item type {s:?}"))),
        })
    }

    /// Whether reads of this class require human approval by default
    /// (`docs/adr/0005-approval-and-reminder-model.md` §1, tiering).
    pub fn approval_required_by_default(self) -> bool {
        matches!(
            self,
            ItemType::ServiceAccount | ItemType::CloudKey | ItemType::Certificate
        )
    }
}

/// Input for creating an item.
#[derive(Clone, Debug)]
pub struct NewItem {
    /// Hierarchical path, e.g. `prod/aws`. Encrypted on disk.
    pub path: String,
    /// Display name, e.g. `billing-account`. Encrypted on disk.
    pub name: String,
    /// Credential class.
    pub item_type: ItemType,
    /// Orthogonal tags. Encrypted on disk, searchable via the blind index.
    pub tags: Vec<String>,
    /// Environment label (`prod`, `staging`, …). Stored in the clear.
    pub env: Option<String>,
    /// Override the type default for approval-required reads.
    pub approval_required: Option<bool>,
    /// Unix seconds. Stored in the clear so expiry can be listed while sealed.
    pub expires_at: Option<i64>,
}

/// Metadata visible while the vault is sealed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemMeta {
    /// Opaque id, `it_` + 16 hex.
    pub id: String,
    /// Credential class.
    pub item_type: ItemType,
    /// Environment label.
    pub env: Option<String>,
    /// Unix seconds.
    pub created: i64,
    /// Unix seconds.
    pub updated: i64,
    /// Unix seconds.
    pub expires_at: Option<i64>,
    /// Whether reads need approval.
    pub approval_required: bool,
    /// Highest version number.
    pub current_version: u32,
    /// Plaintext size of the current version in bytes.
    pub size: u64,
}

/// Everything about an item except its body. Requires an unsealed vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemDetail {
    /// Clear metadata.
    pub meta: ItemMeta,
    /// Decrypted path.
    pub path: String,
    /// Decrypted name.
    pub name: String,
    /// Decrypted tags.
    pub tags: Vec<String>,
}
