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

/// Where and how a credential may be *used on the agent's behalf* without
/// the agent ever seeing it (`use_secret`, ADR 0006 complement). Set by a
/// human; encrypted at rest because the URL patterns reveal which services
/// an item unlocks.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UseBinding {
    /// Allowed request targets, `https://host/path-prefix*` patterns. Empty
    /// means the item cannot be used through `use_secret` at all.
    pub urls: Vec<String>,
    /// Header injected into the outbound request, with `{value}` replaced by
    /// the secret, e.g. `Authorization: Bearer {value}`.
    pub header: String,
    /// Methods the daemon will send. Empty means GET only.
    #[serde(default)]
    pub methods: Vec<String>,
}

impl UseBinding {
    /// Whether `url` matches one of the allowed patterns. Patterns are exact
    /// scheme+host, then path prefix; a trailing `*` allows any suffix. Only
    /// https targets are allowed unless `allow_http` (a test-only relaxation
    /// the daemon ties to its private-upstream setting) is on.
    pub fn allows_url(&self, url: &str, allow_http: bool) -> bool {
        let scheme_ok = url.starts_with("https://") || (allow_http && url.starts_with("http://"));
        if !scheme_ok {
            return false;
        }
        self.urls.iter().any(|p| {
            let p = p.trim();
            if let Some(prefix) = p.strip_suffix('*') {
                url.starts_with(prefix) && prefix.contains("://") && prefix.len() > 8
            } else {
                url == p
            }
        })
    }

    /// Whether `method` is permitted.
    pub fn allows_method(&self, method: &str) -> bool {
        let m = method.to_ascii_uppercase();
        if self.methods.is_empty() {
            return m == "GET";
        }
        self.methods.iter().any(|x| x.eq_ignore_ascii_case(&m))
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
    /// Whether approval may only be given from the local UI, never from an
    /// external channel (ADR 0005 §4).
    pub local_approval_only: bool,
    /// Whether a `use_secret` binding exists (the binding itself is encrypted
    /// and only available through `ItemDetail`).
    pub has_use_binding: bool,
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
    /// Decrypted use binding, if any.
    pub use_binding: Option<UseBinding>,
}
