//! Passphrase → key-encryption key, via Argon2id.

use argon2::{Algorithm, Argon2, Params, Version};
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::{fill_random, CryptoError, Result, KEY_LEN};

/// Salt length. 16 bytes is the Argon2 recommendation and is ample for a
/// single-operator vault.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters plus the vault salt.
///
/// These are stored in the vault header in the clear. That is intended: the
/// parameters are not secret, and storing them is what allows the cost to be
/// raised on a future passphrase change without breaking older vaults.
#[derive(Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
    /// Per-vault random salt.
    pub salt: [u8; SALT_LEN],
}

impl fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The salt is not secret, but printing it invites copy-paste into
        // places it does not belong. Costs are enough for diagnostics.
        f.debug_struct("KdfParams")
            .field("m_cost_kib", &self.m_cost_kib)
            .field("t_cost", &self.t_cost)
            .field("p_cost", &self.p_cost)
            .finish_non_exhaustive()
    }
}

impl KdfParams {
    /// Memory cost this crate will refuse to go below. 64 MiB is comfortably
    /// above the OWASP minimum for Argon2id and is the production default.
    pub const MIN_M_COST_KIB: u32 = 8 * 1024;

    /// Ceilings for parameters that were *read from a file* rather than chosen
    /// by this program. A bundle or vault header is untrusted input: with
    /// `m_cost_kib = u32::MAX` the reader asks Argon2 for 4 TiB and the process
    /// dies long before the authentication tag could reject the file. Real
    /// files use 64 MiB / 3 / 4, so these are far above anything legitimate and
    /// far below a denial of service.
    pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
    /// See [`Self::MAX_M_COST_KIB`].
    pub const MAX_T_COST: u32 = 16;
    /// See [`Self::MAX_M_COST_KIB`].
    pub const MAX_P_COST: u32 = 16;

    /// Production defaults with a fresh random salt: 64 MiB, 3 passes, 4 lanes.
    pub fn recommended() -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        Ok(Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            salt,
        })
    }

    /// Same cost parameters as `like`, fresh random salt. Used on passphrase
    /// rotation so a test vault keeps its fast parameters and a production
    /// vault keeps its strong ones.
    pub fn recommended_like(like: &KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        Ok(Self {
            m_cost_kib: like.m_cost_kib,
            t_cost: like.t_cost,
            p_cost: like.p_cost,
            salt,
        })
    }

    /// Explicit parameters. Rejects memory costs below [`Self::MIN_M_COST_KIB`]
    /// and zero passes or lanes. Tests that need to be fast should use
    /// [`KdfParams::insecure_for_tests`] instead of lying about production.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32, salt: [u8; SALT_LEN]) -> Result<Self> {
        if m_cost_kib < Self::MIN_M_COST_KIB {
            return Err(CryptoError::Parameter("m_cost below minimum"));
        }
        if t_cost == 0 {
            return Err(CryptoError::Parameter("t_cost must be at least 1"));
        }
        if p_cost == 0 {
            return Err(CryptoError::Parameter("p_cost must be at least 1"));
        }
        Ok(Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        })
    }

    /// Check parameters decoded from a file before handing them to the KDF.
    ///
    /// Deliberately does **not** enforce [`Self::MIN_M_COST_KIB`]: a vault
    /// written by an older or a test build must still open, and a weak KDF
    /// costs its creator, not its reader. What it does enforce is that reading
    /// a hostile or corrupt file cannot exhaust memory or time.
    pub fn validate_from_file(&self) -> Result<()> {
        if self.t_cost == 0 || self.p_cost == 0 || self.m_cost_kib == 0 {
            return Err(CryptoError::Parameter("kdf parameter is zero"));
        }
        if self.m_cost_kib > Self::MAX_M_COST_KIB {
            return Err(CryptoError::Parameter("m_cost above ceiling"));
        }
        if self.t_cost > Self::MAX_T_COST {
            return Err(CryptoError::Parameter("t_cost above ceiling"));
        }
        if self.p_cost > Self::MAX_P_COST {
            return Err(CryptoError::Parameter("p_cost above ceiling"));
        }
        Ok(())
    }

    /// Deliberately weak parameters for tests only. Named so it cannot be
    /// mistaken for a production constructor in review.
    pub fn insecure_for_tests(salt: [u8; SALT_LEN]) -> Self {
        Self {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
            salt,
        }
    }

    fn argon2(&self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| CryptoError::Kdf)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// The key-encryption key. Wraps per-item data keys and encrypts small
/// metadata fields. Exists only in memory while the vault is unsealed and is
/// zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Kek([u8; KEY_LEN]);

impl fmt::Debug for Kek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kek(<redacted>)")
    }
}

impl Kek {
    /// Derive the KEK from a passphrase with the given parameters.
    ///
    /// The passphrase is taken as bytes so callers can pass a zeroizing
    /// buffer; this function does not copy it anywhere it does not have to.
    pub fn derive(passphrase: &[u8], params: &KdfParams) -> Result<Kek> {
        let argon = params.argon2()?;
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        argon
            .hash_password_into(passphrase, &params.salt, out.as_mut())
            .map_err(|_| CryptoError::Kdf)?;
        Ok(Kek(*out))
    }

    /// Construct a KEK from raw bytes. Only for tests and key-import paths
    /// that already hold a properly derived key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Kek {
        Kek(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}
