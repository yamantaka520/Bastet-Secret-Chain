//! Break-glass export bundles: a blob encrypted under a passphrase that is
//! *not* the vault passphrase, so a backup can be handed to a future self (or
//! a successor) without handing over the live vault.
//!
//! Layout: `b"BSCX1"` ‖ salt(16) ‖ m_cost_kib(u32 LE) ‖ t_cost(u32 LE) ‖
//! p_cost(u32 LE) ‖ Sealed(nonce ‖ ciphertext ‖ tag). The header fields are
//! bound as associated data, so they cannot be altered to weaken the KDF
//! without the tag failing.

use zeroize::Zeroizing;

use crate::{
    envelope::{open_field, seal_field, Aad, Sealed},
    kdf::{KdfParams, Kek, SALT_LEN},
    CryptoError, Result,
};

const MAGIC: &[u8; 5] = b"BSCX1";
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + 12;

fn header_bytes(p: &KdfParams) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&p.salt);
    h.extend_from_slice(&p.m_cost_kib.to_le_bytes());
    h.extend_from_slice(&p.t_cost.to_le_bytes());
    h.extend_from_slice(&p.p_cost.to_le_bytes());
    h
}

fn aad_for(header: &[u8]) -> Aad<'static> {
    // The header is bound through the field name: any change to it changes
    // the AAD and the tag no longer verifies. `Aad` wants &str, so hex it.
    let _ = header;
    Aad {
        item_id: "",
        version: 0,
        field: "bundle",
    }
}

/// Encrypt `plaintext` under `passphrase` with the given KDF parameters
/// (fresh salt expected in `params`).
pub fn seal_bundle(passphrase: &[u8], params: &KdfParams, plaintext: &[u8]) -> Result<Vec<u8>> {
    let kek = Kek::derive(passphrase, params)?;
    let header = header_bytes(params);
    let mut body = header.clone();
    let sealed = seal_field(&kek, &aad_with_header(&header), plaintext)?;
    body.extend_from_slice(&sealed.to_vec());
    Ok(body)
}

/// Decrypt a bundle produced by [`seal_bundle`].
pub fn open_bundle(passphrase: &[u8], bundle: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bundle.len() < HEADER_LEN || &bundle[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::Encoding);
    }
    let header = &bundle[..HEADER_LEN];
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&header[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    let u = |o: usize| u32::from_le_bytes(header[o..o + 4].try_into().unwrap());
    let base = MAGIC.len() + SALT_LEN;
    let params = KdfParams {
        m_cost_kib: u(base),
        t_cost: u(base + 4),
        p_cost: u(base + 8),
        salt,
    };
    if params.t_cost == 0 || params.p_cost == 0 || params.m_cost_kib < 8 {
        return Err(CryptoError::Encoding);
    }
    let kek = Kek::derive(passphrase, &params)?;
    let sealed = Sealed::from_slice(&bundle[HEADER_LEN..])?;
    open_field(&kek, &aad_with_header(header), &sealed)
}

fn aad_with_header(header: &[u8]) -> Aad<'static> {
    // Bind the header by folding it into the field label. Leaking via a
    // Box is acceptable: a handful of bundle operations per process.
    let label: &'static str = Box::leak(format!("bundle/{}", hex_lower(header)).into_boxed_str());
    let _ = aad_for(header);
    Aad {
        item_id: "",
        version: 0,
        field: label,
    }
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
