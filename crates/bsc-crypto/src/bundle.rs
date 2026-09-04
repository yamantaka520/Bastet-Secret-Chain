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

/// The header is bound through the field name: any change to it changes the
/// AAD and the tag stops verifying. `Aad` borrows a `&str`, so the caller
/// keeps this label alive for the length of the call.
fn header_label(header: &[u8]) -> String {
    format!("bundle/{}", hex_lower(header))
}

fn aad_with_header(label: &str) -> Aad<'_> {
    Aad {
        item_id: "",
        version: 0,
        field: label,
    }
}

/// Encrypt `plaintext` under `passphrase` with the given KDF parameters
/// (fresh salt expected in `params`).
pub fn seal_bundle(passphrase: &[u8], params: &KdfParams, plaintext: &[u8]) -> Result<Vec<u8>> {
    let kek = Kek::derive(passphrase, params)?;
    let header = header_bytes(params);
    let label = header_label(&header);
    let mut body = header.clone();
    let sealed = seal_field(&kek, &aad_with_header(&label), plaintext)?;
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
    // The parameters come from the file, and the file is not ours: check them
    // before the KDF is asked to honour them. Everything else here is cheap,
    // so a hostile bundle costs a few microseconds, not the machine.
    params.validate_from_file()?;
    let sealed = Sealed::from_slice(&bundle[HEADER_LEN..])?;
    let kek = Kek::derive(passphrase, &params)?;
    let label = header_label(header);
    open_field(&kek, &aad_with_header(&label), &sealed)
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
