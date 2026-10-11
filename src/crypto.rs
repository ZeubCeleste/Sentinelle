//! Cryptographic primitives: AES-256-GCM + Argon2id key derivation.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Result};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;

pub const MAGIC: &[u8; 4] = b"SFL1";
const VERIFIER_PLAINTEXT: &[u8] = b"SENTINELLE_VERIFIER_V1";

/// AES-256 key that is wiped from memory when dropped.
pub struct SessionKey(pub [u8; 32]);

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<SessionKey> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(SessionKey(key))
}

fn cipher(key: &SessionKey) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0))
}

/// Encrypts `data` -> [magic | nonce(12) | ciphertext+tag].
pub fn encrypt_blob(key: &SessionKey, data: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<12>();
    let ct = cipher(key)
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_blob(key: &SessionKey, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 16 || &blob[0..4] != MAGIC {
        bail!("unrecognized file (invalid header)");
    }
    cipher(key)
        .decrypt(Nonce::from_slice(&blob[4..16]), &blob[16..])
        .map_err(|_| anyhow!("decryption refused (wrong password or tampered file)"))
}

/// Builds an encrypted verifier (nonce, ciphertext) from a key.
pub fn make_verifier(key: &SessionKey) -> Result<([u8; 12], Vec<u8>)> {
    let nonce = random_bytes::<12>();
    let ct = cipher(key)
        .encrypt(Nonce::from_slice(&nonce), VERIFIER_PLAINTEXT)
        .map_err(|_| anyhow!("failed to build the verifier"))?;
    Ok((nonce, ct))
}

/// Checks that a key matches the verifier (detects a wrong password).
pub fn check_verifier(key: &SessionKey, nonce: &[u8], ct: &[u8]) -> bool {
    match cipher(key).decrypt(Nonce::from_slice(nonce), ct) {
        Ok(p) => p == VERIFIER_PLAINTEXT,
        Err(_) => false,
    }
}
