use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use std::fs;
use std::path::Path;

/// AES-256-GCM encryptor/decryptor.
///
/// The key is read from `filename.key` as a 64-character hex string (32 bytes).
pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    /// Load the symmetric key from `filename.key`.
    pub fn from_key_file(path: &Path) -> Result<Self> {
        let hex_key = fs::read_to_string(path)
            .with_context(|| format!("Failed to read key file: {}", path.display()))?;
        let hex_key = hex_key.trim();
        if hex_key.len() != 64 {
            anyhow::bail!(
                "Key must be 64 hex characters (32 bytes), got {} characters",
                hex_key.len()
            );
        }
        let key_bytes = hex::decode(hex_key)
            .with_context(|| "Failed to decode hex key — must be valid hexadecimal")?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid key length for AES-256-GCM"))?;
        Ok(Self { cipher })
    }

    /// Encrypt `plaintext`, returning `nonce || ciphertext`.
    /// The nonce is 12 bytes (96 bits), placed before the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt `nonce || ciphertext`, returning the plaintext.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            anyhow::bail!("Encrypted data too short (need at least 12 bytes for nonce)");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        Ok(plaintext)
    }

    /// Generate a fresh random 64-char hex key (for bootstrapping).
    pub fn generate_key() -> String {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        hex::encode(key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key_hex = Crypto::generate_key();
        let tmp = std::env::temp_dir().join("swarm_test.key");
        std::fs::write(&tmp, &key_hex).unwrap();
        let crypto = Crypto::from_key_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        let plaintext = b"Hello, Swarm!";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampering_detected() {
        let key_hex = Crypto::generate_key();
        let tmp = std::env::temp_dir().join("swarm_test2.key");
        std::fs::write(&tmp, &key_hex).unwrap();
        let crypto = Crypto::from_key_file(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        let plaintext = b"Hello, Swarm!";
        let mut encrypted = crypto.encrypt(plaintext).unwrap();
        // Tamper with the ciphertext portion
        if encrypted.len() > 13 {
            encrypted[13] ^= 0x01;
        }
        assert!(crypto.decrypt(&encrypted).is_err());
    }
}
