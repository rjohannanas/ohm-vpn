//! Cryptographic primitives for StealthVPN.
//!
//! This module implements:
//! - X25519 ECDH key exchange
//! - ChaCha20-Poly1305 authenticated encryption
//! - HKDF key derivation

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::ZeroizeOnDrop;

/// Errors produced by cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    #[error("AEAD decryption failed (authentication tag mismatch)")]
    DecryptionFailed,

    #[error("HKDF expand failed: {0}")]
    HkdfExpand(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Nonce counter overflow")]
    NonceOverflow,
}

/// A session key derived from ECDH + HKDF, used for symmetric encryption.
/// Zeroized on drop to prevent key material leaking in memory.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey {
    key: [u8; 32],
}

impl SessionKey {
    /// Derive a session key from a shared ECDH secret using HKDF-SHA256.
    ///
    /// `info` is a context string that differentiates keys for different
    /// directions or purposes (e.g. b"client-to-server" / b"server-to-client").
    pub fn derive(shared_secret: &SharedSecret, info: &[u8]) -> Result<Self, CryptoError> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(info, &mut key)
            .map_err(|e| CryptoError::HkdfExpand(e.to_string()))?;
        Ok(Self { key })
    }

    /// Returns a reference to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// An X25519 ephemeral keypair used during handshake.
pub struct EphemeralKeypair {
    secret: EphemeralSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    /// Generate a new random ephemeral keypair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform ECDH with the remote's public key, consuming the secret.
    pub fn diffie_hellman(self, remote_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(remote_public)
    }
}

/// A stateful cipher that tracks a monotonically increasing nonce counter.
/// Each `encrypt` / `decrypt` call automatically increments the counter,
/// preventing nonce reuse.
pub struct CipherState {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl CipherState {
    /// Create a new cipher from a `SessionKey`.
    pub fn new(key: &SessionKey) -> Self {
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        Self { cipher, counter: 0 }
    }

    /// Encrypt `plaintext` and return `(nonce_bytes, ciphertext)`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), CryptoError> {
        let nonce = self.next_nonce()?;
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok((nonce.into(), ciphertext))
    }

    /// Decrypt `ciphertext` using the provided `nonce_bytes`.
    pub fn decrypt(&self, nonce_bytes: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn next_nonce(&mut self) -> Result<Nonce, CryptoError> {
        let counter = self.counter;
        self.counter = self.counter.checked_add(1).ok_or(CryptoError::NonceOverflow)?;

        // Build a 12-byte nonce from an 8-byte little-endian counter.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
        Ok(*Nonce::from_slice(&nonce_bytes))
    }
}

/// Derive two session keys (one per direction) from a shared ECDH secret.
///
/// Returns `(client_to_server_key, server_to_client_key)`.
pub fn derive_session_keys(
    shared_secret: &SharedSecret,
) -> Result<(SessionKey, SessionKey), CryptoError> {
    let c2s = SessionKey::derive(shared_secret, b"stealthvpn-v1-client-to-server")?;
    let s2c = SessionKey::derive(shared_secret, b"stealthvpn-v1-server-to-client")?;
    Ok((c2s, s2c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_produces_same_shared_secret() {
        let client_kp = EphemeralKeypair::generate();
        let server_kp = EphemeralKeypair::generate();

        let client_pub = client_kp.public;
        let server_pub = server_kp.public;

        let client_shared = client_kp.diffie_hellman(&server_pub);
        let server_shared = server_kp.diffie_hellman(&client_pub);

        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    }

    #[test]
    fn test_session_key_derivation_is_deterministic() {
        let client_kp = EphemeralKeypair::generate();
        let server_kp = EphemeralKeypair::generate();

        let client_pub = client_kp.public;
        let server_pub = server_kp.public;

        let client_shared = client_kp.diffie_hellman(&server_pub);
        let server_shared = server_kp.diffie_hellman(&client_pub);

        let (c2s_client, s2c_client) = derive_session_keys(&client_shared).unwrap();
        let (c2s_server, s2c_server) = derive_session_keys(&server_shared).unwrap();

        assert_eq!(c2s_client.as_bytes(), c2s_server.as_bytes());
        assert_eq!(s2c_client.as_bytes(), s2c_server.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let client_kp = EphemeralKeypair::generate();
        let server_kp = EphemeralKeypair::generate();

        let shared = client_kp.diffie_hellman(&server_kp.public);
        let (key, _) = derive_session_keys(&shared).unwrap();

        let mut cipher = CipherState::new(&key);
        let plaintext = b"Hello, StealthVPN!";

        let (nonce, ciphertext) = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();
        let shared = kp1.diffie_hellman(&kp2.public);
        let (key, _) = derive_session_keys(&shared).unwrap();

        let mut cipher = CipherState::new(&key);
        let (nonce, mut ciphertext) = cipher.encrypt(b"secret data").unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        assert!(cipher.decrypt(&nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_nonce_counter_increments() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();
        let shared = kp1.diffie_hellman(&kp2.public);
        let (key, _) = derive_session_keys(&shared).unwrap();

        let mut cipher = CipherState::new(&key);
        let (nonce1, _) = cipher.encrypt(b"msg1").unwrap();
        let (nonce2, _) = cipher.encrypt(b"msg2").unwrap();

        // Nonces must differ to prevent reuse
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_direction_keys_differ() {
        let kp1 = EphemeralKeypair::generate();
        let kp2 = EphemeralKeypair::generate();
        let shared = kp1.diffie_hellman(&kp2.public);
        let (c2s, s2c) = derive_session_keys(&shared).unwrap();

        assert_ne!(c2s.as_bytes(), s2c.as_bytes());
    }
}
