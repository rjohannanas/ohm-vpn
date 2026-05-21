//! Automatic session key rotation.
//!
//! StealthVPN uses ephemeral X25519 keys per session (fresh ECDH on every
//! connect), so forward secrecy is guaranteed at the session level. This
//! module implements **intra-session key rotation**: periodically re-deriving
//! new symmetric cipher keys from a new ECDH exchange while the tunnel is
//! running, without dropping the connection.
//!
//! ## Why rotate intra-session?
//!
//! ChaCha20-Poly1305 uses a 64-bit nonce counter. At line-rate:
//!   - 1 Gbps with 1400-byte packets → ~89 000 packets/s
//!   - Nonce exhaustion in ~2^64 / 89 000 ≈ 6.6 million years
//!
//! Nonce exhaustion is therefore not the threat. The threat is **key
//! compromise**: if an adversary captures ciphertext and later obtains the
//! session key, they can decrypt all recorded traffic for that session
//! window. Intra-session rotation limits the decryption window to
//! `rotation_interval` worth of traffic.
//!
//! ## Wire protocol for key rotation
//!
//! Key rotation reuses the existing handshake message types:
//!
//! ```text
//! Client                          Server
//!   │── KeyRotateRequest ────────►│   (encrypted with current key)
//!   │◄─ KeyRotateAccept ──────────│   (encrypted with current key)
//!   │                             │
//!   │   [Both derive new keys from new ECDH + HKDF with rotation context]
//!   │                             │
//!   │── KeyRotateComplete ────────►│   (encrypted with NEW key — confirms switch)
//!   │                             │
//!   │        [Traffic continues with new keys]
//! ```

use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Default key rotation interval: 1 hour.
/// Balances forward secrecy window size against the overhead of renegotiation.
pub const DEFAULT_ROTATION_INTERVAL: Duration = Duration::from_secs(3600);

/// Minimum allowed rotation interval (prevents DoS via aggressive rotation).
pub const MIN_ROTATION_INTERVAL: Duration = Duration::from_secs(300);

/// Configuration for intra-session key rotation.
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    /// How often to rotate session keys.
    pub interval: Duration,
    /// Whether key rotation is enabled.
    pub enabled: bool,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_ROTATION_INTERVAL,
            enabled: true,
        }
    }
}

impl KeyRotationConfig {
    /// Disabled configuration — no intra-session rotation.
    pub fn disabled() -> Self {
        Self { interval: DEFAULT_ROTATION_INTERVAL, enabled: false }
    }

    /// Create a config with a custom interval (clamped to `MIN_ROTATION_INTERVAL`).
    pub fn with_interval(secs: u64) -> Self {
        let interval = Duration::from_secs(secs)
            .max(MIN_ROTATION_INTERVAL);
        Self { interval, enabled: true }
    }
}

// ── Wire messages ─────────────────────────────────────────────────────────────

/// Sent by the initiating side (client or server) to request key rotation.
/// Carries a new ephemeral public key for ECDH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotateRequest {
    /// The initiator's new ephemeral X25519 public key (32 bytes).
    pub ephemeral_public_key: [u8; 32],
    /// Monotonic rotation counter — both sides must agree on this value.
    /// Protects against replay of old rotation messages.
    pub rotation_id: u64,
}

/// Sent by the responder to accept the rotation request.
/// Carries the responder's new ephemeral public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotateAccept {
    /// The responder's new ephemeral X25519 public key (32 bytes).
    pub ephemeral_public_key: [u8; 32],
    /// Echo of the `rotation_id` from `KeyRotateRequest`.
    pub rotation_id: u64,
}

/// Sent by the initiator after switching to the new keys.
/// If the server receives this successfully with the new key, the rotation is
/// confirmed on both sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotateComplete {
    pub rotation_id: u64,
}

// ── Rotation state tracker ────────────────────────────────────────────────────

/// Tracks when the next key rotation is due for a session.
#[derive(Debug)]
pub struct RotationTimer {
    config: KeyRotationConfig,
    last_rotation: Instant,
    rotation_count: u64,
}

impl RotationTimer {
    pub fn new(config: KeyRotationConfig) -> Self {
        Self {
            config,
            last_rotation: Instant::now(),
            rotation_count: 0,
        }
    }

    /// Returns `true` if a key rotation is due.
    pub fn is_due(&self) -> bool {
        self.config.enabled && self.last_rotation.elapsed() >= self.config.interval
    }

    /// Returns how long until the next rotation (zero if already due).
    pub fn time_until_next(&self) -> Duration {
        if !self.config.enabled {
            return Duration::MAX;
        }
        self.config.interval
            .checked_sub(self.last_rotation.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Called after a successful rotation to reset the timer.
    /// Returns the new rotation ID.
    pub fn record_rotation(&mut self) -> u64 {
        self.last_rotation = Instant::now();
        self.rotation_count += 1;
        self.rotation_count
    }

    /// Returns the number of completed rotations for this session.
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
    }
}

// ── Key derivation context for rotation ───────────────────────────────────────

/// HKDF info strings that differentiate rotation-derived keys from initial
/// session keys, preventing confusion between key generations.
pub fn rotation_info_client_to_server(rotation_id: u64) -> Vec<u8> {
    let mut info = b"stealthvpn-v1-rotate-c2s-".to_vec();
    info.extend_from_slice(&rotation_id.to_be_bytes());
    info
}

pub fn rotation_info_server_to_client(rotation_id: u64) -> Vec<u8> {
    let mut info = b"stealthvpn-v1-rotate-s2c-".to_vec();
    info.extend_from_slice(&rotation_id.to_be_bytes());
    info
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_timer_not_due_immediately() {
        let timer = RotationTimer::new(KeyRotationConfig::default());
        assert!(!timer.is_due(), "Timer should not be due immediately after creation");
    }

    #[test]
    fn test_rotation_timer_disabled_never_due() {
        let timer = RotationTimer::new(KeyRotationConfig::disabled());
        assert!(!timer.is_due());
        assert_eq!(timer.time_until_next(), Duration::MAX);
    }

    #[test]
    fn test_rotation_timer_due_after_backdating() {
        let mut timer = RotationTimer::new(KeyRotationConfig::with_interval(300));
        // Backdate last_rotation to simulate elapsed time
        timer.last_rotation = Instant::now() - Duration::from_secs(400);
        assert!(timer.is_due());
    }

    #[test]
    fn test_record_rotation_resets_timer() {
        let mut timer = RotationTimer::new(KeyRotationConfig::with_interval(300));
        timer.last_rotation = Instant::now() - Duration::from_secs(400);
        assert!(timer.is_due());

        let id = timer.record_rotation();
        assert_eq!(id, 1);
        assert!(!timer.is_due(), "Timer should not be due immediately after rotation");
        assert_eq!(timer.rotation_count(), 1);
    }

    #[test]
    fn test_rotation_count_increments() {
        let mut timer = RotationTimer::new(KeyRotationConfig::default());
        assert_eq!(timer.rotation_count(), 0);

        timer.record_rotation();
        timer.record_rotation();
        timer.record_rotation();

        assert_eq!(timer.rotation_count(), 3);
    }

    #[test]
    fn test_min_interval_clamping() {
        // A 1-second interval is below MIN_ROTATION_INTERVAL (300s) and should be clamped
        let cfg = KeyRotationConfig::with_interval(1);
        assert_eq!(cfg.interval, MIN_ROTATION_INTERVAL);
    }

    #[test]
    fn test_rotation_info_differs_by_direction_and_id() {
        let c2s_1 = rotation_info_client_to_server(1);
        let s2c_1 = rotation_info_server_to_client(1);
        let c2s_2 = rotation_info_client_to_server(2);

        assert_ne!(c2s_1, s2c_1, "c2s and s2c info strings must differ");
        assert_ne!(c2s_1, c2s_2, "Different rotation IDs must produce different info strings");
    }

    #[test]
    fn test_rotation_request_serialization() {
        let req = KeyRotateRequest {
            ephemeral_public_key: [0xABu8; 32],
            rotation_id: 42,
        };
        let bytes = bincode::serialize(&req).unwrap();
        let decoded: KeyRotateRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.rotation_id, 42);
        assert_eq!(decoded.ephemeral_public_key, [0xABu8; 32]);
    }
}
