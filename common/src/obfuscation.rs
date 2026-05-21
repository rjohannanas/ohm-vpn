//! Traffic obfuscation: random padding and timing jitter.
//!
//! These mechanisms make StealthVPN traffic statistically indistinguishable
//! from regular HTTPS traffic by breaking packet-size and timing fingerprints.

use rand::Rng;
use std::time::Duration;

/// Configuration for obfuscation behavior.
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    /// Minimum random padding added to each packet (bytes).
    pub min_padding: usize,
    /// Maximum random padding added to each packet (bytes).
    pub max_padding: usize,
    /// Maximum jitter delay before sending a packet (milliseconds).
    /// Set to 0 to disable jitter.
    pub max_jitter_ms: u64,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            min_padding: 16,
            max_padding: 256,
            max_jitter_ms: 5,
        }
    }
}

impl ObfuscationConfig {
    /// A configuration with no obfuscation (useful for benchmarking).
    pub fn disabled() -> Self {
        Self {
            min_padding: 0,
            max_padding: 0,
            max_jitter_ms: 0,
        }
    }
}

/// Generate a random padding buffer of length between `min` and `max` bytes.
///
/// The padding content is random to avoid entropy-based detection of fixed patterns.
pub fn generate_padding(config: &ObfuscationConfig) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    if config.max_padding == 0 {
        return Vec::new();
    }
    let size = rng.gen_range(config.min_padding..=config.max_padding);
    let mut padding = vec![0u8; size];
    rng.fill(padding.as_mut_slice());
    padding
}

/// Returns the size of padding that will be generated for this call.
/// Use this to write the `padding_size` field in the frame header.
pub fn padding_size(config: &ObfuscationConfig) -> u16 {
    let mut rng = rand::thread_rng();
    if config.max_padding == 0 {
        return 0;
    }
    rng.gen_range(config.min_padding..=config.max_padding) as u16
}

/// Appends random padding to a payload in place, returns the padding size used.
pub fn apply_padding(payload: &mut Vec<u8>, config: &ObfuscationConfig) -> u16 {
    let padding = generate_padding(config);
    let size = padding.len() as u16;
    payload.extend_from_slice(&padding);
    size
}

/// Remove padding from the end of a decrypted payload.
pub fn strip_padding(payload: &mut Vec<u8>, padding_size: u16) {
    let new_len = payload.len().saturating_sub(padding_size as usize);
    payload.truncate(new_len);
}

/// Returns a random jitter duration to sleep before sending a packet.
/// Returns `Duration::ZERO` if jitter is disabled.
pub fn jitter_delay(config: &ObfuscationConfig) -> Duration {
    if config.max_jitter_ms == 0 {
        return Duration::ZERO;
    }
    let mut rng = rand::thread_rng();
    let ms = rng.gen_range(0..=config.max_jitter_ms);
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_length_within_bounds() {
        let config = ObfuscationConfig {
            min_padding: 10,
            max_padding: 100,
            max_jitter_ms: 5,
        };

        for _ in 0..100 {
            let padding = generate_padding(&config);
            assert!(padding.len() >= 10);
            assert!(padding.len() <= 100);
        }
    }

    #[test]
    fn test_disabled_config_produces_no_padding() {
        let config = ObfuscationConfig::disabled();
        let padding = generate_padding(&config);
        assert!(padding.is_empty());
    }

    #[test]
    fn test_apply_and_strip_padding_roundtrip() {
        let config = ObfuscationConfig::default();
        let original = b"IP packet data here".to_vec();
        let mut payload = original.clone();

        let pad_size = apply_padding(&mut payload, &config);
        assert!(payload.len() > original.len());

        strip_padding(&mut payload, pad_size);
        assert_eq!(payload, original);
    }

    #[test]
    fn test_jitter_delay_within_bounds() {
        let config = ObfuscationConfig {
            min_padding: 0,
            max_padding: 0,
            max_jitter_ms: 10,
        };

        for _ in 0..50 {
            let delay = jitter_delay(&config);
            assert!(delay <= Duration::from_millis(10));
        }
    }

    #[test]
    fn test_zero_jitter_returns_zero_duration() {
        let config = ObfuscationConfig::disabled();
        assert_eq!(jitter_delay(&config), Duration::ZERO);
    }

    #[test]
    fn test_padding_content_is_random() {
        let config = ObfuscationConfig {
            min_padding: 64,
            max_padding: 64,
            max_jitter_ms: 0,
        };
        let p1 = generate_padding(&config);
        let p2 = generate_padding(&config);
        // Two random 64-byte buffers being identical is astronomically unlikely
        assert_ne!(p1, p2);
    }
}
