//! Traffic obfuscation: random padding, timing jitter, packet fragmentation,
//! and size normalization.
//!
//! These mechanisms make StealthVPN traffic statistically indistinguishable
//! from regular HTTPS traffic by breaking packet-size and timing fingerprints.
//!
//! ## Anti-DPI strategy summary
//!
//! | Technique              | What it defeats                                   |
//! |------------------------|---------------------------------------------------|
//! | Random padding         | Fixed-size packet fingerprinting                  |
//! | Timing jitter          | Timing-based flow correlation                     |
//! | Packet fragmentation   | Large-packet burst fingerprinting                 |
//! | Size normalization     | Statistical size distribution analysis            |

use rand::Rng;
use std::time::Duration;

// ── Configuration ──────────────────────────────────────────────────────────────

/// Full obfuscation configuration controlling all anti-DPI knobs.
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    /// Minimum random padding added to each packet (bytes).
    pub min_padding: usize,
    /// Maximum random padding added to each packet (bytes).
    pub max_padding: usize,
    /// Maximum jitter delay before sending a packet (milliseconds).
    /// Set to 0 to disable jitter.
    pub max_jitter_ms: u64,
    /// Maximum payload size before a packet is fragmented (bytes).
    /// Packets larger than this will be split into multiple frames.
    /// Set to 0 to disable fragmentation.
    pub fragment_threshold: usize,
    /// If true, pad every packet to the nearest size bucket defined in
    /// `SIZE_BUCKETS` to normalize the packet-size distribution.
    pub normalize_sizes: bool,
}

/// Predefined size buckets used for size normalization.
/// Chosen to mimic common HTTPS response sizes seen in the wild.
const SIZE_BUCKETS: &[usize] = &[128, 256, 512, 1024, 1280, 1452, 2048, 4096, 8192, 16384];

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            min_padding: 16,
            max_padding: 256,
            max_jitter_ms: 5,
            // Default: fragment anything larger than a typical TLS record (~16 KB).
            // In practice most IP packets are ≤1500 bytes, but this covers edge cases.
            fragment_threshold: 1400,
            normalize_sizes: false,
        }
    }
}

impl ObfuscationConfig {
    /// A configuration with **all** obfuscation disabled.
    /// Use this for benchmarking or trusted networks.
    pub fn disabled() -> Self {
        Self {
            min_padding: 0,
            max_padding: 0,
            max_jitter_ms: 0,
            fragment_threshold: 0,
            normalize_sizes: false,
        }
    }

    /// Aggressive obfuscation profile: maximises resistance to DPI at the cost
    /// of some throughput. Suitable for highly restrictive firewalls.
    pub fn aggressive() -> Self {
        Self {
            min_padding: 64,
            max_padding: 512,
            max_jitter_ms: 20,
            fragment_threshold: 900,
            normalize_sizes: true,
        }
    }
}

// ── Padding ────────────────────────────────────────────────────────────────────

/// Generate a random padding buffer of length between `min_padding` and
/// `max_padding` bytes.
///
/// The padding content is cryptographically random to defeat entropy analysis.
pub fn generate_padding(config: &ObfuscationConfig) -> Vec<u8> {
    if config.max_padding == 0 {
        return Vec::new();
    }
    let mut rng = rand::thread_rng();
    let size = rng.gen_range(config.min_padding..=config.max_padding);
    let mut padding = vec![0u8; size];
    rng.fill(padding.as_mut_slice());
    padding
}

/// Append random padding to `payload` in place. Returns the number of padding
/// bytes added (stored in the frame header so the receiver can strip it).
pub fn apply_padding(payload: &mut Vec<u8>, config: &ObfuscationConfig) -> u16 {
    let padding = generate_padding(config);
    let size = padding.len() as u16;
    payload.extend_from_slice(&padding);
    size
}

/// Remove `padding_size` bytes from the end of a decrypted payload.
pub fn strip_padding(payload: &mut Vec<u8>, padding_size: u16) {
    let new_len = payload.len().saturating_sub(padding_size as usize);
    payload.truncate(new_len);
}

// ── Size normalization ─────────────────────────────────────────────────────────

/// Pad `payload` in place to the next size bucket ≥ `payload.len()`.
///
/// Size normalization forces all frames into a small set of known sizes,
/// making statistical size analysis ineffective. The extra bytes are filled
/// with random data so the resulting payload looks uniform.
///
/// Returns the number of normalization-padding bytes added (separate from the
/// regular per-packet padding). The caller must store this so the receiver can
/// strip it — you can reuse the frame's `padding_size` field for this.
pub fn normalize_to_bucket(payload: &mut Vec<u8>) -> usize {
    let current = payload.len();
    let target = SIZE_BUCKETS
        .iter()
        .find(|&&bucket| bucket >= current)
        .copied()
        .unwrap_or_else(|| {
            // Larger than the biggest bucket: round up to the next 4 KiB boundary
            let rem = current % 4096;
            if rem == 0 { current } else { current + 4096 - rem }
        });

    let extra = target.saturating_sub(current);
    if extra > 0 {
        let mut rng = rand::thread_rng();
        let mut fill = vec![0u8; extra];
        rng.fill(fill.as_mut_slice());
        payload.extend_from_slice(&fill);
    }
    extra
}

// ── Fragmentation ──────────────────────────────────────────────────────────────

/// Split `data` into fragments of at most `max_fragment_size` bytes each.
///
/// When `fragment_threshold` is 0 or `data.len() ≤ fragment_threshold`, this
/// returns a single-element vec with the original slice (no allocation).
/// Otherwise the data is split into owned fragments.
///
/// The caller is responsible for sending each fragment as a separate
/// `IpPacketFragment` frame; the receiver must reassemble them in order.
pub fn fragment_packet(data: &[u8], config: &ObfuscationConfig) -> Vec<Vec<u8>> {
    let threshold = config.fragment_threshold;
    if threshold == 0 || data.len() <= threshold {
        return vec![data.to_vec()];
    }

    data.chunks(threshold)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Returns `true` if `data` would be fragmented under `config`.
#[inline]
pub fn needs_fragmentation(data: &[u8], config: &ObfuscationConfig) -> bool {
    config.fragment_threshold > 0 && data.len() > config.fragment_threshold
}

// ── Timing jitter ──────────────────────────────────────────────────────────────

/// Returns a random jitter `Duration` to sleep before sending a packet.
/// Returns `Duration::ZERO` if jitter is disabled (`max_jitter_ms == 0`).
pub fn jitter_delay(config: &ObfuscationConfig) -> Duration {
    if config.max_jitter_ms == 0 {
        return Duration::ZERO;
    }
    let mut rng = rand::thread_rng();
    Duration::from_millis(rng.gen_range(0..=config.max_jitter_ms))
}

// ── Traffic analysis helpers ───────────────────────────────────────────────────

/// Compute the Shannon entropy of a byte slice (bits per byte, 0.0–8.0).
///
/// High entropy (> 7.0) indicates random/encrypted data. Random padding must
/// itself be high-entropy to avoid standing out relative to the ciphertext.
pub fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |entropy, &c| {
        let p = c as f64 / len;
        entropy - p * p.log2()
    })
}

/// Returns `true` if the entropy of `data` is above `threshold` bits/byte.
///
/// Use this to assert that padded/encrypted payloads have high entropy and
/// will not be flagged by DPI entropy filters.
pub fn is_high_entropy(data: &[u8], threshold: f64) -> bool {
    byte_entropy(data) >= threshold
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Padding tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_padding_length_within_bounds() {
        let config = ObfuscationConfig {
            min_padding: 10,
            max_padding: 100,
            ..ObfuscationConfig::disabled()
        };
        for _ in 0..200 {
            let padding = generate_padding(&config);
            assert!(padding.len() >= 10, "padding too short: {}", padding.len());
            assert!(padding.len() <= 100, "padding too long: {}", padding.len());
        }
    }

    #[test]
    fn test_disabled_config_produces_no_padding() {
        let padding = generate_padding(&ObfuscationConfig::disabled());
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
    fn test_padding_content_is_random() {
        let config = ObfuscationConfig {
            min_padding: 64,
            max_padding: 64,
            ..ObfuscationConfig::disabled()
        };
        // Two independently-generated 64-byte random buffers should differ
        // (probability of collision: 2^-512 ≈ 0)
        let p1 = generate_padding(&config);
        let p2 = generate_padding(&config);
        assert_ne!(p1, p2);
    }

    // ── Jitter tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_jitter_delay_within_bounds() {
        let config = ObfuscationConfig {
            max_jitter_ms: 10,
            ..ObfuscationConfig::disabled()
        };
        for _ in 0..100 {
            let delay = jitter_delay(&config);
            assert!(delay <= Duration::from_millis(10));
        }
    }

    #[test]
    fn test_zero_jitter_returns_zero_duration() {
        assert_eq!(jitter_delay(&ObfuscationConfig::disabled()), Duration::ZERO);
    }

    // ── Fragmentation tests ────────────────────────────────────────────────────

    #[test]
    fn test_no_fragmentation_when_below_threshold() {
        let config = ObfuscationConfig {
            fragment_threshold: 1400,
            ..ObfuscationConfig::disabled()
        };
        let data = vec![0xAAu8; 500];
        let frags = fragment_packet(&data, &config);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], data);
    }

    #[test]
    fn test_fragmentation_splits_correctly() {
        let config = ObfuscationConfig {
            fragment_threshold: 100,
            ..ObfuscationConfig::disabled()
        };
        let data: Vec<u8> = (0u8..=255).cycle().take(350).collect();
        let frags = fragment_packet(&data, &config);

        // 350 bytes / 100 = 3 full + 1 partial → 4 fragments
        assert_eq!(frags.len(), 4);
        assert_eq!(frags[0].len(), 100);
        assert_eq!(frags[1].len(), 100);
        assert_eq!(frags[2].len(), 100);
        assert_eq!(frags[3].len(), 50);

        // Reassembled data must equal the original
        let reassembled: Vec<u8> = frags.into_iter().flatten().collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragmentation_exact_boundary() {
        let config = ObfuscationConfig {
            fragment_threshold: 200,
            ..ObfuscationConfig::disabled()
        };
        let data = vec![0u8; 200]; // exactly at threshold → should NOT fragment
        let frags = fragment_packet(&data, &config);
        assert_eq!(frags.len(), 1);
    }

    #[test]
    fn test_no_fragmentation_when_threshold_zero() {
        let config = ObfuscationConfig::disabled(); // fragment_threshold = 0
        let data = vec![0u8; 9000];
        let frags = fragment_packet(&data, &config);
        assert_eq!(frags.len(), 1);
    }

    #[test]
    fn test_needs_fragmentation() {
        let config = ObfuscationConfig {
            fragment_threshold: 500,
            ..ObfuscationConfig::disabled()
        };
        assert!(!needs_fragmentation(&vec![0u8; 499], &config));
        assert!(!needs_fragmentation(&vec![0u8; 500], &config));
        assert!(needs_fragmentation(&vec![0u8; 501], &config));
    }

    // ── Size normalization tests ───────────────────────────────────────────────

    #[test]
    fn test_normalize_pads_to_bucket() {
        let mut payload = vec![0u8; 100]; // between 128 bucket
        let extra = normalize_to_bucket(&mut payload);
        assert_eq!(payload.len(), 128);
        assert_eq!(extra, 28);
    }

    #[test]
    fn test_normalize_already_at_bucket() {
        let mut payload = vec![0u8; 256]; // exactly at a bucket
        let extra = normalize_to_bucket(&mut payload);
        assert_eq!(extra, 0);
        assert_eq!(payload.len(), 256);
    }

    #[test]
    fn test_normalize_larger_than_all_buckets() {
        let mut payload = vec![0u8; 20000]; // > 16384 → rounds to 4 KiB boundary
        let original_len = payload.len();
        let extra = normalize_to_bucket(&mut payload);
        // 20000 % 4096 = 20000 - 4*4096 = 20000 - 16384 = 3616 → 4096 - 3616 = 480 extra
        let expected_extra = 4096 - (original_len % 4096);
        let expected_extra = if expected_extra == 4096 { 0 } else { expected_extra };
        assert_eq!(extra, expected_extra);
        assert_eq!(payload.len(), original_len + extra);
    }

    // ── Entropy tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_all_zeros_is_zero() {
        let data = vec![0u8; 256];
        let entropy = byte_entropy(&data);
        assert!(entropy < 0.001, "entropy of all-zeros should be ~0, got {entropy}");
    }

    #[test]
    fn test_entropy_uniform_is_eight() {
        // All 256 possible bytes, each appearing once → maximum entropy = 8.0
        let data: Vec<u8> = (0..=255).collect();
        let entropy = byte_entropy(&data);
        assert!(
            (entropy - 8.0).abs() < 0.001,
            "entropy of uniform distribution should be 8.0, got {entropy}"
        );
    }

    #[test]
    fn test_entropy_empty_is_zero() {
        assert_eq!(byte_entropy(&[]), 0.0);
    }

    #[test]
    fn test_random_padding_is_high_entropy() {
        let config = ObfuscationConfig {
            min_padding: 256,
            max_padding: 256,
            ..ObfuscationConfig::disabled()
        };
        let padding = generate_padding(&config);
        // Random 256-byte buffer should have entropy > 7.0 bits/byte
        assert!(
            is_high_entropy(&padding, 7.0),
            "random padding entropy too low: {}",
            byte_entropy(&padding)
        );
    }

    // ── Profile tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_aggressive_profile_values() {
        let cfg = ObfuscationConfig::aggressive();
        assert!(cfg.min_padding >= 64);
        assert!(cfg.max_padding >= 256);
        assert!(cfg.max_jitter_ms >= 10);
        assert!(cfg.fragment_threshold > 0 && cfg.fragment_threshold <= 1200);
        assert!(cfg.normalize_sizes);
    }

    #[test]
    fn test_disabled_profile_zero_overhead() {
        let cfg = ObfuscationConfig::disabled();
        assert_eq!(cfg.min_padding, 0);
        assert_eq!(cfg.max_padding, 0);
        assert_eq!(cfg.max_jitter_ms, 0);
        assert_eq!(cfg.fragment_threshold, 0);
        assert!(!cfg.normalize_sizes);
    }
}
