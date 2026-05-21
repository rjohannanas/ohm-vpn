//! CLI definitions for the StealthVPN client.

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "stealthvpn-client",
    version,
    about = "StealthVPN Client — evade DPI and tunnel your traffic securely"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connect to a StealthVPN server
    Connect(ConnectArgs),
    /// Disconnect from the current VPN session
    Disconnect,
    /// Show the current connection status
    Status,
}

/// Obfuscation profile presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ObfuscationProfile {
    /// No obfuscation — maximum throughput (for testing / trusted networks)
    None,
    /// Default profile: light padding + 5 ms jitter + 1400-byte fragmentation
    Default,
    /// Aggressive profile: heavy padding + 20 ms jitter + 900-byte fragmentation
    /// + size normalization. Best resistance to DPI at the cost of throughput.
    Aggressive,
}

#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Server address (e.g. vpn.example.com or 1.2.3.4)
    #[arg(long, short)]
    pub server: String,

    /// Server port (default: 443)
    #[arg(long, short, default_value_t = 443)]
    pub port: u16,

    /// WebSocket path for the VPN endpoint
    #[arg(long, default_value = "/ws")]
    pub path: String,

    /// Disable TLS certificate verification (INSECURE — for testing only)
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    // ── Obfuscation ──────────────────────────────────────────────────────────

    /// Obfuscation preset. Individual flags below override the preset values.
    #[arg(long, value_enum, default_value_t = ObfuscationProfile::Default)]
    pub obfuscation: ObfuscationProfile,

    /// Minimum random padding per packet (bytes). Overrides preset.
    #[arg(long)]
    pub min_padding: Option<usize>,

    /// Maximum random padding per packet (bytes). Overrides preset.
    #[arg(long)]
    pub max_padding: Option<usize>,

    /// Maximum timing jitter before sending each packet (milliseconds). Overrides preset.
    #[arg(long)]
    pub max_jitter_ms: Option<u64>,

    /// Fragment packets larger than this many bytes into multiple frames.
    /// Set to 0 to disable. Overrides preset.
    #[arg(long)]
    pub fragment_threshold: Option<usize>,

    /// Pad all frames to the nearest size bucket to normalize the packet-size
    /// distribution (stronger anti-DPI, higher overhead). Overrides preset.
    #[arg(long, default_value_t = false)]
    pub normalize_sizes: bool,

    // ── Heartbeat ────────────────────────────────────────────────────────────

    /// Interval in seconds between keep-alive heartbeat frames sent to the server.
    /// Set to 0 to disable heartbeats.
    #[arg(long, default_value_t = 25)]
    pub heartbeat_interval_secs: u64,
}
