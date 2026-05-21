//! StealthVPN Server — entry point.

mod handler;
mod routing;
mod session;
mod tun;

use anyhow::Result;
use clap::Parser;
use common::obfuscation::ObfuscationConfig;
use routing::Router;
use session::SessionManager;
use std::net::Ipv4Addr;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "stealthvpn-server", version, about = "StealthVPN Server")]
struct Args {
    /// Address:port for the WebSocket listener (behind Nginx)
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Server VPN IP assigned to the TUN interface
    #[arg(long, default_value = "10.8.0.1")]
    server_ip: Ipv4Addr,

    /// VPN subnet base address
    #[arg(long, default_value = "10.8.0.0")]
    subnet: Ipv4Addr,

    /// Subnet mask
    #[arg(long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,

    /// Maximum simultaneous clients
    #[arg(long, default_value_t = 50)]
    max_clients: usize,

    // ── Obfuscation ──────────────────────────────────────────────────────────

    /// Minimum random padding per packet (bytes)
    #[arg(long, default_value_t = 16)]
    min_padding: usize,

    /// Maximum random padding per packet (bytes). Set 0 to disable.
    #[arg(long, default_value_t = 256)]
    max_padding: usize,

    /// Maximum timing jitter before sending each packet (ms). Set 0 to disable.
    #[arg(long, default_value_t = 5)]
    max_jitter_ms: u64,

    /// Fragment packets larger than this (bytes). Set 0 to disable.
    #[arg(long, default_value_t = 1400)]
    fragment_threshold: usize,

    /// Pad frames to the nearest size bucket (stronger anti-DPI, higher overhead).
    #[arg(long, default_value_t = false)]
    normalize_sizes: bool,

    // ── Session management ───────────────────────────────────────────────────

    /// How often (seconds) to run the stale-session eviction sweep.
    #[arg(long, default_value_t = 60)]
    eviction_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("server=debug".parse()?)
                .add_directive("common=info".parse()?),
        )
        .init();

    let args = Args::parse();

    info!("StealthVPN Server v{}", env!("CARGO_PKG_VERSION"));
    info!(
        "Listen: {}  VPN: {}/{}  Max clients: {}",
        args.listen, args.server_ip, args.netmask, args.max_clients
    );
    info!(
        "Obfuscation: padding=[{},{}] jitter={}ms fragment_threshold={} normalize={}",
        args.min_padding, args.max_padding, args.max_jitter_ms,
        args.fragment_threshold, args.normalize_sizes
    );
    info!("Reminder: Ensure your pre-shared keys are rotated periodically for security.");

    let obfuscation = ObfuscationConfig {
        min_padding: args.min_padding,
        max_padding: args.max_padding,
        max_jitter_ms: args.max_jitter_ms,
        fragment_threshold: args.fragment_threshold,
        normalize_sizes: args.normalize_sizes,
    };

    // ── Session manager ──────────────────────────────────────────────────────
    let sessions = SessionManager::new(args.subnet);

    // ── TUN interface ────────────────────────────────────────────────────────
    let (tun_reader, tun_writer) = tun::create_tun("tun0", args.server_ip, args.netmask)?;

    // TUN writer actor: receives packets from all sessions via mpsc channel
    let (tun_tx, _tun_writer_task) = tun::spawn_tun_writer_task(tun_writer);

    // ── Router ───────────────────────────────────────────────────────────────
    let router = Router::new(sessions.clone(), args.server_ip, tun_tx.clone());

    // TUN reader: routes internet-bound packets back to the correct client
    let _tun_reader_task = tun::spawn_tun_reader_task(tun_reader, router);

    // ── Stale session eviction ───────────────────────────────────────────────
    {
        let sessions_gc = sessions.clone();
        let interval_secs = args.eviction_interval_secs;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                sessions_gc.evict_stale_sessions();
                info!("Active sessions: {}", sessions_gc.active_count());
            }
        });
    }

    // ── WebSocket listener ───────────────────────────────────────────────────
    handler::run(&args.listen, sessions, tun_tx, obfuscation).await?;

    Ok(())
}
