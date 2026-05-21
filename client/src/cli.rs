//! CLI definitions for the StealthVPN client.

use clap::{Args, Parser, Subcommand};

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
}
