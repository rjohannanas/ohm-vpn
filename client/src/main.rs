//! StealthVPN Client — entry point.
//!
//! CLI application that connects to a StealthVPN server over WebSocket/TLS,
//! establishes a cryptographic tunnel, and routes system traffic through it.

mod cli;
mod dns;
mod tun;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("client=debug".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect(args) => {
            println!("Connecting to {}...", args.server);
            tunnel::connect(args).await?;
        }
        Commands::Disconnect => {
            println!("Disconnect is currently handled via Ctrl-C in Connect mode.");
        }
        Commands::Status => {
            println!("Status command not fully implemented (connect runs in foreground).");
        }
    }

    Ok(())
}
