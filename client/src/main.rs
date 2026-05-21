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
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("client=debug".parse()?)
                .add_directive("common=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect(args) => {
            eprintln!("Connecting to {} (port {})...", args.server, args.port);
            eprintln!("Press Ctrl-C to disconnect.");
            tunnel::connect(args).await?;
        }

        Commands::Disconnect => {
            // The client runs as a foreground process; disconnecting is done
            // via Ctrl-C (SIGINT). A future version could write a PID file and
            // send SIGINT to it here. For now we inform the user.
            eprintln!("To disconnect, press Ctrl-C in the terminal running 'connect'.");
            eprintln!("(Daemon mode with a separate disconnect command is planned for v1.1)");
        }

        Commands::Status => {
            // Same limitation as Disconnect — status would require a daemon
            // socket or PID file. Print helpful diagnostics instead.
            eprintln!("StealthVPN status check:");
            eprintln!("  • If a tunnel is active, the tun0 interface will be present:");
            eprintln!("      ip addr show tun0");
            eprintln!("  • Check your public IP to verify routing through the VPN:");
            eprintln!("      curl https://ipinfo.io/ip");
            eprintln!("  • Check for DNS leaks:");
            eprintln!("      cat /etc/resolv.conf");
            eprintln!("(Full daemon mode with 'status' support is planned for v1.1)");
        }
    }

    Ok(())
}
