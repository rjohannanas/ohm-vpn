//! Client-side TUN interface and system routing.
//!
//! Creates the `tun0` interface on the client, configures the assigned VPN IP,
//! and sets up system routes to forward traffic through the tunnel.
//!
//! ## Route setup strategy
//!
//! When connected, we install:
//! 1. A **host route** to the VPN server IP via the original default gateway
//!    (so the encrypted WebSocket traffic doesn't loop through the VPN).
//! 2. A **default route** via the TUN interface (all other traffic goes through VPN).
//!
//! On disconnect, both routes are removed and the original default route is restored.

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::{info, warn};
use tun::AsyncDevice;




const TUN_NAME: &str = "tun0";
const MTU: u16 = 1500;
const READ_BUF_SIZE: usize = 1504; // MTU + PI header

/// Split halves of the client TUN device.
pub struct TunReader(ReadHalf<AsyncDevice>);
pub struct TunWriter(WriteHalf<AsyncDevice>);

/// Create and configure the client TUN interface with the IP assigned by the server.
///
/// **Requires `CAP_NET_ADMIN`** or root privileges.
pub fn create_tun(assigned_ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<(TunReader, TunWriter)> {
    let mut config = tun::Configuration::default();

    config
        .name(TUN_NAME)
        .address(assigned_ip)
        .netmask(netmask)
        .mtu(MTU)
        .up();

    let device = tun::create_as_async(&config)
        .with_context(|| format!("Failed to create client TUN interface — is CAP_NET_ADMIN set?"))?;

    info!("Client TUN up: {TUN_NAME} assigned {assigned_ip}/{netmask}");

    let (reader, writer) = tokio::io::split(device);
    Ok((TunReader(reader), TunWriter(writer)))
}

impl TunReader {
    /// Read one raw IP packet from the TUN device.
    /// The returned buffer may contain a 4-byte PI header on Linux.
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.0.read(buf).await.context("Client TUN read error")?;
        Ok(n)
    }
}

impl TunWriter {
    /// Write one decrypted IP packet received from the server to the TUN device.
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.0.write_all(packet).await.context("Client TUN write error")?;
        Ok(())
    }
}

/// System routing configuration managed by the client.
pub struct RouteGuard {
    /// VPN server's real (public) IP — needed for the bypass route.
    server_ip: Ipv4Addr,
    /// Original default gateway before we installed our routes.
    original_gateway: Ipv4Addr,
    /// Network interface used before VPN (e.g. "eth0", "wlan0").
    original_iface: String,
}

impl RouteGuard {
    /// Install VPN routes. Saves the current default gateway so it can be
    /// restored on `Drop`.
    ///
    /// Route plan:
    /// - `server_ip` via `original_gateway` dev `original_iface` (bypass route)
    /// - `0.0.0.0/0` via TUN (default route through VPN)
    pub fn install(server_ip: Ipv4Addr) -> Result<Self> {
        let (original_gateway, original_iface) = detect_default_gateway()?;

        info!(
            "Installing VPN routes (server={server_ip}, gw={original_gateway}, iface={original_iface})"
        );

        // 1. Bypass route: server IP → real gateway (avoid loop)
        run_ip(&[
            "route", "add", &server_ip.to_string(),
            "via", &original_gateway.to_string(),
            "dev", &original_iface,
        ])?;

        // 2. Default route → TUN
        run_ip(&["route", "add", "default", "dev", TUN_NAME])?;

        Ok(Self { server_ip, original_gateway, original_iface })
    }

    /// Remove VPN routes and restore the original default gateway.
    pub fn remove(&self) -> Result<()> {
        warn!("Removing VPN routes and restoring default gateway");

        // Remove default route via TUN
        let _ = run_ip(&["route", "del", "default", "dev", TUN_NAME]);

        // Remove bypass route
        let _ = run_ip(&[
            "route", "del", &self.server_ip.to_string(),
            "via", &self.original_gateway.to_string(),
            "dev", &self.original_iface,
        ]);

        // Restore original default gateway
        run_ip(&[
            "route", "add", "default",
            "via", &self.original_gateway.to_string(),
            "dev", &self.original_iface,
        ])?;

        info!("Default gateway restored: {} dev {}", self.original_gateway, self.original_iface);
        Ok(())
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            warn!("RouteGuard drop: failed to restore routes: {e}");
        }
    }
}

/// Detect the current default gateway and outbound interface using `ip route`.
fn detect_default_gateway() -> Result<(Ipv4Addr, String)> {
    // `ip route show default` outputs something like:
    // default via 192.168.1.1 dev eth0 proto dhcp ...
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("Failed to run 'ip route show default'")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_default_route(&stdout)
}

fn parse_default_route(output: &str) -> Result<(Ipv4Addr, String)> {
    // Expected format: "default via <GW> dev <IFACE> ..."
    let tokens: Vec<&str> = output.split_whitespace().collect();

    let via_pos = tokens.iter().position(|&t| t == "via")
        .context("No 'via' found in default route output")?;
    let dev_pos = tokens.iter().position(|&t| t == "dev")
        .context("No 'dev' found in default route output")?;

    let gw_str = tokens.get(via_pos + 1)
        .context("Missing gateway IP after 'via'")?;
    let iface = tokens.get(dev_pos + 1)
        .context("Missing interface after 'dev'")?;

    let gw: Ipv4Addr = gw_str.parse()
        .with_context(|| format!("Invalid gateway IP: {gw_str}"))?;

    Ok((gw, iface.to_string()))
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run: ip {}", args.join(" ")))?;

    if !status.success() {
        bail!("Command failed: ip {}", args.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_route_standard() {
        let output = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100";
        let (gw, iface) = parse_default_route(output).unwrap();
        assert_eq!(gw, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(iface, "eth0");
    }

    #[test]
    fn test_parse_default_route_wlan() {
        let output = "default via 10.0.0.1 dev wlan0";
        let (gw, iface) = parse_default_route(output).unwrap();
        assert_eq!(gw, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(iface, "wlan0");
    }

    #[test]
    fn test_parse_default_route_missing_via() {
        let output = "default dev eth0";
        assert!(parse_default_route(output).is_err());
    }

    #[test]
    fn test_parse_default_route_invalid_ip() {
        let output = "default via notanip dev eth0";
        assert!(parse_default_route(output).is_err());
    }
}
