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
use tun::{AbstractDevice, AsyncDevice};




const TUN_NAME: &str = "tun0";
const MTU: u16 = 1500;
const READ_BUF_SIZE: usize = 1504; // MTU + PI header

/// Split halves of the client TUN device.
pub struct TunReader(ReadHalf<AsyncDevice>);
pub struct TunWriter(WriteHalf<AsyncDevice>);

/// Create and configure the client TUN interface with the IP assigned by the server.
///
/// **Requires `CAP_NET_ADMIN`** or root privileges.
pub fn create_tun(assigned_ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<(String, TunReader, TunWriter)> {
    let mut config = tun::Configuration::default();
    config
        .tun_name(TUN_NAME)
        .address(assigned_ip)
        .netmask(netmask)
        .mtu(MTU)
        .up();

    let device = tun::create_as_async(&config)
        .with_context(|| format!("Failed to create client TUN interface — is CAP_NET_ADMIN set?"))?;

    let actual_name = device.tun_name().unwrap_or_else(|_| TUN_NAME.to_string());
    info!("Client TUN up: {actual_name} assigned {assigned_ip}/{netmask}");

    // Dale tiempo al kernel de Linux para registrar la interfaz
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // Fuerza a levantar la interfaz explícitamente por si el sistema no lo hizo
    let _ = run_ip(&["link", "set", "dev", &actual_name, "up"]);

    let (reader, writer) = tokio::io::split(device);
    Ok((actual_name, TunReader(reader), TunWriter(writer)))
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
    server_ip: Ipv4Addr,
    original_gateway: Ipv4Addr,
    original_iface: String,
    tun_name: String,
}

impl RouteGuard {
    pub fn install(server_ip: Ipv4Addr, tun_name: String) -> Result<Self> {
        let (original_gateway, original_iface) = detect_default_gateway()?;

        info!(
            "Installing VPN routes (server={server_ip}, gw={original_gateway}, iface={original_iface}, tun={tun_name})"
        );

        // 1. Bypass route
        run_ip(&[
            "route", "replace", &server_ip.to_string(),
            "via", &original_gateway.to_string(),
            "dev", &original_iface,
        ])?;

        // 2. Override default route
        run_ip(&["route", "replace", "0.0.0.0/1", "dev", &tun_name])?;
        run_ip(&["route", "replace", "128.0.0.0/1", "dev", &tun_name])?;

        Ok(Self { server_ip, original_gateway, original_iface, tun_name })
    }

    pub fn remove(&self) -> Result<()> {
        warn!("Removing VPN routes and restoring default gateway");

        // Remove override routes
        let _ = run_ip(&["route", "del", "0.0.0.0/1", "dev", &self.tun_name]);
        let _ = run_ip(&["route", "del", "128.0.0.0/1", "dev", &self.tun_name]);

        // Remove bypass route
        let _ = run_ip(&[
            "route", "del", &self.server_ip.to_string(),
            "via", &self.original_gateway.to_string(),
            "dev", &self.original_iface,
        ]);

        info!("VPN override routes removed. Original default gateway automatically resumes.");
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
