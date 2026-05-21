//! DNS leak prevention.
//!
//! Temporarily updates the system's DNS resolver to use a public DNS (1.1.1.1)
//! that will be routed through the VPN tunnel. Restores the original configuration
//! when the tunnel is disconnected.

use anyhow::Result;
use std::fs;
use tracing::{info, warn};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const VPN_DNS: &str = "nameserver 1.1.1.1\nnameserver 1.0.0.1\n";

/// Manages system DNS configuration, restoring the original settings on drop.
pub struct DnsGuard {
    original_content: String,
}

impl DnsGuard {
    /// Install VPN DNS. Saves the current resolv.conf so it can be restored on `Drop`.
    pub fn install() -> Result<Self> {
        info!("Setting up DNS leak prevention...");

        // Read current content
        let original_content = match fs::read_to_string(RESOLV_CONF) {
            Ok(content) => content,
            Err(e) => {
                warn!("Could not read {RESOLV_CONF}: {e}");
                String::new()
            }
        };

        // Attempt to overwrite
        if let Err(e) = fs::write(RESOLV_CONF, VPN_DNS) {
            warn!("Failed to overwrite {RESOLV_CONF}: {e}. DNS leaks are possible!");
            warn!("Make sure you run the client as root.");
        } else {
            info!("DNS changed to VPN resolver (1.1.1.1)");
        }

        Ok(Self { original_content })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        if !self.original_content.is_empty() {
            info!("Restoring original DNS settings...");
            if let Err(e) = fs::write(RESOLV_CONF, &self.original_content) {
                warn!("Failed to restore {RESOLV_CONF}: {e}");
            }
        }
    }
}
