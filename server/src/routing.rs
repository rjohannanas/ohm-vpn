//! IP packet routing between TUN interface and client sessions.

use crate::session::SessionManager;
use anyhow::{bail, Result};
use common::packet::{parse_ip_header, IpVersion};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

pub const MTU: usize = 1500;
pub const READ_BUF_SIZE: usize = MTU + 4;

/// Routes IP packets between the TUN interface and client sessions.
#[derive(Clone)]
pub struct Router {
    sessions: SessionManager,
    server_ip: Ipv4Addr,
    /// Channel to the TUN writer task (packets from clients → TUN → internet).
    tun_tx: mpsc::Sender<Vec<u8>>,
}

impl Router {
    pub fn new(sessions: SessionManager, server_ip: Ipv4Addr, tun_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { sessions, server_ip, tun_tx }
    }

    /// Route a raw IP packet from TUN to the correct client session.
    /// Returns `true` if forwarded successfully.
    pub async fn route_to_client(&self, packet: &[u8]) -> bool {
        let info = match parse_ip_header(packet) {
            Ok(i) => i,
            Err(e) => { warn!("TUN→client: bad IP header: {e}"); return false; }
        };

        let dest_v4 = match info.destination {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => { trace!("TUN→client: dropping IPv6"); return false; }
        };

        if dest_v4 == self.server_ip {
            trace!("TUN→client: dropping packet to server IP");
            return false;
        }

        match self.sessions.session_by_ip(&dest_v4) {
            Some(session) => {
                debug!(dest = %dest_v4, sid = %session.id, len = packet.len(), "TUN→client");
                session.enqueue_packet(packet.to_vec()).await
            }
            None => {
                trace!(dest = %dest_v4, "TUN→client: no session for dest");
                false
            }
        }
    }

    /// Route a decrypted IP packet from a client to the TUN interface (→ internet).
    pub async fn route_to_tun(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            bail!("Empty packet");
        }

        let info = parse_ip_header(packet)?;
        if info.version == IpVersion::V6 {
            bail!("IPv6 not yet supported");
        }

        debug!(src = %info.source, dst = %info.destination, len = packet.len(), "client→TUN");

        self.tun_tx.send(packet.to_vec()).await
            .map_err(|_| anyhow::anyhow!("TUN writer channel closed"))
    }
}
