//! Client session management.
//!
//! Each connected client is represented as a `Session`. The `SessionManager`
//! keeps all active sessions in a thread-safe concurrent map and handles
//! IP address assignment from the VPN subnet pool.

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Errors from session management.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("IP address pool exhausted — max clients reached")]
    PoolExhausted,

    #[error("Session not found: {0}")]
    NotFound(SessionId),

    #[error("Session already exists: {0}")]
    AlreadyExists(SessionId),
}

/// Unique identifier for a VPN session.
pub type SessionId = Uuid;

/// Maximum size of a packet queued for a session's WebSocket writer.
const PACKET_CHANNEL_CAPACITY: usize = 256;

/// How long a session can be idle before being considered stale.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// A packet queued for delivery over a client's WebSocket connection.
pub type PacketTx = mpsc::Sender<Vec<u8>>;
pub type PacketRx = mpsc::Receiver<Vec<u8>>;

/// State of an active client session.
#[derive(Debug)]
pub struct Session {
    /// Unique session identifier.
    pub id: SessionId,
    /// VPN IP address assigned to this client.
    pub assigned_ip: Ipv4Addr,
    /// Channel sender: TUN reader → WebSocket writer task.
    pub packet_tx: PacketTx,
    /// Time of the last received packet (heartbeat or data).
    last_seen: std::sync::Mutex<Instant>,
}

impl Session {
    /// Create a new session and return it together with the receiving half
    /// of the packet channel (consumed by the WebSocket writer task).
    pub fn new(assigned_ip: Ipv4Addr) -> (Arc<Self>, PacketRx) {
        let id = Uuid::new_v4();
        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);

        let session = Arc::new(Self {
            id,
            assigned_ip,
            packet_tx,
            last_seen: std::sync::Mutex::new(Instant::now()),
        });

        (session, packet_rx)
    }

    /// Record that we received a packet from this client right now.
    pub fn touch(&self) {
        *self.last_seen.lock().unwrap() = Instant::now();
    }

    /// Returns `true` if the session has been idle longer than `SESSION_IDLE_TIMEOUT`.
    pub fn is_stale(&self) -> bool {
        self.last_seen.lock().unwrap().elapsed() > SESSION_IDLE_TIMEOUT
    }

    /// Send a packet to the WebSocket writer task for this session.
    /// Returns `false` if the channel is closed (client disconnected).
    pub async fn enqueue_packet(&self, packet: Vec<u8>) -> bool {
        self.packet_tx.send(packet).await.is_ok()
    }
}

/// Thread-safe pool of available VPN IP addresses.
///
/// Allocates from a /24 subnet starting at `.2` (`.1` is the server).
/// Uses an atomic counter to hand out IPs sequentially.
#[derive(Debug)]
pub struct IpPool {
    /// Base address of the subnet (e.g. 10.8.0.0).
    base: u32,
    /// Current allocation counter (next host octet to try).
    counter: AtomicU32,
    /// Maximum host index (254 for a /24).
    max_host: u32,
}

impl IpPool {
    /// Create a pool for the given base address (e.g. `10.8.0.0`).
    /// Starts allocating from `.2`; `.1` is reserved for the server.
    pub fn new(base: Ipv4Addr) -> Self {
        let base_u32 = u32::from(base) & 0xFFFFFF00; // zero out host byte
        Self {
            base: base_u32,
            counter: AtomicU32::new(2), // skip .1 (server)
            max_host: 254,
        }
    }

    /// Allocate the next available IP. Returns `None` when the pool is full.
    pub fn allocate(&self) -> Option<Ipv4Addr> {
        let host = self.counter.fetch_add(1, Ordering::Relaxed);
        if host > self.max_host {
            return None;
        }
        Some(Ipv4Addr::from(self.base | host))
    }
}

/// Manages all active sessions.
///
/// Two concurrent maps are maintained:
/// - `by_id`: SessionId → Session (used by the WebSocket handler)
/// - `by_ip`: Ipv4Addr → SessionId (used by the TUN reader for routing)
#[derive(Debug, Clone)]
pub struct SessionManager {
    by_id: Arc<DashMap<SessionId, Arc<Session>>>,
    by_ip: Arc<DashMap<Ipv4Addr, SessionId>>,
    ip_pool: Arc<IpPool>,
}

impl SessionManager {
    /// Create a new manager for the given VPN subnet base (e.g. `10.8.0.0`).
    pub fn new(subnet_base: Ipv4Addr) -> Self {
        Self {
            by_id: Arc::new(DashMap::new()),
            by_ip: Arc::new(DashMap::new()),
            ip_pool: Arc::new(IpPool::new(subnet_base)),
        }
    }

    /// Create a new session, assign an IP, and register it.
    ///
    /// Returns the new `Session` and the `PacketRx` channel that the
    /// WebSocket writer task should consume.
    pub fn create_session(&self) -> Result<(Arc<Session>, PacketRx), SessionError> {
        let ip = self.ip_pool.allocate().ok_or(SessionError::PoolExhausted)?;
        let (session, rx) = Session::new(ip);

        self.by_id.insert(session.id, Arc::clone(&session));
        self.by_ip.insert(ip, session.id);

        info!(
            session_id = %session.id,
            assigned_ip = %ip,
            "New session created"
        );

        Ok((session, rx))
    }

    /// Remove a session by ID, freeing its assigned IP from the routing table.
    pub fn remove_session(&self, id: &SessionId) {
        if let Some((_, session)) = self.by_id.remove(id) {
            self.by_ip.remove(&session.assigned_ip);
            info!(session_id = %id, "Session removed");
        } else {
            warn!(session_id = %id, "Tried to remove non-existent session");
        }
    }

    /// Look up a session by its assigned VPN IP address.
    /// Used by the TUN reader to route inbound packets.
    pub fn session_by_ip(&self, ip: &Ipv4Addr) -> Option<Arc<Session>> {
        let id = self.by_ip.get(ip)?.clone();
        self.by_id.get(&id).map(|s| Arc::clone(&s))
    }

    /// Look up a session by its ID.
    pub fn session_by_id(&self, id: &SessionId) -> Option<Arc<Session>> {
        self.by_id.get(id).map(|s| Arc::clone(&s))
    }

    /// Returns the number of currently active sessions.
    pub fn active_count(&self) -> usize {
        self.by_id.len()
    }

    /// Remove all sessions that have exceeded the idle timeout.
    /// Call this periodically (e.g., every 30 seconds) from a background task.
    pub fn evict_stale_sessions(&self) {
        let stale: Vec<SessionId> = self
            .by_id
            .iter()
            .filter(|entry| entry.value().is_stale())
            .map(|entry| *entry.key())
            .collect();

        for id in stale {
            debug!(session_id = %id, "Evicting stale session");
            self.remove_session(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_pool_allocates_sequentially() {
        let pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 0));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 8, 0, 3)));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 8, 0, 4)));
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 0));
        // Drain the pool (2..=254 = 253 addresses)
        pool.counter.store(254, Ordering::Relaxed);
        assert!(pool.allocate().is_some()); // .254 — last one
        assert!(pool.allocate().is_none()); // exhausted
    }

    #[test]
    fn test_session_manager_create_and_lookup() {
        let mgr = SessionManager::new(Ipv4Addr::new(10, 8, 0, 0));
        let (session, _rx) = mgr.create_session().unwrap();

        let id = session.id;
        let ip = session.assigned_ip;

        // Lookup by ID
        let found_by_id = mgr.session_by_id(&id).unwrap();
        assert_eq!(found_by_id.id, id);

        // Lookup by IP
        let found_by_ip = mgr.session_by_ip(&ip).unwrap();
        assert_eq!(found_by_ip.id, id);
    }

    #[test]
    fn test_session_manager_remove() {
        let mgr = SessionManager::new(Ipv4Addr::new(10, 8, 0, 0));
        let (session, _rx) = mgr.create_session().unwrap();
        let id = session.id;
        let ip = session.assigned_ip;

        mgr.remove_session(&id);

        assert!(mgr.session_by_id(&id).is_none());
        assert!(mgr.session_by_ip(&ip).is_none());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_session_manager_multiple_clients() {
        let mgr = SessionManager::new(Ipv4Addr::new(10, 8, 0, 0));

        let (s1, _) = mgr.create_session().unwrap();
        let (s2, _) = mgr.create_session().unwrap();

        // IPs must be different
        assert_ne!(s1.assigned_ip, s2.assigned_ip);
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn test_session_touch_and_staleness() {
        let (session, _rx) = Session::new(Ipv4Addr::new(10, 8, 0, 2));

        // Freshly created — not stale
        assert!(!session.is_stale());

        // Manually backdate last_seen
        *session.last_seen.lock().unwrap() =
            Instant::now() - SESSION_IDLE_TIMEOUT - Duration::from_secs(1);
        assert!(session.is_stale());

        // Touch should reset staleness
        session.touch();
        assert!(!session.is_stale());
    }

    #[tokio::test]
    async fn test_session_enqueue_packet() {
        let (session, mut rx) = Session::new(Ipv4Addr::new(10, 8, 0, 2));
        let packet = vec![0x45u8; 40];

        let sent = session.enqueue_packet(packet.clone()).await;
        assert!(sent);

        let received = rx.recv().await.unwrap();
        assert_eq!(received, packet);
    }
}
