//! WebSocket connection handler: accept loop, handshake, bidirectional forwarding.
//!
//! ## Per-connection lifecycle
//!
//! 1. TCP accept → WebSocket upgrade
//! 2. Cryptographic handshake (X25519 ECDH + HKDF)
//! 3. Session created; client assigned a VPN IP
//! 4. Bidirectional forwarding (two concurrent tasks):
//!    - **WS → TUN**: decrypt frames from client, write raw IP packets to TUN
//!    - **TUN → WS**: take packets from session channel, encrypt, send to client
//! 5. Either task ending triggers session cleanup

use crate::session::{PacketRx, SessionManager};
use anyhow::{bail, Context, Result};
use common::{
    crypto::{derive_session_keys, CipherState, EphemeralKeypair},
    frame::{decode_encrypted, decode_plain, encode_encrypted, encode_plain},
    obfuscation::{self, ObfuscationConfig},
    protocol::{ClientHello, ClientReady, MessageType, ServerHello, SessionEstablished},
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::mpsc};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{debug, error, info, warn};
use x25519_dalek::PublicKey;

/// Bind the WebSocket listener and accept connections indefinitely.
///
/// `tun_tx` — channel to the TUN writer task; packets routed here go to the internet.
pub async fn run(
    listen_addr: &str,
    sessions: SessionManager,
    tun_tx: mpsc::Sender<Vec<u8>>,
    obfuscation: ObfuscationConfig,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await
        .with_context(|| format!("Failed to bind WebSocket listener on {listen_addr}"))?;

    info!("WebSocket VPN listener ready on {listen_addr}");

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        info!(peer = %peer_addr, "New TCP connection");

        let sessions = sessions.clone();
        let tun_tx = tun_tx.clone();
        let obfuscation = obfuscation.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp_stream, sessions, tun_tx, obfuscation).await {
                warn!(peer = %peer_addr, "Connection closed: {e}");
            }
        });
    }
}

/// Upgrade a TCP stream to WebSocket, run handshake, then forward packets.
async fn handle_connection(
    tcp_stream: tokio::net::TcpStream,
    sessions: SessionManager,
    tun_tx: mpsc::Sender<Vec<u8>>,
    obfuscation: ObfuscationConfig,
) -> Result<()> {
    let ws_stream = accept_async(tcp_stream).await.context("WebSocket upgrade failed")?;
    let (mut ws_sink, mut ws_recv) = ws_stream.split();

    // ── Handshake ────────────────────────────────────────────────────────────
    let (session, packet_rx, mut send_cipher, recv_cipher) =
        perform_handshake(&mut ws_sink, &mut ws_recv, &sessions, &obfuscation).await?;

    let session_id = session.id;
    let assigned_ip = session.assigned_ip;
    info!(session_id = %session_id, assigned_ip = %assigned_ip, "Session established");

    // ── Bidirectional forwarding ─────────────────────────────────────────────
    // Channel to signal both tasks to stop when one finishes.
    let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Task A: TUN → WS  (packets from TUN router, encrypted, sent to client)
    let stop_tx_a = stop_tx.clone();
    let mut stop_rx_a = stop_tx.subscribe();
    let tun_to_ws = tokio::spawn(async move {
        forward_tun_to_ws(packet_rx, &mut ws_sink, &mut send_cipher, &obfuscation, &mut stop_rx_a).await;
        let _ = stop_tx_a.send(());
    });

    // Task B: WS → TUN  (packets from client, decrypted, sent to TUN)
    let stop_tx_b = stop_tx.clone();
    let mut stop_rx_b = stop_tx.subscribe();
    let ws_to_tun = tokio::spawn(async move {
        forward_ws_to_tun(&mut ws_recv, &recv_cipher, tun_tx, session, &mut stop_rx_b).await;
        let _ = stop_tx_b.send(());
    });

    // Wait for both tasks to finish
    let _ = tokio::join!(tun_to_ws, ws_to_tun);

    // Clean up session
    sessions.remove_session(&session_id);
    info!(session_id = %session_id, "Session cleaned up");

    Ok(())
}

/// Execute the X25519 handshake. Returns `(session, packet_rx, send_cipher, recv_cipher)`.
async fn perform_handshake<Sink, Stream>(
    ws_sink: &mut Sink,
    ws_recv: &mut Stream,
    sessions: &SessionManager,
    obf: &ObfuscationConfig,
) -> Result<(
    Arc<crate::session::Session>,
    PacketRx,
    CipherState,
    CipherState,
)>
where
    Sink: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // ── Step 1: Receive ClientHello ──────────────────────────────────────────
    let raw = recv_binary(ws_recv).await.context("Waiting for ClientHello")?;
    let (msg_type, payload) = decode_plain(&raw)?;

    if msg_type != MessageType::ClientHello {
        bail!("Expected ClientHello, got {msg_type:?}");
    }

    let client_hello: ClientHello = bincode::deserialize(payload)
        .context("Deserialize ClientHello")?;

    debug!("Received ClientHello (protocol v{})", client_hello.version);

    // ── Step 2: Generate server keypair + allocate session ──────────────────
    let server_kp = EphemeralKeypair::generate();
    let server_pub_bytes: [u8; 32] = server_kp.public.to_bytes();

    let (session, packet_rx) = sessions.create_session()?;
    let session_id_bytes = session.id.as_bytes().to_owned();

    // ── Step 3: Send ServerHello ─────────────────────────────────────────────
    let server_hello = ServerHello {
        ephemeral_public_key: server_pub_bytes,
        session_id: session_id_bytes,
    };
    let hello_bytes = bincode::serialize(&server_hello)?;
    let frame = encode_plain(MessageType::ServerHello, &hello_bytes);
    ws_sink.send(Message::Binary(frame.into())).await
        .context("Sending ServerHello")?;

    // ── Step 4: ECDH + key derivation ────────────────────────────────────────
    let client_pub = PublicKey::from(client_hello.ephemeral_public_key);
    let shared_secret = server_kp.diffie_hellman(&client_pub);
    let (c2s_key, s2c_key) = derive_session_keys(&shared_secret)?;

    // Server receives from client → use c2s key
    let recv_cipher = CipherState::new(&c2s_key);
    // Server sends to client → use s2c key
    let mut send_cipher = CipherState::new(&s2c_key);

    // ── Step 5: Receive ClientReady (encrypted) ───────────────────────────────
    let raw = recv_binary(ws_recv).await.context("Waiting for ClientReady")?;
    let (msg_type, payload) = decode_encrypted(&recv_cipher, &raw)?;

    if msg_type != MessageType::ClientReady {
        sessions.remove_session(&session.id);
        bail!("Expected ClientReady, got {msg_type:?}");
    }

    let client_ready: ClientReady = bincode::deserialize(&payload)
        .context("Deserialize ClientReady")?;

    // Verify session ID echo
    if client_ready.session_id != session_id_bytes {
        sessions.remove_session(&session.id);
        bail!("ClientReady session_id mismatch");
    }

    // ── Step 6: Send SessionEstablished (encrypted) ───────────────────────────
    let ip_octets = session.assigned_ip.octets();
    let established = SessionEstablished {
        assigned_ip: ip_octets,
        subnet_mask: [255, 255, 255, 0],
    };
    let est_bytes = bincode::serialize(&established)?;
    let frame = encode_encrypted(&mut send_cipher, MessageType::SessionEstablished, &est_bytes, obf)?;
    ws_sink.send(Message::Binary(frame.into())).await
        .context("Sending SessionEstablished")?;

    Ok((session, packet_rx, send_cipher, recv_cipher))
}

/// TUN → WS: read packets from the session channel, optionally fragment large
/// packets, encrypt each fragment, and send to the client.
async fn forward_tun_to_ws<Sink>(
    mut packet_rx: PacketRx,
    ws_sink: &mut Sink,
    send_cipher: &mut CipherState,
    obf: &ObfuscationConfig,
    stop_rx: &mut tokio::sync::broadcast::Receiver<()>,
) where
    Sink: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    loop {
        tokio::select! {
            maybe_packet = packet_rx.recv() => {
                let packet = match maybe_packet {
                    Some(p) => p,
                    None => { debug!("Session packet channel closed"); break; }
                };

                // Optional timing jitter
                let delay = obfuscation::jitter_delay(obf);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }

                // Fragmentation: split large packets into multiple frames
                if obfuscation::needs_fragmentation(&packet, obf) {
                    let fragments = obfuscation::fragment_packet(&packet, obf);
                    debug!("Server fragmenting packet ({} bytes) into {} fragments",
                        packet.len(), fragments.len());

                    for fragment in fragments {
                        match encode_encrypted(send_cipher, MessageType::IpPacketFragment, &fragment, obf) {
                            Ok(frame) => {
                                if ws_sink.send(Message::Binary(frame.into())).await.is_err() {
                                    debug!("WS sink closed during fragment send");
                                    return;
                                }
                            }
                            Err(e) => { error!("Encrypt error (fragment): {e}"); return; }
                        }
                    }
                } else {
                    match encode_encrypted(send_cipher, MessageType::IpPacket, &packet, obf) {
                        Ok(frame) => {
                            if ws_sink.send(Message::Binary(frame.into())).await.is_err() {
                                debug!("WS sink closed");
                                break;
                            }
                        }
                        Err(e) => { error!("Encrypt error: {e}"); break; }
                    }
                }
            }
            _ = stop_rx.recv() => break,
        }
    }
}

/// WS → TUN: receive frames from client, decrypt, reassemble fragments if
/// needed, and forward complete IP packets to the TUN writer.
async fn forward_ws_to_tun<Stream>(
    ws_recv: &mut Stream,
    recv_cipher: &CipherState,
    tun_tx: mpsc::Sender<Vec<u8>>,
    session: Arc<crate::session::Session>,
    stop_rx: &mut tokio::sync::broadcast::Receiver<()>,
) where
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // In-order fragment reassembly buffer
    let mut fragment_buf: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            maybe_msg = ws_recv.next() => {
                let msg = match maybe_msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => { warn!("WS recv error: {e}"); break; }
                    None => { debug!("WS stream ended"); break; }
                };

                let data = match msg {
                    Message::Binary(b) => b,
                    Message::Close(_) => { debug!("WS Close received"); break; }
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => continue,
                };

                match decode_encrypted(recv_cipher, &data) {
                    Ok((MessageType::IpPacket, packet)) => {
                        session.touch();
                        if !fragment_buf.is_empty() {
                            warn!(session_id = %session.id, "Discarding {} bytes of incomplete fragment", fragment_buf.len());
                            fragment_buf.clear();
                        }
                        if tun_tx.send(packet).await.is_err() {
                            error!("TUN channel closed");
                            break;
                        }
                    }
                    Ok((MessageType::IpPacketFragment, fragment)) => {
                        session.touch();
                        fragment_buf.extend_from_slice(&fragment);
                        debug!(session_id = %session.id, "Fragment received ({} bytes, buf={} total)",
                            fragment.len(), fragment_buf.len());

                        // Flush if we have a complete IP packet
                        if let Ok(info) = common::packet::parse_ip_header(&fragment_buf) {
                            if fragment_buf.len() >= info.total_length {
                                let packet = fragment_buf[..info.total_length].to_vec();
                                fragment_buf.drain(..info.total_length);
                                debug!(session_id = %session.id, "Reassembled packet ({} bytes)", packet.len());
                                if tun_tx.send(packet).await.is_err() {
                                    error!("TUN channel closed (reassembled)");
                                    break;
                                }
                            }
                        }
                    }
                    Ok((MessageType::Heartbeat, _)) => {
                        session.touch();
                        debug!(session_id = %session.id, "Heartbeat received");
                    }
                    Ok((MessageType::Disconnect, _)) => {
                        info!(session_id = %session.id, "Client sent Disconnect");
                        break;
                    }
                    Ok((other, _)) => {
                        warn!("Unexpected message type: {other:?}");
                    }
                    Err(e) => {
                        warn!("Decrypt error: {e}");
                        break;
                    }
                }
            }
            _ = stop_rx.recv() => break,
        }
    }
}

/// Helper: receive the next binary WebSocket frame as raw bytes.
async fn recv_binary<Stream>(ws_recv: &mut Stream) -> Result<Vec<u8>>
where
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match ws_recv.next().await {
            Some(Ok(Message::Binary(b))) => return Ok(b.into()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(other)) => bail!("Expected binary frame, got: {other:?}"),
            Some(Err(e)) => bail!("WebSocket error: {e}"),
            None => bail!("WebSocket stream ended unexpectedly"),
        }
    }
}
