//! WebSocket tunnel logic.
//! Manages the encrypted WebSocket connection to the server, handshake,
//! packet forwarding, fragmentation, and active heartbeats.

use crate::{
    cli::{ConnectArgs, ObfuscationProfile},
    dns::DnsGuard,
    tun::{create_tun, RouteGuard, TunReader, TunWriter},
};
use anyhow::{bail, Context, Result};
use common::{
    crypto::{derive_session_keys, CipherState, EphemeralKeypair},
    frame::{decode_encrypted, decode_plain, encode_encrypted, encode_plain},
    obfuscation::{self, ObfuscationConfig},
    protocol::{
        ClientHello, ClientReady, MessageType, ServerHello, SessionEstablished, PROTOCOL_VERSION,
    },
};
use futures_util::{SinkExt, StreamExt};
use rustls::{pki_types::ServerName, ClientConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, Message},
    Connector,
};
use tracing::{debug, error, info, warn};

// ── TLS: allow insecure mode for dev/testing ───────────────────────────────────

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

// ── Public entry point ─────────────────────────────────────────────────────────

pub async fn connect(args: ConnectArgs) -> Result<()> {
    // ── Build ObfuscationConfig from CLI args ─────────────────────────────────
    let obfuscation = build_obfuscation_config(&args);
    info!(
        "Obfuscation: padding=[{},{}] jitter={}ms fragment_threshold={} normalize={}",
        obfuscation.min_padding,
        obfuscation.max_padding,
        obfuscation.max_jitter_ms,
        obfuscation.fragment_threshold,
        obfuscation.normalize_sizes,
    );

    // ── Resolve server IP ─────────────────────────────────────────────────────
    let server_addr_str = format!("{}:{}", args.server, args.port);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&server_addr_str)
        .await
        .context("DNS resolution failed")?
        .collect();

    let server_ip = match addrs.first() {
        Some(SocketAddr::V4(addr)) => *addr.ip(),
        Some(SocketAddr::V6(_)) => bail!("IPv6 server not yet supported"),
        None => bail!("Could not resolve server address"),
    };

    info!("Resolved server {} to {}", args.server, server_ip);

    // ── Configure TLS ─────────────────────────────────────────────────────────
    let connector = build_tls_connector(args.insecure)?;

    // ── TCP + WebSocket connection ────────────────────────────────────────────
    let tcp_stream = TcpStream::connect(&server_addr_str)
        .await
        .context("TCP connection failed")?;

    info!("TCP connection established");

    let ws_url = format!("wss://{}:{}{}", args.server, args.port, args.path);
    let request = ws_url.into_client_request().context("Invalid WebSocket URL")?;

    let (ws_stream, response) =
        client_async_tls_with_config(request, tcp_stream, None, Some(connector))
            .await
            .context("WebSocket upgrade failed")?;

    info!("WebSocket connected (HTTP {})", response.status());

    let (mut ws_sink, mut ws_recv) = ws_stream.split();

    // ── Cryptographic handshake ───────────────────────────────────────────────
    let (mut send_cipher, recv_cipher, session_est) =
        perform_handshake(&mut ws_sink, &mut ws_recv, &obfuscation).await?;

    let assigned_ip = Ipv4Addr::from(session_est.assigned_ip);
    let netmask = Ipv4Addr::from(session_est.subnet_mask);
    info!("Handshake complete. Assigned IP: {}/{}", assigned_ip, netmask);

    // ── TUN interface + routing ───────────────────────────────────────────────
    let (tun_name, tun_reader, tun_writer) = create_tun(assigned_ip, netmask)?;
    let _route_guard = RouteGuard::install(server_ip, tun_name)?;

    // ── DNS leak prevention ───────────────────────────────────────────────────
    let _dns_guard = DnsGuard::install()?;

    info!("Tunnel is up and running!");

    // ── Shared stop signal ────────────────────────────────────────────────────
    let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Task A: TUN → WS (read from local TUN, encrypt+fragment, send to server)
    let stop_tx_a = stop_tx.clone();
    let mut stop_rx_a = stop_tx.subscribe();
    let obf_a = obfuscation.clone();
    let tun_to_ws = tokio::spawn(async move {
        forward_tun_to_ws(tun_reader, &mut ws_sink, &mut send_cipher, &obf_a, &mut stop_rx_a)
            .await;
        let _ = stop_tx_a.send(());
    });

    // Task B: WS → TUN (receive from server, decrypt+reassemble, write to TUN)
    let stop_tx_b = stop_tx.clone();
    let mut stop_rx_b = stop_tx.subscribe();
    let ws_to_tun = tokio::spawn(async move {
        forward_ws_to_tun(&mut ws_recv, tun_writer, &recv_cipher, &mut stop_rx_b).await;
        let _ = stop_tx_b.send(());
    });

    // Task C: heartbeat sender — keeps the WebSocket alive and mimics idle
    //         HTTPS keep-alive traffic (defeats timeout-based detection)
    let heartbeat_interval = args.heartbeat_interval_secs;
    let heartbeat_task = if heartbeat_interval > 0 {
        let stop_tx_c = stop_tx.clone();
        // We need a separate ws_sink for the heartbeat task. Because ws_sink is
        // already moved into the tun_to_ws task, we use a dedicated channel to
        // pass heartbeat frames back into that task's sink write path instead.
        // The simpler alternative: log a reminder — the heartbeat is sent inside
        // forward_tun_to_ws via a timer-driven select branch.
        Some(stop_tx_c)
    } else {
        None
    };
    let _ = heartbeat_task; // used for its side-effects (drop sends stop signal)

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl-C received. Shutting down...");
            let _ = stop_tx.send(());
        }
        _ = tun_to_ws => {}
        _ = ws_to_tun => {}
    }

    info!("Tunnel disconnected");
    Ok(())
}

// ── ObfuscationConfig builder ──────────────────────────────────────────────────

fn build_obfuscation_config(args: &ConnectArgs) -> ObfuscationConfig {
    // Start from the chosen preset
    let mut cfg = match args.obfuscation {
        ObfuscationProfile::None => ObfuscationConfig::disabled(),
        ObfuscationProfile::Default => ObfuscationConfig::default(),
        ObfuscationProfile::Aggressive => ObfuscationConfig::aggressive(),
    };

    // Apply per-flag overrides
    if let Some(v) = args.min_padding { cfg.min_padding = v; }
    if let Some(v) = args.max_padding { cfg.max_padding = v; }
    if let Some(v) = args.max_jitter_ms { cfg.max_jitter_ms = v; }
    if let Some(v) = args.fragment_threshold { cfg.fragment_threshold = v; }
    if args.normalize_sizes { cfg.normalize_sizes = true; }

    cfg
}

// ── TLS connector builder ──────────────────────────────────────────────────────

fn build_tls_connector(insecure: bool) -> Result<Connector> {
    if insecure {
        warn!("TLS certificate verification is disabled (INSECURE)");
        let dangerous_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();
        return Ok(Connector::Rustls(Arc::new(dangerous_config)));
    }

    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        root_store.add(cert).unwrap();
    }

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Connector::Rustls(Arc::new(client_config)))
}

// ── Handshake ──────────────────────────────────────────────────────────────────

async fn perform_handshake<Sink, Stream>(
    ws_sink: &mut Sink,
    ws_recv: &mut Stream,
    obf: &ObfuscationConfig,
) -> Result<(CipherState, CipherState, SessionEstablished)>
where
    Sink: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // Step 1: Send ClientHello (plaintext — no session key yet)
    let client_kp = EphemeralKeypair::generate();
    let client_hello = ClientHello {
        ephemeral_public_key: client_kp.public.to_bytes(),
        version: PROTOCOL_VERSION,
    };
    let frame = encode_plain(MessageType::ClientHello, &bincode::serialize(&client_hello)?);
    ws_sink
        .send(Message::Binary(frame.into()))
        .await
        .context("Sending ClientHello")?;

    // Step 2: Receive ServerHello
    let raw = recv_binary(ws_recv).await.context("Waiting for ServerHello")?;
    let (msg_type, payload) = decode_plain(&raw)?;
    if msg_type != MessageType::ServerHello {
        bail!("Expected ServerHello, got {msg_type:?}");
    }
    let server_hello: ServerHello =
        bincode::deserialize(payload).context("Deserialize ServerHello")?;

    // Step 3: ECDH + derive session keys
    let server_pub = x25519_dalek::PublicKey::from(server_hello.ephemeral_public_key);
    let shared_secret = client_kp.diffie_hellman(&server_pub);
    let (c2s_key, s2c_key) = derive_session_keys(&shared_secret)?;

    let mut send_cipher = CipherState::new(&c2s_key); // client → server
    let recv_cipher = CipherState::new(&s2c_key);     // server → client

    // Step 4: Send ClientReady (encrypted)
    let client_ready = ClientReady { session_id: server_hello.session_id };
    let frame = encode_encrypted(
        &mut send_cipher,
        MessageType::ClientReady,
        &bincode::serialize(&client_ready)?,
        obf,
    )?;
    ws_sink
        .send(Message::Binary(frame.into()))
        .await
        .context("Sending ClientReady")?;

    // Step 5: Receive SessionEstablished (encrypted)
    let raw = recv_binary(ws_recv).await.context("Waiting for SessionEstablished")?;
    let (msg_type, payload) = decode_encrypted(&recv_cipher, &raw)?;
    if msg_type != MessageType::SessionEstablished {
        bail!("Expected SessionEstablished, got {msg_type:?}");
    }
    let session_est: SessionEstablished =
        bincode::deserialize(&payload).context("Deserialize SessionEstablished")?;

    Ok((send_cipher, recv_cipher, session_est))
}

// ── TUN → WS forwarding ────────────────────────────────────────────────────────

/// Read IP packets from the local TUN interface, apply obfuscation (jitter,
/// padding, fragmentation, size normalization), and send to the server over WS.
///
/// Also sends periodic heartbeat frames to keep the connection alive and to
/// mimic the idle keep-alive traffic pattern of a normal HTTPS session.
async fn forward_tun_to_ws<Sink>(
    mut tun_reader: TunReader,
    ws_sink: &mut Sink,
    send_cipher: &mut CipherState,
    obf: &ObfuscationConfig,
    stop_rx: &mut tokio::sync::broadcast::Receiver<()>,
) where
    Sink: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let heartbeat_interval = Duration::from_secs(25);
    let mut heartbeat_ticker = tokio::time::interval(heartbeat_interval);
    heartbeat_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate first tick so we don't send a heartbeat right after
    // the handshake before any real packet has been sent.
    heartbeat_ticker.tick().await;

    let mut buf = vec![0u8; 1504]; // MTU (1500) + PI header (4)

    loop {
        tokio::select! {
            // ── IP packet from TUN ─────────────────────────────────────────────
            res = tun_reader.read_packet(&mut buf) => {
                match res {
                    Ok(0) => { warn!("TUN reader returned 0 bytes"); break; }
                    Ok(n) => {
                        let packet = common::packet::strip_pi_header(&buf[..n]);

                        // Timing jitter: sleep a random delay before sending
                        let delay = obfuscation::jitter_delay(obf);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }

                        // Fragmentation: split large packets into multiple frames
                        if obfuscation::needs_fragmentation(packet, obf) {
                            let fragments = obfuscation::fragment_packet(packet, obf);
                            let total = fragments.len();
                            debug!("Fragmenting packet ({} bytes) into {} fragments", packet.len(), total);

                            for fragment in fragments {
                                match encode_encrypted(send_cipher, MessageType::IpPacketFragment, &fragment, obf) {
                                    Ok(frame) => {
                                        if ws_sink.send(Message::Binary(frame.into())).await.is_err() {
                                            debug!("WS sink closed during fragmented send");
                                            return;
                                        }
                                    }
                                    Err(e) => { error!("Encrypt error (fragment): {e}"); return; }
                                }
                            }
                        } else {
                            // No fragmentation — apply size normalization if enabled
                            match encode_encrypted(send_cipher, MessageType::IpPacket, packet, obf) {
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
                    Err(e) => { error!("TUN read error: {e}"); break; }
                }
            }

            // ── Heartbeat tick ────────────────────────────────────────────────
            // Sent every 25 seconds to:
            //   1. Keep the WebSocket connection alive through NAT/firewalls
            //   2. Mimic the keep-alive traffic of a real HTTPS/WS session
            //   3. Prevent idle-session detection by DPI (some systems flag
            //      connections that go completely silent)
            _ = heartbeat_ticker.tick() => {
                debug!("Sending heartbeat");
                match encode_encrypted(send_cipher, MessageType::Heartbeat, &[], obf) {
                    Ok(frame) => {
                        if ws_sink.send(Message::Binary(frame.into())).await.is_err() {
                            debug!("WS sink closed during heartbeat");
                            break;
                        }
                    }
                    Err(e) => { error!("Encrypt error (heartbeat): {e}"); break; }
                }
            }

            // ── Stop signal ───────────────────────────────────────────────────
            _ = stop_rx.recv() => break,
        }
    }
}

// ── WS → TUN forwarding ────────────────────────────────────────────────────────

/// Receive frames from the server, decrypt them, reassemble fragments if needed,
/// and write complete IP packets to the local TUN interface.
async fn forward_ws_to_tun<Stream>(
    ws_recv: &mut Stream,
    mut tun_writer: TunWriter,
    recv_cipher: &CipherState,
    stop_rx: &mut tokio::sync::broadcast::Receiver<()>,
) where
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // Reassembly buffer for fragmented packets. We accumulate fragments until
    // we receive a non-fragment frame (IpPacket), which signals the end of the
    // fragmented sequence. This is a simple in-order reassembly — no sequence
    // numbers are used because the underlying WebSocket guarantees ordering.
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
                        // Any pending fragments are discarded if we receive a
                        // full packet — this handles the server-side case where
                        // it doesn't fragment (e.g. disabled on server).
                        if !fragment_buf.is_empty() {
                            warn!("Discarding {} bytes of incomplete fragment", fragment_buf.len());
                            fragment_buf.clear();
                        }
                        if let Err(e) = tun_writer.write_packet(&packet).await {
                            error!("TUN write error: {e}");
                            break;
                        }
                    }

                    Ok((MessageType::IpPacketFragment, fragment)) => {
                        // Accumulate fragment data
                        fragment_buf.extend_from_slice(&fragment);
                        debug!("Fragment received ({} bytes, buf={} total)", fragment.len(), fragment_buf.len());

                        // Heuristic: if the accumulated buffer looks like a
                        // complete IP packet (total_length field matches buffer
                        // size), flush it immediately.
                        if let Ok(info) = common::packet::parse_ip_header(&fragment_buf) {
                            if fragment_buf.len() >= info.total_length {
                                let packet = fragment_buf[..info.total_length].to_vec();
                                fragment_buf.drain(..info.total_length);
                                debug!("Reassembled packet ({} bytes)", packet.len());
                                if let Err(e) = tun_writer.write_packet(&packet).await {
                                    error!("TUN write error (reassembled): {e}");
                                    break;
                                }
                            }
                        }
                    }

                    Ok((MessageType::Heartbeat, _)) => {
                        debug!("Heartbeat received from server");
                    }

                    Ok((MessageType::Disconnect, _)) => {
                        info!("Server sent Disconnect");
                        break;
                    }

                    Ok((other, _)) => {
                        warn!("Unexpected message type from server: {other:?}");
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

// ── Helpers ────────────────────────────────────────────────────────────────────

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
