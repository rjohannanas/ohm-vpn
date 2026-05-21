//! WebSocket tunnel logic.
//! Manages the encrypted WebSocket connection to the server, handshake, and packet forwarding.

use crate::{
    cli::ConnectArgs,
    tun::{create_tun, RouteGuard, TunReader, TunWriter},
    dns::DnsGuard,
};
use anyhow::{bail, Context, Result};
use common::{
    crypto::{derive_session_keys, CipherState, EphemeralKeypair},
    frame::{decode_encrypted, decode_plain, encode_encrypted, encode_plain},
    obfuscation::ObfuscationConfig,
    protocol::{ClientHello, ClientReady, MessageType, ServerHello, SessionEstablished, PROTOCOL_VERSION},
};
use futures_util::{SinkExt, StreamExt};
use rustls::{pki_types::ServerName, ClientConfig};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, Message},
    Connector,
};
use tracing::{debug, error, info, warn};

/// Implement a dummy verifier for the --insecure flag
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

pub async fn connect(args: ConnectArgs) -> Result<()> {
    // 1. Resolve server IP
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

    // 2. Configure TLS
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        root_store.add(cert).unwrap();
    }

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if args.insecure {
        warn!("TLS certificate verification is disabled (INSECURE)");
        let mut dangerous_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();
        client_config = dangerous_config;
    }

    let connector = Connector::Rustls(Arc::new(client_config));

    // 3. Connect TCP
    let tcp_stream = TcpStream::connect(server_addr_str.clone())
        .await
        .context("TCP connection failed")?;

    info!("TCP connection established");

    // 4. WebSocket upgrade
    let ws_url = format!("wss://{}:{}{}", args.server, args.port, args.path);
    let request = ws_url.into_client_request().context("Invalid WebSocket URL")?;
    
    let (ws_stream, response) = client_async_tls_with_config(request, tcp_stream, None, Some(connector))
        .await
        .context("WebSocket upgrade failed")?;

    info!("WebSocket connected (HTTP {})", response.status());

    let (mut ws_sink, mut ws_recv) = ws_stream.split();
    let obfuscation = ObfuscationConfig::default(); // TODO: Add CLI args for obfuscation

    // 5. Handshake
    let (mut send_cipher, recv_cipher, session_est) = perform_handshake(
        &mut ws_sink,
        &mut ws_recv,
        &obfuscation,
    )
    .await?;

    let assigned_ip = Ipv4Addr::from(session_est.assigned_ip);
    let netmask = Ipv4Addr::from(session_est.subnet_mask);

    info!("Handshake complete. Assigned IP: {}/{}", assigned_ip, netmask);

    // 6. Setup TUN and routing
    let (tun_reader, tun_writer) = create_tun(assigned_ip, netmask)?;
    let _route_guard = RouteGuard::install(server_ip)?;

    // 7. Setup DNS leak prevention
    let _dns_guard = DnsGuard::install()?;

    info!("Tunnel is up and running!");

    // 8. Forwarding tasks
    let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let stop_tx_a = stop_tx.clone();
    let mut stop_rx_a = stop_tx.subscribe();
    let mut obf_a = obfuscation.clone();
    let tun_to_ws = tokio::spawn(async move {
        forward_tun_to_ws(tun_reader, &mut ws_sink, &mut send_cipher, &obf_a, &mut stop_rx_a).await;
        let _ = stop_tx_a.send(());
    });

    let stop_tx_b = stop_tx.clone();
    let mut stop_rx_b = stop_tx.subscribe();
    let ws_to_tun = tokio::spawn(async move {
        forward_ws_to_tun(&mut ws_recv, tun_writer, &recv_cipher, &mut stop_rx_b).await;
        let _ = stop_tx_b.send(());
    });

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

async fn perform_handshake<Sink, Stream>(
    ws_sink: &mut Sink,
    ws_recv: &mut Stream,
    obf: &ObfuscationConfig,
) -> Result<(CipherState, CipherState, SessionEstablished)>
where
    Sink: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    // Step 1: Send ClientHello
    let client_kp = EphemeralKeypair::generate();
    let client_pub_bytes = client_kp.public.to_bytes();

    let client_hello = ClientHello {
        ephemeral_public_key: client_pub_bytes,
        version: PROTOCOL_VERSION,
    };
    let hello_bytes = bincode::serialize(&client_hello)?;
    let frame = encode_plain(MessageType::ClientHello, &hello_bytes);
    ws_sink.send(Message::Binary(frame.into())).await.context("Sending ClientHello")?;

    // Step 2: Receive ServerHello
    let raw = recv_binary(ws_recv).await.context("Waiting for ServerHello")?;
    let (msg_type, payload) = decode_plain(&raw)?;
    if msg_type != MessageType::ServerHello {
        bail!("Expected ServerHello, got {msg_type:?}");
    }
    let server_hello: ServerHello = bincode::deserialize(payload).context("Deserialize ServerHello")?;

    // Step 3: ECDH
    let server_pub = x25519_dalek::PublicKey::from(server_hello.ephemeral_public_key);
    let shared_secret = client_kp.diffie_hellman(&server_pub);
    let (c2s_key, s2c_key) = derive_session_keys(&shared_secret)?;

    // Client sends to server → c2s key
    let mut send_cipher = CipherState::new(&c2s_key);
    // Client receives from server → s2c key
    let recv_cipher = CipherState::new(&s2c_key);

    // Step 4: Send ClientReady
    let client_ready = ClientReady { session_id: server_hello.session_id };
    let ready_bytes = bincode::serialize(&client_ready)?;
    let frame = encode_encrypted(&mut send_cipher, MessageType::ClientReady, &ready_bytes, obf)?;
    ws_sink.send(Message::Binary(frame.into())).await.context("Sending ClientReady")?;

    // Step 5: Receive SessionEstablished
    let raw = recv_binary(ws_recv).await.context("Waiting for SessionEstablished")?;
    let (msg_type, payload) = decode_encrypted(&recv_cipher, &raw)?;
    if msg_type != MessageType::SessionEstablished {
        bail!("Expected SessionEstablished, got {msg_type:?}");
    }
    let session_est: SessionEstablished = bincode::deserialize(&payload).context("Deserialize SessionEstablished")?;

    Ok((send_cipher, recv_cipher, session_est))
}

async fn forward_tun_to_ws<Sink>(
    mut tun_reader: TunReader,
    ws_sink: &mut Sink,
    send_cipher: &mut CipherState,
    obf: &ObfuscationConfig,
    stop_rx: &mut tokio::sync::broadcast::Receiver<()>,
) where
    Sink: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let mut buf = vec![0u8; 1504]; // MTU + PI header safety
    loop {
        tokio::select! {
            res = tun_reader.read_packet(&mut buf) => {
                match res {
                    Ok(0) => { warn!("TUN reader returned 0 bytes"); break; }
                    Ok(n) => {
                        let packet = common::packet::strip_pi_header(&buf[..n]);
                        
                        let delay = common::obfuscation::jitter_delay(obf);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }

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
                    Err(e) => { error!("TUN read error: {e}"); break; }
                }
            }
            _ = stop_rx.recv() => break,
        }
    }
}

async fn forward_ws_to_tun<Stream>(
    ws_recv: &mut Stream,
    mut tun_writer: TunWriter,
    recv_cipher: &CipherState,
    stop_rx: &mut tokio::sync::broadcast::Receiver<()>,
) where
    Stream: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
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
                    Message::Ping(_) => continue,
                    _ => continue,
                };

                match decode_encrypted(recv_cipher, &data) {
                    Ok((MessageType::IpPacket, packet)) => {
                        if let Err(e) = tun_writer.write_packet(&packet).await {
                            error!("TUN write error: {e}");
                            break;
                        }
                    }
                    Ok((MessageType::Heartbeat, _)) => {
                        debug!("Heartbeat received");
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
