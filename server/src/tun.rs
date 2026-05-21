//! Server-side TUN interface: creation, split read/write, background tasks.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::mpsc,
};
use tracing::{error, warn};
use tun::AsyncDevice;

use crate::routing::{Router, READ_BUF_SIZE};

pub struct TunReader(ReadHalf<AsyncDevice>);
pub struct TunWriter(WriteHalf<AsyncDevice>);

/// Create the server TUN interface. Requires `CAP_NET_ADMIN`.
pub fn create_tun(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<(TunReader, TunWriter)> {
    let mut config = tun::Configuration::default();
    config.name(name).address(address).netmask(netmask).mtu(1500u16).up();

    let device = tun::create_as_async(&config)
        .with_context(|| format!("Failed to create TUN '{name}' — CAP_NET_ADMIN required"))?;

    tracing::info!("TUN '{name}' up: {address}/{netmask}");
    let (r, w) = tokio::io::split(device);
    Ok((TunReader(r), TunWriter(w)))
}

impl TunReader {
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.0.read(buf).await.context("TUN read error")?)
    }
}

impl TunWriter {
    pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.0.write_all(packet).await.context("TUN write error")
    }
}

/// Spawn background task: reads TUN packets and routes them to client sessions.
pub fn spawn_tun_reader_task(mut reader: TunReader, router: Router) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF_SIZE];
        loop {
            match reader.read_packet(&mut buf).await {
                Ok(0) => { warn!("TUN reader: 0 bytes — interface closed"); break; }
                Ok(n) => { router.route_to_client(&buf[..n]).await; }
                Err(e) => { error!("TUN reader error: {e}"); break; }
            }
        }
        error!("TUN reader task exited");
    })
}

/// Spawn background task: receives packets from sessions via channel and writes to TUN.
pub fn spawn_tun_writer_task(mut writer: TunWriter) -> (mpsc::Sender<Vec<u8>>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(512);
    let handle = tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if let Err(e) = writer.write_packet(&packet).await {
                error!("TUN write error: {e}");
                break;
            }
        }
        error!("TUN writer task exited");
    });
    (tx, handle)
}
