//! Raw IP packet parsing utilities.
//!
//! Extracts metadata from IPv4 and IPv6 packet headers without
//! pulling in a full networking stack dependency.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Errors when parsing an IP packet.
#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Packet too short: need at least {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("Unknown IP version: {0}")]
    UnknownVersion(u8),
}

/// Metadata extracted from an IP packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacketInfo {
    pub version: IpVersion,
    pub source: IpAddr,
    pub destination: IpAddr,
    /// Total packet length in bytes (as declared in the header).
    pub total_length: usize,
    /// IP protocol number (TCP=6, UDP=17, ICMP=1, etc.)
    pub protocol: u8,
}

/// IP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Parse the header of a raw IP packet (no Ethernet frame, no PI header).
///
/// Supports IPv4 and IPv6. Returns an error for malformed or truncated packets.
pub fn parse_ip_header(packet: &[u8]) -> Result<IpPacketInfo, PacketError> {
    if packet.is_empty() {
        return Err(PacketError::TooShort { need: 1, got: 0 });
    }

    let version = packet[0] >> 4;

    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        v => Err(PacketError::UnknownVersion(v)),
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<IpPacketInfo, PacketError> {
    // Minimum IPv4 header: 20 bytes
    const MIN_LEN: usize = 20;
    if packet.len() < MIN_LEN {
        return Err(PacketError::TooShort { need: MIN_LEN, got: packet.len() });
    }

    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let protocol = packet[9];
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Ok(IpPacketInfo {
        version: IpVersion::V4,
        source: IpAddr::V4(source),
        destination: IpAddr::V4(destination),
        total_length,
        protocol,
    })
}

fn parse_ipv6(packet: &[u8]) -> Result<IpPacketInfo, PacketError> {
    // Fixed IPv6 header: 40 bytes
    const MIN_LEN: usize = 40;
    if packet.len() < MIN_LEN {
        return Err(PacketError::TooShort { need: MIN_LEN, got: packet.len() });
    }

    let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_length = 40 + payload_length;
    let protocol = packet[6]; // Next Header field

    let src_bytes: [u8; 16] = packet[8..24].try_into().unwrap();
    let dst_bytes: [u8; 16] = packet[24..40].try_into().unwrap();

    Ok(IpPacketInfo {
        version: IpVersion::V6,
        source: IpAddr::V6(Ipv6Addr::from(src_bytes)),
        destination: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        total_length,
        protocol,
    })
}

/// On Linux, the TUN driver prepends a 4-byte Packet Information (PI) header
/// to each read when `IFF_NO_PI` is not set.
///
/// Layout: `[flags: u16 BE] [protocol: u16 BE] [IP packet...]`
///
/// This function strips the PI header and returns the raw IP packet slice.
/// Returns the original slice unchanged on non-Linux platforms.
#[inline]
pub fn strip_pi_header(buf: &[u8]) -> &[u8] {
    #[cfg(target_os = "linux")]
    {
        if buf.len() >= 4 {
            &buf[4..]
        } else {
            buf
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        buf
    }
}

/// Build a 4-byte Linux PI header for an IP packet before writing to TUN.
/// Detects IPv4 vs IPv6 from the first nibble of the packet.
#[inline]
pub fn make_pi_header(packet: &[u8]) -> [u8; 4] {
    let mut hdr = [0u8; 4];
    if !packet.is_empty() {
        let version = packet[0] >> 4;
        // EtherType: 0x0800 = IPv4, 0x86DD = IPv6
        if version == 6 {
            hdr[2] = 0x86;
            hdr[3] = 0xDD;
        } else {
            hdr[2] = 0x08;
            hdr[3] = 0x00;
        }
    }
    hdr
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid IPv4 packet: 20-byte header, no payload
    fn ipv4_packet(src: [u8; 4], dst: [u8; 4], proto: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2] = 0;
        pkt[3] = 20; // total length = 20
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt
    }

    #[test]
    fn test_parse_ipv4() {
        let pkt = ipv4_packet([10, 8, 0, 1], [10, 8, 0, 2], 6);
        let info = parse_ip_header(&pkt).unwrap();

        assert_eq!(info.version, IpVersion::V4);
        assert_eq!(info.source, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)));
        assert_eq!(info.destination, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(info.protocol, 6); // TCP
        assert_eq!(info.total_length, 20);
    }

    #[test]
    fn test_parse_ipv4_too_short() {
        let short = vec![0x45u8; 10];
        assert!(matches!(
            parse_ip_header(&short),
            Err(PacketError::TooShort { need: 20, got: 10 })
        ));
    }

    #[test]
    fn test_parse_ipv6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version=6
        pkt[4] = 0;
        pkt[5] = 0; // payload length = 0
        pkt[6] = 17; // UDP
        pkt[8..24].copy_from_slice(&[0u8; 16]); // src ::
        pkt[24..40].copy_from_slice(&[0u8; 16]); // dst ::
        let info = parse_ip_header(&pkt).unwrap();

        assert_eq!(info.version, IpVersion::V6);
        assert_eq!(info.protocol, 17);
        assert_eq!(info.total_length, 40);
    }

    #[test]
    fn test_unknown_version() {
        let pkt = vec![0x30u8; 20]; // version=3, unknown
        assert!(matches!(parse_ip_header(&pkt), Err(PacketError::UnknownVersion(3))));
    }

    #[test]
    fn test_empty_packet() {
        assert!(matches!(
            parse_ip_header(&[]),
            Err(PacketError::TooShort { need: 1, got: 0 })
        ));
    }

    #[test]
    fn test_strip_pi_header() {
        let buf = [0x00, 0x00, 0x08, 0x00, 0x45, 0x00];
        let stripped = strip_pi_header(&buf);
        // On Linux this removes the first 4 bytes; on other platforms it's a no-op
        #[cfg(target_os = "linux")]
        assert_eq!(stripped, &[0x45, 0x00]);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(stripped.len(), buf.len());
    }

    #[test]
    fn test_make_pi_header_ipv4() {
        let pkt = ipv4_packet([1, 2, 3, 4], [5, 6, 7, 8], 1);
        let hdr = make_pi_header(&pkt);
        assert_eq!(hdr, [0x00, 0x00, 0x08, 0x00]);
    }

    #[test]
    fn test_make_pi_header_ipv6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        let hdr = make_pi_header(&pkt);
        assert_eq!(hdr, [0x00, 0x00, 0x86, 0xDD]);
    }
}
