//! Wire protocol: message types, frame format, and serialization.
//!
//! ## Frame layout (over WebSocket binary frames)
//!
//! ```text
//! ┌────────────┬────────────────┬──────────────┬──────────────────────┐
//! │  2 bytes   │   12 bytes     │   2 bytes    │       N bytes        │
//! │  version   │    nonce       │ padding_size │  encrypted payload   │
//! └────────────┴────────────────┴──────────────┴──────────────────────┘
//! ```
//!
//! The encrypted payload contains:
//! ```text
//! [ MessageType (1 byte) | body (variable) | random padding (padding_size bytes) ]
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const FRAME_HEADER_SIZE: usize = 2 + 12 + 2; // version + nonce + padding_size

/// Errors produced by protocol framing / parsing.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u16),

    #[error("Frame too short: need at least {FRAME_HEADER_SIZE} bytes, got {0}")]
    FrameTooShort(usize),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unknown message type: {0}")]
    UnknownMessageType(u8),
}

/// All message types exchanged between client and server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake: client sends its ephemeral public key.
    ClientHello = 0x01,
    /// Handshake: server responds with its ephemeral public key.
    ServerHello = 0x02,
    /// Client confirms the session is ready.
    ClientReady = 0x03,
    /// Server acknowledges; session is established.
    SessionEstablished = 0x04,
    /// A tunneled IP packet.
    IpPacket = 0x10,
    /// A fragment of a tunneled IP packet that exceeded the fragmentation
    /// threshold. Multiple consecutive fragments must be reassembled by the
    /// receiver before the payload can be interpreted as an IP packet.
    IpPacketFragment = 0x11,
    /// Keep-alive ping.
    Heartbeat = 0x20,
    /// Graceful disconnect notification.
    Disconnect = 0xFF,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerHello),
            0x03 => Ok(Self::ClientReady),
            0x04 => Ok(Self::SessionEstablished),
            0x10 => Ok(Self::IpPacket),
            0x11 => Ok(Self::IpPacketFragment),
            0x20 => Ok(Self::Heartbeat),
            0xFF => Ok(Self::Disconnect),
            other => Err(ProtocolError::UnknownMessageType(other)),
        }
    }
}

/// Handshake message from the client to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Client's ephemeral X25519 public key (32 bytes).
    pub ephemeral_public_key: [u8; 32],
    /// Protocol version the client supports.
    pub version: u16,
}

/// Handshake response from the server to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    /// Server's ephemeral X25519 public key (32 bytes).
    pub ephemeral_public_key: [u8; 32],
    /// Unique session identifier assigned by the server.
    pub session_id: [u8; 16],
}

/// Client confirmation that it has derived the session key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientReady {
    /// Session ID echoed back to the server.
    pub session_id: [u8; 16],
}

/// Server confirmation that the session is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEstablished {
    /// IP address assigned to the client for the tunnel (e.g. 10.0.0.2).
    pub assigned_ip: [u8; 4],
    /// Subnet mask for the VPN network (e.g. 255.255.255.0 for /24).
    pub subnet_mask: [u8; 4],
}

/// A raw, unencrypted frame header parsed from the wire.
#[derive(Debug)]
pub struct FrameHeader {
    pub version: u16,
    pub nonce: [u8; 12],
    pub padding_size: u16,
}

impl FrameHeader {
    /// Parse a frame header from the beginning of `data`.
    /// Returns the header and a slice of the remaining bytes (the payload).
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), ProtocolError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(ProtocolError::FrameTooShort(data.len()));
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[2..14]);

        let padding_size = u16::from_be_bytes([data[14], data[15]]);

        let header = Self { version, nonce, padding_size };
        let payload = &data[FRAME_HEADER_SIZE..];

        Ok((header, payload))
    }

    /// Serialize this header into a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_SIZE);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.padding_size.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_roundtrip() {
        let header = FrameHeader {
            version: PROTOCOL_VERSION,
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            padding_size: 42,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), FRAME_HEADER_SIZE);

        let (parsed, remaining) = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.nonce, header.nonce);
        assert_eq!(parsed.padding_size, 42);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_frame_too_short_returns_error() {
        let short = vec![0u8; 4];
        assert!(matches!(
            FrameHeader::parse(&short),
            Err(ProtocolError::FrameTooShort(4))
        ));
    }

    #[test]
    fn test_unsupported_version_returns_error() {
        let mut bytes = FrameHeader {
            version: PROTOCOL_VERSION,
            nonce: [0u8; 12],
            padding_size: 0,
        }
        .to_bytes();

        // Overwrite version with an unsupported value
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;

        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(ProtocolError::UnsupportedVersion(0xFFFF))
        ));
    }

    #[test]
    fn test_message_type_roundtrip() {
        let types = [
            MessageType::ClientHello,
            MessageType::ServerHello,
            MessageType::ClientReady,
            MessageType::SessionEstablished,
            MessageType::IpPacket,
            MessageType::IpPacketFragment,
            MessageType::Heartbeat,
            MessageType::Disconnect,
        ];

        for msg_type in &types {
            let byte = msg_type.clone() as u8;
            let parsed = MessageType::try_from(byte).unwrap();
            assert_eq!(&parsed, msg_type);
        }
    }

    #[test]
    fn test_unknown_message_type_returns_error() {
        assert!(matches!(
            MessageType::try_from(0x42),
            Err(ProtocolError::UnknownMessageType(0x42))
        ));
    }
}
