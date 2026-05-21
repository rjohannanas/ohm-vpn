//! Frame encoding/decoding for the StealthVPN wire protocol.
//!
//! **Unencrypted** (handshake only): `[msg_type: u8][payload]`
//! **Encrypted** (post-handshake): `[version: u16][nonce: 12 B][padding_size: u16][ciphertext]`
//!   where ciphertext decrypts to `[msg_type: u8][payload][padding]`

use anyhow::{bail, Result};
use crate::{
    crypto::CipherState,
    obfuscation::{apply_padding, strip_padding, ObfuscationConfig},
    protocol::{FrameHeader, MessageType, PROTOCOL_VERSION},
};

/// Build an unencrypted handshake frame: `[msg_type][payload]`.
pub fn encode_plain(msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(msg_type as u8);
    buf.extend_from_slice(payload);
    buf
}

/// Parse an unencrypted handshake frame.
pub fn decode_plain(data: &[u8]) -> Result<(MessageType, &[u8])> {
    if data.is_empty() {
        bail!("Empty plain frame");
    }
    let msg_type = MessageType::try_from(data[0])?;
    Ok((msg_type, &data[1..]))
}

/// Encrypt and frame a message for transmission.
pub fn encode_encrypted(
    cipher: &mut CipherState,
    msg_type: MessageType,
    payload: &[u8],
    obf: &ObfuscationConfig,
) -> Result<Vec<u8>> {
    // Plaintext: [msg_type][payload][random padding][normalization padding]
    let mut plaintext = Vec::with_capacity(1 + payload.len() + obf.max_padding + 4096);
    plaintext.push(msg_type as u8);
    plaintext.extend_from_slice(payload);

    // Both padding steps are counted together so the receiver can strip them all.
    let mut total_padding = apply_padding(&mut plaintext, obf) as usize;
    if obf.normalize_sizes {
        total_padding += crate::obfuscation::normalize_to_bucket(&mut plaintext);
    }

    let (nonce, ciphertext) = cipher.encrypt(&plaintext)?;

    let header = FrameHeader { version: PROTOCOL_VERSION, nonce, padding_size: total_padding as u16 };
    let mut frame = header.to_bytes();
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

/// Decrypt a received frame. Returns `(MessageType, payload)` without padding.
pub fn decode_encrypted(cipher: &CipherState, data: &[u8]) -> Result<(MessageType, Vec<u8>)> {
    let (header, ciphertext) = FrameHeader::parse(data)?;
    let mut plaintext = cipher.decrypt(&header.nonce, ciphertext)?;
    strip_padding(&mut plaintext, header.padding_size);

    if plaintext.is_empty() {
        bail!("Decrypted payload is empty");
    }
    let msg_type = MessageType::try_from(plaintext[0])?;
    Ok((msg_type, plaintext[1..].to_vec()))
}
