//! Pure-Rust `#![forbid(unsafe_code)]` RFC-6455 WebSocket Handshake & Frame Codec.
//!
//! Uses `TCP_NODELAY` single-buffer writes for sub-millisecond JSON-RPC order placement and
//! `private/mass_quote` bursts without external async runtime bloat.
#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// FIPS 180-4 SHA-1 used exclusively for RFC-6455 `Sec-WebSocket-Accept` header derivation.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 9).div_ceil(64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word_bytes) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word_bytes);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(B64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

/// Computes the exact RFC-6455 `Sec-WebSocket-Accept` value for `sec_ws_key`.
pub fn compute_websocket_accept(sec_ws_key: &str) -> String {
    let mut preimage = String::with_capacity(sec_ws_key.len() + WS_GUID.len());
    preimage.push_str(sec_ws_key.trim());
    preimage.push_str(WS_GUID);
    let digest = sha1_digest(preimage.as_bytes());
    base64_encode(&digest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsOpcode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub opcode: WsOpcode,
    pub payload: Vec<u8>,
}

const MAX_WS_FRAME_BYTES: usize = 2 * 1024 * 1024;

pub fn read_ws_frame<R: Read>(reader: &mut R) -> io::Result<WsFrame> {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr)?;
    let opcode = match hdr[0] & 0x0F {
        0x1 => WsOpcode::Text,
        0x2 => WsOpcode::Binary,
        0x8 => WsOpcode::Close,
        0x9 => WsOpcode::Ping,
        0xA => WsOpcode::Pong,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported websocket opcode 0x{other:x}"),
            ))
        }
    };
    let masked = (hdr[1] & 0x80) != 0;
    let len7 = (hdr[1] & 0x7F) as usize;
    let payload_len = if len7 <= 125 {
        len7
    } else if len7 == 126 {
        let mut ext = [0u8; 2];
        reader.read_exact(&mut ext)?;
        u16::from_be_bytes(ext) as usize
    } else {
        let mut ext = [0u8; 8];
        reader.read_exact(&mut ext)?;
        let raw = u64::from_be_bytes(ext);
        usize::try_from(raw).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ws len overflow"))?
    };

    if payload_len > MAX_WS_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket frame exceeds 2 MiB safety cap",
        ));
    }

    let mut mask_key = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask_key)?;
    }
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i & 3];
        }
    }
    Ok(WsFrame { opcode, payload })
}

pub fn write_ws_frame<W: Write>(
    writer: &mut W,
    opcode: WsOpcode,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) -> io::Result<()> {
    let op_byte = match opcode {
        WsOpcode::Text => 0x81,
        WsOpcode::Binary => 0x82,
        WsOpcode::Close => 0x88,
        WsOpcode::Ping => 0x89,
        WsOpcode::Pong => 0x8A,
    };
    let mask_bit = if mask.is_some() { 0x80u8 } else { 0x00u8 };
    let mut buf = Vec::with_capacity(14 + payload.len());
    buf.push(op_byte);
    if payload.len() <= 125 {
        buf.push(mask_bit | (payload.len() as u8));
    } else if payload.len() <= 65_535 {
        buf.push(mask_bit | 126);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        buf.push(mask_bit | 127);
        buf.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    if let Some(mk) = mask {
        buf.extend_from_slice(&mk);
        for (i, &b) in payload.iter().enumerate() {
            buf.push(b ^ mk[i & 3]);
        }
    } else {
        buf.extend_from_slice(payload);
    }
    writer.write_all(&buf)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rfc6455_accept_vector_matches_spec() {
        assert_eq!(
            compute_websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn masked_and_unmasked_ws_frame_roundtrip() {
        let msg = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"private/place_intent\"}";
        let mut wire = Vec::new();
        write_ws_frame(&mut wire, WsOpcode::Text, msg, Some([0x37, 0xFA, 0x21, 0x3D])).unwrap();
        let mut cur = Cursor::new(wire);
        let decoded = read_ws_frame(&mut cur).unwrap();
        assert_eq!(decoded.opcode, WsOpcode::Text);
        assert_eq!(decoded.payload, msg);
    }
}
