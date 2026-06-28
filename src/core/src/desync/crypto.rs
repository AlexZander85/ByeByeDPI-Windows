//! Крипто-обфускация — шифрование пакетов.
//!
//! ## Техники
//! - [CT2] ChaCha20 — per-packet шифрование через ChaCha20
//! - [CT6] XorFec — XOR Forward Error Correction
//!
//! ## Источник
//! Адаптировано из [CandyTunnel](https://github.com/nickel-org/candy-tunnel).

use crate::desync::{parse_ip_header, DesyncResult};
use tracing::debug;

/// [CT2] ChaCha20: per-packet шифрование.
///
/// ## Принцип
/// Шифруем payload пакета через ChaCha20 с уникальным nonce для каждого пакета.
/// DPI видит зашифрованные данные и не может классифицировать трафик.
/// Сервер расшифровывает (если他知道 ключ).
///
/// ## Важно
/// Это обфускация, не криптографическая защита. Nonce детерминирован
/// (SEQ + timestamp), чтобы сервер мог восстановить порядок.
///
/// ## Алгоритм
/// 1. Берём TCP payload (после заголовков)
/// 2. Генерируем nonce из packet sequence number (8 байт)
/// 3. Шифруем payload через ChaCha20 (RFC 8439)
/// 4. Заменяем payload на зашифрованный
pub fn chacha20_encrypt(packet: &[u8], key: &[u8; 32]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    if ip.protocol.0 != 6 {
        return DesyncResult::passthrough();
    }

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 8 {
        return DesyncResult::passthrough();
    }

    // Nonce: 8 байт из sequence number + 4 нуля (total 12 for ChaCha20-Poly1305)
    let seq = tcp.get_sequence();
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&seq.to_be_bytes());

    // ChaCha20 encryption (RFC 8439, simplified)
    let encrypted = chacha20_block_xor(payload, key, &nonce);

    let mut modified = packet.to_vec();
    let payload_start = ip.header_len + data_offset;
    if payload_start + encrypted.len() <= modified.len() {
        modified[payload_start..payload_start + encrypted.len()].copy_from_slice(&encrypted);
    }

    // Recalculate TCP checksum
    let tcp_start = ip.header_len;
    let tcp_len = modified.len() - tcp_start;
    if tcp_len > 18 {
        modified[tcp_start + 16] = 0;
        modified[tcp_start + 17] = 0;
    }
    let tcp_csum =
        crate::desync::tcp_checksum_v4(ip.src, ip.dst, &modified[tcp_start..tcp_start + tcp_len]);
    modified[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    debug!("[CT2] ChaCha20: {} bytes encrypted", payload.len());

    DesyncResult::modified_only(modified)
}

/// [CT6] XorFec: XOR Forward Error Correction.
///
/// ## Принцип
/// XOR-based FEC: k данных + n parity пакетов.
/// Если до сервера дошли все k данных — parity не нужны.
/// Если DPI заблокировал часть данных — parity восстанавливают потерю.
///
/// ## Алгоритм
/// 1. Берём k пакетов данных
/// 2. XOR'им их payload → parity пакет
/// 3. Отправляем parity через alternate path
/// 4. Сервер может восстановить丢失数据 через XOR
pub fn xorfec_encode(packets: &[Vec<u8>], parity_index: usize) -> Vec<u8> {
    if packets.is_empty() {
        return Vec::new();
    }

    // XOR всех payload'ов → parity
    let mut parity = packets[0].clone();
    for pkt in packets.iter().skip(1) {
        let max_len = parity.len().max(pkt.len());
        parity.resize(max_len, 0);
        for (i, byte) in pkt.iter().enumerate() {
            if i < parity.len() {
                parity[i] ^= byte;
            }
        }
    }

    debug!(
        "[CT6] XorFec: {} packets → parity #{}",
        packets.len(),
        parity_index
    );
    parity
}

/// Восстановление丢失数据 через XOR.
pub fn xorfec_decode(received: &[Vec<u8>], parity: &[u8], missing_index: usize) -> Option<Vec<u8>> {
    if received.is_empty() {
        return None;
    }

    // XOR всех полученных + parity → восстановленный пакет
    let mut result = parity.to_vec();
    for pkt in received {
        let max_len = result.len().max(pkt.len());
        result.resize(max_len, 0);
        for (i, byte) in pkt.iter().enumerate() {
            if i < result.len() {
                result[i] ^= byte;
            }
        }
    }

    debug!("[CT6] XorFec decode: recovered packet #{}", missing_index);
    Some(result)
}

/// ChaCha20 quarter-round (RFC 8439).
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function (RFC 8439).
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];

    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (8 × u32)
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    // Counter
    state[12] = counter;

    // Nonce (3 × u32)
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let initial_state = state;

    // 20 rounds (10 double rounds)
    for _ in 0..10 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }

    // Serialize to bytes
    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = state[i].to_le_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    output
}

/// ChaCha20 XOR encryption (simplified, no Poly1305).
pub fn chacha20_block_xor(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let mut output = data.to_vec();
    let blocks = data.len().div_ceil(64);

    for block_idx in 0..blocks {
        let keystream = chacha20_block(key, block_idx as u32, nonce);
        let start = block_idx * 64;
        let end = (start + 64).min(data.len());
        for i in start..end {
            output[i] ^= keystream[i - start];
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_block() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let block = chacha20_block(&key, 0, &nonce);
        assert_eq!(block.len(), 64);
        // First block with zero key should produce known output
        assert_ne!(block, [0u8; 64]);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello, ChaCha20!";
        let encrypted = chacha20_block_xor(plaintext, &key, &nonce);
        let decrypted = chacha20_block_xor(&encrypted, &key, &nonce);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xorfec_roundtrip() {
        let p1 = vec![0x01, 0x02, 0x03, 0x04];
        let p2 = vec![0x05, 0x06, 0x07, 0x08];
        let parity_data = xorfec_encode(&[p1.clone(), p2], 0);
        assert_eq!(
            parity_data,
            vec![0x01 ^ 0x05, 0x02 ^ 0x06, 0x03 ^ 0x07, 0x04 ^ 0x08]
        );
    }

    #[test]
    fn test_xorfec_recovery() {
        let p1 = vec![0xAA, 0xBB];
        let p2 = vec![0xCC, 0xDD];
        let parity = xorfec_encode(&[p1.clone(), p2.clone()], 0);
        // Recover p1 from p2 + parity
        let recovered = xorfec_decode(&[p2], &parity, 0).unwrap();
        assert_eq!(recovered, p1);
    }
}
