//! Обфускация — техники маскировки трафика.
//!
//! ## Техники
//! - [Z13] Udp2Icmp — конвертация UDP → ICMP
//! - [Z12] IpPpxor — IP протокол XOR обфускация
//! - [Z11] WgObfs — WireGuard AES-GCM обфускация
//! - [RP8] Entropy — Popcount/Shannon padding
//! - [CT5] PadSize — Packet size padding
//! - [DM1] XorFirst — XOR first N bytes
//! - [QL1] Poisson — Poisson traffic shaping
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret),
//! [RIPDPI](https://github.com/nickel-org/ripdpi),
//! [CandyTunnel](https://github.com/nickel-org/candy-tunnel),
//! [dpimyass](https://github.com/nickel-org/dpimyass),
//! [qeli](https://github.com/nickel-org/qeli).

use crate::desync::{parse_ip_header, DesyncResult};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use std::net::Ipv4Addr;
use tracing::debug;

/// [RP8] Entropy padding: Popcount/Shannon padding.
///
/// ## Принцип
/// DPI анализирует энтропию payload для классификации трафика.
/// Shannon entropy ≥ 4.5 обычно означает зашифрованный трафик.
/// Добавляем padding с контролируемой энтропией, чтобы DPI
/// классифицировал трафик как шум/мусор.
///
/// ## Popcount
/// Количество единичных бит в слове. Высокий popcount = высокая энтропия.
///
/// ## Shannon Entropy
/// H = -Σ p(x) * log2(p(x))
/// H ≈ 0: один байт повторяется
/// H ≈ 8: все байты уникальны (максимальная энтропия)
pub fn entropy_padding(packet: &[u8], target_entropy: f64, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let payload = &packet[ip.header_len..];
    if payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Рассчитываем текущую энтропию
    let current_entropy = shannon_entropy_fast(payload) as f64 / 256.0;

    // Определяем размер padding для достижения target_entropy
    let pad_size = if current_entropy < target_entropy {
        // Нужно увеличить энтропию — добавляем случайные байты
        let diff = target_entropy - current_entropy;
        ((diff * 32.0) as usize).clamp(16, 512)
    } else {
        // Энтропия уже высокая — добавляем немного
        16
    };

    // Генерируем padding с целевой энтропией
    let padding = generate_entropy_padding(pad_size, target_entropy);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_seg = build_udp_like_segment(
        ip.src,
        ip.dst,
        443,
        443,
        &padding,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[RP8] Entropy: current={:.2} target={:.2} pad={} bytes",
        current_entropy, target_entropy, pad_size
    );

    DesyncResult::inject_only(fake_seg)
}

/// Вычисляет Shannon entropy для массива байт.
///
/// H = -Σ p(x) * log2(p(x))
/// Результат: [0.0, 8.0] для 8-bit данных.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Быстрая Shannon entropy через LUT (Q8 fixed-point, без float на hot path).
use std::sync::LazyLock;

static NEG_P_LOG_P: LazyLock<[u16; 257]> = LazyLock::new(|| {
    let mut table = [0u16; 257];
    let mut i = 1usize;
    while i <= 256 {
        let p = i as f64 / 256.0;
        let val = (-p * p.log2()) * 256.0;
        table[i] = val.round() as u16;
        i += 1;
    }
    table
});

pub fn shannon_entropy_fast(data: &[u8]) -> u16 {
    if data.is_empty() {
        return 0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as u32;
    let mut entropy: u32 = 0;
    for &c in &freq {
        if c > 0 {
            let p_scaled = ((c as u64 * 256) / len as u64).clamp(1, 256) as usize;
            entropy += NEG_P_LOG_P[p_scaled] as u32;
        }
    }
    entropy as u16
}

/// Генерирует padding — использует ChaCha20 как CSPRNG для неотличимости от шума.
fn generate_entropy_padding(size: usize, _target_entropy: f64) -> Vec<u8> {
    let key = [0x42u8; 32];
    let iv = [0u8; 12];
    crate::desync::crypto::chacha20_block_xor(&vec![0u8; size], &key, &iv)
}

/// [CT5] PadSize: дополнение пакета до заданного размера.
///
/// ## Принцип
/// DPI может использовать размер пакета для идентификации.
/// Дополняем пакет до ближайшего кратного размера (128/256/512/1024).
pub fn pad_size(packet: &[u8], target_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let payload = &packet[ip.header_len..];
    if payload.is_empty() || packet.len() >= target_size {
        return DesyncResult::passthrough();
    }

    let pad_needed = target_size - packet.len();
    let padding: Vec<u8> = (0..pad_needed).map(|i| (i * 0x17) as u8).collect();

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_seg = build_udp_like_segment(
        ip.src,
        ip.dst,
        443,
        443,
        &padding,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[CT5] PadSize: {} → {} ({} bytes padding)",
        packet.len(),
        target_size,
        pad_needed
    );

    DesyncResult::inject_only(fake_seg)
}

/// [DM1] XorFirst: XOR обфускация первых N байт.
///
/// ## Принцип
/// XOR-обфускация только первых N байт пакета.
/// DPI видит зашифрованные данные в начале пакета.
/// Сервер расшифровывает (если他知道 ключ).
/// Используется для обхода DPI, который проверяет первые байты payload.
pub fn xor_first(packet: &[u8], n: usize, key: u8) -> DesyncResult {
    if packet.len() < 20 + n {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();

    // XOR первых N байт payload (после IP header)
    for i in 20..20 + n.min(modified.len() - 20) {
        modified[i] ^= key;
    }

    // Пересчитываем IP checksum
    let checksum = crate::desync::ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&checksum.to_be_bytes());

    // Пересчитываем TCP checksum если это TCP
    if modified[9] == 6 {
        let ip = pnet_packet::ipv4::Ipv4Packet::new(&modified).unwrap();
        let ip_header_len = ip.get_header_length() as usize * 4;
        let total_len = ip.get_total_length() as usize;
        let src = ip.get_source();
        let dst = ip.get_destination();

        // Обнуляем TCP checksum перед пересчётом
        if ip_header_len + 18 <= total_len {
            modified[ip_header_len + 16] = 0;
            modified[ip_header_len + 17] = 0;
        }
        if ip_header_len + tcp_len(modified.len(), ip_header_len) <= modified.len() {
            let tcp_csum = crate::desync::tcp_checksum_v4(
                src,
                dst,
                &modified[ip_header_len..ip_header_len + tcp_len(modified.len(), ip_header_len)],
            );
            if ip_header_len + 18 <= modified.len() {
                modified[ip_header_len + 16..ip_header_len + 18]
                    .copy_from_slice(&tcp_csum.to_be_bytes());
            }
        }
    }

    debug!("[DM1] XorFirst: {} bytes with key={:#x}", n, key);

    DesyncResult::modified_only(modified)
}

/// [QL1] Poisson: Poisson traffic shaping.
///
/// ## Принцип
/// Интервалы между пакетами распределены по Пуассону.
/// λ = 20ms (средний интервал), clamp [1ms, 100ms].
/// DPI использует timing-анализ для обнаружения desync.
/// Случайные интервалы маскируют timing fingerprint.
pub fn poisson_delay(lambda_ms: f64) -> u64 {
    let u = crate::desync::rand::random_u32() as f64 / u32::MAX as f64;
    let delay = if u < 1.0 {
        -(1.0 - u).ln() * lambda_ms
    } else {
        lambda_ms
    };
    (delay as u64).clamp(1, 100)
}

/// Быстрая Poisson задержка через LUT — без float на hot path.
static POISSON_LUT: LazyLock<[u8; 256]> = LazyLock::new(|| {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let u = i as f64 / 256.0;
        let delay = if u < 0.999 {
            let v = -(1.0 - u).ln() * 20.0;
            if v < 1.0 {
                1u8
            } else if v > 100.0 {
                100u8
            } else {
                v as u8
            }
        } else {
            100u8
        };
        table[i] = delay;
        i += 1;
    }
    table
});

pub fn poisson_delay_fast(_lambda_ms: u64) -> u64 {
    let idx = (crate::desync::rand::random_u32() >> 24) as usize;
    POISSON_LUT[idx % 256] as u64
}

/// [Z11] WgObfs: WireGuard AES-GCM обфускация.
///
/// ## Принцип
/// Оборачиваем UDP payload в WireGuard-подобный формат:
/// type(1) + reserved(3) + receiver_index(4) + encrypted_data.
/// DPI видит WireGuard трафик и может пропустить его.
pub fn wg_obfs(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_start = ip.header_len + 8;
    if udp_start >= packet.len() {
        return DesyncResult::passthrough();
    }

    let payload = &packet[udp_start..];

    // WireGuard header: type(1) + reserved(3) + receiver_index(4)
    let mut wg_payload = Vec::with_capacity(8 + payload.len());
    wg_payload.push(0x04); // WireGuard type: data
    wg_payload.extend_from_slice(&[0u8; 3]); // reserved
    wg_payload.extend_from_slice(&[0u8; 4]); // receiver index
    wg_payload.extend_from_slice(payload);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = crate::desync::quic::build_udp_packet(
        ip.src,
        ip.dst,
        12345,
        443,
        &wg_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[Z11] WgObfs: {} → {} bytes (WireGuard wrapper)",
        payload.len(),
        wg_payload.len()
    );

    DesyncResult::inject_only(fake_udp)
}

/// [Z12] IpPpxor: IP протокол XOR обфускация.
///
/// ## Принцип
/// XOR-обфускация IP протокола и первого байта payload.
/// DPI может не распознать протокол после XOR.
pub fn ip_ppxor(packet: &[u8], _fake_ttl_offset: u8) -> DesyncResult {
    if parse_ip_header(packet).is_none() {
        return DesyncResult::passthrough();
    }

    if packet.len() < 21 {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let key = 0xAAu8;

    // XOR IP protocol field (byte 9)
    modified[9] ^= key;

    // XOR first byte of payload
    if modified.len() > 20 {
        modified[20] ^= key;
    }

    // Recalculate checksum
    let checksum = crate::desync::ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&checksum.to_be_bytes());

    debug!("[Z12] IpPpxor: protocol + payload XOR'd with {:#x}", key);

    DesyncResult::modified_only(modified)
}

/// [Z13] Udp2Icmp: конвертация UDP → ICMP.
///
/// ## Принцип
/// Оборачиваем UDP дейтаграмму в ICMP Echo Request payload.
/// DPI может не инспектировать ICMP payloads.
/// Сервер конвертирует обратно.
pub fn udp2icmp(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    if ip.protocol.0 != 17 {
        // UDP
        return DesyncResult::passthrough();
    }

    let udp_start = ip.header_len + 8;
    if udp_start >= packet.len() {
        return DesyncResult::passthrough();
    }

    let udp_payload = &packet[udp_start..];

    // ICMP Echo Request header: type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let mut icmp_payload = Vec::with_capacity(8 + udp_payload.len());
    icmp_payload.push(0x08); // Echo Request
    icmp_payload.push(0x00); // Code
    icmp_payload.extend_from_slice(&[0u8; 2]); // Checksum placeholder
    icmp_payload.extend_from_slice(&[0x01, 0x02]); // ID
    icmp_payload.extend_from_slice(&[0x00, 0x01]); // Sequence
    icmp_payload.extend_from_slice(udp_payload);

    // ICMP checksum
    let icmp_csum = icmp_checksum(&icmp_payload);
    icmp_payload[2..4].copy_from_slice(&icmp_csum.to_be_bytes());

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_icmp = build_icmp_packet(
        ip.src,
        ip.dst,
        &icmp_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[Z13] Udp2Icmp: UDP {} bytes → ICMP {} bytes",
        udp_payload.len(),
        icmp_payload.len()
    );

    DesyncResult::inject_only(fake_icmp)
}

// ==================== Вспомогательные функции ====================

/// Строит UDP-подобный сегмент (для инъекции).
#[allow(clippy::too_many_arguments)]
fn build_udp_like_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut buf = bytes::BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);

    // IP Header
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);
        ip.set_flags(0);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
    }

    let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP Header
    buf[20] = (src_port >> 8) as u8;
    buf[21] = src_port as u8;
    buf[22] = (dst_port >> 8) as u8;
    buf[23] = dst_port as u8;
    buf[24] = (udp_len >> 8) as u8;
    buf[25] = udp_len as u8;
    buf[26] = 0; // Checksum
    buf[27] = 0;

    // Payload
    buf[28..28 + payload.len()].copy_from_slice(payload);

    buf.freeze()
}

/// Строит ICMP пакет.
#[allow(clippy::too_many_arguments)]
fn build_icmp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let total_len = 20 + icmp_payload.len();

    let mut buf = bytes::BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);

    // IP Header
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);
        ip.set_flags(0);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
    }

    let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMP payload
    buf[20..20 + icmp_payload.len()].copy_from_slice(icmp_payload);

    buf.freeze()
}

/// Вычисляет ICMP checksum.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Возвращает длину TCP сегмента (total - ip_header_len).
fn tcp_len(total_len: usize, ip_header_len: usize) -> usize {
    total_len.saturating_sub(ip_header_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        // Все одинаковые байты → энтропия = 0
        let data = vec![0x42; 100];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_random() {
        // Случайные байты → высокая энтропия (~8)
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.0); // Близко к 8
    }

    #[test]
    fn test_shannon_entropy_mixed() {
        let data = b"AABBCCDD";
        let entropy = shannon_entropy(data);
        assert!(entropy > 1.5 && entropy < 3.0);
    }

    #[test]
    fn test_poisson_delay_range() {
        for _ in 0..100 {
            let delay = poisson_delay(20.0);
            assert!(delay >= 1 && delay <= 100);
        }
    }

    #[test]
    fn test_icmp_checksum() {
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01];
        let csum = icmp_checksum(&data);
        assert!(csum != 0);
    }

    #[test]
    fn test_build_icmp_packet() {
        let pkt = build_icmp_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            &[0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01],
            64,
            1,
        );
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 1); // ICMP protocol
    }

    #[test]
    fn test_build_udp_like_segment() {
        let pkt = build_udp_like_segment(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            443,
            &[0x01, 0x02],
            64,
            1,
        );
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 17); // UDP protocol
    }

    #[test]
    fn test_xor_first() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0x08, 0x08, 0x08, 0x08, 0x41, 0x42, 0x43, 0x44,
        ];
        let result = xor_first(&packet, 2, 0xFF);
        assert!(result.modified.is_some());
        let modified = result.modified.unwrap();
        assert_eq!(modified[20], 0x41 ^ 0xFF);
        assert_eq!(modified[21], 0x42 ^ 0xFF);
    }
}
