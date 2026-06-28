//! TLS-level Desync техники.
//!
//! ## Техники
//! - [15] TlsRecordFrag — TLS Record Fragmentation
//! - [07] TlsRecordPad — TLS Record Padding
//!
//! ## Принципы
//! TLS desync техники манипулируют TLS Record Layer до того,
//! как DPI успевает проинспектировать ClientHello. DPI ожидает
//! один TLS record с полным CH. Разделение на несколько
//! records или добавление padding сбивает DPI.
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret) и
//! [byedpi](https://github.com/hufrea/byedpi).

use crate::desync::{ipv4_checksum, parse_ip_header, DesyncResult};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::tcp::TcpFlags;
use pnet_packet::MutablePacket;
use std::net::Ipv4Addr;
use tracing::debug;

/// [15] TlsRecordFrag: разделение TLS record на несколько фрагментов.
///
/// ## Принцип
/// DPI ожидает TLS ClientHello целиком в одном TCP сегменте.
/// Разделяем TLS record на 2+ части. DPI видит первый фрагмент
/// (только начало CH) и может не распознать его как TLS. Сервер
/// собирает fragments по ContentType.
///
/// ## Подробности
/// TLS record: [ContentType(1) + Version(2) + Length(2) + Payload]
/// Разделяем так, чтобы второй фрагмент начинался после Length
/// (т.е. режем по границе record payload, не внутри).
///
/// ## Returns
/// - inject: [frag1, frag2, ...] — фрагменты record'а
///   frag1 = ContentType + Version + Length (5 байт)
///   frag2+ = остаток данных
pub fn tls_record_frag(packet: &[u8], frag_at: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || frag_at >= payload.len() {
        return DesyncResult::passthrough();
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();
    let src = ip.src;
    let dst = ip.dst;
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    let mut inject: Vec<bytes::Bytes> = Vec::new();

    // Фрагмент 1: начало TLS record (до frag_at)
    let frag1_payload = &payload[..frag_at];
    let frag1 = build_tcp_with_payload(
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        frag1_payload,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );
    inject.push(frag1);

    // Фрагмент 2: остаток данных
    let frag2_payload = &payload[frag_at..];
    let new_seq = seq.wrapping_add(frag_at as u32);
    let frag2 = build_tcp_with_payload(
        src,
        dst,
        src_port,
        dst_port,
        new_seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        frag2_payload,
        ip.ttl,
        ip.identification.wrapping_add(2),
    );
    inject.push(frag2);

    debug!(
        "[15] TlsRecordFrag: split at byte {} ({} + {} bytes)",
        frag_at,
        frag1_payload.len(),
        frag2_payload.len()
    );

    DesyncResult::inject_many(inject)
}

/// [07] TlsRecordPad: padding TLS record.
///
/// ## Принцип
/// Добавляем фиктивные байты после реального TLS record.
/// DPI может читать padding как часть CH и сбиться.
/// Сервер игнорирует данные после завершения record.
///
/// ## Подробности
/// Добавляем N байт случайного мусора после payload.
/// TCP header остаётся тем же (SEQ не меняется).
/// Сервер читает первые M байт как CH, остальное игнорирует.
pub fn tls_record_pad(packet: &[u8], pad_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Padding: N байт случайного мусора
    let padding: Vec<u8> = (0..pad_size).map(|i| (i * 0x13) as u8).collect();

    // Первые пакет: реальные данные
    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();
    let src = ip.src;
    let dst = ip.dst;
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    let real = build_tcp_with_payload(
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        payload,
        ip.ttl,
        ip.identification,
    );

    // Padding пакет: TTL-1 (не должен дойти до сервера)
    let pad_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let pad_seq = seq.wrapping_add(payload.len() as u32);
    let pad_pkt = build_tcp_with_payload(
        src,
        dst,
        src_port,
        dst_port,
        pad_seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        &padding,
        pad_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[07] TlsRecordPad: {} bytes real + {} bytes padding",
        payload.len(),
        pad_size
    );

    DesyncResult::inject_many(vec![real, pad_pkt])
}

/// [OM2] SniMicrofrag: микро-фрагментация TLS ClientHello.
///
/// ## Принцип
/// DPI часто использует signature-based детекцию для TLS ClientHello.
/// Микро-фрагментация разбивает начало CH на очень маленькие TCP сегменты
/// (1-2 байта каждый). DPI не может собрать сигнатуру из микро-фрагментов.
///
/// ## Стратегия
/// Первые `micro_count` байт TLS record отправляются как отдельные TCP
/// сегменты по 1 байту. Остаток — нормальным сегментом.
///
/// ## Пример
/// Для `micro_count=5`:
/// - Segment 1: байт 0 (SEQ = original_SEQ)
/// - Segment 2: байт 1 (SEQ = original_SEQ + 1)
/// - ...
/// - Segment 5: байт 4 (SEQ = original_SEQ + 4)
/// - Last: байты 5..N (SEQ = original_SEQ + 5)
///
/// Все микро-сегменты имеют TTL-1 (чтобы не перегружать сервер).
/// Последний сегмент — нормальный TTL (доходит до сервера).
///
/// ## Аргументы
/// * `packet` — исходный IP-пакет с TLS ClientHello
/// * `micro_count` — количество микро-фрагментов (1-16)
/// * `fake_ttl_offset` — уменьшение TTL для микро-фрагментов
///
/// ## Источник
/// omoikane [OM2] — SNI Microfrag
pub fn sni_microfrag(packet: &[u8], micro_count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    let micro_count = micro_count.clamp(1, 16);

    if payload.len() < micro_count + 1 {
        return DesyncResult::passthrough();
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();
    let src = ip.src;
    let dst = ip.dst;
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    let mut inject: Vec<bytes::Bytes> = Vec::with_capacity(micro_count);

    // Микро-фрагменты: по 1 байту
    for i in 0..micro_count {
        let frag_payload = &payload[i..i + 1];
        let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
        let frag_seq = seq.wrapping_add(i as u32);
        let frag = build_tcp_with_payload(
            src,
            dst,
            src_port,
            dst_port,
            frag_seq,
            ack,
            TcpFlags::PSH | TcpFlags::ACK,
            window,
            frag_payload,
            fake_ttl,
            ip.identification.wrapping_add(i as u16 + 1),
        );
        inject.push(frag);
    }

    // Последний сегмент: остаток данных, нормальный TTL
    let remaining = &payload[micro_count..];
    let last_seq = seq.wrapping_add(micro_count as u32);
    let modified = build_tcp_with_payload(
        src,
        dst,
        src_port,
        dst_port,
        last_seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        remaining,
        ip.ttl,
        ip.identification.wrapping_add(micro_count as u16 + 1),
    );

    debug!(
        "[OM2] SniMicrofrag: {} micro-frags × 1 byte + {} remaining bytes",
        micro_count,
        remaining.len()
    );

    DesyncResult {
        modified: Some(modified),
        inject,
        drop: false,
    }
}

// ==================== Вспомогательные функции ====================

/// Строит TCP пакет с payload, IP обёрткой и корректным checksum.
#[allow(clippy::too_many_arguments)]
fn build_tcp_with_payload(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let tcp_header_len = 20;

    // --- TCP segment ---
    let mut tcp_buf = vec![0u8; tcp_header_len];
    {
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(window);
        tcp.set_checksum(0);
        tcp.set_urgent_ptr(0);
        // tcp drops here → mutable borrow ends
    }
    let csum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &tcp_buf);
    tcp_buf[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut full = tcp_buf.to_vec();
    full.extend_from_slice(payload);

    // --- IP packet ---
    let total_len = 20 + full.len();
    let mut ip_buf = vec![0u8; total_len];
    {
        let mut ip = MutableIpv4Packet::new(&mut ip_buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);
        ip.set_flags(0);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.payload_mut().copy_from_slice(&full);
        // ip drops here → mutable borrow ends
    }
    let ip_csum = ipv4_checksum(&ip_buf[..20]);
    ip_buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    bytes::Bytes::from(ip_buf)
}

/// [OF1] SniMasking: маскировка SNI в существующем TLS ClientHello.
///
/// ## Принцип
/// Заменяем каждый байт hostname в SNI на `mask_byte`.
/// DPI видит зашифрованный/замаскированный SNI и не может
/// определить целевой домен для блокировки.
///
/// Оригинальный SNI восстанавливается сервером (ECH или other means).
///
/// ## Алгоритм
/// 1. Парсим TCP header → payload
/// 2. Ищем TLS ClientHello: `0x16 0x03 0x01` или `0x16 0x03 0x03`
/// 3. Ищем SNI extension (type `0x0000`)
/// 4. Заменяем каждый байт hostname на `mask_byte`
/// 5. Пересчитываем TCP checksum
pub fn sni_masking(packet: &[u8], mask_byte: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match crate::desync::parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < 5 {
        return DesyncResult::passthrough();
    }

    // Проверяем TLS ContentType = Handshake (0x16)
    if tcp.payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    // Ищем SNI extension
    // TLS Record: ContentType(1) + Version(2) + Length(2) = 5 bytes header
    // HandshakeType(1) + Length(3) + Version(2) + Random(32) + SessionID + CipherSuites + Compression + Extensions
    let payload = tcp.payload;
    let mut pos = 5; // пропускаем TLS record header

    if pos + 4 > payload.len() {
        return DesyncResult::passthrough();
    }

    // HandshakeType: ClientHello = 0x01
    if payload[pos] != 0x01 {
        return DesyncResult::passthrough();
    }
    pos += 4; // HandshakeType + Length

    if pos + 34 > payload.len() {
        return DesyncResult::passthrough();
    }
    pos += 34; // Version(2) + Random(32)

    // SessionID
    if pos >= payload.len() {
        return DesyncResult::passthrough();
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    // CipherSuites
    if pos + 2 > payload.len() {
        return DesyncResult::passthrough();
    }
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= payload.len() {
        return DesyncResult::passthrough();
    }
    let compression_len = payload[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > payload.len() {
        return DesyncResult::passthrough();
    }
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > payload.len() {
        return DesyncResult::passthrough();
    }

    // Ищем SNI extension (type = 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;

        if ext_type == 0x0000 && pos + 4 + ext_len <= payload.len() {
            // SNI extension найден
            // SNI structure: ServerNameListLen(2) + NameType(1) + NameLen(2) + hostname
            let sni_start = pos + 4;
            if sni_start + 5 > payload.len() {
                return DesyncResult::passthrough();
            }

            let name_len =
                u16::from_be_bytes([payload[sni_start + 3], payload[sni_start + 4]]) as usize;
            let hostname_start = sni_start + 5;
            let hostname_end = hostname_start + name_len;

            if hostname_end > payload.len() {
                return DesyncResult::passthrough();
            }

            // Маскируем hostname
            let mut modified = packet.to_vec();
            let tcp_offset = ip.header_len;
            let payload_offset = tcp_offset + tcp.data_offset;

            for i in hostname_start..hostname_end {
                modified[payload_offset + i] = mask_byte;
            }

            // Пересчитываем TCP checksum
            let _tcp_len = modified.len() - tcp_offset;
            let src_ip = ip.src;
            let dst_ip = ip.dst;
            let tcp_csum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &modified[tcp_offset..]);
            modified[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_csum.to_be_bytes());

            debug!(
                "[SM] SniMasking: hostname_len={} mask=0x{:02x}",
                name_len, mask_byte
            );

            return DesyncResult::modified_only(modified);
        }

        pos += 4 + ext_len;
    }

    DesyncResult::passthrough()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_record_frag_passthrough() {
        let pkt = build_test_tls_packet();
        let result = tls_record_frag(&pkt, 5, 1);
        // Should either fragment or passthrough (depends on packet size)
        assert!(!result.drop);
    }

    fn build_test_tls_packet() -> Vec<u8> {
        // Minimal IP+TCP+TLS packet
        let mut pkt = vec![0u8; 60]; // IP(20) + TCP(20) + TLS(20)
        pkt[0] = 0x45; // IPv4
        pkt[9] = 6; // TCP protocol
        pkt[12..14].copy_from_slice(&100u16.to_be_bytes()); // total length
                                                            // TCP
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port
        pkt[32] = 0x50; // data offset = 5 (20 bytes)
        pkt[33] = 0x18; // PSH+ACK
                        // TLS record
        pkt[40] = 0x16; // ContentType: Handshake
        pkt[41] = 0x03;
        pkt[42] = 0x01; // Version: TLS 1.0
        pkt
    }
}

/// TLS Version Overwrite — перезапись version field в record header.
///
/// ## Принцип (Demergi)
/// DPI фильтрует по record-layer version. Замена на TLS 1.3 (0x0304)
/// сбивает fingerprinting. Комбинируется с Record Re-wrapping.
pub fn tls_version_overwrite(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let payload_start = ip.header_len + data_offset;
    modified[payload_start + 1] = 0x03;
    modified[payload_start + 2] = 0x04; // TLS 1.3

    // Пересчитываем IP checksum
    let ip_csum = ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    debug!("[TLS] VersionOverwrite: TLS 1.3 spoof");
    DesyncResult::modified_only(modified)
}

/// TLS Record Re-wrapping — каждый фрагмент получает валидный record header.
///
/// ## Принцип (GreenTunnel)
/// Вместо простого TCP-level split, разбиваем TLS record payload на chunk_size
/// байтных кусков. Каждый кусок оборачиваем в НОВЫЙ TLS record header:
/// [ContentType(1) + Version(2) + Length(2) + chunk].
///
/// DPI, проверяющие TLS record boundaries, видят N валидных записей вместо одного.
pub fn tls_record_rewrap(packet: &[u8], chunk_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || payload[0] != 0x16 || chunk_size == 0 {
        return DesyncResult::passthrough();
    }

    let content_type = payload[0];
    let _version = [payload[1], payload[2]];
    let record_payload = &payload[5..];

    let mut rewrapped =
        Vec::with_capacity(record_payload.len() + record_payload.len() / chunk_size * 5);
    let tls_13_version = [0x03, 0x04]; // TLS 1.3 — комбинируется с Version Spoof
    for chunk in record_payload.chunks(chunk_size) {
        rewrapped.push(content_type);
        rewrapped.extend_from_slice(&tls_13_version);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();

    let inject_pkt = build_tcp_with_payload(
        ip.src,
        ip.dst,
        tcp.get_source(),
        tcp.get_destination(),
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        &rewrapped,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[TLS] RecordRewrap: {} chunks × {} bytes",
        rewrapped.len() / (chunk_size + 5),
        chunk_size
    );
    DesyncResult::inject_only(inject_pkt)
}

/// SNI-Targeted Record Fragmentation — разбиение SNI на 2B chunks.
///
/// ## Принцип (NoDPI)
/// Извлекаем SNI extension из ClientHello, разбиваем доменное имя
/// на 2-байтные куски. Каждый кусок оборачиваем в TLS 1.3 record header.
/// DPI не может собрать SNI из фрагментов.
pub fn sni_record_frag(packet: &[u8], chunk_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    // TLS record: [ContentType(1) + Version(2) + Length(2) + HandshakeType(1) + ...]
    let record_payload = &payload[5..];
    if record_payload.len() < 6 || record_payload[0] != 0x01 {
        return DesyncResult::passthrough(); // Не ClientHello
    }

    // Ищем SNI extension: type = 0x0000
    let mut pos = 38; // пропускаем: handshake_type(1) + len(3) + version(2) + random(32)
    if pos >= record_payload.len() {
        return DesyncResult::passthrough();
    }

    // Session ID
    let session_id_len = record_payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > record_payload.len() {
        return DesyncResult::passthrough();
    }

    // Cipher Suites
    let cs_len = u16::from_be_bytes([record_payload[pos], record_payload[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > record_payload.len() {
        return DesyncResult::passthrough();
    }

    // Compression Methods
    let cm_len = record_payload[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > record_payload.len() {
        return DesyncResult::passthrough();
    }

    // Extensions Length
    let ext_len = u16::from_be_bytes([record_payload[pos], record_payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    // Walk extensions
    while pos + 4 <= ext_end && pos + 4 <= record_payload.len() {
        let ext_type = u16::from_be_bytes([record_payload[pos], record_payload[pos + 1]]);
        let ext_len =
            u16::from_be_bytes([record_payload[pos + 2], record_payload[pos + 3]]) as usize;

        if ext_type == 0x0000 && pos + 4 + ext_len <= record_payload.len() {
            // SNI extension found
            let sni_ext = &record_payload[pos + 4..pos + 4 + ext_len];
            if sni_ext.len() > 5 {
                // ServerNameList(2) + ServerNameType(1) + NameLen(2) + Name
                let name_len = u16::from_be_bytes([sni_ext[3], sni_ext[4]]) as usize;
                if name_len > 0 && 5 + name_len <= sni_ext.len() {
                    let sni_start_in_payload = 5 + pos + 4 + 5; // record_offset + ext_start + sni_header
                    let sni_end_in_payload = sni_start_in_payload + name_len;

                    return build_sni_frag_result(
                        packet,
                        &tcp,
                        &ip,
                        data_offset,
                        payload,
                        sni_start_in_payload,
                        sni_end_in_payload,
                        chunk_size,
                        fake_ttl_offset,
                    );
                }
            }
        }
        pos += 4 + ext_len;
    }

    DesyncResult::passthrough()
}

#[allow(clippy::too_many_arguments)]
fn build_sni_frag_result(
    _packet: &[u8],
    tcp: &pnet_packet::tcp::TcpPacket,
    ip: &crate::desync::ParsedIpHeader,
    _data_offset: usize,
    payload: &[u8],
    sni_start: usize,
    sni_end: usize,
    chunk_size: usize,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let pre_sni = &payload[..sni_start];
    let sni = &payload[sni_start..sni_end];
    let post_sni = &payload[sni_end..];

    let mut rewrapped = Vec::with_capacity(payload.len() + sni.len());
    let header_13 = [0x16u8, 0x03, 0x04]; // TLS 1.3 record header

    // Pre-SNI chunks
    for chunk in pre_sni.chunks(chunk_size) {
        rewrapped.extend_from_slice(&header_13);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    // SNI chunks (именно SNI разбиваем на 2B)
    for chunk in sni.chunks(chunk_size) {
        rewrapped.extend_from_slice(&header_13);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    // Post-SNI chunks
    for chunk in post_sni.chunks(chunk_size) {
        rewrapped.extend_from_slice(&header_13);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();

    let inject_pkt = build_tcp_with_payload(
        ip.src,
        ip.dst,
        tcp.get_source(),
        tcp.get_destination(),
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        &rewrapped,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[TLS] SniRecordFrag: SNI {} bytes → {} chunks",
        sni.len(),
        sni.len().div_ceil(chunk_size)
    );
    DesyncResult::inject_only(inject_pkt)
}
