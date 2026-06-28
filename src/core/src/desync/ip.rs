//! IP-level Desync техники.
//!
//! ## Техники
//! - [W1] FragOverlap — IP fragmentation overlap
//! - [Z14] BadChecksum — намеренно неправильная контрольная сумма
//! - [19] TtlManipulation — манипуляция TTL
//! - [Z15] IpFragPrimitives — примитивы IP фрагментации
//!
//! ## Источник
//! Адаптировано из [dpibreak](https://github.com/hufrea/dpibreak) и
//! [zapret](https://github.com/bol-van/zapret).

use crate::desync::{ipv4_checksum, parse_ip_header, DesyncResult};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::MutablePacket;
use std::net::Ipv4Addr;
use tracing::debug;

/// [W1] FragOverlap: IP fragmentation с перекрытием.
///
/// ## Принцип
/// Отправляем два IP фрагмента с перекрывающимися offset'ами.
/// DPI собирает из фрагмента 1 (fake SNI). Сервер собирает
/// из фрагмента 2 (real SNI — имеет больший offset и перезаписывает).
///
/// ## Подробности
/// Фрагмент 1: offset=0, More Fragments=1 — содержит fake SNI
/// Фрагмент 2: offset=20 (в 8-байтовых единицах = 20/8 = 2),
///             More Fragments=0 — содержит реальные данные
///             offset=20 перекрывает байты 0-19 фрагмента 1
///
/// ## Returns
/// - modified: None (оригинал можно не менять)
/// - inject: [frag1, frag2] — два фрагмента
pub fn frag_overlap(packet: &[u8], fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let payload = &packet[ip.header_len..];

    if payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let fake_payload = build_fake_ch(fake_sni);

    // Фрагмент 1: fake CH, offset=0, MF=1, TTL-1
    let frag1_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let frag1 = build_ip_fragment(
        ip.src,
        ip.dst,
        ip.protocol,
        ip.identification.wrapping_add(1),
        0,
        true,
        frag1_ttl,
        &fake_payload,
    );

    // Динамический overlap_offset на основе TCP header length
    let tcp_start = ip.header_len;
    let tcp_header_len = if packet.len() > tcp_start + 12 {
        ((packet[tcp_start + 12] >> 4) & 0xF) as usize * 4
    } else {
        20
    };
    let overlap_offset = tcp_header_len;
    let frag2_offset_units = overlap_offset.div_ceil(8) as u16;

    let frag2 = build_ip_fragment(
        ip.src,
        ip.dst,
        ip.protocol,
        ip.identification.wrapping_add(1),
        frag2_offset_units,
        false,
        ip.ttl,
        payload,
    );

    debug!(
        "[W1] FragOverlap: fake {} overlapped at offset {}",
        fake_sni, overlap_offset
    );

    DesyncResult::inject_many(vec![frag1, frag2])
}

/// [Z14] BadChecksum: намеренно неправильная контрольная сумма.
///
/// ## Принцип
/// DPI часто проверяет целостность пакета по IP/TCP checksum.
/// Если checksum неправильный — DPI может отбросить пакет
/// и не инспектировать его содержимое. Сервер обычно всё
/// равно принимает (некоторые ОС игнорируют checksum).
///
/// ## Варианты
/// - TCP badsum: меняем TCP checksum на заведомо неверный
/// - IP badsum: меняем IP header checksum на неверный
pub fn bad_checksum(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let mut modified = packet.to_vec();

    let csum_offset = 10;
    if csum_offset + 2 <= modified.len() {
        let old_csum = u16::from_be_bytes([modified[csum_offset], modified[csum_offset + 1]]);
        let delta = crate::desync::rand::random_range(1, 65535) as u16;
        let new_csum = old_csum.wrapping_add(delta);
        modified[csum_offset..csum_offset + 2].copy_from_slice(&new_csum.to_be_bytes());
    }

    let tcp_checksum_offset = ip.header_len + 16;
    if tcp_checksum_offset + 2 <= modified.len() {
        let old_tcp_csum = u16::from_be_bytes([
            modified[tcp_checksum_offset],
            modified[tcp_checksum_offset + 1],
        ]);
        let delta = crate::desync::rand::random_range(1, 65535) as u16;
        let new_tcp_csum = old_tcp_csum.wrapping_add(delta);
        modified[tcp_checksum_offset..tcp_checksum_offset + 2]
            .copy_from_slice(&new_tcp_csum.to_be_bytes());
    }

    debug!("[Z14] BadChecksum: IP csum flipped, TCP csum flipped");

    DesyncResult::modified_only(modified)
}

/// [19] TtlManipulation: манипуляция TTL.
///
/// ## Принцип
/// Изменяем TTL в IP header пакета. Некоторые DPI используют
/// TTL для идентификации операционной системы или обнаружения
/// подозрительных пакетов.
///
/// ## Стратегии
/// - Установить TTL=64 (Linux default) — маскировка под Linux
/// - Установить TTL=128 (Windows default) — маскировка под Windows
/// - Случайный TTL в диапазоне [64, 128] — анти-DPI fingerprint
pub fn ttl_manipulation(packet: &[u8], new_ttl: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let mut modified = packet.to_vec();

    // TTL — байт 8 в IP header
    if 9 <= modified.len() {
        modified[8] = new_ttl;

        // Пересчитываем IP checksum
        let checksum = ipv4_checksum(&modified[..20]);
        modified[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    debug!("[19] TtlManipulation: TTL {} → {}", ip.ttl, new_ttl);

    DesyncResult::modified_only(modified)
}

/// [Z15] IpFragPrimitives: примитивы IP фрагментации.
///
/// ## Принцип
/// Разделяем TCP сегмент на несколько IP фрагментов. DPI может
/// не собрать фрагменты правильно, что приведёт к пропуску
/// DPI-инспекции.
///
/// ## Стратегии
/// - Каждый фрагмент = 1 байт TCP payload — максимальная фрагментация
/// - Первый фрагмент = fake SNI, остальные = реальные данные
/// - Чередование правильных и bad checksum фрагментов
pub fn ip_frag_primitives(packet: &[u8], frag_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let payload = &packet[ip.header_len..];

    if payload.len() <= frag_size {
        return DesyncResult::passthrough();
    }

    let mut inject: Vec<bytes::Bytes> = Vec::new();
    let mut pos = 0;
    let frag_id = ip.identification.wrapping_add(1);

    while pos < payload.len() {
        let end = (pos + frag_size).min(payload.len());
        let frag_payload = &payload[pos..end];
        let is_last = end >= payload.len();

        let frag_ttl = if is_last {
            ip.ttl
        } else {
            ip.ttl.saturating_sub(fake_ttl_offset)
        };

        let frag = build_ip_fragment(
            ip.src,
            ip.dst,
            ip.protocol,
            frag_id,
            (pos / 8) as u16,
            !is_last,
            frag_ttl,
            frag_payload,
        );
        inject.push(frag);
        pos = end;
    }

    debug!(
        "[Z15] IpFragPrimitives: {} fragments × {} bytes max",
        inject.len(),
        frag_size
    );

    DesyncResult::inject_many(inject)
}

/// [OF4] RstDropIpId: дроп RST пакетов с IP ID ≤ 0x000F.
///
/// ## Принцип
/// DPI часто инжектирует RST-пакеты для принудительного разрыва соединения.
/// У таких пакетов IP ID обычно очень мал (≤ 15, т.е. 0x000F), так как они
/// генерируются автоматически без нормального счётчика.
///
/// Проверяем: если пакет — TCP RST и IP ID ≤ 0x000F → дропаем его.
/// Это предотвращает разрыв соединения DPI.
///
/// ## Returns
/// - `drop: true` если RST с низким IP ID
/// - `passthrough` для всех остальных пакетов
///
/// ## Источник
/// offveil [OF4] — RST Drop IP ID
pub fn rst_drop_ip_id(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    // Проверяем IP ID ≤ 0x000F
    if ip.identification > 0x000F {
        return DesyncResult::passthrough();
    }

    // Проверяем TCP RST флаг
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let flags = tcp.get_flags();
    let is_rst = (flags & 0x04) != 0; // TcpFlags::RST = 0x04

    if !is_rst {
        return DesyncResult::passthrough();
    }

    debug!(
        "[OF4] RstDropIpId: dropping RST with IP ID={} (≤15)",
        ip.identification
    );

    DesyncResult::drop_packet()
}

// ==================== Вспомогательные функции ====================

/// Строит IP фрагмент.
#[allow(clippy::too_many_arguments)]
fn build_ip_fragment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    ttl: u8,
    payload: &[u8],
) -> bytes::Bytes {
    let total_len = 20 + payload.len();
    let mut buf = vec![0u8; total_len];

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();

        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);

        let flags: u8 = if more_fragments { 1 } else { 0 };
        ip.set_flags(flags);
        ip.set_fragment_offset(fragment_offset);

        ip.set_ttl(ttl);
        ip.set_next_level_protocol(protocol);
        ip.set_source(src);
        ip.set_destination(dst);

        ip.payload_mut().copy_from_slice(payload);
        // ip drops here → mutable borrow ends
    }

    let checksum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes::Bytes::from(buf)
}

/// Строит fake TLS ClientHello для инъекции.
fn build_fake_ch(sni: &str) -> Vec<u8> {
    // Minimal TLS 1.3 ClientHello — только SNI extension
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len() as u16;

    // SNI extension: type(2) + len(2) + ServerNameList(len(2) +
    //   ServerName(type(1) + len(2) + name(sni_len)))
    let server_name_list_len = 1 + 2 + sni_len;
    let ext_data_len = 2 + server_name_list_len;
    let ext_total_len = ext_data_len;

    // Cipher suites
    let cipher_suites: &[u8] = &[0x00, 0x02, 0x00, 0x01]; // TLS_ECDHE_RSA_... fake

    let mut ch = Vec::new();

    // ClientHello body: version(2) + random(32) + session_id(1+0)
    //   + cipher_suites(2+len) + compression(1+1) + extensions(2+len)
    ch.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version

    // Random (32 bytes) — фиксированный для детерминизма
    for i in 0..32u8 {
        ch.push(i.wrapping_mul(0x11));
    }

    // Session ID (empty)
    ch.push(0x00);

    // Cipher Suites
    ch.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    ch.extend_from_slice(cipher_suites);

    // Compression Methods: null
    ch.push(0x01);
    ch.push(0x00);

    // Extensions
    ch.extend_from_slice(&ext_total_len.to_be_bytes());

    // SNI extension
    ch.extend_from_slice(&[0x00, 0x00]); // type: sni
    ch.extend_from_slice(&server_name_list_len.to_be_bytes());
    ch.push(0x00); // ServerNameType: host_name
    ch.extend_from_slice(&sni_len.to_be_bytes());
    ch.extend_from_slice(sni_bytes);

    // Заворачиваем в Handshake + Record Layer
    let _ch_len = ch.len() as u16;

    // Handshake header: type(1) + length(3)
    let hs_len_bytes = (ch.len() as u32).to_be_bytes();

    // Record: content_type(1) + version(2) + length(2)
    let record_len = 4 + 1 + 3 + ch.len() as u16; // handshake header + body

    let mut buf = Vec::with_capacity(5 + record_len as usize);
    buf.push(0x16); // ContentType: Handshake
    buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    buf.extend_from_slice(&record_len.to_be_bytes());
    buf.push(0x01); // HandshakeType: ClientHello
    buf.extend_from_slice(&hs_len_bytes[1..4]); // length (3 bytes)
    buf.extend_from_slice(&ch);

    buf
}

// ==================== P6: CandyTunnel IP техники ====================

/// [CT3] TtlJitter: случайный TTL для каждого пакета.
///
/// ## Принцип
/// DPI использует TTL для fingerprinting ОС и обнаружения desync.
/// Случайный TTL (TTL ± random(3)) маскирует fingerprint.
pub fn ttl_jitter(packet: &[u8], base_ttl: Option<u8>) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let current_ttl = base_ttl.unwrap_or(ip.ttl);
    let jitter = (crate::desync::rand::random_u32() % 7) as i16 - 3;
    let new_ttl = (current_ttl as i16 + jitter).clamp(1, 255) as u8;

    if new_ttl == ip.ttl {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    modified[8] = new_ttl;
    let checksum = ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&checksum.to_be_bytes());

    debug!("[CT3] TtlJitter: {} → {}", ip.ttl, new_ttl);
    DesyncResult::modified_only(modified)
}

/// [CT4] DscpRandom: случайная DSCP метка.
///
/// ## Принцип
/// DPI анализирует DSCP для классификации трафика.
/// Случайная DSCP метка сбивает классификацию.
pub fn dscp_random(packet: &[u8]) -> DesyncResult {
    let _ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let current_dscp = (packet[1] >> 2) & 0x3F;
    let new_dscp = [0u8, 8, 16, 24, 32, 40, 48][(crate::desync::rand::random_u32() % 7) as usize];

    if new_dscp == current_dscp {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let ecn = modified[1] & 0x03;
    modified[1] = (new_dscp << 2) | ecn;
    let checksum = ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&checksum.to_be_bytes());

    debug!("[CT4] DscpRandom: DSCP {} → {}", current_dscp, new_dscp);
    DesyncResult::modified_only(modified)
}

/// [CT1] MutualSpoof: двусторонняя подмена source/dest IP.
///
/// ## Принцип
/// Подменяем source на dest. DPI может сбиться при обработке
/// пакетов с "неправильным" source IP.
pub fn mutual_spoof(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let mut modified = packet.to_vec();
    let src = ip.src.octets();
    let dst = ip.dst.octets();

    modified[12..16].copy_from_slice(&dst);
    modified[16..20].copy_from_slice(&src);

    let checksum = ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&checksum.to_be_bytes());

    if modified[9] == 6 {
        let new_src = Ipv4Addr::from(dst);
        let new_dst = Ipv4Addr::from(src);
        let tcp_start = 20;
        let tcp_len = modified.len().saturating_sub(tcp_start);
        if tcp_len > 18 {
            modified[tcp_start + 16] = 0;
            modified[tcp_start + 17] = 0;
        }
        let tcp_csum = crate::desync::tcp_checksum_v4(
            new_src,
            new_dst,
            &modified[tcp_start..tcp_start + tcp_len],
        );
        modified[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    }

    debug!("[CT1] MutualSpoof: src={} → dst={}", ip.src, ip.dst);
    DesyncResult::modified_only(modified)
}
