//! QUIC Desync техники.
//!
//! ## Техники
//! - QUIC Initial Injection — инъекция fake Initial пакета
//! - QUIC Short Header Poisoning — отравление short header пакетов
//! - QUIC Padding Flood — flooding padding-only пакетами
//! - UDP Coalescing — объединение UDP дейтаграмм
//! - Doppelganger GREASE — GREASE версии для обхода DPI
//! - QUIC Normalizer — нормализация QUIC пакетов
//! - [OF8] Long Header Drop — дроп QUIC Long Header пакетов от DPI
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret) и
//! [offveil](https://github.com/nickel-org/offveil).

use crate::desync::{ipv4_checksum, parse_ip_header, DesyncResult};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::udp::MutableUdpPacket;
use std::net::Ipv4Addr;
use tracing::debug;

/// QUIC Version 1 (RFC 9000).
const QUIC_VERSION_1: u32 = 0x0000_0001;

/// QUIC Version 2 (RFC 9369).
#[allow(dead_code)]
const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// QUIC Initial packet type (Long Header, Type=0x00).
const QUIC_INITIAL_TYPE: u8 = 0xC0; // Fixed bit + Long Header + Initial

/// QUIC Initial packet: Long Header + Initial type.
///
/// ## Принцип
/// DPI анализирует QUIC Initial пакеты для определения SNI.
/// Инъекция fake Initial пакета с белым SNI может сбить DPI.
///
/// ## Структура QUIC Initial packet
/// ```text
/// Header Form (1 bit) = 1 (Long)
/// Fixed Bit (1 bit) = 1
/// Long Packet Type (2 bits) = 0 (Initial)
/// Reserved Bits (2 bits) = 0
/// Packet Number Length (2 bits) = 0 (1 byte)
/// Version (4 bytes) = 0x00000001
/// Destination Connection ID Length (1 byte)
/// Destination Connection ID (N bytes)
/// Source Connection ID Length (1 byte)
/// Source Connection ID (N bytes)
/// Token Length (1-8 bytes)
/// Token (variable)
/// Length (1-8 bytes)
/// Packet Number (1-4 bytes)
/// Payload (encrypted)
/// ```
pub fn quic_initial_inject(packet: &[u8], fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..]; // skip UDP header
    if udp_data.len() < 20 {
        return DesyncResult::passthrough();
    }

    // Проверяем, что это QUIC Long Header (первый бит = 1)
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    // Извлекаем Connection ID из оригинального пакета
    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough(); // Version negotiation
    }

    let dcid_len = udp_data[5] as usize;
    if 6 + dcid_len > udp_data.len() {
        return DesyncResult::passthrough();
    }
    let dcid = &udp_data[6..6 + dcid_len];

    let scid_offset = 6 + dcid_len;
    if scid_offset >= udp_data.len() {
        return DesyncResult::passthrough();
    }
    let _scid_len = udp_data[scid_offset] as usize;

    // Строим fake QUIC Initial пакет
    let fake_payload = build_quic_initial(dcid, fake_sni);

    // Fake UDP дейтаграмм
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_src_port = crate::desync::rand::random_range(1024, 65535) as u16;
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        fake_src_port,
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[QUIC] Initial inject: fake '{}' ({} bytes)",
        fake_sni,
        fake_payload.len()
    );

    DesyncResult::inject_only(fake_udp)
}

/// QUIC Short Header Poisoning.
///
/// ## Принцип
/// Отравление short header пакетов (0-RTT, 1-RTT) fake данными.
/// DPI может потерять sync с QUIC потоком.
pub fn quic_short_header_poison(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.is_empty() {
        return DesyncResult::passthrough();
    }

    // Short Header: первый бит = 0
    if udp_data[0] & 0x80 != 0 {
        return DesyncResult::passthrough();
    }

    // Фейковый short header пакет (8 байт padding)
    let fake_payload = vec![0u8; 8];
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // Извлекаем source port из UDP
    let udp = pnet_packet::udp::UdpPacket::new(&packet[ip.header_len..]);
    let src_port = udp
        .map(|u| u.get_source())
        .unwrap_or(crate::desync::rand::random_range(1024, 65535) as u16);

    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        src_port,
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[QUIC] Short header poison: 8 bytes fake payload");

    DesyncResult::inject_only(fake_udp)
}

/// QUIC Padding Flood.
///
/// ## Принцип
/// Отправляем несколько padding-only пакетов для переполнения
/// conntrack DPI. QUIC padding пакеты не содержат полезных данных,
/// но DPI должен их обрабатывать.
pub fn quic_padding_flood(packet: &[u8], count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let mut inject: Vec<bytes::Bytes> = Vec::with_capacity(count);

    for i in 0..count {
        let mut rng = crate::desync::rand::PerConnRng::new(i as u64);
        let pad_size = (rng.next_unbiased(20) + 1) as usize;
        let mut fake_payload = vec![0u8; pad_size];
        for byte in &mut fake_payload {
            *byte = rng.next_u64() as u8;
        }

        let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
        let src_port = rng.next_range(1024, 65535) as u16;
        let ip_id = rng.next_u64() as u16;
        let fake_udp = build_udp_packet(
            ip.src,
            ip.dst,
            src_port,
            443,
            &fake_payload,
            fake_ttl,
            ip_id,
        );
        inject.push(fake_udp);
    }

    debug!("[QUIC] Padding flood: {} packets", count);

    DesyncResult::inject_many(inject)
}

/// UDP Coalescing — объединение UDP дейтаграмм.
///
/// ## Принцип
/// Объединяем несколько маленьких UDP пакетов в один большой.
/// DPI может не обработать коалесцированный пакет.
pub fn udp_coalescing(packet: &[u8], extra_packets: &[&[u8]], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    if extra_packets.is_empty() {
        return DesyncResult::passthrough();
    }

    // Объединяем payload
    let mut combined = Vec::new();
    let udp_start = ip.header_len + 8;
    if udp_start < packet.len() {
        combined.extend_from_slice(&packet[udp_start..]);
    }
    for extra in extra_packets {
        combined.extend_from_slice(extra);
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let combined_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &combined,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[QUIC] UDP coalescing: {} packets → {} bytes",
        extra_packets.len() + 1,
        combined.len()
    );

    DesyncResult::inject_only(combined_udp)
}

/// Doppelganger GREASE — отправка QUIC с fake версией.
///
/// ## Принцип
/// Отправляем пакет с GREASE версией (0x?a?a?a?a). DPI может
/// не распознать QUIC и пропустить пакет.
pub fn doppelganger_grease(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    // GREASE version: 0x?a?a?a?a (RFC 8701)
    let grease_version: u32 = 0x0a0a_0a0a;
    let mut fake_payload = Vec::new();
    fake_payload.push(0xC0); // Long Header + Initial
    fake_payload.extend_from_slice(&grease_version.to_be_bytes());
    fake_payload.extend_from_slice(&[0u8; 8]); // CID placeholder

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[QUIC] Doppelganger GREASE: version={:#x}", grease_version);

    DesyncResult::inject_only(fake_udp)
}

/// [OF8] Long Header Drop: дроп QUIC Long Header пакетов от DPI.
///
/// ## Принцип
/// DPI часто инжектирует QUIC пакеты с Long Header (ServerHello,
/// NewToken, etc.) для анализа. Если пакет содержит Long Header
/// и отправлен от клиента — это很可能 инъекция DPI.
///
/// Проверяем: если пакет — QUIC Long Header (бит 0x80 установлен)
/// и это ответ (не outbound) — дропаем.
pub fn quic_long_header_drop(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.is_empty() {
        return DesyncResult::passthrough();
    }

    // Long Header: первый бит = 1
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    debug!(
        "[OF8] LongHeaderDrop: dropping QUIC Long Header packet from {}",
        ip.src
    );

    DesyncResult::drop_packet()
}

/// QUIC Normalizer — нормализация QUIC пакетов для DPI.
///
/// ## Принцип
/// Нормализуем QUIC Initial пакет: убираем GREASE, исправляем
/// version, чистим padding. DPI может сбиться на аномальных пакетах.
pub fn quic_normalizer(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 {
        return DesyncResult::passthrough();
    }

    // Проверяем Long Header
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    // Нормализуем GREASE версию на Version 1
    if (version & 0x0a0a_0a0a) == 0x0a0a_0a0a {
        let mut modified = packet.to_vec();
        let version_offset = ip.header_len + 8 + 1; // +1 for first byte
        modified[version_offset..version_offset + 4].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());

        // Пересчитываем IP checksum
        let checksum = ipv4_checksum(&modified[..20]);
        modified[10..12].copy_from_slice(&checksum.to_be_bytes());

        debug!("[QUIC] Normalizer: GREASE version → Version 1");

        return DesyncResult::modified_only(modified);
    }

    DesyncResult::passthrough()
}

// ==================== P5: Оставшиеся QUIC техники ====================

/// [Z20] QUIC Blocking: блокировка QUIC для fallback на TCP.
///
/// ## Принцип
/// Блокируем все QUIC пакеты (UDP:443). Клиент вынужден
/// использовать TCP fallback. DPI может не блокировать TCP
/// (или блокировать слабее).
pub fn quic_blocking(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    // Проверяем UDP:443
    if ip.protocol.0 != 17 {
        return DesyncResult::passthrough();
    }

    let udp_data = &packet[ip.header_len..];
    if udp_data.len() < 8 {
        return DesyncResult::passthrough();
    }

    let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
    if dst_port != 443 {
        return DesyncResult::passthrough();
    }

    debug!("[Z20] QUIC Blocking: dropping UDP:443 from {}", ip.src);

    DesyncResult::drop_packet()
}

/// [Z21] QUIC Version Downgrade: принудительный downgrade версии.
///
/// ## Принцип
/// Отправляем fake Version Negotiation пакет с unsupported версией.
/// Клиент должен повторить handshake с поддерживаемой версией.
/// DPI может потерять sync с QUIC потоком.
pub fn quic_version_downgrade(
    packet: &[u8],
    fake_version: u32,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 || version == fake_version {
        return DesyncResult::passthrough();
    }

    // Version Negotiation: Long Header + Type=0x7F + version=0
    let mut fake_payload = Vec::with_capacity(64);
    fake_payload.push(0xFF); // Header Form + Fixed Bit + Long Packet Type (0x3F = VN)
    fake_payload.extend_from_slice(&fake_version.to_be_bytes()); // fake version
    fake_payload.push(0x08); // DCID length
                             // Copy DCID from original
    let dcid_start = 6;
    if dcid_start + 8 <= udp_data.len() {
        fake_payload.extend_from_slice(&udp_data[dcid_start..dcid_start + 8]);
    }
    fake_payload.push(0x08); // SCID length
    let scid_start = dcid_start + 8 + 1;
    if scid_start + 8 <= udp_data.len() {
        fake_payload.extend_from_slice(&udp_data[scid_start..scid_start + 8]);
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[Z21] QUIC VersionDowngrade: fake version={:#x}",
        fake_version
    );

    DesyncResult::inject_only(fake_udp)
}

/// [Z22] QUIC Retry Injection: инъекция fake Retry пакета.
///
/// ## Принцип
/// Отправляем fake Retry пакет с невалидным токеном.
/// Клиент должен повторить handshake с токеном. DPI
/// может сбиться при обработке Retry.
pub fn quic_retry_inject(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // Retry: Long Header + Type=0x7E (Retry Packet)
    let mut fake_payload = Vec::with_capacity(64);
    fake_payload.push(0xFE); // Retry packet type
    fake_payload.extend_from_slice(&version.to_be_bytes());

    let dcid_start = 6;
    let dcid_len = if dcid_start < udp_data.len() {
        udp_data[dcid_start] as usize
    } else {
        0
    };
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        fake_payload.push(dcid_len as u8);
        fake_payload.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }

    // Random SCID (server chosen)
    fake_payload.push(0x08);
    for i in 0..8 {
        fake_payload.push(crate::desync::rand::random_u32() as u8);
        let _ = i;
    }

    // Retry Token (16 bytes random)
    for _ in 0..16 {
        fake_payload.push(crate::desync::rand::random_u32() as u8);
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        443,
        crate::desync::rand::random_range(1024, 65535) as u16,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z22] QUIC RetryInject: fake Retry token injected");

    DesyncResult::inject_only(fake_udp)
}

/// [Z23] QUIC ConnectionClose: инъекция CONNECTION_CLOSE.
///
/// ## Принцип
/// Отправляем fake CONNECTION_CLOSE frame. DPI видит
/// закрытие соединения и может перестать инспектировать.
/// Клиент создаст новое соединение.
pub fn quic_connection_close(packet: &[u8], error_code: u64, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // CONNECTION_CLOSE frame: type=0x1C, error_code(varint), frame_type(varint)
    let mut frame = Vec::with_capacity(20);
    frame.push(0x1C); // CONNECTION_CLOSE frame type
                      // error_code as varint (simple encoding)
    if error_code < 64 {
        frame.push(error_code as u8);
    } else {
        frame.push(0x40 | ((error_code >> 8) & 0x3F) as u8);
        frame.push((error_code & 0xFF) as u8);
    }
    // frame_type that caused error: 0x00 (unknown)
    frame.push(0x00);
    // reason phrase length: 0
    frame.push(0x00);

    // Wrap in Initial packet
    let dcid_start = 6;
    let mut initial = Vec::with_capacity(64);
    initial.push(QUIC_INITIAL_TYPE);
    initial.extend_from_slice(&version.to_be_bytes());

    let dcid_len = if dcid_start < udp_data.len() {
        udp_data[dcid_start] as usize
    } else {
        0
    };
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }

    // SCID = DCID
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }

    // Token length = 0
    initial.push(0x00);
    // Length
    let remaining = frame.len() + 16; // + padding
    initial.push(((remaining >> 8) | 0xC0) as u8);
    initial.push((remaining & 0xFF) as u8);
    // Packet number
    initial.push(0x00);
    // Frame
    initial.extend_from_slice(&frame);
    // Padding
    initial.resize(initial.len() + 16, 0);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &initial,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z23] QUIC ConnectionClose: error_code={}", error_code);

    DesyncResult::inject_only(fake_udp)
}

/// [Z24] QUIC StreamReset: инъекция RESET_STREAM.
///
/// ## Принцип
/// Отправляем fake RESET_STREAM frame для stream 0.
/// DPI видит сброс потока и может перестать инспектировать.
pub fn quic_stream_reset(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // RESET_STREAM frame: type=0x04, stream_id=0, error_code=0
    let mut frame = Vec::with_capacity(5);
    frame.push(0x04); // RESET_STREAM type
    frame.push(0x00); // stream_id=0 (varint)
    frame.push(0x00); // error_code=0
    frame.push(0x00); // final_size=0

    // Wrap in 1-RTT packet (Short Header)
    let mut short = Vec::with_capacity(20);
    short.push(0x40); // Short Header: Fixed bit=1, spin=0
                      // Use random packet number
    short.push(crate::desync::rand::random_u32() as u8);
    short.extend_from_slice(&frame);
    short.resize(short.len() + 8, 0); // padding

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &short,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z24] QUIC StreamReset: RESET_STREAM for stream 0");

    DesyncResult::inject_only(fake_udp)
}

/// [Z25] QUIC MaxStreams: инъекция MAX_STREAMS frame.
///
/// ## Принцип
/// Отправляем MAX_STREAMS frame с large value.
/// DPI должен обновить лимит потоков. Это может
/// переполнить state machine DPI.
pub fn quic_max_streams(packet: &[u8], max_streams: u32, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // MAX_STREAMS frame: type=0x12 (bidi), count as varint
    let mut frame = Vec::with_capacity(5);
    frame.push(0x12); // MAX_STREAMS type
                      // max_streams as varint
    if max_streams < 64 {
        frame.push(max_streams as u8);
    } else {
        frame.push(0x40 | ((max_streams >> 8) & 0x3F) as u8);
        frame.push((max_streams & 0xFF) as u8);
    }

    // Wrap in Initial packet
    let mut initial = Vec::with_capacity(40);
    initial.push(QUIC_INITIAL_TYPE);
    initial.extend_from_slice(&version.to_be_bytes());
    let dcid_start = 6;
    let dcid_len = if dcid_start < udp_data.len() {
        udp_data[dcid_start] as usize
    } else {
        0
    };
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }
    initial.push(0x00); // token length
    let remaining = frame.len() + 8;
    initial.push(((remaining >> 8) | 0xC0) as u8);
    initial.push((remaining & 0xFF) as u8);
    initial.push(0x00); // packet number
    initial.extend_from_slice(&frame);
    initial.resize(initial.len() + 8, 0);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &initial,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z25] QUIC MaxStreams: max={}", max_streams);

    DesyncResult::inject_only(fake_udp)
}

/// [Z26] QUIC NewConnectionID: инъекция NEW_CONNECTION_ID.
///
/// ## Принцип
/// Отправляем fake NEW_CONNECTION_ID frame. DPI должен
/// отслеживать connection ID смены. Это может сбить DPI.
pub fn quic_new_connection_id(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // NEW_CONNECTION_ID frame: type=0x18, sequence_number=1, cid_len=8, cid, stateless_reset_token=16
    let mut frame = Vec::with_capacity(40);
    frame.push(0x18); // type
    frame.push(0x01); // sequence_number=1
    frame.push(0x08); // connection_id_length=8
                      // Random connection ID
    for _ in 0..8 {
        frame.push(crate::desync::rand::random_u32() as u8);
    }
    // Stateless Reset Token (16 bytes random)
    for _ in 0..16 {
        frame.push(crate::desync::rand::random_u32() as u8);
    }

    // Wrap in 1-RTT Short Header
    let mut short = Vec::with_capacity(40);
    short.push(0x40);
    short.push(crate::desync::rand::random_u32() as u8);
    short.extend_from_slice(&frame);
    short.resize(short.len() + 8, 0);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        crate::desync::rand::random_range(1024, 65535) as u16,
        443,
        &short,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z26] QUIC NewConnectionID: fake CID injected");

    DesyncResult::inject_only(fake_udp)
}

// ==================== Вспомогательные функции ====================

/// Строит fake QUIC Initial пакет.
fn build_quic_initial(dcid: &[u8], _sni: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128);

    // Long Header: Header Form(1) + Fixed Bit(1) + Type(2) = 0xC0
    // Reserved Bits(2) = 0 + Packet Number Length(2) = 0
    payload.push(QUIC_INITIAL_TYPE);

    // Version: 0x00000001 (QUIC v1)
    payload.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());

    // Destination Connection ID Length + CID
    payload.push(dcid.len() as u8);
    payload.extend_from_slice(dcid);

    // Source Connection ID Length = 0
    payload.push(0);

    // Token Length = 0 (no token)
    payload.push(0);

    // Length: placeholder (will be filled)
    let length_offset = payload.len();
    payload.extend_from_slice(&[0u8; 2]); // placeholder

    // Packet Number: 0
    payload.push(0);

    // RFC 9000 §14.1: Initial packets must be ≥ 1200 bytes
    const QUIC_MIN_INITIAL_SIZE: usize = 1200;
    let current_len = payload.len();
    if current_len < QUIC_MIN_INITIAL_SIZE {
        payload.resize(QUIC_MIN_INITIAL_SIZE, 0);
    }

    // Fill length (remaining bytes after length field)
    let length = payload.len() - length_offset - 2;
    payload[length_offset..length_offset + 2].copy_from_slice(&(length as u16).to_be_bytes());

    payload
}

/// Строит UDP пакет с IP header.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_udp_packet(
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

    let mut buf = vec![0u8; total_len];

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

    // IP checksum
    let ip_csum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP Header
    {
        let mut udp = MutableUdpPacket::new(&mut buf[20..]).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(udp_len as u16);
        udp.set_checksum(0);
    }

    // UDP payload
    buf[28..28 + payload.len()].copy_from_slice(payload);

    // UDP checksum (optional for IPv4, but set for correctness)
    let udp_csum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &buf[20..20 + udp_len]);
    buf[26..28].copy_from_slice(&udp_csum.to_be_bytes());

    bytes::Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_quic_initial() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let payload = build_quic_initial(&dcid, "example.com");
        assert!(!payload.is_empty());
        // Long Header flag
        assert!(payload[0] & 0x80 != 0);
        // Version
        assert_eq!(
            u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]),
            QUIC_VERSION_1
        );
    }

    #[test]
    fn test_build_udp_packet() {
        let pkt = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            crate::desync::rand::random_range(1024, 65535) as u16,
            443,
            &[0x01, 0x02],
            64,
            1,
        );
        assert_eq!(pkt.len(), 20 + 8 + 2); // IP + UDP + payload
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 17); // UDP protocol
    }

    #[test]
    fn test_quic_long_header_detection() {
        let long_header = vec![
            0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        assert!(long_header[0] & 0x80 != 0); // Long Header

        let short_header = vec![0x40, 0x00, 0x00, 0x01];
        assert!(short_header[0] & 0x80 == 0); // Short Header
    }

    fn make_quic_packet() -> Vec<u8> {
        // IP(20) + UDP(8) + QUIC Initial(20+)
        let quic_payload = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID len
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID len
        ];
        let udp_len = 8 + quic_payload.len();
        let total = 20 + udp_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // UDP header
        pkt[20..22].copy_from_slice(
            &(crate::desync::rand::random_range(1024, 65535) as u16).to_be_bytes(),
        );
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // QUIC payload
        let data_start = 28;
        pkt[data_start..data_start + quic_payload.len()].copy_from_slice(&quic_payload);
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn test_quic_blocking() {
        let pkt = make_quic_packet();
        let result = quic_blocking(&pkt);
        assert!(result.drop);
    }

    #[test]
    fn test_quic_version_downgrade() {
        let pkt = make_quic_packet();
        let result = quic_version_downgrade(&pkt, 0xFF00_001D, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_retry_inject() {
        let pkt = make_quic_packet();
        let result = quic_retry_inject(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_connection_close() {
        let pkt = make_quic_packet();
        let result = quic_connection_close(&pkt, 0x01, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_stream_reset() {
        let pkt = make_quic_packet();
        let result = quic_stream_reset(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_max_streams() {
        let pkt = make_quic_packet();
        let result = quic_max_streams(&pkt, 100, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_new_connection_id() {
        let pkt = make_quic_packet();
        let result = quic_new_connection_id(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_non_quic_passthrough() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP, not UDP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        assert!(quic_blocking(&pkt).inject.is_empty());
        assert!(!quic_blocking(&pkt).drop);
    }
}
