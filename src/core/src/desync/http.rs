//! HTTP Desync техники.
//!
//! ## Техники
//! - [10] HeaderTamper — модификация HTTP заголовков (7 режимов)
//! - [OM4] HostObfs — HTTP Host Obfuscation (из Omoikane)
//! - [RH1] HostSpace — Host-Space (из rust-DPI-http-proxy)
//! - [RH2] TitleCase — Title-Case заголовки (из rust-DPI-http-proxy)
//! - [31] H2HpackAware — HPACK-aware frame splitting
//! - [41] HpackBomber — HPACK Table Header Bombing
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret),
//! [Omoikane](https://github.com/nickel-org/omoikane),
//! [rust-DPI-http-proxy](https://github.com/nickel-org/rust-dpi-http-proxy).

use crate::desync::{parse_ip_header, parse_tcp_packet, DesyncResult};
use pnet_packet::tcp::TcpFlags;
use std::net::Ipv4Addr;
use tracing::debug;

/// Режим модификации HTTP заголовков.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderTamperMode {
    /// Замена Host на fake (proxy/redirect)
    HostReplace,
    /// Добавление пробела после Host:
    HostSpace,
    /// Title-Case заголовки
    TitleCase,
    /// Обфускация Host (замена на 'a' · len)
    HostObfs,
    /// Разделение заголовков на несколько сегментов
    HeaderSplit,
    /// Добавление мусорных заголовков
    JunkHeaders,
    /// Комбинация: split + junk
    SplitAndJunk,
}

/// [10] HeaderTamper: модификация HTTP заголовков.
///
/// ## Принцип
/// DPI анализирует HTTP заголовки для классификации трафика.
/// Модификация заголовков может сбить DPI:
/// - Host → proxy-хост (redirect)
/// - Добавление пробела после Host:
/// - Title-Case вместо lowercase
/// - Обфускация имени хоста
pub fn header_tamper(
    packet: &[u8],
    mode: HeaderTamperMode,
    fake_host: Option<&str>,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Проверяем, что это HTTP (первые буквы payload)
    if !is_http_request(tcp.payload) {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let data_offset = ip.header_len + tcp.data_offset;

    match mode {
        HeaderTamperMode::HostReplace => {
            if let Some(fake) = fake_host {
                replace_host_header(&mut modified, data_offset, tcp.payload, fake);
            }
        }
        HeaderTamperMode::HostSpace => {
            apply_host_space(&mut modified, data_offset, tcp.payload);
        }
        HeaderTamperMode::TitleCase => {
            apply_title_case(&mut modified, data_offset, tcp.payload);
        }
        HeaderTamperMode::HostObfs => {
            obfuscate_host(&mut modified, data_offset, tcp.payload);
        }
        HeaderTamperMode::HeaderSplit => {
            return header_split(packet, tcp.data_offset);
        }
        HeaderTamperMode::JunkHeaders => {
            return header_junk(packet, tcp.data_offset);
        }
        HeaderTamperMode::SplitAndJunk => {
            let split = header_split(packet, tcp.data_offset);
            let junk = header_junk(packet, tcp.data_offset);
            let mut result = split;
            result.merge(junk);
            return result;
        }
    }

    debug!("[10] HeaderTamper: mode={:?}", mode);
    DesyncResult::modified_only(modified)
}

/// [OM4] HostObfs: HTTP Host Obfuscation.
///
/// ## Принцип
/// DPI проверяет Host заголовок для блокировки сайтов.
/// Обфускация Host: замена имени хоста на 'a' повторяющееся len раз.
/// DPI видит "aaaaaaa..." вместо реального домена.
/// Сервер обычно игнорирует payload (HTTP/1.1 прокси).
pub fn host_obfuscation(packet: &[u8]) -> DesyncResult {
    header_tamper(packet, HeaderTamperMode::HostObfs, None)
}

/// [RH1] HostSpace: Host-Space HTTP Header.
///
/// ## Принцип
/// Добавление пробела после `Host:` → `Host: example.com`
/// Некоторые DPI парсят заголовки с точным соответствием и могут
/// не распознать формат с пробелом.
pub fn host_space(packet: &[u8]) -> DesyncResult {
    header_tamper(packet, HeaderTamperMode::HostSpace, None)
}

/// [RH2] TitleCase: Title-Case HTTP Headers.
///
/// ## Принцип
/// Преобразование заголовков в Title-Case: `Host` → `Host`,
/// `Content-Type` → `Content-Type`. Некоторые DPI ожидают
/// lowercase и могут не распознать Title-Case.
pub fn title_case(packet: &[u8]) -> DesyncResult {
    header_tamper(packet, HeaderTamperMode::TitleCase, None)
}

/// [31] H2HpackAware: HPACK-aware frame splitting.
///
/// ## Принцип
/// Разделяем HTTP/2 HPACK-закодированные заголовки на границах
/// HPACK entries. DPI может не собрать HPACK из нескольких TCP
/// сегментов, так как HPACK использует динамическую таблицу.
pub fn h2_hpack_aware(packet: &[u8], split_at: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < split_at + 1 {
        return DesyncResult::passthrough();
    }

    let seq = tcp.sequence;
    let ack = tcp.acknowledgment;
    let window = tcp.window;
    let src = ip.src;
    let dst = ip.dst;
    let src_port = tcp.src_port;
    let dst_port = tcp.dst_port;

    // Фрагмент 1: начало HPACK (до split_at)
    let frag1_payload = &tcp.payload[..split_at];
    let frag1 = build_tcp_segment_http(
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        window,
        frag1_payload,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );

    // Фрагмент 2: остаток HPACK
    let frag2_payload = &tcp.payload[split_at..];
    let frag2 = build_tcp_segment_http(
        src,
        dst,
        src_port,
        dst_port,
        seq.wrapping_add(split_at as u32),
        ack,
        window,
        frag2_payload,
        ip.ttl,
        ip.identification.wrapping_add(2),
    );

    debug!("[31] H2HpackAware: HPACK split at {}", split_at);

    DesyncResult::inject_many(vec![frag1, frag2])
}

/// [41] HpackBomber: HPACK Table Header Bombing.
///
/// ## Принцип
/// Отправляем перед реальным HTTP/2 запросом фейковые HPACK entries,
/// которые заполняют динамическую таблицу DPI. DPI может потратить
/// ресурсы на обработку фейковых entries.
pub fn hpack_bomber(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Создаём fake HPACK entries (Indexed Header Field Representation)
    // HPACK index 0 = :authority с фейковым значением
    let fake_hpack = build_fake_hpack_entries();

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_seg = build_tcp_segment_http(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        tcp.window,
        &fake_hpack,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[41] HpackBomber: {} bytes fake HPACK", fake_hpack.len());

    DesyncResult::inject_only(fake_seg)
}

// ==================== Вспомогательные функции ====================

/// Проверяет, является ли payload HTTP запросом.
fn is_http_request(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    // HTTP methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT
    matches!(
        &payload[..3],
        b"GET" | b"POS" | b"PUT" | b"DEL" | b"HEA" | b"OPT" | b"PAT" | b"CON"
    )
}

/// Проверяет, является ли payload HTTP/2 framing (SETTINGS, etc.)
#[allow(dead_code)]
fn is_http2_frame(payload: &[u8]) -> bool {
    // HTTP/2 frame: length(3) + type(1) + flags(1) + stream_id(4)
    // Type 0 = DATA, 1 = HEADERS, 2 = PRIORITY, 3 = RST_STREAM, 4 = SETTINGS
    payload.len() >= 9 && payload[3] <= 9
}

/// Замена Host заголовка на fake.
fn replace_host_header(packet: &mut [u8], data_offset: usize, payload: &[u8], fake_host: &str) {
    if let Some(pos) = find_header(payload, "Host: ") {
        let header_start = data_offset + pos + 6; // "Host: ".len()
        let line_end = find_line_end(payload, pos);
        let host_len = line_end - pos - 6;

        let fake_bytes = fake_host.as_bytes();
        let copy_len = host_len.min(fake_bytes.len());

        for i in 0..copy_len {
            if header_start + i < packet.len() {
                packet[header_start + i] = fake_bytes[i];
            }
        }
    }
}

/// Host-Space: добавление пробела после `Host:`.
fn apply_host_space(packet: &mut [u8], data_offset: usize, payload: &[u8]) {
    if let Some(pos) = find_header(payload, "Host:") {
        let colon_pos = data_offset + pos + 5; // "Host:".len()
        if colon_pos < packet.len() {
            // Если следующий символ не пробел — вставляем
            if packet[colon_pos] != b' ' {
                // Сдвигаем всё вправо на 1 байт
                let shift_start = data_offset + pos + 5;
                let shift_end = packet.len().saturating_sub(1);
                if shift_end >= shift_start {
                    for i in (shift_start..shift_end).rev() {
                        if i + 1 < packet.len() {
                            packet[i + 1] = packet[i];
                        }
                    }
                    packet[shift_start] = b' ';
                    // Обновляем TCP length в IP header
                    update_ip_total_length(packet);
                }
            }
        }
    }
}

/// Title-Case: преобразование заголовков.
fn apply_title_case(packet: &mut [u8], data_offset: usize, payload: &[u8]) {
    let mut i = 0;
    while i < payload.len() {
        // Находим начало заголовка (после \r\n или в начале payload)
        if i == 0 || (i >= 2 && payload[i - 2] == b'\r' && payload[i - 1] == b'\n') {
            // Преобразуем первый символ заголовка в uppercase
            let byte_idx = data_offset + i;
            if byte_idx < packet.len() {
                let b = packet[byte_idx];
                if b.is_ascii_lowercase() {
                    packet[byte_idx] = b - 32;
                }
            }
            // Преобразуем все символы после дефиса
            let mut j = i + 1;
            let mut after_dash = false;
            while j < payload.len() && payload[j] != b':' {
                if payload[j - 1] == b'-' {
                    after_dash = true;
                }
                let byte_idx = data_offset + j;
                if byte_idx < packet.len() {
                    let b = packet[byte_idx];
                    if after_dash && b.is_ascii_lowercase() {
                        packet[byte_idx] = b - 32;
                    } else if !after_dash && b.is_ascii_uppercase() {
                        packet[byte_idx] = b + 32;
                    }
                }
                after_dash = false;
                j += 1;
            }
        }
        i += 1;
    }
}

/// Обфускация Host: замена hostname на 'a' · len.
fn obfuscate_host(packet: &mut [u8], data_offset: usize, payload: &[u8]) {
    if let Some(pos) = find_header(payload, "Host: ") {
        let header_start = data_offset + pos + 6;
        let line_end = find_line_end(payload, pos);
        let host_len = line_end - pos - 6;

        for i in 0..host_len {
            let byte_idx = header_start + i;
            if byte_idx < packet.len() {
                let b = packet[byte_idx];
                if b != b'.' && b != b'-' && b != b':' {
                    packet[byte_idx] = b'a';
                }
            }
        }
    }
}

/// Разделение HTTP заголовков на два TCP сегмента.
fn header_split(packet: &[u8], _tcp_data_offset: usize) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    // Ищем конец первого заголовка (после первого \r\n)
    let split_pos = find_line_end(tcp.payload, 0).min(tcp.payload.len());
    if split_pos >= tcp.payload.len() {
        return DesyncResult::passthrough();
    }

    let seq = tcp.sequence;
    let ack = tcp.acknowledgment;
    let window = tcp.window;

    // Фрагмент 1: метод + первый заголовок
    let frag1 = build_tcp_segment_http(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        seq,
        ack,
        window,
        &tcp.payload[..split_pos],
        ip.ttl.saturating_sub(1),
        ip.identification.wrapping_add(1),
    );

    // Фрагмент 2: остальные заголовки + body
    let frag2 = build_tcp_segment_http(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        seq.wrapping_add(split_pos as u32),
        ack,
        window,
        &tcp.payload[split_pos..],
        ip.ttl,
        ip.identification.wrapping_add(2),
    );

    debug!(
        "[10] HeaderSplit: {} + {} bytes",
        split_pos,
        tcp.payload.len() - split_pos
    );

    DesyncResult::inject_many(vec![frag1, frag2])
}

/// Добавление мусорных HTTP заголовков перед реальными.
fn header_junk(packet: &[u8], _tcp_data_offset: usize) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Мусорный заголовок
    let junk_header = b"X-Padding: aaaaa\r\n";
    let mut fake_payload = Vec::with_capacity(junk_header.len() + tcp.payload.len());
    fake_payload.extend_from_slice(junk_header);
    fake_payload.extend_from_slice(tcp.payload);

    // Модифицируем оригинал: добавляем junk перед реальными данными
    let mut modified = packet.to_vec();
    let data_start = ip.header_len + tcp.data_offset;
    modified.splice(data_start..data_start, junk_header.iter().copied());
    update_ip_total_length(&mut modified);

    // Обновляем SEQ в modified
    let new_seq = tcp.sequence.wrapping_add(junk_header.len() as u32);
    set_tcp_sequence(&mut modified, ip.header_len, new_seq);

    // Recalculate TCP checksum
    recalc_tcp_checksum(&mut modified, ip.header_len, ip.src, ip.dst);

    debug!(
        "[10] JunkHeader: {} bytes junk + {} bytes real",
        junk_header.len(),
        tcp.payload.len()
    );

    DesyncResult::modified_only(modified)
}

/// Строит TCP сегмент с HTTP payload.
#[allow(clippy::too_many_arguments)]
fn build_tcp_segment_http(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let tcp_header_len = 20;
    let mut tcp_buf = vec![0u8; tcp_header_len];
    {
        let mut tcp = pnet_packet::tcp::MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::PSH | TcpFlags::ACK);
        tcp.set_window(window);
        tcp.set_checksum(0);
        tcp.set_urgent_ptr(0);
    }
    let checksum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &tcp_buf);
    tcp_buf[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut full_payload = tcp_buf.to_vec();
    full_payload.extend_from_slice(payload);
    crate::desync::build_ip_packet(
        src_ip,
        dst_ip,
        pnet_packet::ip::IpNextHeaderProtocols::Tcp,
        ttl,
        identification,
        &full_payload,
    )
}

/// Ищет начало заголовка в HTTP payload.
fn find_header(payload: &[u8], name: &str) -> Option<usize> {
    let name_bytes = name.as_bytes();
    if payload.len() < name_bytes.len() {
        return None;
    }
    for i in 0..=payload.len() - name_bytes.len() {
        if payload[i..].starts_with(name_bytes) {
            // Проверяем, что это начало строки (после \r\n или начало payload)
            if i == 0 || (i >= 2 && payload[i - 2] == b'\r' && payload[i - 1] == b'\n') {
                return Some(i);
            }
        }
    }
    None
}

/// Ищет конец строки (\r\n) в payload.
fn find_line_end(payload: &[u8], from: usize) -> usize {
    let search = &payload[from..];
    for i in 0..search.len().saturating_sub(1) {
        if search[i] == b'\r' && search[i + 1] == b'\n' {
            return from + i + 2;
        }
    }
    payload.len()
}

/// Обновляет IP total length ( увеличивает на 1 для host-space).
fn update_ip_total_length(packet: &mut [u8]) {
    if packet.len() < 4 {
        return;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    let new_total_len = total_len + 1;
    packet[2..4].copy_from_slice(&new_total_len.to_be_bytes());

    // Пересчитываем IP checksum
    let checksum = crate::desync::ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// Устанавливает TCP sequence number в пакете.
fn set_tcp_sequence(packet: &mut [u8], tcp_offset: usize, seq: u32) {
    if tcp_offset + 8 <= packet.len() {
        packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
    }
}

/// Пересчитывает TCP checksum.
fn recalc_tcp_checksum(packet: &mut [u8], tcp_offset: usize, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let tcp_len = total_len.saturating_sub(20);
    if tcp_offset + tcp_len <= packet.len() {
        // Обнуляем checksum перед пересчётом
        if tcp_offset + 18 <= packet.len() {
            packet[tcp_offset + 16] = 0;
            packet[tcp_offset + 17] = 0;
        }
        let checksum = crate::desync::tcp_checksum_v4(
            src_ip,
            dst_ip,
            &packet[tcp_offset..tcp_offset + tcp_len],
        );
        if tcp_offset + 18 <= packet.len() {
            packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&checksum.to_be_bytes());
        }
    }
}

/// Строит fake HPACK entries для HpackBomber.
fn build_fake_hpack_entries() -> bytes::Bytes {
    let mut entries = vec![
        0x82, // HPACK: :method = GET (Indexed, index 2)
        0x84, // HPACK: :path = / (Indexed, index 4)
        0x87, // HPACK: :scheme = https (Indexed, index 7)
        0x41, // HPACK: :authority (Literal with Indexing, index 1)
        0x09, // value length = 9
    ];
    entries.extend_from_slice(b"aaaaaaaaa");

    bytes::Bytes::from(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request(b"GET / HTTP/1.1\r\n"));
        assert!(is_http_request(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http_request(b"HEAD / HTTP/1.1\r\n"));
        assert!(!is_http_request(b"\x16\x03\x01\x00\x02")); // TLS
        assert!(!is_http_request(b"AB")); // too short
    }

    #[test]
    fn test_find_header() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(find_header(payload, "Host: "), Some(16));
        assert!(find_header(payload, "X-Custom: ").is_none());
    }

    #[test]
    fn test_find_line_end() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        // "GET / HTTP/1.1" = 14 bytes, \r at 14, \n at 15 → returns 16
        assert_eq!(find_line_end(payload, 0), 16);
        // From 16: "Host: example.com" = 17 bytes, \r at 33, \n at 34 → returns 35
        assert_eq!(find_line_end(payload, 16), 35);
    }

    #[test]
    fn test_build_fake_hpack_entries() {
        let entries = build_fake_hpack_entries();
        assert!(!entries.is_empty());
        assert_eq!(entries[0], 0x82); // :method = GET
    }

    #[test]
    fn test_host_space_inserts_space() {
        let payload = b"GET / HTTP/1.1\r\nHost:example.com\r\n\r\n";
        let mut modified = payload.to_vec();
        apply_host_space(&mut modified, 0, payload);
        let modified_str = String::from_utf8_lossy(&modified);
        assert!(modified_str.contains("Host: e"));
    }

    #[test]
    fn test_title_case_basic() {
        let payload = b"GET / HTTP/1.1\r\nhost: example.com\r\n";
        let mut packet = payload.to_vec();
        apply_title_case(&mut packet, 0, payload);
        assert_eq!(packet[16], b'H');
    }
}

// ==================== P4: Оставшиеся HTTP техники ====================

/// [NP2] H2SettingsFlood: HTTP/2 SETTINGS frame flooding.
///
/// ## Принцип
/// Отправляем несколько fake HTTP/2 SETTINGS frame'ов перед
/// реальным запросом. DPI должен обработать каждый SETTINGS.
/// Это может переполнить state machine DPI.
///
/// ## Структура HTTP/2 SETTINGS frame
/// ```text
/// Length (3 bytes) | Type = 0x04 (1 byte) | Flags (1 byte) | Stream ID (4 bytes)
/// Setting: Identifier (2 bytes) + Value (4 bytes)
/// ```
pub fn h2_settings_flood(packet: &[u8], count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let mut inject: Vec<bytes::Bytes> = Vec::with_capacity(count);
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    for i in 0..count {
        let settings_frame = build_h2_settings_frame(i);
        let seg = build_http_segment(
            ip.src,
            ip.dst,
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence,
            tcp.acknowledgment,
            tcp.window,
            &settings_frame,
            fake_ttl,
            ip.identification.wrapping_add(i as u16 + 1),
        );
        inject.push(seg);
    }

    debug!("[NP2] H2SettingsFlood: {} SETTINGS frames", count);

    DesyncResult::inject_many(inject)
}

/// [NP3] RstPadding: RST frame с padding.
///
/// ## Принцип
/// Отправляем HTTP/2 RST_STREAM frame с padding перед реальными данными.
/// DPI видит сброс потока и может перестать инспектировать.
pub fn h2_rst_padding(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // RST_STREAM: length=4, type=0x03, flags=0, stream_id=1, error_code=0
    let mut rst_frame = Vec::with_capacity(13);
    rst_frame.extend_from_slice(&[0x00, 0x00, 0x04]); // length=4
    rst_frame.push(0x03); // type: RST_STREAM
    rst_frame.push(0x00); // flags: none
    rst_frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // stream_id=1
    rst_frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // error_code=NO_ERROR

    let seg = build_http_segment(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        tcp.window,
        &rst_frame,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[NP3] RstPadding: fake RST_STREAM injected");

    DesyncResult::inject_only(seg)
}

/// [NP4] H2WindowUpdate: HTTP/2 WINDOW_UPDATE flood.
///
/// ## Принцип
/// Отправляем WINDOW_UPDATE frame'ы с большими значениями.
/// DPI может потратить ресурсы на обновление window state.
pub fn h2_window_update_flood(packet: &[u8], count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let mut inject: Vec<bytes::Bytes> = Vec::with_capacity(count);
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    for i in 0..count {
        // WINDOW_UPDATE: length=4, type=0x08, flags=0, stream_id=0, increment=65535
        let mut frame = Vec::with_capacity(13);
        frame.extend_from_slice(&[0x00, 0x00, 0x04]); // length=4
        frame.push(0x08); // type: WINDOW_UPDATE
        frame.push(0x00); // flags
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // stream_id=0 (connection)
        frame.extend_from_slice(&[0x00, 0x00, 0x7F, 0xFF]); // increment=32767

        let seg = build_http_segment(
            ip.src,
            ip.dst,
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence,
            tcp.acknowledgment,
            tcp.window,
            &frame,
            fake_ttl,
            ip.identification.wrapping_add(i as u16 + 1),
        );
        inject.push(seg);
    }

    debug!("[NP4] H2WindowUpdate: {} WINDOW_UPDATE frames", count);

    DesyncResult::inject_many(inject)
}

/// [NP5] H2Priority: HTTP/2 PRIORITY frame abuse.
///
/// ## Принцип
/// Отправляем PRIORITY frame'ы для манипуляции приоритетами потоков.
/// DPI может неправильно распарсить приоритеты и потерять sync.
pub fn h2_priority_abuse(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // PRIORITY frame: length=5, type=0x02, flags=0, stream_id=0
    let mut frame = Vec::with_capacity(14);
    frame.extend_from_slice(&[0x00, 0x00, 0x05]); // length=5
    frame.push(0x02); // type: PRIORITY
    frame.push(0x00); // flags
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // stream_id=0
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // exclusive=0, dep_stream=1
    frame.push(0xFF); // weight=255

    let seg = build_http_segment(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        tcp.window,
        &frame,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[NP5] H2Priority: fake PRIORITY frame injected");

    DesyncResult::inject_only(seg)
}

/// [NP6] H2Goaway: HTTP/2 GOAWAY injection.
///
/// ## Принцип
/// Отправляем GOAWAY frame с Last-Stream-ID. DPI видит закрытие
/// соединения и может перестать инспектировать последующие данные.
pub fn h2_goaway_inject(packet: &[u8], last_stream_id: u32, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // GOAWAY: length=8, type=0x07, flags=0, stream_id=0
    // + reserved(1) + last_stream_id(4) + error_code(4) = 17 bytes total
    let mut frame = Vec::with_capacity(17);
    frame.extend_from_slice(&[0x00, 0x00, 0x08]); // length=8
    frame.push(0x07); // type: GOAWAY
    frame.push(0x00); // flags
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // stream_id=0
                                                        // reserved + last_stream_id (4 bytes)
    frame.push(0x00); // reserved bit
    frame.push(((last_stream_id >> 24) & 0x7F) as u8);
    frame.push(((last_stream_id >> 16) & 0xFF) as u8);
    frame.push(((last_stream_id >> 8) & 0xFF) as u8);
    frame.push((last_stream_id & 0xFF) as u8);
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // error_code=NO_ERROR

    let seg = build_http_segment(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        tcp.window,
        &frame,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[NP6] H2Goaway: GOAWAY last_stream={}", last_stream_id);

    DesyncResult::inject_only(seg)
}

/// [B1] ChunkObfuscation: обфускация HTTP chunked encoding.
///
/// ## Принцип
/// Разделяем HTTP chunked transfer на多个 TCP сегментов по границам
/// chunk headers. DPI должен собрать chunk boundaries.
pub fn chunk_obfuscation(packet: &[u8], split_count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < split_count * 2 {
        return DesyncResult::passthrough();
    }

    // Проверяем что это chunked transfer
    if !tcp.payload.windows(14).any(|w| w == b"Transfer-Encoding") {
        return DesyncResult::passthrough();
    }

    let seg_size = tcp.payload.len() / split_count;
    let mut inject: Vec<bytes::Bytes> = Vec::new();

    for i in 0..split_count - 1 {
        let start = i * seg_size;
        let end = (i + 1) * seg_size;
        let seg_payload = &tcp.payload[start..end];

        let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
        let seg = build_http_segment(
            ip.src,
            ip.dst,
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence.wrapping_add(start as u32),
            tcp.acknowledgment,
            tcp.window,
            seg_payload,
            fake_ttl,
            ip.identification.wrapping_add(i as u16 + 1),
        );
        inject.push(seg);
    }

    // Последний сегмент — modified original
    let last_start = (split_count - 1) * seg_size;
    let modified = build_http_segment(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(last_start as u32),
        tcp.acknowledgment,
        tcp.window,
        &tcp.payload[last_start..],
        ip.ttl,
        ip.identification.wrapping_add(split_count as u16),
    );

    debug!(
        "[B1] ChunkObfuscation: {} segments × {} bytes",
        split_count, seg_size
    );

    DesyncResult {
        modified: Some(modified),
        inject,
        drop: false,
    }
}

/// [RP12] H2FrameOrdering: манипуляция порядком HTTP/2 frame'ов.
///
/// ## Принцип
/// Отправляем HPACK-encoded headers отдельными frame'ами в
/// неожиданном порядке. DPI может не собрать заголовки.
pub fn h2_frame_ordering(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < 10 {
        return DesyncResult::passthrough();
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // HEADERS frame: type=0x01, flags=END_HEADERS
    let mut headers_frame = Vec::with_capacity(14);
    headers_frame.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
    headers_frame.push(0x01); // type: HEADERS
    headers_frame.push(0x04); // flags: END_HEADERS
    headers_frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // stream_id=1

    // Fake HPACK payload: :method = GET (indexed, index 2)
    headers_frame.push(0x82);

    // Update length
    let payload_len = 1;
    headers_frame[0] = 0;
    headers_frame[1] = 0;
    headers_frame[2] = payload_len;

    let seg = build_http_segment(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        tcp.window,
        &headers_frame,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[RP12] H2FrameOrdering: reordered HEADERS frame");

    DesyncResult::inject_only(seg)
}

/// HTTP Header Case Mixing — чередование регистра в Host header (Demergi).
pub fn http_case_mix(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.data_offset;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 10 {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let payload_start = ip.header_len + data_offset;

    for i in 0..payload.len().saturating_sub(5) {
        if payload[i..i + 5].eq_ignore_ascii_case(b"Host:") {
            let host_bytes = b"Host";
            for j in 0..4 {
                let byte = if j % 2 == 0 {
                    host_bytes[j].to_ascii_lowercase()
                } else {
                    host_bytes[j].to_ascii_uppercase()
                };
                modified[payload_start + i + j] = byte;
            }
            debug!("[HTTP] CaseMix: Host → hOsT");
            return DesyncResult::modified_only(modified);
        }
    }

    DesyncResult::passthrough()
}

/// [NP7] Http11Pipeline: HTTP/1.1 pipeline abuse.
///
/// ## Принцип
/// Отправляем несколько HTTP запросов в одном TCP сегменте
/// (pipelining). DPI может неправильно разбить pipeline.
pub fn http11_pipeline(packet: &[u8], fake_host: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Проверяем что это HTTP/1.1 запрос
    if !is_http_payload(tcp.payload) {
        return DesyncResult::passthrough();
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // Второй pipelined запрос (HEAD вместо GET)
    let pipeline = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
        fake_host
    );

    let seg = build_http_segment(
        ip.src,
        ip.dst,
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(tcp.payload.len() as u32),
        tcp.acknowledgment,
        tcp.window,
        pipeline.as_bytes(),
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[NP7] Http11Pipeline: pipelined HEAD request to '{}'",
        fake_host
    );

    DesyncResult::inject_only(seg)
}

/// [NP8] ContentLengthFuzz: манипуляция Content-Length.
///
/// ## Принцип
/// Добавляем fake Content-Length заголовок с неверным значением
/// перед реальным. DPI может потерять sync по байтам.
pub fn content_length_fuzz(packet: &[u8], fake_cl: usize) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    if !is_http_payload(tcp.payload) {
        return DesyncResult::passthrough();
    }

    // Вставляем fake Content-Length перед \r\n\r\n
    let terminator = tcp.payload.windows(4).position(|w| w == b"\r\n\r\n");
    let term_pos = match terminator {
        Some(p) => p,
        None => return DesyncResult::passthrough(),
    };

    let fake_cl_header = format!("Content-Length: {}\r\n", fake_cl);

    let mut modified = packet.to_vec();
    let insert_offset = ip.header_len + tcp.data_offset + term_pos;

    if insert_offset <= modified.len() {
        modified.splice(insert_offset..insert_offset, fake_cl_header.bytes());

        // Обновляем IP total length
        let new_total = modified.len() as u16;
        modified[2..4].copy_from_slice(&new_total.to_be_bytes());
        let ip_csum = crate::desync::ipv4_checksum(&modified[..20]);
        modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // Пересчитываем TCP checksum
        let tcp_start = ip.header_len;
        let tcp_len = modified.len() - tcp_start;
        if tcp_len > 18 {
            modified[tcp_start + 16] = 0;
            modified[tcp_start + 17] = 0;
        }
        let tcp_csum = crate::desync::tcp_checksum_v4(
            ip.src,
            ip.dst,
            &modified[tcp_start..tcp_start + tcp_len],
        );
        modified[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    }

    debug!("[NP8] ContentLengthFuzz: fake CL={}", fake_cl);

    DesyncResult::modified_only(modified)
}

/// [NP9] HttpUpgrade: HTTP Upgrade abuse.
///
/// ## Принцип
/// Добавляем Upgrade: h2c заголовок. DPI может переключиться
/// на HTTP/2 парсинг и потерять sync с HTTP/1.1 потоком.
pub fn http_upgrade_abuse(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() || !is_http_payload(tcp.payload) {
        return DesyncResult::passthrough();
    }

    // Вставляем Upgrade: h2c перед \r\n\r\n
    let terminator = tcp.payload.windows(4).position(|w| w == b"\r\n\r\n");
    let term_pos = match terminator {
        Some(p) => p,
        None => return DesyncResult::passthrough(),
    };

    let upgrade_header = b"Upgrade: h2c\r\nConnection: Upgrade\r\n";

    let mut modified = packet.to_vec();
    let insert_offset = ip.header_len + tcp.data_offset + term_pos;

    if insert_offset <= modified.len() {
        modified.splice(insert_offset..insert_offset, upgrade_header.iter().copied());

        let new_total = modified.len() as u16;
        modified[2..4].copy_from_slice(&new_total.to_be_bytes());
        let ip_csum = crate::desync::ipv4_checksum(&modified[..20]);
        modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        let tcp_start = ip.header_len;
        let tcp_len = modified.len() - tcp_start;
        if tcp_len > 18 {
            modified[tcp_start + 16] = 0;
            modified[tcp_start + 17] = 0;
        }
        let tcp_csum = crate::desync::tcp_checksum_v4(
            ip.src,
            ip.dst,
            &modified[tcp_start..tcp_start + tcp_len],
        );
        modified[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    }

    debug!("[NP9] HttpUpgrade: Upgrade: h2c injected");

    DesyncResult::modified_only(modified)
}

// ==================== Вспомогательные функции HTTP ====================

/// Строит HTTP/2 SETTINGS frame для инъекции.
fn build_h2_settings_frame(index: usize) -> bytes::Bytes {
    let mut frame = Vec::with_capacity(15);

    // SETTINGS frame: length=6, type=0x04, flags=ACK for index 0
    frame.extend_from_slice(&[0x00, 0x00, 0x06]); // length=6 (1 setting)
    frame.push(0x04); // type: SETTINGS
    if index == 0 {
        frame.push(0x01); // flags: ACK
    } else {
        frame.push(0x00);
    }
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // stream_id=0

    // Setting: HEADER_TABLE_SIZE = 4096 (0x01)
    frame.extend_from_slice(&[0x00, 0x01]); // identifier
    frame.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);

    bytes::Bytes::from(frame)
}

/// Проверяет, является ли payload HTTP запросом/ответом.
fn is_http_payload(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    // HTTP methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT
    // HTTP/1.1 response: "HTTP"
    matches!(
        &payload[..3],
        b"GET" | b"POS" | b"PUT" | b"DEL" | b"HEA" | b"OPT" | b"PAT" | b"CON"
    ) || payload.len() >= 4 && &payload[..4] == b"HTTP"
}

/// Строит TCP сегмент с HTTP payload для P4 техник.
#[allow(clippy::too_many_arguments)]
fn build_http_segment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let tcp_header_len = 20;
    let mut tcp_buf = vec![0u8; tcp_header_len];
    {
        let mut tcp = pnet_packet::tcp::MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::PSH | TcpFlags::ACK);
        tcp.set_window(window);
        tcp.set_checksum(0);
        tcp.set_urgent_ptr(0);
    }
    let checksum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &tcp_buf);
    tcp_buf[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut full_payload = tcp_buf.to_vec();
    full_payload.extend_from_slice(payload);
    crate::desync::build_ip_packet(
        src_ip,
        dst_ip,
        pnet_packet::ip::IpNextHeaderProtocols::Tcp,
        ttl,
        identification,
        &full_payload,
    )
}

#[cfg(test)]
mod p4_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_http_packet() -> bytes::Bytes {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let tcp_len = 20 + http.len();
        let total = 20 + tcp_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1000u32.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::PSH | TcpFlags::ACK;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        let data_start = 40;
        pkt[data_start..data_start + http.len()].copy_from_slice(http);
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        bytes::Bytes::from(pkt)
    }

    #[test]
    fn test_h2_settings_flood() {
        let pkt = make_http_packet();
        let result = h2_settings_flood(&pkt, 3, 1);
        assert_eq!(result.inject.len(), 3);
    }

    #[test]
    fn test_h2_rst_padding() {
        let pkt = make_http_packet();
        let result = h2_rst_padding(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_h2_window_update_flood() {
        let pkt = make_http_packet();
        let result = h2_window_update_flood(&pkt, 2, 1);
        assert_eq!(result.inject.len(), 2);
    }

    #[test]
    fn test_h2_priority_abuse() {
        let pkt = make_http_packet();
        let result = h2_priority_abuse(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_h2_goaway_inject() {
        let pkt = make_http_packet();
        let result = h2_goaway_inject(&pkt, 5, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_http11_pipeline() {
        let pkt = make_http_packet();
        let result = http11_pipeline(&pkt, "evil.com", 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_content_length_fuzz() {
        let pkt = make_http_packet();
        let result = content_length_fuzz(&pkt, 99999);
        assert!(result.modified.is_some());
    }

    #[test]
    fn test_http_upgrade_abuse() {
        let pkt = make_http_packet();
        let result = http_upgrade_abuse(&pkt);
        assert!(result.modified.is_some());
    }

    #[test]
    fn test_non_http_passthrough() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::PSH | TcpFlags::ACK;
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(h2_settings_flood(&pkt, 3, 1).inject.len(), 0);
        assert_eq!(h2_rst_padding(&pkt, 1).inject.len(), 0);
        assert_eq!(http11_pipeline(&pkt, "x.com", 1).inject.len(), 0);
    }

    #[test]
    fn test_build_h2_settings_frame() {
        let frame = build_h2_settings_frame(0);
        assert_eq!(frame[3], 0x04);
        assert_eq!(frame[4], 0x01);
    }

    #[test]
    fn test_is_http_payload() {
        assert!(is_http_payload(b"GET / HTTP/1.1"));
        assert!(is_http_payload(b"POST /api"));
        assert!(is_http_payload(b"HTTP/1.1 200 OK"));
        assert!(!is_http_payload(b"\x16\x03\x01"));
    }

    #[test]
    fn test_build_http_segment_fn() {
        let seg = build_http_segment(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            443,
            1000,
            2000,
            65535,
            b"test",
            64,
            1,
        );
        assert!(seg.len() > 40);
        assert_eq!(seg[0] >> 4, 4);
    }
}
