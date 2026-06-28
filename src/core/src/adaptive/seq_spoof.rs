//! SEQ Number Spoofing — fake ClientHello с SEQ вне окна приёма DPI.
//!
//! ## Принцип работы
//! DPI отслеживает TCP SEQ/ACK для сборки потока. Если отправить fake
//! ClientHello с SEQ, который DPI ещё не ожидает (out-of-window), DPI
//! может принять его за настоящий ClientHello. Реальный ClientHello
//! идёт следом с корректным SEQ и перезаписывает данные на сервере.
//!
//! ## Математика
//! ```text
//! SYN:      client(SEQ=1000)             → server
//! SYN-ACK:  client(ACK=1001)             ← server(SEQ=5000)
//! FAKE CH:  client(SEQ=10000)            → DPI (out-of-window!)
//! REAL CH:  client(SEQ=1001, ACK=5001)   → server (correct SEQ)
//!           DPI видит fake CH как "ClientHello"
//!           Сервер принимает real CH, игнорирует fake
//! ```
//!
//! ## Требования
//! - Raw socket (IP_HDRINCL) — полный контроль TCP SEQ
//! - HopTab для fake TTL — fake CH не должен дойти до сервера
//! - ClientHello generator — создание CH без дампа
//! - Conntrack — знание реального SEQ/ACK
//!
//! ## Источник
//! Адаптировано из [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust) —
//! техника SEQ Number Spoofing.

use crate::adaptive::ch_gen;
use crate::adaptive::hop_tab::HopTab;
use crate::conntrack::Conntrack;
use anyhow::Result;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use std::net::Ipv4Addr;
use tracing::debug;

/// Смещение SEQ для fake ClientHello (насколько далеко от окна).
///
/// DPI ожидает SEQ в диапазоне [client_isn, client_isn + window].
/// Fake CH отправляется с SEQ = client_isn + SPOOF_OFFSET, что
/// гарантированно вне окна приёма (окно обычно 65535).
const SPOOF_OFFSET: u32 = 10_000;

/// Результат операции SEQ Spoofing.
#[derive(Debug)]
pub struct SeqSpoofResult {
    /// Fake ClientHello (полный IP + TCP пакет для инъекции)
    pub fake_packet: Vec<u8>,
    /// Рекомендованный TTL для fake пакета
    pub fake_ttl: u8,
}

/// Выполняет SEQ Number Spoofing.
///
/// Строит fake IP + TCP пакет с ClientHello, где SEQ установлен
/// вне окна приёма DPI. fake TTL берётся из HopTab (на 1 меньше,
/// чем нужно, чтобы пакет НЕ дошёл до сервера).
///
/// # Arguments
/// * `fake_sni` — SNI для fake ClientHello
/// * `src_ip` — IP источника (локальный)
/// * `dst_ip` — IP назначения (сервер)
/// * `src_port` — порт источника
/// * `dst_port` — порт назначения (обычно 443)
/// * `client_isn` — начальный SEQ клиента (из conntrack после SYN-ACK)
/// * `conntrack` — connection tracking (для получения SEQ/ACK)
/// * `hop_tab` — auto-TTL cache (для fake TTL)
///
/// # Returns
/// `SeqSpoofResult` с готовым пакетом для инъекции через raw socket.
///
/// # Errors
/// Возвращает ошибку если:
/// - HopTab не имеет данных для этого IP
/// - Размер пакета превышает лимиты
#[allow(clippy::too_many_arguments)]
pub fn build_seq_spoof_packet(
    fake_sni: &str,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    client_isn: u32,
    _conntrack: &Conntrack,
    hop_tab: &HopTab,
) -> Result<SeqSpoofResult> {
    let fake_ch = ch_gen::build_client_hello(fake_sni);

    // Определяем fake TTL из HopTab
    let fake_ttl = hop_tab.fake_ttl_for_ip(&dst_ip).unwrap_or(64); // fallback, если нет данных

    // Строим полный IP + TCP пакет
    let packet = build_fake_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        client_isn.wrapping_add(SPOOF_OFFSET), // SEQ вне окна
        0,                                     // ACK = 0 (fake SYN-like)
        &fake_ch,
        fake_ttl,
    )?;

    debug!(
        "SEQ Spoof: {}:{} → {}:{} fake_seq={} real_isn={} fake_ttl={} sni={}",
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        client_isn.wrapping_add(SPOOF_OFFSET),
        client_isn,
        fake_ttl,
        fake_sni,
    );

    Ok(SeqSpoofResult {
        fake_packet: packet,
        fake_ttl,
    })
}

/// Строит fake IP + TCP пакет с payload и указанным SEQ.
///
/// # Arguments
/// * `src_ip` — IP источника
/// * `dst_ip` — IP назначения
/// * `src_port` — порт источника
/// * `dst_port` — порт назначения
/// * `seq_num` — TCP sequence number (fake, out-of-window)
/// * `ack_num` — TCP acknowledgement number
/// * `payload` — данные (TLS ClientHello)
/// * `ttl` — IP TTL (может быть fake для предотвращения доставки)
///
/// # Returns
/// Полный IP пакет (Vec<u8>), готовый для отправки через raw socket.
#[allow(clippy::too_many_arguments)]
fn build_fake_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    payload: &[u8],
    ttl: u8,
) -> Result<Vec<u8>> {
    const IP_HLEN: usize = 20;
    const TCP_HLEN: usize = 20;
    let total_len = IP_HLEN + TCP_HLEN + payload.len();

    let mut buf = vec![0u8; total_len];

    // --- IP Header (use pnet_packet to set fields, compute checksum after scope) ---
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IP_HLEN])
            .ok_or_else(|| anyhow::anyhow!("Failed to create IP packet"))?;
        ip.set_version(4);
        ip.set_header_length((IP_HLEN / 4) as u8);
        ip.set_total_length(total_len as u16);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
    }
    // Write IP checksum manually (after MutableIpv4Packet scope ends)
    let cksum = ipv4_checksum(&buf[..IP_HLEN]);
    let cksum_bytes = cksum.to_be_bytes();
    buf[10] = cksum_bytes[0];
    buf[11] = cksum_bytes[1];

    // --- TCP Header (use pnet_packet to set fields, compute checksum after scope) ---
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IP_HLEN..])
            .ok_or_else(|| anyhow::anyhow!("Failed to create TCP packet"))?;
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(ack_num);
        tcp.set_data_offset((TCP_HLEN / 4) as u8);
        tcp.set_flags(0x02); // SYN flag
        tcp.set_window(65535);
        tcp.set_urgent_ptr(0);
    }
    // Copy payload (after TCP header)
    if !payload.is_empty() {
        buf[IP_HLEN + TCP_HLEN..][..payload.len()].copy_from_slice(payload);
    }
    // Write TCP checksum manually (after MutableTcpPacket scope ends)
    let cksum = tcp_checksum_v4(&src_ip.octets(), &dst_ip.octets(), &buf[IP_HLEN..]);
    let cksum_bytes = cksum.to_be_bytes();
    buf[IP_HLEN + 16] = cksum_bytes[0];
    buf[IP_HLEN + 17] = cksum_bytes[1];

    Ok(buf)
}

/// Вычисляет IP header checksum.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    // One's complement
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Вычисляет TCP checksum с IPv4 псевдо-header.
fn tcp_checksum_v4(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    // Псевдо-header: src_ip(4) + dst_ip(4) + zeros(1) + proto(1) + tcp_len(2) = 12 байт
    let tcp_len = tcp_segment.len() as u16;
    let mut sum: u32 = 0;

    // Псевдо-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // TCP protocol number
    sum += tcp_len as u32;

    // TCP segment (с checksum = 0)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // One's complement
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Альтернативная стратегия: fake CH с badsum (dpibreak).
///
/// Отличается от `build_seq_spoof_packet` тем, что использует
/// **неправильную** TCP checksum. Fake пакет гарантированно будет
/// отброшен сервером (но DPI может его обработать до проверки checksum).
///
/// Плюс: не нужен HopTab (fake TTL не обязателен).
/// Минус: некоторые DPI проверяют checksum.
pub fn build_seq_spoof_packet_badsum(
    fake_sni: &str,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    client_isn: u32,
) -> Result<SeqSpoofResult> {
    let fake_ch = ch_gen::build_client_hello(fake_sni);

    let mut packet = build_fake_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        client_isn.wrapping_add(SPOOF_OFFSET),
        0,
        &fake_ch,
        64, // TTL не важен для badsum
    )?;

    // Инвертируем checksum (делаем заведомо неправильной)
    let tcp_start = 20; // IP header = 20 bytes
    if packet.len() > tcp_start + 18 {
        let cksum = &packet[tcp_start + 16..tcp_start + 18];
        let bad = (!u16::from_be_bytes([cksum[0], cksum[1]])).to_be_bytes();
        packet[tcp_start + 16] = bad[0];
        packet[tcp_start + 17] = bad[1];
    }

    debug!(
        "SEQ Spoof (badsum): {}:{} → {}:{}",
        src_ip, src_port, dst_ip, dst_port
    );

    Ok(SeqSpoofResult {
        fake_packet: packet,
        fake_ttl: 64,
    })
}

/// Строит fake TCP RST пакет для сброса DPI состояния.
///
/// Отправляется сразу после fake CH, чтобы сбить DPI с толку.
pub fn build_fake_rst_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Result<Vec<u8>> {
    const IP_HLEN: usize = 20;
    const TCP_HLEN: usize = 20;
    let total_len = IP_HLEN + TCP_HLEN;

    let mut buf = vec![0u8; total_len];

    // --- IP Header ---
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IP_HLEN])
            .ok_or_else(|| anyhow::anyhow!("Failed to create IP packet"))?;
        ip.set_version(4);
        ip.set_header_length((IP_HLEN / 4) as u8);
        ip.set_total_length(total_len as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
    }
    // Write IP checksum manually
    let cksum = ipv4_checksum(&buf[..IP_HLEN]);
    let cksum_bytes = cksum.to_be_bytes();
    buf[10] = cksum_bytes[0];
    buf[11] = cksum_bytes[1];

    // --- TCP Header ---
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IP_HLEN..])
            .ok_or_else(|| anyhow::anyhow!("Failed to create TCP packet"))?;
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(ack_num);
        tcp.set_data_offset((TCP_HLEN / 4) as u8);
        tcp.set_flags(0x04 | 0x10); // RST + ACK
        tcp.set_window(0);
        tcp.set_urgent_ptr(0);
    }
    // Write TCP checksum manually
    let cksum = tcp_checksum_v4(&src_ip.octets(), &dst_ip.octets(), &buf[IP_HLEN..]);
    let cksum_bytes = cksum.to_be_bytes();
    buf[IP_HLEN + 16] = cksum_bytes[0];
    buf[IP_HLEN + 17] = cksum_bytes[1];

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::hop_tab::HopTab;
    use crate::conntrack::{ConnState, Conntrack, ConntrackEntry};
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn setup_conntrack() -> Conntrack {
        let ct = Conntrack::default();
        let key = crate::conntrack::ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(142, 250, 185, 46),
            54321,
            443,
        );
        let entry = ConntrackEntry {
            client_isn: 1000,
            server_isn: 5000,
            client_seq: 1001,
            server_seq: 5001,
            client_ack: 5001,
            server_ack: 1001,
            rtt_us: 50000,
            state: ConnState::SynReceived,
            desync_applied: false,
            strategy_id: 0,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
        };
        ct.insert(key, entry);
        ct
    }

    #[test]
    fn test_seq_spoof_packet_size() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&ip), 12);

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2),
            ip,
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        // IP(20) + TCP(20) + TLS CH(517) = 557
        let expected_size = 20 + 20 + ch_gen::CLIENT_HELLO_SIZE;
        assert_eq!(result.fake_packet.len(), expected_size);
    }

    #[test]
    fn test_seq_spoof_fake_seq() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&ip), 12);

        let result = build_seq_spoof_packet(
            "test.com",
            Ipv4Addr::new(192, 168, 1, 2),
            ip,
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let fake_packet = &result.fake_packet;
        // TCP header starts at byte 20 (after IP header)
        let tcp_seq_bytes = &fake_packet[24..28]; // TCP SEQ at offset 4 from TCP header
        let tcp_seq = u32::from_be_bytes([
            tcp_seq_bytes[0],
            tcp_seq_bytes[1],
            tcp_seq_bytes[2],
            tcp_seq_bytes[3],
        ]);
        // Expected: client_isn(1000) + SPOOF_OFFSET(10000) = 11000
        assert_eq!(tcp_seq, 11000);
    }

    #[test]
    fn test_seq_spoof_ttl_from_hop_tab() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&ip), 12); // 12 hops

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2),
            ip,
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        // IP TTL at byte 8
        let ttl = result.fake_packet[8];
        // 12 hops → fake TTL = 11
        assert_eq!(ttl, 11);
    }

    #[test]
    fn test_seq_spoof_fallback_ttl() {
        let ct = setup_conntrack();
        let ht = HopTab::new(); // Empty HopTab
        let ip = Ipv4Addr::new(142, 250, 185, 46);

        // HopTab empty → fallback TTL = 64
        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2),
            ip,
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let ttl = result.fake_packet[8];
        assert_eq!(ttl, 64);
    }

    #[test]
    fn test_seq_spoof_ip_header_fields() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&ip), 8);

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2),
            ip,
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let pkt = &result.fake_packet;
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 6); // TCP protocol
                               // Source IP
        assert_eq!(&pkt[12..16], &[192, 168, 1, 2]);
        // Dest IP
        assert_eq!(&pkt[16..20], &[142, 250, 185, 46]);
    }

    #[test]
    fn test_seq_spoof_badsum() {
        let result = build_seq_spoof_packet_badsum(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(142, 250, 185, 46),
            54321,
            443,
            1000,
        )
        .unwrap();

        let expected_size = 20 + 20 + ch_gen::CLIENT_HELLO_SIZE;
        assert_eq!(result.fake_packet.len(), expected_size);
    }

    #[test]
    fn test_fake_rst_packet() {
        let pkt = build_fake_rst_packet(
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(142, 250, 185, 46),
            54321,
            443,
            1001,
            5001,
        )
        .unwrap();

        // IP(20) + TCP(20) = 40 bytes
        assert_eq!(pkt.len(), 40);
        // IP protocol = TCP
        assert_eq!(pkt[9], 6);
        // TCP flags: RST + ACK (0x14)
        let tcp_flags = pkt[33]; // TCP header starts at 20, flags at offset 13
        assert_eq!(tcp_flags, 0x14);
    }

    #[test]
    fn test_ipv4_checksum() {
        // Пример: простой IP header
        let header = vec![
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
        ];
        let cksum = ipv4_checksum(&header);
        assert!(cksum != 0);
    }

    #[test]
    fn test_tcp_checksum_v4() {
        let src = [192, 168, 1, 1];
        let dst = [8, 8, 8, 8];
        let tcp = vec![
            0x00, 0x35, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x71, 0x10, 0x00, 0x00, 0x00, 0x00,
        ];
        let cksum = tcp_checksum_v4(&src, &dst, &tcp);
        assert!(cksum != 0);
    }
}
