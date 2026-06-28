//! Synthetic Event Tagging — UUID-теги для injected пакетов.
//!
//! ## Проблема
//! При инъекции пакетов через raw socket они могут быть повторно перехвачены
//! WinDivert, создавая бесконечный loop (inject → divert → inject → ...).
//!
//! ## Решение
//! Глобальный UUID-тег (16 байт), который записывается в
//! **TCP payload** (не в IP header!) каждого injected пакета.
//!
//! WinDivert фильтр исключает пакеты с этим тегом:
//! ```text
//! not (tcp.PayloadLength >= 16 and
//!      tcp.Payload[0:16] == <UUID bytes>)
//! ```
//!
//! ## Важно
//! Тег пишется в TCP payload (после IP + TCP заголовков), а НЕ в начало пакета.
//! Запись в packet[0..16] уничтожит IP header и сломает пакет.

use std::sync::OnceLock;
use uuid::Uuid;

const UUID_SIZE: usize = 16;

static GLOBAL_TAG: OnceLock<[u8; UUID_SIZE]> = OnceLock::new();

fn tag() -> &'static [u8; UUID_SIZE] {
    GLOBAL_TAG.get_or_init(|| *Uuid::new_v4().as_bytes())
}

/// Определяет смещение до TCP payload в пакете.
///
/// Возвращает смещение (bytes) от начала пакета до начала TCP payload.
/// Если пакет не содержит TCP — возвращает `None`.
fn tcp_payload_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }

    let version = (packet[0] >> 4) & 0xF;
    if version != 4 {
        return None;
    }

    let ihl = (packet[0] & 0xF) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    if packet[9] != 6 {
        return None;
    }

    if packet.len() < ihl + 12 {
        return None;
    }
    let tcp_header_len = ((packet[ihl + 12] >> 4) & 0xF) as usize * 4;

    Some(ihl + tcp_header_len)
}

/// Маркирует пакет UUID-тегом в TCP payload.
pub fn tag_injected_packet(packet: &mut [u8]) {
    let Some(offset) = tcp_payload_offset(packet) else {
        return;
    };

    let payload_end = packet.len();
    if payload_end - offset < UUID_SIZE {
        return;
    }

    let t = tag();
    packet[offset..offset + UUID_SIZE].copy_from_slice(t);
}

/// Проверяет, является ли пакет нашим собственным injected.
pub fn is_injected_packet(packet: &[u8]) -> bool {
    let Some(offset) = tcp_payload_offset(packet) else {
        return false;
    };

    let payload_end = packet.len();
    if payload_end - offset < UUID_SIZE {
        return false;
    }

    &packet[offset..offset + UUID_SIZE] == tag()
}

/// Генерирует строку для WinDivert фильтра.
pub fn injected_filter_clause() -> String {
    let t = tag();
    let hex_bytes: Vec<String> = t.iter().map(|b| format!("{:#04x}", b)).collect();
    format!(
        "not (tcp.PayloadLength >= {} and tcp.Payload[0:16] == {})",
        UUID_SIZE,
        hex_bytes.join(" ")
    )
}

pub fn reset_injection_tag() {
    let new_uuid = Uuid::new_v4();
    let _ = GLOBAL_TAG.set(*new_uuid.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tcp_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt
    }

    #[test]
    fn test_tag_in_tcp_payload() {
        let mut pkt = build_tcp_packet();
        assert_eq!(tcp_payload_offset(&pkt), Some(40));

        tag_injected_packet(&mut pkt);
        assert!(is_injected_packet(&pkt));

        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[9], 6);
        assert_ne!(pkt[40], 0);
    }

    #[test]
    fn test_non_tcp_packet_not_tagged() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 17;
        tag_injected_packet(&mut pkt);
        assert!(!is_injected_packet(&pkt));
    }

    #[test]
    fn test_short_payload_no_tag() {
        let mut pkt = build_tcp_packet();
        tag_injected_packet(&mut pkt);
        assert!(is_injected_packet(&pkt));
    }

    #[test]
    fn test_empty_packet_no_panic() {
        let mut empty: Vec<u8> = vec![];
        tag_injected_packet(&mut empty);
        assert!(!is_injected_packet(&empty));
    }

    #[test]
    fn test_filter_clause_format() {
        let clause = injected_filter_clause();
        assert!(clause.starts_with("not (tcp.PayloadLength >= 16"));
    }

    #[test]
    fn test_ip_header_preserved() {
        let mut pkt = build_tcp_packet();
        let original_ip = pkt[..20].to_vec();

        tag_injected_packet(&mut pkt);

        assert_eq!(pkt[..20], original_ip[..]);
    }
}
