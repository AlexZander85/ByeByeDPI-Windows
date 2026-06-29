//! Packet Classifier — классификация пакетов по протоколу и направлению.

use crate::conntrack::ConnKey;
use pnet_packet::{ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket};
use std::net::Ipv4Addr;

/// Направление пакета относительно origin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketDirection {
    /// От клиента к серверу (outbound)
    Outbound,
    /// От сервера к клиенту (inbound)
    Inbound,
}

/// Классифицированный пакет.
#[derive(Debug)]
pub struct ClassifiedPacket {
    /// Исходный IP
    pub src_ip: Ipv4Addr,
    /// IP назначения
    pub dst_ip: Ipv4Addr,
    /// Порт источника
    pub src_port: u16,
    /// Порт назначения
    pub dst_port: u16,
    /// Протокол
    pub protocol: u8,
    /// Направление
    pub direction: PacketDirection,
    /// Ключ соединения (для conntrack)
    pub conn_key: ConnKey,
    /// Указатель на начало payload (TCP/UDP data)
    pub payload_offset: usize,
    /// Длина payload
    pub payload_len: usize,
}

/// Результат классификации.
pub enum Classification {
    /// TLS (TCP:443)
    Tls(ClassifiedPacket),
    /// QUIC (UDP:443)
    Quic(ClassifiedPacket),
    /// DNS (UDP:53)
    Dns(ClassifiedPacket),
    /// HTTP (TCP:80)
    Http(ClassifiedPacket),
    /// Другой протокол
    Other(ClassifiedPacket),
    /// Не смогли разобрать пакет
    Unknown,
}

/// Классификатор пакетов.
pub struct Classifier;

impl Classifier {
    /// Классифицирует raw IP пакет.
    pub fn classify(packet: &[u8]) -> Classification {
        let ip = match Ipv4Packet::new(packet) {
            Some(ip) => ip,
            None => return Classification::Unknown,
        };

        let src_ip = ip.get_source();
        let dst_ip = ip.get_destination();
        let protocol = ip.get_next_level_protocol().0;
        let header_len = ip.get_header_length() as usize * 4;

        match protocol {
            6 => {
                // TCP
                let tcp = match TcpPacket::new(&packet[header_len..]) {
                    Some(tcp) => tcp,
                    None => return Classification::Unknown,
                };
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let tcp_header_len = (tcp.get_data_offset() as usize) * 4;
                let payload_offset = header_len + tcp_header_len;

                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    direction: PacketDirection::Outbound, // будет уточнено
                    conn_key: ConnKey::new(src_ip, dst_ip, src_port, dst_port),
                    payload_offset,
                    payload_len: packet.len().saturating_sub(payload_offset),
                };

                // Content-based classification (DPI) before port fallback
                let payload = &packet[payload_offset..];
                if payload.len() >= 5 {
                    // TLS ClientHello: 0x16 0x03 0x01-0x03
                    if payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x03 {
                        return Classification::Tls(cp);
                    }
                    // HTTP methods
                    if payload.starts_with(b"GET ")
                        || payload.starts_with(b"POST ")
                        || payload.starts_with(b"PUT ")
                        || payload.starts_with(b"HEAD ")
                        || payload.starts_with(b"DELETE ")
                        || payload.starts_with(b"CONNECT ")
                        || payload.starts_with(b"OPTIONS ")
                    {
                        return Classification::Http(cp);
                    }
                    // HTTP/2 connection preface
                    if payload.len() >= 24 && &payload[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                    {
                        return Classification::Http(cp);
                    }
                }

                // Port-based fallback
                match dst_port {
                    443 => Classification::Tls(cp),
                    80 => Classification::Http(cp),
                    _ => Classification::Other(cp),
                }
            }
            17 => {
                // UDP
                let udp = match UdpPacket::new(&packet[header_len..]) {
                    Some(udp) => udp,
                    None => return Classification::Unknown,
                };
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                let payload_offset = header_len + 8; // UDP header = 8 bytes

                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    direction: PacketDirection::Outbound,
                    conn_key: ConnKey::new(src_ip, dst_ip, src_port, dst_port),
                    payload_offset,
                    payload_len: packet.len().saturating_sub(payload_offset),
                };

                // Content-based QUIC detection (long header: first bit = 1)
                let payload = &packet[payload_offset..];
                if !payload.is_empty() && (payload[0] & 0x80) != 0 {
                    return Classification::Quic(cp);
                }

                match dst_port {
                    53 => Classification::Dns(cp),
                    443 => Classification::Quic(cp),
                    _ => Classification::Other(cp),
                }
            }
            _ => {
                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port: 0,
                    dst_port: 0,
                    protocol,
                    direction: PacketDirection::Outbound,
                    conn_key: ConnKey::new(src_ip, dst_ip, 0, 0),
                    payload_offset: header_len,
                    payload_len: packet.len().saturating_sub(header_len),
                };
                Classification::Other(cp)
            }
        }
    }

    /// Определяет направление пакета на основе conntrack.
    ///
    /// Если src_ip — локальный → Outbound.
    /// Иначе → Inbound (ответ сервера).
    pub fn determine_direction(local_ips: &[Ipv4Addr], cp: &ClassifiedPacket) -> PacketDirection {
        if local_ips.contains(&cp.src_ip) {
            PacketDirection::Outbound
        } else {
            PacketDirection::Inbound
        }
    }

    /// Проверяет, является ли пакет TLS ClientHello.
    pub fn is_client_hello(payload: &[u8]) -> bool {
        payload.len() > 5
            && payload[0] == 0x16 // ContentType: Handshake
            && (payload[1] == 0x03) // TLS version major
            && payload[5] == 0x01 // HandshakeType: ClientHello
    }

    /// Проверяет, является ли пакет TLS ServerHello.
    pub fn is_server_hello(payload: &[u8]) -> bool {
        payload.len() > 5 && payload[0] == 0x16 && (payload[1] == 0x03) && payload[5] == 0x02
        // HandshakeType: ServerHello
    }

    /// Извлекает SNI из TLS ClientHello.
    ///
    /// Возвращает Some(domain) если найден.
    pub fn extract_sni(payload: &[u8]) -> Option<String> {
        if !Self::is_client_hello(payload) {
            return None;
        }

        // Парсим extensions в ClientHello
        // Позиция после session_id
        let session_id_len = payload[43] as usize;

        if 44 + session_id_len + 2 > payload.len() {
            return None;
        }

        let cipher_suites_len = ((payload[44 + session_id_len] as usize) << 8)
            | (payload[45 + session_id_len] as usize);

        let mut pos = 46 + session_id_len + cipher_suites_len;

        if pos + 1 >= payload.len() {
            return None;
        }

        let compression_len = payload[pos] as usize;
        pos += 1 + compression_len;

        if pos + 2 > payload.len() {
            return None;
        }

        let ext_total_len = ((payload[pos] as usize) << 8) | (payload[pos + 1] as usize);
        pos += 2;

        let end = pos + ext_total_len;
        while pos + 4 <= end && pos + 4 <= payload.len() {
            let ext_type = ((payload[pos] as usize) << 8) | (payload[pos + 1] as usize);
            let ext_len = ((payload[pos + 2] as usize) << 8) | (payload[pos + 3] as usize);

            pos += 4;

            if ext_type == 0x0000 {
                // SNI extension
                if pos + 3 > payload.len() {
                    return None;
                }
                let sni_list_len = ((payload[pos] as usize) << 8) | (payload[pos + 1] as usize);
                if pos + 3 + sni_list_len > payload.len() {
                    return None;
                }
                let name_type = payload[pos + 2];
                if name_type == 0 {
                    // host_name
                    let name_len = ((payload[pos + 3] as usize) << 8) | (payload[pos + 4] as usize);
                    if pos + 5 + name_len <= payload.len() {
                        return String::from_utf8(payload[pos + 5..pos + 5 + name_len].to_vec())
                            .ok();
                    }
                }
                return None;
            }

            pos += ext_len;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_tcp_syn() {
        // Build a minimal TCP SYN packet
        let pkt = vec![
            0x45, 0x00, 0x00, 0x28, // IP header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, // TCP proto
            0xc0, 0xa8, 0x01, 0x01, // src: 192.168.1.1
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
            // TCP header (20 bytes)
            0x30, 0x39, // src port: 12345
            0x01, 0xbb, // dst port: 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x71, 0x10, // data offset + flags + window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent ptr
        ];

        match Classifier::classify(&pkt) {
            Classification::Tls(cp) => {
                assert_eq!(cp.dst_port, 443);
                assert_eq!(cp.src_ip, Ipv4Addr::new(192, 168, 1, 1));
            }
            _ => panic!("Expected TLS classification"),
        }
    }

    #[test]
    fn test_classify_dns() {
        let pkt = vec![
            0x45, 0x00, 0x00, 0x1c, // IP header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // UDP proto
            0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08, // UDP header (8 bytes)
            0x00, 0x35, // src port: 53
            0x00, 0x35, // dst port: 53
            0x00, 0x08, 0x00, 0x00, // length + checksum
        ];

        match Classifier::classify(&pkt) {
            Classification::Dns(cp) => {
                assert_eq!(cp.dst_port, 53);
            }
            _ => panic!("Expected DNS classification"),
        }
    }

    #[test]
    fn test_client_hello_detection() {
        let ch = vec![
            0x16, 0x03, 0x01, 0x00, 0x02, // record
            0x01, // ClientHello
        ];
        assert!(Classifier::is_client_hello(&ch));

        let not_ch = vec![0x16, 0x03, 0x01, 0x00, 0x02, 0x02]; // ServerHello
        assert!(!Classifier::is_client_hello(&not_ch));
    }

    #[test]
    fn test_direction_detection() {
        let local_ips = vec![Ipv4Addr::new(192, 168, 1, 1)];
        let remote = Ipv4Addr::new(8, 8, 8, 8);

        let cp = ClassifiedPacket {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: remote,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            direction: PacketDirection::Outbound,
            conn_key: ConnKey::new(Ipv4Addr::new(192, 168, 1, 1), remote, 12345, 443),
            payload_offset: 40,
            payload_len: 0,
        };

        assert_eq!(
            Classifier::determine_direction(&local_ips, &cp),
            PacketDirection::Outbound
        );
    }

    #[test]
    fn test_unknown_packet() {
        let pkt = vec![0x00; 10]; // Too short for IP
        match Classifier::classify(&pkt) {
            Classification::Unknown => {} // expected
            _ => panic!("Expected Unknown"),
        }
    }
}
