//! DNS Integrity Probe — cross-validation UDP/53 vs DoH.
//!
//! Методика (из dpi-detector):
//! 1. Запрос A-записи через UDP/53
//! 2. Запрос A-записи через DoH (RFC 8484)
//! 3. Cross-validate:
//!    - UDP IPs ⊂ DoH IPs → OK
//!    - UDP IPs ∩ DoH IPs = ∅ → Poisoned
//!    - UDP timeout, DoH ok → Intercepted
//!    - UDP NXDOMAIN, DoH ok → NxdomainSpoof
//!    - UDP пустой, DoH ok → EmptySpoof
//!    - Все DoH timeout → DohBlocked
//!
//! Дополнительно: Fake-IP range detection (198.18.0.0/15, 100.64.0.0/10).

use crate::probe::classifier::DnsFailureCode;
use crate::probe::config::ProbeConfig;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, warn};

/// Результат DNS probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProbeResult {
    pub verdict: DnsFailureCode,
    pub resolved_ips: Vec<Ipv4Addr>,
    pub udp_ips: Vec<Ipv4Addr>,
    pub doh_ips: Vec<Ipv4Addr>,
    pub latency_us: u64,
    /// Обнаружены ли fake-IP адреса
    pub fake_ip_detected: bool,
}

/// Результат одного UDP DNS запроса.
#[derive(Debug, Clone)]
enum UdpDnsResult {
    /// Успешный ответ с IP адресами
    Ok(Vec<Ipv4Addr>),
    /// NXDOMAIN — домен не существует (по rcode)
    Nxdomain,
    /// Пустой ответ ( есть заголовок, но нет A-записей)
    EmptyResponse,
    /// Таймаут — нет ответа
    Timeout,
    /// Ошибка парсинга или другая ошибка
    Error,
}

/// DNS Probe — cross-validation UDP vs DoH.
pub struct DnsProbe {
    config: ProbeConfig,
    doh_client: reqwest::Client,
}

impl DnsProbe {
    pub fn new(config: &ProbeConfig) -> Self {
        let doh_client = reqwest::Client::builder()
            .timeout(config.dns_timeout)
            .build()
            .expect("Failed to create DoH client");

        Self {
            config: config.clone(),
            doh_client,
        }
    }

    /// Запрос A-записи через UDP/53.
    async fn query_udp(&self, domain: &str, server: &str) -> UdpDnsResult {
        let sock_addr: SocketAddr = match format!("{}:53", server).parse() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Invalid DNS server address {}: {}", server, e);
                return UdpDnsResult::Error;
            }
        };

        let query = build_dns_query(domain);
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to bind UDP socket: {}", e);
                return UdpDnsResult::Error;
            }
        };

        if let Err(e) = socket.send_to(&query, sock_addr).await {
            warn!("UDP send failed to {}: {}", server, e);
            return UdpDnsResult::Error;
        }

        let mut buf = vec![0u8; 512];
        match tokio::time::timeout(self.config.dns_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => parse_dns_response_detailed(&buf[..len]),
            Ok(Err(e)) => {
                debug!("UDP recv error from {}: {}", server, e);
                UdpDnsResult::Error
            }
            Err(_) => {
                debug!("UDP timeout from {}", server);
                UdpDnsResult::Timeout
            }
        }
    }

    /// Запрос A-записи через DoH (RFC 8484, GET с base64).
    async fn query_doh(&self, domain: &str, url: &str) -> Vec<Ipv4Addr> {
        let query = build_dns_query(domain);
        let encoded = base64url_encode(&query);

        let doh_url = format!("{}?dns={}", url, encoded);

        match tokio::time::timeout(
            self.config.dns_timeout,
            self.doh_client.get(&doh_url).send(),
        )
        .await
        {
            Ok(Ok(resp)) => {
                if resp.status().is_success() {
                    match resp.bytes().await {
                        Ok(body) => parse_dns_response_ips(&body),
                        Err(e) => {
                            debug!("DoH read error: {}", e);
                            vec![]
                        }
                    }
                } else {
                    debug!("DoH HTTP status: {}", resp.status());
                    vec![]
                }
            }
            Ok(Err(e)) => {
                debug!("DoH request error: {}", e);
                vec![]
            }
            Err(_) => {
                debug!("DoH timeout for {}", url);
                vec![]
            }
        }
    }

    /// Cross-validation: UDP vs DoH.
    pub async fn probe(&self, domain: &str) -> DnsProbeResult {
        let start = std::time::Instant::now();

        // Parallel: all UDP servers + all DoH servers
        let mut udp_futs = Vec::new();
        for server in &self.config.dns_udp_servers {
            let domain = domain.to_string();
            let server = server.clone();
            let config = self.config.clone();
            let doh_client = self.doh_client.clone();
            udp_futs.push(async move {
                let probe = DnsProbe { config, doh_client };
                probe.query_udp(&domain, &server).await
            });
        }

        let mut doh_futs = Vec::new();
        for url in &self.config.dns_doh_urls {
            let domain = domain.to_string();
            let url = url.clone();
            let config = self.config.clone();
            let doh_client = self.doh_client.clone();
            doh_futs.push(async move {
                let probe = DnsProbe { config, doh_client };
                probe.query_doh(&domain, &url).await
            });
        }

        // Execute all queries in parallel
        let (udp_results, doh_results) = tokio::join!(
            futures::future::join_all(udp_futs),
            futures::future::join_all(doh_futs),
        );

        // Analyze UDP results
        let mut all_udp_ips: Vec<Ipv4Addr> = Vec::new();
        let mut any_udp_timeout = false;
        let mut any_udp_nxdomain = false;

        for result in udp_results {
            match result {
                UdpDnsResult::Ok(ips) => {
                    all_udp_ips.extend(ips);
                }
                UdpDnsResult::Nxdomain => any_udp_nxdomain = true,
                UdpDnsResult::Timeout => any_udp_timeout = true,
                _ => {}
            }
        }
        all_udp_ips.sort();
        all_udp_ips.dedup();

        // Merge DoH results
        let mut doh_ips: Vec<Ipv4Addr> = doh_results.into_iter().flatten().collect();
        doh_ips.sort();
        doh_ips.dedup();

        let latency_us = start.elapsed().as_micros() as u64;

        // Cross-validate
        let verdict = cross_validate(&all_udp_ips, &doh_ips, any_udp_timeout, any_udp_nxdomain);

        // Use DoH IPs as authoritative (they're encrypted, harder to poison)
        let resolved_ips = if !doh_ips.is_empty() {
            doh_ips.clone()
        } else {
            all_udp_ips.clone()
        };

        // Check for fake-IP ranges
        let fake_ip_detected = resolved_ips.iter().any(|ip| is_fake_ip(*ip));

        DnsProbeResult {
            verdict,
            resolved_ips,
            udp_ips: all_udp_ips,
            doh_ips,
            latency_us,
            fake_ip_detected,
        }
    }
}

/// Cross-validation: определение типа DNS-блокировки.
fn cross_validate(
    udp_ips: &[Ipv4Addr],
    doh_ips: &[Ipv4Addr],
    any_udp_timeout: bool,
    any_udp_nxdomain: bool,
) -> DnsFailureCode {
    // Case 1: DoH has results
    if !doh_ips.is_empty() {
        if udp_ips.is_empty() {
            // UDP failed, DoH works
            if any_udp_nxdomain {
                return DnsFailureCode::NxdomainSpoof;
            }
            if any_udp_timeout {
                return DnsFailureCode::Intercepted;
            }
            // UDP returned empty response (not NXDOMAIN, not timeout)
            return DnsFailureCode::EmptySpoof;
        }
        // Both have IPs — check overlap
        let has_overlap = udp_ips.iter().any(|ip| doh_ips.contains(ip));
        if has_overlap {
            DnsFailureCode::Ok
        } else {
            DnsFailureCode::Poisoned
        }
    } else {
        // Case 2: DoH failed
        if udp_ips.is_empty() {
            if any_udp_nxdomain && !any_udp_timeout {
                // All servers returned NXDOMAIN — genuinely unresolvable
                return DnsFailureCode::Unresolvable;
            }
            DnsFailureCode::DohBlocked
        } else {
            // DoH failed but UDP works — can't validate
            DnsFailureCode::DohBlocked
        }
    }
}

/// Проверка, является ли IP адресом из fake-IP диапазона.
///
/// Fake-IP диапазоны (из v2ray/clash):
/// - 198.18.0.0/15 (198.18.0.0 — 198.19.255.255)
/// - 100.64.0.0/10 (100.64.0.0 — 100.127.255.255)
pub fn is_fake_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let u32_ip = u32::from_be_bytes(octets);

    // 198.18.0.0/15 = 198.18.0.0 — 198.19.255.255
    let base_198_18 = u32::from_be_bytes([198, 18, 0, 0]);
    let mask_15 = !((1u32 << (32 - 15)) - 1); // /15 mask
    if (u32_ip & mask_15) == (base_198_18 & mask_15) {
        return true;
    }

    // 100.64.0.0/10 = 100.64.0.0 — 100.127.255.255
    let base_100_64 = u32::from_be_bytes([100, 64, 0, 0]);
    let mask_10 = !((1u32 << (32 - 10)) - 1); // /10 mask
    if (u32_ip & mask_10) == (base_100_64 & mask_10) {
        return true;
    }

    false
}

/// Build DNS A-record query for domain.
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::with_capacity(512);

    // Transaction ID
    query.extend_from_slice(&[0xAB, 0xCD]);

    // Flags: standard query, recursion desired
    query.extend_from_slice(&[0x01, 0x00]);

    // Questions: 1
    query.extend_from_slice(&[0x00, 0x01]);
    // Answer RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);
    // Authority RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);
    // Additional RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);

    // QNAME
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // root label

    // QTYPE: A (1)
    query.extend_from_slice(&[0x00, 0x01]);
    // QCLASS: IN (1)
    query.extend_from_slice(&[0x00, 0x01]);

    query
}

/// Parse DNS response с детекцией NXDOMAIN (rcode).
fn parse_dns_response_detailed(response: &[u8]) -> UdpDnsResult {
    if response.len() < 12 {
        return UdpDnsResult::Error;
    }

    // Parse flags
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & 0x000F; // lower 4 bits

    // NXDOMAIN = rcode 3
    if rcode == 3 {
        return UdpDnsResult::Nxdomain;
    }

    // SERVFAIL = rcode 2, REFUSED = rcode 5
    if rcode == 2 || rcode == 5 {
        return UdpDnsResult::Error;
    }

    let ips = parse_dns_response_ips(response);
    if ips.is_empty() {
        UdpDnsResult::EmptyResponse
    } else {
        UdpDnsResult::Ok(ips)
    }
}

/// Parse DNS response, extract A-record IPs.
fn parse_dns_response_ips(response: &[u8]) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();

    if response.len() < 12 {
        return ips;
    }

    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        while pos < response.len() {
            let label_len = response[pos] as usize;
            if label_len == 0 {
                pos += 1;
                break;
            }
            pos += 1 + label_len;
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer section
    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }

        // Skip NAME (could be pointer)
        if (response[pos] & 0xC0) == 0xC0 {
            pos += 2;
        } else {
            while pos < response.len() && response[pos] != 0 {
                pos += 1 + response[pos] as usize;
            }
            pos += 1;
        }

        if pos + 10 > response.len() {
            break;
        }

        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;

        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= response.len() {
            let ip = Ipv4Addr::new(
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            );
            ips.push(ip);
        }

        pos += rdlength;
    }

    ips
}

/// Base64url encoding (RFC 4648 §5, no padding).
fn base64url_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::with_capacity((data.len() * 4).div_ceil(3));

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("example.com");
        assert!(query.len() > 20);
        assert_eq!(query[0], 0xAB);
        assert_eq!(query[1], 0xCD);
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
    }

    #[test]
    fn test_cross_validate_ok() {
        let udp = vec![Ipv4Addr::new(8, 8, 8, 8)];
        let doh = vec![Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            cross_validate(&udp, &doh, false, false),
            DnsFailureCode::Ok
        );
    }

    #[test]
    fn test_cross_validate_poisoned() {
        let udp = vec![Ipv4Addr::new(1, 2, 3, 4)];
        let doh = vec![Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            cross_validate(&udp, &doh, false, false),
            DnsFailureCode::Poisoned
        );
    }

    #[test]
    fn test_cross_validate_empty_spoof() {
        let udp: Vec<Ipv4Addr> = vec![];
        let doh = vec![Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            cross_validate(&udp, &doh, false, false),
            DnsFailureCode::EmptySpoof
        );
    }

    #[test]
    fn test_cross_validate_nxdomain_spoof() {
        let udp: Vec<Ipv4Addr> = vec![];
        let doh = vec![Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            cross_validate(&udp, &doh, false, true),
            DnsFailureCode::NxdomainSpoof
        );
    }

    #[test]
    fn test_cross_validate_intercepted() {
        let udp: Vec<Ipv4Addr> = vec![];
        let doh = vec![Ipv4Addr::new(8, 8, 8, 8)];
        assert_eq!(
            cross_validate(&udp, &doh, true, false),
            DnsFailureCode::Intercepted
        );
    }

    #[test]
    fn test_cross_validate_unresolvable() {
        let udp: Vec<Ipv4Addr> = vec![];
        let doh: Vec<Ipv4Addr> = vec![];
        assert_eq!(
            cross_validate(&udp, &doh, false, true),
            DnsFailureCode::Unresolvable
        );
    }

    #[test]
    fn test_cross_validate_doh_blocked() {
        let udp: Vec<Ipv4Addr> = vec![];
        let doh: Vec<Ipv4Addr> = vec![];
        assert_eq!(
            cross_validate(&udp, &doh, false, false),
            DnsFailureCode::DohBlocked
        );
    }

    #[test]
    fn test_is_fake_ip_198_18() {
        assert!(is_fake_ip(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_fake_ip(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!is_fake_ip(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_fake_ip(Ipv4Addr::new(198, 20, 0, 0)));
    }

    #[test]
    fn test_is_fake_ip_100_64() {
        assert!(is_fake_ip(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_fake_ip(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_fake_ip(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_fake_ip(Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn test_is_fake_ip_normal() {
        assert!(!is_fake_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_fake_ip(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_base64url_encode() {
        assert_eq!(base64url_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ");
        assert_eq!(base64url_encode(b"\x00\x01"), "AAE");
    }

    #[test]
    fn test_parse_dns_response_empty() {
        let response = [0u8; 12];
        let ips = parse_dns_response_ips(&response);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_nxdomain() {
        // flags with rcode=3 (NXDOMAIN)
        let mut response = [0u8; 12];
        response[2] = 0x81; // QR=1, OPCODE=0
        response[3] = 0x83; // RCODE=3 (NXDOMAIN)
        let result = parse_dns_response_detailed(&response);
        assert!(matches!(result, UdpDnsResult::Nxdomain));
    }
}
