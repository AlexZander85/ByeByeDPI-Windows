//! TCP 16-20KB Data-Volume Probe — обнаружение DPI, обрывающего соединение после N КБ.
//!
//! Методика (из dpi-detector + dpi-checkers):
//! 1. Открыть keep-alive соединение (TcpStream::connect)
//! 2. Отправить N HEAD запросов с X-Pad заголовком (4KB random каждый)
//! 3. Замерить RTT первыми 2 запросами
//! 4. Dynamic timeout: max(rtt × factor, min_timeout), capped at 12s
//! 5. Если соединение падает на запросе N → blocking detected at N × pad_size
//!
//! Источники:
//! - [dpi-detector](https://github.com/Runnin4ik/dpi-detector): TCP16-20KB detection
//! - [dpi-checkers](https://github.com/hyperion-cs/dpi-checkers): L4-25 / data-volume blocking

use crate::probe::config::ProbeConfig;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tracing::debug;

/// Результат TCP16 probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tcp16ProbeResult {
    /// Обнаружена ли блокировка
    pub detected: bool,
    /// На каком КБ обнаружена (если detected=true)
    pub detected_at_kb: u64,
    /// Общее количество отправленных запросов
    pub requests_sent: u32,
    /// Замеренный RTT (мкс)
    pub rtt_us: u64,
}

/// TCP 16-20KB Data-Volume Probe.
pub struct Tcp16Probe {
    config: ProbeConfig,
}

impl Tcp16Probe {
    pub fn new(config: &ProbeConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Data-volume probe: keep-alive соединение + N HEAD запросов с padding.
    ///
    /// Использует сырой TCP (TcpStream) для keep-alive, как в dpi-detector.
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> Tcp16ProbeResult {
        let addr = SocketAddr::new(ip.into(), 443);
        let config = self.config.clone();
        let domain = domain.to_string();

        let result = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::task::spawn_blocking(move || {
                probe_blocking(addr, &domain, &config)
            }),
        )
        .await;

        match result {
            Ok(Ok(r)) => r,
            _ => Tcp16ProbeResult {
                detected: false,
                detected_at_kb: 0,
                requests_sent: 0,
                rtt_us: 0,
            },
        }
    }
}

/// Blocking TCP16 probe (runs in spawn_blocking).
fn probe_blocking(addr: SocketAddr, domain: &str, config: &ProbeConfig) -> Tcp16ProbeResult {
    // TCP connect (keep-alive)
    let tcp_stream = match std::net::TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => {
            return Tcp16ProbeResult {
                detected: false,
                detected_at_kb: 0,
                requests_sent: 0,
                rtt_us: 0,
            };
        }
    };

    // Set TCP keep-alive
    let _ = tcp_stream.set_nodelay(true);

    // Measure RTT with first 2 requests
    let mut rtt_total: u64 = 0;
    let mut rtt_count: u32 = 0;

    for _ in 0..2 {
        let req = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n", domain);
        let start = std::time::Instant::now();

        let mut stream = match tcp_stream.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };

        if stream.write_all(req.as_bytes()).is_ok() {
            // Read response (simplified - just read some bytes)
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            rtt_total += start.elapsed().as_micros() as u64;
            rtt_count += 1;
        }
    }

    let avg_rtt = if rtt_count > 0 {
        rtt_total / rtt_count as u64
    } else {
        5_000_000 // default 5s
    };

    let timeout_per_req = Duration::from_secs_f64(
        (avg_rtt as f64 / 1_000_000.0 * config.tcp16_timeout_factor)
            .max(config.tcp16_min_timeout.as_secs_f64())
            .min(12.0),
    );

    let pad_size = config.tcp16_pad_size;
    let total_requests = config.tcp16_requests as u32;

    // Generate random padding
    let padding = generate_padding(pad_size);

    for i in 0..total_requests {
        // Build HEAD request with X-Pad header
        let pad_hex = hex_encode(&padding);
        let req = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nX-Pad: {}\r\nConnection: keep-alive\r\n\r\n",
            domain, pad_hex
        );

        let mut stream = match tcp_stream.try_clone() {
            Ok(s) => s,
            Err(_) => {
                let detected_kb = (i as u64 * pad_size as u64) / 1024;
                debug!(
                    "TCP16 detected at {}KB for {} (request {}/{}) - stream clone failed",
                    detected_kb, domain, i + 1, total_requests
                );
                return Tcp16ProbeResult {
                    detected: true,
                    detected_at_kb: detected_kb,
                    requests_sent: i + 1,
                    rtt_us: avg_rtt,
                };
            }
        };

        // Set write timeout
        let _ = stream
            .set_write_timeout(Some(timeout_per_req));

        match stream.write_all(req.as_bytes()) {
            Ok(()) => {
                // Read response
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                debug!(
                    "TCP16 request {}/{} OK for {}",
                    i + 1,
                    total_requests,
                    domain
                );
            }
            Err(_) => {
                let detected_kb = (i as u64 * pad_size as u64) / 1024;
                debug!(
                    "TCP16 detected at {}KB for {} (request {}/{})",
                    detected_kb,
                    domain,
                    i + 1,
                    total_requests
                );
                return Tcp16ProbeResult {
                    detected: true,
                    detected_at_kb: detected_kb,
                    requests_sent: i + 1,
                    rtt_us: avg_rtt,
                };
            }
        }
    }

    Tcp16ProbeResult {
        detected: false,
        detected_at_kb: 0,
        requests_sent: total_requests,
        rtt_us: avg_rtt,
    }
}

/// Generate random padding bytes.
fn generate_padding(size: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now()
        .hash(&mut hasher);
    let seed = hasher.finish();

    (0..size)
        .map(|i| ((seed.wrapping_add(i as u64) >> (i % 8 * 8)) & 0xFF) as u8)
        .collect()
}

/// Hex encode bytes.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp16_result_serialization() {
        let result = Tcp16ProbeResult {
            detected: true,
            detected_at_kb: 16,
            requests_sent: 5,
            rtt_us: 12000,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: Tcp16ProbeResult = serde_json::from_str(&json).unwrap();
        assert!(back.detected);
        assert_eq!(back.detected_at_kb, 16);
    }

    #[test]
    fn test_generate_padding() {
        let padding = generate_padding(4096);
        assert_eq!(padding.len(), 4096);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00ffab");
    }

    #[test]
    fn test_tcp16_uses_config() {
        let config = ProbeConfig {
            tcp16_requests: 8,
            tcp16_pad_size: 2048,
            tcp16_timeout_factor: 2.0,
            tcp16_min_timeout: Duration::from_secs(1),
            ..ProbeConfig::default()
        };
        let probe = Tcp16Probe::new(&config);
        assert_eq!(probe.config.tcp16_requests, 8);
        assert_eq!(probe.config.tcp16_pad_size, 2048);
    }
}
