//! TCP Probe — проверка TCP-connectivity с parallel dial racing.
//!
//! Методика:
//! 1. Parallel race: N IP параллельно через tokio, первый успешный побеждает
//! 2. Замер RTT для dynamic timeout в TLS/HTTP phases
//! 3. Классификация ошибок: Reset / Timeout / Refused / Unreachable

use crate::probe::classifier::TcpFailureCode;
use crate::probe::config::ProbeConfig;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::debug;

/// Результат TCP probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbeResult {
    pub verdict: TcpFailureCode,
    pub rtt_us: u64,
    pub ip: Option<Ipv4Addr>,
}

/// TCP Probe — parallel dial racing.
pub struct TcpProbe {
    config: ProbeConfig,
}

impl TcpProbe {
    pub fn new(config: &ProbeConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Parallel race: подключиться к первому успешному IP.
    pub async fn probe(&self, ips: &[Ipv4Addr], port: u16) -> TcpProbeResult {
        if ips.is_empty() {
            return TcpProbeResult {
                verdict: TcpFailureCode::Timeout,
                rtt_us: 0,
                ip: None,
            };
        }

        let race_count = self.config.tcp_race_count.min(ips.len());
        let futs: Vec<_> = ips[..race_count]
            .iter()
            .map(|ip| self.probe_single(*ip, port))
            .collect();

        // First successful wins
        let results = futures::future::join_all(futs).await;

        // Find first ConnectOk
        for result in &results {
            if result.verdict == TcpFailureCode::ConnectOk {
                return result.clone();
            }
        }

        // All failed — return worst verdict (first non-ConnectOk)
        results.into_iter().next().unwrap_or(TcpProbeResult {
            verdict: TcpFailureCode::Timeout,
            rtt_us: 0,
            ip: None,
        })
    }

    /// Probe одного IP: TCP connect с таймаутом.
    async fn probe_single(&self, ip: Ipv4Addr, port: u16) -> TcpProbeResult {
        let addr = SocketAddr::new(ip.into(), port);
        let start = std::time::Instant::now();

        match tokio::time::timeout(
            self.config.tcp_connect_timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                let rtt = start.elapsed().as_micros() as u64;
                debug!("TCP connect OK to {}:{} ({}µs)", ip, port, rtt);
                TcpProbeResult {
                    verdict: TcpFailureCode::ConnectOk,
                    rtt_us: rtt,
                    ip: Some(ip),
                }
            }
            Ok(Err(e)) => {
                let err_str = e.to_string().to_lowercase();
                let verdict = if err_str.contains("connection reset")
                    || err_str.contains("connection refused")
                {
                    if err_str.contains("refused") {
                        TcpFailureCode::Refused
                    } else {
                        TcpFailureCode::Reset
                    }
                } else if err_str.contains("unreachable") || err_str.contains("no route") {
                    TcpFailureCode::Unreachable
                } else {
                    TcpFailureCode::Timeout
                };

                debug!("TCP connect failed to {}:{}: {:?}", ip, port, verdict);
                TcpProbeResult {
                    verdict,
                    rtt_us: start.elapsed().as_micros() as u64,
                    ip: Some(ip),
                }
            }
            Err(_timeout) => {
                debug!("TCP connect timeout to {}:{}", ip, port);
                TcpProbeResult {
                    verdict: TcpFailureCode::Timeout,
                    rtt_us: self.config.tcp_connect_timeout.as_micros() as u64,
                    ip: Some(ip),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_empty_ips() {
        let config = ProbeConfig::default();
        let probe = TcpProbe::new(&config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(probe.probe(&[], 443));
        assert_eq!(result.verdict, TcpFailureCode::Timeout);
    }

    #[test]
    fn test_probe_config_timeout() {
        let mut config = ProbeConfig::default();
        config.tcp_connect_timeout = Duration::from_millis(100);
        let probe = TcpProbe::new(&config);

        // Non-routable IP — should timeout
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(probe.probe(&[Ipv4Addr::new(192, 0, 2, 1)], 443));
        // Should get timeout or unreachable
        assert!(
            result.verdict == TcpFailureCode::Timeout
                || result.verdict == TcpFailureCode::Unreachable
                || result.verdict == TcpFailureCode::Refused
        );
    }
}
