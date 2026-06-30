//! DPI Probe Module — превентивное определение типа DPI-блокировки.
//!
//! ## Архитектура
//! Pipeline из 5 phases:
//! 1. DNS Integrity (UDP vs DoH cross-validation)
//! 2. TCP Connectivity (parallel dial racing)
//! 3. TLS Handshake (staged: 1.3 → 1.2)
//! 4. HTTP Application Layer (GET, cutoff detection)
//! 5. Data-Volume (TCP 16-20KB)
//!
//! ## Источники
//! - Pipeline от [Ladon](https://github.com/nickspaargaren/ladon)
//! - Классификатор от [dpi-detector](https://github.com/Runnin4ik/dpi-detector)
//! - Data-volume от [dpi-checkers](https://github.com/hyperion-cs/dpi-checkers)
//! - Preset-списки из [ByeByeDPI](https://github.com/nickspaargaren/ByeByeDPI)

pub mod accumulator;
pub mod classifier;
pub mod config;
pub mod discriminator;
pub mod dns_probe;
pub mod http_probe;
pub mod presets;
pub mod rkn_stub;
pub mod strategy_map;
pub mod tcp16_probe;
pub mod tcp_probe;
pub mod tls_probe;

use accumulator::Accumulator;
use classifier::*;
use config::ProbeConfig;
use discriminator::{discriminate, DiscriminationResult};
use dns_probe::DnsProbeResult;
use http_probe::HttpProbeResult;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tcp16_probe::Tcp16ProbeResult;
use tcp_probe::TcpProbeResult;
use tls_probe::TlsProbeResult;
use tracing::info;

/// Результат probe'а одного домена.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Домен
    pub domain: String,
    /// IP-адрес сервера (первый из DNS)
    pub ip: Option<Ipv4Addr>,
    /// Вердикт
    pub verdict: ProbeVerdict,
    /// Confidence (0.0–1.0)
    pub confidence: f64,
    /// Результат Phase 1: DNS
    pub dns: DnsProbeResult,
    /// Результат Phase 2: TCP
    pub tcp: TcpProbeResult,
    /// Результат Phase 3: TLS
    pub tls: Option<TlsProbeResult>,
    /// Результат Phase 4: HTTP
    pub http: Option<HttpProbeResult>,
    /// Результат Phase 5: Data-Volume (TCP 16-20KB)
    pub tcp16: Option<Tcp16ProbeResult>,
    /// Дискриминация: server-active vs path-active
    pub discrimination: Option<DiscriminationResult>,
    /// Accumulation verdict (should_tunnel)
    pub should_tunnel: bool,
    /// Timestamp
    pub timestamp: String,
}

/// DPI Probe Module — оркестратор pipeline.
pub struct ProbeModule {
    config: ProbeConfig,
    dns: dns_probe::DnsProbe,
    tcp: tcp_probe::TcpProbe,
    tls: tls_probe::TlsProbe,
    http: http_probe::HttpProbe,
    tcp16: tcp16_probe::Tcp16Probe,
    accumulator: Accumulator,
}

impl ProbeModule {
    /// Создаёт новый ProbeModule с конфигурацией по умолчанию.
    pub fn new() -> Self {
        Self::with_config(ProbeConfig::default())
    }

    /// Создаёт ProbeModule с указанной конфигурацией.
    pub fn with_config(config: ProbeConfig) -> Self {
        let dns = dns_probe::DnsProbe::new(&config);
        let tcp = tcp_probe::TcpProbe::new(&config);
        let tls = tls_probe::TlsProbe::new(&config);
        let http = http_probe::HttpProbe::new(&config);
        let tcp16 = tcp16_probe::Tcp16Probe::new(&config);
        let accumulator = Accumulator::new(
            config.promote_threshold,
            config.family_threshold,
            config.hot_ttl,
        );

        Self {
            config,
            dns,
            tcp,
            tls,
            http,
            tcp16,
            accumulator,
        }
    }

    /// Запуск pipeline probe для одного домена.
    ///
    /// Выполняет Phase 1 (DNS) + Phase 2 (TCP) + Phase 3 (TLS) + Phase 4 (HTTP)
    /// + Phase 5 (Data-Volume) + Discrimination + Accumulation.
    pub async fn probe(&self, domain: &str) -> ProbeResult {
        info!("Probing domain: {}", domain);

        // Phase 1: DNS Integrity
        let dns = self.dns.probe(domain).await;

        // Resolve IPs из DNS probe result
        let ips = if dns.verdict == DnsFailureCode::Ok {
            dns.resolved_ips.clone()
        } else {
            vec![]
        };

        let ip = ips.first().copied();

        // Phase 2: TCP Connectivity (parallel race)
        let tcp = if !ips.is_empty() {
            self.tcp.probe(&ips, 443).await
        } else {
            TcpProbeResult {
                verdict: TcpFailureCode::Timeout,
                rtt_us: 0,
                ip: None,
            }
        };

        // Phase 3: TLS Handshake (staged: 1.3 → 1.2)
        let tls = if tcp.verdict == TcpFailureCode::ConnectOk {
            if let Some(ip) = ip {
                Some(self.tls.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };

        // Phase 4: HTTP Application Layer (only if TLS succeeded)
        let http = if tls.as_ref().is_some_and(|t| !t.verdict.is_tls_fail()) {
            if let Some(ip) = ip {
                Some(self.http.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };

        // Phase 5: Data-Volume (only if HTTP detected cutoff)
        let tcp16 = if http
            .as_ref()
            .is_some_and(|h| h.verdict == HttpFailureCode::Cutoff)
        {
            if let Some(ip) = ip {
                Some(self.tcp16.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };

        // If TCP16 detected data-volume cutoff, update TCP verdict
        let tcp = if tcp16.as_ref().is_some_and(|t| t.detected) {
            TcpProbeResult {
                verdict: TcpFailureCode::DataVolumeCut,
                rtt_us: tcp.rtt_us,
                ip: tcp.ip,
            }
        } else {
            tcp
        };

        // Discriminate: server-active vs path-active (TLS + HTTP)
        let discrimination = match (&tls, &http) {
            (Some(t), Some(h)) => Some(discriminate(&t.verdict, &h.verdict)),
            (Some(t), None) => Some(discriminate(&t.verdict, &HttpFailureCode::Ok)),
            _ => None,
        };

        // Compute verdict и confidence
        let (mut verdict, mut confidence) = compute_verdict(&dns, &tcp);

        // Override with discrimination result if available
        if let Some(ref disc) = discrimination {
            verdict = disc.verdict;
            confidence = disc.confidence;
        } else if let Some(ref tls) = tls {
            if tls.verdict == TlsFailureCode::Version12Only {
                verdict = ProbeVerdict::Blocked;
                confidence = 0.90;
            } else if tls.verdict.is_tls_fail() {
                verdict = ProbeVerdict::Blocked;
                confidence = 0.85;
            }
        }

        // Accumulate verdict
        self.accumulator.record(domain, &verdict);
        let should_tunnel = self.accumulator.should_tunnel(domain);

        info!(
            "Probe result for {}: verdict={:?}, confidence={:.0}%, should_tunnel={}",
            domain,
            verdict,
            confidence * 100.0,
            should_tunnel
        );

        ProbeResult {
            domain: domain.to_string(),
            ip,
            verdict,
            confidence,
            dns,
            tcp,
            tls,
            http,
            tcp16,
            discrimination,
            should_tunnel,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Probe нескольких доменов.
    pub async fn probe_batch(&self, domains: &[&str]) -> Vec<ProbeResult> {
        let mut results = Vec::with_capacity(domains.len());
        for domain in domains {
            results.push(self.probe(domain).await);
        }
        results
    }

    /// Возвращает конфигурацию.
    pub fn config(&self) -> &ProbeConfig {
        &self.config
    }

    /// Возвращает accumulator.
    pub fn accumulator(&self) -> &Accumulator {
        &self.accumulator
    }
}

impl Default for ProbeModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Вычисление итогового вердикта и confidence по фазам DNS + TCP.
fn compute_verdict(dns: &DnsProbeResult, tcp: &TcpProbeResult) -> (ProbeVerdict, f64) {
    match (&dns.verdict, &tcp.verdict) {
        // DNS poisoned — 95% blocked
        (DnsFailureCode::Poisoned, _) => (ProbeVerdict::Blocked, 0.95),
        (DnsFailureCode::NxdomainSpoof, _) => (ProbeVerdict::Blocked, 0.90),
        (DnsFailureCode::EmptySpoof, _) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Intercepted, _) => (ProbeVerdict::Blocked, 0.90),
        (DnsFailureCode::DohBlocked, _) => (ProbeVerdict::Blocked, 0.80),

        // DNS OK + TCP OK — needs further TLS/HTTP phases
        (DnsFailureCode::Ok, TcpFailureCode::ConnectOk) => {
            (ProbeVerdict::Ambiguous, 0.30) // not final
        }

        // DNS OK + TCP blocked
        (DnsFailureCode::Ok, TcpFailureCode::Reset) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Ok, TcpFailureCode::Timeout) => (ProbeVerdict::Blocked, 0.75),

        // DNS ambiguous + TCP issues
        (_, TcpFailureCode::Reset) => (ProbeVerdict::Blocked, 0.80),
        (_, TcpFailureCode::Timeout) => (ProbeVerdict::Blocked, 0.60),

        // DNS fail + TCP refuse/unreachable
        (_, TcpFailureCode::Refused) => (ProbeVerdict::Ambiguous, 0.40),
        (_, TcpFailureCode::Unreachable) => (ProbeVerdict::Ambiguous, 0.30),

        // Data-volume cutoff — DPI обрывает на N КБ
        (_, TcpFailureCode::DataVolumeCut) => (ProbeVerdict::Blocked, 0.85),

        // DNS unresolvable
        (DnsFailureCode::Unresolvable, _) => (ProbeVerdict::Ambiguous, 0.50),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_verdict_dns_poisoned() {
        let dns = DnsProbeResult {
            verdict: DnsFailureCode::Poisoned,
            resolved_ips: vec![],
            udp_ips: vec![],
            doh_ips: vec![],
            latency_us: 0,
            fake_ip_detected: false,
        };
        let tcp = TcpProbeResult {
            verdict: TcpFailureCode::ConnectOk,
            rtt_us: 10000,
            ip: None,
        };
        let (v, c) = compute_verdict(&dns, &tcp);
        assert_eq!(v, ProbeVerdict::Blocked);
        assert!(c > 0.9);
    }

    #[test]
    fn test_compute_verdict_tcp_ok_dns_ok() {
        let dns = DnsProbeResult {
            verdict: DnsFailureCode::Ok,
            resolved_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            udp_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            doh_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            latency_us: 50000,
            fake_ip_detected: false,
        };
        let tcp = TcpProbeResult {
            verdict: TcpFailureCode::ConnectOk,
            rtt_us: 12000,
            ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
        };
        let (v, _c) = compute_verdict(&dns, &tcp);
        assert_eq!(v, ProbeVerdict::Ambiguous); // needs TLS/HTTP
    }

    #[test]
    fn test_compute_verdict_tcp_reset() {
        let dns = DnsProbeResult {
            verdict: DnsFailureCode::Ok,
            resolved_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            udp_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            doh_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            latency_us: 50000,
            fake_ip_detected: false,
        };
        let tcp = TcpProbeResult {
            verdict: TcpFailureCode::Reset,
            rtt_us: 5000,
            ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
        };
        let (v, c) = compute_verdict(&dns, &tcp);
        assert_eq!(v, ProbeVerdict::Blocked);
        assert!(c >= 0.8);
    }
}
