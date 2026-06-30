//! TLS Probe — staged TLS handshake (1.3 → 1.2) + stage tracking.
//!
//! Методика (из Ladon + dpi-detector):
//! 1. Attempt 1: TLS 1.3 (через native-tls с强制ой версией)
//! 2. Attempt 2: TLS 1.2 (fallback если 1.3 fail)
//! 3. TLS version split detection: 1.3 fail + 1.2 ok = Version12Only (DPI атакует ClientHello!)
//! 4. Stage-aware classification: RST/timeout/garbage/alert/MITM
//!
//! Источники:
//! - [Ladon](https://github.com/nickspaargaren/ladon): TLS version split detection
//! - [dpi-detector](https://github.com/Runnin4ik/dpi-detector): stage tracking + MITM detection

use crate::probe::classifier::{ConnectionStage, TlsFailureCode};
use crate::probe::config::ProbeConfig;
use native_tls::Protocol;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{debug, info};

/// Результат TLS probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProbeResult {
    pub verdict: TlsFailureCode,
    pub tls13_ok: bool,
    pub tls12_ok: bool,
    pub stage: ConnectionStage,
    pub latency_us: u64,
}

/// TLS Probe — staged handshake (1.3 → 1.2) + stage tracking.
pub struct TlsProbe {
    config: ProbeConfig,
    http_client: reqwest::Client,
}

impl TlsProbe {
    pub fn new(config: &ProbeConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.tls_connect_timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to create HTTP client for TLS probe");

        Self {
            config: config.clone(),
            http_client,
        }
    }

    /// TLS probe: two-stage (1.3 → 1.2) with Version12Only detection.
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> TlsProbeResult {
        let start = std::time::Instant::now();
        let addr = SocketAddr::new(ip.into(), 443);

        // Stage 1: TCP connect to detect RST/timeout at TCP level
        let tcp_stream = match tokio::time::timeout(
            self.config.tcp_connect_timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let err_str = e.to_string().to_lowercase();
                let verdict = if err_str.contains("reset") {
                    TlsFailureCode::Reset
                } else if err_str.contains("refused") {
                    TlsFailureCode::Reset
                } else {
                    TlsFailureCode::SilentDrop
                };
                return TlsProbeResult {
                    verdict,
                    tls13_ok: false,
                    tls12_ok: false,
                    stage: ConnectionStage::TcpConnected,
                    latency_us: start.elapsed().as_micros() as u64,
                };
            }
            Err(_) => {
                return TlsProbeResult {
                    verdict: TlsFailureCode::SilentDrop,
                    tls13_ok: false,
                    tls12_ok: false,
                    stage: ConnectionStage::TcpConnect,
                    latency_us: start.elapsed().as_micros() as u64,
                };
            }
        };
        drop(tcp_stream);

        // Attempt 1: TLS 1.3
        let tls13_result = self.probe_version(ip, domain, Protocol::Tlsv13).await;
        let tls13_ok = tls13_result == TlsFailureCode::HandshakeOk
            || tls13_result == TlsFailureCode::Version13Ok;

        debug!(
            "TLS 1.3 probe for {}: {:?} (ok={})",
            domain, tls13_result, tls13_ok
        );

        // If TLS 1.3 succeeded, also try to confirm it's really 1.3
        if tls13_ok {
            // Try reqwest with default settings to confirm TLS works
            let reqwest_ok = self.probe_reqwest(domain).await;
            if reqwest_ok {
                return TlsProbeResult {
                    verdict: TlsFailureCode::Version13Ok,
                    tls13_ok: true,
                    tls12_ok: true,
                    stage: ConnectionStage::TlsConnected,
                    latency_us: start.elapsed().as_micros() as u64,
                };
            }
        }

        // Attempt 2: TLS 1.2 (fallback)
        let tls12_result = self.probe_version(ip, domain, Protocol::Tlsv12).await;
        let tls12_ok = tls12_result == TlsFailureCode::HandshakeOk;

        debug!(
            "TLS 1.2 probe for {}: {:?} (ok={})",
            domain, tls12_result, tls12_ok
        );

        // TLS version split detection: 1.3 fail + 1.2 ok = DPI attacks ClientHello
        if !tls13_ok && tls12_ok {
            info!(
                "Version12Only detected for {}: TLS 1.3 blocked, 1.2 works — DPI attacking ClientHello",
                domain
            );
            return TlsProbeResult {
                verdict: TlsFailureCode::Version12Only,
                tls13_ok: false,
                tls12_ok: true,
                stage: ConnectionStage::TlsConnected,
                latency_us: start.elapsed().as_micros() as u64,
            };
        }

        // If TLS 1.2 also failed, return the more informative error
        if !tls12_ok && !tls13_ok {
            // Use TLS 1.3 error as primary (it's the first attempt)
            let verdict = if tls13_result.is_tls_fail() {
                tls13_result
            } else {
                tls12_result
            };
            return TlsProbeResult {
                verdict,
                tls13_ok: false,
                tls12_ok: false,
                stage: ConnectionStage::TlsHandshake,
                latency_us: start.elapsed().as_micros() as u64,
            };
        }

        // TLS 1.2 ok but 1.3 failed (shouldn't reach here due to Version12Only check above)
        TlsProbeResult {
            verdict: TlsFailureCode::HandshakeOk,
            tls13_ok,
            tls12_ok,
            stage: ConnectionStage::TlsConnected,
            latency_us: start.elapsed().as_micros() as u64,
        }
    }

    /// Probe a specific TLS version using native-tls.
    async fn probe_version(
        &self,
        ip: Ipv4Addr,
        domain: &str,
        protocol: Protocol,
    ) -> TlsFailureCode {
        let addr = SocketAddr::new(ip.into(), 443);
        let domain = domain.to_string();
        let timeout = self.config.tls_connect_timeout;

        let result = tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || {
            // Build TLS connector with specific version
            let connector = native_tls::TlsConnector::builder()
                .min_protocol_version(Some(protocol))
                .max_protocol_version(Some(protocol))
                .danger_accept_invalid_certs(true)
                .build();

            let connector = match connector {
                Ok(c) => c,
                Err(_) => return TlsFailureCode::Garbage,
            };

            // TCP connect
            let tcp_stream = match std::net::TcpStream::connect(addr) {
                Ok(s) => s,
                Err(e) => {
                    let err = e.to_string().to_lowercase();
                    if err.contains("reset") {
                        return TlsFailureCode::Reset;
                    }
                    if err.contains("refused") {
                        return TlsFailureCode::Reset;
                    }
                    return TlsFailureCode::SilentDrop;
                }
            };

            // TLS handshake
            match connector.connect(&domain, tcp_stream) {
                Ok(_stream) => TlsFailureCode::HandshakeOk,
                Err(e) => classify_handshake_error(&e),
            }
        }))
        .await;

        match result {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_)) => TlsFailureCode::Garbage,
            Err(_) => TlsFailureCode::SilentDrop,
        }
    }

    /// Fallback probe using reqwest (confirms TLS works).
    async fn probe_reqwest(&self, domain: &str) -> bool {
        let url = format!("https://{}/", domain);
        match tokio::time::timeout(
            self.config.tls_connect_timeout,
            self.http_client.get(&url).send(),
        )
        .await
        {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }
}

/// Классификация ошибок TLS handshake.
fn classify_handshake_error(e: &native_tls::HandshakeError<std::net::TcpStream>) -> TlsFailureCode {
    match e {
        native_tls::HandshakeError::Failure(tls_err) => {
            let err_str = tls_err.to_string().to_lowercase();

            if err_str.contains("certificate") || err_str.contains("cert") {
                if err_str.contains("expired") {
                    return TlsFailureCode::MitmExpired;
                }
                if err_str.contains("self-signed") || err_str.contains("unknown issuer") {
                    return TlsFailureCode::MitmSelfSigned;
                }
                if err_str.contains("hostname") || err_str.contains("mismatch") {
                    return TlsFailureCode::MitmHostnameMismatch;
                }
                return TlsFailureCode::Mitm;
            }

            if err_str.contains("alert") {
                if err_str.contains("unrecognized") || err_str.contains("sni") {
                    return TlsFailureCode::AlertSniblock;
                }
                if err_str.contains("handshake") {
                    return TlsFailureCode::AlertHandshake;
                }
                if err_str.contains("protocol") {
                    return TlsFailureCode::AlertProtocol;
                }
                return TlsFailureCode::Alert;
            }

            if err_str.contains("decode") || err_str.contains("oversized") || err_str.contains("illegal") {
                return TlsFailureCode::Garbage;
            }

            TlsFailureCode::Garbage
        }
        native_tls::HandshakeError::WouldBlock(_mid) => {
            // WouldBlock means TLS handshake is incomplete (timeout or non-blocking)
            TlsFailureCode::SilentDrop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_probe_result_serialization() {
        let result = TlsProbeResult {
            verdict: TlsFailureCode::Version12Only,
            tls13_ok: false,
            tls12_ok: true,
            stage: ConnectionStage::TlsConnected,
            latency_us: 50000,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TlsProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, TlsFailureCode::Version12Only);
        assert!(back.tls12_ok);
    }

    #[test]
    fn test_tls_handshake_error_types() {
        // Verify error classification logic exists
        let verdict = TlsFailureCode::SilentDrop;
        assert!(verdict.is_tls_fail());
        let ok = TlsFailureCode::HandshakeOk;
        assert!(!ok.is_tls_fail());
    }
}
