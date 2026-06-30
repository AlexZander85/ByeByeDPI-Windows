//! HTTP Probe — проверка HTTP application layer.
//!
//! Методика (из Ladon + dpi-detector):
//! 1. GET / → read up to 32KB
//! 2. Verdict: ok / cutoff / http_451 / redirect / timeout
//! 3. Redirect check: same domain = ok, foreign = ISP page
//! 4. RKN stub detection
//!
//! Источники:
//! - [Ladon](https://github.com/nickspaargaren/ladon): HTTP cutoff detection (32KB)
//! - [dpi-detector](https://github.com/Runnin4ik/dpi-detector): HTTP 451 + redirect + stub

use crate::probe::classifier::HttpFailureCode;
use crate::probe::config::ProbeConfig;
use crate::probe::rkn_stub::is_rkn_stub;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tracing::debug;

/// Результат HTTP probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub verdict: HttpFailureCode,
    pub bytes_read: u64,
    pub redirect_url: Option<String>,
    pub latency_us: u64,
}

/// HTTP Probe — GET request + response analysis.
pub struct HttpProbe {
    config: ProbeConfig,
    client: reqwest::Client,
}

impl HttpProbe {
    pub fn new(config: &ProbeConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.http_read_timeout)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config: config.clone(),
            client,
        }
    }

    /// HTTP probe: GET / + response analysis.
    pub async fn probe(&self, _ip: Ipv4Addr, domain: &str) -> HttpProbeResult {
        let start = std::time::Instant::now();
        let url = format!("https://{}/", domain);

        match tokio::time::timeout(
            self.config.http_read_timeout,
            self.client.get(&url).header("Host", domain).send(),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let latency = start.elapsed().as_micros() as u64;
                let status = resp.status().as_u16();

                // HTTP 451: legal block
                if status == 451 {
                    debug!("HTTP 451 for {}", domain);
                    return HttpProbeResult {
                        verdict: HttpFailureCode::Http451,
                        bytes_read: 0,
                        redirect_url: None,
                        latency_us: latency,
                    };
                }

                // Check redirect
                if (300..400).contains(&status) {
                    let redirect_url = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    if let Some(ref redir) = redirect_url {
                        let is_same = redir.contains(domain)
                            || domain.ends_with(
                                &redir
                                    .split("://")
                                    .nth(1)
                                    .unwrap_or("")
                                    .split('/')
                                    .next()
                                    .unwrap_or(""),
                            );

                        return HttpProbeResult {
                            verdict: if is_same {
                                HttpFailureCode::RedirectSame
                            } else {
                                HttpFailureCode::RedirectForeign
                            },
                            bytes_read: 0,
                            redirect_url: Some(redir.clone()),
                            latency_us: latency,
                        };
                    }
                }

                // Read response body
                match resp.bytes().await {
                    Ok(body) => {
                        let bytes_read = body.len() as u64;

                        // Check for RKN stub (configurable substrings)
                        if is_rkn_stub(&body, &self.config) {
                            debug!("RKN stub detected for {}", domain);
                            return HttpProbeResult {
                                verdict: HttpFailureCode::StubPage,
                                bytes_read,
                                redirect_url: None,
                                latency_us: latency,
                            };
                        }

                        // Check for cutoff (response too small)
                        if bytes_read < 1000 && status == 200 {
                            debug!("HTTP cutoff for {}: only {} bytes", domain, bytes_read);
                            return HttpProbeResult {
                                verdict: HttpFailureCode::Cutoff,
                                bytes_read,
                                redirect_url: None,
                                latency_us: latency,
                            };
                        }

                        HttpProbeResult {
                            verdict: HttpFailureCode::Ok,
                            bytes_read,
                            redirect_url: None,
                            latency_us: latency,
                        }
                    }
                    Err(e) => {
                        debug!("HTTP read error for {}: {}", domain, e);
                        HttpProbeResult {
                            verdict: HttpFailureCode::Cutoff,
                            bytes_read: 0,
                            redirect_url: None,
                            latency_us: start.elapsed().as_micros() as u64,
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("HTTP request error for {}: {}", domain, e);
                HttpProbeResult {
                    verdict: HttpFailureCode::Timeout,
                    bytes_read: 0,
                    redirect_url: None,
                    latency_us: start.elapsed().as_micros() as u64,
                }
            }
            Err(_) => {
                debug!("HTTP timeout for {}", domain);
                HttpProbeResult {
                    verdict: HttpFailureCode::Timeout,
                    bytes_read: 0,
                    redirect_url: None,
                    latency_us: self.config.http_read_timeout.as_micros() as u64,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_probe_result_serialization() {
        let result = HttpProbeResult {
            verdict: HttpFailureCode::Cutoff,
            bytes_read: 500,
            redirect_url: Some("https://other.com".into()),
            latency_us: 12000,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: HttpProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, HttpFailureCode::Cutoff);
        assert_eq!(back.bytes_read, 500);
    }
}
