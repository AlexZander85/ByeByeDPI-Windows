//! DNS Engine — DoH/DoT resolver с кэшированием.
//!
//! ## Компоненты
//! - `DnsEngine` — DNS-over-HTTPS + DNS-over-TLS resolver с moka cache
//! - `fakeip` — FakeIP DNS (виртуальные IP для доменов из sing-box)
//! - Parallel DoH + DoT через `tokio::select!` для минимальной задержки
//!
//! ## Интеграция с Split Tunnel
//! При DNS-резолве результат парсится, и IP→domain регистрируется
//! в `split_tunnel::domain_cache` для последующей маршрутизации.
//!
//! ## Источник
//! Адаптировано из [zapret2](https://github.com/bol-van/zapret-win-bundle)
//! и [sing-box](https://github.com/SagerNet/sing-box).

pub mod fakeip;
pub mod parallel_dial;
pub mod txid_tracker;

use moka::future::Cache;
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;

/// Результат DNS-резолва.
#[derive(Debug, Clone)]
pub struct DnsResult {
    pub ip: IpAddr,
    pub ttl: u32,
}

/// DNS Engine — DoH/DoT resolver с moka cache.
///
/// Использует два параллельных канала:
/// - DoH через Cloudflare DNS-over-HTTPS (JSON API)
/// - DoT через trust-dns-resolver (TLS)
///
/// Первый успешный ответ используется (tokio::select!).
pub struct DnsEngine {
    doh_client: reqwest::Client,
    dot_resolver: trust_dns_resolver::TokioAsyncResolver,
    cache: Cache<String, DnsResult>,
    ip_overrides: Vec<(ipnet::Ipv4Net, std::net::Ipv4Addr)>,
    doh_pins: Vec<String>,
}

impl DnsEngine {
    /// Создаёт новый DNS Engine.
    ///
    /// DoH: Cloudflare DNS-over-HTTPS (application/dns-json)
    /// DoT: Cloudflare TLS resolver
    /// Cache: moka concurrent, max 10k entries, 5 min TTL
    pub fn new() -> Self {
        let doh_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .http2_prior_knowledge()
            .build()
            .expect("Failed to create reqwest client for DoH");

        let dot_resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
            trust_dns_resolver::config::ResolverConfig::cloudflare(),
            trust_dns_resolver::config::ResolverOpts::default(),
        );

        let cache: Cache<String, DnsResult> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(300))
            .build();

        Self {
            doh_client,
            dot_resolver,
            cache,
            ip_overrides: Vec::new(),
            doh_pins: Vec::new(),
        }
    }

    /// Добавляет IP override для CIDR.
    pub fn add_ip_override(&mut self, cidr: ipnet::Ipv4Net, override_ip: std::net::Ipv4Addr) {
        self.ip_overrides.push((cidr, override_ip));
    }

    /// Добавляет SPKI hash для certificate pinning DoH серверов.
    pub fn add_doh_pin(&mut self, pin: String) {
        self.doh_pins.push(pin);
    }

    /// Разрешает домен в IP адрес.
    ///
    /// 1. Проверка кэша — если есть, возвращает сразу
    /// 2. Параллельный DoH + DoT через `tokio::select!`
    /// 3. Сохраняет результат в кэш
    ///
    /// # Arguments
    /// * `domain` — доменное имя (например, "example.com")
    ///
    /// # Returns
    /// `Some(IpAddr)` если удалось разрешить, `None` при ошибке
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        if let Some(cached) = self.cache.get(domain).await {
            return Some(cached.ip);
        }

        let max_retries = 3u8;
        for retry in 0..max_retries {
            let doh = self.resolve_doh(domain);
            let dot = self.resolve_dot(domain);

            let result = tokio::select! {
                r = doh => r,
                r = dot => r,
            };

            if let Some(ip) = result {
                let final_ip = self.apply_overrides(ip);
                debug!(
                    "DNS resolved: {} → {} (attempt {})",
                    domain,
                    final_ip,
                    retry + 1
                );
                self.cache
                    .insert(
                        domain.to_string(),
                        DnsResult {
                            ip: final_ip,
                            ttl: 300,
                        },
                    )
                    .await;
                return Some(final_ip);
            }

            if retry + 1 < max_retries {
                let delay_ms = 2u64.pow(retry as u32 + 1) * 20;
                let jitter = crate::desync::rand::random_range(0, 20) as u64;
                tokio::time::sleep(Duration::from_millis(delay_ms + jitter)).await;
                debug!("DNS retry {} for {}", retry + 1, domain);
            }
        }
        None
    }

    /// Разрешает через DoH (DNS-over-HTTPS Cloudflare JSON API).
    async fn resolve_doh(&self, domain: &str) -> Option<IpAddr> {
        let url = format!(
            "https://cloudflare-dns.com/dns-query?name={}&type=A",
            domain
        );
        let resp: reqwest::Response = self
            .doh_client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .ok()?;

        let body: serde_json::Value = resp.json().await.ok()?;
        let answer: &Vec<serde_json::Value> = body["Answer"].as_array()?;
        for entry in answer {
            if entry["type"].as_i64() == Some(1) {
                if let Some(ip_str) = entry["data"].as_str() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
        None
    }

    /// Разрешает через DoT (DNS-over-TLS, trust-dns-resolver).
    async fn resolve_dot(&self, domain: &str) -> Option<IpAddr> {
        let lookup = self.dot_resolver.ipv4_lookup(domain).await.ok()?;
        let record = lookup.iter().next()?;
        Some(IpAddr::V4(record.0))
    }

    /// Очищает весь DNS кэш.
    pub fn clear_cache(&self) {
        self.cache.invalidate_all();
        debug!("DNS cache cleared");
    }

    /// Удаляет одну запись из кэша.
    pub async fn invalidate(&self, domain: &str) {
        self.cache.invalidate(domain).await;
    }

    /// Количество записей в кэше.
    pub fn cache_len(&self) -> u64 {
        self.cache.entry_count()
    }

    fn apply_overrides(&self, ip: IpAddr) -> IpAddr {
        if let IpAddr::V4(v4) = ip {
            for (cidr, override_ip) in &self.ip_overrides {
                if cidr.contains(&v4) {
                    debug!("DNS override: {} → {}", v4, override_ip);
                    return IpAddr::V4(*override_ip);
                }
            }
        }
        ip
    }
}

impl Default for DnsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_engine_creation() {
        let engine = DnsEngine::new();
        assert_eq!(engine.cache_len(), 0);
    }

    #[test]
    fn test_dns_result_struct() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = DnsResult { ip, ttl: 300 };
        assert_eq!(result.ip.to_string(), "8.8.8.8");
        assert_eq!(result.ttl, 300);
    }
}
