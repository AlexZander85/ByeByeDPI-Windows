//! ProbeConfig — конфигурация DPI Probe Module.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Конфигурация DPI Probe Module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    // DNS
    /// UDP DNS серверы для cross-validation
    pub dns_udp_servers: Vec<String>,
    /// DoH URLs для cross-validation
    pub dns_doh_urls: Vec<String>,
    /// Таймаут DNS запроса
    pub dns_timeout: Duration,
    /// Домены для тестирования DNS
    pub dns_test_domains: Vec<String>,

    // TCP
    /// Таймаут TCP connect
    pub tcp_connect_timeout: Duration,
    /// Количество IP для parallel dial race
    pub tcp_race_count: usize,

    // TLS
    pub tls_connect_timeout: Duration,
    pub tls_read_timeout: Duration,

    // HTTP
    pub http_read_timeout: Duration,
    pub http_max_bytes: usize,

    // TCP16 (Data-Volume probe)
    /// Количество HEAD запросов (по умолчанию 16)
    pub tcp16_requests: usize,
    /// Размер X-Pad заголовка в байтах (по умолчанию 4KB)
    pub tcp16_pad_size: usize,
    /// Минимальный размер обнаружения блокировки в КБ
    pub tcp16_min_kb: u64,
    /// Максимальный размер тестирования в КБ
    pub tcp16_max_kb: u64,
    /// Множитель таймаута: timeout = max(rtt * factor, min_timeout)
    pub tcp16_timeout_factor: f64,
    /// Минимальный timeout на запрос
    pub tcp16_min_timeout: Duration,

    // Accumulation
    /// TTL горячих записей (по умолчанию 24ч)
    pub hot_ttl: Duration,
    /// Интервал повторного probe (по умолчанию 5 мин)
    pub probe_interval: Duration,
    /// Порог для promotion в permanent cache (количество blocked verdicts)
    pub promote_threshold: u32,
    /// Порог количества поддоменов для eTLD+1 expansion
    pub family_threshold: usize,

    // RKN stub detection
    /// Подстроки для обнаружения RKN-заглушек
    pub rkn_stub_substrings: Vec<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            // DNS
            dns_udp_servers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "9.9.9.9".to_string(),
            ],
            dns_doh_urls: vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/resolve".to_string(),
            ],
            dns_timeout: Duration::from_secs(3),
            dns_test_domains: vec![
                "google.com".to_string(),
                "youtube.com".to_string(),
                "telegram.org".to_string(),
            ],

            // TCP
            tcp_connect_timeout: Duration::from_secs(3),
            tcp_race_count: 3,

            // TLS
            tls_connect_timeout: Duration::from_secs(5),
            tls_read_timeout: Duration::from_secs(5),

            // HTTP
            http_read_timeout: Duration::from_secs(8),
            http_max_bytes: 32 * 1024, // 32KB

            // TCP16
            tcp16_requests: 16,
            tcp16_pad_size: 4096, // 4KB
            tcp16_min_kb: 12,
            tcp16_max_kb: 69,
            tcp16_timeout_factor: 3.0,
            tcp16_min_timeout: Duration::from_millis(1500),

            // Accumulation
            hot_ttl: Duration::from_secs(86400),       // 24h
            probe_interval: Duration::from_secs(300),   // 5 min
            promote_threshold: 50,
            family_threshold: 10,

            // RKN stub
            rkn_stub_substrings: vec![
                "роскомнадзор".to_string(),
                "poiskman".to_string(),
                "blockpage".to_string(),
                "заблокир".to_string(),
                "ограничен".to_string(),
                "restricted".to_string(),
                "roskomsvoboda".to_string(),
                "internet-zapret".to_string(),
                "technique-of-blocking".to_string(),
                "decision of".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProbeConfig::default();
        assert_eq!(config.dns_udp_servers.len(), 3);
        assert_eq!(config.dns_doh_urls.len(), 2);
        assert_eq!(config.tcp_race_count, 3);
        assert_eq!(config.dns_timeout, Duration::from_secs(3));
        assert_eq!(config.tcp_connect_timeout, Duration::from_secs(3));
        // TCP16 fields
        assert_eq!(config.tcp16_requests, 16);
        assert_eq!(config.tcp16_pad_size, 4096);
        assert_eq!(config.tcp16_timeout_factor, 3.0);
        assert_eq!(config.tcp16_min_timeout, Duration::from_millis(1500));
        // Accumulation fields
        assert_eq!(config.hot_ttl, Duration::from_secs(86400));
        assert_eq!(config.probe_interval, Duration::from_secs(300));
        assert_eq!(config.promote_threshold, 50);
        assert_eq!(config.family_threshold, 10);
        // RKN stubs
        assert_eq!(config.rkn_stub_substrings.len(), 10);
    }

    #[test]
    fn test_config_serialization() {
        let config = ProbeConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: ProbeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.dns_udp_servers, back.dns_udp_servers);
        assert_eq!(config.tcp_race_count, back.tcp_race_count);
        assert_eq!(config.tcp16_requests, back.tcp16_requests);
        assert_eq!(config.promote_threshold, back.promote_threshold);
    }
}
