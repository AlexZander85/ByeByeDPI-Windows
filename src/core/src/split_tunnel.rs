//! Split Tunneling Engine — blacklist/whitelist/auto режимы.
//!
//! Определяет, какие домены/IP должны проходить через DPI-обход,
//! а какие — напрямую (банки, госуслуги, корпоративные ресурсы).

use dashmap::{DashMap, DashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Thread-local LRU cache для `should_bypass_ip()`.
/// Устраняет 5 DashMap lookups на пакет при 10Gbps.
const TL_CACHE_SIZE: usize = 1024;

thread_local! {
    static BYPASS_CACHE: std::cell::RefCell<Vec<(u32, bool)>> =
        std::cell::RefCell::new(Vec::with_capacity(TL_CACHE_SIZE));
}

/// Режим раздельного туннелирования.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SplitMode {
    /// Только whitelist-домены проходят через DPI-обход.
    /// Остальные — напрямую (безопасный режим).
    WhitelistOnly,
    /// Все домены, кроме blacklist, проходят через DPI-обход.
    /// Blacklist — напрямую (банки, госуслуги).
    BlacklistOnly,
    /// Авто-режим: пробуем через DPI-обход, при ошибке
    /// добавляем в auto-detected blacklist.
    Auto,
}

/// Результат проверки split tunnel.
#[derive(Debug, Clone, PartialEq)]
pub enum SplitDecision {
    /// Пропустить через DPI-обход
    Bypass,
    /// Пропустить напрямую
    Direct,
    /// Проверить (Auto-режим)
    Probe,
}

/// Движок раздельного туннелирования.
pub struct SplitTunnel {
    /// Домены, которые НЕ нужно обходить (банки, госуслуги)
    blacklist_domains: Arc<DashSet<String>>,
    /// IP, которые НЕ нужно обходить
    blacklist_ips: Arc<DashSet<Ipv4Addr>>,
    /// Домены, которые нужно обходить (только в WhitelistOnly)
    whitelist_domains: Arc<DashSet<String>>,
    /// IP для whitelist
    whitelist_ips: Arc<DashSet<Ipv4Addr>>,
    /// Авто-детекшенные IP (для Auto-режима)
    auto_detected: Arc<DashSet<Ipv4Addr>>,
    /// Маппинг IP → domain (из DNS ответов)
    domain_cache: Arc<DashMap<Ipv4Addr, String>>,
    /// Текущий режим
    mode: SplitMode,
}

impl SplitTunnel {
    /// Создаёт новый split tunnel engine.
    pub fn new(mode: SplitMode) -> Self {
        Self {
            blacklist_domains: Arc::new(DashSet::new()),
            blacklist_ips: Arc::new(DashSet::new()),
            whitelist_domains: Arc::new(DashSet::new()),
            whitelist_ips: Arc::new(DashSet::new()),
            auto_detected: Arc::new(DashSet::new()),
            domain_cache: Arc::new(DashMap::new()),
            mode,
        }
    }

    /// Определяет, нужно ли обходить этот IP (fast path с thread-local cache).
    pub fn should_bypass_ip_fast(&self, dst_ip: &Ipv4Addr) -> bool {
        let ip_int = u32::from_ne_bytes(dst_ip.octets());

        // Thread-local cache lookup
        let cached = BYPASS_CACHE.with(|c| {
            let cache = c.borrow();
            cache.iter().find(|(ip, _)| *ip == ip_int).map(|(_, v)| *v)
        });
        if let Some(result) = cached {
            return result;
        }

        // Cache miss — делаем DashMap lookup
        let result = self.should_bypass_ip(dst_ip);

        // Сохраняем в cache
        BYPASS_CACHE.with(|c| {
            let mut cache = c.borrow_mut();
            if cache.len() >= TL_CACHE_SIZE {
                cache.remove(0);
            }
            cache.push((ip_int, result));
        });

        result
    }

    /// Определяет, нужно ли обходить этот IP.
    pub fn should_bypass_ip(&self, dst_ip: &Ipv4Addr) -> bool {
        match self.mode {
            SplitMode::WhitelistOnly => {
                // Проверяем, есть ли IP в whitelist (через domain cache)
                let domain = self.domain_cache.get(dst_ip);
                domain.is_some_and(|d| self.whitelist_domains.contains(d.value()))
                    || self.whitelist_ips.contains(dst_ip)
            }
            SplitMode::BlacklistOnly => !self.blacklist_ips.contains(dst_ip),
            SplitMode::Auto => !self.auto_detected.contains(dst_ip),
        }
    }

    /// Определяет, нужно ли обходить этот домен.
    pub fn should_bypass_domain(&self, domain: &str) -> bool {
        match self.mode {
            SplitMode::WhitelistOnly => self.whitelist_domains.contains(domain),
            SplitMode::BlacklistOnly => !self.blacklist_domains.contains(domain),
            SplitMode::Auto => true, // Auto: пробуем всё
        }
    }

    /// Принимает решение для домена.
    pub fn decide(&self, domain: &str) -> SplitDecision {
        match self.mode {
            SplitMode::WhitelistOnly => {
                if self.whitelist_domains.contains(domain) {
                    SplitDecision::Bypass
                } else {
                    SplitDecision::Direct
                }
            }
            SplitMode::BlacklistOnly => {
                if self.blacklist_domains.contains(domain) {
                    SplitDecision::Direct
                } else {
                    SplitDecision::Bypass
                }
            }
            SplitMode::Auto => {
                if self.auto_detected.iter().any(|ip| {
                    self.domain_cache
                        .get(&ip)
                        .is_some_and(|d| d.value() == domain)
                }) {
                    SplitDecision::Direct
                } else {
                    SplitDecision::Probe
                }
            }
        }
    }

    /// Добавляет домен в blacklist.
    pub fn add_to_blacklist(&self, domain: String) {
        debug!("Adding to blacklist: {}", domain);
        self.blacklist_domains.insert(domain);
    }

    /// Добавляет IP в blacklist.
    pub fn add_ip_to_blacklist(&self, ip: Ipv4Addr) {
        debug!("Adding IP to blacklist: {}", ip);
        self.blacklist_ips.insert(ip);
    }

    /// Добавляет домен в whitelist.
    pub fn add_to_whitelist(&self, domain: String) {
        debug!("Adding to whitelist: {}", domain);
        self.whitelist_domains.insert(domain);
    }

    /// Регистрирует IP→domain маппинг (из DNS ответов).
    pub fn register_dns(&self, ip: Ipv4Addr, domain: String) {
        self.domain_cache.insert(ip, domain);
    }

    /// Маркирует IP как заблокированный (Auto-режим).
    pub fn mark_blocked(&self, ip: Ipv4Addr) {
        debug!("Auto-detected blocked IP: {}", ip);
        self.auto_detected.insert(ip);
    }

    /// Построение WinDivert фильтра (оптимизация).
    ///
    /// WinDivert фильтр может быть длиной до 256 символов.
    /// Если blacklist слишком большой — используем базовый фильтр.
    pub fn build_win_divert_filter(&self) -> String {
        let base = "ip && (tcp.DstPort == 443 or tcp.SrcPort == 443 \
                     or udp.DstPort == 53 or udp.DstPort == 443)"
            .to_string();

        match self.mode {
            SplitMode::BlacklistOnly if !self.blacklist_ips.is_empty() => {
                let exclusions: Vec<String> = self
                    .blacklist_ips
                    .iter()
                    .take(32) // WinDivert лимит
                    .map(|ip| format!("ip.DstAddr != {}", *ip))
                    .collect();
                if exclusions.is_empty() {
                    base
                } else {
                    format!("({}) && ({})", base, exclusions.join(" && "))
                }
            }
            _ => base,
        }
    }

    /// Меняет режим.
    pub fn set_mode(&mut self, mode: SplitMode) {
        debug!("Split tunnel mode changed: {:?} → {:?}", self.mode, mode);
        self.mode = mode;
    }

    /// Текущий режим.
    pub fn mode(&self) -> SplitMode {
        self.mode
    }

    /// Снапшот blacklist для API.
    pub fn blacklist_snapshot(&self) -> Vec<String> {
        self.blacklist_domains.iter().map(|d| d.clone()).collect()
    }

    /// Снапшот whitelist для API.
    pub fn whitelist_snapshot(&self) -> Vec<String> {
        self.whitelist_domains.iter().map(|d| d.clone()).collect()
    }
}

impl Default for SplitTunnel {
    fn default() -> Self {
        Self::new(SplitMode::BlacklistOnly)
    }
}

/// Prober для Auto-режима.
pub struct AutoProber {
    /// Успешно пробированные домены (whitelist — не блокировать повторно).
    whitelist: dashmap::DashSet<String>,
    /// Путь к файлу с blocked доменами.
    blocked_file: Option<String>,
}

impl AutoProber {
    pub fn new(blocked_file: Option<String>) -> Self {
        Self {
            whitelist: dashmap::DashSet::new(),
            blocked_file,
        }
    }

    /// Проверяет доступность сайта. Результаты сохраняются в whitelist/blacklist.
    pub async fn probe(&self, domain: &str, ip: Ipv4Addr) -> ProbeResult {
        if self.whitelist.contains(domain) {
            return ProbeResult::Direct;
        }

        let result = Self::probe_raw(domain, ip).await;

        match result {
            ProbeResult::Direct => {
                self.whitelist.insert(domain.to_string());
                debug!("AutoProbe: {} → Direct (whitelisted)", domain);
            }
            ProbeResult::Blocked => {
                if let Some(ref path) = self.blocked_file {
                    self.append_to_file(path, domain);
                }
                debug!("AutoProbe: {} → Blocked", domain);
            }
        }
        result
    }

    async fn probe_raw(domain: &str, ip: Ipv4Addr) -> ProbeResult {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let stream =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((ip, 443))).await;

        let Ok(Ok(mut stream)) = stream else {
            return ProbeResult::Blocked;
        };

        let ch = build_probe_client_hello(domain);
        if stream.write(&ch).await.is_err() {
            return ProbeResult::Blocked;
        }

        let mut buf = [0u8; 1024];
        let response = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

        match response {
            Ok(Ok(n)) if n > 5 && buf[0] == 0x16 => ProbeResult::Direct,
            _ => ProbeResult::Blocked,
        }
    }

    fn append_to_file(&self, path: &str, domain: &str) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{}", domain);
        }
    }

    /// Загружает blocked домены из файла в SplitTunnel blacklist.
    pub fn load_blocked_file(path: &str, tunnel: &SplitTunnel) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let domain = line.trim().to_string();
                if !domain.is_empty() && !domain.starts_with('#') {
                    tunnel.add_to_blacklist(domain);
                }
            }
        }
    }
}

/// Результат пробы.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResult {
    /// Сайт доступен напрямую
    Direct,
    /// Сайт заблокирован (или недоступен)
    Blocked,
}

/// Строит минимальный TLS ClientHello для пробы.
///
/// Содержит только SNI extension (минимальный размер).
fn build_probe_client_hello(domain: &str) -> Vec<u8> {
    let sni_len = domain.len();

    // TLS record header: ContentType(0x16), Version(0x0301), Length
    let mut packet = Vec::with_capacity(1024);

    // TLS record: Handshake
    packet.extend_from_slice(&[
        0x16, // ContentType: Handshake
        0x03, 0x01, // TLS version (TLS 1.0 in record layer)
        0x00, 0x00, // Length (placeholder)
    ]);

    // Handshake: ClientHello
    packet.extend_from_slice(&[
        0x01, // HandshakeType: ClientHello
        0x00, 0x00, 0x00, // Length (placeholder)
        0x03,
        0x03, // Version: TLS 1.2
              // Random (32 bytes) — можно из реального Chrome
    ]);
    packet.extend_from_slice(&[0u8; 32]);

    // Session ID length = 0
    packet.push(0x00);

    // Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301)
    packet.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

    // Compression methods: null
    packet.extend_from_slice(&[0x01, 0x00]);

    // Extensions length
    let ext_len = 2 + 2 + 2 + 2 + sni_len + 2;
    packet.extend_from_slice(&[(ext_len >> 8) as u8, (ext_len & 0xFF) as u8]);

    // Extension: SNI (server_name)
    packet.extend_from_slice(&[0x00, 0x00]); // Type: SNI (0)
    let sni_payload_len = 2 + 1 + 2 + sni_len;
    packet.extend_from_slice(&[(sni_payload_len >> 8) as u8, (sni_payload_len & 0xFF) as u8]);
    packet.extend_from_slice(&[0x00, (sni_len + 5) as u8]); // SNI list length
    packet.extend_from_slice(&[0x00]); // NameType: host_name
    packet.extend_from_slice(&[(sni_len >> 8) as u8, (sni_len & 0xFF) as u8]);
    packet.extend_from_slice(domain.as_bytes());

    // Fill lengths
    let handshake_len = (packet.len() - 5) as u16;
    packet[3] = (handshake_len >> 8) as u8;
    packet[4] = (handshake_len & 0xFF) as u8;

    let record_len = (packet.len() - 5) as u16;
    packet[3] = (record_len >> 8) as u8;
    packet[4] = (record_len & 0xFF) as u8;

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklist_bypass() {
        let tunnel = SplitTunnel::new(SplitMode::BlacklistOnly);
        tunnel.add_to_blacklist("gosuslugi.ru".to_string());
        tunnel.add_ip_to_blacklist(Ipv4Addr::new(95, 213, 0, 1));

        assert!(!tunnel.should_bypass_domain("gosuslugi.ru"));
        assert!(tunnel.should_bypass_domain("youtube.com"));
        assert!(!tunnel.should_bypass_ip(&Ipv4Addr::new(95, 213, 0, 1)));
    }

    #[test]
    fn test_whitelist_bypass() {
        let tunnel = SplitTunnel::new(SplitMode::WhitelistOnly);
        tunnel.add_to_whitelist("youtube.com".to_string());

        assert!(tunnel.should_bypass_domain("youtube.com"));
        assert!(!tunnel.should_bypass_domain("gosuslugi.ru"));
    }

    #[test]
    fn test_auto_mode() {
        let tunnel = SplitTunnel::new(SplitMode::Auto);
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        assert!(tunnel.should_bypass_ip(&ip)); // Initially true
        tunnel.mark_blocked(ip);
        assert!(!tunnel.should_bypass_ip(&ip)); // Now blocked
    }

    #[test]
    fn test_dns_registration() {
        let tunnel = SplitTunnel::new(SplitMode::WhitelistOnly);
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        tunnel.register_dns(ip, "youtube.com".to_string());

        // Without whitelist, should not bypass
        assert!(!tunnel.should_bypass_ip(&ip));

        // With whitelist
        tunnel.add_to_whitelist("youtube.com".to_string());
        assert!(tunnel.should_bypass_ip(&ip));
    }

    #[test]
    fn test_win_divert_filter() {
        let tunnel = SplitTunnel::new(SplitMode::BlacklistOnly);
        let filter = tunnel.build_win_divert_filter();
        assert!(filter.contains("tcp.DstPort == 443"));
    }
}
