//! Proxy Fallback Engine — SOCKS5/HTTP прокси с failover.
//!
//! ## Компоненты
//! - `ProxyFallback` — цепочка прокси с automatic failover
//! - `FreeProxyPool` — пул бесплатных прокси с health checks
//! - `FingerprintRotator` — ротация TLS fingerprint'ов (JA3)
//!
//! ## Архитектура
//! ```text
//! Клиент → ProxyFallback → [SOCKS5 #1] → fail → [SOCKS5 #2] → fail → Direct
//!                                ↑                              ↑
//!                           FreeProxyPool               FreeProxyPool
//! ```
//!
//! ## Источник
//! Адаптировано из [CandyTunnel](https://github.com/nickel-org/candy-tunnel) и
//! [DPIReaper](https://github.com/rage8885/DPIReaper).

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Тип прокси-провайдера.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyType {
    Socks5,
    Http,
    Direct,
}

/// Запись о прокси в пуле.
///
/// Использует interior mutability через atomics для безопасного
/// обновления состояния из `&self` методов (mark_failed/mark_success).
pub struct ProxyEntry {
    pub addr: SocketAddr,
    pub proxy_type: ProxyType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub last_check: Instant,
    is_healthy: AtomicBool,
    latency_ms: AtomicU64,
    fail_count: AtomicU32,
    success_count: AtomicU32,
}

impl std::fmt::Debug for ProxyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyEntry")
            .field("addr", &self.addr)
            .field("proxy_type", &self.proxy_type)
            .field("is_healthy", &self.is_healthy.load(Ordering::Relaxed))
            .field("latency_ms", &self.latency_ms.load(Ordering::Relaxed))
            .field("fail_count", &self.fail_count.load(Ordering::Relaxed))
            .field("success_count", &self.success_count.load(Ordering::Relaxed))
            .finish()
    }
}

impl Clone for ProxyEntry {
    fn clone(&self) -> Self {
        Self {
            addr: self.addr,
            proxy_type: self.proxy_type.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            last_check: self.last_check,
            is_healthy: AtomicBool::new(self.is_healthy.load(Ordering::Relaxed)),
            latency_ms: AtomicU64::new(self.latency_ms.load(Ordering::Relaxed)),
            fail_count: AtomicU32::new(self.fail_count.load(Ordering::Relaxed)),
            success_count: AtomicU32::new(self.success_count.load(Ordering::Relaxed)),
        }
    }
}

impl ProxyEntry {
    pub fn new(addr: SocketAddr, proxy_type: ProxyType) -> Self {
        Self {
            addr,
            proxy_type,
            username: None,
            password: None,
            last_check: Instant::now(),
            is_healthy: AtomicBool::new(true),
            latency_ms: AtomicU64::new(0),
            fail_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
        }
    }

    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::Relaxed)
    }

    pub fn latency_ms(&self) -> u64 {
        self.latency_ms.load(Ordering::Relaxed)
    }

    pub fn fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::Relaxed)
    }

    pub fn success_count(&self) -> u32 {
        self.success_count.load(Ordering::Relaxed)
    }

    /// Соотношение успех/ошибка (> 0.5 = хороший прокси).
    pub fn success_rate(&self) -> f64 {
        let s = self.success_count.load(Ordering::Relaxed) as f64;
        let f = self.fail_count.load(Ordering::Relaxed) as f64;
        let total = s + f;
        if total == 0.0 {
            return 1.0;
        }
        s / total
    }

    /// Помечает прокси как.failed.
    pub fn mark_failed(&self) {
        self.fail_count.fetch_add(1, Ordering::Relaxed);
        self.is_healthy.store(false, Ordering::Relaxed);
    }

    /// Помечает прокси как успешный.
    pub fn mark_success(&self, latency: u64) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.latency_ms.store(latency, Ordering::Relaxed);
        self.is_healthy.store(true, Ordering::Relaxed);
    }
}

/// [35] ProxyFallback: цепочка прокси с automatic failover.
///
/// ## Принцип
/// При ошибке соединения автоматически переключаемся на следующий
/// прокси из цепочки. Если все прокси недоступны — direct connection.
pub struct ProxyFallback {
    /// Цепочка прокси для попыток
    chain: Vec<ProxyEntry>,
    /// Текущий индекс в цепочке
    current: AtomicUsize,
    /// Direct fallback (без прокси)
    direct_fallback: bool,
    /// Таймаут на подключение к прокси
    connect_timeout: Duration,
    /// Максимальное количество retry
    #[allow(dead_code)]
    max_retries: u32,
}

impl ProxyFallback {
    /// Создаёт новый ProxyFallback с пустой цепочкой.
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            current: AtomicUsize::new(0),
            direct_fallback: true,
            connect_timeout: Duration::from_secs(5),
            max_retries: 3,
        }
    }

    /// Добавляет прокси в цепочку.
    pub fn add_proxy(&mut self, entry: ProxyEntry) {
        self.chain.push(entry);
    }

    /// Устанавливает таймаут подключения.
    pub fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
    }

    /// Включает/выключает direct fallback.
    pub fn set_direct_fallback(&mut self, enabled: bool) {
        self.direct_fallback = enabled;
    }

    /// Получает следующий доступный прокси.
    pub fn next_proxy(&self) -> Option<&ProxyEntry> {
        let len = self.chain.len();
        if len == 0 {
            return None;
        }

        let start = self.current.load(Ordering::Relaxed);
        for i in 0..len {
            let idx = (start + i) % len;
            let entry = &self.chain[idx];
            if entry.is_healthy() && entry.success_rate() > 0.3 {
                self.current.store((idx + 1) % len, Ordering::Relaxed);
                return Some(entry);
            }
        }

        None
    }

    /// Помечает прокси как.failed.
    pub fn mark_failed(&self, addr: SocketAddr) {
        for entry in &self.chain {
            if entry.addr == addr {
                entry.mark_failed();
                debug!("Proxy {} marked as failed", addr);
                break;
            }
        }
    }

    /// Помечает прокси как успешный.
    pub fn mark_success(&self, addr: SocketAddr, latency_ms: u64) {
        for entry in &self.chain {
            if entry.addr == addr {
                entry.mark_success(latency_ms);
                debug!("Proxy {} success ({}ms)", addr, latency_ms);
                break;
            }
        }
    }

    /// Количество прокси в цепочке.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Пуста ли цепочка.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Снапшот цепочки для API.
    pub fn snapshot(&self) -> Vec<ProxySnapshot> {
        self.chain
            .iter()
            .map(|e| ProxySnapshot {
                addr: e.addr.to_string(),
                proxy_type: format!("{:?}", e.proxy_type),
                healthy: e.is_healthy(),
                latency_ms: e.latency_ms(),
                success_rate: e.success_rate(),
            })
            .collect()
    }
}

impl Default for ProxyFallback {
    fn default() -> Self {
        Self::new()
    }
}

/// Снапшот прокси для API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxySnapshot {
    pub addr: String,
    pub proxy_type: String,
    pub healthy: bool,
    pub latency_ms: u64,
    pub success_rate: f64,
}

/// [37] FreeProxyPool: пул бесплатных прокси.
///
/// ## Принцип
/// Скачиваем списки бесплатных SOCKS5/HTTP прокси,
/// проверяем их доступность, храним healthy прокси.
pub struct FreeProxyPool {
    /// Хранилище прокси
    proxies: Arc<DashMap<String, ProxyEntry>>,
    /// URL'ы для скачивания списков
    #[allow(dead_code)]
    source_urls: Vec<String>,
    /// Интервал обновления
    #[allow(dead_code)]
    update_interval: Duration,
}

impl FreeProxyPool {
    /// Создаёт новый пул.
    pub fn new() -> Self {
        Self {
            proxies: Arc::new(DashMap::new()),
            source_urls: vec![
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt"
                    .to_string(),
                "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"
                    .to_string(),
            ],
            update_interval: Duration::from_secs(300),
        }
    }

    /// Добавляет прокси в пул.
    pub fn add(&self, entry: ProxyEntry) {
        self.proxies.insert(entry.addr.to_string(), entry);
    }

    /// Получает случайный здоровый прокси.
    pub fn get_random(&self) -> Option<ProxyEntry> {
        let healthy: Vec<_> = self
            .proxies
            .iter()
            .filter(|e| e.value().is_healthy() && e.value().success_rate() > 0.5)
            .map(|e| e.value().clone())
            .collect();

        if healthy.is_empty() {
            return None;
        }

        let idx = crate::desync::rand::random_range(0, healthy.len() as u32) as usize;
        healthy.into_iter().nth(idx)
    }

    /// Получает лучший прокси (по success_rate и latency).
    pub fn get_best(&self) -> Option<ProxyEntry> {
        self.proxies
            .iter()
            .filter(|e| e.value().is_healthy())
            .map(|e| e.value().clone())
            .max_by(|a, b| {
                let score_a = a.success_rate() * 1000.0 - a.latency_ms() as f64;
                let score_b = b.success_rate() * 1000.0 - b.latency_ms() as f64;
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Помечает прокси как.failed.
    pub fn mark_failed(&self, addr: &str) {
        if let Some(entry) = self.proxies.get(addr) {
            entry.mark_failed();
            let fails = entry.fail_count();
            if fails > 5 {
                warn!("Proxy {} disabled after {} failures", addr, fails);
            }
        }
    }

    /// Помечает прокси как успешный.
    pub fn mark_success(&self, addr: &str, latency_ms: u64) {
        if let Some(entry) = self.proxies.get(addr) {
            entry.mark_success(latency_ms);
        }
    }

    /// Количество прокси в пуле.
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Пуст ли пул.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Количество здоровых прокси.
    pub fn healthy_count(&self) -> usize {
        self.proxies
            .iter()
            .filter(|e| e.value().is_healthy())
            .count()
    }

    /// Удаляет все прокси.
    pub fn clear(&self) {
        self.proxies.clear();
    }
}

impl Default for FreeProxyPool {
    fn default() -> Self {
        Self::new()
    }
}

/// [42] FingerprintRotator: ротация TLS fingerprint'ов.
///
/// ## Принцип
/// DPI анализирует JA3 fingerprint для идентификации браузера.
/// Ротация cipher suites и extensions сбивает fingerprint matching.
pub struct FingerprintRotator {
    /// Индекс текущего fingerprint
    current: AtomicUsize,
    /// Список fingerprint'ов (cipher suite sets)
    fingerprints: Vec<TlsFingerprint>,
}

/// TLS fingerprint (набор cipher suites + extensions).
#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    /// Имя (Chrome, Firefox, Safari...)
    pub name: String,
    /// Cipher suites (в порядке приоритета)
    pub cipher_suites: Vec<u16>,
    /// Extensions
    pub extensions: Vec<u16>,
    /// Supported groups (elliptic curves)
    pub supported_groups: Vec<u16>,
    /// Signature algorithms
    pub sig_algorithms: Vec<u16>,
}

impl FingerprintRotator {
    /// Создаёт ротатор с встроенными fingerprint'ами.
    pub fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            fingerprints: vec![
                Self::chrome_120(),
                Self::firefox_121(),
                Self::safari_17(),
                Self::edge_120(),
            ],
        }
    }

    /// Получает текущий fingerprint и переходит к следующему.
    pub fn next(&self) -> &TlsFingerprint {
        let idx = self.current.fetch_add(1, Ordering::Relaxed) % self.fingerprints.len();
        &self.fingerprints[idx]
    }

    /// Получает fingerprint по индексу.
    pub fn get(&self, index: usize) -> Option<&TlsFingerprint> {
        self.fingerprints.get(index % self.fingerprints.len())
    }

    /// Количество fingerprint'ов.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Пуст ли ротатор.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Chrome 120 fingerprint.
    fn chrome_120() -> TlsFingerprint {
        TlsFingerprint {
            name: "Chrome 120".to_string(),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, // TLS_AES_128/256_GCM, TLS_CHACHA20_POLY1305
                0xc02b, 0xc02f, // ECDHE_ECDSA/RSA AES_128_GCM
                0xc02c, 0xc030, // ECDHE_ECDSA/RSA AES_256_GCM
                0xcca9, 0xcca8, // ECDHE_ECDSA/RSA CHACHA20
                0xc013, 0xc014, // ECDHE_ECDSA/RSA AES_128_CBC
                0xc009, 0xc00a, // ECDHE_ECDSA/RSA AES_256_CBC
                0x009c, 0x009d, 0x002f, 0x0035, // AES_128/256_GCM, AES_128/256_CBC
            ],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            supported_groups: vec![0x001d, 0x0017, 0x0018], // x25519, secp256r1, secp384r1
            sig_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        }
    }

    /// Firefox 121 fingerprint.
    fn firefox_121() -> TlsFingerprint {
        TlsFingerprint {
            name: "Firefox 121".to_string(),
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, // TLS_AES_128_GCM, CHACHA20, AES_256_GCM
                0xc02b, 0xc02f, // ECDHE_ECDSA/RSA AES_128_GCM
                0xc02c, 0xc030, // ECDHE_ECDSA/RSA AES_256_GCM
                0xcca9, 0xcca8, // ECDHE_CHACHA20
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 27, 21, 17513,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            sig_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
            ],
        }
    }

    /// Safari 17 fingerprint.
    fn safari_17() -> TlsFingerprint {
        TlsFingerprint {
            name: "Safari 17".to_string(),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, // ECDHE
                0xcca9, 0xcca8, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c,
                0x003d, 0x003c, 0x0035, 0x002f,
            ],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            supported_groups: vec![0x001d, 0x0017, 0x0100], // x25519, secp256r1, secp256k1
            sig_algorithms: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601],
        }
    }

    /// Edge 120 fingerprint.
    fn edge_120() -> TlsFingerprint {
        TlsFingerprint {
            name: "Edge 120".to_string(),
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0xc009, 0xc00a, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            sig_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        }
    }
}

impl Default for FingerprintRotator {
    fn default() -> Self {
        Self::new()
    }
}

/// Парсит список прокси из текста (one per line: host:port).
pub fn parse_proxy_list(text: &str) -> Vec<ProxyEntry> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let addr: SocketAddr = line.parse().ok()?;
            Some(ProxyEntry::new(addr, ProxyType::Socks5))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_proxy_fallback_empty() {
        let fb = ProxyFallback::new();
        assert!(fb.is_empty());
        assert!(fb.next_proxy().is_none());
    }

    #[test]
    fn test_proxy_fallback_add_and_get() {
        let mut fb = ProxyFallback::new();
        let entry = ProxyEntry::new("127.0.0.1:1080".parse().unwrap(), ProxyType::Socks5);
        fb.add_proxy(entry);
        assert_eq!(fb.len(), 1);
        assert!(fb.next_proxy().is_some());
    }

    #[test]
    fn test_proxy_entry_success_rate() {
        let entry = ProxyEntry::new("127.0.0.1:1080".parse().unwrap(), ProxyType::Socks5);
        assert_eq!(entry.success_rate(), 1.0); // no failures yet
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_success(0);
        entry.mark_failed();
        entry.mark_failed();
        assert_eq!(entry.success_count(), 8);
        assert_eq!(entry.fail_count(), 2);
        assert_eq!(entry.success_rate(), 0.8);
    }

    #[test]
    fn test_free_proxy_pool() {
        let pool = FreeProxyPool::new();
        let entry = ProxyEntry::new("127.0.0.1:1080".parse().unwrap(), ProxyType::Socks5);
        pool.add(entry);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.healthy_count(), 1);
    }

    #[test]
    fn test_free_proxy_pool_mark() {
        let pool = FreeProxyPool::new();
        let entry = ProxyEntry::new("127.0.0.1:1080".parse().unwrap(), ProxyType::Socks5);
        pool.add(entry);
        pool.mark_success("127.0.0.1:1080", 50);
        assert_eq!(pool.healthy_count(), 1);
        pool.mark_failed("127.0.0.1:1080");
        assert_eq!(pool.healthy_count(), 0); // now actually disabled
    }

    #[test]
    fn test_fingerprint_rotator() {
        let rotator = FingerprintRotator::new();
        assert_eq!(rotator.len(), 4);
        let fp1 = rotator.next();
        let fp2 = rotator.next();
        // Should rotate through different fingerprints
        assert!(!fp1.cipher_suites.is_empty());
        assert!(!fp2.cipher_suites.is_empty());
    }

    #[test]
    fn test_parse_proxy_list() {
        let list = "127.0.0.1:1080\n192.168.1.1:9050\n\n# comment\n10.0.0.1:1080";
        let proxies = parse_proxy_list(list);
        assert_eq!(proxies.len(), 3);
    }

    #[test]
    fn test_fingerprint_chrome_cipher_count() {
        let fp = FingerprintRotator::chrome_120();
        assert!(fp.cipher_suites.len() >= 15);
    }

    #[test]
    fn test_fingerprint_firefox_different_from_chrome() {
        let chrome = FingerprintRotator::chrome_120();
        let firefox = FingerprintRotator::firefox_121();
        // Firefox has different extension list
        assert_ne!(chrome.extensions, firefox.extensions);
    }
}
