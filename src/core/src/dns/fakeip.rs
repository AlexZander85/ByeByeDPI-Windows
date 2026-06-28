//! FakeIP DNS — аллокация fake IP адресов для доменов (из sing-box).
//!
//! ## Принцип работы
//! Когда DPI-обход изменяет SNI на белый домен, ответ сервера
//! приходит с другим сертификатом. FakeIP позволяет сопоставить
//! реальный домен с fake IP из резервированного диапазона 10.0.0.0/8.
//!
//! ## Бизнес-логика
//! 1. Клиент делает DNS запрос → engine возвращает fake IP (10.x.x.x)
//! 2. Клиент подключается к fake IP → engine видит fake IP
//! 3. Engine подставляет реальный SNI из маппинга fake IP → domain
//! 4. Сервер отвечает → engine конвертирует ответ обратно
//!
//! ## Диапазон
//! 10.0.0.0 – 10.255.255.255 (16 777 216 адресов)
//!
//! ## Thread Safety
//! DashMap для domain→IP и IP→domain маппингов. AtomicU32 для
//! счётчика следующего свободного IP. Lock-free для всех операций.
//!
//! ## Источник
//! Адаптировано из [sing-box](https://github.com/SagerNet/sing-box) —
//! FakeIP DNS (dns.fakeip).

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::debug;

/// Базовый префикс FakeIP диапазона (10.0.0.0/8).
const FAKEIP_BASE: u32 = 0x0A00_0000;
/// Маска для 16M адресов (первые 8 бит фиксированы).
const FAKEIP_MASK: u32 = 0x00FF_FFFF;

/// FakeIP DNS Manager.
///
/// Выделяет виртуальные IP адреса из диапазона 10.0.0.0/8
/// для доменов. Позволяет engine определить реальный домен
/// по fake IP при обработке входящих пакетов.
///
/// # Пример
/// ```rust
/// use freedpi_core::dns::fakeip::FakeIpManager;
///
/// let manager = FakeIpManager::new(10_000);
/// let ip = manager.allocate("example.com").unwrap();
/// assert!(FakeIpManager::is_fake_ip(&ip));
/// assert_eq!(manager.lookup(&ip), Some("example.com".to_string()));
/// ```
pub struct FakeIpManager {
    /// Маппинг domain → fake IP
    domain_to_ip: Arc<DashMap<String, Ipv4Addr>>,
    /// Маппинг fake IP → domain (обратный lookup)
    ip_to_domain: Arc<DashMap<Ipv4Addr, String>>,
    /// Следующий свободный IP в диапазоне (atomic, начиная с 1)
    next_ip: Arc<AtomicU32>,
    /// Максимальное количество записей
    max_entries: usize,
}

impl FakeIpManager {
    /// Создаёт новый FakeIP менеджер.
    ///
    /// # Arguments
    /// * `max_entries` — максимальное количество записей
    ///   (по умолчанию 10 000, адресов 16M)
    pub fn new(max_entries: usize) -> Self {
        Self {
            domain_to_ip: Arc::new(DashMap::new()),
            ip_to_domain: Arc::new(DashMap::new()),
            next_ip: Arc::new(AtomicU32::new(1)),
            max_entries,
        }
    }

    /// Выделяет (или возвращает существующий) fake IP для домена.
    ///
    /// Если домен уже имеет fake IP — возвращает его.
    /// Если пул заполнен — возвращает None.
    ///
    /// # Arguments
    /// * `domain` — доменное имя
    ///
    /// # Returns
    /// `Some(Ipv4Addr)` — выделенный fake IP
    /// `None` — пул заполнен
    pub fn allocate(&self, domain: &str) -> Option<Ipv4Addr> {
        // Проверяем существующий маппинг
        if let Some(ip) = self.domain_to_ip.get(domain) {
            return Some(*ip);
        }

        // Проверяем лимит
        if self.domain_to_ip.len() >= self.max_entries {
            tracing::warn!(
                "FakeIP cache full ({} entries), cannot allocate for {}",
                self.max_entries,
                domain
            );
            return None;
        }

        // Выделяем новый IP: 10.0.0.0 + atomic counter (mask to /8)
        let offset = self.next_ip.fetch_add(1, Ordering::Relaxed);
        if offset > FAKEIP_MASK {
            tracing::warn!("FakeIP pool exhausted (16M addresses)");
            return None;
        }
        let ip_val = FAKEIP_BASE | (offset & FAKEIP_MASK);
        let ip = Ipv4Addr::from_bits(ip_val);

        debug!("FakeIP allocated: {} → {}", domain, ip);
        self.domain_to_ip.insert(domain.to_string(), ip);
        self.ip_to_domain.insert(ip, domain.to_string());

        Some(ip)
    }

    /// Обратный lookup: fake IP → домен.
    ///
    /// # Arguments
    /// * `fake_ip` — виртуальный IP адрес
    ///
    /// # Returns
    /// `Some(String)` с доменом, если IP найден в маппинге
    pub fn lookup(&self, fake_ip: &Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(fake_ip).map(|d| d.clone())
    }

    /// Удаляет маппинг для домена.
    ///
    /// # Arguments
    /// * `domain` — домен для удаления
    pub fn remove(&self, domain: &str) {
        if let Some((_, ip)) = self.domain_to_ip.remove(domain) {
            self.ip_to_domain.remove(&ip);
            debug!("FakeIP removed: {} → {}", domain, ip);
        }
    }

    /// Очищает все маппинги и сбрасывает счётчик.
    pub fn clear(&self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.next_ip.store(1, Ordering::Relaxed);
    }

    /// Количество активных маппингов.
    pub fn len(&self) -> usize {
        self.domain_to_ip.len()
    }

    /// Пуст ли менеджер.
    pub fn is_empty(&self) -> bool {
        self.domain_to_ip.is_empty()
    }

    /// Проверяет, является ли IP fake IP (из диапазона 10.0.0.0/8).
    ///
    /// # Arguments
    /// * `ip` — IP адрес для проверки
    ///
    /// # Returns
    /// `true` если IP принадлежит диапазону 10.x.x.x
    pub fn is_fake_ip(ip: &Ipv4Addr) -> bool {
        ip.octets()[0] == 10
    }

    /// Возвращает снапшот всех записей (для API/debug).
    pub fn snapshot(&self) -> Vec<(String, Ipv4Addr)> {
        self.domain_to_ip
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }
}

impl Default for FakeIpManager {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_lookup() {
        let manager = FakeIpManager::new(100);
        let ip = manager.allocate("example.com").unwrap();

        assert!(FakeIpManager::is_fake_ip(&ip));
        assert!(ip.octets()[0] == 10);

        let domain = manager.lookup(&ip);
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_same_domain_returns_same_ip() {
        let manager = FakeIpManager::new(100);
        let ip1 = manager.allocate("example.com").unwrap();
        let ip2 = manager.allocate("example.com").unwrap();
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_different_domains_different_ips() {
        let manager = FakeIpManager::new(100);
        let ip1 = manager.allocate("example.com").unwrap();
        let ip2 = manager.allocate("google.com").unwrap();
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_remove() {
        let manager = FakeIpManager::new(100);
        let ip = manager.allocate("example.com").unwrap();

        manager.remove("example.com");
        assert!(manager.lookup(&ip).is_none());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_clear() {
        let manager = FakeIpManager::new(100);
        manager.allocate("a.com");
        manager.allocate("b.com");
        assert_eq!(manager.len(), 2);

        manager.clear();
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_is_fake_ip() {
        assert!(FakeIpManager::is_fake_ip(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(FakeIpManager::is_fake_ip(&Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!FakeIpManager::is_fake_ip(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!FakeIpManager::is_fake_ip(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_snapshot() {
        let manager = FakeIpManager::new(100);
        manager.allocate("a.com");
        manager.allocate("b.com");

        let snap = manager.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|(d, _)| d == "a.com"));
        assert!(snap.iter().any(|(d, _)| d == "b.com"));
    }

    #[test]
    fn test_max_entries() {
        let manager = FakeIpManager::new(5);
        for i in 0..5 {
            assert!(manager.allocate(&format!("{}.com", i)).is_some());
        }
        // 6th should fail
        assert!(manager.allocate("overflow.com").is_none());
    }

    #[test]
    fn test_sequential_ips() {
        let manager = FakeIpManager::new(10);
        let ip1 = manager.allocate("a.com").unwrap();
        let ip2 = manager.allocate("b.com").unwrap();
        // 10.0.0.1, 10.0.0.2, ...
        let expected1 = Ipv4Addr::new(10, 0, 0, 1);
        let expected2 = Ipv4Addr::new(10, 0, 0, 2);
        assert_eq!(ip1, expected1);
        assert_eq!(ip2, expected2);
    }
}
