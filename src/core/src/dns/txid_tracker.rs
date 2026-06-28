//! [OF5] DNS TXID Tracker — трекинг DNS Transaction ID для выбора стратегии.
//!
//! ## Принцип
//! DPI часто перехватывает DNS-запросы и возвращает поддельные ответы
//! с изменённым TXID или IP-адресом. TXID Tracker отслеживает DNS
//! транзакции (запрос → ответ) и детектирует:
//!
//! 1. **TXID Mismatch** — ответ с неверным TXID (DPI подмена)
//! 2. **Fake IP** — ответ с IP из пула DPI (известные DPI-IP)
//! 3. **Fast Response** — подозрительно быстрый ответ (< 10ms, DPI inject)
//!
//! На основе анализа TXID Tracker рекомендует стратегию desync:
//! - `Direct` — DPI не вмешивается, можно gentle стратегию
//! - `DnsMitigation` — DPI подменяет DNS → нужен DoH/DoT или TCP DNS
//! - `HeavyDesync` — глубокий DPI → нужны агрессивные техники
//!
//! ## Источник
//! offveil [OF5] — DNS TXID Tracker
//!
//! ## Пример
//! ```rust
//! use freedpi_core::dns::txid_tracker::{TxidTracker, DnsThreatLevel};
//!
//! let mut tracker = TxidTracker::default();
//!
//! // Регистрируем DNS запрос
//! let id = tracker.register_query("example.com", 0x1234);
//!
//! // Проверяем ответ
//! let threat = tracker.analyze_response(id, 0x1234, "1.2.3.4", 50);
//! assert_eq!(threat, DnsThreatLevel::Clean); // OK
//!
//! // DPI подмена TXID
//! let threat = tracker.analyze_response(id, 0x5678, "1.2.3.4", 50);
//! assert_eq!(threat, DnsThreatLevel::TxidMismatch);
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::debug;

/// Уровень угрозы DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsThreatLevel {
    /// DNS чистый — DPI не вмешивается
    Clean,
    /// Несовпадение TXID — DPI подменяет ответы
    TxidMismatch,
    /// IP из пула DPI — известный подменный адрес
    FakeIpDetected,
    /// Подозрительно быстрый ответ (< 10ms)
    FastResponse,
    /// Множественные проблемы — глубокий DPI
    HeavyDpi,
}

impl DnsThreatLevel {
    /// Человекочитаемое имя.
    pub fn name(&self) -> &'static str {
        match self {
            DnsThreatLevel::Clean => "Clean",
            DnsThreatLevel::TxidMismatch => "TXID Mismatch",
            DnsThreatLevel::FakeIpDetected => "Fake IP Detected",
            DnsThreatLevel::FastResponse => "Fast Response",
            DnsThreatLevel::HeavyDpi => "Heavy DPI",
        }
    }

    /// Нужно ли применять desync для этого уровня.
    pub fn requires_desync(&self) -> bool {
        matches!(
            self,
            DnsThreatLevel::TxidMismatch
                | DnsThreatLevel::FakeIpDetected
                | DnsThreatLevel::HeavyDpi
        )
    }

    /// Рекомендуемая агрессивность (0-4).
    pub fn recommended_aggression(&self) -> u8 {
        match self {
            DnsThreatLevel::Clean => 0,
            DnsThreatLevel::FastResponse => 1,
            DnsThreatLevel::TxidMismatch => 2,
            DnsThreatLevel::FakeIpDetected => 3,
            DnsThreatLevel::HeavyDpi => 4,
        }
    }
}

/// Статус DNS запроса.
#[derive(Debug, Clone)]
struct QueryState {
    /// Домен запроса
    domain: String,
    /// TXID запроса
    txid: u16,
    /// Время запроса
    timestamp: Instant,
    /// Получен ли ответ
    answered: bool,
    /// Ответный TXID
    response_txid: Option<u16>,
    /// Ответный IP
    response_ip: Option<IpAddr>,
    /// Время ответа (ms)
    response_time_ms: Option<u64>,
}

impl QueryState {
    fn new(domain: String, txid: u16) -> Self {
        Self {
            domain,
            txid,
            timestamp: Instant::now(),
            answered: false,
            response_txid: None,
            response_ip: None,
            response_time_ms: None,
        }
    }
}

/// DNS TXID Tracker.
#[derive(Debug, Clone)]
pub struct TxidTracker {
    /// Активные запросы (key = query_id)
    queries: HashMap<u64, QueryState>,
    /// Счётчик TXID mismatch'ей
    txid_mismatches: u64,
    /// Счётчик fake IP детекций
    fake_ip_detections: u64,
    /// Счётчик быстрых ответов
    fast_responses: u64,
    /// Известные DPI IP-адреса (пулы подмены)
    known_dpi_ips: Vec<IpAddr>,
    /// Известные DPI CIDR-блоки
    known_dpi_cidrs: Vec<ipnet::Ipv4Net>,
    /// Максимальное количество отслеживаемых запросов
    max_queries: usize,
    /// Время жизни неотвеченного запроса
    query_ttl: Duration,
    /// Порог быстрого ответа (ms)
    fast_response_threshold_ms: u64,
    /// Следующий ID запроса
    next_id: u64,
}

impl TxidTracker {
    /// Создаёт новый TXID Tracker.
    ///
    /// # Arguments
    /// * `known_dpi_ips` — список известных IP-адресов DPI
    /// * `max_queries` — максимум одновременных запросов (default: 1000)
    pub fn new(known_dpi_ips: Vec<IpAddr>, max_queries: usize) -> Self {
        Self {
            queries: HashMap::new(),
            txid_mismatches: 0,
            fake_ip_detections: 0,
            fast_responses: 0,
            known_dpi_ips,
            known_dpi_cidrs: Vec::new(),
            max_queries,
            query_ttl: Duration::from_secs(5),
            fast_response_threshold_ms: 10,
            next_id: 1,
        }
    }

    /// Проверяет, является ли IP известным DPI.
    pub fn is_known_dpi_ip(&self, ip: &IpAddr) -> bool {
        if self.known_dpi_ips.contains(ip) {
            return true;
        }
        if let IpAddr::V4(v4) = ip {
            self.known_dpi_cidrs.iter().any(|cidr| cidr.contains(v4))
        } else {
            false
        }
    }

    /// Регистрирует новый DNS запрос.
    ///
    /// # Arguments
    /// * `domain` — доменное имя
    /// * `txid` — Transaction ID
    ///
    /// # Returns
    /// Уникальный ID запроса для последующего анализа ответа.
    pub fn register_query(&mut self, domain: &str, txid: u16) -> u64 {
        // Очищаем устаревшие
        self.clean_stale();

        // Проверяем лимит
        if self.queries.len() >= self.max_queries {
            // Удаляем самый старый
            if let Some(oldest_id) = self
                .queries
                .iter()
                .min_by_key(|(_, q)| q.timestamp)
                .map(|(&id, _)| id)
            {
                self.queries.remove(&oldest_id);
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        self.queries
            .insert(id, QueryState::new(domain.to_string(), txid));

        debug!("[OF5] DNS query #{}: {} TXID=0x{:04x}", id, domain, txid);

        id
    }

    /// Анализирует DNS ответ.
    ///
    /// # Arguments
    /// * `query_id` — ID от `register_query`
    /// * `response_txid` — TXID из ответа
    /// * `response_ip` — IP адрес из ответа (строка)
    /// * `response_time_ms` — время получения ответа (ms)
    ///
    /// # Returns
    /// `DnsThreatLevel` — уровень угрозы
    pub fn analyze_response(
        &mut self,
        query_id: u64,
        response_txid: u16,
        response_ip: &str,
        response_time_ms: u64,
    ) -> DnsThreatLevel {
        // Step 1: Update query state (mutable borrow)
        let query_txid;
        let query_domain;
        match self.queries.get_mut(&query_id) {
            Some(query) => {
                query.answered = true;
                query.response_txid = Some(response_txid);
                query.response_time_ms = Some(response_time_ms);
                let parsed_ip: Option<IpAddr> = response_ip.parse().ok();
                query.response_ip = parsed_ip;
                query_txid = query.txid;
                query_domain = query.domain.clone();
            }
            None => {
                debug!("[OF5] Unknown query #{}", query_id);
                return DnsThreatLevel::Clean;
            }
        };
        // Mutable borrow of self.queries is dropped here

        let parsed_ip: Option<IpAddr> = response_ip.parse().ok();
        let mut threats = Vec::new();

        // 1. Проверка TXID
        if response_txid != query_txid {
            self.txid_mismatches += 1;
            threats.push(DnsThreatLevel::TxidMismatch);
            debug!(
                "[OF5] TXID mismatch for #{}: expected 0x{:04x}, got 0x{:04x}",
                query_id, query_txid, response_txid
            );
        }

        // 2. Проверка IP
        if let Some(ip) = parsed_ip {
            if self.is_known_dpi_ip(&ip) {
                self.fake_ip_detections += 1;
                threats.push(DnsThreatLevel::FakeIpDetected);
                debug!("[OF5] Fake IP detected for #{}: {}", query_id, ip);
            }
        }

        // 3. Проверка времени ответа
        if response_time_ms < self.fast_response_threshold_ms {
            self.fast_responses += 1;
            threats.push(DnsThreatLevel::FastResponse);
            debug!(
                "[OF5] Fast response for #{}: {}ms",
                query_id, response_time_ms
            );
        }

        // Определяем итоговый уровень
        let result = if threats.contains(&DnsThreatLevel::TxidMismatch)
            && threats.contains(&DnsThreatLevel::FakeIpDetected)
        {
            DnsThreatLevel::HeavyDpi
        } else if threats.contains(&DnsThreatLevel::FakeIpDetected) {
            DnsThreatLevel::FakeIpDetected
        } else if threats.contains(&DnsThreatLevel::TxidMismatch) {
            DnsThreatLevel::TxidMismatch
        } else if threats.contains(&DnsThreatLevel::FastResponse) {
            DnsThreatLevel::FastResponse
        } else {
            DnsThreatLevel::Clean
        };

        debug!(
            "[OF5] DNS response #{}: {} → {:?} ({})",
            query_id,
            query_domain,
            result,
            result.name()
        );

        result
    }

    /// Очищает устаревшие неотвеченные запросы.
    pub fn clean_stale(&mut self) {
        let cutoff = Instant::now() - self.query_ttl;
        let before = self.queries.len();
        self.queries
            .retain(|_, q| q.timestamp > cutoff || q.answered);
        let removed = before - self.queries.len();
        if removed > 0 {
            debug!("[OF5] Cleaned {} stale DNS queries", removed);
        }
    }

    /// Добавляет IP в список известных DPI адресов.
    pub fn add_dpi_ip(&mut self, ip: IpAddr) {
        if !self.known_dpi_ips.contains(&ip) {
            self.known_dpi_ips.push(ip);
            debug!("[OF5] Added DPI IP: {}", ip);
        }
    }

    /// Возвращает статистику.
    pub fn stats(&self) -> TxidTrackerStats {
        TxidTrackerStats {
            active_queries: self.queries.len(),
            txid_mismatches: self.txid_mismatches,
            fake_ip_detections: self.fake_ip_detections,
            fast_responses: self.fast_responses,
            total_tracked: self.next_id - 1,
        }
    }

    /// Сбрасывает всю статистику.
    pub fn reset(&mut self) {
        self.queries.clear();
        self.txid_mismatches = 0;
        self.fake_ip_detections = 0;
        self.fast_responses = 0;
        self.next_id = 1;
    }

    /// Количество активных запросов.
    pub fn active_count(&self) -> usize {
        self.queries.len()
    }
}

impl Default for TxidTracker {
    fn default() -> Self {
        // Известные DPI CIDR-блоки (пулы Роскомнадзора и др.)
        let known_dpi_cidrs: Vec<ipnet::Ipv4Net> = vec![
            "77.88.0.0/18".parse().unwrap(),  // TSPU (РКН) основной пул
            "93.184.0.0/16".parse().unwrap(), // ТСПУ расширенный
            "95.108.0.0/16".parse().unwrap(), // ТСПУ альтернативный
        ];

        Self {
            queries: HashMap::new(),
            txid_mismatches: 0,
            fake_ip_detections: 0,
            fast_responses: 0,
            known_dpi_ips: Vec::new(),
            known_dpi_cidrs,
            max_queries: 1000,
            query_ttl: Duration::from_secs(5),
            fast_response_threshold_ms: 10,
            next_id: 1,
        }
    }
}

/// Статистика TXID Tracker.
#[derive(Debug, Clone)]
pub struct TxidTrackerStats {
    /// Активных запросов
    pub active_queries: usize,
    /// Количество TXID mismatch'ей
    pub txid_mismatches: u64,
    /// Количество fake IP детекций
    pub fake_ip_detections: u64,
    /// Количество быстрых ответов
    pub fast_responses: u64,
    /// Всего отслежено запросов
    pub total_tracked: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_register_query() {
        let mut tracker = TxidTracker::default();
        let id = tracker.register_query("example.com", 0x1234);
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(id, 1);

        let id2 = tracker.register_query("test.org", 0x5678);
        assert_eq!(id2, 2);
        assert_eq!(tracker.active_count(), 2);
    }

    #[test]
    fn test_clean_response() {
        let mut tracker = TxidTracker::default();
        let id = tracker.register_query("example.com", 0x1234);

        let threat = tracker.analyze_response(id, 0x1234, "1.2.3.4", 50);
        assert_eq!(threat, DnsThreatLevel::Clean);
    }

    #[test]
    fn test_txid_mismatch() {
        let mut tracker = TxidTracker::default();
        let id = tracker.register_query("example.com", 0x1234);

        let threat = tracker.analyze_response(id, 0xDEAD, "1.2.3.4", 50);
        assert_eq!(threat, DnsThreatLevel::TxidMismatch);
    }

    #[test]
    fn test_fast_response() {
        let mut tracker = TxidTracker::default();
        let id = tracker.register_query("example.com", 0x1234);

        let threat = tracker.analyze_response(id, 0x1234, "1.2.3.4", 5);
        assert_eq!(threat, DnsThreatLevel::FastResponse);
    }

    #[test]
    fn test_fake_ip_detection() {
        let dpi_ip: IpAddr = Ipv4Addr::new(77, 88, 8, 8).into();
        let mut tracker = TxidTracker::new(vec![dpi_ip], 1000);

        let id = tracker.register_query("example.com", 0x1234);
        let threat = tracker.analyze_response(id, 0x1234, "77.88.8.8", 50);
        assert_eq!(threat, DnsThreatLevel::FakeIpDetected);
    }

    #[test]
    fn test_heavy_dpi() {
        let dpi_ip: IpAddr = Ipv4Addr::new(77, 88, 8, 8).into();
        let mut tracker = TxidTracker::new(vec![dpi_ip], 1000);

        let id = tracker.register_query("example.com", 0x1234);
        // TXID mismatch + Fake IP = HeavyDpi
        let threat = tracker.analyze_response(id, 0xDEAD, "77.88.8.8", 50);
        assert_eq!(threat, DnsThreatLevel::HeavyDpi);
    }

    #[test]
    fn test_unknown_query() {
        let mut tracker = TxidTracker::default();
        let threat = tracker.analyze_response(999, 0x1234, "1.2.3.4", 50);
        assert_eq!(threat, DnsThreatLevel::Clean);
    }

    #[test]
    fn test_stale_cleanup() {
        let mut tracker = TxidTracker::default();
        tracker.register_query("example.com", 0x1234);
        assert_eq!(tracker.active_count(), 1);

        // clean_stale удалит неотвеченные запросы старше query_ttl (5 sec)
        // В тесте мы не можем ждать, но можем проверить что clean_stale не падает
        tracker.clean_stale();
        // Запрос только что создан, не должен быть удалён
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_stats() {
        let mut tracker = TxidTracker::default();
        tracker.register_query("a.com", 0x1);
        tracker.register_query("b.com", 0x2);

        let stats = tracker.stats();
        assert_eq!(stats.active_queries, 2);
        assert_eq!(stats.total_tracked, 2);
    }

    #[test]
    fn test_reset() {
        let mut tracker = TxidTracker::default();
        tracker.register_query("example.com", 0x1234);
        tracker.reset();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.stats().total_tracked, 0);
    }

    #[test]
    fn test_add_dpi_ip() {
        let mut tracker = TxidTracker::default();
        assert_eq!(tracker.known_dpi_ips.len(), 0);

        tracker.add_dpi_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(tracker.known_dpi_ips.len(), 1);

        // Duplicate
        tracker.add_dpi_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(tracker.known_dpi_ips.len(), 1);
    }

    #[test]
    fn test_threat_level_methods() {
        assert!(!DnsThreatLevel::Clean.requires_desync());
        assert!(DnsThreatLevel::TxidMismatch.requires_desync());
        assert!(DnsThreatLevel::HeavyDpi.requires_desync());
        assert!(!DnsThreatLevel::FastResponse.requires_desync());

        assert_eq!(DnsThreatLevel::Clean.recommended_aggression(), 0);
        assert_eq!(DnsThreatLevel::HeavyDpi.recommended_aggression(), 4);
    }

    #[test]
    fn test_max_queries() {
        let mut tracker = TxidTracker::new(vec![], 3); // max 3
        tracker.register_query("a.com", 0x1);
        tracker.register_query("b.com", 0x2);
        tracker.register_query("c.com", 0x3);
        assert_eq!(tracker.active_count(), 3);

        // Превышаем лимит → старый удаляется
        tracker.register_query("d.com", 0x4);
        assert_eq!(tracker.active_count(), 3);
        // Статистика total_tracked растёт
        assert_eq!(tracker.stats().total_tracked, 4);
    }

    #[test]
    fn test_dns_threat_level_names() {
        assert_eq!(DnsThreatLevel::Clean.name(), "Clean");
        assert_eq!(DnsThreatLevel::TxidMismatch.name(), "TXID Mismatch");
        assert_eq!(DnsThreatLevel::HeavyDpi.name(), "Heavy DPI");
    }
}
