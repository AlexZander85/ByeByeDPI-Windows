//! Strategy Trait + Registry — trait-based архитектура DPI-стратегий.
//!
//! ## Компоненты
//! - `Strategy` trait — интерфейс для всех DPI-bypass техник
//! - `StrategyRegistry` — глобальный singleton реестр стратегий
//! - `StrategyCtx` — контекст применения стратегии
//! - `StrategyResult` — результат применения
//! - `StrategyCategory` — категоризация стратегий
//!
//! ## Использование
//! ```rust,no_run
//! use freedpi_core::adaptive::strategy::*;
//! use freedpi_core::conntrack::Conntrack;
//! use anyhow::Result;
//! use std::net::Ipv4Addr;
//! use std::sync::Arc;
//! # struct MyStrategy;
//! # impl Strategy for MyStrategy {
//! #     fn id(&self) -> u32 { 42 }
//! #     fn name(&self) -> &'static str { "example" }
//! #     fn description(&self) -> &'static str { "Example strategy" }
//! #     fn category(&self) -> StrategyCategory { StrategyCategory::General }
//! #     fn apply(&self, _pkt: &mut [u8], _ctx: &StrategyCtx) -> Result<StrategyResult> { Ok(StrategyResult::Passthrough) }
//! #     fn applicable(&self, _pkt: &[u8]) -> bool { true }
//! # }
//!
//! // Регистрация стратегии
//! StrategyRegistry::global().register(Box::new(MyStrategy));
//!
//! // Применение
//! let mut packet = vec![0x45, 0x00, 0x00, 0x14];
//! let ctx = StrategyCtx::new(
//!     Ipv4Addr::new(8, 8, 8, 8), 443, vec![], packet.clone(),
//!     Arc::new(Conntrack::default()),
//! );
//! let result = StrategyRegistry::global().apply(42, &mut packet, &ctx).unwrap();
//! ```
//!
//! ## Источник
//! Адаптировано из [autodpi](https://github.com/brannondorsey/autodpi).

use crate::conntrack::Conntrack;
use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::OnceLock;

/// Категория стратегии.
///
/// Определяет, к какому типу трафика применяется стратегия.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StrategyCategory {
    /// TCP-level десинхронизация (split, disorder, MSS)
    Tcp,
    /// TLS-level (SNI спуфинг, TLS record fragment)
    Tls,
    /// QUIC (Initial spoof, version downgrade)
    Quic,
    /// DNS (fake query, padding)
    Dns,
    /// HTTP (host-space, title-case)
    Http,
    /// IP-level (fragmentation, TTL)
    Ip,
    /// Обфускация (ChaCha20, XOR, padding)
    Obfs,
    /// Общая стратегия
    General,
}

impl StrategyCategory {
    /// Описание категории для CLI/API.
    pub fn description(&self) -> &'static str {
        match self {
            StrategyCategory::Tcp => "TCP-level desync (split, disorder, MSS)",
            StrategyCategory::Tls => "TLS-level (SNI spoof, record fragment, JA3 mimic)",
            StrategyCategory::Quic => "QUIC (Initial spoof, version downgrade, padding)",
            StrategyCategory::Dns => "DNS (fake query, padding, TCP fallback)",
            StrategyCategory::Http => "HTTP (host-space, title-case, method mutation)",
            StrategyCategory::Ip => "IP-level (fragmentation, TTL jitter, DSCP)",
            StrategyCategory::Obfs => "Obfuscation (ChaCha20, XOR, padding)",
            StrategyCategory::General => "General-purpose strategy",
        }
    }
}

/// Контекст для применения стратегии.
///
/// Содержит всю информацию, необходимую стратегии для принятия решения:
/// - Адреса и порты
/// - TLS ClientHello (для спуфинга)
/// - Оригинальный пакет
/// - Connection tracking (для SEQ/ACK)
///
/// # Note
/// В P0.2 будет добавлено поле `hop_tab: Arc<HopTab>` после реализации
/// HopTab (auto-TTL cache из dpibreak).
#[derive(Debug, Clone)]
pub struct StrategyCtx {
    /// IP назначения
    pub dst_ip: Ipv4Addr,
    /// Порт назначения
    pub dst_port: u16,
    /// TLS ClientHello (если применимо)
    pub client_hello: Vec<u8>,
    /// Оригинальный пакет (полный IP пакет для модификации)
    pub packet: Vec<u8>,
    /// Connection tracking
    pub conntrack: Arc<Conntrack>,
}

impl StrategyCtx {
    /// Создаёт новый контекст стратегии.
    pub fn new(
        dst_ip: Ipv4Addr,
        dst_port: u16,
        client_hello: Vec<u8>,
        packet: Vec<u8>,
        conntrack: Arc<Conntrack>,
    ) -> Self {
        Self {
            dst_ip,
            dst_port,
            client_hello,
            packet,
            conntrack,
        }
    }
}

/// Результат применения стратегии к пакету.
#[derive(Debug, Clone)]
pub enum StrategyResult {
    /// Пакет модифицирован — использовать этот вариант для отправки
    Modified(Vec<u8>),
    /// Пакет следует дропнуть (не отправлять серверу)
    Drop,
    /// Пропустить — пакет не требует модификации (forward as-is)
    Passthrough,
}

/// Trait для всех DPI-bypass стратегий.
///
/// Каждая техника DPI-обхода реализует этот trait и регистрируется
/// в глобальном `StrategyRegistry`. Engine вызывает стратегии по ID.
///
/// # Requirements
/// - `Send + Sync` — стратегии могут вызываться из любого потока
/// - `'static` — стратегии живут всё время работы engine
///
/// # Пример
/// ```rust
/// use freedpi_core::adaptive::strategy::*;
/// use anyhow::Result;
///
/// struct MySplitStrategy;
///
/// impl Strategy for MySplitStrategy {
///     fn id(&self) -> u32 { 1 }
///     fn name(&self) -> &'static str { "tcp_split" }
///     fn description(&self) -> &'static str { "TCP Split desync" }
///     fn category(&self) -> StrategyCategory { StrategyCategory::Tcp }
///
///     fn apply(&self, pkt: &mut [u8], ctx: &StrategyCtx) -> Result<StrategyResult> {
///         // ... implement desync ...
///         Ok(StrategyResult::Passthrough)
///     }
///
///     fn applicable(&self, pkt: &[u8]) -> bool {
///         pkt.len() > 40 // TCP SYN or data
///     }
/// }
/// ```
pub trait Strategy: Send + Sync + 'static {
    /// Уникальный ID стратегии.
    fn id(&self) -> u32;

    /// Короткое имя стратегии (для CLI/API).
    fn name(&self) -> &'static str;

    /// Описание стратегии (для документации).
    fn description(&self) -> &'static str;

    /// Категория стратегии (для группировки).
    fn category(&self) -> StrategyCategory;

    /// Применить стратегию к пакету.
    ///
    /// # Arguments
    /// * `pkt` — mutable reference к пакету для модификации in-place
    /// * `ctx` — контекст с информацией о соединении
    ///
    /// # Returns
    /// * `Modified(packet)` — пакет модифицирован
    /// * `Drop` — пакет нужно дропнуть
    /// * `Passthrough` — пакет не требует модификации
    fn apply(&self, pkt: &mut [u8], ctx: &StrategyCtx) -> Result<StrategyResult>;

    /// Проверка применимости (activation filter).
    ///
    /// Возвращает `true`, если стратегия может быть применена к пакету.
    /// Позволяет быстро отфильтровать неподходящие стратегии без
    /// полного применения.
    fn applicable(&self, pkt: &[u8]) -> bool;
}

/// Глобальный реестр всех стратегий (singleton).
///
/// Thread-safe, используется через `StrategyRegistry::global()`.
/// Стратегии регистрируются при старте engine.
///
/// # Пример
/// ```rust,no_run
/// use freedpi_core::adaptive::strategy::*;
/// use freedpi_core::conntrack::Conntrack;
/// use anyhow::Result;
/// use std::net::Ipv4Addr;
/// use std::sync::Arc;
/// # struct TcpSplitStrategy;
/// # impl Strategy for TcpSplitStrategy {
/// #     fn id(&self) -> u32 { 1 }
/// #     fn name(&self) -> &'static str { "tcp_split" }
/// #     fn description(&self) -> &'static str { "" }
/// #     fn category(&self) -> StrategyCategory { StrategyCategory::Tcp }
/// #     fn apply(&self, _pkt: &mut [u8], _ctx: &StrategyCtx) -> Result<StrategyResult> { Ok(StrategyResult::Passthrough) }
/// #     fn applicable(&self, _pkt: &[u8]) -> bool { true }
/// # }
///
/// // Регистрация
/// StrategyRegistry::global().register(Box::new(TcpSplitStrategy));
///
/// // Применение по ID
/// let mut packet = vec![0x45, 0x00, 0x00, 0x14];
/// let ctx = StrategyCtx::new(
///     Ipv4Addr::new(8, 8, 8, 8), 443, vec![], packet.clone(),
///     Arc::new(Conntrack::default()),
/// );
/// let result = StrategyRegistry::global()
///     .apply(1, &mut packet, &ctx).unwrap();
/// ```
pub struct StrategyRegistry {
    strategies: DashMap<u32, Box<dyn Strategy>>,
}

impl StrategyRegistry {
    /// Создаёт новый локальный реестр (для тестов).
    pub fn new_local() -> Self {
        StrategyRegistry {
            strategies: DashMap::new(),
        }
    }

    /// Возвращает глобальный singleton экземпляр.
    ///
    /// Thread-safe инициализация через `OnceLock`.
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<StrategyRegistry> = OnceLock::new();
        INSTANCE.get_or_init(|| StrategyRegistry {
            strategies: DashMap::new(),
        })
    }

    /// Регистрирует новую стратегию в реестре.
    ///
    /// Если стратегия с таким ID уже существует — будет перезаписана.
    ///
    /// # Panics
    /// Не паникует. Стратегия с дублирующимся ID перезаписывает старую.
    pub fn register(&self, strategy: Box<dyn Strategy>) {
        let id = strategy.id();
        self.strategies.insert(id, strategy);
    }

    /// Возвращает стратегию по ID.
    pub fn get(&self, id: u32) -> Option<dashmap::mapref::one::Ref<'_, u32, Box<dyn Strategy>>> {
        self.strategies.get(&id)
    }

    /// Применяет стратегию по ID к пакету.
    ///
    /// # Errors
    /// Возвращает ошибку, если стратегия с указанным ID не найдена.
    pub fn apply(&self, id: u32, pkt: &mut [u8], ctx: &StrategyCtx) -> Result<StrategyResult> {
        self.strategies
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("Strategy {} not found", id))
            .map(|strategy| strategy.apply(pkt, ctx))?
    }

    /// Проверяет, существует ли стратегия с указанным ID.
    pub fn contains(&self, id: u32) -> bool {
        self.strategies.contains_key(&id)
    }

    /// Количество зарегистрированных стратегий.
    pub fn len(&self) -> usize {
        self.strategies.len()
    }

    /// Пуст ли реестр.
    pub fn is_empty(&self) -> bool {
        self.strategies.is_empty()
    }

    /// Возвращает список ID всех зарегистрированных стратегий.
    pub fn list_ids(&self) -> Vec<u32> {
        self.strategies.iter().map(|entry| *entry.key()).collect()
    }

    /// Возвращает список имён всех зарегистрированных стратегий.
    pub fn list_names(&self) -> Vec<(u32, &'static str)> {
        self.strategies
            .iter()
            .map(|entry| (*entry.key(), entry.value().name()))
            .collect()
    }

    /// Возвращает статистику по категориям.
    pub fn category_stats(&self) -> std::collections::HashMap<StrategyCategory, usize> {
        let mut stats = std::collections::HashMap::new();
        for entry in self.strategies.iter() {
            let cat = entry.value().category();
            *stats.entry(cat).or_insert(0) += 1;
        }
        stats
    }

    /// Удаляет стратегию из реестра.
    pub fn unregister(&self, id: u32) -> Option<Box<dyn Strategy>> {
        self.strategies.remove(&id).map(|(_, v)| v)
    }

    /// Очищает реестр (для тестов).
    pub fn clear(&self) {
        self.strategies.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::Conntrack;

    /// Тестовая стратегия для unit-тестов.
    struct TestStrategy {
        id: u32,
        name: &'static str,
    }

    impl TestStrategy {
        fn new(id: u32, name: &'static str) -> Self {
            Self { id, name }
        }
    }

    impl Strategy for TestStrategy {
        fn id(&self) -> u32 {
            self.id
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn description(&self) -> &'static str {
            "Test strategy for unit tests"
        }

        fn category(&self) -> StrategyCategory {
            StrategyCategory::General
        }

        fn apply(&self, _pkt: &mut [u8], _ctx: &StrategyCtx) -> Result<StrategyResult> {
            Ok(StrategyResult::Passthrough)
        }

        fn applicable(&self, _pkt: &[u8]) -> bool {
            true
        }
    }

    #[test]
    fn test_registry_global_singleton() {
        let r1 = StrategyRegistry::global();
        let r2 = StrategyRegistry::global();
        assert!(std::ptr::eq(r1, r2));
    }

    #[test]
    fn test_register_and_get() {
        let registry = StrategyRegistry::new_local();

        let strategy = TestStrategy::new(1, "test_strategy");
        registry.register(Box::new(strategy));

        assert!(registry.contains(1));
        assert!(!registry.contains(2));

        let retrieved = registry.get(1).unwrap();
        assert_eq!(retrieved.name(), "test_strategy");
        assert_eq!(retrieved.id(), 1);
    }

    #[test]
    fn test_apply_existing_strategy() {
        let registry = StrategyRegistry::new_local();
        registry.register(Box::new(TestStrategy::new(1, "test")));

        let mut packet = vec![0x45, 0x00, 0x00, 0x14];
        let ctx = StrategyCtx::new(
            Ipv4Addr::new(8, 8, 8, 8),
            443,
            vec![],
            packet.clone(),
            Arc::new(Conntrack::default()),
        );

        let result = registry.apply(1, &mut packet, &ctx).unwrap();
        match result {
            StrategyResult::Passthrough => {} // expected
            _ => panic!("Expected Passthrough"),
        }
    }

    #[test]
    fn test_apply_missing_strategy() {
        let registry = StrategyRegistry::new_local();

        let mut packet = vec![0x45, 0x00, 0x00, 0x14];
        let ctx = StrategyCtx::new(
            Ipv4Addr::new(8, 8, 8, 8),
            443,
            vec![],
            packet.clone(),
            Arc::new(Conntrack::default()),
        );

        let result = registry.apply(999, &mut packet, &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_applicable_filter() {
        struct ApplicableTest(bool);

        impl Strategy for ApplicableTest {
            fn id(&self) -> u32 { 2 }
            fn name(&self) -> &'static str { "applicable_test" }
            fn description(&self) -> &'static str { "Test applicable filter" }
            fn category(&self) -> StrategyCategory { StrategyCategory::General }

            fn apply(&self, _pkt: &mut [u8], _ctx: &StrategyCtx) -> Result<StrategyResult> {
                Ok(StrategyResult::Modified(vec![1, 2, 3]))
            }

            fn applicable(&self, pkt: &[u8]) -> bool {
                self.0 && pkt.len() > 5
            }
        }

        assert!(!ApplicableTest(false).applicable(&[0u8; 3]));
        assert!(!ApplicableTest(true).applicable(&[0u8; 3]));  // too short
        assert!(ApplicableTest(true).applicable(&[0u8; 10]));  // ok
    }

    #[test]
    fn test_list_ids_and_names() {
        let registry = StrategyRegistry::new_local();
        registry.register(Box::new(TestStrategy::new(10, "first")));
        registry.register(Box::new(TestStrategy::new(20, "second")));

        let ids = registry.list_ids();
        assert!(ids.contains(&10));
        assert!(ids.contains(&20));

        let names = registry.list_names();
        assert!(names.contains(&(10, "first")));
        assert!(names.contains(&(20, "second")));
    }

    #[test]
    fn test_category_stats() {
        struct CatStrategy {
            id: u32,
            cat: StrategyCategory,
        }
        impl Strategy for CatStrategy {
            fn id(&self) -> u32 { self.id }
            fn name(&self) -> &'static str { "cat_test" }
            fn description(&self) -> &'static str { "" }
            fn category(&self) -> StrategyCategory { self.cat }
            fn apply(&self, _pkt: &mut [u8], _ctx: &StrategyCtx) -> Result<StrategyResult> {
                Ok(StrategyResult::Passthrough)
            }
            fn applicable(&self, _pkt: &[u8]) -> bool { true }
        }

        let registry = StrategyRegistry::new_local();
        registry.register(Box::new(CatStrategy { id: 1, cat: StrategyCategory::Tcp }));
        registry.register(Box::new(CatStrategy { id: 2, cat: StrategyCategory::Tcp }));
        registry.register(Box::new(CatStrategy { id: 3, cat: StrategyCategory::Tls }));

        let stats = registry.category_stats();
        assert_eq!(stats.get(&StrategyCategory::Tcp), Some(&2));
        assert_eq!(stats.get(&StrategyCategory::Tls), Some(&1));
        assert_eq!(stats.get(&StrategyCategory::Quic), None);
    }

    #[test]
    fn test_unregister() {
        let registry = StrategyRegistry::new_local();
        registry.register(Box::new(TestStrategy::new(1, "remove_me")));
        assert!(registry.contains(1));

        let removed = registry.unregister(1);
        assert!(removed.is_some());
        assert!(!registry.contains(1));

        // Повторное удаление
        assert!(registry.unregister(1).is_none());
    }

    #[test]
    fn test_strategy_ctx_creation() {
        let conntrack = Arc::new(Conntrack::default());
        let ctx = StrategyCtx::new(
            Ipv4Addr::new(142, 250, 185, 46), // google.com
            443,
            vec![0x16, 0x03, 0x01, 0x00, 0x02, 0x01], // minimal CH
            vec![0x45, 0x00, 0x00, 0x3c], // minimal IP
            conntrack.clone(),
        );

        assert_eq!(ctx.dst_port, 443);
        assert_eq!(ctx.dst_ip, Ipv4Addr::new(142, 250, 185, 46));
        assert_eq!(ctx.client_hello.len(), 6);
    }

    #[test]
    fn test_strategy_category_description() {
        assert!(StrategyCategory::Tcp.description().contains("TCP"));
        assert!(StrategyCategory::Tls.description().contains("TLS"));
        assert!(StrategyCategory::General.description().contains("General"));
    }
}
