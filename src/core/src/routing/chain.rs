//! Proxy Chain Manager — интеллектуальная цепочка egress-провайдеров с failover.
//!
//! ## Алгоритм
//! 1. `build_attempts(target)` — строит упорядоченные попытки из цепочки
//! 2. `execute(target)` — sequential failover: пробует каждый hop
//! 3. При успехе → возвращает результат
//! 4. При ошибке → маркирует bad route, пробует следующий hop
//! 5. Если все hops неудачны → возвращает последнюю ошибку
//!
//! ## Bad Route Cache
//! При ошибке/таймауте hop'а, маршрут `"domain|ip"` кэшируется в DashMap
//! с TTL. Это предотвращает повторные попытки к заведомо недоступным
//! прокси для одного и того же домена/IP.
//!
//! ## Пример
//! ```rust
//! use freedpi_core::routing::chain::EgressChain;
//! use freedpi_core::routing::EgressHop;
//!
//! let chain = EgressChain::new(vec![
//!     EgressHop::direct(),
//!     EgressHop::socks5("127.0.0.1", 1370),
//! ]);
//! // execute требует async контекст и реальное соединение
//! ```
//!
//! ## Источник
//! Адаптировано из [Nova](https://github.com/patrykkalinowski/nova) — proxy chain.

use crate::routing::EgressHop;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::debug;

/// Ошибки выполнения egress chain.
#[derive(Error, Debug)]
pub enum ChainError {
    /// Все hop'ы в цепочке неудачны
    #[error("All hops failed: {0}")]
    AllHopsFailed(String),

    /// Hop вернул ошибку
    #[error("Hop '{hop}' failed: {reason}")]
    HopFailed {
        hop: String,
        reason: String,
    },

    /// Таймаут hop'а
    #[error("Hop '{hop}' timed out after {timeout:?}")]
    HopTimeout {
        hop: String,
        timeout: Duration,
    },

    /// Невалидная конфигурация
    #[error("Chain configuration error: {0}")]
    ConfigError(String),
}

/// Результат выполнения hop'а.
#[derive(Debug, Clone)]
pub struct HopResult {
    /// Индекс hop'а в цепочке (0-based)
    pub hop_index: usize,
    /// Тип egress (для диагностики)
    pub hop_type: String,
    /// Время выполнения hop'а
    pub duration: Duration,
}

/// Попытка соединения — один hop из цепочки.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// Индекс hop'а в цепочке
    pub hop_index: usize,
    /// Egress hop для попытки
    pub hop: EgressHop,
    /// Таймаут на эту попытку
    pub timeout: Duration,
}

/// Egress Chain — sequential failover цепочка прокси.
///
/// ## Failover логика
/// 1. Пробует первый hop
/// 2. Если ошибка/таймаут → маркирует bad route → пробует следующий
/// 3. Если все hop'ы провалились → `ChainError::AllHopsFailed`
///
/// ## Bad Route Cache
/// При ошибке hop'а для конкретного домена/IP, маршрут кэшируется на TTL.
/// Повторные запросы к тому же домену/IP пропустят этот hop.
pub struct EgressChain {
    /// Цепочка egress hop'ов (порядок определяет failover)
    hops: Vec<EgressHop>,
    /// Bad route cache (TTL-based)
    bad_routes: DashMap<String, Instant>,
    /// TTL для bad route записей
    bad_route_ttl: Duration,
}

impl EgressChain {
    /// Создаёт новую цепочку из hop'ов.
    pub fn new(hops: Vec<EgressHop>) -> Self {
        Self {
            hops,
            bad_routes: DashMap::new(),
            bad_route_ttl: Duration::from_secs(300), // 5 минут
        }
    }

    /// Создаёт цепочку с кастомным bad route TTL.
    pub fn with_bad_route_ttl(hops: Vec<EgressHop>, ttl: Duration) -> Self {
        Self {
            hops,
            bad_routes: DashMap::new(),
            bad_route_ttl: ttl,
        }
    }

    /// Строит список Attempt из цепочки, исключая bad route.
    ///
    /// Bad route hop'ы пропускаются (не включаются в попытки).
    /// Если все hop'ы bad → возвращается fallback (просто direct).
    pub fn build_attempts(&self, target: &str) -> Vec<Attempt> {
        let now = Instant::now();
        let mut attempts: Vec<Attempt> = Vec::new();

        for (index, hop) in self.hops.iter().enumerate() {
            let key = format!("{}|{}|{}", target, index, hop.egress);

            // Пропускаем bad route
            if let Some(expires) = self.bad_routes.get(&key) {
                if *expires > now {
                    debug!("Skipping bad route: {}", key);
                    continue;
                }
                // TTL истёк — удаляем
                drop(expires);
                self.bad_routes.remove(&key);
            }

            attempts.push(Attempt {
                hop_index: index,
                hop: hop.clone(),
                timeout: hop.timeout,
            });
        }

        // Если все hop'ы bad → fallback direct
        if attempts.is_empty() {
            debug!("All hops are bad routes, adding fallback direct hop");
            attempts.push(Attempt {
                hop_index: 0,
                hop: EgressHop::direct(),
                timeout: Duration::from_secs(5),
            });
        }

        attempts
    }

    /// Помечает hop как bad route для target.
    ///
    /// Вызывается при ошибке/таймауте hop'а.
    pub fn mark_bad(&self, target: &str, hop_index: usize) {
        if hop_index < self.hops.len() {
            let key = format!(
                "{}|{}|{}",
                target, hop_index, self.hops[hop_index].egress
            );
            let expires = Instant::now() + self.bad_route_ttl;
            self.bad_routes.insert(key, expires);
            debug!(
                "Marked bad route: {} hop={} (TTL: {:?})",
                target, hop_index, self.bad_route_ttl
            );
        }
    }

    /// Очищает bad route кэш.
    pub fn clear_bad_routes(&self) {
        self.bad_routes.clear();
        debug!("Chain bad route cache cleared");
    }

    /// Возвращает количество bad route записей.
    pub fn bad_routes_len(&self) -> usize {
        self.bad_routes.len()
    }

    /// Возвращает количество hop'ов в цепочке.
    pub fn hops_len(&self) -> usize {
        self.hops.len()
    }

    /// Возвращает hop'ы цепочки (для инспекции).
    pub fn hops(&self) -> &[EgressHop] {
        &self.hops
    }
}

impl Default for EgressChain {
    fn default() -> Self {
        Self::new(vec![EgressHop::direct()])
    }
}
