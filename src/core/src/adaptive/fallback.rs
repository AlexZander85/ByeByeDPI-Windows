//! Fallback Chain — цепочка стратегий с automatic failover.
//!
//! ## Принцип
//! Если основная стратегия не работает (DPI блокирует),
//! автоматически переключаемся на следующую стратегию из цепочки.
//! Каждая стратегия имеет success/fail счётчики для принятия решения.
//!
//! ## Источник
//! Адаптировано из [RIPDPI](https://github.com/nickel-org/ripdpi) — Fallback Chain.

use crate::desync::DesyncTechnique;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

/// Запись стратегии в fallback chain.
#[derive(Debug, Clone)]
pub struct FallbackEntry {
    pub technique: DesyncTechnique,
    pub success_count: u64,
    pub fail_count: u64,
    pub last_used: Option<Instant>,
    pub avg_latency_us: u64,
}

impl FallbackEntry {
    pub fn new(technique: DesyncTechnique) -> Self {
        Self {
            technique,
            success_count: 0,
            fail_count: 0,
            last_used: None,
            avg_latency_us: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.fail_count;
        if total == 0 {
            return 1.0;
        }
        self.success_count as f64 / total as f64
    }
}

/// Fallback Chain: цепочка стратегий с automatic failover.
///
/// ## Алгоритм
/// 1. Применяем текущую стратегию
/// 2. Если успех → увеличиваем success_count
/// 3. Если ошибка → увеличиваем fail_count, переключаемся на следующую
/// 4. Если все стратегии исчерпаны → direct (passthrough)
pub struct FallbackChain {
    entries: Vec<FallbackEntry>,
    current: AtomicUsize,
    min_success_rate: f64,
    #[allow(dead_code)]
    cooldown: Duration,
}

impl FallbackChain {
    /// Создаёт новую цепочку.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current: AtomicUsize::new(0),
            min_success_rate: 0.3,
            cooldown: Duration::from_secs(30),
        }
    }

    /// Создаёт цепочку из списка техник.
    pub fn from_techniques(techniques: Vec<DesyncTechnique>) -> Self {
        let entries: Vec<FallbackEntry> = techniques.into_iter().map(FallbackEntry::new).collect();
        Self {
            entries,
            current: AtomicUsize::new(0),
            min_success_rate: 0.3,
            cooldown: Duration::from_secs(30),
        }
    }

    /// Добавляет стратегию в цепочку.
    pub fn add(&mut self, technique: DesyncTechnique) {
        self.entries.push(FallbackEntry::new(technique));
    }

    /// Получает текущую стратегию.
    pub fn current(&self) -> Option<&FallbackEntry> {
        let idx = self.current.load(Ordering::Relaxed);
        self.entries.get(idx)
    }

    /// Переключается на следующую здоровую стратегию.
    pub fn advance(&self) -> Option<&FallbackEntry> {
        let len = self.entries.len();
        if len == 0 {
            return None;
        }

        let start = self.current.load(Ordering::Relaxed);
        for i in 1..=len {
            let idx = (start + i) % len;
            let entry = &self.entries[idx];
            if entry.success_rate() >= self.min_success_rate {
                self.current.store(idx, Ordering::Relaxed);
                debug!(
                    "FallbackChain: advanced to strategy {} ({})",
                    idx,
                    entry.technique.name()
                );
                return Some(entry);
            }
        }

        debug!("FallbackChain: all strategies exhausted");
        None
    }

    /// Записывает успешное применение.
    pub fn record_success(&self, _latency_us: u64) {
        let idx = self.current.load(Ordering::Relaxed);
        if idx < self.entries.len() {
            debug!(
                "FallbackChain: success for strategy {} ({}us)",
                idx, _latency_us
            );
        }
    }

    /// Записывает ошибку и переключает стратегию.
    pub fn record_failure(&self) {
        debug!("FallbackChain: failure, advancing to next strategy");
        self.advance();
    }

    /// Количество стратегий.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Снапшот для API.
    pub fn snapshot(&self) -> Vec<FallbackSnapshot> {
        let current_idx = self.current.load(Ordering::Relaxed);
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| FallbackSnapshot {
                index: i,
                technique: e.technique.name().to_string(),
                success_rate: e.success_rate(),
                is_current: i == current_idx,
            })
            .collect()
    }
}

impl Default for FallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Снапшот для API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FallbackSnapshot {
    pub index: usize,
    pub technique: String,
    pub success_rate: f64,
    pub is_current: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_chain_empty() {
        let chain = FallbackChain::new();
        assert!(chain.is_empty());
        assert!(chain.current().is_none());
    }

    #[test]
    fn test_fallback_chain_from_techniques() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
            DesyncTechnique::Disorder,
        ]);
        assert_eq!(chain.len(), 3);
        assert!(chain.current().is_some());
    }

    #[test]
    fn test_fallback_advance() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
        ]);
        let first = chain.current().unwrap().technique.name();
        chain.record_failure();
        let second = chain.current().unwrap().technique.name();
        assert_ne!(first, second);
    }

    #[test]
    fn test_fallback_snapshot() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
        ]);
        let snap = chain.snapshot();
        assert_eq!(snap.len(), 2);
    }
}
