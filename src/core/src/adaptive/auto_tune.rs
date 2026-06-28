//! Auto-Tune — автоматическая подстройка параметров стратегий.
//!
//! ## Принцип
//! На основе результатов применения стратегий (success/fail, latency)
//! автоматически подстраиваем параметры: split_size, ttl_offset,
//! split_count, inject_delay.
//!
//! ## Источник
//! Адаптировано из [autodpi](https://github.com/brannondorsey/autodpi) — Auto-tune.

use std::collections::HashMap;
use tracing::debug;

/// Параметры для auto-tune.
#[derive(Debug, Clone, Default)]
pub struct TuneParams {
    pub split_size: Option<usize>,
    pub split_count: Option<usize>,
    pub fake_ttl_offset: Option<u8>,
    pub max_seg_size: Option<usize>,
}

/// Метрики стратегии для auto-tune.
#[derive(Debug, Clone, Default)]
pub struct StrategyMetrics {
    pub success_count: u64,
    pub fail_count: u64,
    pub total_latency_us: u64,
    pub avg_latency_us: u64,
    pub current_params: TuneParams,
}

impl StrategyMetrics {
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.fail_count;
        if total == 0 {
            return 1.0;
        }
        self.success_count as f64 / total as f64
    }

    pub fn record_success(&mut self, latency_us: u64) {
        self.success_count += 1;
        self.total_latency_us += latency_us;
        self.avg_latency_us = self.total_latency_us / self.success_count;
    }

    pub fn record_failure(&mut self) {
        self.fail_count += 1;
    }
}

/// Auto-Tune engine.
///
/// ## Алгоритм
/// 1. Собираем метрики по каждой стратегии
/// 2. Если success_rate < 0.5 — пробуем изменить параметры
/// 3. Если success_rate > 0.8 и latency низкое — оставляем как есть
/// 4. Эвристики:
///    - Мало success → увеличить split_count
///    - Высокий latency → уменьшить split_count
///    - Все fail → сменить технику
pub struct AutoTune {
    metrics: HashMap<String, StrategyMetrics>,
    /// Минимальный success rate для активации tune
    tune_threshold: f64,
    /// Максимальное количество попыток tune
    #[allow(dead_code)]
    max_tune_attempts: u32,
}

impl AutoTune {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            tune_threshold: 0.5,
            max_tune_attempts: 3,
        }
    }

    /// Записывает результат применения стратегии.
    pub fn record(&mut self, strategy_name: &str, success: bool, latency_us: u64) {
        let metrics = self.metrics.entry(strategy_name.to_string()).or_default();

        if success {
            metrics.record_success(latency_us);
        } else {
            metrics.record_failure();
        }
    }

    /// Получает рекомендованные параметры для стратегии.
    pub fn recommend(&self, strategy_name: &str) -> TuneParams {
        let metrics = match self.metrics.get(strategy_name) {
            Some(m) => m,
            None => return TuneParams::default(),
        };

        let mut params = TuneParams::default();

        if metrics.success_rate() < self.tune_threshold {
            // Низкий success rate — пробуем агрессивный split
            params.split_size = Some(1);
            params.split_count = Some(5);
            params.fake_ttl_offset = Some(2);
            debug!(
                "AutoTune: {} low success ({:.1}%) → aggressive split",
                strategy_name,
                metrics.success_rate() * 100.0
            );
        } else if metrics.avg_latency_us > 50_000 {
            // Высокий latency — упрощаем
            params.split_count = Some(2);
            params.fake_ttl_offset = Some(1);
            debug!(
                "AutoTune: {} high latency ({}us) → simplified",
                strategy_name, metrics.avg_latency_us
            );
        } else if metrics.success_rate() > 0.8 {
            // Хороший результат — минимальный overhead
            params.split_size = Some(1);
            params.split_count = Some(2);
            debug!(
                "AutoTune: {} good ({:.1}%) → minimal",
                strategy_name,
                metrics.success_rate() * 100.0
            );
        }

        params
    }

    /// Проверяет, нужно ли сменить стратегию.
    pub fn should_escalate(&self, strategy_name: &str) -> bool {
        match self.metrics.get(strategy_name) {
            Some(m) => m.fail_count >= 5 && m.success_rate() < 0.2,
            None => false,
        }
    }

    /// Получает метрики стратегии.
    pub fn get_metrics(&self, strategy_name: &str) -> Option<&StrategyMetrics> {
        self.metrics.get(strategy_name)
    }

    /// Все метрики.
    pub fn all_metrics(&self) -> &HashMap<String, StrategyMetrics> {
        &self.metrics
    }

    /// Сброс метрик.
    pub fn reset(&mut self) {
        self.metrics.clear();
    }
}

impl Default for AutoTune {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_tune_record() {
        let mut tune = AutoTune::new();
        tune.record("FakeSni", true, 1000);
        tune.record("FakeSni", true, 1500);
        tune.record("FakeSni", false, 0);

        let m = tune.get_metrics("FakeSni").unwrap();
        assert_eq!(m.success_count, 2);
        assert_eq!(m.fail_count, 1);
        assert!((m.success_rate() - 0.667).abs() < 0.01);
    }

    #[test]
    fn test_auto_tune_recommend_low_success() {
        let mut tune = AutoTune::new();
        for _ in 0..3 {
            tune.record("Test", false, 0);
        }
        let params = tune.recommend("Test");
        assert_eq!(params.split_size, Some(1));
        assert_eq!(params.split_count, Some(5));
    }

    #[test]
    fn test_auto_tune_should_escalate() {
        let mut tune = AutoTune::new();
        for _ in 0..6 {
            tune.record("Test", false, 0);
        }
        assert!(tune.should_escalate("Test"));
    }

    #[test]
    fn test_auto_tune_no_escalate_good() {
        let mut tune = AutoTune::new();
        for _ in 0..10 {
            tune.record("Test", true, 500);
        }
        assert!(!tune.should_escalate("Test"));
    }
}
