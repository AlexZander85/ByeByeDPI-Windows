//! Probe/Tune/Run — трёхфазный цикл выбора стратегии (из autodpi).
//!
//! ## Фазы
//! 1. **Probe** — пробуем стратегию на тестовых пакетах, собираем метрики
//! 2. **Tune** — на основе метрик корректируем параметры стратегии
//! 3. **Run** — применяем настроенную стратегию к реальному трафику
//!
//! Если после Tune фазы success_rate < порога — стратегия отключается
//! (авто-детекция неэффективных техник).
//!
//! ## Бизнес-логика
//! ```text
//! Register → Probe (min 100 pkt) → success ≥ 80%? → Yes → Run
//!                                    No  → Tune (15 sec) → success ≥ 90%? → Run
//!                                                           No → Disable
//! ```
//!
//! ## Источник
//! Адаптировано из [autodpi](https://github.com/brannondorsey/autodpi) —
//! Probe/Tune/Run трёхфазный lifecycle с auto-promotion.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

/// Метрики пробы стратегии.
#[derive(Debug, Clone)]
pub struct ProbeMetric {
    /// Сколько пакетов обработано
    pub packets_processed: u64,
    /// Сколько успешных модификаций
    pub modifications: u64,
    /// Сколько ошибок
    pub errors: u64,
    /// Среднее время применения (микросекунды)
    pub avg_apply_time_us: f64,
}

impl Default for ProbeMetric {
    fn default() -> Self {
        Self {
            packets_processed: 0,
            modifications: 0,
            errors: 0,
            avg_apply_time_us: 0.0,
        }
    }
}

/// Фаза жизненного цикла стратегии.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrategyPhase {
    /// Пробная фаза — сбор метрик
    Probe,
    /// Настройка параметров
    Tune,
    /// Применение к реальному трафику (активна)
    Run,
}

/// Состояние стратегии в цикле Probe/Tune/Run.
#[derive(Debug, Clone)]
pub struct StrategyState {
    /// ID стратегии
    pub strategy_id: u32,
    /// Текущая фаза
    pub phase: StrategyPhase,
    /// Метрики пробы
    pub metrics: ProbeMetric,
    /// Успешность (0.0 – 1.0)
    pub success_rate: f64,
    /// Время перехода в текущую фазу
    pub phase_started: Instant,
    /// Включена ли стратегия
    pub enabled: bool,
}

/// Конфигурация Probe/Tune/Run цикла.
#[derive(Debug, Clone)]
pub struct PtrConfig {
    /// Минимальное количество пакетов для Probe фазы
    pub probe_min_packets: u64,
    /// Порог успешности для перехода Probe → Run
    pub probe_success_threshold: f64,
    /// Порог успешности для перехода Tune → Run
    pub tune_success_threshold: f64,
    /// Максимальное время в Probe фазе
    pub probe_max_duration: Duration,
    /// Максимальное время в Tune фазе
    pub tune_max_duration: Duration,
}

impl Default for PtrConfig {
    fn default() -> Self {
        Self {
            probe_min_packets: 100,
            probe_success_threshold: 0.8,
            tune_success_threshold: 0.9,
            probe_max_duration: Duration::from_secs(30),
            tune_max_duration: Duration::from_secs(15),
        }
    }
}

/// Probe/Tune/Run Engine.
///
/// Управляет жизненным циклом всех стратегий:
/// - Регистрирует новые стратегии в Probe фазе
/// - Собирает метрики применения
/// - Автоматически продвигает Probe → Tune → Run
/// - Отключает неэффективные стратегии
///
/// # Пример
/// ```rust
/// use freedpi_core::adaptive::probe_tune_run::ProbeTuneRun;
///
/// let mut ptr = ProbeTuneRun::default();
/// ptr.register_strategy(1);
///
/// // Симулируем 100 успешных применений
/// for _ in 0..100 {
///     ptr.record_apply(1, true, 5.0);
/// }
///
/// // Должно перейти в Run фазу
/// assert!(ptr.tick(1));
/// assert_eq!(ptr.state(1).unwrap().phase,
///     freedpi_core::adaptive::probe_tune_run::StrategyPhase::Run);
/// ```
pub struct ProbeTuneRun {
    /// Состояния стратегий (key = strategy_id)
    states: HashMap<u32, StrategyState>,
    /// Конфигурация
    config: PtrConfig,
    /// Глобальный счётчик пакетов
    total_packets: AtomicU64,
}

impl ProbeTuneRun {
    /// Создаёт новый Probe/Tune/Run engine.
    ///
    /// # Arguments
    /// * `config` — конфигурация цикла (пороги, таймауты)
    pub fn new(config: PtrConfig) -> Self {
        Self {
            states: HashMap::new(),
            config,
            total_packets: AtomicU64::new(0),
        }
    }

    /// Регистрирует стратегию для цикла Probe/Tune/Run.
    ///
    /// Начинает с Probe фазы. Если стратегия уже зарегистрирована —
    /// сбрасывает её в Probe.
    ///
    /// # Arguments
    /// * `strategy_id` — ID стратегии
    pub fn register_strategy(&mut self, strategy_id: u32) {
        self.states.insert(
            strategy_id,
            StrategyState {
                strategy_id,
                phase: StrategyPhase::Probe,
                metrics: ProbeMetric::default(),
                success_rate: 0.0,
                phase_started: Instant::now(),
                enabled: true,
            },
        );
        debug!("PTR: Strategy {} registered, phase=Probe", strategy_id);
    }

    /// Записывает метрики применения стратегии.
    ///
    /// Вызывается после каждого применения стратегии к пакету.
    ///
    /// # Arguments
    /// * `strategy_id` — ID стратегии
    /// * `success` — успешно ли применена
    /// * `apply_time_us` — время применения в микросекундах
    pub fn record_apply(&mut self, strategy_id: u32, success: bool, apply_time_us: f64) {
        if let Some(state) = self.states.get_mut(&strategy_id) {
            state.metrics.packets_processed += 1;
            if success {
                state.metrics.modifications += 1;
            } else {
                state.metrics.errors += 1;
            }
            // Скользящее среднее времени применения
            let n = state.metrics.packets_processed as f64;
            state.metrics.avg_apply_time_us =
                state.metrics.avg_apply_time_us * (n - 1.0) / n + apply_time_us / n;
        }
        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Выполняет итерацию цикла для стратегии.
    ///
    /// Автоматически продвигает стратегию по фазам:
    /// Probe → Tune (если success_rate < порога) → Run (если success_rate ≥ порога)
    /// Probe → Run (если success_rate ≥ порога)
    ///
    /// # Arguments
    /// * `strategy_id` — ID стратегии
    ///
    /// # Returns
    /// `true` если стратегия перешла в Run фазу
    pub fn tick(&mut self, strategy_id: u32) -> bool {
        let state = match self.states.get_mut(&strategy_id) {
            Some(s) => s,
            None => return false,
        };

        if !state.enabled {
            return false;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(state.phase_started);

        match state.phase {
            StrategyPhase::Probe => {
                // Проверяем: достаточно ли пакетов или вышло время
                if state.metrics.packets_processed >= self.config.probe_min_packets
                    || elapsed >= self.config.probe_max_duration
                {
                    state.success_rate = if state.metrics.packets_processed > 0 {
                        state.metrics.modifications as f64
                            / state.metrics.packets_processed as f64
                    } else {
                        0.0
                    };

                    if state.success_rate >= self.config.probe_success_threshold {
                        state.phase = StrategyPhase::Run;
                        debug!(
                            "PTR: Strategy {} → Run (rate={:.2})",
                            strategy_id, state.success_rate
                        );
                        return true;
                    } else {
                        state.phase = StrategyPhase::Tune;
                        state.phase_started = now;
                        debug!(
                            "PTR: Strategy {} → Tune (rate={:.2})",
                            strategy_id, state.success_rate
                        );
                    }
                }
            }
            StrategyPhase::Tune => {
                if elapsed >= self.config.tune_max_duration {
                    state.success_rate = if state.metrics.packets_processed > 0 {
                        state.metrics.modifications as f64
                            / state.metrics.packets_processed as f64
                    } else {
                        0.0
                    };

                    if state.success_rate >= self.config.tune_success_threshold {
                        state.phase = StrategyPhase::Run;
                        debug!(
                            "PTR: Strategy {} → Run after tune (rate={:.2})",
                            strategy_id, state.success_rate
                        );
                        return true;
                    } else {
                        state.enabled = false;
                        debug!(
                            "PTR: Strategy {} disabled (rate={:.2})",
                            strategy_id, state.success_rate
                        );
                    }
                }
            }
            StrategyPhase::Run => {
                return true;
            }
        }
        false
    }

    /// Возвращает состояние стратегии.
    pub fn state(&self, strategy_id: u32) -> Option<&StrategyState> {
        self.states.get(&strategy_id)
    }

    /// Возвращает снапшот всех состояний (для API).
    pub fn snapshot(&self) -> Vec<StrategyState> {
        self.states.values().cloned().collect()
    }

    /// Общее количество обработанных пакетов.
    pub fn total_packets(&self) -> u64 {
        self.total_packets.load(Ordering::Relaxed)
    }

    /// Включает/отключает стратегию и сбрасывает в Probe фазу.
    ///
    /// # Arguments
    /// * `strategy_id` — ID стратегии
    /// * `enabled` — включить (true) или отключить (false)
    pub fn set_enabled(&mut self, strategy_id: u32, enabled: bool) {
        if let Some(state) = self.states.get_mut(&strategy_id) {
            state.enabled = enabled;
            if enabled {
                state.phase = StrategyPhase::Probe;
                state.phase_started = Instant::now();
                state.metrics = ProbeMetric::default();
            }
        }
    }

    /// Возвращает список активных (Run фаза) стратегий.
    pub fn active_strategies(&self) -> Vec<u32> {
        self.states
            .iter()
            .filter(|(_, s)| s.enabled && s.phase == StrategyPhase::Run)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Количество зарегистрированных стратегий.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Пуст ли engine.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

impl Default for ProbeTuneRun {
    fn default() -> Self {
        Self::new(PtrConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptr_creation() {
        let ptr = ProbeTuneRun::default();
        assert!(ptr.is_empty());
        assert_eq!(ptr.total_packets(), 0);
    }

    #[test]
    fn test_register_strategy() {
        let mut ptr = ProbeTuneRun::default();
        ptr.register_strategy(1);

        let state = ptr.state(1).unwrap();
        assert_eq!(state.phase, StrategyPhase::Probe);
        assert!(state.enabled);
    }

    #[test]
    fn test_probe_to_run() {
        let mut ptr = ProbeTuneRun::new(PtrConfig {
            probe_min_packets: 10,
            ..Default::default()
        });

        ptr.register_strategy(1);

        // Симулируем 10 успешных применений
        for _ in 0..10 {
            ptr.record_apply(1, true, 5.0);
        }

        // Должно перейти в Run
        assert!(ptr.tick(1));
        assert_eq!(ptr.state(1).unwrap().phase, StrategyPhase::Run);
    }

    #[test]
    fn test_probe_to_tune_on_low_success() {
        let mut ptr = ProbeTuneRun::new(PtrConfig {
            probe_min_packets: 10,
            probe_success_threshold: 0.8,
            ..Default::default()
        });

        ptr.register_strategy(1);

        // 5 успешных из 10 = 50% успешности < 80% порога
        for i in 0..10 {
            ptr.record_apply(1, i < 5, 5.0);
        }

        // Должно перейти в Tune (не в Run)
        assert!(!ptr.tick(1));
        assert_eq!(ptr.state(1).unwrap().phase, StrategyPhase::Tune);
    }

    #[test]
    fn test_disabled_after_tune_failure() {
        let mut ptr = ProbeTuneRun::new(PtrConfig {
            probe_min_packets: 5,
            probe_success_threshold: 0.8,
            tune_success_threshold: 0.9,
            probe_max_duration: Duration::from_secs(30),
            tune_max_duration: Duration::from_secs(0), // Немедленный выход из Tune
        });

        ptr.register_strategy(1);

        // 3 из 5 = 60% → Tune
        for i in 0..5 {
            ptr.record_apply(1, i < 3, 5.0);
        }
        assert!(!ptr.tick(1)); // → Tune
        assert_eq!(ptr.state(1).unwrap().phase, StrategyPhase::Tune);

        // Сразу выходим из Tune (tune_max_duration = 0)
        // 60% < 90% → disable
        assert!(!ptr.tick(1));
        assert!(!ptr.state(1).unwrap().enabled);
    }

    #[test]
    fn test_record_apply_metrics() {
        let mut ptr = ProbeTuneRun::default();
        ptr.register_strategy(1);

        ptr.record_apply(1, true, 10.0);
        ptr.record_apply(1, true, 20.0);
        ptr.record_apply(1, false, 5.0);

        let state = ptr.state(1).unwrap();
        assert_eq!(state.metrics.packets_processed, 3);
        assert_eq!(state.metrics.modifications, 2);
        assert_eq!(state.metrics.errors, 1);
        assert!(state.metrics.avg_apply_time_us > 0.0);
    }

    #[test]
    fn test_active_strategies() {
        let mut ptr = ProbeTuneRun::new(PtrConfig {
            probe_min_packets: 5,
            ..Default::default()
        });

        ptr.register_strategy(1);
        ptr.register_strategy(2);

        // Strategy 1: 100% success → Run
        for _ in 0..5 {
            ptr.record_apply(1, true, 1.0);
        }
        ptr.tick(1);

        let active = ptr.active_strategies();
        assert!(active.contains(&1));
        assert!(!active.contains(&2)); // ещё не прошла Probe
    }

    #[test]
    fn test_set_enabled() {
        let mut ptr = ProbeTuneRun::default();
        ptr.register_strategy(1);

        ptr.set_enabled(1, false);
        assert!(!ptr.state(1).unwrap().enabled);

        ptr.set_enabled(1, true);
        assert!(ptr.state(1).unwrap().enabled);
        assert_eq!(ptr.state(1).unwrap().phase, StrategyPhase::Probe);
    }

    #[test]
    fn test_snapshot() {
        let mut ptr = ProbeTuneRun::default();
        ptr.register_strategy(1);
        ptr.register_strategy(2);

        let snap = ptr.snapshot();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn test_total_packets() {
        let mut ptr = ProbeTuneRun::default();
        ptr.register_strategy(1);
        ptr.register_strategy(2);

        ptr.record_apply(1, true, 1.0);
        ptr.record_apply(2, true, 2.0);
        ptr.record_apply(1, false, 3.0);

        assert_eq!(ptr.total_packets(), 3);
    }

    #[test]
    fn test_probe_timeout() {
        let mut ptr = ProbeTuneRun::new(PtrConfig {
            probe_min_packets: 1000, // high threshold (not met)
            probe_success_threshold: 0.5,
            probe_max_duration: Duration::from_millis(0), // zero = instant timeout
            ..Default::default()
        });

        ptr.register_strategy(1);
        // Минимальное количество пакетов не набрано,
        // но probe_max_duration = 0 → timeout → вычисляем rate
        ptr.record_apply(1, true, 1.0);

        // 100% success rate при 1 пакете → ≥ 0.5 → Run
        assert!(ptr.tick(1));
        assert_eq!(ptr.state(1).unwrap().phase, StrategyPhase::Run);
    }
}
