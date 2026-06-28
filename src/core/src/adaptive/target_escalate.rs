//! [OF2] Target Escalation — адаптивное повышение агрессивности при RST.
//!
//! ## Принцип
//! Когда DPI инжектирует RST-пакеты, это сигнал, что текущая стратегия
//! desync недостаточно эффективна. TargetEscalation отслеживает RST rate
//! для каждого соединения и повышает уровень агрессивности при превышении
//! порога.
//!
//! ## Уровни агрессивности
//! 0. **L0: Gentle** — MultiSplit, минимальное воздействие
//! 1. **L1: Moderate** — FakeDataSplit, TcpSeg, WinSize
//! 2. **L2: Aggressive** — FakeSni, BadChecksum, TtlManipulation
//! 3. **L3: Extreme** — FragOverlap, IpFragPrimitives, OobInjection
//! 4. **L4: Panic** — все техники сразу, SynHide, bad checksum everywhere
//!
//! ## Параметры
//! - `rst_threshold`: количество RST за период для эскалации (default: 3)
//! - `window_sec`: окно наблюдения в секундах (default: 10)
//! - `cooldown_sec`: время до деэскалации после стабилизации (default: 30)
//!
//! ## Источник
//! offveil [OF2] — Adaptive Escalation
//!
//! ## Пример
//! ```rust
//! use freedpi_core::adaptive::target_escalate::{TargetEscalation, EscalationLevel};
//!
//! let mut esc = TargetEscalation::default();
//! assert_eq!(esc.current_level(), EscalationLevel::L0Gentle);
//!
//! // Симулируем RST-атаку
//! for _ in 0..5 {
//!     esc.record_rst("1.2.3.4:443");
//! }
//! assert!(esc.should_escalate("1.2.3.4:443"));
//! esc.do_escalate("1.2.3.4:443");
//! assert_eq!(esc.current_level(), EscalationLevel::L1Moderate);
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::debug;

/// Уровень агрессивности стратегии.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EscalationLevel {
    /// L0: Gentle — MultiSplit, минимальное воздействие
    L0Gentle = 0,
    /// L1: Moderate — FakeDataSplit, TcpSeg, WinSize
    L1Moderate = 1,
    /// L2: Aggressive — FakeSni, BadChecksum, TtlManipulation
    L2Aggressive = 2,
    /// L3: Extreme — FragOverlap, IpFragPrimitives, OobInjection
    L3Extreme = 3,
    /// L4: Panic — все техники сразу
    L4Panic = 4,
}

impl EscalationLevel {
    /// Следующий уровень (выше).
    pub fn escalate(self) -> Self {
        match self {
            EscalationLevel::L0Gentle => EscalationLevel::L1Moderate,
            EscalationLevel::L1Moderate => EscalationLevel::L2Aggressive,
            EscalationLevel::L2Aggressive => EscalationLevel::L3Extreme,
            EscalationLevel::L3Extreme | EscalationLevel::L4Panic => EscalationLevel::L4Panic,
        }
    }

    /// Предыдущий уровень (ниже).
    pub fn deescalate(self) -> Self {
        match self {
            EscalationLevel::L0Gentle | EscalationLevel::L1Moderate => EscalationLevel::L0Gentle,
            EscalationLevel::L2Aggressive => EscalationLevel::L1Moderate,
            EscalationLevel::L3Extreme => EscalationLevel::L2Aggressive,
            EscalationLevel::L4Panic => EscalationLevel::L3Extreme,
        }
    }

    /// Человекочитаемое название.
    pub fn name(&self) -> &'static str {
        match self {
            EscalationLevel::L0Gentle => "Gentle",
            EscalationLevel::L1Moderate => "Moderate",
            EscalationLevel::L2Aggressive => "Aggressive",
            EscalationLevel::L3Extreme => "Extreme",
            EscalationLevel::L4Panic => "Panic",
        }
    }
}

/// Статистика RST для одного таргета (IP:порт).
#[derive(Debug, Clone)]
struct RstStats {
    /// Моменты RST (timestamps)
    timestamps: Vec<Instant>,
    /// Текущий уровень эскалации
    level: EscalationLevel,
    /// Время последней эскалации
    last_escalated: Option<Instant>,
    /// Общее количество RST (за всё время)
    total_rst: u64,
}

impl RstStats {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            level: EscalationLevel::L0Gentle,
            last_escalated: None,
            total_rst: 0,
        }
    }

    /// Добавляет RST и обрезает устаревшие записи.
    fn record(&mut self, now: Instant, window: Duration) {
        self.timestamps.push(now);
        self.total_rst += 1;
        // Оставляем только записи в пределах окна
        let cutoff = now - window;
        self.timestamps.retain(|&t| t > cutoff);
    }

    /// Количество RST в текущем окне.
    fn count_in_window(&self) -> usize {
        self.timestamps.len()
    }
}

/// TargetEscalation — адаптивная эскалация стратегий.
///
/// ## Потокобезопасность
/// Не thread-safe (использует `&mut self`). Предназначен для использования
/// внутри одного потока (ProcessingPipeline).
#[derive(Debug, Clone)]
pub struct TargetEscalation {
    /// Статистика по таргетам (key = "ip:port")
    targets: HashMap<String, RstStats>,
    /// Порог RST для эскалации
    rst_threshold: usize,
    /// Окно наблюдения
    window: Duration,
    /// Время до деэскалации
    cooldown: Duration,
    /// Глобальный уровень эскалации (максимум по всем таргетам)
    global_level: EscalationLevel,
}

impl TargetEscalation {
    /// Создаёт новый TargetEscalation с указанными параметрами.
    pub fn new(rst_threshold: usize, window_sec: u64, cooldown_sec: u64) -> Self {
        Self {
            targets: HashMap::new(),
            rst_threshold,
            window: Duration::from_secs(window_sec),
            cooldown: Duration::from_secs(cooldown_sec),
            global_level: EscalationLevel::L0Gentle,
        }
    }

    /// Записывает RST для указанного таргета.
    ///
    /// # Arguments
    /// * `target` — строка "ip:port"
    pub fn record_rst(&mut self, target: &str) {
        let now = Instant::now();
        let stats = self.targets.entry(target.to_string()).or_insert_with(|| {
            debug!("[OF2] TargetEscalation: new target {}", target);
            RstStats::new()
        });
        stats.record(now, self.window);

        debug!(
            "[OF2] RST for {}: {} in window (total: {})",
            target,
            stats.count_in_window(),
            stats.total_rst
        );
    }

    /// Проверяет, нужно ли эскалировать для указанного таргета.
    ///
    /// Возвращает `true`, если количество RST за окно ≥ порога.
    pub fn should_escalate(&self, target: &str) -> bool {
        self.targets
            .get(target)
            .map(|s| s.count_in_window() >= self.rst_threshold)
            .unwrap_or(false)
    }

    /// Выполняет эскалацию для указанного таргета.
    ///
    /// Увеличивает уровень на 1, сбрасывает счётчик RST.
    pub fn do_escalate(&mut self, target: &str) -> EscalationLevel {
        let now = Instant::now();

        // Убеждаемся, что таргет существует
        if !self.targets.contains_key(target) {
            self.targets.insert(target.to_string(), RstStats::new());
        }

        let stats = self.targets.get_mut(target).unwrap();
        let old_level = stats.level;
        stats.level = stats.level.escalate();
        stats.last_escalated = Some(now);
        stats.timestamps.clear(); // Сбрасываем RST счётчик после эскалации

        if stats.level != old_level {
            debug!(
                "[OF2] Target {}: escalated {} → {}",
                target,
                old_level.name(),
                stats.level.name()
            );
        }

        let new_level = stats.level;

        // Обновляем глобальный уровень
        self.update_global_level();

        new_level
    }

    /// Проверяет, нужно ли деэскалировать (cooldown истёк).
    pub fn check_deescalate(&mut self, target: &str) -> bool {
        let now = Instant::now();
        let should_de = self.targets.get(target).is_some_and(|s| {
            if let Some(last_esc) = s.last_escalated {
                // Деэскалируем если: прошло > cooldown И RST за окно < порога
                now - last_esc > self.cooldown && s.count_in_window() < self.rst_threshold / 2
            } else {
                false
            }
        });

        if should_de {
            if let Some(stats) = self.targets.get_mut(target) {
                let old_level = stats.level;
                stats.level = stats.level.deescalate();
                if stats.level != old_level {
                    debug!(
                        "[OF2] Target {}: deescalated {} → {}",
                        target,
                        old_level.name(),
                        stats.level.name()
                    );
                }
            }
            self.update_global_level();
        }

        should_de
    }

    /// Возвращает текущий уровень для таргета.
    pub fn target_level(&self, target: &str) -> EscalationLevel {
        self.targets
            .get(target)
            .map(|s| s.level)
            .unwrap_or(EscalationLevel::L0Gentle)
    }

    /// Возвращает глобальный (максимальный) уровень эскалации.
    pub fn current_level(&self) -> EscalationLevel {
        self.global_level
    }

    /// Обновляет глобальный уровень (максимум по всем таргетам).
    fn update_global_level(&mut self) {
        let max_level = self
            .targets
            .values()
            .map(|s| s.level)
            .max()
            .unwrap_or(EscalationLevel::L0Gentle);
        self.global_level = max_level;
    }

    /// Очищает устаревшие записи (таргеты без RST дольше 2× cooldown).
    pub fn clean_stale(&mut self) {
        let now = Instant::now();
        let stale_cutoff = now - self.cooldown * 2;
        self.targets.retain(|target, stats| {
            let has_recent = stats.timestamps.iter().any(|&t| t > stale_cutoff);
            if !has_recent {
                debug!("[OF2] Removing stale target: {}", target);
            }
            has_recent
        });
        self.update_global_level();
    }

    /// Количество отслеживаемых таргетов.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Общее количество RST по всем таргетам.
    pub fn total_rst(&self) -> u64 {
        self.targets.values().map(|s| s.total_rst).sum()
    }
}

impl Default for TargetEscalation {
    fn default() -> Self {
        Self::new(3, 10, 30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escalation_level_order() {
        assert!(EscalationLevel::L0Gentle < EscalationLevel::L1Moderate);
        assert!(EscalationLevel::L1Moderate < EscalationLevel::L2Aggressive);
        assert!(EscalationLevel::L2Aggressive < EscalationLevel::L3Extreme);
        assert!(EscalationLevel::L3Extreme < EscalationLevel::L4Panic);
    }

    #[test]
    fn test_escalation_cycle() {
        let mut level = EscalationLevel::L0Gentle;
        assert_eq!(level.name(), "Gentle");

        level = level.escalate();
        assert_eq!(level, EscalationLevel::L1Moderate);
        assert_eq!(level.name(), "Moderate");

        level = level.escalate();
        assert_eq!(level, EscalationLevel::L2Aggressive);

        level = level.escalate();
        assert_eq!(level, EscalationLevel::L3Extreme);

        level = level.escalate();
        assert_eq!(level, EscalationLevel::L4Panic);

        level = level.escalate();
        assert_eq!(level, EscalationLevel::L4Panic); // Не поднимается выше
    }

    #[test]
    fn test_deescalation_cycle() {
        let mut level = EscalationLevel::L4Panic;
        level = level.deescalate();
        assert_eq!(level, EscalationLevel::L3Extreme);

        level = level.deescalate();
        assert_eq!(level, EscalationLevel::L2Aggressive);

        level = level.deescalate();
        assert_eq!(level, EscalationLevel::L1Moderate);

        level = level.deescalate();
        assert_eq!(level, EscalationLevel::L0Gentle);

        level = level.deescalate();
        assert_eq!(level, EscalationLevel::L0Gentle); // Не опускается ниже
    }

    #[test]
    fn test_target_escalation_default() {
        let esc = TargetEscalation::default();
        assert_eq!(esc.current_level(), EscalationLevel::L0Gentle);
        assert_eq!(esc.target_count(), 0);
        assert_eq!(esc.total_rst(), 0);
    }

    #[test]
    fn test_record_rst() {
        let mut esc = TargetEscalation::new(3, 10, 30);
        assert!(!esc.should_escalate("1.2.3.4:443"));

        esc.record_rst("1.2.3.4:443");
        esc.record_rst("1.2.3.4:443");
        assert!(!esc.should_escalate("1.2.3.4:443")); // Need 3

        esc.record_rst("1.2.3.4:443");
        assert!(esc.should_escalate("1.2.3.4:443"));

        assert_eq!(esc.total_rst(), 3);
    }

    #[test]
    fn test_do_escalate() {
        let mut esc = TargetEscalation::new(3, 10, 30);
        for _ in 0..5 {
            esc.record_rst("1.2.3.4:443");
        }

        let level = esc.do_escalate("1.2.3.4:443");
        assert_eq!(level, EscalationLevel::L1Moderate);
        assert_eq!(esc.current_level(), EscalationLevel::L1Moderate);

        // После эскалации счётчик сброшен
        assert!(!esc.should_escalate("1.2.3.4:443"));

        // Снова RST → ещё эскалация
        for _ in 0..5 {
            esc.record_rst("1.2.3.4:443");
        }
        let level = esc.do_escalate("1.2.3.4:443");
        assert_eq!(level, EscalationLevel::L2Aggressive);
    }

    #[test]
    fn test_multiple_targets() {
        let mut esc = TargetEscalation::new(2, 10, 30);

        esc.record_rst("a.com:443");
        esc.record_rst("b.com:443");

        esc.record_rst("a.com:443");
        assert!(esc.should_escalate("a.com:443"));
        assert!(!esc.should_escalate("b.com:443")); // still 1

        esc.do_escalate("a.com:443");
        assert_eq!(esc.target_level("a.com:443"), EscalationLevel::L1Moderate);
        assert_eq!(esc.target_level("b.com:443"), EscalationLevel::L0Gentle);

        // Глобальный уровень = максимум
        assert_eq!(esc.current_level(), EscalationLevel::L1Moderate);
    }

    #[test]
    fn test_target_level_unknown() {
        let esc = TargetEscalation::default();
        assert_eq!(esc.target_level("unknown:443"), EscalationLevel::L0Gentle);
    }

    #[test]
    fn test_clean_stale_no_removal_for_recent() {
        // Recent entries should not be removed by clean_stale
        let mut esc = TargetEscalation::new(3, 10, 60);
        esc.record_rst("recent:443");
        assert_eq!(esc.target_count(), 1);

        esc.clean_stale();
        // Entry was just created, should be kept
        assert_eq!(esc.target_count(), 1);
    }

    #[test]
    fn test_escalation_global_level() {
        let mut esc = TargetEscalation::new(1, 10, 30); // threshold = 1

        esc.record_rst("a.com:443");
        esc.do_escalate("a.com:443"); // L1
        assert_eq!(esc.current_level(), EscalationLevel::L1Moderate);

        esc.record_rst("b.com:443");
        esc.do_escalate("b.com:443"); // L1
        assert_eq!(esc.current_level(), EscalationLevel::L1Moderate);

        // a.com ещё раз → L2
        esc.record_rst("a.com:443");
        esc.do_escalate("a.com:443"); // L2
        assert_eq!(esc.current_level(), EscalationLevel::L2Aggressive);
    }
}
