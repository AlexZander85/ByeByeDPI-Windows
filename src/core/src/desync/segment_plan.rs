//! Custom Segment Plans + Noise (из SpoofDPI).
//!
//! TOML-конфигурация точных позиций split в ClientHello
//! с параметром noise для jitter.
//!
//! ## Принцип
//! Каждый план описывает позицию split:
//! - `ref`: "head" (начало пакета) или "sni" (начало SNI)
//! - `offset`: смещение от ref в байтах
//! - `lazy`: флаг для disorder (TTL=1)
//! - `noise`: ±random(N) байт jitter к offset
//!
//! Планы сортируются по позиции независимо от порядка объявления.
//! Noise делает каждый пакет уникальным — DPI не может натренировать паттерн.

use serde::{Deserialize, Serialize};

/// Референсная точка для split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitRef {
    /// Начало пакета (байт 0).
    Head,
    /// Начало SNI extension в ClientHello.
    Sni,
}

/// Один сегмент-план: позиция split + флаги.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentPlan {
    /// Референсная точка.
    pub ref_point: SplitRef,
    /// Смещение от ref в байтах.
    pub offset: i32,
    /// Disorder: отправить сегмент с TTL=1 (умрёт у первого хопа, DPI видит).
    #[serde(default)]
    pub lazy: bool,
    /// Noise: ±random(noise) байт jitter к offset.
    /// Делает паттерн фрагментации непредсказуемым.
    #[serde(default)]
    pub noise: u32,
}

/// Набор сегмент-планов для одного соединения.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentPlanSet {
    /// Имя плана (для отладки / GUI).
    #[serde(default)]
    pub name: String,
    /// Планы split (будут отсортированы по позиции).
    pub plans: Vec<SegmentPlan>,
}

/// Рассчитанная позиция split (после применения noise).
#[derive(Debug, Clone, Copy)]
pub struct SplitPosition {
    /// Абсолютная позиция split в пакете.
    pub position: usize,
    /// Отправлять ли этот сегмент с TTL=1 (disorder).
    pub lazy: bool,
}

impl SegmentPlanSet {
    /// Вычисляет отсортированные позиции split для конкретного пакета.
    ///
    /// # Arguments
    /// * `sni_offset` — абсолютный байт начала SNI в ClientHello (0 если нет SNI).
    ///
    /// # Returns
    /// Вектор SplitPosition, отсортированный по position.
    pub fn resolve(&self, sni_offset: usize) -> Vec<SplitPosition> {
        let mut positions: Vec<SplitPosition> = self
            .plans
            .iter()
            .map(|plan| {
                let base = match plan.ref_point {
                    SplitRef::Head => 0usize,
                    SplitRef::Sni => sni_offset,
                };
                let noise = if plan.noise > 0 {
                    crate::desync::rand::random_range(0, plan.noise) as i32
                } else {
                    0
                };
                let raw = base as i32 + plan.offset + noise;
                let position = raw.max(0) as usize;
                SplitPosition {
                    position,
                    lazy: plan.lazy,
                }
            })
            .filter(|p| p.position > 0)
            .collect();

        positions.sort_by_key(|p| p.position);
        positions
    }
}

/// Парсит SegmentPlanSet из TOML строки.
pub fn parse_plan_set(toml_str: &str) -> anyhow::Result<SegmentPlanSet> {
    Ok(toml::from_str(toml_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_plan() {
        let plan = SegmentPlanSet {
            name: "test".into(),
            plans: vec![
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: 0,
                    lazy: false,
                    noise: 0,
                },
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: 5,
                    lazy: false,
                    noise: 0,
                },
            ],
        };
        let positions = plan.resolve(100);
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0].position, 100);
        assert_eq!(positions[1].position, 105);
    }

    #[test]
    fn test_plan_with_noise() {
        let plan = SegmentPlanSet {
            name: "noisy".into(),
            plans: vec![SegmentPlan {
                ref_point: SplitRef::Head,
                offset: 10,
                lazy: false,
                noise: 5,
            }],
        };
        // Position should be in range [10, 15] (10 + random(0..=5))
        let positions = plan.resolve(0);
        assert_eq!(positions.len(), 1);
        assert!(positions[0].position >= 10);
        assert!(positions[0].position <= 15);
    }

    #[test]
    fn test_lazy_flag() {
        let plan = SegmentPlanSet {
            name: "lazy-test".into(),
            plans: vec![SegmentPlan {
                ref_point: SplitRef::Sni,
                offset: 3,
                lazy: true,
                noise: 0,
            }],
        };
        let positions = plan.resolve(50);
        assert_eq!(positions[0].position, 53);
        assert!(positions[0].lazy);
    }

    #[test]
    fn test_sorted_by_position() {
        let plan = SegmentPlanSet {
            name: "sort-test".into(),
            plans: vec![
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: 10,
                    lazy: false,
                    noise: 0,
                },
                SegmentPlan {
                    ref_point: SplitRef::Head,
                    offset: 5,
                    lazy: false,
                    noise: 0,
                },
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: -3,
                    lazy: false,
                    noise: 0,
                },
            ],
        };
        let positions = plan.resolve(20);
        // Head+5=5, Sni-3=17, Sni+10=30
        assert_eq!(positions[0].position, 5);
        assert_eq!(positions[1].position, 17);
        assert_eq!(positions[2].position, 30);
    }

    #[test]
    fn test_toml_parse() {
        let toml = r#"
name = "aggressive"
[[plans]]
ref_point = "sni"
offset = 0
lazy = false
noise = 3

[[plans]]
ref_point = "sni"
offset = 10
lazy = true
noise = 5
"#;
        let plan_set = parse_plan_set(toml).unwrap();
        assert_eq!(plan_set.name, "aggressive");
        assert_eq!(plan_set.plans.len(), 2);
        assert!(plan_set.plans[1].lazy);
    }
}
