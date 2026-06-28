//! Adaptive Strategy Engine — trait-based архитектура стратегий.
//!
//! Реализует паттерн Strategy (GoF) для DPI-bypass техник:
//! - `strategy` — Strategy trait + глобальный реестр стратегий (из autodpi)
//! - `hop_tab` — auto-TTL cache для fake ClientHello (из dpibreak)
//! - `ch_gen` — TLS ClientHello Generator (из sni-spoofing-rust)
//! - `seq_spoof` — SEQ Number Spoofing (из sni-spoofing-rust)
//!
//! ## Дизайн
//! Каждая DPI-bypass техника реализует trait `Strategy` и регистрируется
//! в глобальном `StrategyRegistry`. Engine применяет стратегии по ID
//! через единый интерфейс.
//!
//! ## Преимущества trait-based подхода
//! - **Open/Closed**: новые стратегии добавляются без изменения существующего кода
//! - **Composition**: стратегии могут быть скомпонованы в цепочки (DesyncGroup)
//! - **Testability**: каждая стратегия тестируется изолированно
//! - **Serialization**: стратегии можно конфигурировать через JSON/TOML
//!
//! ## P0.2 модули
//! - `hop_tab` — кэш TTL для auto-TTL fake пакетов (не требует HopTab)
//! - `ch_gen` — TLS ClientHello генератор без дампа
//! - `seq_spoof` — SEQ Number Spoofing: fake CH с SEQ вне окна DPI
//!
//! ## Источник
//! Архитектура адаптирована из [autodpi](https://github.com/brannondorsey/autodpi),
//! [dpibreak](https://github.com/hufrea/dpibreak),
//! [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust).

pub mod auto_tune;
pub mod ch_gen;
pub mod fallback;
pub mod hop_tab;
pub mod persist;
pub mod probe_tune_run;
pub mod seq_spoof;
pub mod strategy;
pub mod target_escalate;
