//! Infrastructure — Sentinel, Event Tagging, IPC, Firewall, Named Pipes, WinDivert Driver.
//!
//! Вспомогательные модули ядра:
//! - `sentinel` — файловый триггер аварийной остановки (из DPIReaper)
//! - `event_tag` — UUID-тегирование injected пакетов (из OpenLogi)
//! - `named_pipe` — защищённый IPC для AI агента (Windows Named Pipes)
//! - `windivert_driver` — установка и управление WinDivert driver (из sing-box/offveil)

pub mod event_tag;
pub mod named_pipe;
pub mod sentinel;
pub mod windivert_driver;
