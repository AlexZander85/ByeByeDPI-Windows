//! Geo-Routing Engine + Proxy Chain Manager (из [Nova](https://github.com/patrykkalinowski/nova))
//!
//! ## Компоненты
//! - `geo::GeoRouter` — классификация трафика по региону домена/IP (Russia→desync, Europe→Opera VPN, US→user proxy)
//! - `chain::EgressChain` — интеллектуальная цепочка egress-провайдеров с sequential failover
//! - `health::HealthChecker` — фоновый мониторинг прокси (SOCKS5 handshake, HTTP CONNECT)
//! - `opera::OperaVpnProvider` — интеграция бесплатных Opera VPN SOCKS5 прокси (без регистрации)
//! - `detect::GeoBlockDetector` — DPI vs Geo-block детекция (RST/timeout → DPI, HTTP 403/451 → Geo-block)
//!
//! ## Маршрутизация
//! 1. `GeoRouter.resolve(domain, ip)` → `RouteDecision`
//! 2. `RouteDecision.egress_chain` → список `EgressHop` для sequential failover
//! 3. `EgressChain.execute(target)` → sequential failover с per-hop таймаутом
//!
//! ## Схема egress цепочек
//! | Регион | Chain |
//! |--------|-------|
//! | Russia | Direct(desync) → SOCKS5:127.0.0.1:1370 |
//! | Europe | Opera VPN → Direct(desync) |
//! | UnitedStates | UserProxy → Direct(desync) |
//! | Global / Excluded | Direct(desync) |
//!
//! ## Источник
//! Адаптировано из [Nova](https://github.com/patrykkalinowski/nova) и [sing-box](https://github.com/SagerNet/sing-box).

pub mod chain;
pub mod detect;
pub mod domain_trie;
pub mod geo;
pub mod health;
pub mod opera;

#[cfg(test)]
mod tests;

use std::fmt;
use std::time::Duration;

/// Географический регион для маршрутизации.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GeoRegion {
    /// Россия — desync локально (DPI глубокий, нужны агрессивные техники)
    Russia,
    /// Европа — Opera VPN для geo-spoof (DPI слабый, достаточно базового desync)
    Europe,
    /// США — пользовательский прокси (пользователь явно указал)
    UnitedStates,
    /// Глобальный регион — direct desync (нет региональных ограничений)
    Global,
    /// Исключённый трафик — direct без модификаций (банки, госуслуги)
    Excluded,
}

impl GeoRegion {
    /// Человекочитаемое имя региона.
    pub fn name(&self) -> &'static str {
        match self {
            GeoRegion::Russia => "Russia",
            GeoRegion::Europe => "Europe",
            GeoRegion::UnitedStates => "UnitedStates",
            GeoRegion::Global => "Global",
            GeoRegion::Excluded => "Excluded",
        }
    }
}

/// Тип egress-провайдера для исходящего соединения.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Egress {
    /// Прямое соединение (с DPI desync или без)
    Direct { desync: bool },
    /// SOCKS5 прокси
    Socks5 { host: String, port: u16 },
    /// Opera VPN (бесплатный SOCKS5)
    OperaVpn,
    /// Пользовательский прокси (настраивается в UI)
    UserProxy,
}

impl fmt::Display for Egress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Egress::Direct { desync } => {
                if *desync {
                    write!(f, "Direct(desync)")
                } else {
                    write!(f, "Direct(pass)")
                }
            }
            Egress::Socks5 { host, port } => write!(f, "SOCKS5({host}:{port})"),
            Egress::OperaVpn => write!(f, "OperaVPN"),
            Egress::UserProxy => write!(f, "UserProxy"),
        }
    }
}

/// Хоп в цепочке egress-попыток.
///
/// Каждый hop содержит тип egress и таймаут на подключение.
/// Chain выполняет hops последовательно, пока один не удастся.
#[derive(Debug, Clone)]
pub struct EgressHop {
    /// Тип egress-провайдера
    pub egress: Egress,
    /// Таймаут на подключение/ожидание первого байта от этого hop
    pub timeout: Duration,
}

impl EgressHop {
    /// Создаёт hop прямого соединения с desync (default).
    pub fn direct() -> Self {
        Self {
            egress: Egress::Direct { desync: true },
            timeout: Duration::from_secs(5),
        }
    }

    /// Создаёт SOCKS5 hop.
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self {
            egress: Egress::Socks5 {
                host: host.into(),
                port,
            },
            timeout: Duration::from_secs(10),
        }
    }

    /// Создаёт Opera VPN hop.
    pub fn opera_vpn() -> Self {
        Self {
            egress: Egress::OperaVpn,
            timeout: Duration::from_secs(10),
        }
    }

    /// Создаёт user proxy hop.
    pub fn user_proxy() -> Self {
        Self {
            egress: Egress::UserProxy,
            timeout: Duration::from_secs(15),
        }
    }
}

/// Решение маршрутизации для домена/IP.
///
/// Содержит определённый регион и цепочку egress-попыток для failover.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// Регион, к которому относится трафик
    pub region: GeoRegion,
    /// Цепочка egress-провайдеров (sequential failover)
    pub egress_chain: Vec<EgressHop>,
    /// True если домен в exclude списке (банки, госуслуги)
    pub excluded: bool,
}

impl RouteDecision {
    /// Создаёт решение "excluded" — прямой проход без модификаций.
    pub fn excluded() -> Self {
        Self {
            region: GeoRegion::Excluded,
            egress_chain: vec![EgressHop {
                egress: Egress::Direct { desync: false },
                timeout: Duration::from_secs(5),
            }],
            excluded: true,
        }
    }

    /// Создаёт fallback решение — direct desync.
    pub fn fallback() -> Self {
        Self {
            region: GeoRegion::Global,
            egress_chain: vec![EgressHop::direct()],
            excluded: false,
        }
    }

    /// Проверяет, нужно ли применять DPI desync.
    pub fn needs_desync(&self) -> bool {
        !self.excluded
            && self
                .egress_chain
                .iter()
                .any(|hop| matches!(&hop.egress, Egress::Direct { desync: true }))
    }
}
