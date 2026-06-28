//! Opera VPN Integration — бесплатные EU-прокси без регистрации.
//!
//! ## Как это работает
//! Opera Browser предоставляет бесплатный VPN через SOCKS5 прокси.
//! Прокси работают без регистрации и аутентификации.
//!
//! ## Известные серверы
//! Opera VPN использует несколько SOCKS5 серверов в Европе:
//! - `185.167.238.201` (Нидерланды)
//! - `185.167.238.202` (Нидерланды)
//! - `185.167.238.203` (Нидерланды)
//! - `185.167.238.204` (Германия)
//! - `185.167.238.205` (Франция)
//!
//! Все на порту `1080`, без аутентификации.
//!
//! ## Использование
//! 1. Получить список прокси: `OperaVpnProvider::discover()`
//! 2. Проверить здоровье: `check_health().await`
//! 3. Использовать в EgressChain как `Egress::OperaVpn`
//!
//! ## Важно
//! - Opera VPN может меняться (IP адреса и порты)
//! - Серверы могут быть недоступны в некоторых регионах
//! - Скорость ограничена (бесплатный сервис)
//! - Не хранит логи (по заявлению Opera)
//!
//! ## Источник
//! Адаптировано из [Nova](https://github.com/patrykkalinowski/nova) — Opera VPN.

use crate::routing::health::{HealthChecker, ProxyStatus, ProxyType};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Известные Opera VPN SOCKS5 прокси-серверы.
///
/// ## Формат
/// `(host, port, location)`
const OPERA_PROXIES: &[(&str, u16, &str)] = &[
    ("185.167.238.201", 1080, "Netherlands"),
    ("185.167.238.202", 1080, "Netherlands"),
    ("185.167.238.203", 1080, "Netherlands"),
    ("185.167.238.204", 1080, "Germany"),
    ("185.167.238.205", 1080, "France"),
];

/// Прокси-сервер Opera VPN с информацией о статусе.
#[derive(Debug, Clone)]
pub struct OperaProxy {
    /// IP адрес
    pub host: String,
    /// Порт (обычно 1080)
    pub port: u16,
    /// Локация сервера
    pub location: String,
    /// Статус прокси
    pub status: ProxyStatus,
}

/// Opera VPN Provider — обнаружение и мониторинг бесплатных прокси.
pub struct OperaVpnProvider {
    /// Список обнаруженных прокси
    proxies: Vec<OperaProxy>,
    /// Health checker для мониторинга
    health_checker: Arc<HealthChecker>,
}

impl OperaVpnProvider {
    /// Создаёт нового провайдера с известными прокси.
    ///
    /// Все известные серверы Opera VPN добавляются в health checker.
    pub async fn new() -> Self {
        let health_checker = Arc::new(HealthChecker::new());
        let mut proxies = Vec::new();

        for (host, port, location) in OPERA_PROXIES {
            health_checker.add_socks5(*host, *port).await;
            proxies.push(OperaProxy {
                host: host.to_string(),
                port: *port,
                location: location.to_string(),
                status: ProxyStatus::Unknown,
            });
        }

        Self {
            proxies,
            health_checker,
        }
    }

    /// Проверяет здоровье всех Opera VPN прокси.
    pub async fn check_health(&mut self) {
        self.health_checker.check_all().await;
        for proxy in &mut self.proxies {
            let result = self
                .health_checker
                .get_result(&proxy.host, proxy.port, ProxyType::Socks5);
            proxy.status = result.map(|r| r.status).unwrap_or(ProxyStatus::Dead);
            match proxy.status {
                ProxyStatus::Alive => {
                    debug!(
                        "Opera VPN {}:{} ({}) — alive",
                        proxy.host, proxy.port, proxy.location
                    );
                }
                ProxyStatus::Dead => {
                    debug!(
                        "Opera VPN {}:{} ({}) — dead",
                        proxy.host, proxy.port, proxy.location
                    );
                }
                ProxyStatus::Unknown => {}
            }
        }
    }

    /// Запускает фоновый health checker с периодическим обновлением.
    ///
    /// ## Returns
    /// `JoinHandle` для отмены через `.abort()`.
    pub fn start_background_check(
        self: Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let checker = self.health_checker.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // первый tick сразу
            loop {
                ticker.tick().await;
                debug!("Checking Opera VPN proxies...");
                checker.check_all().await;
            }
        })
    }

    /// Возвращает список всех прокси с их статусами.
    pub fn all_proxies(&self) -> &[OperaProxy] {
        &self.proxies
    }

    /// Возвращает первый живой прокси.
    pub fn first_alive(&self) -> Option<&OperaProxy> {
        self.proxies.iter().find(|p| p.status == ProxyStatus::Alive)
    }

    /// Возвращает все живые прокси.
    pub fn alive_proxies(&self) -> Vec<&OperaProxy> {
        self.proxies
            .iter()
            .filter(|p| p.status == ProxyStatus::Alive)
            .collect()
    }

    /// Обновляет список прокси.
    ///
    /// Источники (по приоритету):
    /// 1. Пользовательский файл `data/opera_proxies.txt`
    /// 2. Hardcoded список (fallback)
    pub async fn discover(&mut self) {
        // 1. Пробуем загрузить из файла
        if let Ok(content) = std::fs::read_to_string("data/opera_proxies.txt") {
            let file_proxies: Vec<OperaProxy> = content
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        let host = parts[0].to_string();
                        let port: u16 = parts[1].parse().ok()?;
                        let location = parts.get(2).map(|s| s.to_string()).unwrap_or_default();
                        Some(OperaProxy {
                            host,
                            port,
                            location,
                            status: ProxyStatus::Unknown,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            if !file_proxies.is_empty() {
                info!("Loaded {} Opera VPN proxies from file", file_proxies.len());
                self.proxies = file_proxies;
                return;
            }
        }

        // 2. Fallback на hardcoded список
        debug!(
            "Using hardcoded Opera VPN proxy list ({} servers)",
            OPERA_PROXIES.len()
        );
    }

    /// Возвращает количество прокси.
    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }
}

impl Default for OperaVpnProvider {
    fn default() -> Self {
        // Создаём временный runtime для async инициализации
        // (Default не поддерживает async)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create temp runtime for OperaVpnProvider::default()");
        rt.block_on(async { Self::new().await })
    }
}
