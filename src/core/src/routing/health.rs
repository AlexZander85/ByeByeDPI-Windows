//! Proxy Health Checks — фоновый мониторинг доступности прокси.
//!
//! ## Типы проверок
//! - **SOCKS5 handshake**: подключение → отправка приветствия (0x05, 0x01, 0x00)
//!   → ожидание ответа (0x05, 0x00)
//! - **HTTP CONNECT**: подключение → HEAD запрос → проверка 200 OK
//!
//! ## Периодичность
//! Фоновый health checker запускается каждые 30 секунд, проверяет все
//! зарегистрированные прокси и обновляет их статус.
//!
//! ## Пример
//! ```rust
//! use freedpi_core::routing::health::{HealthChecker, ProxyStatus, ProxyType};
//!
//! let mut checker = HealthChecker::new();
//! checker.add_socks5("127.0.0.1", 9050);
//! let status = checker.get_status("127.0.0.1", 9050, ProxyType::Socks5);
//! assert_eq!(status, ProxyStatus::Unknown);
//! ```
//!
//! ## Источник
//! Адаптировано из [Nova](https://github.com/patrykkalinowski/nova) — health checks.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::debug;

/// Статус прокси после health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    /// Прокси работает
    Alive,
    /// Прокси недоступен
    Dead,
    /// Статус неизвестен (ещё не проверялся)
    Unknown,
}

/// Тип прокси для health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyType {
    /// SOCKS5 прокси
    Socks5,
    /// HTTP прокси
    Http,
}

/// Результат health check.
#[derive(Debug, Clone)]
pub struct HealthResult {
    /// Статус прокси
    pub status: ProxyStatus,
    /// Время последней проверки
    pub checked_at: Instant,
    /// Время ответа
    pub latency: Duration,
    /// Ошибка (если была)
    pub error: Option<String>,
}

/// Ключ прокси в кэше статусов.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ProxyKey {
    host: String,
    port: u16,
    proxy_type: ProxyType,
}

/// Health Checker — мониторинг доступности прокси.
///
/// ## Потокобезопасность
/// - DashMap для кэша статусов (lock-free reads)
/// - tokio::sync::Mutex для списка прокси (редкие изменения)
///
/// ## Использование
/// 1. Добавить прокси: `checker.add_socks5(host, port)`
/// 2. Запустить фоновый checker: `checker.start_background_check()`
/// 3. Получить статус: `checker.get_status(host, port, ProxyType::Socks5)`
/// 4. Принудительная проверка: `checker.check_all().await`
pub struct HealthChecker {
    /// Список прокси для мониторинга
    proxies: Arc<Mutex<Vec<(ProxyKey, ProxyType)>>>,
    /// Кэш статусов (key → HealthResult)
    status_cache: Arc<DashMap<ProxyKey, HealthResult>>,
}

impl HealthChecker {
    /// Создаёт новый Health Checker.
    pub fn new() -> Self {
        Self {
            proxies: Arc::new(Mutex::new(Vec::new())),
            status_cache: Arc::new(DashMap::new()),
        }
    }

    /// Добавляет SOCKS5 прокси для мониторинга.
    pub async fn add_socks5(&self, host: impl Into<String>, port: u16) {
        let key = ProxyKey {
            host: host.into(),
            port,
            proxy_type: ProxyType::Socks5,
        };
        self.proxies.lock().await.push((key, ProxyType::Socks5));
    }

    /// Добавляет HTTP прокси для мониторинга.
    pub async fn add_http(&self, host: impl Into<String>, port: u16) {
        let key = ProxyKey {
            host: host.into(),
            port,
            proxy_type: ProxyType::Http,
        };
        self.proxies.lock().await.push((key, ProxyType::Http));
    }

    /// Получает статус прокси из кэша.
    pub fn get_status(&self, host: &str, port: u16, proxy_type: ProxyType) -> ProxyStatus {
        let key = ProxyKey {
            host: host.to_string(),
            port,
            proxy_type,
        };
        self.status_cache
            .get(&key)
            .map(|r| r.status)
            .unwrap_or(ProxyStatus::Unknown)
    }

    /// Получает полный результат health check из кэша.
    pub fn get_result(&self, host: &str, port: u16, proxy_type: ProxyType) -> Option<HealthResult> {
        let key = ProxyKey {
            host: host.to_string(),
            port,
            proxy_type,
        };
        self.status_cache.get(&key).map(|r| r.clone())
    }

    /// Проверяет SOCKS5 прокси.
    ///
    /// ## SOCKS5 handshake
    /// Клиент → Сервер: `0x05, 0x01, 0x00` (SOCKS5, 1 auth method, no auth)
    /// Сервер → Клиент: `0x05, 0x00` (SOCKS5, no auth accepted)
    pub async fn check_socks5(host: &str, port: u16, timeout_dur: Duration) -> HealthResult {
        let start = Instant::now();
        let addr = format!("{}:{}", host, port);

        match timeout(timeout_dur, TokioTcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // SOCKS5 handshake: greeting
                let greeting = [0x05, 0x01, 0x00]; // SOCKS5, 1 method, no auth
                if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut stream, &greeting).await {
                    return HealthResult {
                        status: ProxyStatus::Dead,
                        checked_at: Instant::now(),
                        latency: start.elapsed(),
                        error: Some(format!("SOCKS5 write failed: {}", e)),
                    };
                }

                // Читаем ответ
                let mut buf = [0u8; 2];
                match timeout(
                    Duration::from_secs(2),
                    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf),
                )
                .await
                {
                    Ok(Ok(_n)) => {
                        if buf[0] == 0x05 && buf[1] == 0x00 {
                            debug!("SOCKS5 {}:{} — alive", host, port);
                            HealthResult {
                                status: ProxyStatus::Alive,
                                checked_at: Instant::now(),
                                latency: start.elapsed(),
                                error: None,
                            }
                        } else {
                            HealthResult {
                                status: ProxyStatus::Dead,
                                checked_at: Instant::now(),
                                latency: start.elapsed(),
                                error: Some(format!(
                                    "SOCKS5 unexpected response: {:02x} {:02x}",
                                    buf[0], buf[1]
                                )),
                            }
                        }
                    }
                    Ok(Err(e)) => HealthResult {
                        status: ProxyStatus::Dead,
                        checked_at: Instant::now(),
                        latency: start.elapsed(),
                        error: Some(format!("SOCKS5 read failed: {}", e)),
                    },
                    Err(_) => HealthResult {
                        status: ProxyStatus::Dead,
                        checked_at: Instant::now(),
                        latency: start.elapsed(),
                        error: Some("SOCKS5 response timeout".to_string()),
                    },
                }
            }
            Ok(Err(e)) => HealthResult {
                status: ProxyStatus::Dead,
                checked_at: Instant::now(),
                latency: start.elapsed(),
                error: Some(format!("SOCKS5 connect failed: {}", e)),
            },
            Err(_) => HealthResult {
                status: ProxyStatus::Dead,
                checked_at: Instant::now(),
                latency: start.elapsed(),
                error: Some("SOCKS5 connect timeout".to_string()),
            },
        }
    }

    /// Проверяет HTTP прокси (через CONNECT).
    pub async fn check_http(host: &str, port: u16, timeout_dur: Duration) -> HealthResult {
        let start = Instant::now();
        let addr = format!("{}:{}", host, port);

        match timeout(timeout_dur, TokioTcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // HTTP HEAD запрос
                let head = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
                if let Err(e) =
                    tokio::io::AsyncWriteExt::write_all(&mut stream, head.as_bytes()).await
                {
                    return HealthResult {
                        status: ProxyStatus::Dead,
                        checked_at: Instant::now(),
                        latency: start.elapsed(),
                        error: Some(format!("HTTP write failed: {}", e)),
                    };
                }

                // Читаем первую строку ответа
                let mut buf = [0u8; 1024];
                match timeout(
                    Duration::from_secs(2),
                    tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        let response = String::from_utf8_lossy(&buf[..n]);
                        if response.contains("200 OK")
                            || response.contains("200 Connection established")
                        {
                            debug!("HTTP {}:{} — alive", host, port);
                            HealthResult {
                                status: ProxyStatus::Alive,
                                checked_at: Instant::now(),
                                latency: start.elapsed(),
                                error: None,
                            }
                        } else {
                            let status = response.lines().next().unwrap_or("unknown");
                            HealthResult {
                                status: ProxyStatus::Dead,
                                checked_at: Instant::now(),
                                latency: start.elapsed(),
                                error: Some(format!("HTTP unexpected status: {}", status)),
                            }
                        }
                    }
                    _ => HealthResult {
                        status: ProxyStatus::Dead,
                        checked_at: Instant::now(),
                        latency: start.elapsed(),
                        error: Some("HTTP no response".to_string()),
                    },
                }
            }
            Ok(Err(e)) => HealthResult {
                status: ProxyStatus::Dead,
                checked_at: Instant::now(),
                latency: start.elapsed(),
                error: Some(format!("HTTP connect failed: {}", e)),
            },
            Err(_) => HealthResult {
                status: ProxyStatus::Dead,
                checked_at: Instant::now(),
                latency: start.elapsed(),
                error: Some("HTTP connect timeout".to_string()),
            },
        }
    }

    /// Проверяет все зарегистрированные прокси.
    pub async fn check_all(&self) {
        let proxies = self.proxies.lock().await.clone();
        for (key, proxy_type) in &proxies {
            let timeout_dur = Duration::from_secs(5);
            let result = match proxy_type {
                ProxyType::Socks5 => Self::check_socks5(&key.host, key.port, timeout_dur).await,
                ProxyType::Http => Self::check_http(&key.host, key.port, timeout_dur).await,
            };
            self.status_cache.insert(key.clone(), result);
        }
    }

    /// Запускает фоновый health checker с заданным интервалом.
    ///
    /// Возвращает `JoinHandle` для отмены через `.abort()`.
    pub fn start_background_check(
        self: Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Первая проверка сразу (не ждём interval)
            ticker.tick().await; // первый tick сразу
            loop {
                ticker.tick().await;
                debug!("Running background health check...");
                self.check_all().await;
            }
        })
    }

    /// Удаляет прокси из мониторинга.
    pub async fn remove(&self, host: &str, port: u16) {
        let mut proxies = self.proxies.lock().await;
        proxies.retain(|(k, _)| k.host != host || k.port != port);

        let key = ProxyKey {
            host: host.to_string(),
            port,
            proxy_type: ProxyType::Socks5,
        };
        self.status_cache.remove(&key);
    }

    /// Количество отслеживаемых прокси.
    pub async fn proxy_count(&self) -> usize {
        self.proxies.lock().await.len()
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}
