//! FreeDPI Windows Core Library
//!
//! Core library providing the packet engine, connection tracking,
//! split tunneling, and runtime infrastructure for DPI bypass on Windows.

pub mod adaptive;
pub mod classifier;
pub mod config;
pub mod conntrack;
pub mod desync;
pub mod dns;
pub mod engine;
pub mod infra;
pub mod packet_engine;
pub mod probe;
pub mod proxy;
pub mod routing;
pub mod split_tunnel;

use rayon::ThreadPoolBuilder;
use std::sync::OnceLock;

/// Единый runtime для всего приложения.
///
/// Разделяет I/O (tokio) и CPU-bound (rayon) задачи для максимальной
/// производительности на multi-core системах.
///
/// # Модель потоков
/// - tokio: async I/O (WinDivert recv, DNS, proxy, HTTP API)
/// - rayon: parallel CPU (desync, TLS, frag, checksum)
pub struct Runtime {
    /// tokio async runtime для I/O-bound операций
    pub io: tokio::runtime::Runtime,
    /// rayon thread pool для CPU-bound операций
    pub cpu: rayon::ThreadPool,
}

static GLOBAL_RUNTIME: OnceLock<Runtime> = OnceLock::new();

impl Runtime {
    /// Создаёт новый runtime с оптимальной конфигурацией потоков.
    ///
    /// - tokio workers: `max(2, cpus/2 + 1)` — I/O-bound
    /// - rayon threads: `max(2, cpus)` — CPU-bound (все ядра)
    pub fn new() -> Self {
        let cpus = num_cpus::get().max(2);

        let io = tokio::runtime::Builder::new_multi_thread()
            .worker_threads((cpus / 2 + 1).max(2))
            .enable_io()
            .enable_time()
            .thread_name("byedpi-io-")
            .build()
            .expect("Failed to create tokio runtime");

        let cpu = ThreadPoolBuilder::new()
            .num_threads(cpus.max(2))
            .thread_name(|i| format!("byedpi-cpu-{}", i))
            .build()
            .expect("Failed to create rayon thread pool");

        Self { io, cpu }
    }

    /// Инициализирует глобальный singleton runtime.
    /// Безопасно вызывать multiple times — второй вызов no-op.
    pub fn global() -> &'static Runtime {
        GLOBAL_RUNTIME.get_or_init(|| {
            tracing::info!("Initializing global Runtime");
            Self::new()
        })
    }

    /// Блокирующий вход в async runtime.
    /// Запускает future на tokio runtime и ждёт завершения.
    pub fn block_on<F: std::future::Future<Output = T>, T>(&self, future: F) -> T {
        self.io.block_on(future)
    }

    /// Запускает CPU-bound задачу на rayon thread pool через tokio.
    /// Возвращает `JoinHandle` для ожидания результата из async контекста.
    pub async fn spawn_cpu<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cpu.spawn(move || {
            let _ = tx.send(f());
        });
        rx.await.expect("Rayon task panicked")
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

/// Типы протоколов для классификации
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Unknown,
}

impl Protocol {
    pub fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Unknown,
        }
    }
}

/// Результат обработки пакета
#[derive(Debug)]
pub enum PacketAction {
    /// Пропустить пакет без изменений (forward)
    Forward,
    /// Заблокировать пакет (drop)
    Drop,
    /// Модифицировать и отправить
    Modify(Vec<u8>),
    /// Инжектировать дополнительные пакеты
    Inject(Vec<Vec<u8>>),
    /// Модифицировать + инжектировать
    ModifyAndInject {
        modified: Vec<u8>,
        inject: Vec<Vec<u8>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let rt = Runtime::new();
        // Проверяем, что можно получить reference к handle (всегда Ok после new)
        let _h = rt.io.handle();
        // Пробуем выполнить простую задачу внутри runtime
        let result = rt.io.block_on(async { 42 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_global_runtime() {
        let rt = Runtime::global();
        let rt2 = Runtime::global();
        assert!(std::ptr::eq(rt, rt2));
    }

    #[test]
    fn test_protocol_from_ip() {
        assert_eq!(Protocol::from_ip_protocol(6), Protocol::Tcp);
        assert_eq!(Protocol::from_ip_protocol(17), Protocol::Udp);
        assert_eq!(Protocol::from_ip_protocol(1), Protocol::Icmp);
        assert_eq!(Protocol::from_ip_protocol(255), Protocol::Unknown);
    }

    #[test]
    fn test_spawn_cpu() {
        let rt = Runtime::new();
        let result = rt.block_on(rt.spawn_cpu(|| 42 + 1));
        assert_eq!(result, 43);
    }
}
