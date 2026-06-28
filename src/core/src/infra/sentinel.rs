//! Sentinel File System — файловый механизм аварийной остановки engine.
//!
//! ## Принцип работы
//! - При запуске engine создаётся sentinel-файл в `%ProgramData%/ByeDPI/sentinel`
//! - Фоновый поток проверяет существование файла каждые 5 секунд
//! - Если файл удалён (вручную, системой, вирусом) — engine немедленно останавливается
//! - Fallback на `%APPDATA%/ByeDPI/sentinel` при отсутствии ProgramData
//!
//! ## Безопасность
//! Sentinel file — это physical kill switch, который работает даже если:
//! - HTTP API не отвечает
//! - GUI завис
//! - Tray icon не реагирует
//!
//! Достаточно удалить файл → engine остановится в течение check_interval секунд.
//!
//! ## Источник
//! Адаптировано из [DPIReaper](https://github.com/rage8885/DPIReaper) —
//! концепция Sentinel file для безопасного управления DPI-движком.
//!
//! ## Пример
//! ```rust,no_run
//! use freedpi_core::infra::sentinel::Sentinel;
//! use std::sync::Arc;
//! let sentinel = Arc::new(Sentinel::create());
//! sentinel.start_monitor(); // Запуск фонового потока
//! // ... работа engine ...
//! // Удаление sentinel файла или вызов sentinel.stop() остановит engine
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Интервал проверки sentinel файла (секунды).
const CHECK_INTERVAL_SECS: u64 = 5;

/// Имя sentinel файла.
const SENTINEL_FILENAME: &str = "sentinel";

/// Директория ByeDPI в ProgramData/AppData.
const BYEDPI_DIR: &str = "ByeDPI";

/// Sentinel — файловый триггер для безопасной остановки engine.
///
/// Если sentinel файл существует — engine работает.
/// Если файл удалён — engine останавливается.
///
/// # Thread Safety
/// `Sentinel` использует `AtomicBool` для флага running и может быть
/// безопасно разделён между потоками через `Arc`.
#[derive(Debug)]
pub struct Sentinel {
    /// Путь к sentinel файлу.
    path: PathBuf,
    /// Флаг: работает ли engine.
    running: AtomicBool,
    /// Интервал проверки файла.
    check_interval: Duration,
}

impl Sentinel {
    /// Создаёт sentinel в `%ProgramData%/ByeDPI/sentinel`.
    ///
    /// Если `ProgramData` недоступен — fallback на `%APPDATA%/ByeDPI/sentinel`.
    /// Автоматически создаёт директорию и sentinel файл.
    pub fn create() -> Self {
        let path = Self::determine_path();

        // Создаём директорию
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                match std::fs::create_dir_all(parent) {
                    Ok(_) => info!("Sentinel directory created: {}", parent.display()),
                    Err(e) => warn!(
                        "Cannot create sentinel directory {}: {}",
                        parent.display(),
                        e
                    ),
                }
            }
        }

        // Создаём sentinel файл
        match std::fs::write(&path, b"running") {
            Ok(_) => info!("Sentinel file created: {}", path.display()),
            Err(e) => warn!("Cannot create sentinel file {}: {}", path.display(), e),
        }

        Self {
            path,
            running: AtomicBool::new(true),
            check_interval: Duration::from_secs(CHECK_INTERVAL_SECS),
        }
    }

    /// Определяет путь к sentinel файлу.
    ///
    /// Предпочитает `%ProgramData%/ByeDPI/sentinel`,
    /// fallback на `%APPDATA%/ByeDPI/sentinel`.
    fn determine_path() -> PathBuf {
        // Пробуем ProgramData (машина)
        if let Ok(prog_data) = std::env::var("ProgramData") {
            let path = PathBuf::from(prog_data)
                .join(BYEDPI_DIR)
                .join(SENTINEL_FILENAME);
            return path;
        }

        // Fallback на AppData (пользователь)
        if let Ok(app_data) = std::env::var("APPDATA") {
            let path = PathBuf::from(app_data)
                .join(BYEDPI_DIR)
                .join(SENTINEL_FILENAME);
            return path;
        }

        // Последний fallback: текущая директория
        warn!("Neither ProgramData nor APPDATA available — using local sentinel");
        PathBuf::from(SENTINEL_FILENAME)
    }

    /// Создаёт sentinel с пользовательским путём (для тестов).
    pub fn with_path(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, b"running").ok();

        Self {
            path,
            running: AtomicBool::new(true),
            check_interval: Duration::from_secs(CHECK_INTERVAL_SECS),
        }
    }

    /// Возвращает путь к sentinel файлу.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Проверка: работает ли engine?
    ///
    /// Использует `Acquire` ordering для видимости между потоками.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Фоновый поток проверки sentinel.
    ///
    /// Запускает отдельный системный поток, который каждые `check_interval`
    /// секунд проверяет существование sentinel файла.
    /// Если файл удалён — устанавливает `running = false`.
    ///
    /// # Panics
    /// Не паникует. Ошибки логируются через `tracing::warn!`.
    pub fn start_monitor(self: Arc<Self>) {
        let interval = self.check_interval;
        let path = self.path.clone();

        std::thread::Builder::new()
            .name("sentinel-monitor".to_string())
            .spawn(move || {
                info!(
                    "Sentinel monitor started (check every {}s)",
                    interval.as_secs()
                );

                // Делаем snapshot указателя для проверки running
                while self.running.load(Ordering::Acquire) {
                    std::thread::sleep(interval);

                    if !path.exists() {
                        warn!(
                            "Sentinel file deleted — stopping engine (path={})",
                            path.display()
                        );
                        self.running.store(false, Ordering::Release);
                        break;
                    }
                }

                info!("Sentinel monitor stopped");
            })
            .expect("Failed to spawn sentinel monitor thread");
    }

    /// Ручная остановка: удаляет sentinel файл и сбрасывает флаг.
    ///
    /// Безопасно вызывать multiple times — повторные вызовы no-op.
    pub fn stop(&self) {
        if !self.running.load(Ordering::Acquire) {
            return; // Уже остановлен
        }

        // Пытаемся удалить файл
        if self.path.exists() {
            match std::fs::remove_file(&self.path) {
                Ok(_) => info!("Sentinel file removed: {}", self.path.display()),
                Err(e) => warn!("Cannot remove sentinel file {}: {}", self.path.display(), e),
            }
        }

        self.running.store(false, Ordering::Release);
        info!("Sentinel stopped");
    }

    /// Принудительная остановка (без удаления файла).
    ///
    /// Используется при нормальном завершении через Ctrl+C.
    pub fn stop_soft(&self) {
        self.running.store(false, Ordering::Release);
    }

    /// Проверяет, существует ли sentinel файл на диске.
    pub fn file_exists(&self) -> bool {
        self.path.exists()
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        // При Drop пытаемся удалить sentinel файл для чистоты
        if self.path.exists() {
            std::fs::remove_file(&self.path).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_sentinel_create_and_check() {
        let tmp = std::env::temp_dir().join(format!("sentinel_test_{}", std::process::id()));
        let path = tmp.join("sentinel");

        let sentinel = Sentinel::with_path(path.clone());
        assert!(sentinel.is_running());
        assert!(sentinel.file_exists());
        assert_eq!(sentinel.path(), &path);

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_sentinel_stop() {
        let tmp = std::env::temp_dir().join(format!("sentinel_stop_{}", std::process::id()));
        let path = tmp.join("sentinel");

        let sentinel = Sentinel::with_path(path.clone());
        assert!(sentinel.is_running());

        sentinel.stop();
        assert!(!sentinel.is_running());
        assert!(!sentinel.file_exists()); // Файл удалён

        // Повторный stop — no-op
        sentinel.stop();
        assert!(!sentinel.is_running());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_sentinel_stop_soft() {
        let tmp = std::env::temp_dir().join(format!("sentinel_soft_{}", std::process::id()));
        let path = tmp.join("sentinel");

        let sentinel = Sentinel::with_path(path.clone());
        assert!(sentinel.is_running());

        sentinel.stop_soft();
        assert!(!sentinel.is_running());
        // Файл не удалён
        assert!(sentinel.file_exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_sentinel_file_deleted_externally() {
        let tmp = std::env::temp_dir().join(format!("sentinel_ext_{}", std::process::id()));
        let path = tmp.join("sentinel");

        let sentinel = Arc::new(Sentinel::with_path(path.clone()));
        assert!(sentinel.is_running());

        // Удаляем файл вручную (имитация внешнего удаления)
        std::fs::remove_file(&path).unwrap();
        assert!(!sentinel.file_exists());

        // После внешнего удаления is_running всё ещё true
        // (только monitor thread сбрасывает флаг)
        assert!(sentinel.is_running());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_sentinel_drop_removes_file() {
        let tmp = std::env::temp_dir().join(format!("sentinel_drop_{}", std::process::id()));
        let path = tmp.join("sentinel");

        {
            let sentinel = Sentinel::with_path(path.clone());
            assert!(sentinel.file_exists());
        } // Drop — файл удалён

        assert!(!path.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_sentinel_create_existing() {
        // Создание sentinel, когда файл уже существует
        let tmp = std::env::temp_dir().join(format!("sentinel_exist_{}", std::process::id()));
        let path = tmp.join("sentinel");

        // Создаём файл заранее
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(&path, b"old").unwrap();

        let sentinel = Sentinel::with_path(path.clone());
        assert!(sentinel.is_running());
        assert!(sentinel.file_exists());

        // Файл перезаписан
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "running");

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
