//! Strategy Persistence — сохранение/загрузка конфигурации стратегий.
//!
//! ## Формат
//! JSON файл в `%ProgramData%/ByeDPI/strategies.json`.
//!
//! ```json
//! {
//!   "strategies": [
//!     { "id": 1, "enabled": true, "priority": 10, "params": { "split_pos": 0.5 } }
//!   ],
//!   "split_mode": "BlacklistOnly"
//! }
//! ```
//!
//! ## Авто-сохранение
//! `start_auto_save()` запускает фоновый tokio task, который сохраняет
//! dirty конфигурацию с debounce (каждые N секунд).
//!
//! ## Источник
//! Адаптировано из [autodpi](https://github.com/brannondorsey/autodpi)
//! — persistence layer.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::debug;

/// Сериализуемая конфигурация стратегии.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyConfig {
    /// ID стратегии
    pub id: u32,
    /// Включена ли стратегия
    pub enabled: bool,
    /// Приоритет (выше = важнее)
    pub priority: u32,
    /// Параметры стратегии (для tune)
    #[serde(default)]
    pub params: std::collections::HashMap<String, f64>,
}

/// Конфигурация persistence — сохраняется в JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistenceConfig {
    /// Список стратегий с конфигурацией
    pub strategies: Vec<StrategyConfig>,
    /// Split tunnel режим
    pub split_mode: Option<String>,
}

/// Менеджер persistence стратегий.
///
/// Сохраняет/загружает конфигурацию стратегий в JSON файл.
/// Thread-safe через tokio::sync::Mutex.
///
/// # Пример
/// ```rust,no_run
/// use freedpi_core::adaptive::persist::PersistenceManager;
///
/// # async fn example() {
/// let pm = PersistenceManager::new(None);
/// let config = pm.load_or_default().await;
/// println!("Loaded {} strategies", config.strategies.len());
/// # }
/// ```
pub struct PersistenceManager {
    /// Путь к файлу конфигурации
    path: PathBuf,
    /// Текущая конфигурация (под async mutex)
    config: Arc<Mutex<PersistenceConfig>>,
    /// Флаг несохранённых изменений
    dirty: Arc<AtomicBool>,
}

impl PersistenceManager {
    /// Создаёт новый менеджер persistence.
    ///
    /// # Arguments
    /// * `path` — путь к JSON файлу.
    ///   Если None — используется `%ProgramData%/ByeDPI/strategies.json`
    pub fn new(path: Option<PathBuf>) -> Self {
        let config_path = path.unwrap_or_else(default_config_path);

        // Создаём директорию, если её нет
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        Self {
            path: config_path,
            config: Arc::new(Mutex::new(PersistenceConfig::default())),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Загружает конфигурацию из JSON файла.
    ///
    /// # Errors
    /// Возвращает ошибку, если файл не существует, не читается
    /// или содержит невалидный JSON.
    pub async fn load(&self) -> Result<PersistenceConfig> {
        let data = tokio::fs::read_to_string(&self.path).await?;
        let config: PersistenceConfig = serde_json::from_str(&data)?;
        debug!(
            "Loaded {} strategies from {}",
            config.strategies.len(),
            self.path.display()
        );

        let mut current = self.config.lock().await;
        *current = config.clone();
        self.dirty.store(false, Ordering::Release);
        Ok(config)
    }

    /// Сохраняет конфигурацию в JSON файл.
    ///
    /// # Errors
    /// Возвращает ошибку, если не удаётся записать файл
    /// (например, нет прав на запись в ProgramData).
    pub async fn save(&self) -> Result<()> {
        let config = self.config.lock().await;
        let data = serde_json::to_string_pretty(&*config)?;
        tokio::fs::write(&self.path, &data).await?;
        debug!(
            "Saved {} strategies to {}",
            config.strategies.len(),
            self.path.display()
        );
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    /// Обновляет конфигурацию стратегии.
    ///
    /// Если стратегия с таким ID существует — обновляет её.
    /// Если нет — добавляет новую.
    ///
    /// # Arguments
    /// * `config` — конфигурация стратегии
    pub async fn update_strategy(&self, config: StrategyConfig) {
        let mut current = self.config.lock().await;
        if let Some(existing) = current.strategies.iter_mut().find(|s| s.id == config.id) {
            *existing = config;
        } else {
            current.strategies.push(config);
        }
        self.dirty.store(true, Ordering::Release);
    }

    /// Включает/отключает стратегию.
    ///
    /// # Arguments
    /// * `id` — ID стратегии
    /// * `enabled` — включить (true) или отключить (false)
    pub async fn set_enabled(&self, id: u32, enabled: bool) {
        let mut current = self.config.lock().await;
        if let Some(strategy) = current.strategies.iter_mut().find(|s| s.id == id) {
            strategy.enabled = enabled;
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// Возвращает текущую конфигурацию.
    pub async fn get_config(&self) -> PersistenceConfig {
        self.config.lock().await.clone()
    }

    /// Запускает фоновый auto-save с debounce.
    ///
    /// Сохраняет dirty конфигурацию каждые `interval`.
    /// Запускается через `tokio::spawn`.
    ///
    /// # Arguments
    /// * `interval` — интервал между проверками dirty флага
    pub fn start_auto_save(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            loop {
                timer.tick().await;
                if self.dirty.load(Ordering::Acquire) {
                    if let Err(e) = self.save().await {
                        tracing::warn!("Auto-save failed: {}", e);
                    }
                }
            }
        });
    }

    /// Загружает конфигурацию или создаёт дефолтную, если файл не найден.
    ///
    /// Удобно использовать при старте engine:
    /// если файла нет — начинаем с дефолтной конфигурации.
    pub async fn load_or_default(&self) -> PersistenceConfig {
        match self.load().await {
            Ok(config) => config,
            Err(_) => {
                debug!(
                    "No existing config at {}, using defaults",
                    self.path.display()
                );
                let default = PersistenceConfig::default();
                let mut current = self.config.lock().await;
                *current = default.clone();
                default
            }
        }
    }

    /// Путь к файлу конфигурации.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Возвращает путь по умолчанию: %ProgramData%/ByeDPI/strategies.json
fn default_config_path() -> PathBuf {
    let base = std::env::var("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"));
    base.join("ByeDPI").join("strategies.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "byedpi_test_persist_{}_{}.json",
            name,
            std::process::id()
        ));
        p
    }

    fn cleanup(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_save_and_load() {
        let path = temp_path("save_and_load");
        let pm = PersistenceManager::new(Some(path.clone()));

        let config = StrategyConfig {
            id: 1,
            enabled: true,
            priority: 10,
            params: [("split_pos".to_string(), 0.5)].into(),
        };
        pm.update_strategy(config).await;
        pm.save().await.unwrap();

        // Новый менеджер для загрузки
        let pm2 = PersistenceManager::new(Some(path.clone()));
        let loaded = pm2.load().await.unwrap();
        assert_eq!(loaded.strategies.len(), 1);
        assert_eq!(loaded.strategies[0].id, 1);
        assert!(loaded.strategies[0].enabled);
        assert_eq!(loaded.strategies[0].params.get("split_pos"), Some(&0.5));

        cleanup(&path);
    }

    #[tokio::test]
    async fn test_load_or_default_when_no_file() {
        let path = temp_path("load_or_default");
        cleanup(&path); // ensure file doesn't exist

        let pm = PersistenceManager::new(Some(path.clone()));
        let config = pm.load_or_default().await;
        assert!(config.strategies.is_empty());
        assert!(config.split_mode.is_none());

        cleanup(&path);
    }

    #[tokio::test]
    async fn test_set_enabled() {
        let path = temp_path("set_enabled");
        let pm = PersistenceManager::new(Some(path.clone()));

        pm.update_strategy(StrategyConfig {
            id: 1,
            enabled: true,
            priority: 5,
            params: Default::default(),
        })
        .await;

        pm.set_enabled(1, false).await;
        let config = pm.get_config().await;
        assert!(!config.strategies[0].enabled);

        cleanup(&path);
    }

    #[tokio::test]
    async fn test_multiple_strategies() {
        let path = temp_path("multiple_strategies");
        let pm = PersistenceManager::new(Some(path.clone()));

        for i in 0..3 {
            pm.update_strategy(StrategyConfig {
                id: i,
                enabled: true,
                priority: i * 10,
                params: Default::default(),
            })
            .await;
        }
        pm.save().await.unwrap();

        let pm2 = PersistenceManager::new(Some(path.clone()));
        let loaded = pm2.load().await.unwrap();
        assert_eq!(loaded.strategies.len(), 3);

        cleanup(&path);
    }

    #[test]
    fn test_default_config_path() {
        let path = default_config_path();
        assert!(path.ends_with("strategies.json"));
        assert!(path.to_string_lossy().contains("ByeDPI"));
    }
}
