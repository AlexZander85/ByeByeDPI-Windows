//! Configuration — загрузка, валидация и хранение конфигурации.

pub mod rule_override;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Режим работы приложения.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    /// Полноценный сервис с API
    #[default]
    Service,
    /// Только CLI, без сервиса
    Cli,
}

/// Режим раздельного туннелирования.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitModeConfig {
    WhitelistOnly,
    #[default]
    BlacklistOnly,
    Auto,
}

/// Конфигурация DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DoH сервер (Cloudflare по умолчанию)
    #[serde(default = "default_doh_url")]
    pub doh_url: String,
    /// DoT сервер
    #[serde(default = "default_dot_addr")]
    pub dot_addr: String,
    /// TTL кэша в секундах
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    /// Использовать persistent HTTP/2 для DoH (повторное использование сессии)
    #[serde(default = "default_true")]
    pub doh_persistent: bool,
    /// IP overrides для DNS: CIDR → IP (формат: "1.2.3.0/24=5.6.7.8")
    #[serde(default)]
    pub dns_ip_overrides: Vec<String>,
    /// SPKI hashes для certificate pinning DoH серверов (base64 SHA256)
    #[serde(default)]
    pub doh_pins: Vec<String>,
}

fn default_doh_url() -> String {
    "https://cloudflare-dns.com/dns-query".to_string()
}
fn default_dot_addr() -> String {
    "1.1.1.1:853".to_string()
}
fn default_cache_ttl() -> u64 {
    300
}

/// Конфигурация HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Порт API сервера (только localhost)
    #[serde(default = "default_api_port")]
    pub port: u16,
    /// API ключ для аутентификации
    #[serde(default = "default_api_key")]
    pub api_key: String,
    /// Включить API
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_api_port() -> u16 {
    11337
}
fn default_api_key() -> String {
    let key = uuid::Uuid::new_v4().to_string();
    debug!("Generated new API key: {}", key);
    key
}
fn default_true() -> bool {
    true
}

/// Конфигурация WinDivert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindivertConfig {
    /// Filter string
    #[serde(default = "default_filter")]
    pub filter: String,
    /// Queue length (packets)
    #[serde(default = "default_queue_len")]
    pub queue_length: u32,
    /// Queue time (ms)
    #[serde(default = "default_queue_time")]
    pub queue_time: u32,
}

fn default_filter() -> String {
    "ip && (tcp.DstPort == 443 or tcp.SrcPort == 443 \
     or udp.DstPort == 53 or udp.DstPort == 443)"
        .to_string()
}
fn default_queue_len() -> u32 {
    8192
}
fn default_queue_time() -> u32 {
    2000
}

/// Полная конфигурация приложения.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Режим работы
    #[serde(default)]
    pub mode: AppMode,
    /// Режим split tunnel
    #[serde(default)]
    pub split_mode: SplitModeConfig,
    /// DNS настройки
    #[serde(default)]
    pub dns: DnsConfig,
    /// API настройки
    #[serde(default)]
    pub api: ApiConfig,
    /// WinDivert настройки
    #[serde(default)]
    pub windivert: WindivertConfig,
    /// Путь к файлам списков
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Количество потоков rayon (0 = все ядра)
    #[serde(default)]
    pub cpu_threads: usize,
    /// Desync настройки (техники, параметры)
    #[serde(default)]
    pub desync: DesyncSection,
}

/// Desync секция конфигурации.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesyncSection {
    /// Fake SNI для инъекции
    #[serde(default = "default_fake_sni")]
    pub fake_sni: String,
    /// Размер сплита (байт)
    #[serde(default)]
    pub split_size: usize,
    /// Количество сегментов
    #[serde(default = "default_split_count")]
    pub split_count: usize,
    /// TTL offset для fake пакетов
    #[serde(default = "default_fake_ttl_offset")]
    pub fake_ttl_offset: u8,
    /// Задержка между инъекциями (мкс)
    #[serde(default = "default_inject_delay")]
    pub inject_delay_us: u64,
    /// Техники (пусто = default set: FakeSni + MultiSplit + BadChecksum)
    #[serde(default)]
    pub techniques: Vec<String>,
}

fn default_fake_sni() -> String {
    "www.google.com".to_string()
}
fn default_split_count() -> usize {
    3
}
fn default_fake_ttl_offset() -> u8 {
    1
}
fn default_inject_delay() -> u64 {
    1000
}

impl Default for DesyncSection {
    fn default() -> Self {
        Self {
            fake_sni: default_fake_sni(),
            split_size: 1,
            split_count: default_split_count(),
            fake_ttl_offset: default_fake_ttl_offset(),
            inject_delay_us: default_inject_delay(),
            techniques: Vec::new(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    let path = PathBuf::from("data");
    // Try to find data dir relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let exe_path = parent.join("data");
            if exe_path.exists() {
                return exe_path;
            }
        }
    }
    path
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: AppMode::Service,
            split_mode: SplitModeConfig::BlacklistOnly,
            dns: DnsConfig::default(),
            api: ApiConfig::default(),
            windivert: WindivertConfig::default(),
            data_dir: default_data_dir(),
            cpu_threads: 0,
            desync: DesyncSection::default(),
        }
    }
}

impl Config {
    /// Конвертирует Config в ProcessingConfig для engine.
    pub fn to_processing_config(&self) -> crate::engine::ProcessingConfig {
        use crate::desync::{DesyncConfig, DesyncTechnique};

        let desync_config = DesyncConfig {
            fake_sni: self.desync.fake_sni.clone(),
            split_size: self.desync.split_size,
            split_count: self.desync.split_count,
            max_seg_size: 10,
            bad_checksum: false,
            fake_ttl_offset: self.desync.fake_ttl_offset,
            inject_delay_us: self.desync.inject_delay_us,
            reseed_interval: 8192,
        };

        let techniques: Vec<DesyncTechnique> = self
            .desync
            .techniques
            .iter()
            .filter_map(|name| parse_technique(name))
            .collect();

        crate::engine::ProcessingConfig {
            seq_spoof_enabled: true,
            fake_sni: self.desync.fake_sni.clone(),
            hop_tab_enabled: true,
            geo_routing_enabled: true,
            desync_port: 443,
            only_outbound: true,
            stats_print_interval: std::time::Duration::from_secs(60),
            desync: desync_config,
            techniques,
        }
    }
}

/// Парсит имя техники в DesyncTechnique.
fn parse_technique(name: &str) -> Option<crate::desync::DesyncTechnique> {
    use crate::desync::DesyncTechnique::*;
    match name {
        "MultiSplit" => Some(MultiSplit),
        "MultiDisorder" => Some(MultiDisorder),
        "FakeDataSplit" => Some(FakeDataSplit),
        "FakeSni" => Some(FakeSni),
        "OobInjection" => Some(OobInjection),
        "BadChecksum" => Some(BadChecksum),
        "TtlManipulation" => Some(TtlManipulation),
        "FragOverlap" => Some(FragOverlap),
        "TlsRecordFrag" => Some(TlsRecordFrag),
        "TlsRecordPad" => Some(TlsRecordPad),
        "Disorder" => Some(Disorder),
        "SynData" => Some(SynData),
        "MssClamp" => Some(MssClamp),
        "AckSuppress" => Some(AckSuppress),
        "PktReorder" => Some(PktReorder),
        "RstSelective" => Some(RstSelective),
        "WinScaleManip" => Some(WinScaleManip),
        "H2SettingsFlood" => Some(H2SettingsFlood),
        "H2RstPadding" => Some(H2RstPadding),
        "QuicBlocking" => Some(QuicBlocking),
        "QuicVersionDowngrade" => Some(QuicVersionDowngrade),
        "ChaCha20" => Some(ChaCha20),
        "XorFirst" => Some(XorFirst),
        _ => None,
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            doh_url: default_doh_url(),
            dot_addr: default_dot_addr(),
            cache_ttl: default_cache_ttl(),
            doh_persistent: true,
            dns_ip_overrides: Vec::new(),
            doh_pins: Vec::new(),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: default_api_port(),
            api_key: default_api_key(),
            enabled: true,
        }
    }
}

impl Default for WindivertConfig {
    fn default() -> Self {
        Self {
            filter: default_filter(),
            queue_length: default_queue_len(),
            queue_time: default_queue_time(),
        }
    }
}

impl Config {
    /// Загружает конфигурацию из файла.
    /// Если файл не существует — создаёт с настройками по умолчанию.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = toml::from_str(&content)?;
            debug!("Config loaded from {}", path.display());
            Ok(config)
        } else {
            let config = Config::default();
            config.save(path)?;
            debug!("Default config saved to {}", path.display());
            Ok(config)
        }
    }

    /// Сохраняет конфигурацию в файл.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        debug!("Config saved to {}", path.display());
        Ok(())
    }

    /// Создаёт конфиг из TOML строки (для тестов).
    pub fn from_toml(toml_str: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(toml_str)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.api.port, 11337);
        assert!(config.api.enabled);
        assert!(config.dns.cache_ttl >= 60);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("doh_url"));
        assert!(toml_str.contains("api_key"));
    }

    #[test]
    fn test_config_deserialization() {
        let toml_str = r#"
[api]
port = 12345
enabled = true

[dns]
cache_ttl = 600

[windivert]
queue_length = 4096
"#;
        let config = Config::from_toml(toml_str).unwrap();
        assert_eq!(config.api.port, 12345);
        assert_eq!(config.dns.cache_ttl, 600);
        assert_eq!(config.windivert.queue_length, 4096);
    }

    #[test]
    fn test_api_key_generation() {
        let config1 = Config::default();
        let config2 = Config::default();
        // Each instance generates a unique key
        assert_ne!(config1.api.api_key, config2.api.api_key);
    }
}
