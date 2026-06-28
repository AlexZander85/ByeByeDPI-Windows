//! Per-Rule Config Override (из SpoofDPI).
//!
//! Позволяет каждому домену или CIDR-блоку переопределять
//! параметры desync engine: split-mode, fake-count, disorder, ttl_offset и т.д.
//!
//! ## Приоритет
//! 1. Per-domain override (самый высокий)
//! 2. Per-CIDR override
//! 3. Глобальные настройки (DesyncConfig)
//!
//! ## Формат TOML
//! ```toml
//! [[rules]]
//! domain = "*.google.com"
//! split_size = 2
//! disorder = true
//! ttl_offset = 3
//!
//! [[rules]]
//! cidr = "142.250.0.0/16"
//! fake_count = 5
//! skip = true
//! ```

use crate::desync::DesyncConfig;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Per-rule override параметров.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleOverride {
    /// Доменный паттерн (wildcard: `*`, `**`).
    #[serde(default)]
    pub domain: Option<String>,
    /// CIDR блок.
    #[serde(default)]
    pub cidr: Option<String>,
    /// Переопределение split_size.
    #[serde(default)]
    pub split_size: Option<usize>,
    /// Переопределение split_count.
    #[serde(default)]
    pub split_count: Option<usize>,
    /// Включить disorder (TTL=1 для lazy сегментов).
    #[serde(default)]
    pub disorder: Option<bool>,
    /// Переопределение fake TTL offset.
    #[serde(default)]
    pub ttl_offset: Option<u8>,
    /// Количество fake пакетов перед реальным.
    #[serde(default)]
    pub fake_count: Option<usize>,
    /// Пропустить desync для этого домена/CIDR.
    #[serde(default)]
    pub skip: Option<bool>,
    /// Задержка между инъекциями (мкс).
    #[serde(default)]
    pub inject_delay_us: Option<u64>,
}

/// Результат применения override к DesyncConfig.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Итоговый DesyncConfig (с учётом override).
    pub desync: DesyncConfig,
    /// Нужно ли пропустить desync (skip=true).
    pub skip: bool,
    /// Имя matched rule (для отладки).
    pub matched_rule: Option<String>,
}

/// Реестр per-rule overrides.
pub struct RuleRegistry {
    rules: Vec<Arc<RuleOverride>>,
}

impl std::fmt::Debug for RuleRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleRegistry")
            .field("len", &self.rules.len())
            .finish()
    }
}

impl RuleRegistry {
    /// Создаёт пустой реестр.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Загружает правила из TOML.
    pub fn from_toml(toml_str: &str) -> anyhow::Result<Self> {
        let rules: Vec<RuleOverride> = toml::from_str(toml_str)?;
        Ok(Self {
            rules: rules.into_iter().map(Arc::new).collect(),
        })
    }

    /// Добавляет правило.
    pub fn push(&mut self, rule: RuleOverride) {
        self.rules.push(Arc::new(rule));
    }

    /// Ищет matching rule для домена/IP.
    ///
    /// Приоритет: domain match > cidr match > none.
    fn find_match(&self, domain: Option<&str>, ip: Option<Ipv4Addr>) -> Option<&RuleOverride> {
        let mut best_domain: Option<&RuleOverride> = None;
        let mut best_cidr: Option<&RuleOverride> = None;

        for rule in &self.rules {
            // Проверяем domain match
            if let Some(ref pattern) = rule.domain {
                if let Some(dom) = domain {
                    if domain_matches(dom, pattern) && best_domain.is_none() {
                        best_domain = Some(rule.as_ref());
                    }
                }
            }

            // Проверяем CIDR match
            if let Some(ref cidr_str) = rule.cidr {
                if let Some(ip) = ip {
                    if cidr_matches(ip, cidr_str) && best_cidr.is_none() {
                        best_cidr = Some(rule.as_ref());
                    }
                }
            }
        }

        // Domain приоритетнее CIDR
        best_domain.or(best_cidr)
    }

    /// Применяет override к базовому DesyncConfig.
    pub fn resolve(
        &self,
        base: &DesyncConfig,
        domain: Option<&str>,
        ip: Option<Ipv4Addr>,
    ) -> ResolvedConfig {
        let rule = match self.find_match(domain, ip) {
            Some(r) => r,
            None => {
                return ResolvedConfig {
                    desync: base.clone(),
                    skip: false,
                    matched_rule: None,
                };
            }
        };

        let mut desync = base.clone();

        if let Some(v) = rule.split_size {
            desync.split_size = v;
        }
        if let Some(v) = rule.split_count {
            desync.split_count = v;
        }
        if let Some(v) = rule.ttl_offset {
            desync.fake_ttl_offset = v;
        }
        if let Some(v) = rule.inject_delay_us {
            desync.inject_delay_us = v;
        }

        ResolvedConfig {
            desync,
            skip: rule.skip.unwrap_or(false),
            matched_rule: rule.domain.clone().or_else(|| rule.cidr.clone()),
        }
    }

    /// Количество правил.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Пуст ли реестр.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Проверяет совпадение домена с wildcard-паттерном.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    let dom_labels: Vec<&str> = domain.split('.').rev().collect();
    let pat_labels: Vec<&str> = pattern.split('.').rev().collect();
    domain_matches_recursive(&dom_labels, &pat_labels, 0, 0)
}

fn domain_matches_recursive(dom: &[&str], pat: &[&str], di: usize, pi: usize) -> bool {
    if pi >= pat.len() {
        return di >= dom.len();
    }
    if di >= dom.len() {
        return false;
    }

    match pat[pi] {
        "**" => {
            // Multi-level wildcard: пробуем пропустить 1..=N уровней
            for skip in 0..=(dom.len() - di) {
                if domain_matches_recursive(dom, pat, di + skip, pi + 1) {
                    return true;
                }
            }
            false
        }
        "*" => {
            // Single-level wildcard: пропускаем один уровень
            domain_matches_recursive(dom, pat, di + 1, pi + 1)
        }
        p => p.eq_ignore_ascii_case(dom[di]) && domain_matches_recursive(dom, pat, di + 1, pi + 1),
    }
}

/// Проверяет принадлежность IP к CIDR-блоку.
fn cidr_matches(ip: Ipv4Addr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u32 = match parts[1].parse() {
        Ok(len) => len,
        Err(_) => return false,
    };

    if prefix_len > 32 {
        return false;
    }

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };

    let ip_bits = u32::from_be_bytes(ip.octets());
    let net_bits = u32::from_be_bytes(network.octets());

    (ip_bits & mask) == (net_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_exact() {
        assert!(domain_matches("www.google.com", "www.google.com"));
        assert!(!domain_matches("mail.google.com", "www.google.com"));
    }

    #[test]
    fn test_domain_single_wildcard() {
        assert!(domain_matches("www.google.com", "*.google.com"));
        assert!(domain_matches("mail.google.com", "*.google.com"));
        assert!(!domain_matches("google.com", "*.google.com"));
    }

    #[test]
    fn test_domain_multi_wildcard() {
        assert!(domain_matches("mail.ru", "**.ru"));
        assert!(domain_matches("www.mail.ru", "**.ru"));
        assert!(!domain_matches("example.com", "**.ru"));
    }

    #[test]
    fn test_cidr_match() {
        assert!(cidr_matches(
            "142.250.185.46".parse().unwrap(),
            "142.250.0.0/16"
        ));
        assert!(cidr_matches(
            "142.250.0.1".parse().unwrap(),
            "142.250.0.0/16"
        ));
        assert!(!cidr_matches(
            "142.251.0.1".parse().unwrap(),
            "142.250.0.0/16"
        ));
    }

    #[test]
    fn test_cidr_exact_32() {
        assert!(cidr_matches("8.8.8.8".parse().unwrap(), "8.8.8.8/32"));
        assert!(!cidr_matches("8.8.8.9".parse().unwrap(), "8.8.8.8/32"));
    }

    #[test]
    fn test_registry_resolve() {
        let mut registry = RuleRegistry::new();
        registry.push(RuleOverride {
            domain: Some("*.google.com".into()),
            split_size: Some(2),
            disorder: Some(true),
            ..Default::default()
        });
        registry.push(RuleOverride {
            cidr: Some("142.250.0.0/16".into()),
            skip: Some(true),
            ..Default::default()
        });

        let base = DesyncConfig::default();

        // Google domain → override
        let resolved = registry.resolve(&base, Some("www.google.com"), None);
        assert_eq!(resolved.desync.split_size, 2);
        assert!(!resolved.skip);

        // CIDR match → skip
        let resolved = registry.resolve(&base, None, Some("142.250.1.1".parse().unwrap()));
        assert!(resolved.skip);

        // No match → defaults
        let resolved = registry.resolve(&base, Some("example.com"), None);
        assert_eq!(resolved.desync.split_size, 1);
        assert!(!resolved.skip);
    }

    #[test]
    fn test_registry_len() {
        let mut registry = RuleRegistry::new();
        assert_eq!(registry.len(), 0);
        registry.push(RuleOverride {
            domain: Some("a.com".into()),
            ..Default::default()
        });
        assert_eq!(registry.len(), 1);
    }
}
