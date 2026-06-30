//! Accumulator — 24h temporal accumulation + eTLD+1 family expansion.
//!
//! Методика (из Ladon):
//! 1. Per-domain hot state с 24h TTL
//! 2. Re-probe каждые 5 минут
//! 3. 50+ blocked verdicts в 24h окне → permanent cache
//! 4. eTLD+1 expansion: 10+ поддоменов заблокированы → весь family
//!
//! Источники:
//! - [Ladon](https://github.com/nickspaargaren/ladon): 24h accumulation + eTLD+1

use crate::probe::classifier::ProbeVerdict;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Hot entry: данные для одного домена в 24h окне.
#[derive(Debug)]
struct HotEntry {
    blocked_count: AtomicU32,
    total_probes: AtomicU32,
    #[allow(dead_code)]
    first_seen: Instant,
    last_probe: Instant,
}

/// Family entry: eTLD+1 → набор поддоменов.
#[derive(Debug, Clone)]
struct FamilyEntry {
    subdomains: Vec<String>,
    blocked_count: u32,
}

/// Вердикт accumulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccumulatedVerdict {
    pub domain: String,
    pub blocked: bool,
    pub confidence: f64,
    pub should_tunnel: bool,
    pub blocked_count: u32,
    pub total_probes: u32,
    pub is_family: bool,
}

/// Accumulator — хранение истории verdict'ов с 24h окном.
pub struct Accumulator {
    hot_entries: Arc<DashMap<String, Arc<HotEntry>>>,
    cache_entries: Arc<DashSet<String>>,
    family_entries: Arc<DashMap<String, FamilyEntry>>,
    promote_threshold: u32,
    family_threshold: usize,
    hot_ttl: Duration,
}

use dashmap::DashSet;

impl Accumulator {
    pub fn new(promote_threshold: u32, family_threshold: usize, hot_ttl: Duration) -> Self {
        Self {
            hot_entries: Arc::new(DashMap::new()),
            cache_entries: Arc::new(DashSet::new()),
            family_entries: Arc::new(DashMap::new()),
            promote_threshold,
            family_threshold,
            hot_ttl,
        }
    }

    /// Записать результат probe для домена.
    pub fn record(&self, domain: &str, verdict: &ProbeVerdict) {
        let is_blocked = *verdict == ProbeVerdict::Blocked;

        // Update hot entry
        let entry = self
            .hot_entries
            .entry(domain.to_string())
            .or_insert_with(|| {
                Arc::new(HotEntry {
                    blocked_count: AtomicU32::new(0),
                    total_probes: AtomicU32::new(0),
                    first_seen: Instant::now(),
                    last_probe: Instant::now(),
                })
            });

        entry.total_probes.fetch_add(1, Ordering::Relaxed);
        if is_blocked {
            entry.blocked_count.fetch_add(1, Ordering::Relaxed);
        }

        // Check for promotion to cache
        let blocked = entry.blocked_count.load(Ordering::Relaxed);
        let total = entry.total_probes.load(Ordering::Relaxed);
        if total >= self.promote_threshold && blocked * 100 / total >= 80 {
            self.cache_entries.insert(domain.to_string());
        }

        // Update eTLD+1 family
        if let Some(etld1) = extract_etld1(domain) {
            let mut family =
                self.family_entries
                    .entry(etld1.clone())
                    .or_insert_with(|| FamilyEntry {
                        subdomains: Vec::new(),
                        blocked_count: 0,
                    });

            if is_blocked && !family.subdomains.contains(&domain.to_string()) {
                family.subdomains.push(domain.to_string());
                family.blocked_count += 1;
            }
        }
    }

    /// Проверить, нужно ли туннелевать этот домен.
    pub fn should_tunnel(&self, domain: &str) -> bool {
        // Check cache (permanent)
        if self.cache_entries.contains(domain) {
            return true;
        }

        // Check family expansion
        if let Some(etld1) = extract_etld1(domain) {
            if let Some(family) = self.family_entries.get(&etld1) {
                if family.blocked_count >= self.family_threshold as u32 {
                    return true;
                }
            }
        }

        // Check hot entry
        if let Some(entry) = self.hot_entries.get(domain) {
            let blocked = entry.blocked_count.load(Ordering::Relaxed);
            let total = entry.total_probes.load(Ordering::Relaxed);
            if total >= 5 && blocked * 100 / total >= 80 {
                return true;
            }
        }

        false
    }

    /// Получить вердикт для домена.
    pub fn get_verdict(&self, domain: &str) -> AccumulatedVerdict {
        let should_tunnel = self.should_tunnel(domain);

        let (blocked_count, total_probes) = if let Some(entry) = self.hot_entries.get(domain) {
            (
                entry.blocked_count.load(Ordering::Relaxed),
                entry.total_probes.load(Ordering::Relaxed),
            )
        } else {
            (0, 0)
        };

        let confidence = if total_probes > 0 {
            blocked_count as f64 / total_probes as f64
        } else {
            0.0
        };

        let is_family = extract_etld1(domain)
            .and_then(|etld1| self.family_entries.get(&etld1))
            .is_some_and(|f| f.blocked_count >= self.family_threshold as u32);

        AccumulatedVerdict {
            domain: domain.to_string(),
            blocked: should_tunnel,
            confidence,
            should_tunnel,
            blocked_count,
            total_probes,
            is_family,
        }
    }

    /// Очистить устаревшие записи.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.hot_entries
            .retain(|_, entry| now.duration_since(entry.last_probe) < self.hot_ttl);
    }

    /// Количество горячих записей.
    pub fn hot_count(&self) -> usize {
        self.hot_entries.len()
    }

    /// Количество кэшированных записей.
    pub fn cache_count(&self) -> usize {
        self.cache_entries.len()
    }

    /// Количество семей.
    pub fn family_count(&self) -> usize {
        self.family_entries.len()
    }
}

/// Извлечь eTLD+1 из домена.
fn extract_etld1(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.rsplitn(3, '.').collect();
    if parts.len() >= 2 {
        Some(format!("{}.{}", parts[1], parts[0]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_etld1() {
        assert_eq!(extract_etld1("sub.example.com"), Some("example.com".into()));
        assert_eq!(extract_etld1("example.com"), Some("example.com".into()));
        assert_eq!(extract_etld1("com"), None);
    }

    #[test]
    fn test_accumulator_record_and_verdict() {
        let acc = Accumulator::new(3, 2, Duration::from_secs(86400));

        // Record 5 blocked verdicts
        for _ in 0..5 {
            acc.record("test.com", &ProbeVerdict::Blocked);
        }

        let verdict = acc.get_verdict("test.com");
        assert!(verdict.should_tunnel);
        assert_eq!(verdict.blocked_count, 5);
        assert_eq!(verdict.total_probes, 5);
    }

    #[test]
    fn test_accumulator_family_expansion() {
        let acc = Accumulator::new(50, 2, Duration::from_secs(86400));

        // Record blocked for multiple subdomains
        acc.record("a.example.com", &ProbeVerdict::Blocked);
        acc.record("b.example.com", &ProbeVerdict::Blocked);

        // Check family expansion
        assert!(acc.should_tunnel("c.example.com"));
    }

    #[test]
    fn test_accumulator_cleanup() {
        let acc = Accumulator::new(50, 10, Duration::from_millis(1));
        acc.record("test.com", &ProbeVerdict::Blocked);

        std::thread::sleep(Duration::from_millis(5));
        acc.cleanup();

        assert_eq!(acc.hot_count(), 0);
    }
}
