//! Connection tracking — отслеживание состояния TCP/UDP соединений.

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConnKey {
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    pub client_isn: u32,
    pub server_isn: u32,
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_ack: u32,
    pub server_ack: u32,
    pub rtt_us: u64,
    pub state: ConnState,
    pub desync_applied: bool,
    /// DSCP per-connection: фиксированное значение для всех пакетов соединения
    pub dscp_spoof: u8,
    pub strategy_id: u32,
    pub last_activity: Instant,
    pub dup_ack_count: u32,
    pub rng: Option<crate::desync::rand::PerConnRng>,
}

#[derive(Clone, Debug)]
pub struct Conntrack {
    inner: Arc<ConntrackInner>,
}

#[derive(Debug)]
struct ConntrackInner {
    map: DashMap<ConnKey, ConntrackEntry>,
    gc_interval: Duration,
    total_created: AtomicU64,
    active_count: AtomicU64,
}

impl Conntrack {
    pub fn new(gc_interval: Duration) -> Self {
        Self {
            inner: Arc::new(ConntrackInner {
                map: DashMap::new(),
                gc_interval,
                total_created: AtomicU64::new(0),
                active_count: AtomicU64::new(0),
            }),
        }
    }

    /// Вставляет или обновляет запись — использует Entry API (один shard lock).
    /// Не перезаписывает существующий entry — только обновляет last_activity.
    pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
        use dashmap::mapref::entry::Entry;
        match self.inner.map.entry(key) {
            Entry::Vacant(e) => {
                e.insert(entry);
                self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                self.inner.active_count.fetch_add(1, Ordering::Relaxed);
            }
            Entry::Occupied(mut e) => {
                e.get_mut().last_activity = Instant::now();
            }
        }
    }

    pub fn get(
        &self,
        key: &ConnKey,
    ) -> Option<dashmap::mapref::one::Ref<'_, ConnKey, ConntrackEntry>> {
        self.inner.map.get(key)
    }

    pub fn get_mut(
        &self,
        key: &ConnKey,
    ) -> Option<dashmap::mapref::one::RefMut<'_, ConnKey, ConntrackEntry>> {
        self.inner.map.get_mut(key)
    }

    pub fn remove(&self, key: &ConnKey) -> Option<(ConnKey, ConntrackEntry)> {
        let result = self.inner.map.remove(key);
        if result.is_some() {
            self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    pub fn contains(&self, key: &ConnKey) -> bool {
        self.inner.map.contains_key(key)
    }

    /// Обновление SEQ — расширенный delta limit (2^30 вместо 65535).
    pub fn update_seq_monotonic(&self, key: &ConnKey, seq: u32, ack: u32) {
        if let Some(mut entry) = self.inner.map.get_mut(key) {
            let delta = seq.wrapping_sub(entry.client_seq);
            if delta == 0 {
                entry.dup_ack_count = entry.dup_ack_count.saturating_add(1);
            } else if delta < (1u32 << 30) {
                entry.client_seq = seq;
                entry.dup_ack_count = 0;
            }
            entry.client_ack = ack;
            entry.last_activity = Instant::now();
        }
    }

    pub fn insert(&self, key: ConnKey, entry: ConntrackEntry) {
        self.upsert(key, entry);
    }

    /// GC: удаление stale entry (полный итератор).
    pub fn gc(&self, max_idle: Duration) {
        let now = Instant::now();
        let before = self.inner.map.len();
        self.inner.map.retain(|_, entry| {
            let active = now.duration_since(entry.last_activity) < max_idle;
            if !active {
                self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
            }
            active
        });
        let after = self.inner.map.len();
        if before != after {
            debug!("Conntrack GC: {} → {} entries", before, after);
        }
    }

    /// Incremental GC — обрабатывает записи с time budget ≤1ms.
    /// Использует безопасный API DashMap (iter + remove).
    pub fn gc_incremental(&self, max_idle: Duration) {
        let deadline = Instant::now() + Duration::from_millis(1);
        let mut evicted = 0u64;

        // Собираем ключи для удаления, Respect time budget
        let to_remove: Vec<ConnKey> = self
            .inner
            .map
            .iter()
            .take_while(|_| Instant::now() <= deadline)
            .filter(|r| r.value().last_activity.elapsed() > max_idle)
            .map(|r| *r.key())
            .collect();

        for key in to_remove {
            self.inner.map.remove(&key);
            evicted += 1;
        }

        if evicted > 0 {
            self.inner
                .active_count
                .fetch_sub(evicted, Ordering::Relaxed);
            debug!("Conntrack GC incremental: evicted {} entries", evicted);
        }
    }

    pub async fn gc_loop(&self) {
        let mut interval = tokio::time::interval(self.inner.gc_interval);
        loop {
            interval.tick().await;
            self.gc_incremental(Duration::from_secs(120));
        }
    }

    pub fn active_count(&self) -> u64 {
        self.inner.active_count.load(Ordering::Relaxed)
    }

    pub fn total_created(&self) -> u64 {
        self.inner.total_created.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Vec<(ConnKey, ConntrackEntry)> {
        self.inner
            .map
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect()
    }
}

impl Default for Conntrack {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn test_key() -> ConnKey {
        ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            54321,
            443,
        )
    }

    fn test_entry() -> ConntrackEntry {
        ConntrackEntry {
            client_isn: 1000,
            server_isn: 2000,
            client_seq: 1001,
            server_seq: 2001,
            client_ack: 2001,
            server_ack: 1001,
            rtt_us: 50000,
            state: ConnState::Established,
            desync_applied: true,
            dscp_spoof: 0,
            strategy_id: 42,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        assert!(ct.contains(&key));
        assert_eq!(ct.get(&key).unwrap().strategy_id, 42);
    }

    #[test]
    fn test_remove() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        assert!(ct.remove(&key).is_some());
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_removes_stale() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.last_activity = Instant::now() - Duration::from_secs(300);
        ct.insert(key, entry);
        ct.gc(Duration::from_secs(120));
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_keeps_recent() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        ct.gc(Duration::from_secs(120));
        assert!(ct.contains(&key));
    }
}
