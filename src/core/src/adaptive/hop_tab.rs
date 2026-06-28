//! HopTab — Auto-TTL Cache for fake ClientHello.
//!
//! Direct-mapped hash table для O(1) lookup вместо O(256) linear scan.

use std::sync::atomic::{AtomicU64, Ordering};

const HOPTAB_SIZE: usize = 4096;
const HOPTAB_MASK: usize = HOPTAB_SIZE - 1;

fn pack_entry(ip: u32, hops: u8) -> u64 {
    (ip as u64) | ((hops as u64) << 32)
}

fn unpack_entry(val: u64) -> (u32, u8) {
    let ip = val as u32;
    let hops = (val >> 32) as u8;
    (ip, hops)
}

pub struct HopTab {
    cache: [AtomicU64; HOPTAB_SIZE],
}

impl std::fmt::Debug for HopTab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopTab").field("len", &self.len()).finish()
    }
}

impl HopTab {
    pub fn new() -> Self {
        Self {
            cache: [const { AtomicU64::new(0) }; HOPTAB_SIZE],
        }
    }

    pub fn estimate(recv_ttl: u8) -> u8 {
        let init_ttl: u8 = if recv_ttl <= 64 {
            64
        } else if recv_ttl <= 128 {
            128
        } else {
            255
        };
        init_ttl - recv_ttl.min(init_ttl)
    }

    pub fn ip_to_u32(ip: &std::net::Ipv4Addr) -> u32 {
        ip.to_bits()
    }

    fn hash(ip: u32) -> usize {
        let mut h = ip.wrapping_mul(0x01000193);
        h ^= h >> 16;
        (h as usize) & HOPTAB_MASK
    }

    pub fn insert(&self, dst_ip: u32, hops: u8) {
        let idx = Self::hash(dst_ip);
        self.cache[idx].store(pack_entry(dst_ip, hops), Ordering::Relaxed);
    }

    pub fn get(&self, dst_ip: u32) -> Option<u8> {
        let idx = Self::hash(dst_ip);
        let (ip, hops) = unpack_entry(self.cache[idx].load(Ordering::Relaxed));
        if ip == dst_ip {
            Some(hops)
        } else {
            None
        }
    }

    pub fn fake_ttl(&self, dst_ip: u32) -> Option<u8> {
        self.get(dst_ip).map(|hops| {
            if hops <= 2 {
                return 0;
            }
            (hops - 1).clamp(2, 64)
        })
    }

    pub fn fake_ttl_for_ip(&self, ip: &std::net::Ipv4Addr) -> Option<u8> {
        self.fake_ttl(Self::ip_to_u32(ip))
    }

    pub fn observe(&self, ip: u32, recv_ttl: u8) {
        let hops = Self::estimate(recv_ttl);
        self.insert(ip, hops);
    }

    pub fn estimate_udp(recv_ttl: u8, src_port: u16) -> (u32, u8) {
        let hops = Self::estimate(recv_ttl);
        let key = (src_port as u32) << 16 | (recv_ttl as u32);
        (key, hops)
    }

    pub fn len(&self) -> usize {
        self.cache
            .iter()
            .filter(|e| unpack_entry(e.load(Ordering::Relaxed)).0 != 0)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot(&self) -> Vec<(u32, u8)> {
        self.cache
            .iter()
            .map(|e| unpack_entry(e.load(Ordering::Relaxed)))
            .filter(|(ip, _)| *ip != 0)
            .collect()
    }
}

impl Default for HopTab {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_estimate_linux() {
        assert_eq!(HopTab::estimate(51), 13);
        assert_eq!(HopTab::estimate(64), 0);
    }

    #[test]
    fn test_estimate_windows() {
        assert_eq!(HopTab::estimate(119), 9);
        assert_eq!(HopTab::estimate(128), 0);
    }

    #[test]
    fn test_insert_get() {
        let tab = HopTab::new();
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        tab.insert(ip, 13);
        assert_eq!(tab.get(ip), Some(13));
    }

    #[test]
    fn test_fake_ttl() {
        let tab = HopTab::new();
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        tab.insert(ip, 13);
        assert_eq!(tab.fake_ttl(ip), Some(12));
    }
}
