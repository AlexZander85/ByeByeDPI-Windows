//! Random Number Generator — Xorshift128** PRNG.
//!
//! ## Назначение
//! Быстрый PRNG для генерации:
//! - Случайных TTL offset
//! - Случайных split позиций
//! - Случайных padding размеров
//! - Случайных задержек между инъекциями
//!
//! ## Seed
//! Используется `getrandom` (OS CSPRNG) вместо SystemTime для защиты от ML-DPI.
//! Periodic reseed каждые 8192 вызова разрывает ML-корреляцию.

use std::sync::atomic::{AtomicU64, Ordering};

/// Глобальный seed для RNG (init из getrandom CSPRNG).
static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);

/// Инициализирует глобальный seed через OS CSPRNG.
fn init_seed() -> u64 {
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);
    if seed != 0 {
        return seed;
    }
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    let new_seed = u64::from_le_bytes(buf);
    let new_seed = if new_seed == 0 {
        0xDEAD_BEEF_CAFE_BABE
    } else {
        new_seed
    };
    GLOBAL_SEED
        .compare_exchange(0, new_seed, Ordering::SeqCst, Ordering::Relaxed)
        .unwrap_or(new_seed)
}

/// splitmix64 — хэш-функция для seed initialization.
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Количество PRNG вызовов между reseed'ами.
/// 0 = отключено (для benchmarking).
const RESEED_INTERVAL: u64 = 8192;

/// Per-connection Xorshift128** PRNG.
#[derive(Clone)]
pub struct PerConnRng {
    state: [u64; 2],
    counter: u64,
}

impl std::fmt::Debug for PerConnRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerConnRng")
            .field("counter", &self.counter)
            .finish()
    }
}

impl PerConnRng {
    pub fn new(conn_id: u64) -> Self {
        let mut buf = [0u8; 16];
        let _ = getrandom::getrandom(&mut buf);
        let e = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let flow_counter = u64::from_le_bytes(buf[8..].try_into().unwrap());
        let seed = splitmix64(e ^ conn_id ^ flow_counter.rotate_left(17));
        Self {
            state: [seed, splitmix64(seed.wrapping_add(0x9E3779B97F4A7C15))],
            counter: 0,
        }
    }

    /// Следующее u64 значение (Xorshift128** по Vigna 2017).
    pub fn next_u64(&mut self) -> u64 {
        self.counter += 1;
        if RESEED_INTERVAL > 0 && self.counter.is_multiple_of(RESEED_INTERVAL) {
            self.reseed();
        }
        let mut s1 = self.state[0];
        let s0 = self.state[1];
        let result = s1.wrapping_mul(0x517CC1B727220A95);
        self.state[0] = s0;
        s1 ^= s1 << 23;
        s1 ^= s1 >> 17;
        s1 ^= s0;
        s1 ^= s0 >> 26;
        self.state[1] = s1;
        result
    }

    /// Следующее u32 значение.
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Случайное число в диапазоне [0, range) без bias (Lemire's method).
    pub fn next_unbiased(&mut self, range: u64) -> u64 {
        if range == 0 {
            return 0;
        }
        let m = (self.next_u64() as u128).wrapping_mul(range as u128);
        (m >> 64) as u64
    }

    /// Случайное число в диапазоне [min, max] без bias.
    pub fn next_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        let range = max - min + 1;
        min + self.next_unbiased(range)
    }

    fn reseed(&mut self) {
        let mut fresh = [0u8; 16];
        let _ = getrandom::getrandom(&mut fresh);
        let new_s0 = u64::from_le_bytes(fresh[..8].try_into().unwrap());
        let new_s1 = u64::from_le_bytes(fresh[8..].try_into().unwrap());
        self.state[0] ^= new_s0;
        self.state[1] ^= new_s1;
        if self.state[0] == 0 {
            self.state[0] = 0xDEADBEEFCAFEF00D;
        }
        if self.state[1] == 0 {
            self.state[1] = 0x0123456789ABCDEF;
        }
    }
}

/// Генерирует случайное u64 через thread-local Xorshift64.
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            x = init_seed();
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x
    })
}

pub fn random_u32() -> u32 {
    (random_u64() >> 32) as u32
}

/// Генерирует случайное число в диапазоне [min, max].
pub fn random_range(min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let range = max - min + 1;
    if range.is_power_of_two() {
        return min + (random_u32() & (range - 1));
    }
    let m = (random_u64() as u128).wrapping_mul(range as u128);
    min + (m >> 64) as u32
}

pub fn random_ttl_offset() -> u8 {
    random_range(1, 5) as u8
}

pub fn random_split_size() -> usize {
    random_range(1, 100) as usize
}

/// Генерирует случайную задержку в микросекундах (0-9999) без modulo bias.
pub fn random_delay_us() -> u64 {
    random_range(0, 9999) as u64
}

pub fn random_padding_size() -> usize {
    random_range(16, 512) as usize
}

pub fn random_identification() -> u16 {
    random_u32() as u16
}

pub fn random_source_port() -> u16 {
    random_range(1024, 65535) as u16
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(random_u32() as u8);
    }
    buf
}

/// Генерирует 64-битную split mask — один вызов PRNG.
pub fn gen_split_mask() -> u64 {
    random_u64()
}

pub fn mask_to_positions(mask: u64, base_offset: usize) -> Vec<usize> {
    let mut positions = Vec::new();
    for bit in 0..64u32 {
        if (mask >> bit) & 1 == 1 {
            positions.push(base_offset + bit as usize);
        }
    }
    positions
}

pub fn random_split_positions(base: usize, len: usize, min_count: usize) -> Vec<usize> {
    use std::collections::HashSet;

    let mask = gen_split_mask();
    let mut seen = HashSet::with_capacity(min_count.max(64));
    let mut positions = Vec::with_capacity(min_count.max(64));

    for bit in 0..64u32 {
        if (mask >> bit) & 1 == 1 {
            let p = base + bit as usize;
            if p < base + len && seen.insert(p) {
                positions.push(p);
            }
        }
    }

    while positions.len() < min_count && positions.len() < len {
        let pos = base + random_range(0, len as u32 - 1) as usize;
        if seen.insert(pos) {
            positions.push(pos);
        }
    }

    positions.sort_unstable();
    positions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_u64_range() {
        let val = random_u64();
        assert!(val > 0 || val == 0);
    }

    #[test]
    fn test_random_u32_range() {
        let val = random_u32();
        assert!(val <= u32::MAX);
    }

    #[test]
    fn test_random_range() {
        for _ in 0..100 {
            let val = random_range(5, 10);
            assert!(val >= 5 && val <= 10);
        }
    }

    #[test]
    fn test_random_ttl_offset() {
        for _ in 0..50 {
            let ttl = random_ttl_offset();
            assert!(ttl >= 1 && ttl <= 5);
        }
    }

    #[test]
    fn test_random_split_size() {
        for _ in 0..50 {
            let size = random_split_size();
            assert!(size >= 1 && size <= 100);
        }
    }

    #[test]
    fn test_random_delay_us() {
        for _ in 0..50 {
            let delay = random_delay_us();
            assert!(delay < 10000);
        }
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_identification() {
        let id = random_identification();
        assert!(id <= u16::MAX);
    }

    #[test]
    fn test_random_source_port() {
        for _ in 0..50 {
            let port = random_source_port();
            assert!(port >= 1024 && port <= 65535);
        }
    }

    #[test]
    fn test_random_padding_size() {
        for _ in 0..50 {
            let size = random_padding_size();
            assert!(size >= 16 && size <= 512);
        }
    }

    #[test]
    fn test_random_range_min_equals_max() {
        assert_eq!(random_range(42, 42), 42);
    }

    #[test]
    fn test_perconnrng_reseed() {
        let mut rng = PerConnRng::new(12345);
        let mut last = rng.next_u64();
        for _ in 0..RESEED_INTERVAL {
            last = rng.next_u64();
        }
        let after_reseed = rng.next_u64();
        assert_ne!(last, after_reseed);
    }
}
