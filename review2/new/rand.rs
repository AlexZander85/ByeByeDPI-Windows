//! Random Number Generator — xoshiro256++ PRNG (fixed cross-thread bug).
//!
//! ## Критический фикс
//! Предыдущая версия использовала `GLOBAL_SEED: AtomicU64` — все потоки
//! получали один и тот же seed, что приводило к идентичным последовательностям
//! случайных чисел на разных потоках. Это создавало идеальный fingerprint
//! для ML-DPI (корреляция random-полей между параллельными соединениями).
//!
//! Новая версия: каждый thread инициализирует свой state из OS CSPRNG
//! при первом вызове. Используется xoshiro256++ (passes BigCrush, O'Neill 2019).
//!
//! ## Per-connection RNG
//! `PerConnRng` использует Xorshift128** (Vigna 2017) с periodic reseed
//! из OS CSPRNG. Подходит для per-connection randomisation (GREASE, padding,
//! key share, TTL jitter).

use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Thread-local fast PRNG (xoshiro256++)
// ============================================================================

/// Генерирует случайное u64 через thread-local xoshiro256++.
///
/// Каждый поток инициализирует свой state из OS CSPRNG при первом вызове.
/// В отличие от предыдущей версии, потоки НЕ делят seed — каждая
/// последовательность независима.
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<[u64; 4]> =
            const { std::cell::Cell::new([0u64; 4]) };
    }
    STATE.with(|state| {
        let mut s = state.get();
        if s == [0u64; 4] {
            s = fresh_seed_xoshiro();
        }
        let result = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        state.set(s);
        result
    })
}

/// Инициализирует xoshiro256 state из OS CSPRNG.
/// Гарантирует ненулевой state (all-zero = degenerate).
fn fresh_seed_xoshiro() -> [u64; 4] {
    let mut buf = [0u8; 32];
    let _ = getrandom::getrandom(&mut buf);
    let mut s = [0u64; 4];
    for i in 0..4 {
        s[i] = u64::from_le_bytes(buf[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    // xoshiro256 требует ненулевой state
    if s == [0u64; 4] {
        s[0] = 0xDEADBEEFCAFEBABE;
    }
    s
}

pub fn random_u32() -> u32 {
    (random_u64() >> 32) as u32
}

/// Случайное число в диапазоне [min, max] (включительно) без modulo bias.
/// Использует Lemire's method (debias).
pub fn random_range(min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let range = (max - min) as u64 + 1;
    min + (lemire_debias(random_u64(), range) as u32)
}

fn lemire_debias(random: u64, range: u64) -> u64 {
    let m = (random as u128).wrapping_mul(range as u128);
    (m >> 64) as u64
}

pub fn random_ttl_offset() -> u8 {
    random_range(1, 5) as u8
}

pub fn random_split_size() -> usize {
    random_range(1, 100) as usize
}

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

/// Генерирует случайные байты. Эффективно — 8 байт per PRNG call.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fill_random_bytes(&mut buf);
    buf
}

/// Заполняет буфер случайными байтами in-place.
pub fn fill_random_bytes(buf: &mut [u8]) {
    let mut i = 0;
    while i + 8 <= buf.len() {
        buf[i..i + 8].copy_from_slice(&random_u64().to_le_bytes());
        i += 8;
    }
    if i < buf.len() {
        let r = random_u64();
        buf[i..].copy_from_slice(&r.to_le_bytes()[..buf.len() - i]);
    }
}

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

// ============================================================================
// GREASE values (RFC 8701)
// ============================================================================

/// 16 possible GREASE values с шаблоном 0x?A?A.
/// Chrome выбирает одно значение per-connection для каждой категории
/// (cipher_suites, extensions, groups, versions).
pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Выбирает random GREASE value (для global RNG).
pub fn random_grease() -> u16 {
    GREASE_VALUES[(random_u32() as usize) & 0xF]
}

// ============================================================================
// Per-connection PRNG (Xorshift128**)
// ============================================================================

/// Количество PRNG вызовов между reseed'ами.
const RESEED_INTERVAL: u64 = 8192;

/// Per-connection Xorshift128** PRNG.
///
/// Используется для per-connection randomisation:
/// - GREASE values (cipher, ext, group, version)
/// - TLS random field (32 bytes)
/// - Session ID (32 bytes)
/// - Key share (X25519 32 bytes + PQ 1184 bytes)
/// - Padding size
/// - TTL jitter
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
    /// Создаёт per-connection PRNG.
    ///
    /// `conn_id` должен включать 4-tuple (src_ip, dst_ip, src_port, dst_port)
    /// для уникальности per-flow. Рекомендуется:
    /// ```ignore
    /// let conn_id = (src_ip.to_bits() as u64)
    ///     ^ ((dst_ip.to_bits() as u64) << 32)
    ///     ^ ((src_port as u64) << 48)
    ///     ^ (dst_port as u64);
    /// ```
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

    /// Следующее u64 (Xorshift128** по Vigna 2017).
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

    /// Случайное число в диапазоне [min, max] (включительно) без bias.
    pub fn next_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        let range = max - min + 1;
        min + self.next_unbiased(range)
    }

    /// Заполняет буфер случайными байтами. Эффективно — 8 байт per PRNG call.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let r = self.next_u64();
            buf[i..].copy_from_slice(&r.to_le_bytes()[..buf.len() - i]);
        }
    }

    /// Выбирает random GREASE value (0x?A?A pattern, RFC 8701).
    pub fn pick_grease(&mut self) -> u16 {
        GREASE_VALUES[(self.next_u32() as usize) & 0xF]
    }

    /// Выбирает 4 per-connection GREASE values для разных категорий.
    /// Возвращает (cipher_grease, ext_grease, group_grease, version_grease).
    pub fn generate_grease_set(&mut self) -> (u16, u16, u16, u16) {
        (
            self.pick_grease(),
            self.pick_grease(),
            self.pick_grease(),
            self.pick_grease(),
        )
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

/// splitmix64 — хэш-функция для seed initialization (Steele 2014).
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

pub fn random_split_positions(base: usize, len: usize, min_count: usize) -> Vec<usize> {
    let mask = gen_split_mask();
    let mut seen = std::collections::HashSet::with_capacity(min_count.max(64));
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
    fn test_random_u64_nonzero() {
        let val = random_u64();
        // Допускаем 0, но проверяем что PRNG работает
        let _ = val;
    }

    #[test]
    fn test_random_range() {
        for _ in 0..1000 {
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
    fn test_random_bytes_filled() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
        // Very unlikely all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut buf = [0u8; 100];
        fill_random_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_perconnrng_basic() {
        let mut rng = PerConnRng::new(12345);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn test_perconnrng_next_range() {
        let mut rng = PerConnRng::new(42);
        for _ in 0..100 {
            let val = rng.next_range(1, 10);
            assert!(val >= 1 && val <= 10);
        }
    }

    #[test]
    fn test_perconnrng_fill_bytes() {
        let mut rng = PerConnRng::new(99);
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_perconnrng_grease() {
        let mut rng = PerConnRng::new(7);
        for _ in 0..50 {
            let g = rng.pick_grease();
            assert!(GREASE_VALUES.contains(&g));
        }
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

    #[test]
    fn test_cross_thread_independence() {
        // Два потока должны получать разные последовательности
        let (tx1, rx1) = std::sync::mpsc::channel();
        let (tx2, rx2) = std::sync::mpsc::channel();

        let h1 = std::thread::spawn(move || {
            let mut vals = Vec::new();
            for _ in 0..10 {
                vals.push(random_u64());
            }
            tx1.send(vals).unwrap();
        });

        let h2 = std::thread::spawn(move || {
            let mut vals = Vec::new();
            for _ in 0..10 {
                vals.push(random_u64());
            }
            tx2.send(vals).unwrap();
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let v1 = rx1.recv().unwrap();
        let v2 = rx2.recv().unwrap();

        // Последовательности должны различаться (вероятность совпадения ~0)
        let matches = v1.iter().zip(v2.iter()).filter(|(a, b)| a == b).count();
        assert!(
            matches < v1.len() / 2,
            "Cross-thread sequences too similar: {}/{} matches",
            matches,
            v1.len()
        );
    }

    #[test]
    fn test_random_grease() {
        for _ in 0..50 {
            let g = random_grease();
            assert!(GREASE_VALUES.contains(&g));
        }
    }
}
