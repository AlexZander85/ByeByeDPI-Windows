# План реализации 8 оставшихся MR

Все решения взяты из `review2/meta_review2.md` — эталонные патчи экспертов.

---

## Фаза 1: Очистка мёртвого кода (MR-12, MR-34, MR-18)

### MR-12: Удалить мёртвый `random_split_positions`

**Эталон:** meta_review2.md MR-12 (строки 443-488) — эксперты glm2/claude2 предлагали SmallVec, но exploration показал **0 вызовов** в проекте.
**Файл:** `desync/rand.rs`, строки 307-330
**Действие:** Удалить функцию целиком — мёртвый код.
**Верификация:** `cargo test`, `cargo clippy`

### MR-34: Удалить мёртвый `mask_to_positions`

**Эталон:** meta_review2.md MR-34 (строки 1169-1206) — kimi2 предлагал branchless `trailing_zeros`, но exploration показал **0 вызовов**.
**Файл:** `desync/rand.rs`, строки 133-141
**Действие:** Удалить функцию. Также удалить `gen_split_mask` (строка 129-131) — единственный вызывавший `random_split_positions`.
**Верификация:** `cargo test`, `cargo clippy`

### MR-18: Удалить event_tag модуль

**Эталон:** meta_review2.md MR-18 (строки 657-680) — glm2 (3.5) рекомендовал IP ID/option. Но exploration показал:
- `tag_injected_packet()` — **0 production callers** (мёртвый код)
- `is_injected_packet()` — вызывается в engine/mod.rs:282, но **избыточен** — `set_impostor(true)` в packet_engine.rs:216 уже предотвращает re-capture
- Весь модуль event_tag можно удалить

**Файлы:**
1. Удалить `infra/event_tag.rs`
2. `infra/mod.rs` — удалить `pub mod event_tag;`
3. `engine/mod.rs`:
   - Удалить `use crate::infra::event_tag;`
   - Удалить блок `if self.config.event_tag_enabled && event_tag::is_injected_packet(...)` (строки 282-285)
   - Удалить поле `event_tag_enabled` из `ProcessingConfig` и `Default` impl
4. Найти все создания `ProcessingConfig` и удалить `event_tag_enabled`

**Верификация:** `cargo build`, `cargo test`

---

## Фаза 2: Конкурентность и аллокации (MR-07, MR-10*)

### MR-07: InjectedSeqTracker → DashMap с 5-tuple ключом

**Эталон:** meta_review2.md MR-07 (строки 264-311) — claude2 (C4) + qwen2 (4.3):
```rust
use dashmap::DashMap;

struct InjectedSeqTracker {
    map: DashMap<(u32, u32, u16, u16, u32), Instant>, // 5-tuple + SEQ
    ttl: Duration,
}

impl InjectedSeqTracker {
    fn contains(&self, key: (u32, u32, u16, u16, u32)) -> bool {
        self.map.get(&key).map(|t| t.elapsed() < self.ttl).unwrap_or(false)
    }
    fn insert(&self, key: (u32, u32, u16, u16, u32)) {
        self.map.insert(key, Instant::now());
        // GC асинхронно, не в hot path
    }
}
```

**Файл:** `engine/mod.rs`
**Действия:**
1. Заменить структуру `InjectedSeqTracker` (строки 131-158) на DashMap версию из эталона
2. Обновить поле в `ProcessingPipeline`: `injected_seqs: Arc<InjectedSeqTracker>`
3. Обновить `contains` вызов (строка ~443): передавать `(cp.src_ip.to_bits(), cp.dst_ip.to_bits(), cp.src_port, cp.dst_port, tcp.get_sequence())`
4. Обновить `insert` вызов (строка ~521): аналогично с 5-tuple
5. Добавить async GC через `tokio::spawn` каждые 30 сек

**Верификация:** `cargo test`, добавить тест cross-connection collision

### MR-10*: BytesMut pool для desync/tcp.rs

**Эталон:** meta_review2.md MR-10 (строки 386-416) — glm2 (2.2) + kimi2 (2.2):
```rust
fn build_ip_packet_zc(src: Ipv4Addr, dst: Ipv4Addr, ...) -> bytes::Bytes {
    let total = 20 + payload.len();
    let mut buf = bytes::BytesMut::with_capacity(total);
    // ... fill header inline
    buf.extend_from_slice(payload);
    buf.freeze() // single allocation
}
```

**Файл:** `desync/tcp.rs`
**Действия:**
1. Добавить thread-local buffer pool (строка ~603 в `build_ip_tcp_packet`):
```rust
thread_local! {
    static PACKET_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(1500));
}
```
2. В `build_ip_tcp_packet` (строка 618): заменить `vec![0u8; total_len]` на thread-local buffer
3. Удалить неиспользуемый `TcpSegmentWriter` (строки 32-85)

**Верификация:** `cargo test`, `cargo clippy`

---

## Фаза 3: CSPRNG pool (MR-35)

### MR-35: PerConnRng CSPRNG pool

**Эталон:** meta_review2.md MR-35 (строки 1209-1244) — claude2 (S5):
```rust
static GLOBAL_CSPRNG_POOL: OnceLock<[u64; 4]> = OnceLock::new();

impl PerConnRng {
    pub fn new(conn_id: u64) -> Self {
        let pool = get_csprng_pool();
        let ctr = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let s0 = splitmix64(pool[0] ^ conn_id ^ ctr);
        let s1 = splitmix64(pool[1] ^ ctr.wrapping_add(1));
        Self { state: [s0, s1], counter: 0 }
    }
}
```

**Примечание:** Exploration показал что getrandom на Windows = BCryptGenRandom (non-blocking, ~100ns). При 10K connections/sec = 1ms/sec total — пренебрежимо. **Решение: пропустить для v3.0**, реализовать при необходимости.

---

## Фаза 4: AutoTune wiring (MR-37)

### MR-37: Подключение AutoTune к pipeline

**Эталон:** meta_review2.md MR-37 (строки 1274-1287) — glm2 (4.11): Wiring `detect_dpi_block()` → `AutoTune::record()` + Thompson sampling bandit.

**Файлы:** `engine/mod.rs`, `adaptive/auto_tune.rs`
**Действия:**
1. Добавить `auto_tune: std::sync::Mutex<AutoTune>` в `ProcessingPipeline`
2. В `process_outbound_tls` после `apply_desync_async()`:
   - Запомнить `start = Instant::now()` перед вызовом
   - Вычислить `success = !result.inject.is_empty() || result.modified.is_some()`
   - Вызвать `self.auto_tune.lock().record(strategy_name, success, latency_us)`
3. Добавить метод `get_tuned_config()` — вызывать `tune.recommend()` для получения override параметров
4. Передавать tuned config в `DesyncGroup::apply()`
5. Добавить `should_escalate()` check + warning лог

**Верификация:** `cargo test`, `cargo test auto_tune`, ручная проверка логов

---

## Итого

| MR | Файл(ы) | Решение (эксперт) | Сложность | Время |
|----|---------|-------------------|-----------|-------|
| MR-12 | rand.rs | Удалить dead code | Нет | 5 мин |
| MR-34 | rand.rs | Удалить dead code | Нет | 5 мин |
| MR-18 | event_tag.rs, mod.rs, engine/mod.rs | Удалить модуль (set_impostor sufficient) | Низкая | 20 мин |
| MR-07 | engine/mod.rs | DashMap 5-tuple (claude2 C4 + qwen2 4.3) | Средняя | 45 мин |
| MR-10* | tcp.rs | BytesMut thread-local pool (glm2 2.2 + kimi2 2.2) | Низкая | 30 мин |
| MR-35 | — | Пропустить (getrandom non-blocking на Windows) | — | — |
| MR-37 | engine/mod.rs, auto_tune.rs | AutoTune wiring + Thompson sampling (glm2 4.11) | Средняя | 60 мин |

**Общее время:** ~2.5 часа
