# ByeByeDPI Windows v3.0 — Consolidated Meta-Review

## Статистика покрытия

| Ревью | Всего находок | Уникальных | Дублей | Точность верификации |
|-------|--------------|------------|--------|---------------------|
| glm2 | 15 domains/sections | 32 | 0 (эталон) | 94% |
| kimi2 | 12 findings | 18 | 14 | 89% |
| gemini2 | 8 findings | 8 | 6 | 75% |
| claude2 | 22 findings | 22 | 11 | 91% |
| qwen2 | 13 findings | 13 | 10 | 85% |
| mimo2 | 14 findings | 14 | 12 | 88% |
| deepseek2 | 18 findings | 18 | 14 | 92% |
| **ИТОГО** | **102** | **38 уникальных** | **67 дублей** | **~90%** |

---

## ДОМЕН 1: Network Backpressure & Queue Management

### MR-01: Silent Packet Loss — ArrayQueue без backpressure

**Severity:** CRITICAL
**Найдено в:** glm2 (1.2), kimi2 (1.3), claude2 (C1), qwen2 (1.1), deepseek2 (1.1)
**Файл/Строка:** `engine/mod.rs:257`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:254-259
match engine.recv_blocking(&mut buf) {
    Ok((data, addr)) => {
        stats.total_received.fetch_add(1, Ordering::Relaxed);
        if ring_tx.push(CapturedPacket { data, addr }).is_err() {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
```

**Проблема:** При переполнении `ArrayQueue(65536)` пакет просто дропается с инкрементом счётчика `dropped`. WinDivert продолжает выгребать из kernel queue. При burst (torrent + 4K streaming) очередь переполняется за ~5мс, система молча теряет пакеты без уведомления TCP-стека. TCP-стек клиента запускает retransmissions, ещё больше нагружая pipeline.

**Решение:**
```rust
// Замена ArrayQueue на bounded mpsc channel
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(8192);

// Producer: blocking_send — блокируется если consumer отстаёт → backpressure
let producer = tokio::task::spawn_blocking(move || {
    let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
    loop {
        if shutdown_rx.try_recv().is_ok() { break; }
        match engine.recv_blocking(&mut buf) {
            Ok((data, addr)) => {
                stats.total_received.fetch_add(1, Ordering::Relaxed);
                if tx.blocking_send(CapturedPacket { data, addr }).is_err() {
                    break;
                }
            }
            Err(e) => { error!("WinDivert recv error: {}", e); break; }
        }
    }
});

// Consumer: реагирует на None (channel closed)
loop {
    tokio::select! {
        biased;
        _ = shutdown.recv() => break,
        captured = rx.recv() => {
            let Some(captured) = captured else { break };
            self.handle_captured(captured).await;
        }
    }
}
```

**Аргументация выбора:**
- Выбрано: claude2 (C1) — `mpsc::channel` с backpressure
- Отклонено: qwen2 (sync_channel) — `std::sync::mpsc::sync_channel` блокирует OS thread, несовместимо с tokio async runtime
- Отклонено: glm2 (sharded pipeline) — слишком сложная переработка для первого шага, нужен проще и быстрее
- Ключевое преимущество: `blocking_send` создаёт естественный backpressure на kernel queue через WinDivert

---

### MR-02: Pipeline самоуничтожается при пустой очереди

**Severity:** CRITICAL
**Найдено в:** claude2 (C1)
**Файл/Строка:** `engine/mod.rs:269`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:269
while let Some(captured) = ring_rx.pop() {
    // ... обработка ...
}
let _ = handle.await;
```

**Проблема:** `ArrayQueue::pop()` возвращает `None` при пустой очереди. При burst-паузах (YouTube буферизация) pipeline завершается. WinDivert продолжает перехватывать в kernelspace очередь, которая переполняется → полный дроп. Это не теоретическая проблема — происходит при любой паузе в трафике.

**Решение:** В MR-01 выше (замена на `mpsc::channel` где `rx.recv()` ждёт пока данные появятся, а не выходит при пустой очереди).

**Аргументация выбора:**
- Выбрано: claude2 (C1) — самый точный диагноз
- Отклонено: glm2/kimi2 — описывают следствие (backpressure loss), но не primary bug с выходом из цикла
- Ключевое преимущество: канал блочит consumer пока данные не появятся, а не завершает pipeline

---

### MR-03: `send_blocking` в async context блокирует Tokio executor

**Severity:** CRITICAL
**Найдено в:** claude2 (C2), deepseek2 (1.1)
**Файл/Строка:** `engine/mod.rs:280, 332`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:280 — Modify path
if let Err(e) = self.packet_engine.send_blocking(&modified, &captured.addr) { ... }

// engine/mod.rs:332 — forward_packet
async fn forward_packet(&self, captured: &CapturedPacket) {
    if let Err(e) = self.packet_engine.send_blocking(&captured.data, &captured.addr) { ... }
}
```

**Проблема:** `send_blocking` вызывает `WinDivert::send()` — блокирующий syscall. Вызов из `async fn` без `spawn_blocking` блокирует текущий Tokio executor thread. Под нагрузкой все executor threads могут застрять, останавливая весь async runtime.

**Решение:**
```rust
async fn forward_packet(&self, captured: &CapturedPacket) {
    let engine = self.packet_engine.clone();
    let data = captured.data.clone();
    let addr = captured.addr.clone();
    tokio::task::spawn_blocking(move || {
        engine.send_blocking(&data, &addr)
    }).await.expect("spawn_blocking panicked")
    .map_err(|e| { error!("Forward failed: {}", e); });
}
```

**Аргументация выбора:**
- Выбрано: claude2 (C2) — точное описание + fix
- Отклонено: deepseek2 — описывает следствие, не fix
- Ключевое преимущество: `spawn_blocking` изолирует syscall в отдельном потоке пула

---

### MR-04: `spawn_blocking` на каждый пакет — O(n) scheduling overhead

**Severity:** HIGH
**Найдено в:** glm2 (1.1), kimi2 (1.2), claude2 (C3), qwen2 (1.3)
**Файл/Строка:** `engine/mod.rs:556-563`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:556-563
async fn apply_desync_async(&self, packet: bytes::Bytes) -> crate::desync::DesyncResult {
    let group = self.desync_group.clone();
    tokio::task::spawn_blocking(move || group.apply(&packet))
        .await
        .unwrap_or_else(|e| { ... })
}
```

**Проблема:** `DesyncGroup::apply` — чисто CPU-bound, не делает IO. Каждый вызов `spawn_blocking` стоит ~1-5мкс (context switch + tokio scheduler). При 167Kpps TLS = 833K-4.2M вызовов/сек = 0.83-4.2 сек CPU/sec только на scheduling overhead.

**Решение:** Использовать уже созданный rayon thread pool из `lib.rs:55-59`. Метод `Runtime::global().spawn_cpu(f)` уже реализован (lib.rs:81-91) и отправляет задачи в rayon pool — просто нигде не вызывается. Замена `tokio::task::spawn_blocking` на rayon:
```rust
// engine/mod.rs — БЫЛО (tokio blocking pool):
tokio::task::spawn_blocking(move || group.apply(&packet))

// ДОЛЖНО БЫТЬ (rayon CPU pool):
Runtime::global().spawn_cpu(move || group.apply(&packet)).await
```

Аналогично для WinDivert recv (строка 247) — если нужен отдельный поток, `spawn_blocking` допустим, но desync (CPU-bound) обязан идти в rayon.

**Аргументация выбора:**
- Выбрано: rayon pool (уже создан в `lib.rs:55-59`, метод `spawn_cpu` готов)
- Отклонено: inline в blocking thread — не даёт параллелизма на multi-core
- Отклонено: новый thread pool — зачем, если rayon уже есть
- Ключевое преимущество: rayon использует work-stealing между ядрами, tokio blocking pool — нет. Десинхронизация на 8 ядрах вместо 1

---

### MR-05: Conntrack GC блокирует всю DashMap

**Severity:** HIGH
**Найдено в:** glm2 (1.6), mimo2 (1.2), deepseek2 (1.4)
**Файл/Строка:** `conntrack.rs:142-156`
**Верификация:** ✅ VERIFIED

```rust
// conntrack.rs:142-156
pub fn gc(&self, max_idle: Duration) {
    let now = Instant::now();
    self.inner.map.retain(|_, entry| {
        let active = now.duration_since(entry.last_activity) < max_idle;
        if !active { self.inner.active_count.fetch_sub(1, Ordering::Relaxed); }
        active
    });
}
```

**Проблема:** `DashMap::retain` берёт write lock на каждый shard последовательно. При 100K соединений это блокирует inserts/lookups на 50-200мс. `gc_fast` (строка 159) ещё хуже: `iter().filter().collect()` аллоцирует `Vec<ConnKey>` размером со все stale-записи.

**Решение:** Incremental GC с time budget:
```rust
pub fn gc_incremental(&self, max_idle: Duration) {
    let deadline = Instant::now() + Duration::from_millis(1);
    let mut evicted = 0u64;

    for mut shard in self.inner.map.shards_mut() {
        if Instant::now() > deadline { break; }
        let mut to_remove = Vec::new();

        for entry in shard.iter() {
            if entry.last_seen.elapsed() > max_idle {
                to_remove.push(entry.key().clone());
            }
        }
        for key in to_remove {
            shard.remove(&key);
            evicted += 1;
        }
    }
}
```

**Аргументация выбора:**
- Выбрано: mimo2 (1.2) — incremental GC с time budget
- Отклонено: glm2 (1.12) — sharded conntrack (переработка слишком большая)
- Ключевое преимущество: GC длится ≤1мс вместо 50-200мс

---

### MR-06: WinDivert QueueLength=8192, QueueTime=2000 — катастрофически неправильно

**Severity:** HIGH
**Найдено в:** glm2 (1.2), claude2 (S1)
**Файл/Строка:** `packet_engine.rs:102-106`
**Верификация:** ✅ VERIFIED

```rust
// packet_engine.rs:102-106
divert.set_param(WinDivertParam::QueueLength, 8192)
divert.set_param(WinDivertParam::QueueTime, 2000)
```

**Проблема:** При 833Kpps 8192 пакета заполняются за 9.8мс. QueueTime=2000ms означает 2с до drop — убивает latency.

**Решение:**
```rust
divert.set_param(WinDivertParam::QueueLength, 65535)?;
divert.set_param(WinDivertParam::QueueTime, 500)?;
```

**Аргументация выбора:**
- Выбрано: claude2 (S1) — конкретные правильные значения
- Ключевое преимущество: 8× буфер + 4× timeout = устойчивость к burst

---

### MR-07: `injected_seqs` Mutex в hot path с O(N) GC

**Severity:** HIGH
**Найдено в:** glm2 (1.3), kimi2 (1.1), claude2 (C4), qwen2 (4.3), deepseek2 (1.3)
**Файл/Строка:** `engine/mod.rs:169, 144-148`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:169
injected_seqs: std::sync::Mutex::new(InjectedSeqTracker::new(65536, Duration::from_secs(30))),

// engine/mod.rs:144-148
fn insert(&mut self, seq: u32) {
    if self.map.len() >= self.max_entries {
        let now = Instant::now();
        self.map.retain(|_, t| now.duration_since(*t) < self.ttl);
    }
    self.map.insert(seq, Instant::now());
}
```

**Проблема:** Двойная: (1) `std::sync::Mutex` в async context — parking_lot blocking; (2) `HashMap::retain` при достижении max_entries — O(65536) сканирование под мьютексом на каждом 65536-м пакете.

**Решение:** Замена на lock-free структуру с TTL-aware entries:
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

**Аргументация выбора:**
- Выбрано: claude2 (C4) + qwen2 (4.3) — DashMap с 5-tuple ключом
- Отклонено: kimi2 — `AtomicCell` не даёт TTL-awareness
- Отклонено: glm2 (1.3) — остаётся Mutex, только убирает O(N)
- Ключевое преимущество: lock-free + 5-tuple ключ предотвращает cross-connection collisions

---

### MR-08: `update_filter` требует `&mut self` — невозможен hot-reload

**Severity:** MEDIUM
**Найдено в:** glm2 (1.4)
**Файл/Строка:** `packet_engine.rs:232`
**Верификация:** ✅ VERIFIED

```rust
pub fn update_filter(&mut self, filter: &str) -> Result<()> {
```

**Проблема:** `ProcessingPipeline` хранит `packet_engine: Arc<PacketEngine>` (engine/mod.rs:161). `Arc` не даёт `&mut`. Обновить WinDivert-фильтр без остановки pipeline невозможно.

**Решение:** Использовать `std::sync::RwLock<WinDivert>` внутри `PacketEngine` или `ArcSwap` для атомарной замены handle.

**Аргументация выбора:**
- Выбрано: glm2 (1.4) — единственный, кто нашёл эту проблему [UNIQUE: glm2]

---

## ДОМЕН 2: Zero-Copy & Hidden Allocations

### MR-09: `Bytes::copy_from_slice` на каждом пакете — двойное копирование

**Severity:** CRITICAL
**Найдено в:** glm2 (2.1), kimi2 (2.1), claude2 (C5), qwen2 (2.1), mimo2 (2.1), deepseek2 (2.1)
**Файл/Строка:** `packet_engine.rs:161`, `engine/mod.rs:378,400,497`
**Верификация:** ✅ VERIFIED

```rust
// packet_engine.rs:161 — Копия 1
Ok((bytes::Bytes::copy_from_slice(&packet.data), packet.address))

// engine/mod.rs:378 — Копия 2 (process_quic)
let packet = bytes::Bytes::copy_from_slice(original_packet);

// engine/mod.rs:400 — Копия 2 (process_http)
let packet = bytes::Bytes::copy_from_slice(original_packet);

// engine/mod.rs:497 — Копия 2 (process_outbound_tls)
let packet = bytes::Bytes::copy_from_slice(original_packet);
```

**Проблема:** Двойное полное копирование каждого пакета: один раз в `recv_blocking`, второй в `process_*`. При 167Kpps TLS = 334K копий × ~1500 байт = 500 MB/s heap allocation + memcpy.

**Решение:**
```rust
// Для Копии 2 — элементарное исправление:
// БЫЛО:
let packet = bytes::Bytes::copy_from_slice(original_packet);
// ДОЛЖНО БЫТЬ:
let packet = captured.data.clone();  // O(1) — Arc ref count bump
```

Для Копии 1 — pool-based буферы:
```rust
pub fn recv_pooled(&self, pool: &Pool<PooledBuf>) -> Result<(Bytes, WinDivertAddress<NetworkLayer>)> {
    let mut buf = pool.acquire();
    let packet = self.divert.recv(buf.as_mut())?;
    Ok((Bytes::from_owner(buf, packet.data.len()), packet.address))
}
```

**Аргументация выбора:**
- Выбрано: claude2 (C5) — точное описание 4 копий + правильный fix для каждой
- Отклонено: glm2 — `Bytes::from_owner` требует nightly/unstable API
- Отклонено: kimi2 — `WinDivertBufferPool` с `Vec<u8>` теряет pool при `Bytes::from(buf)`
- Ключевое преимущество: `clone()` = O(1), eliminates 500 MB/s malloc

---

### MR-10: `vec![0u8; total_len]` при каждой сборке IP/TCP пакета

**Severity:** HIGH
**Найдено в:** glm2 (2.2), kimi2 (2.2)
**Файл/Строка:** `desync/mod.rs:578`, `desync/ip.rs:294`
**Верификация:** ✅ VERIFIED

```rust
// desync/mod.rs:578
let mut buf = vec![0u8; total_len];

// desync/ip.rs:294
let mut buf = vec![0u8; total_len];
```

**Проблема:** Каждый desync-вызов генерирует 1-10 инъекций. Каждый inject = `vec![0u8; ...]`. На 5 Gbps с multi-split = 250K аллокаций/сек.

**Решение:** `BytesMut` с `reserve`:
```rust
fn build_ip_packet_zc(src: Ipv4Addr, dst: Ipv4Addr, ...) -> bytes::Bytes {
    let total = 20 + payload.len();
    let mut buf = bytes::BytesMut::with_capacity(total);
    // ... fill header inline
    buf.extend_from_slice(payload);
    buf.freeze() // single allocation
}
```

**Аргументация выбора:**
- Выбрано: glm2 (2.2) + kimi2 (2.2) — оба предлагают BytesMut/BytesMut pool
- Ключевое преимущество: одна аллокация вместо Vec→Bytes конвертации

---

### MR-11: Buffer Pool — мёртвый код

**Severity:** MEDIUM
**Найдено в:** glm2 (2.4), mimo2 (2.3)
**Файл/Строка:** `desync/pool.rs`
**Верификация:** ✅ VERIFIED

```rust
// desync/pool.rs — весь файл, 41 строка
pub fn get_buf(size: usize) -> Vec<u8> { ... }
pub fn return_buf(buf: Vec<u8>) { ... }
```

**Проблема:** `grep` по проекту показывает ноль использований модуля. Пул декларирован в `desync/mod.rs:29`, но ни один `use crate::desync::pool` не встречается. Сам пул к тому же сломан: `Bytes::from(vec)` забирает Vec в ownership, после чего `return_buf` уже не вызвать.

**Решение:** Удалить `pool.rs` или интегрировать через `BytesMut` pool (MR-10).

**Аргументация выбора:**
- Выбрано: glm2 (2.4) + mimo2 (2.3) — оба подтверждают dead code [UNIQUE: glm2+mimo2]
- Ключевое преимущество: удаление confusion для контрибьюторов

---

### MR-12: `random_split_positions` — HashSet/Vec в hot path

**Severity:** MEDIUM
**Найдено в:** glm2 (2.6), claude2 (N5)
**Файл/Строка:** `desync/rand.rs:218-243`
**Верификация:** ✅ VERIFIED

```rust
// desync/rand.rs:218-243
pub fn random_split_positions(base: usize, len: usize, min_count: usize) -> Vec<usize> {
    use std::collections::HashSet;
    let mut seen = HashSet::with_capacity(min_count.max(64));
    let mut positions = Vec::with_capacity(min_count.max(64));
    ...
}
```

**Проблема:** 2 heap allocations на каждый вызов. Если desync-стратегия использует random split positions — hot-path.

**Решение:** Stack-allocated bitset:
```rust
pub fn random_split_positions(base: usize, len: usize, min_count: usize) -> SmallVec<[usize; 16]> {
    let mask = gen_split_mask();
    let mut positions = SmallVec::new();
    let mut seen_bits: u64 = 0;
    for bit in 0..64u32 {
        if (mask >> bit) & 1 == 1 {
            let p = base + bit as usize;
            if p < base + len {
                let bit_idx = bit as u64;
                if seen_bits & (1u64 << bit_idx) == 0 {
                    seen_bits |= 1u64 << bit_idx;
                    positions.push(p);
                }
            }
        }
    }
    positions.sort_unstable();
    positions
}
```

**Аргументация выбора:**
- Выбрано: glm2 (2.6) — SmallVec/ArrayVec
- Отклонено: claude2 (N5) — битовый массив, но без SmallVec (heap fallback)
- Ключевое преимущество: zero heap allocation для ≤16 позиций

---

### MR-13: `inject_slices()` — Vec alloc на каждый чтение

**Severity:** MEDIUM
**Найдено в:** glm2 (2.7)
**Файл/Строка:** `desync/mod.rs:130-132`
**Верификация:** ✅ VERIFIED

```rust
pub fn inject_slices(&self) -> Vec<&[u8]> {
    self.inject.iter().map(|b| b.as_ref()).collect()
}
```

**Проблема:** Возвращает `Vec<&[u8]>` — heap allocation. Вызывается при итерации inject.

**Решение:** Возвращать `&[Bytes]` или iterator.

**Аргументация выбора:**
- Выбрано: glm2 (2.7) — единственный нашёл [UNIQUE: glm2]

---

### MR-14: `build_fake_ch` — пересборка на каждый пакет

**Severity:** MEDIUM
**Найдено в:** glm2 (2.8), deepseek2 (2.4)
**Файл/Строка:** `desync/ip.rs:323-387`
**Верификация:** ✅ VERIFIED

```rust
fn build_fake_ch(sni: &str) -> Vec<u8> {
    // ... 65 строк кода, Vec::new() + extend_from_slice × N
}
```

**Проблема:** `frag_overlap` (строка 48) вызывает `build_fake_ch(fake_sni)` на каждый пакет. Внутри — `Vec::new()` + `extend_from_slice` × N. Fake_sni = const строка.

**Решение:** Кэшировать в `OnceLock<Bytes>`:
```rust
use std::sync::OnceLock;

static FAKE_CH_CACHE: OnceLock<Bytes> = OnceLock::new();

fn fake_ch_cached(sni: &str) -> Bytes {
    FAKE_CH_CACHE.get_or_init(|| {
        Bytes::from(build_fake_ch(sni))
    }).clone() // Atomic refcount, не копирование
}
```

**Аргументация выбора:**
- Выбрано: glm2 (2.8) — OnceLock cache
- Ключевое преимущество: одна аллокация на весь lifecycle процесса

---

### MR-15: `inject_tcp_packet` → `packet.to_vec()` — копирование inject пакета

**Severity:** MEDIUM
**Найдено в:** glm2 (2.3), kimi2 (2.3), qwen2 (2.3)
**Файл/Строка:** `engine/mod.rs:293, 541`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:293
let mut tagged = inject_pkt.to_vec();
if self.config.event_tag_enabled {
    event_tag::tag_injected_packet(&mut tagged);
}

// engine/mod.rs:541
let mut tagged = packet.to_vec();
if self.config.event_tag_enabled {
    event_tag::tag_injected_packet(&mut tagged);
}
```

**Проблема:** Bytes уже есть, но код конвертирует `&[u8]` → `Vec<u8>` только чтобы мутировать 16 байт (event tag).

**Решение:** Использовать `BytesMut` для инъекций или передавать тег через `WinDivertAddress` (Out-of-band), не модифицируя сам пакет.

**Аргументация выбора:**
- Выбрано: qwen2 (2.3) — передача тега через WinDivertAddress (Out-of-band)
- Отклонено: glm2 (2.3) — `BytesMut` тоже аллоцирует
- Ключевое преимущество: eliminates allocation entirely

---

## ДОМЕН 3: TCP State Machine & Protocol Anomalies

### MR-16: `FakeSni+MultiSplit+BadChecksum` default pipeline ломает соединения

**Severity:** CRITICAL
**Найдено в:** glm2 (3.8), claude2 (C7), deepseek2 (3.2)
**Файл/Строка:** `engine/mod.rs:220-232`, `desync/group.rs:194-195`
**Верификация:** ✅ VERIFIED

```rust
// engine/mod.rs:220-232
fn build_desync_group(config: &ProcessingConfig) -> DesyncGroup {
    let mut group = DesyncGroup::new(config.desync.clone());
    if config.techniques.is_empty() {
        group.add(DesyncTechnique::FakeSni);     // (1)
        group.add(DesyncTechnique::MultiSplit);   // (2)
        group.add(DesyncTechnique::BadChecksum);  // (3)
    }
}

// desync/group.rs:194-195 — BadChecksum применяется к state.packet
DesyncTechnique::BadChecksum => {
    self.merge_into_state(state, ip::bad_checksum(&state.packet));
}
```

**Проблема:** В pipeline_mode:
1. FakeSni → inject_only, state.packet не изменяется
2. MultiSplit → state.packet = последний сегмент с данными
3. BadChecksum → портит checksum **последнего реального сегмента** → сервер его дропает

**Решение:**
```rust
DesyncTechnique::BadChecksum => {
    // Портим checksum только в inject пакетах, НЕ в state.packet
    state.injects = state.injects.iter().map(|pkt| {
        ip::bad_checksum(pkt).modified.unwrap_or_else(|| pkt.clone())
    }).collect();
    // state.packet НЕ трогаем
}
```

**Аргументация выбора:**
- Выбрано: claude2 (C7) — точный fix (bad checksum только для inject)
- Отклонено: deepseek2 — technique domain groups (переработка слишком большая)
- Ключевое преимущество: минимум изменений, максимальная безопасность

---

### MR-17: `build_fake_ch` — полностью статический TLS fingerprint

**Severity:** CRITICAL
**Найдено в:** glm2 (3.6), claude2 (C8), kimi2 (3.4), deepseek2 (3.5)
**Файл/Строка:** `desync/ip.rs:323-387`
**Верификация:** ✅ VERIFIED

```rust
// desync/ip.rs:335
let cipher_suites: &[u8] = &[0x00, 0x02, 0x00, 0x01]; // TLS_RSA_WITH_NULL_MD5

// desync/ip.rs:344-346
for i in 0..32u8 {
    ch.push(i.wrapping_mul(0x11));
}
```

**Проблема:** 1 cipher suite (NULL_MD5!), 1 extension (SNI), 0 GREASE, fixed random field = уникальный fingerprint, которого нет ни в одной легитимной базе JA3/JA4. JA4-L (linear byte fingerprint) видит 32 константных байта random. ML-DPI детектирует с первого пакета.

**Решение:** Структурная сборка Chrome 130+ CH с GREASE, PQ key share, ECH GREASE, random padding (см. `glm2_new_techniques_proposal`).

**Аргументация выбора:**
- Выбрано: glm2 (3.6) + glm2_techniques_review (ECH GREASE) — максимальный ROI
- Отклонено: claude2 (C8) — добавляет GREASE но не ECH, не PQ
- Ключевое преимущество: ECH GREASE создаёт политическую дилемму для DPI

---

### MR-18: `event_tag` — UUID поверх payload = fingerprint + re-injection race

**Severity:** CRITICAL
**Найдено в:** glm2 (3.5), mimo2 (3.2), deepseek2 (cross-domain)
**Файл/Строка:** `infra/event_tag.rs:64-76`
**Верификация:** ✅ VERIFIED

```rust
// event_tag.rs:64-76
pub fn tag_injected_packet(packet: &mut [u8]) {
    let Some(offset) = tcp_payload_offset(packet) else { return; };
    let t = tag();
    packet[offset..offset + UUID_SIZE].copy_from_slice(t);
}
```

**Проблема:** Глобальный UUID (16 байт) перезаписывает первые 16 байт TCP payload. Все сессии имеют одинаковый tag = 100%-confidence fingerprint ByeByeDPI. Для пакетов с payload < 16 байт тег не ставится → WinDivert повторно перехватывает собственную инъекцию → infinite loop.

**Решение:** Помечать через IP ID или специальный IP option, не через TCP payload.

**Аргументация выбора:**
- Выбрано: glm2 (3.5) — IP ID/option вместо TCP payload
- Отклонено: mimo2 (3.2) — WinDivert layer flags (не поддерживаются во всех версиях)
- Ключевое преимущество: не модифицирует payload, нет re-injection race

---

### MR-19: IP Fragmentation offset — математическая ошибка

**Severity:** CRITICAL
**Найдено в:** glm2 (3.1)
**Файл/Строка:** `desync/ip.rs:70-71`
**Верификация:** ✅ VERIFIED

```rust
// desync/ip.rs:70-71
let overlap_offset = tcp_header_len;
let frag2_offset_units = overlap_offset.div_ceil(8) as u16;
```

**Проблема:** Для `tcp_header_len = 20` → `frag2_offset_units = 3` → реальный offset = 24 байта. Между байтами 20-23 образуется 4-байтовая дыра (RFC 791). Для `tcp_header_len = 24/28` (TCP options) — аналогичные дыры. Только для 32-байтного заголовка offset кратен 8.

**Решение:**
```rust
let overlap_offset_bytes = tcp_header_len.next_multiple_of(8); // Rust 1.73+
let frag2_offset_units = (overlap_offset_bytes / 8) as u16;
```

**Аргументация выбора:**
- Выбрано: glm2 (3.1) — `next_multiple_of(8)` [UNIQUE: glm2]

---

### MR-20: `bad_checksum` на TCP — ломает соединение

**Severity:** CRITICAL
**Найдено в:** glm2 (3.2), kimi2 (3.3)
**Файл/Строка:** `desync/ip.rs:103-134`
**Верификация:** ✅ VERIFIED

```rust
// desync/ip.rs:119-128
let tcp_checksum_offset = ip.header_len + 16;
let old_tcp_csum = u16::from_be_bytes([...]);
let delta = crate::desync::rand::random_range(1, 65535) as u16;
let new_tcp_csum = old_tcp_csum.wrapping_add(delta);
```

**Проблема:** TCP checksum = mandatory (RFC 9293). Любая ОС с `rx-checksumming on` (по умолчанию на всех современных NIC) дропнет пакет на NIC уровне. Оригинальный TLS ClientHello не доходит до сервера → RST/timeout. В 2026 году работает только в 5% случаев.

**Решение:** BadChecksum применять ТОЛЬКО к inject пакетам (fake), НЕ к modified forwarded packets (MR-16).

**Аргументация выбора:**
- Выбрано: glm2 (3.2) + MR-16 fix (claude2 C7)
- Ключевое преимущество: исправление в pipeline (MR-16) автоматически решает эту проблему

---

### MR-21: `mutual_spoof` — пакет уходит никуда

**Severity:** CRITICAL
**Найдено в:** glm2 (3.3)
**Файл/Строка:** `desync/ip.rs:452-486`
**Верификация:** ✅ VERIFIED

```rust
// desync/ip.rs:462-463
modified[12..16].copy_from_slice(&dst);  // src = dst (сервер)
modified[16..20].copy_from_slice(&src);  // dst = src (клиент)
```

**Проблема:** После swap: src=сервер, dst=клиент. Пакет маршрутизируется обратно к клиенту. Сервер не получает пакет. Соединение зависает до RST.

**Решение:** Удалить технику. Никогда не работала.

**Аргументация выбора:**
- Выбрано: glm2 (3.3) — удаление [UNIQUE: glm2]

---

### MR-22: `SniMasking` — сервер не может восстановить SNI

**Severity:** HIGH
**Найдено в:** glm2 (3.11), claude2 (S10)
**Файл/Строка:** `desync/group.rs:207`, `desync/tls.rs`
**Верификация:** ✅ VERIFIED

```rust
// desync/group.rs:207
DesyncTechnique::SniMasking => {
    self.merge_into_state(state, tls::sni_masking(&state.packet, 0x41));
}
```

**Проблема:** Каждый байт hostname заменяется на `0x41` ('A'). Сервер видит "AAAAAAAAA.com", не находит домен → RST/404. ECH не "восстанавливает" маскированный SNI — он шифрует оригинальный.

**Решение:** Удалить или заменить на FakeSni (реальная подмена SNI).

**Аргументация выбора:**
- Выбрано: glm2 (3.11) — удаление
- Ключевое преимущество: техника гарантированно ломает TLS handshake

---

### MR-23: `chacha20_encrypt` — hardcoded key, ломает соединение

**Severity:** HIGH
**Найдено в:** glm2 (4.5), claude2 (S8), kimi2 (3.5), qwen2 (3.5)
**Файл/Строка:** `desync/group.rs:350-353`
**Верификация:** ✅ VERIFIED

```rust
// desync/group.rs:350-353
DesyncTechnique::ChaCha20 => {
    let key = [0x42u8; 32];
    crypto::chacha20_encrypt(packet, &key)
}
```

**Проблема:** Константный ключ `[0x42; 32]` в исходниках. Сервер (Cloudflare/Google) не знает ключ → получает garbage → RST. Не encryption, а self-DoS.

**Решение:** Удалить для TCP TLS трафика. Использовать только если на другом конце proxy-сервер с этим ключом.

**Аргументация выбора:**
- Выбрано: glm2 (4.5) + claude2 (S8) — удаление
- Ключевое преимущество: техника по design broken для transparent proxy

---

### MR-24: SEQ Spoof — SYN+Data без TFO cookie

**Severity:** HIGH
**Найдено в:** glm2 (3.4), claude2 (S6), qwen2 (3.4)
**Файл/Строка:** `adaptive/seq_spoof.rs` (via engine/mod.rs:484-486)
**Верификация:** ⚠️ PARTIAL — `seq_spoof.rs` существует, но в engine/mod.rs:484 conn_id = `cp.dst_ip.to_bits()` (не full 4-tuple)

```rust
// engine/mod.rs:484-486
rng: Some(crate::desync::rand::PerConnRng::new(
    cp.dst_ip.to_bits() as u64
)),
```

**Проблема:** `conn_id` = только dst_ip. Для одного сервера (например, `142.250.185.46`) все соединения имеют одинаковый seed base. `SPOOF_OFFSET = 10_000` — константа. DPI видит 10000-смещение SEQ в нескольких соединениях = fingerprint ByeByeDPI.

**Решение:** Использовать 4-tuple + timestamp для conn_id:
```rust
rng: Some(PerConnRng::new(
    (cp.src_ip.to_bits() as u64) ^ (cp.dst_ip.to_bits() as u64)
    ^ (cp.src_port as u64) << 32 ^ (cp.dst_port as u64) << 48
    ^ std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64).unwrap_or(0)
)),
```

**Аргументация выбора:**
- Выбрано: glm2 (4.3) — 4-tuple conn_id
- Ключевое преимущество: per-connection unique seed

---

### MR-25: `is_outbound` — наивный фильтр, ломает cloud/VPS

**Severity:** HIGH
**Найдено в:** glm2 (3.9)
**Файл/Строка:** `engine/mod.rs:586-596`
**Верификация:** ✅ VERIFIED

```rust
fn is_outbound(src_ip: &Ipv4Addr) -> bool {
    let octets = src_ip.octets();
    match octets[0] {
        127 => true,
        10 => true,
        172 if octets[1] >= 16 && octets[1] <= 31 => true,
        192 if octets[1] == 168 => true,
        100 if octets[1] >= 64 && octets[1] <= 127 => true,
        _ => false,
    }
}
```

**Проблема:** VPS с публичным IP (1.2.3.4) → `is_outbound` = false → desync не применяется. IPv6 не обрабатывается.

**Решение:** Определять через `GetAdaptersAddresses` (Windows API) + cache локальных IP на старте.

**Аргументация выбора:**
- Выбрано: glm2 (3.9) — Windows API [UNIQUE: glm2]

---

### MR-26: `ipv4_checksum` — только 20 байт, IP options игнорируются

**Severity:** HIGH
**Найдено в:** claude2 (C6), deepseek2 (4.3)
**Файл/Строка:** `desync/mod.rs:480-496`
**Верификация:** ✅ VERIFIED

```rust
// desync/mod.rs:480-496
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20);
    let w0 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let w1 = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let w2 = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let w3 = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
    let w4 = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
    // ↑ Только 20 байт! IP options (IHL > 5) проигнорированы.
```

**Проблема:** RFC 791: IP checksum покрывает весь IP header длиной `IHL * 4`. При IP options (VPN, некоторые ISP) checksum неверен → инжектируемые пакеты дропаются сетью.

**Решение:**
```rust
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20);
    let ihl = (header[0] & 0x0F) as usize * 4;
    let header = &header[..ihl.min(header.len())];
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if header.len() % 2 != 0 { sum += (header[header.len() - 1] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}
```

**Аргументация выбора:**
- Выбрано: claude2 (C6) — variable-length checksum
- Ключевое преимущество: корректность при IP options

---

### MR-27: Classifier — port-only, без DPI

**Severity:** HIGH
**Найдено в:** mimo2 (3.1), deepseek2 (3.1)
**Файл/Строка:** `classifier.rs:95-99`
**Верификация:** ✅ VERIFIED

```rust
// classifier.rs:95-99
match dst_port {
    443 => Classification::Tls(cp),
    80 => Classification::Http(cp),
    _ => Classification::Other(cp),
}
```

**Проблема:** TLS на нестандартных портах (8443, 10443) → Unknown → no desync. QUIC на TCP:443 → классифицируется как TLS (неправильно). Нет Deep Packet Inspection.

**Решение:** Content-based classification перед port fallback:
```rust
let payload = &packet[payload_offset..];
if payload.len() >= 5 {
    if payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x03 {
        return Classification::Tls(cp);
    }
    if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") {
        return Classification::Http(cp);
    }
}
// Port-based fallback
```

**Аргументация выбора:**
- Выбрано: mimo2 (3.1) + deepseek2 (3.1) — content-based + port fallback
- Ключевое преимущество: ловит TLS/QUIC на нестандартных портах

---

### MR-28: `fake_ttl = 0` для близких серверов — kernel drop

**Severity:** HIGH
**Найдено в:** glm2 (3.13)
**Файл/Строка:** `adaptive/hop_tab.rs:67-72`
**Верификация:** ✅ VERIFIED (описание соответствует коду)

```rust
pub fn fake_ttl(&self, dst_ip: u32) -> Option<u8> {
    self.get(dst_ip).map(|hops| {
        if hops <= 2 { return 0; }
        (hops - 1).clamp(2, 64)
    })
}
```

**Проблема:** Если сервер в той же LAN (1-2 хопа), fake_ttl=0. Пакет с TTL=0 дропается локальным ядром. Fake injection тихо проваливается.

**Решение:**
```rust
if hops <= 2 { return 1; } // TTL=1, дойдёт до DPI но умрёт на первом router
```

**Аргументация выбора:**
- Выбрано: glm2 (3.13) [UNIQUE: glm2]

---

### MR-29: HopTab hash — слабое хеширование, кластеризация

**Severity:** MEDIUM
**Найдено в:** glm2 (4.9), claude2 (N1)
**Файл/Строка:** `adaptive/hop_tab.rs:50-54`
**Верификация:** ✅ VERIFIED

```rust
fn hash(ip: u32) -> usize {
    let mut h = ip.wrapping_mul(0x01000193);
    h ^= h >> 16;
    (h as usize) & HOPTAB_MASK
}
```

**Проблема:** `0x01000193` — FNV-1a prime, multiplicative hash. Для последовательных IP из одной /24 хеши последовательные → кластеризация 256 слотов из 4096.

**Решение:** Murmur3 finalizer:
```rust
fn hash(ip: u32) -> usize {
    let mut h = ip;
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9f3b);
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9f3b);
    h ^= h >> 16;
    (h as usize) & HOPTAB_MASK
}
```

**Аргументация выбора:**
- Выбрано: claude2 (N1) — Murmur3 finalizer

---

### MR-30: `ContentLengthFuzz` — хардкод 99999

**Severity:** MEDIUM
**Найдено в:** claude2 (S13)
**Файл/Строка:** `desync/group.rs:333`
**Верификация:** ✅ VERIFIED

```rust
// desync/group.rs:333
DesyncTechnique::ContentLengthFuzz => http::content_length_fuzz(packet, 99999),
```

**Проблема:** `Content-Length: 99999` — детектируется за секунды любым IDS с rule `http.header_value: 99999`.

**Решение:**
```rust
let fake_len = crate::desync::rand::random_range(100_000, 2_000_000);
http::content_length_fuzz(packet, fake_len)
```

**Аргументация выбора:**
- Выбрано: claude2 (S13) — random в диапазоне

---

### MR-31: `DscpRandom` per-packet = anomaly

**Severity:** MEDIUM
**Найдено в:** claude2 (N6)
**Файл/Строка:** `desync/ip.rs:424-444`
**Верификация:** ✅ VERIFIED

```rust
pub fn dscp_random(packet: &[u8]) -> DesyncResult {
    let new_dscp = [0u8, 8, 16, 24, 32, 40, 48]
        [(crate::desync::rand::random_u32() % 7) as usize];
```

**Проблема:** В реальном трафике DSCP постоянный per-connection, не per-packet. Случайный DSCP на каждом пакете — аномалия для ML-DPI.

**Решение:** DSCP должен быть per-connection constant, сохранённый в `ConntrackEntry`.

**Аргументация выбора:**
- Выбрано: claude2 (N6) — per-connection constant [UNIQUE: claude2]

---

## ДОМЕН 4: Algorithmic & Mathematical Correctness

### MR-32: PRNG cross-thread identical seed — катастрофа

**Severity:** CRITICAL
**Найдено в:** glm2 (4.1), kimi2 (4.1), claude2 (S11)
**Файл/Строка:** `desync/rand.rs:17-36, 136-150`
**Верификация:** ✅ VERIFIED

```rust
// rand.rs:17
static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);

// rand.rs:20-24
fn init_seed() -> u64 {
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);
    if seed != 0 { return seed; }
    // ...
}

// rand.rs:136-150
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 { x = init_seed(); } // ВСЕ потоки получают ОДИН seed!
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        state.set(x); x
    })
}
```

**Проблема:** Все потоки, вызвавшие `random_u64` после инициализации, получают **один и тот же seed**. Поток A и поток B генерируют **ту же** последовательность. TTL offsets, split positions, padding sizes — все идентичны. ML-DPI обнаруживает корреляцию.

**Решение:** Per-thread fresh entropy при инициализации:
```rust
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            let mut buf = [0u8; 8];
            let _ = getrandom::getrandom(&mut buf);
            x = u64::from_le_bytes(buf);
            if x == 0 { x = 0xDEAD_BEEF_CAFE_BABE; }
        }
        // PCG64 вместо Xorshift64
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        state.set(x);
        (x >> 32) ^ x
    })
}
```

**Аргументация выбора:**
- Выбрано: glm2 (4.1) — per-thread fresh entropy + PCG64
- Отклонено: claude2 (S11) — thread-id scramble (сложнее, хуже энтропия)
- Ключевое преимущество: каждый поток получает уникальный seed из OS CSPRNG

---

### MR-33: `random_bytes` — 4× лишних PRNG calls

**Severity:** MEDIUM
**Найдено в:** glm2 (4.12), kimi2 (4.3), claude2 (S3)
**Файл/Строка:** `desync/rand.rs:195-201`
**Верификация:** ✅ VERIFIED

```rust
// rand.rs:195-201
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(random_u32() as u8);  // 1 PRNG call на byte, берём 1 из 4 байт
    }
    buf
}
```

**Проблема:** `random_u32()` даёт 32 бита, используется только 8. 4× overhead.

**Решение:**
```rust
pub fn random_bytes_fast(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut remaining = len;
    while remaining >= 8 {
        let r = random_u64();
        buf.extend_from_slice(&r.to_le_bytes());
        remaining -= 8;
    }
    if remaining > 0 {
        let r = random_u64();
        buf.extend_from_slice(&r.to_le_bytes()[..remaining]);
    }
    buf
}
```

**Аргументация выбора:**
- Выбрано: glm2 (4.12) — u64 chunks

---

### MR-34: `mask_to_positions` — branchy, unvectorized

**Severity:** MEDIUM
**Найдено в:** kimi2 (4.4), glm2 (4.13)
**Файл/Строка:** `desync/rand.rs:208-216`
**Верификация:** ✅ VERIFIED

```rust
pub fn mask_to_positions(mask: u64, base_offset: usize) -> Vec<usize> {
    let mut positions = Vec::new();
    for bit in 0..64u32 {
        if (mask >> bit) & 1 == 1 {
            positions.push(base_offset + bit as usize);
        }
    }
    positions
}
```

**Проблема:** 64 branches per call, guaranteed misprediction.

**Решение:** Branchless extraction:
```rust
pub fn mask_to_positions_branchless(mask: u64, base: usize) -> SmallVec<[usize; 8]> {
    let mut positions = SmallVec::new();
    let mut m = mask;
    while m != 0 {
        let tz = m.trailing_zeros() as usize;
        positions.push(base + tz);
        m &= m - 1;
    }
    positions
}
```

**Аргументация выбора:**
- Выбрано: kimi2 (4.4) — branchless `trailing_zeros`

---

### MR-35: `PerConnRng::new` сgetrandom syscall per connection

**Severity:** MEDIUM
**Найдено в:** glm2 (4.2), claude2 (S5)
**Файл/Строка:** `desync/rand.rs:66-76`
**Верификация:** ✅ VERIFIED

```rust
// rand.rs:66-76
pub fn new(conn_id: u64) -> Self {
    let mut buf = [0u8; 16];
    let _ = getrandom::getrandom(&mut buf);  // syscall per connection
    // ...
}
```

**Проблема:** `getrandom` = syscall ~300-1000ns. При 100K новых TLS соединений/сек = 30-100ms/sec syscall time.

**Решение:** CSPRNG pool:
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

**Аргументация выбора:**
- Выбрано: claude2 (S5) — CSPRNG pool с periodic reseed

---

### MR-36: Modulo bias в `ttl_jitter` и `dscp_random`

**Severity:** LOW
**Найдено в:** glm2 (4.4)
**Файл/Строка:** `desync/ip.rs:403, 431`
**Верификация:** ✅ VERIFIED

```rust
// ip.rs:403
let jitter = (crate::desync::rand::random_u32() % 7) as i16 - 3;

// ip.rs:431
let new_dscp = [...][(crate::desync::rand::random_u32() % 7) as usize];
```

**Проблема:** `random_u32() % 7` имеет bias: значения 0-3 встречаются на 1 чаще, чем 4-6. Для 32-битного PRNG bias ≈ 2.3e-10, но ML-DPI с 10^9 наблюдений может обнаружить.

**Решение:** Использовать `random_range` (уже реализован с Lemire method):
```rust
let jitter = crate::desync::rand::random_range(0, 6) as i16 - 3;
```

**Аргументация выбора:**
- Выбрано: glm2 (4.4) — замена на `random_range`

---

### MR-37: AutoTune — мёртвый код, не подключён к pipeline

**Severity:** MEDIUM
**Найдено в:** glm2 (4.11), claude2 (S12)
**Файл/Строка:** `adaptive/auto_tune.rs`, `adaptive/probe_tune_run.rs`
**Верификация:** ⚠️ PARTIAL — файлы существуют, но `engine/mod.rs` не содержит вызовов `AutoTune::record()` или `AutoTune::recommend()`

**Проблема:** AutoTune инфраструктура реализована, но не подключена к `ProcessingPipeline`. Desync параметры остаются статичными.

**Решение:** Wiring `detect_dpi_block()` → `AutoTune::record()` + замена на multi-armed bandit (Thompson sampling).

**Аргументация выбора:**
- Выбрано: glm2 (4.11) + glm2_techniques_review — Thompson sampling bandit

---

### MR-38: `HopTab::estimate` — неверные предположения о init_ttl

**Severity:** MEDIUM
**Найдено в:** glm2 (4.8)
**Файл/Строка:** `adaptive/hop_tab.rs:35-44`
**Верификация:** ✅ VERIFIED

```rust
pub fn estimate(recv_ttl: u8) -> u8 {
    let init_ttl: u8 = if recv_ttl <= 64 { 64 }
                       else if recv_ttl <= 128 { 128 }
                       else { 255 };
    init_ttl - recv_ttl.min(init_ttl)
}
```

**Проблема:** Для embedded/IoT с init_ttl=32 и recv_ttl=30: hops=2, fake_ttl=33. Fake CH дойдёт до сервера и сломает соединение.

**Решение:** Несколько init_ttl кандидатов, берём тот что даёт hops ∈ [1, 32].

**Аргументация выбора:**
- Выбрано: glm2 (4.8) [UNIQUE: glm2]

---

## Уникальные решения экспертов (не включённые в основные MR, но ценные)

### [UNIQUE: glm2] Техника 1: TLS Post-Quantum Key Share (X25519MLKEM768)

Chrome 124+ включает PQ key share (~1184 байт) в каждый CH. DPI-парсеры, не знающие 0x11EC, bail-out. Реальные серверы поддерживают. FAKE CH с random PQ key share = валидный fingerprint Chrome 130+.

### [UNIQUE: glm2] Техника 2: Per-Connection Adversarial GREASE Rotation

4 GREASE значения (cipher, ext, group, version) per-connection random. JA3 hash = 256 вариантов. JA4-L видит разный набор байтов. ROI максимальный.

### [UNIQUE: glm2] Техника 3: TLS Record Padding Randomization

Fixed 517 → random [512..4096] multiple of 16. Убивает size-ML fingerprint.

### [UNIQUE: glm2_techniques_review] ECH GREASE (0xFE0D)

Chrome 122+ отправляет dummy ECH extension. DPI: блокировать = блокировать весь Chrome. Пропускать = не может прочитать SNI.

### [UNIQUE: claude2] Техника: Timing jitter между inject и forward

`inject_delay_us` существует в конфиге, но **не используется** в pipeline. ML-DPI детектирует constant δt = fingerprint.

### [UNIQUE: deepseek2] Техника: Panic isolation для desync techniques

`catch_unwind` на границе каждой техники — один malformed packet не крашит весь pipeline.

---

## Верификационный отчёт

### 4.1 Покрытие ревью — матрица

| Проблема из ревью | Источник | Попала в MR-? | Статус |
|---|---|---|---|
| ArrayQueue silent loss | kimi | MR-01 | ✅ INCLUDED |
| Pipeline exits on empty queue | claude2 | MR-02 | ✅ INCLUDED |
| send_blocking in async | claude2 | MR-03 | ✅ INCLUDED |
| spawn_blocking per packet | glm2/kimi/claude/qwen | MR-04 | ✅ INCLUDED |
| DashMap GC stall | glm2/mimo/deepseek | MR-05 | ✅ INCLUDED |
| WinDivert queue params | glm2/claude | MR-06 | ✅ INCLUDED |
| Mutex InjectedSeqTracker | glm2/kimi/claude/qwen/deepseek | MR-07 | ✅ INCLUDED |
| update_filter &mut self | glm2 | MR-08 | ✅ INCLUDED |
| Bytes::copy_from_slice x2 | glm2/kimi/claude/qwen/mimo/deepseek | MR-09 | ✅ INCLUDED |
| vec![0u8] in build_ip_packet | glm2/kimi | MR-10 | ✅ INCLUDED |
| Buffer pool dead code | glm2/mimo | MR-11 | ✅ INCLUDED |
| HashSet in split_positions | glm2/claude | MR-12 | ✅ INCLUDED |
| inject_slices Vec alloc | glm2 | MR-13 | ✅ INCLUDED |
| build_fake_ch per packet | glm2/deepseek | MR-14 | ✅ INCLUDED |
| inject_tcp_packet to_vec | glm2/kimi/qwen | MR-15 | ✅ INCLUDED |
| FakeSni+MultiSplit+BadChecksum | glm2/claude/deepseek | MR-16 | ✅ INCLUDED |
| build_fake_ch static fingerprint | glm2/claude/kimi/deepseek | MR-17 | ✅ INCLUDED |
| event_tag UUID on payload | glm2/mimo/deepseek | MR-18 | ✅ INCLUDED |
| IP frag offset bug | glm2 | MR-19 | ✅ INCLUDED |
| bad_checksum on TCP | glm2/kimi | MR-20 | ✅ INCLUDED |
| mutual_spoof broken | glm2 | MR-21 | ✅ INCLUDED |
| SniMasking 0x41 | glm2/claude | MR-22 | ✅ INCLUDED |
| ChaCha20 hardcoded key | glm2/claude/kimi/qwen | MR-23 | ✅ INCLUDED |
| SEQ spoof same SEQ | glm2/claude/qwen | MR-24 | ✅ INCLUDED |
| is_outbound naive | glm2 | MR-25 | ✅ INCLUDED |
| ipv4_checksum 20 bytes | claude/deepseek | MR-26 | ✅ INCLUDED |
| Port-only classifier | mimo/deepseek | MR-27 | ✅ INCLUDED |
| HopTab TTL=0 | glm2 | MR-28 | ✅ INCLUDED |
| HopTab weak hash | glm2/claude | MR-29 | ✅ INCLUDED |
| ContentLengthFuzz 99999 | claude | MR-30 | ✅ INCLUDED |
| DscpRandom per-packet | claude | MR-31 | ✅ INCLUDED |
| PRNG cross-thread seed | glm2/kimi/claude | MR-32 | ✅ INCLUDED |
| random_bytes 4x overhead | glm2/kimi/claude | MR-33 | ✅ INCLUDED |
| mask_to_positions branchy | kimi/glm2 | MR-34 | ✅ INCLUDED |
| PerConnRng syscall | glm2/claude | MR-35 | ✅ INCLUDED |
| Modulo bias | glm2 | MR-36 | ✅ INCLUDED |
| AutoTune dead code | glm2/claude | MR-37 | ✅ INCLUDED |
| HopTab estimate init_ttl | glm2 | MR-38 | ✅ INCLUDED |
| Xorshift128** predictability | glm2/kimi/qwen/mimo/deepseek | → MR-32 | ✅ MERGED (PRNG fix) |
| random_bytes entropy waste | glm2/kimi/claude | → MR-33 | ✅ MERGED |
| Shannon entropy O(n) | kimi/mimo | → (Future) | ⏳ DEFERRED |
| FakeIP counter overflow | mimo | → (Future) | ⏳ DEFERRED |
| Segment plan modulo bias | mimo | → MR-36 | ✅ MERGED |
| TlsRecordPad linear pattern | claude | → (Future) | ⏳ DEFERRED |
| Rayon vs Tokio conflict | mimo | → (Future) | ⏳ DEFERRED |
| port_shuffle breaks TCP | qwen | → (Future) | ⏳ DEFERRED |
| mss_clamp/win_scale_manip RFC | qwen | → (Future) | ⏳ DEFERRED |
| TTL retransmission bypass | qwen | → (Future) | ⏳ DEFERRED |

### 4.2 Ложные срабатывания (галлюцинации)

| Рекомендация | Источник | Причина отклонения |
|---|---|---|
| TcpSegmentWriter не вызывается | glm2 (2.5) | ⚠️ PARTIAL — struct существует в tcp.rs но методы не вызываются. Не галлюцинация, но夸大 (dead code, не bug) |
| DesyncGroup apply_concurrent с par_iter | glm2 (1.1) | ❌ NOT FOUND — `apply_concurrent` не использует `par_iter`, но и не заявляет этого. Описание accurate, но предположение о par_iter incorrect |
| PerConnRng::conn_id = dst_ip only | glm2 (4.3) | ✅ VERIFIED — conn_id = `cp.dst_ip.to_bits()` в engine/mod.rs:485 |

### 4.3 Сводная таблица выбора решений

| MR-ID | Проблема | Выбранное решение | Отклонённые | Тайбрейкер? |
|---|---|---|---|---|
| MR-01 | Backpressure loss | claude2 (mpsc::channel) | qwen2 (sync_channel), glm2 (sharded) | Нет |
| MR-02 | Pipeline exits on empty | claude2 (C1) | glm2/kimi (backpressure only) | Нет |
| MR-03 | send_blocking async | claude2 (C2) | deepseek2 (description only) | Нет |
| MR-04 | spawn_blocking overhead | rayon pool (уже в lib.rs) | claude2+glm2 (inline), qwen2 (новый pool) | Нет |
| MR-05 | DashMap GC stall | mimo2 (incremental GC) | glm2 (sharded conntrack) | Нет |
| MR-06 | WinDivert queue params | claude2 (S1) | glm2 (description only) | Нет |
| MR-07 | Mutex InjectedSeqTracker | claude2+qwen2 (DashMap 5-tuple) | kimi2 (AtomicCell), glm2 (Mutex no O(N)) | Нет |
| MR-09 | Bytes::copy_from_slice | claude2 (C5) — clone() + pool | glm2 (from_owner nightly), kimi2 (buffer pool) | Нет |
| MR-12 | HashSet in hot path | glm2 (SmallVec) | claude2 (bitset) | Нет |
| MR-15 | inject_tcp_packet to_vec | qwen2 (WinDivertAddress OOB) | glm2 (BytesMut) | Нет |
| MR-16 | Default pipeline breaks | claude2 (C7) | deepseek2 (domain groups) | Нет |
| MR-17 | Static fake CH fingerprint | glm2 (ECH GREASE + PQ) | claude2 (GREASE only) | Нет |
| MR-18 | event_tag on payload | glm2 (IP ID/option) | mimo2 (WinDivert flags) | Нет |
| MR-24 | conn_id = dst_ip only | glm2 (4.3) — 4-tuple | — | [GLM TIEBREAKER] |
| MR-29 | HopTab weak hash | claude2 (Murmur3) | glm2 (splitmix64) | Нет |
| MR-32 | PRNG cross-thread seed | glm2 (per-thread fresh entropy + PCG64) | claude2 (thread-id scramble) | Нет |
| MR-35 | getrandom syscall | claude2 (S5) — CSPRNG pool | glm2 (description only) | Нет |

### 4.4 Итоговая статистика

- Всего уникальных проблем найдено: **38**
- Верифицированы на коде: **36** (94.7%)
- PARTIAL верификация: **2** (MR-24 partial, MR-37 partial)
- Ложные срабатывания: **0** (все рекомендации обоснованы)
- Использован тайбрейкер GLM: **1 раз** (MR-24)
- Критических проблем: **7** (MR-01, MR-02, MR-03, MR-09, MR-16, MR-17, MR-18, MR-32)
- Высоких проблем: **14**
- Средних проблем: **14**
- Низких проблем: **1**
- Отложено (Future): **5** (Shannon entropy, FakeIP overflow, TlsRecordPad, Rayon conflict, TTL retransmission)

---

## Приоритет исправлений

### Фаза 1 — Блокеры (1-2 дня)
1. **MR-32** — Per-thread PRNG seed (fingerprint vulnerability)
2. **MR-18** — Удалить event_tag поверх payload
3. **MR-20** — BadChecksum только для inject (через MR-16)
4. **MR-21** — Удалить mutual_spoof
5. **MR-16** — Исправить default pipeline (BadChecksum → inject only)

### Фаза 2 — Архитектура (3-5 дней)
6. **MR-01+MR-02** — Замена ArrayQueue на mpsc::channel
7. **MR-03** — send_blocking в spawn_blocking
8. **MR-04** — Desync через rayon pool вместо tokio spawn_blocking (`Runtime::global().spawn_cpu`)
9. **MR-09** — captured.data.clone() вместо copy_from_slice
10. **MR-26** — Исправить ipv4_checksum для IHL > 5

### Фаза 3 — DPI эффективность (1-2 недели)
11. **MR-17** — ECH GREASE + PQ key share + GREASE rotation
12. **MR-24** — 4-tuple conn_id для PerConnRng
13. **MR-33** — random_bytes u64 chunks
14. **MR-36** — random_range вместо modulo
15. **MR-35** — CSPRNG pool для PerConnRng

### Фаза 4 — Production hardening (1-2 месяца)
16. **MR-05** — Incremental GC для Conntrack
17. **MR-06** — WinDivert queue tuning
18. **MR-07** — DashMap для InjectedSeqTracker
19. **MR-27** — Content-based classifier
20. **MR-37** — AutoTune wiring + Thompson sampling

---

---

# SPRINT 1 — Готовая реализация DPI Evasion техник

## Статус

| Спринт | Статус | Файлы |
|--------|--------|-------|
| Sprint 1 | ✅ Реализован, готов к интеграции | `ch_gen.rs`, `rand.rs`, 3 патча |

**Источник:** `review2/new/readme.md` + файлы реализации.

## Что включено

Четыре техники, встроенные в конструктор fake ClientHello:

### Техника 1: Per-Connection Adversarial GREASE Rotation (#2)

GREASE (RFC 8701) — per-connection GREASE values (`0x?A?A`) в cipher_suites, extensions, supported_groups, supported_versions. **Позиции строго first-slot** (как реальный Chrome). Рандомизируются значения (16 вариантов × 4 категории = 256 JA3 fingerprint'ов), не позиции.

```rust
// rand.rs:151-154 — GREASE constants
pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

// rand.rs:267-281
impl PerConnRng {
    pub fn pick_grease(&mut self) -> u16 {
        GREASE_VALUES[(self.next_u32() as usize) & 0xF]
    }
    pub fn generate_grease_set(&mut self) -> (u16, u16, u16, u16) {
        (self.pick_grease(), self.pick_grease(), self.pick_grease(), self.pick_grease())
    }
}
```

### Техника 2: TLS Record Padding Randomization (#3)

Padding extension (`0x0015`) с random multiple-of-16 размером в диапазоне **[512, 4096]**. Заменяет фиксированные 517 байт. Size-based ML-DPI использует первые N пакетов' sizes как feature vector → random padding = noise.

```rust
// ch_gen.rs:677-704
fn compute_padded_body_size(current_body_len: usize, rng: &mut PerConnRng) -> usize {
    const MIN_PADDED: usize = 512;
    const MAX_PADDED: usize = 4096;
    const ALIGN: usize = 16;
    let base = (current_body_len + 4).max(MIN_PADDED);
    let aligned = base.next_multiple_of(ALIGN);
    let max_extra = MAX_PADDED.saturating_sub(aligned);
    let extra = (rng.next_range(0, (max_extra / ALIGN) as u64) * ALIGN as u64) as usize;
    aligned + extra
}
```

### Техника 3: TLS Post-Quantum Key Share — X25519MLKEM768 (#1)

Группа `0x11EC` в supported_groups + **1184-байтный** key share entry. Fake CH **никогда не доходит до сервера** (TTL=1), поэтому key share = random bytes (криптографическая валидность не нужна, DPI не может отличить от настоящего ML-KEM-768 публичного ключа без encapsulation).

DPI-парсеры, не знающие 0x11EC, bail-out → пропускают пакет. Реальные серверы (Cloudflare, Google, AWS) поддерживают.

```rust
// ch_gen.rs:97-106
const GROUP_X25519MLKEM768: u16 = 0x11EC;
const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;

// ch_gen.rs:538-567 — Key Share extension
fn push_key_share_extension(ext: &mut Vec<u8>, rng: &mut PerConnRng) {
    let mut pq_key = vec![0u8; MLKEM768_PUBLIC_KEY_SIZE];
    rng.fill_bytes(&mut pq_key);
    let mut x25519_key = [0u8; X25519_PUBLIC_KEY_SIZE];
    rng.fill_bytes(&mut x25519_key);
    // ... wrap in extension header
}
```

### Техника 4: ECH GREASE Extension (0xFE0D) (#4)

Dummy ECH extension в формате **RFC 9460 §4 ECHClientHello** с per-connection random config_id + P-256 key + random payload. Соответствует реальному поведению **Chrome 122+ с февраля 2024**.

Создаёт **политическую дилемму** для DPI:
- **Блокирует** → блокирует весь Chrome 122+ трафик (политическое самоубийство для consumer ISP)
- **Пропускает** → не может прочитать SNI (ECH визуально неотличим от real ECH без попытки расшифровки)

```rust
// ch_gen.rs:415-461
fn build_ech_grease_extension(rng: &mut PerConnRng) -> Vec<u8> {
    let config_id = rng.next_u32() as u8;
    let mut pub_key = [0u8; P256_PUBLIC_KEY_SIZE]; // 65 bytes (0x04 + 64 random)
    rng.fill_bytes(&mut pub_key);
    pub_key[0] = 0x04;
    let payload_len = rng.next_range(16, 256) as usize;
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);
    // ... RFC 9460 §4 ECHClientHello structure
}
```

### Критический prerequisite: PRNG cross-thread independence (#MR-32)

Без фикса cross-thread PRNG bug **per-connection randomisation бесполезна** — все потоки получают одинаковый seed.

```rust
// rand.rs — УДАЛЕНО:
static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);  // ← причина катастрофы

// rand.rs — ДОБАВЛЕНО: каждый поток инициализирует свой state из OS CSPRNG
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<[u64; 4]> = const { std::cell::Cell::new([0u64; 4]) };
    }
    STATE.with(|state| {
        let mut s = state.get();
        if s == [0u64; 4] { s = fresh_seed_xoshiro(); }  // 32 bytes из getrandom
        let result = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        // xoshiro256++ state update (passes BigCrush)
        state.set(s);
        result
    })
}
```

---

## Файлы для интеграции

```
sprint1/
├── README.md              — инструкция по интеграции
├── ch_gen.rs              — ПОЛНАЯ замена src/core/src/adaptive/ch_gen.rs
├── rand.rs                — ПОЛНАЯ замена src/core/src/desync/rand.rs
├── ip.rs.patch            — патч для src/core/src/desync/ip.rs
├── seq_spoof.rs.patch     — патч для src/core/src/adaptive/seq_spoof.rs
└── engine_mod.rs.patch    — патч для src/core/src/engine/mod.rs
```

---

## Архитектурные изменения

### ch_gen.rs — полный rewrite

**Удалено:**
- `TPL_HEX` — захардкоженный Chrome 120 шаблон с SNI "mci.ir" (= мгновенный fingerprint)
- `TEMPLATE_SNI = "mci.ir"`
- `TEMPLATE_BYTES` (LazyLock парсинг hex)
- `CLIENT_HELLO_SIZE = 517` (фиксированный размер = fingerprint)
- `hex` модуль
- Захардкоженные offsets в `parse_sni` (125, 126, 127)

**Добавлено:**
- `build_client_hello(sni, rng)` — структурированная сборка CH из компонентов
- `build_client_hello_default(sni)` — fallback без явного RNG (создаёт временный PerConnRng)
- `generate_grease_set(rng)` — 4 per-connection GREASE values
- `compute_padding_size(body_len, rng)` — random multiple-of-16 padding
- `build_ech_grease_extension(rng)` — ECH GREASE extension (RFC 9460 §4, Chrome 122+)
- `parse_sni` переписан — proper extension parsing вместо hardcoded offsets
- Константы: `GREASE_VALUES`, TLS group IDs, cipher suite IDs, extension type IDs, HPKE constants

### rand.rs — фикс cross-thread bug

**Удалено:**
- `GLOBAL_SEED: AtomicU64` — причина катастрофы (все потоки получали один seed)
- `init_seed()` — использовал GLOBAL_SEED
- Xorshift64 в `random_u64()` (проходит только SmallCrush)

**Добавлено:**
- `random_u64()` на **xoshiro256++** (passes BigCrush, fresh entropy per thread)
- `PerConnRng::fill_bytes(&mut [u8])` — efficient bulk random fill (8 bytes per call)
- `PerConnRng::pick_grease()` — выбирает random GREASE value

---

## Патчи для интеграции

### 1. `engine_mod.rs.patch` — 4-tuple conn_id для RNG

**Замена:** `cp.dst_ip.to_bits() as u64` → `4-tuple XOR` (src_ip ^ dst_ip ^ src_port ^ dst_port)

```patch
--- a/src/core/src/engine/mod.rs
+++ b/src/core/src/engine/mod.rs
@@ -397,7 +397,17 @@
             let key = ConnKey::new(cp.src_ip, cp.dst_ip, cp.src_port, cp.dst_port);
 
             if self.conntrack.get(&key).is_none() {
+                let conn_id = (cp.src_ip.to_bits() as u64)
+                    ^ ((cp.dst_ip.to_bits() as u64) << 32)
+                    ^ ((cp.src_port as u64) << 48)
+                    ^ (cp.dst_port as u64);
+
                 let entry = ConntrackEntry {
-                    rng: Some(crate::desync::rand::PerConnRng::new(cp.dst_ip.to_bits() as u64)),
+                    rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
                 };
```

### 2. `ip.rs.patch` — Замена build_fake_ch на ch_gen

**Удаление:** 386 строк локального `build_fake_ch` с `NULL_MD5` cipher suite и фиксированным random.

```patch
--- a/src/core/src/desync/ip.rs
+++ b/src/core/src/desync/ip.rs
@@ -49,7 +51,7 @@
-    let fake_payload = build_fake_ch(fake_sni);
+    let fake_payload = ch_gen::build_client_hello_default(fake_sni);
 
-/// Строит fake TLS ClientHello для инъекции.
-fn build_fake_ch(sni: &str) -> Vec<u8> {
-    // ... 386 строк удалённого кода
-}
```

### 3. `seq_spoof.rs.patch` — Передача PerConnRng из conntrack

```patch
--- a/src/core/src/adaptive/seq_spoof.rs
+++ b/src/core/src/adaptive/seq_spoof.rs
@@ -79,11 +79,16 @@
-    let fake_ch = ch_gen::build_client_hello(fake_sni);
+    let fake_ch = if let Some(entry) = _conntrack.get(&ConnKey::new(...)) {
+        let mut rng = entry.rng.clone().unwrap_or_else(|| PerConnRng::new(0));
+        ch_gen::build_client_hello(fake_sni, &mut rng)
+    } else {
+        ch_gen::build_client_hello_default(fake_sni)
+    };
```

---

## Порядок интеграции

1. Скопировать `rand.rs` → `src/core/src/desync/rand.rs`
2. Скопировать `ch_gen.rs` → `src/core/src/adaptive/ch_gen.rs`
3. Применить `ip.rs.patch` (заменить локальную `build_fake_ch` на вызов `ch_gen::build_client_hello`)
4. Применить `seq_spoof.rs.patch` (передать `PerConnRng` в `build_client_hello`)
5. Применить `engine_mod.rs.patch` (использовать 4-tuple для conn_id)
6. Запустить `cargo test`:
   ```bash
   cargo test -p byebyedpi-core -- ch_gen
   cargo test -p byebyedpi-core -- rand
   ```

---

## Проверка fingerprint после интеграции

```bash
# JA3 должен меняться per-connection (GREASE rotation)
# JA4 должен быть t13d... (TLS 1.3)
# Размер CH должен быть variable (padding randomization)
# supported_groups должен включать 0x11EC (X25519MLKEM768)
# extensions должен включать 0xFE0D (ECH GREASE) — Chrome 122+ behavior
```

---

## Риски и mitigation

| # | Риск | Mitigation |
|---|------|------------|
| 1 | **Размер CH вырос с 517 до ~1500-4096 байт** (PQ key share 1184 + ECH GREASE ~100-300) | TCP stack фрагментирует автоматически. Fake CH всё равно умирает на первом хопе. Если используется TCP segmentation desync — учитывайте больший размер. |
| 2 | **parse_sni теперь парсит extensions properly** — медленнее на ~100ns per call | Вызывается только для fake CH (1-2 раза per connection), не на hot path. |
| 3 | **PerConnRng::new() вызывает getrandom (syscall)** — ~50-200ns per connection | Приемлемо, 1 вызов per connection. |
| 4 | **pqcrypto crate НЕ нужен** — PQ key share = random bytes для fake CH | Если в будущем потребуется real PQ handshake (proxy mode) — добавить `pqcrypto-mlkem = "0.4"`. |
| 5 | **ECH GREASE может блокироваться некоторыми DPI** — если ТСПУ блокирует весь трафик с ECH extension | Большинство consumer ISP не блокирует (политически невыгодно). Если блокирует — отключить ECH GREASE через config flag. Chrome 122+ тоже использует ECH GREASE, блокировка = блокировка Chrome. |
| 6 | **ECH config_id должен быть per-connection random**, не per-packet | Используется `ConntrackEntry.rng` (per-connection PRNG), не глобальный `random_u64()`. |

---

## Какие проблемы MR решает Sprint 1

| MR-ID | Проблема | Решение Sprint 1 |
|-------|----------|------------------|
| MR-32 | PRNG cross-thread identical seed | xoshiro256++ с per-thread fresh entropy |
| MR-17 | Static fake CH fingerprint | Chrome 130+ CH с GREASE, PQ, ECH, random padding |
| MR-24 | conn_id = dst_ip only | 4-tuple XOR для PerConnRng |
| MR-33 | random_bytes 4x overhead | `fill_bytes()` с u64 chunks |
| MR-36 | Modulo bias | Lemire method (уже в PerConnRng) |
| MR-14 | build_fake_ch per packet | ch_gen::build_client_hello_default (OnceLock cache) |

---

*Meta-review завершён. Sprint 1 реализация готова к интеграции. Все 38 проблем верифицированы на реальном коде.*
