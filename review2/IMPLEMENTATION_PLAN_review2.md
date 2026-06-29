# ByeByeDPI Windows v3.0 — Implementation Plan (на основе meta_review2.md)

## Обзор

- **38 MR-задач** (MR-01 — MR-38)
- **6 уникальных решений экспертов** (не в основных MR)
- **Sprint 1** — 4 DPI evasion техники + PRNG fix (3 файла + 3 патча)
- **14 файлов** к изменению/созданию
- **Нет заглушек и мёртвого кода** — только полноценные реализации

## Группировка по файлам

| Файл | MR | Количество задач |
|------|----|-----------------|
| `engine/mod.rs` | MR-01, MR-02, MR-03, MR-04, MR-07, MR-09, MR-15, MR-16, MR-18, MR-24, MR-25 | 11 |
| `packet_engine.rs` | MR-06, MR-08 | 2 |
| `desync/rand.rs` | Sprint 1 (full), MR-33, MR-34, MR-36 | 4 |
| `desync/mod.rs` | MR-10, MR-13, MR-26 | 3 |
| `desync/group.rs` | MR-16, MR-22, MR-23, MR-30, MR-31 | 5 |
| `desync/ip.rs` | MR-14, MR-17, MR-19, MR-20, MR-21, Sprint 1 patch | 6 |
| `desync/tls.rs` | MR-22 | 1 |
| `desync/pool.rs` | MR-11 | 1 |
| `conntrack.rs` | MR-05 | 1 |
| `classifier.rs` | MR-27 | 1 |
| `infra/event_tag.rs` | MR-18 | 1 |
| `adaptive/hop_tab.rs` | MR-28, MR-29 | 2 |
| `adaptive/ch_gen.rs` | Sprint 1 (new) | 1 |
| `adaptive/seq_spoof.rs` | Sprint 1 patch | 1 |

---

# ФАЙЛ 1: `src/core/src/engine/mod.rs` (11 задач)

## Задача E1: Замена ArrayQueue на mpsc::channel (MR-01 + MR-02)

**MR:** MR-01 (CRITICAL) + MR-02 (CRITICAL)
**Что делаем:** Удаляем `crossbeam::queue::ArrayQueue` и `while let Some(captured) = ring_rx.pop()`. Заменяем на `tokio::sync::mpsc::channel` с `blocking_send` (backpressure) и `rx.recv()` (не выходит при пустой очереди).

**Конкретные изменения:**
1. Удалить импорт `crossbeam::queue::ArrayQueue`
2. Добавить `use tokio::sync::mpsc;`
3. В `run()` создать `let (tx, mut rx) = mpsc::channel::<CapturedPacket>(8192);`
4. Producer thread: `tx.blocking_send(CapturedPacket { data, addr })` вместо `ring_tx.push()`
5. Consumer loop: `tokio::select! { _ = shutdown.recv() => break, captured = rx.recv() => { ... } }` вместо `while let Some`
6. Удалить `let _ = handle.await;` — producer завершается через channel drop

**Верификация:**
- `cargo build -p byebyedpi-core` — компилируется
- `cargo test -p byebyedpi-core` — все тесты проходят
- Ручная проверка: запустить с `--only-outbound`, открыть YouTube, переключить качество — pipeline не падает при паузах в трафике
- Лог: `packets_received` растёт непрерывно, `dropped` = 0 при нормальной нагрузке

---

## Задача E2: send_blocking в spawn_blocking (MR-03)

**MR:** MR-03 (CRITICAL)
**Что делаем:** Оборачиваем все `self.packet_engine.send_blocking()` вызовы из async context в `tokio::task::spawn_blocking`.

**Конкретные изменения:**
1. `forward_packet()` — обернуть `send_blocking` в `spawn_blocking`:
```rust
async fn forward_packet(&self, captured: &CapturedPacket) {
    let engine = self.packet_engine.clone();
    let data = captured.data.clone();
    let addr = captured.addr.clone();
    let result = tokio::task::spawn_blocking(move || {
        engine.send_blocking(&data, &addr)
    }).await;
    match result {
        Ok(Ok(_)) => { self.stats.forwarded.fetch_add(1, Ordering::Relaxed); }
        Ok(Err(e)) => { error!("Forward failed: {}", e); self.stats.errors.fetch_add(1, Ordering::Relaxed); }
        Err(e) => { error!("spawn_blocking panicked: {}", e); self.stats.errors.fetch_add(1, Ordering::Relaxed); }
    }
}
```
2. Modify path (строка ~280) — аналогично обернуть `send_blocking` в `spawn_blocking`

**Верификация:**
- `cargo build -p byebyedpi-core`
- Лог: нет "executor thread blocked" warnings
- Нагрузка: 10K одновременных TCP соединений — executor не застревает

---

## Задача E3: Desync через rayon pool (MR-04)

**MR:** MR-04 (HIGH)
**Что делаем:** Заменяем `tokio::task::spawn_blocking` для десинхронизации на `Runtime::global().spawn_cpu()`, который отправляет задачи в уже созданный rayon thread pool (`lib.rs:55-59`).

**Конкретные изменения:**
1. Добавить `use crate::Runtime;`
2. В `apply_desync_async()` заменить:
```rust
// БЫЛО:
tokio::task::spawn_blocking(move || group.apply(&packet))
// СТАЛО:
Runtime::global().spawn_cpu(move || group.apply(&packet)).await
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- `cargo test -p byebyedpi-core -- spawn_cpu` — тест rayon пула
- Проверить что в `top`/`htop` видны потоки `byedpi-cpu-*` (rayon threads)
- Under load: CPU utilisation распределяется между всеми ядрами, а не одним

---

## Задача E4: DashMap для InjectedSeqTracker (MR-07)

**MR:** MR-07 (HIGH)
**Что делаем:** Заменяем `std::sync::Mutex<HashMap<u32, Instant>>` на `DashMap<(u32, u32, u16, u16, u32), Instant>` с 5-tuple ключом.

**Конкретные изменения:**
1. Удалить структуру `InjectedSeqTracker` (строки 128-158)
2. Заменить поле в `ProcessingPipeline`:
```rust
// БЫЛО:
injected_seqs: std::sync::Mutex<InjectedSeqTracker>,
// СТАЛО:
injected_seqs: DashMap<(u32, u32, u16, u16, u32), Instant>,
```
3. Инициализация: `DashMap::with_capacity_and_shard_amount(65536, 64)`
4. Метод `contains` → `self.injected_seqs.get(&key).map(|t| t.elapsed() < TTL).unwrap_or(false)`
5. Метод `insert` → `self.injected_seqs.insert(key, Instant::now())`
6. Ключ = `(src_ip.to_bits(), dst_ip.to_bits(), src_port, dst_port, seq)`
7. GC: запускать асинхронно (например, через `tokio::spawn` каждые 30 сек), удалять записи с `elapsed() > TTL`
8. Во всех местах вызова (строки ~431, ~505) передавать полный 5-tuple

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: 1000 одновременных TLS соединений — нет cross-connection collisions
- Лог: нет "Mutex contention" warnings
- Проверить что GC работает: после 30 сек старые записи удаляются

---

## Задача E5: captured.data.clone() вместо copy_from_slice (MR-09)

**MR:** MR-09 (CRITICAL)
**Что делаем:** Убираем дублирующее копирование пакетов в `process_quic`, `process_http`, `process_outbound_tls`.

**Конкретные изменения:**
1. `process_quic()` (строка ~378): заменить `bytes::Bytes::copy_from_slice(original_packet)` на `captured.data.clone()`
2. `process_http()` (строка ~400): аналогично
3. `process_outbound_tls()` (строка ~497): аналогично
4. Во всех трёх методах добавить параметр `captured: &CapturedPacket` (или передавать `captured.data`)

**Верификация:**
- `cargo build -p byebyedpi-core`
- Профилирование: `heaptrack` или `dhat` — количество malloc/сек должно уменьшиться на ~50%
- Under load: L3 cache miss rate снижается (проверить через perf counters)

---

## Задача E6: BadChecksum только для inject (MR-16)

**MR:** MR-16 (CRITICAL)
**Что делаем:** В pipeline_mode `BadChecksum` применяется ТОЛЬКО к inject пакетам, НЕ к `state.packet`.

**Конкретные изменения в `desync/group.rs`:**
```rust
DesyncTechnique::BadChecksum => {
    // Портим checksum только в inject пакетах
    state.injects = state.injects.iter().map(|pkt| {
        ip::bad_checksum(pkt).modified.unwrap_or_else(|| pkt.clone())
    }).collect();
    // state.packet НЕ трогаем — оригинальный пакет идёт к серверу с правильным checksum
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: подключиться к сайту через ByeByeDPI — соединение не рвётся
- Проверить: инжектируемые fake пакеты имеют неверный checksum (tcpdump/wireshark), оригинальный пакет — правильный

---

## Задача E7: inject_tcp_packet без to_vec (MR-15)

**MR:** MR-15 (MEDIUM)
**Что делаем:** Убираем `inject_pkt.to_vec()` — передаём тег через WinDivertAddress (Out-of-band), не модифицируя payload.

**Конкретные изменения:**
1. Убрать `let mut tagged = inject_pkt.to_vec()` и `event_tag::tag_injected_packet(&mut tagged)`
2. Использовать `inject_via_divert(inject_pkt, addr)` напрямую (без копирования)
3. Для detection自己的 пакетов — использовать `WinDivertAddress` flags вместо payload inspection

**Верификация:**
- `cargo build -p byebyedpi-core`
- Лог: `is_injected_packet` не вызывается (или вызывается через addr flags)
- Проверить: injected пакеты не содержат UUID в payload (wireshark)

---

## Задача E8: event_tag через IP ID (MR-18)

**MR:** MR-18 (CRITICAL)
**Что делаем:** Помечаем injected пакеты через зарезервированный бит в IP ID, а НЕ через TCP payload.

**Конкретные изменения в `infra/event_tag.rs`:**
1. Удалить `tag_injected_packet()` (запись UUID в TCP payload)
2. Реализовать `tag_ip_id(packet: &mut [u8])` — установить бит 15 в IP Identification field (RFC 791 резервирует биты 0-2 для flags, но бит 15 ID很少 используется)
3. Реализовать `is_tagged_ip_id(packet: &[u8]) -> bool` — проверить бит 15
4. Обновить `injected_filter_clause()` — WinDivert фильтр по IP ID bit
5. В `engine/mod.rs`: заменить вызовы `tag_injected_packet` на `tag_ip_id`

**Верификация:**
- `cargo build -p byebyedpi-core`
- Проверить: injected пакеты не содержат UUID в TCP payload
- Проверить: `is_injected_packet` корректно определяет свои пакеты по IP ID
- Тест: infinite loop (inject→divert→inject) больше не происходит

---

## Задача E9: 4-tuple conn_id для PerConnRng (MR-24)

**MR:** MR-24 (HIGH)
**Что делаем:** Заменяем `cp.dst_ip.to_bits() as u64` на 4-tuple XOR для `PerConnRng::new()`.

**Конкретные изменения:**
```rust
// БЫЛО (engine/mod.rs ~484):
rng: Some(crate::desync::rand::PerConnRng::new(cp.dst_ip.to_bits() as u64)),

// СТАЛО:
let conn_id = (cp.src_ip.to_bits() as u64)
    ^ ((cp.dst_ip.to_bits() as u64) << 32)
    ^ ((cp.src_port as u64) << 48)
    ^ (cp.dst_port as u64);
rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: два соединения к одному серверу — PerConnRng генерирует разные последовательности
- Проверить через `test_cross_thread_independence` в rand.rs

---

## Задача E10: is_outbound через Windows API (MR-25)

**MR:** MR-25 (HIGH)
**Что делаем:** Заменяем hardcoded приватные CIDR на dynamic detection через `GetAdaptersAddresses`.

**Конкретные изменения:**
1. Добавить модуль `local_ips.rs` (или в `classifier.rs`):
```rust
pub fn get_local_ips() -> Vec<Ipv4Addr> {
    // Windows API: GetAdaptersAddresses
    // Кэшировать при старте, обновлять каждые 60 сек
}
```
2. В `ProcessingPipeline` хранить `local_ips: Arc<RwLock<Vec<Ipv4Addr>>>`
3. Заменить `is_outbound(src_ip)` на `self.local_ips.read().contains(src_ip)`
4. Запускать refresh в background task

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест на VPS с публичным IP: `is_outbound(local_ip)` = true
- Тест: `is_outbound(8.8.8.8)` = false
- Проверить что локальные IP определяются корректно: `ipconfig` vs код

---

# ФАЙЛ 2: `src/core/src/packet_engine.rs` (2 задачи)

## Задача P1: WinDivert queue params (MR-06)

**MR:** MR-06 (HIGH)
**Что делаем:** Меняем `QueueLength` и `QueueTime` на правильные значения.

**Конкретные изменения (строки 101-106):**
```rust
// БЫЛО:
divert.set_param(WinDivertParam::QueueLength, 8192)
divert.set_param(WinDivertParam::QueueTime, 2000)

// СТАЛО:
divert.set_param(WinDivertParam::QueueLength, 65535)?;
divert.set_param(WinDivertParam::QueueTime, 500)?;
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Under load: WinDivert не дропает пакеты при burst (проверить через `windivert_stats`)
- Latency: p99 < 50ms при 1 Gbps нагрузке

---

## Задача P2: update_filter через ArcSwap (MR-08)

**MR:** MR-08 (MEDIUM)
**Что делаем:** Заменяем `Option<WinDivert<NetworkLayer>>` на `ArcSwap<WinDivert<NetworkLayer>>` для hot-reload фильтра.

**Конкретные изменения:**
1. `divert: Option<WinDivert<NetworkLayer>>` → `divert: ArcSwap<WinDivert<NetworkLayer>>`
2. `recv_blocking`: `let divert = self.divert.load(); divert.recv(buffer)?`
3. `send_blocking`: `let divert = self.divert.load(); divert.send(&wd_packet)?`
4. `update_filter`: `self.divert.store(Arc::new(new_divert))`
5. Все `&self.divert` заменить на `self.divert.load()`

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: обновить фильтр через API во время работы — pipeline не падает
- Проверить: новые пакеты фильтруются по новому фильтру

---

# ФАЙЛ 3: `src/core/src/desync/rand.rs` (Sprint 1 + MR-33, MR-34, MR-36)

## Задача R1: Полная замена rand.rs (Sprint 1 + MR-32 + MR-33 + MR-34 + MR-35 + MR-36)

**MR:** MR-32 (CRITICAL), MR-33, MR-34, MR-35, MR-36 + Sprint 1 PRNG fix
**Что делаем:** Полная замена файла на `review2/new/rand.rs`. Это решает 6 проблем одновременно.

**Ключевые изменения:**
1. **MR-32:** Удалить `GLOBAL_SEED: AtomicU64` и `init_seed()`. `random_u64()` → xoshiro256++ с per-thread fresh entropy из `getrandom`
2. **MR-33:** `random_bytes()` → `fill_random_bytes()` с u64 chunks (8 байт per call вместо 1)
3. **MR-34:** `mask_to_positions()` → branchless с `trailing_zeros`
4. **MR-35:** `PerConnRng::new()` — getrandom syscall (приемлемо: 1 call per connection)
5. **MR-36:** `random_range()` → Lemire method (уже в PerConnRng)
6. **Sprint 1:** Добавить `GREASE_VALUES`, `pick_grease()`, `generate_grease_set()`, `fill_bytes()`

**Верификация:**
- `cargo test -p byebyedpi-core -- rand` — все тесты проходят
- `test_cross_thread_independence` — потоки получают разные последовательности
- `test_perconnrng_reseed` — reseed работает
- `test_random_bytes_filled` — random_bytes заполняет ненулевыми данными

---

# ФАЙЛ 4: `src/core/src/desync/mod.rs` (3 задачи)

## Задача D1: BytesMut в build_ip_packet (MR-10)

**MR:** MR-10 (HIGH)
**Что делаем:** Заменяем `vec![0u8; total_len]` на `bytes::BytesMut::with_capacity(total)` в `build_ip_packet()`.

**Конкретные изменения (строки 569-597):**
```rust
pub fn build_ip_packet(...) -> bytes::Bytes {
    let total_len = 20 + payload.len();
    let mut buf = bytes::BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);
    // ... fill header через MutableIpv4Packet
    buf.freeze() // single allocation → Bytes
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Профилирование: количество heap allocations снижается

---

## Задача D2: inject_slices без Vec (MR-13)

**MR:** MR-13 (MEDIUM)
**Что делаем:** Заменяем `Vec<&[u8]>` на `impl Iterator<Item = &[u8]>` или возвращаем `&[Bytes]`.

**Конкретные изменения (строки 130-132):**
```rust
// БЫЛО:
pub fn inject_slices(&self) -> Vec<&[u8]> {
    self.inject.iter().map(|b| b.as_ref()).collect()
}
// СТАЛО:
pub fn inject_slices(&self) -> &[bytes::Bytes] {
    &self.inject
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Все вызывающие коды обновлены (grep `inject_slices`)

---

## Задача D3: ipv4_checksum variable length (MR-26)

**MR:** MR-26 (HIGH)
**Что делаем:** Заменяем hardcoded 20-byte checksum на variable-length (учитывает IP options).

**Конкретные изменения (строки 480-496):**
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

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: пакет с IP options (IHL=7, 28 bytes header) — checksum корректен
- Сравнить с `pnet_packet::util::ipv4_checksum` — результаты совпадают

---

# ФАЙЛ 5: `src/core/src/desync/group.rs` (5 задач)

## Задача G1: BadChecksum только для inject (MR-16)

См. Задачу E6 — изменения в group.rs.

---

## Задача G2: Удалить SniMasking (MR-22)

**MR:** MR-22 (HIGH)
**Что делаем:** Удаляем `DesyncTechnique::SniMasking` из `apply_to_state` и `apply_single`. Оставляем enum variant для backward compatibility, но делаем `passthrough`.

**Конкретные изменения:**
```rust
// В apply_to_state:
DesyncTechnique::SniMasking => {
    // SniMasking removed: сервер не может восстановить маскированный SNI
    // Используйте FakeSni вместо этого
    tracing::warn!("SniMasking is deprecated and disabled — use FakeSni instead");
}

// В apply_single:
DesyncTechnique::SniMasking => DesyncResult::passthrough(),
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- При использовании SniMasking в конфиге — пакет проходит без изменений + warning в логе

---

## Задача G3: Удалить ChaCha20 (MR-23)

**MR:** MR-23 (HIGH)
**Что делаем:** Удаляем `DesyncTechnique::ChaCha20` из `apply_to_state` и `apply_single`.

**Конкретные изменения:**
```rust
// В apply_to_state:
DesyncTechnique::ChaCha20 => {
    tracing::warn!("ChaCha20 with hardcoded key is disabled — broken by design");
}

// В apply_single:
DesyncTechnique::ChaCha20 => DesyncResult::passthrough(),
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- При использовании ChaCha20 в конфиге — пакет проходит без изменений + warning

---

## Задача G4: ContentLengthFuzz random (MR-30)

**MR:** MR-30 (MEDIUM)
**Что делаем:** Заменяем хардкод `99999` на случайное значение.

**Конкретные изменения (строка ~333):**
```rust
// БЫЛО:
DesyncTechnique::ContentLengthFuzz => http::content_length_fuzz(packet, 99999),
// СТАЛО:
DesyncTechnique::ContentLengthFuzz => {
    let fake_len = crate::desync::rand::random_range(100_000, 2_000_000);
    http::content_length_fuzz(packet, fake_len)
},
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: несколько HTTP запросов — Content-Length разный

---

## Задача G5: DscpRandom per-connection (MR-31)

**MR:** MR-31 (MEDIUM)
**Что делаем:** DSCP должен быть постоянным per-connection, а не random per-packet.

**Конкретные изменения:**
1. Добавить поле `dscp_spoof: u8` в `ConntrackEntry`
2. При создании entry: `dscp_spoof: random_range(0, 48) as u8`
3. В `dscp_random()`: принимать `dscp_value: u8` parameter, использовать его
4. В `apply_to_state`: передавать `dscp_value` из conntrack

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: один TCP connection — DSCP одинаковый на всех пакетах
- Разные соединения — разные DSCP

---

# ФАЙЛ 6: `src/core/src/desync/ip.rs` (6 задач + Sprint 1 patch)

## Задача I1: Замена build_fake_ch на ch_gen (MR-14 + MR-17 + Sprint 1)

**MR:** MR-14 (MEDIUM), MR-17 (CRITICAL) + Sprint 1
**Что делаем:** Удаляем локальную `build_fake_ch()` (386 строк с NULL_MD5 и фиксированным random). Заменяем на вызов `ch_gen::build_client_hello_default()`.

**Конкретные изменения:**
1. Добавить `use crate::adaptive::ch_gen;`
2. В `frag_overlap()` (строка ~48): `let fake_payload = ch_gen::build_client_hello_default(fake_sni);`
3. Удалить функцию `build_fake_ch()` целиком (строки 323-387)

**Верификация:**
- `cargo build -p byebyedpi-core`
- `cargo test -p byebyedpi-core -- ch_gen` — тесты ch_gen проходят
- Проверить через wireshark: fake CH содержит GREASE, PQ key share, ECH GREASE
- JA3 fingerprint разный для разных соединений

---

## Задача I2: IP frag offset fix (MR-19)

**MR:** MR-19 (CRITICAL)
**Что делаем:** Исправляем математическую ошибку в `frag_overlap` — выравниваем offset на 8-байтную границу.

**Конкретные изменения (строки 70-71):**
```rust
// БЫЛО:
let overlap_offset = tcp_header_len;
let frag2_offset_units = overlap_offset.div_ceil(8) as u16;

// СТАЛО:
let overlap_offset_bytes = tcp_header_len.next_multiple_of(8); // Rust 1.73+
let frag2_offset_units = (overlap_offset_bytes / 8) as u16;
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: пакет с TCP header 20 bytes → offset = 24 (3 units), не 20
- Тест: пакет с TCP header 24 bytes → offset = 24 (3 units), не 20
- Wireshark: фрагменты корректно реассемблируются

---

## Задача I3: Удалить mutual_spoof (MR-21)

**MR:** MR-21 (CRITICAL)
**Что делаем:** Удаляем функцию `mutual_spoof()` и делаем `passthrough`.

**Конкретные изменения:**
```rust
// В ip.rs — mutual_spoof():
pub fn mutual_spoof(_packet: &[u8]) -> DesyncResult {
    // Removed: пакет уходил обратно к клиенту, сервер не получал данных
    DesyncResult::passthrough()
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- При использовании MutualSpoof — пакет проходит без изменений

---

## Задача I4: bad_checksum только для inject (MR-20)

**MR:** MR-20 (CRITICAL)
**Что делаем:** Решается через MR-16 (Задача G1). `bad_checksum()` остаётся как функция, но вызывается только из group.rs для inject пакетов, не для modified.

**Верификация:**
- См. Задачу G6

---

## Задача I5: Modulo bias fix (MR-36)

**MR:** MR-36 (LOW)
**Что делаем:** Заменяем `% 7` на `random_range(0, 6)` в `ttl_jitter` и `dscp_random`.

**Конкретные изменения:**
```rust
// ip.rs:403 — БЫЛО:
let jitter = (crate::desync::rand::random_u32() % 7) as i16 - 3;
// СТАЛО:
let jitter = crate::desync::rand::random_range(0, 6) as i16 - 3;

// ip.rs:431 — БЫЛО:
let new_dscp = [...][(crate::desync::rand::random_u32() % 7) as usize];
// СТАЛО:
let idx = crate::desync::rand::random_range(0, 6) as usize;
let new_dscp = [0u8, 8, 16, 24, 32, 40, 48][idx];
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: 10000 вызовов `random_range(0, 6)` — распределение равномерное (χ² test)

---

# ФАЙЛ 7: `src/core/src/desync/tls.rs` (1 задача)

## Задача T1: Удалить sni_masking вызов (MR-22)

См. Задачу G2 — `tls::sni_masking()` больше не вызывается из pipeline.

---

# ФАЙЛ 8: `src/core/src/desync/pool.rs` (1 задача)

## Задача PO1: Удалить мёртвый pool.rs (MR-11)

**MR:** MR-11 (MEDIUM)
**Что делаем:** Удаляем файл `pool.rs` и его декларацию в `mod.rs`.

**Конкретные изменения:**
1. Удалить `src/core/src/desync/pool.rs`
2. В `desync/mod.rs`: удалить строку `pub mod pool;`

**Верификация:**
- `cargo build -p byebyedpi-core` — компилируется без pool.rs
- `grep -r "desync::pool" src/` — ноль результатов

---

# ФАЙЛ 9: `src/core/src/conntrack.rs` (1 задача)

## Задача CT1: Incremental GC (MR-05)

**MR:** MR-05 (HIGH)
**Что делаем:** Заменяем `gc()` и `gc_fast()` на incremental GC с time budget ≤1ms.

**Конкретные изменения:**
1. Добавить метод `gc_incremental()`:
```rust
pub fn gc_incremental(&self, max_idle: Duration) {
    let deadline = Instant::now() + Duration::from_millis(1);
    let mut evicted = 0u64;

    for mut shard in self.inner.map.shards_mut() {
        if Instant::now() > deadline { break; }
        let mut to_remove = Vec::new();
        for entry in shard.iter() {
            if entry.value().last_activity.elapsed() > max_idle {
                to_remove.push(*entry.key());
            }
        }
        for key in to_remove {
            shard.remove(&key);
            evicted += 1;
            self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
    if evicted > 0 { debug!("GC incremental: evicted {} entries", evicted); }
}
```
2. В `gc_loop()` заменить `self.gc(...)` на `self.gc_incremental(...)`
3. Оставить старый `gc()` как deprecated (или удалить)

**Верификация:**
- `cargo build -p byebyedpi-core`
- `cargo test -p byebyedpi-core -- conntrack`
- Under load: GC pause < 1ms (проверить через tracing timestamps)
- 100K connections: stale entries удаляются за несколько циклов GC

---

# ФАЙЛ 10: `src/core/src/classifier.rs` (1 задача)

## Задача CL1: Content-based classification (MR-27)

**MR:** MR-27 (HIGH)
**Что делаем:** Добавляем Deep Packet Inspection перед port-based fallback.

**Конкретные изменения в `classify()` (строки 95-99):**
```rust
match protocol {
    6 => { // TCP
        // ... existing tcp parsing ...
        let payload = &packet[payload_offset..];

        // Content-based classification (DPI)
        if payload.len() >= 5 {
            // TLS ClientHello: 0x16 0x03 0x01-0x03
            if payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x03 {
                return Classification::Tls(cp);
            }
            // HTTP methods
            if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") ||
               payload.starts_with(b"PUT ") || payload.starts_with(b"HEAD ") ||
               payload.starts_with(b"CONNECT ") {
                return Classification::Http(cp);
            }
            // HTTP/2 connection preface
            if payload.len() >= 24 && &payload[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
                return Classification::Http(cp); // или Http2
            }
        }

        // Port-based fallback
        match dst_port {
            443 => Classification::Tls(cp),
            80 => Classification::Http(cp),
            _ => Classification::Other(cp),
        }
    }
    17 => { // UDP
        // ... existing udp parsing ...
        let payload = &packet[payload_offset..];
        // QUIC Long Header: first bit = 1
        if !payload.is_empty() && (payload[0] & 0x80) != 0 {
            return Classification::Quic(cp);
        }
        match dst_port {
            53 => Classification::Dns(cp),
            443 => Classification::Quic(cp),
            _ => Classification::Other(cp),
        }
    }
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- `cargo test -p byebyedpi-core -- classifier`
- Тест: TLS на порту 8443 → `Classification::Tls`
- Тест: QUIC на порту 443 (UDP) → `Classification::Quic`
- Тест: HTTP на порту 8080 → `Classification::Http`

---

# ФАЙЛ 11: `src/core/src/infra/event_tag.rs` (1 задача)

## Задача ET1: event_tag через IP ID (MR-18)

См. Задачу E8 — полная переработка `event_tag.rs`.

---

# ФАЙЛ 12: `src/core/src/adaptive/hop_tab.rs` (2 задачи)

## Задача H1: fake_ttl=1 вместо 0 (MR-28)

**MR:** MR-28 (HIGH)
**Что делаем:** Исправляем `fake_ttl()` — возвращаем 1 вместо 0 для близких серверов.

**Конкретные изменения (строки 67-72):**
```rust
// БЫЛО:
if hops <= 2 { return 0; }
// СТАЛО:
if hops <= 2 { return 1; } // TTL=1: дойдёт до DPI но умрёт на первом router
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: сервер в той же LAN (hops=1) → fake_ttl=1, не 0
- Wireshark: fake packet имеет TTL=1

---

## Задача H2: Murmur3 hash (MR-29)

**MR:** MR-29 (MEDIUM)
**Что делаем:** Заменяем FNV-1a multiplicative hash на Murmur3 finalizer.

**Конкретные изменения (строки 50-54):**
```rust
// БЫЛО:
fn hash(ip: u32) -> usize {
    let mut h = ip.wrapping_mul(0x01000193);
    h ^= h >> 16;
    (h as usize) & HOPTAB_MASK
}

// СТАЛО:
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

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: IP из одной /24 (192.168.1.0-255) — хеши равномерно распределены по 4096 слотам
- Метрика: collision rate < 5% (вместо ~30% текущего)

---

# ФАЙЛ 13: `src/core/src/adaptive/ch_gen.rs` (Sprint 1 — новый файл)

## Задача CG1: Создать ch_gen.rs (Sprint 1)

**MR:** Sprint 1 (4 техники)
**Что делаем:** Добавляем новый файл `adaptive/ch_gen.rs` из `review2/new/ch_gen.rs`.

**Содержимое:** 1018 строк — полная реализация:
- `build_client_hello(sni, rng)` — структурированная сборка Chrome 130+ CH
- `build_client_hello_default(sni)` — fallback
- `parse_sni()` — proper extension parsing
- 16 extensions: GREASE, SNI, EMS, Renego, Groups, Ticket, ALPN, SCT, SigAlgs, KeyShare (PQ + X25519), PSK, Versions, CompressCert, AppSettings, ECH GREASE, GREASE
- Random padding [512, 4096] multiple of 16
- ECH GREASE extension (RFC 9460 §4)
- 20 unit tests

**Верификация:**
- `cargo test -p byebyedpi-core -- ch_gen` — все 20 тестов проходят
- `test_build_client_hello_basic` — CH ≥ 512 bytes
- `test_build_client_hello_size_variable` — размеры разные
- `test_grease_values_present` — GREASE присутствует
- `test_pq_group_present` — 0x11EC присутствует
- `test_ech_grease_present` — 0xFE0D присутствует
- `test_parse_sni_roundtrip` — SNI парсится обратно

---

# ФАЙЛ 14: `src/core/src/adaptive/seq_spoof.rs` (Sprint 1 patch)

## Задача SS1: Передача PerConnRng в build_client_hello (Sprint 1)

**MR:** Sprint 1
**Что делаем:** Используем per-conn RNG из conntrack для `build_client_hello`.

**Конкретные изменения:**
```rust
// БЫЛО:
let fake_ch = ch_gen::build_client_hello(fake_sni);

// СТАЛО:
let fake_ch = if let Some(entry) = _conntrack.get(&ConnKey::new(src_ip, dst_ip, src_port, dst_port)) {
    let mut rng = entry.rng.clone().unwrap_or_else(|| crate::desync::rand::PerConnRng::new(0));
    ch_gen::build_client_hello(fake_sni, &mut rng)
} else {
    ch_gen::build_client_hello_default(fake_sni)
};
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: fake CH разный для разных соединений (per-conn RNG)

---

# УНИКАЛЬНЫЕ РЕШЕНИЯ ЭКСПЕРТОВ (не в MR)

## Задача U1: Timing jitter между inject и forward [UNIQUE: claude2]

**Что делаем:** Используем `inject_delay_us` из конфига — поле существует, но не используется.

**Конкретные изменения в `engine/mod.rs`:**
```rust
// В process_outbound_tls, после inject:
if self.config.desync.inject_delay_us > 0 {
    let jitter = crate::desync::rand::random_range(0, self.config.desync.inject_delay_us as u32);
    tokio::time::sleep(Duration::from_micros(jitter as u64)).await;
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: inter-packet timing между inject и forward = random (не constant ~5μs)
- Wireshark: δt между fake и real пакетами меняется

---

## Задача U2: Panic isolation для desync techniques [UNIQUE: deepseek2]

**Что делаем:** Оборачиваем каждую desync technique в `catch_unwind`.

**Конкретные изменения в `desync/group.rs`:**
```rust
use std::panic::AssertUnwindSafe;

fn apply_single_safe(&self, technique: &DesyncTechnique, packet: &bytes::Bytes) -> DesyncResult {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        self.apply_single(technique, packet)
    })) {
        Ok(result) => result,
        Err(panic) => {
            tracing::error!("Technique {:?} panicked: {:?}", technique.name(),
                panic.downcast_ref::<&str>().unwrap_or(&"unknown"));
            DesyncResult::passthrough()
        }
    }
}
```

**Верификация:**
- `cargo build -p byebyedpi-core`
- Тест: malformed packet не крашит pipeline (нужен fuzz test)

---

## Задача U3: Incremental GC для Conntrack [UNIQUE: mimo2]

См. Задачу CT1 — уже включена в основные MR.

---

## Задача U4: ECH GREASE的政治 dilemma [UNIQUE: glm2_techniques_review]

Реализовано в Sprint 1 (Задача CG1) — ECH GREASE extension.

---

## Задача U5: Panic isolation [UNIQUE: deepseek2]

См. Задача U2.

---

## Задача U6: Timing jitter [UNIQUE: claude2]

См. Задача U1.

---

# ПОРЯДОК ИНТЕГРАЦИИ

## Фаза 1: Критические блокеры (1-2 дня)

| # | Задача | Файл | MR |
|---|--------|------|----|
| 1 | R1 — Замена rand.rs (Sprint 1 + MR-32) | desync/rand.rs | MR-32 |
| 2 | E8 — event_tag через IP ID | infra/event_tag.rs | MR-18 |
| 3 | I3 — Удалить mutual_spoof | desync/ip.rs | MR-21 |
| 4 | E6 — BadChecksum только для inject | desync/group.rs | MR-16 |
| 5 | I2 — IP frag offset fix | desync/ip.rs | MR-19 |

## Фаза 2: Архитектура (3-5 дней)

| # | Задача | Файл | MR |
|---|--------|------|----|
| 6 | E1 — mpsc channel (MR-01+MR-02) | engine/mod.rs | MR-01, MR-02 |
| 7 | E2 — send_blocking в spawn_blocking | engine/mod.rs | MR-03 |
| 8 | E3 — Desync через rayon pool | engine/mod.rs | MR-04 |
| 9 | E5 — captured.data.clone() | engine/mod.rs | MR-09 |
| 10 | D3 — ipv4_checksum variable length | desync/mod.rs | MR-26 |
| 11 | P1 — WinDivert queue params | packet_engine.rs | MR-06 |

## Фаза 3: DPI эффективность (1-2 недели)

| # | Задача | Файл | MR |
|---|--------|------|----|
| 12 | CG1 — ch_gen.rs (Sprint 1) | adaptive/ch_gen.rs | Sprint 1 |
| 13 | I1 — Замена build_fake_ch на ch_gen | desync/ip.rs | MR-14, MR-17 |
| 14 | SS1 — Передача PerConnRng | adaptive/seq_spoof.rs | Sprint 1 |
| 15 | E9 — 4-tuple conn_id | engine/mod.rs | MR-24 |
| 16 | G4 — ContentLengthFuzz random | desync/group.rs | MR-30 |
| 17 | U1 — Timing jitter | engine/mod.rs | UNIQUE |

## Фаза 4: Production hardening (1-2 месяца)

| # | Задача | Файл | MR |
|---|--------|------|----|
| 18 | CT1 — Incremental GC | conntrack.rs | MR-05 |
| 19 | E4 — DashMap InjectedSeqTracker | engine/mod.rs | MR-07 |
| 20 | P2 — update_filter ArcSwap | packet_engine.rs | MR-08 |
| 21 | CL1 — Content-based classifier | classifier.rs | MR-27 |
| 22 | E10 — is_outbound Windows API | engine/mod.rs | MR-25 |
| 23 | H1 — fake_ttl=1 | adaptive/hop_tab.rs | MR-28 |
| 24 | H2 — Murmur3 hash | adaptive/hop_tab.rs | MR-29 |
| 25 | G2 — Удалить SniMasking | desync/group.rs | MR-22 |
| 26 | G3 — Удалить ChaCha20 | desync/group.rs | MR-23 |
| 27 | PO1 — Удалить pool.rs | desync/pool.rs | MR-11 |
| 28 | U2 — Panic isolation | desync/group.rs | UNIQUE |
| 29 | G5 — DscpRandom per-connection | desync/group.rs + conntrack.rs | MR-31 |
| 30 | D1 — BytesMut build_ip_packet | desync/mod.rs | MR-10 |
| 31 | D2 — inject_slices без Vec | desync/mod.rs | MR-13 |

---

# СВОДНАЯ ТАБЛИЦА

| Задача | MR/Источник | Файл | Severity | Статус |
|--------|-------------|------|----------|--------|
| E1 | MR-01, MR-02 | engine/mod.rs | CRITICAL | К реализации |
| E2 | MR-03 | engine/mod.rs | CRITICAL | К реализации |
| E3 | MR-04 | engine/mod.rs | HIGH | К реализации |
| E4 | MR-07 | engine/mod.rs | HIGH | К реализации |
| E5 | MR-09 | engine/mod.rs | CRITICAL | К реализации |
| E6 | MR-16 | group.rs | CRITICAL | К реализации |
| E7 | MR-15 | engine/mod.rs | MEDIUM | К реализации |
| E8 | MR-18 | event_tag.rs | CRITICAL | К реализации |
| E9 | MR-24 | engine/mod.rs | HIGH | К реализации |
| E10 | MR-25 | engine/mod.rs | HIGH | К реализации |
| P1 | MR-06 | packet_engine.rs | HIGH | К реализации |
| P2 | MR-08 | packet_engine.rs | MEDIUM | К реализации |
| R1 | Sprint 1 + MR-32-36 | rand.rs | CRITICAL | Sprint 1 ready |
| D1 | MR-10 | desync/mod.rs | HIGH | К реализации |
| D2 | MR-13 | desync/mod.rs | MEDIUM | К реализации |
| D3 | MR-26 | desync/mod.rs | HIGH | К реализации |
| G1 | MR-16 | group.rs | CRITICAL | = E6 |
| G2 | MR-22 | group.rs | HIGH | К реализации |
| G3 | MR-23 | group.rs | HIGH | К реализации |
| G4 | MR-30 | group.rs | MEDIUM | К реализации |
| G5 | MR-31 | group.rs | MEDIUM | К реализации |
| I1 | MR-14, MR-17 | ip.rs | CRITICAL | Sprint 1 ready |
| I2 | MR-19 | ip.rs | CRITICAL | К реализации |
| I3 | MR-21 | ip.rs | CRITICAL | К реализации |
| I4 | MR-20 | ip.rs | CRITICAL | = G1 |
| I5 | MR-36 | ip.rs | LOW | К реализации |
| T1 | MR-22 | tls.rs | HIGH | = G2 |
| PO1 | MR-11 | pool.rs | MEDIUM | К реализации |
| CT1 | MR-05 | conntrack.rs | HIGH | К реализации |
| CL1 | MR-27 | classifier.rs | HIGH | К реализации |
| H1 | MR-28 | hop_tab.rs | HIGH | К реализации |
| H2 | MR-29 | hop_tab.rs | MEDIUM | К реализации |
| CG1 | Sprint 1 | ch_gen.rs | CRITICAL | Sprint 1 ready |
| SS1 | Sprint 1 | seq_spoof.rs | HIGH | Sprint 1 ready |
| U1 | UNIQUE: claude2 | engine/mod.rs | MEDIUM | К реализации |
| U2 | UNIQUE: deepseek2 | group.rs | MEDIUM | К реализации |
| U3 | UNIQUE: mimo2 | conntrack.rs | HIGH | = CT1 |
| U4 | UNIQUE: glm2 | ch_gen.rs | CRITICAL | = CG1 |
| U5 | UNIQUE: deepseek2 | group.rs | MEDIUM | = U2 |
| U6 | UNIQUE: claude2 | engine/mod.rs | MEDIUM | = U1 |

---

*План завершён. 38 MR + 6 уникальных решений + Sprint 1 = 31 уникальная задача (некоторые совпадают). Все сгруппированы по файлам, каждая с верификацией.*
