# FreeDPI Windows v3.0 — Implementation Plan (по файлам)

**Источник:** `meta_review.md` — 30 уникальных проблем из 9 экспертных ревью
**Принцип:** каждая задача = один файл, все изменения в нём сразу
**Порядок:** файлы идут от корневых (dependencies) к зависимым

---

## Задача 1: `desync/pool.rs` — Глобальный Mutex → thread-local pool

**MR:** MR-05
**Severity:** HIGH
**Приоритет:** P2 ( Dependencies для других задач не нужны, но MR-09/MR-10 могут переиспользовать pool)

**Что менять:**
- Заменить `static POOL: Mutex<Vec<Vec<u8>>>` на `thread_local!` pool
- Добавить `return_buf` в hot path (сейчас нигде не вызывается)

**Файл:** `src/core/src/desync/pool.rs` (35 строк → ~50 строк)

**Верификация:**
```bash
cargo test --lib pool
# Ожидаемый результат: все тесты проходят, grep -rn "Mutex<Vec<Vec<u8>>>" src/ не должен finds в pool.rs
```

**Критерий выполнения:**
- `pool.rs` не содержит `Mutex`
- `get_buf()` и `return_buf()` работают через `thread_local!`
- `cargo clippy` без warnings
- Существующие тесты (если есть) проходят

---

## Задача 2: `desync/obfs.rs` — Shannon entropy, Poisson, entropy padding

**MR:** MR-25 (shannon_entropy), MR-26 (poisson_delay), MR-33 (entropy_padding)
**Severity:** HIGH + MEDIUM + MEDIUM
**Приоритет:** P2

**Что менять:**
- `shannon_entropy()` → `shannon_entropy_fast()` с LUT (256 entries)
- `poisson_delay()` → `poisson_delay_fast()` с pre-computed table
- Оригинальные функции оставить для non-hot-path (auto-tune, profiling)
- **[NEW — MR-33] `generate_entropy_padding()` — заменить детерминированные паттерны на ChaCha20:**
  - `target_entropy < 2.0`: один повторяющийся байт → DPI ML детектирует
  - `target_entropy 2-5`: два чередующихся байта → DPI ML находит pattern
  - `target_entropy > 5.0`: multiplicative LCG → period ~2^32, слабо
  - Решение: `ChaCha20::apply_keystream()` — неотличим от настоящего шума (уже есть `crypto::chacha20_encrypt`)

**Файл:** `src/core/src/desync/obfs.rs` (587 строк)

**Верификация:**
```bash
# Проверить что f64 деление/log2/ln больше нет в hot path:
grep -n "as f64" src/core/src/desync/obfs.rs | grep -v "const\|test\|doc"
# Ожидаемый: 0 результатов в hot path функциях
grep -n "\.log2()\|\.ln()" src/core/src/desync/obfs.rs
# Ожидаемый: только в const fn инициализации LUT, не в runtime
```

**Критерий выполнения:**
- `shannon_entropy_fast()` возвращает `u16` (Q8 fixed-point)
- `poisson_delay_fast()` не использует f64 ни в одной ветке
- LUT инициализируются через `const fn` или `lazy_static`
- `entropy_padding()` вызывает `shannon_entropy_fast()` вместо `shannon_entropy()`
- **[MR-33]** `generate_entropy_padding()` использует ChaCha20 вместо LCG/одного байта
- `cargo bench` (если есть) показывает ускорение ≥10x

---

## Задача 3: `desync/rand.rs` — PRNG: seed predictability + Xorshift128** wrong formula + modulo bias

**MR:** MR-23 (seed), MR-24 (Xorshift128**), MR-27 (random_delay_us), MR-28 (gen_split_mask)
**Severity:** CRITICAL + CRITICAL + MEDIUM + LOW
**Приоритет:** P1

**Что менять:**
1. `init_seed()` → использовать `getrandom` (OS CSPRNG) вместо `SystemTime::now()`
2. `PerConnRng::next_u64()` → исправить формулу: `s1.wrapping_mul(0x517CC1B727220A95)` вместо `self.state[0].wrapping_mul(self.state[1])`
3. `PerConnRng::new()` → принимать `flow_counter` для per-connection уникальности
4. `random_delay_us()` → заменить `% 10000` на `random_range(0, 9999) as u64`
5. `gen_split_mask()` → заменить loop на `random_u64()`
6. **[NEW — reseed] `PerConnRng` → periodic reseed каждые N вызовов:**
   - Добавить поле `counter: u64` в `PerConnRng`
   - В `next_u64()`: при `counter % RESEED_INTERVAL == 0` вызывать `reseed()`
   - `reseed()`: `getrandom::getrandom(&mut fresh[16])` → XOR с текущим state
   - `RESEED_INTERVAL = 8192` (константа, ~10ms при 844K pps)
   - Добавить `reseed_interval: u64` в `DesyncConfig` (desync/mod.rs:253)
   - Default: `reseed_interval: 8192` (0 = отключено для benchmarking)

**Файл:** `src/core/src/desync/rand.rs` (334 строки)

**Верификация:**
```bash
# Проверить что SystemTime::now() не используется в seed:
grep -n "SystemTime::now" src/core/src/desync/rand.rs
# Ожидаемый: 0 результатов

# Проверить Xorshift128** формулу:
grep -n "wrapping_mul" src/core/src/desync/rand.rs
# Ожидаемый: wrapping_mul(0x517CC1B727220A95) для output, НЕ wrapping_mul(self.state[1])

# Проверить что modulo bias нет:
grep -n "% " src/core/src/desync/rand.rs
# Ожидаемый: только в random_range (который использует Lemire)

# Проверить что reseed реализован:
grep -n "reseed\|RESEED_INTERVAL\|counter.*%" src/core/src/desync/rand.rs
# Ожидаемый: const RESEED_INTERVAL, fn reseed(), counter check в next_u64()

# Проверить что reseed_interval есть в DesyncConfig:
grep -n "reseed_interval" src/core/src/desync/mod.rs
# Ожидаемый: pub reseed_interval: u64 в struct и default: 8192
```

**Критерий выполнения:**
- `init_seed()` вызывает `getrandom::getrandom()`, не `SystemTime`
- `PerConnRng::next_u64()` = `s1.wrapping_mul(0x517CC1B727220A95)` перед update state
- `random_delay_us()` не содержит `%`
- `gen_split_mask()` — одно вызова `random_u64()`
- `PerConnRng` содержит `counter: u64` и вызывает `reseed()` каждые `RESEED_INTERVAL` вызовов
- `reseed()` делает `getrandom::getrandom()` → XOR с текущим state
- `DesyncConfig` содержит `reseed_interval: u64` с default `8192`
- При `reseed_interval = 0` reseed отключён (для benchmarking)
- `cargo test` для PRNG (если есть) проходит
- `cargo clippy` без warnings

---

## Задача 4: `desync/mod.rs` — DesyncResult::merge destructive overwrite

**MR:** MR-12
**Severity:** CRITICAL
**Приоритет:** P1

**Что менять:**
- Добавить `PacketPatch` семантику: техники возвращают patches (offset→bytes), а не полный modified packet
- `merge()` накапливает patches вместо перезаписи `modified`
- `finalize()` применяет patches к оригиналу перед отправкой
- Альтернатива (проще): включить `pipeline_mode = true` по умолчанию ( group.rs:114 )

**Файл:** `src/core/src/desync/mod.rs` (397 строк)

**Верификация:**
```bash
# Проверить что pipeline_mode = true по умолчанию:
grep -n "pipeline_mode" src/core/src/desync/group.rs
# Ожидаемый: pipeline_mode: true (а не false)

# ИЛИ: проверить что merge() содержит conflict detection:
grep -n "merge" src/core/src/desync/mod.rs
# Ожидаемый: merge() с warning/log при конфликте modified
```

**Критерий выполнения:**
- `DesyncGroup::new()` устанавливает `pipeline_mode = true`
- ИЛИ: `DesyncResult::merge()` содержит conflict detection + warning log
- При комбинации FakeSni + WinSize в concurrent mode: сервер не получает broken TCP
- `cargo test` проходит (если есть тесты на DesyncGroup)

---

## Задача 5: `desync/tcp.rs` — build_tcp_segment triple copy + TCP checksum bug + buf.to_vec()

**MR:** MR-09 (triple copy), MR-11 (checksum before payload), MR-10 (buf.to_vec double alloc)
**Severity:** HIGH + CRITICAL + MEDIUM
**Приоритет:** P0 (MR-11) + P2 (остальные)

**Что менять:**
1. **MR-11 (P0):** `build_full_tcp_packet()` и `build_tcp_segment()` — вычислять TCP checksum ПОСЛЕ добавления payload, а не до
2. **MR-09 (P2):** Объединить `build_tcp_segment()` + `build_ip_packet()` в одну функцию `build_ip_tcp_packet()` — одна аллокация вместо трёх
3. **MR-10 (P2):** Во всех функциях с `buf.to_vec()` → `DesyncResult::modified_only(buf)` (move вместо clone)
   - `winsize()` (line ~394)
   - `mss_clamp()` (line ~882)
   - `win_scale_manip()` (line ~1145)
   - `port_shuffle()` (line ~1589)
   - `ts_md5()` (line ~1727)
   - `bad_checksum()` (ip.rs:130)
   - `ttl_manipulation()` (ip.rs:163)
   - `ttl_jitter()` (ip.rs:416)
   - `dscp_random()` (ip.rs:445)
   - `mutual_spoof()` (ip.rs:487)

**Файл:** `src/core/src/desync/tcp.rs` (2103 строки)

**Верификация:**
```bash
# MR-11: Проверить что checksum вычисляется ПОСЛЕ payload:
grep -n "tcp_checksum_v4" src/core/src/desync/tcp.rs
# Для каждой строки: checksum ДОЛЖЕН быть после extend_from_slice(payload)

# MR-09: Проверить что нет тройного копирования:
grep -n "tcp_buf.to_vec()" src/core/src/desync/tcp.rs
# Ожидаемый: 0 результатов (вместо этого — build_ip_tcp_packet)

# MR-10: Проверить что нет buf.to_vec() в modified_only:
grep -n "\.to_vec()" src/core/src/desync/tcp.rs | grep "modified_only"
# Ожидаемый: 0 результатов
```

**Критерий выполнения:**
- `build_tcp_segment()` вычисляет checksum ПОСЛЕ `full_payload.extend_from_slice(payload)`
- Функция `build_ip_tcp_packet()` существует и используется вместо `build_tcp_segment()` + `build_ip_packet()`
- Ни в одной функции нет `.to_vec()` в `DesyncResult::modified_only()`
- Фейковые TCP сегменты (TTL-1) имеют невалидный checksum — это ОК (сервер их не получает)
- Modified-пакеты (нормальный TTL) имеют валидный checksum
- `cargo test` + `cargo clippy` проходят

---

## Задача 6: `desync/tcp.rs` — fakedsplit SEQ + tcpseg fake TTL

**MR:** MR-13 (fakedsplit SEQ), MR-19 (tcpseg fake TTL)
**Severity:** CRITICAL + CRITICAL
**Приоритет:** P0

**Что менять:**
1. **MR-13:** `fakedsplit()` — убрать `new_seq = tcp.sequence.wrapping_add(fake_payload.len())`. Fake и real должны иметь ОДИНАКОВЫЙ SEQ. Modified = None (оригинал проходит как Forward)
2. **MR-19:** `tcpseg()` — убрать `is_multiple_of(2)` проверку для fake_ttl. Все real-сегменты должны иметь нормальный TTL. Fake TTL применяется ТОЛЬКО к отдельным fake-сегментам

**Файл:** `src/core/src/desync/tcp.rs` (2103 строки)

**Верификация:**
```bash
# MR-13: Проверить что fakedsplit не сдвигает SEQ:
grep -n "wrapping_add.*fake_payload" src/core/src/desync/tcp.rs
# Ожидаемый: 0 результатов в fakedsplit()

# MR-19: Проверить что tcpseg не использует is_multiple_of:
grep -n "is_multiple_of" src/core/src/desync/tcp.rs
# Ожидаемый: 0 результатов
```

**Критерий выполнения:**
- `fakedsplit()` возвращает `DesyncResult::inject_only(fake_seg)` (без modified)
- `fake_seg` имеет `tcp.sequence` (тот же что оригинал)
- `tcpseg()` все сегменты имеют `ip.ttl` (нормальный), fake TTL только для отдельных fake
- Сервер корректно собирает TCP stream без DUP-ACK
- `cargo test` проходит

---

## Задача 7: `desync/ip.rs` — frag_overlap + ip_frag_primitives + bad_checksum

**MR:** MR-14 (different IP IDs), MR-15 (hardcoded offset=20), MR-29 (fixed delta 0x1234/0x5678)
**Severity:** CRITICAL + HIGH + MEDIUM
**Приоритет:** P0 (MR-14) + P1 (MR-15) + P3 (MR-29)

**Что менять:**
1. **MR-14:** `ip_frag_primitives()` — одинаковый `frag_id` для всех фрагментов (сейчас `wrapping_add(frag_index as u16 + 1)`)
2. **MR-15:** `frag_overlap()` — dynamic `overlap_offset` вместо hardcoded 20; 8-byte alignment
3. **MR-29:** `bad_checksum()` — `random_range(1, 65535)` вместо `0x1234`/`0x5678`

**Файл:** `src/core/src/desync/ip.rs` (488 строк)

**Верификация:**
```bash
# MR-14: Проверить что frag_id одинаковый:
grep -n "wrapping_add.*frag_index" src/core/src/desync/ip.rs
# Ожидаемый: 0 результатов (вместо этого — один frag_id для всех)

# MR-15: Проверить что overlap_offset не hardcoded:
grep -n "overlap_offset = 20" src/core/src/desync/ip.rs
# Ожидаемый: 0 результатов

# MR-29: Проверить что delta рандомный:
grep -n "0x1234\|0x5678" src/core/src/desync/ip.rs
# Ожидаемый: 0 результатов
```

**Критерий выполнения:**
- `ip_frag_primitives()` использует один `frag_id` для всех фрагментов
- `frag_overlap()` вычисляет `overlap_offset` динамически из TCP header length
- `bad_checksum()` использует `random_range()` для delta
- Фрагменты собираются сервером (RFC 791 compliance)
- `cargo test` + `cargo clippy` проходят

---

## Задача 8: `conntrack.rs` — gc_fast deadlock + double-lookup upsert + update_seq_monotonic

**MR:** MR-03 (gc_fast), MR-04 (double-lookup), MR-16 (update_seq delta)
**Severity:** CRITICAL + HIGH + HIGH
**Приоритет:** P1 (MR-03) + P2 (MR-04, MR-16)

**Что менять:**
1. **MR-03:** `gc_fast()` — two-phase: collect stale keys, then remove (без remove во время iter)
2. **MR-04:** `upsert()` — `dashmap::mapref::entry::Entry` API вместо get+insert
3. **MR-16:** `update_seq_monotonic()` — `delta < (1u32 << 30)` вместо `delta < 65535`; сброс `dup_ack_count` при нормальном пакете; обновление `last_activity`

**Файл:** `src/core/src/conntrack.rs` (320 строк)

**Верификация:**
```bash
# MR-03: Проверить что gc_fast не делает remove во время iter:
grep -n "remove.*r\.key\(\)" src/core/src/conntrack.rs
# Ожидаемый: 0 результатов (вместо этого — collect + iterate)

# MR-04: Проверить что upsert использует entry API:
grep -n "get(&key).*is_some" src/core/src/conntrack.rs
# Ожидаемый: 0 результатов

# MR-16: Проверить что delta limit расширен:
grep -n "delta < 65535" src/core/src/conntrack.rs
# Ожидаемый: 0 результатов (вместо этого — delta < (1u32 << 30))
```

**Критерий выполнения:**
- `gc_fast()` собирает ключи в Vec, затем удаляет — нет remove во время iter
- `upsert()` использует `Entry::Vacant`/`Entry::Occupied`
- `update_seq_monotonic()` обновляет `client_seq` при `delta < 2^30`
- `dup_ack_count` сбрасывается при `delta > 0`
- `last_activity` обновляется при каждом вызове
- `cargo test` (gc тесты) проходят

---

## Задача 9: `engine/mod.rs` — channel deadlock + injected_seqs + apply_desync_async + conntrack overwrite + is_outbound

**MR:** MR-01 (channel), MR-02 (injected_seqs), MR-08 (double copy), MR-17 (conntrack overwrite), MR-20 (is_outbound)
**Severity:** CRITICAL + CRITICAL + HIGH + HIGH + HIGH
**Приоритет:** P1 (MR-01, MR-17) + P2 (MR-02, MR-08) + P3 (MR-20)

**Что менять:**
1. **MR-01:** `run()` — заменить `tokio::sync::mpsc::channel(1024)` + `blocking_send` на `crossbeam_queue::ArrayQueue` с head-drop
2. **MR-02:** `injected_seqs: DashSet<u32>` → `InjectedSeqTracker` с TTL (bounded HashMap)
3. **MR-08:** `apply_desync_async()` — принимать `bytes::Bytes` вместо `&[u8]`, убрать `Bytes::copy_from_slice`
4. **MR-17:** `process_outbound_tls()` — раздельный create/update для conntrack entry (не перезаписывать client_seq/server_seq)
5. **MR-20:** `is_outbound()` — добавить CGN (100.64.0.0/10) и/или использовать `WinDivertAddress.outbound()`

**Файл:** `src/core/src/engine/mod.rs` (668 строк)

**Верификация:**
```bash
# MR-01: Проверить что mpsc::channel удалён:
grep -n "mpsc::channel" src/core/src/engine/mod.rs
# Ожидаемый: 0 результатов

# MR-02: Проверить что DashSet заменён:
grep -n "DashSet<u32>" src/core/src/engine/mod.rs
# Ожидаемый: 0 результатов

# MR-08: Проверить что copy_from_slice удалён из apply_desync_async:
grep -n "copy_from_slice" src/core/src/engine/mod.rs | grep "apply_desync"
# Ожидаемый: 0 результатов

# MR-17: Проверить что conntrack entry не создаётся с нулями:
grep -n "client_seq: 0" src/core/src/engine/mod.rs
# Ожидаемый: только в Vacant branch (новое соединение), не в Occupied

# MR-20: Проверить что is_outbound покрывает CGN:
grep -n "100.*64" src/core/src/engine/mod.rs
# Ожидаемый: match branch для 100.64.0.0/10
```

**Критерий выполнения:**
- `run()` использует `ArrayQueue` с head-drop, не `mpsc::channel`
- `injected_seqs` — bounded structure с TTL (максимум ~64K записей)
- `apply_desync_async()` принимает `bytes::Bytes`, не `&[u8]`
- `process_outbound_tls()` — conntrack entry создаётся только для нового соединения
- `is_outbound()` покрывает loopback, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10
- `cargo test` + `cargo clippy` проходят

---

## Задача 10: `packet_engine.rs` — recv_blocking to_vec()

**MR:** MR-07
**Severity:** CRITICAL
**Приоритет:** P2

**Что менять:**
- `recv_blocking()` — возвращать `bytes::Bytes` вместо `Vec<u8>`
- Одна `Bytes::copy_from_slice()` вместо `Vec::new()` + copy

**Файл:** `src/core/src/packet_engine.rs` (453 строки)

**Верификация:**
```bash
grep -n "to_vec()" src/core/src/packet_engine.rs
# Ожидаемый: 0 результатов в recv_blocking()
```

**Критерий выполнения:**
- `recv_blocking()` возвращает `Result<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>`
- Вызывающий код (`engine/mod.rs`) обновлён для приёма `Bytes`
- `cargo test` + `cargo clippy` проходят

---

## Задача 11: `desync/group.rs` — PipelineState::from_packet + pipeline_mode default

**MR:** MR-08 (partial, from_packet), MR-12 (pipeline_mode), MR-34 (cache offsets)
**Severity:** HIGH + CRITICAL + LOW
**Приоритет:** P1

**Что менять:**
1. `PipelineState::from_packet()` — принимать `bytes::Bytes` вместо `&[u8]` (zero-copy)
2. `DesyncGroup::new()` — `pipeline_mode: true` по умолчанию
3. **[NEW — MR-34] Кэширование TCP offsets в `PipelineState`:**
   - Добавить `cached_payload_offset: Option<usize>` и `cached_tcp_seq: Option<u32>`
   - `tcp_payload_offset()` — lazy compute через `get_or_insert_with`
   - `invalidate_header_cache()` — вызывать в техниках, меняющих header (multi_split, frag_overlap, tcpseg)

**Файл:** `src/core/src/desync/group.rs` (340 строк)

**Верификация:**
```bash
grep -n "copy_from_slice" src/core/src/desync/group.rs
# Ожидаемый: 0 результатов в from_packet()

grep -n "pipeline_mode: false" src/core/src/desync/group.rs
# Ожидаемый: 0 результатов (должно быть true)

# MR-34: Проверить кэширование:
grep -n "cached_payload_offset\|invalidate_header_cache" src/core/src/desync/group.rs
# Ожидаемый: поле в struct и методы
```

**Критерий выполнения:**
- `PipelineState::from_packet(packet: bytes::Bytes)` — ownership transfer, no copy
- `DesyncGroup::new()` устанавливает `pipeline_mode: true`
- `apply()` по умолчанию вызывает `apply_pipeline()`
- **[MR-34]** `PipelineState` содержит cached TCP offsets, пересчитываются только при invalidate
- `cargo test` проходит

---

## Задача 12: `adaptive/hop_tab.rs` — O(256) scan → O(1) hash lookup

**MR:** MR-06
**Severity:** HIGH
**Приоритет:** P3

**Что менять:**
- `get()` — direct-mapped hash table вместо linear scan по 256 записям
- `cache: [AtomicU64; 256]` → `cache: [AtomicU64; 4096]`
- `hash(ip)` через FNV-1a fold → index

**Файл:** `src/core/src/adaptive/hop_tab.rs` (351 строка)

**Верификация:**
```bash
grep -n "find_map\|iter()" src/core/src/adaptive/hop_tab.rs
# Ожидаемый: 0 результатов в get() (вместо этого — hash + direct index)
```

**Критерий выполнения:**
- `HopTab::get()` = O(1): hash + single AtomicU64 load
- `HopTab::insert()` = O(1): hash + single AtomicU64 store
- `estimate()` не изменена
- `cargo test` проходит

---

## Задача 13: `infra/event_tag.rs` + `packet_engine.rs` — per-thread UUID → global UUID + Impostor flag

**MR:** MR-18, MR-31
**Severity:** CRITICAL + HIGH
**Приоритет:** P0

**Что менять:**
- `INJECTION_TAG: thread_local!` → `GLOBAL_TAG: OnceLock<[u8; 16]>`
- `tag_injected_packet()` использовать глобальный UUID
- `is_injected_packet()` использовать глобальный UUID
- `injected_filter_clause()` использовать глобальный UUID
- **[NEW — MR-31] `packet_engine.rs`: установить `Impostor` flag при инъекции TCP:**
  - В `inject_via_divert()`: `impostor_addr.set_impostor(true)` перед отправкой
  - Если Impostor работает корректно, EventTag может стать не нужен (проверить experimentally)

**Файлы:** `src/core/src/infra/event_tag.rs` (213 строк) + `src/core/src/packet_engine.rs` (453 строки)

**Верификация:**
```bash
grep -n "thread_local" src/core/src/infra/event_tag.rs
# Ожидаемый: 0 результатов

grep -n "OnceLock" src/core/src/infra/event_tag.rs
# Ожидаемый: минимум 1 результат (GLOBAL_TAG)

# MR-31: Проверить что Impostor flag устанавливается:
grep -n "set_impostor\|Impostor" src/core/src/packet_engine.rs
# Ожидаемый: минимум 1 результат в inject_via_divert()
```

**Критерий выполнения:**
- `INJECTION_TAG` thread_local удалён
- `GLOBAL_TAG: OnceLock<[u8; 16]>` инициализируется через `uuid::Uuid::new_v4()`
- Все функции используют `tag()` → `&'static [u8; 16]`
- `injected_filter_clause()` возвращает строку с глобальным UUID
- Пакеты от разных потоков корректно фильтруются WinDivert
- **[MR-31]** `inject_via_divert()` устанавливает `Impostor` flag на `WinDivertAddress`
- `cargo test` (tag тесты) проходят

---

## Задача 14: `desync/quic.rs` — QUIC Initial < 1200 bytes + padding_flood randomization

**MR:** MR-21, MR-32
**Severity:** HIGH + MEDIUM
**Приоритет:** P2

**Что менять:**
1. `quic_initial_inject()` — паддинг до `QUIC_MIN_INITIAL_SIZE = 1200` байт (RFC 9000 §14.1)
2. Проверка MTU перед инъекцией
3. **[NEW — MR-32] `quic_padding_flood()` — рандомизация паттернов:**
   - `pad_size = ((i * 7 + 3) % 20) + 1` → `(rng.next_unbiased(20) + 1)`
   - `port = 12345 + i` → `rng.next_range(1024, 65535)`
   - `payload = (j * 0x13) as u8` → `rng.next_u64() as u8`
   - Использовать `PerConnRng` для детерминизма per-connection
- `quic_initial_inject()` — паддинг до `QUIC_MIN_INITIAL_SIZE = 1200` байт
- Проверка MTU перед инъекцией

**Файл:** `src/core/src/desync/quic.rs` (нужно прочитать)

**Верификация:**
```bash
grep -n "1200\|QUIC_MIN" src/core/src/desync/quic.rs
# Ожидаемый: константа QUIC_MIN_INITIAL_SIZE и resize до неё

# MR-32: Проверить рандомизацию:
grep -n "i \* 7\|12345 + i\|j \* 0x13" src/core/src/desync/quic.rs
# Ожидаемый: 0 результатов (вместо этого — rng.next_unbiased/next_range)
```

**Критерий выполнения:**
- Fake QUIC Initial packet ≥ 1200 байт (RFC 9000 §14.1)
- Если payload > MTU — truncate SNI или вернуть passthrough
- **[MR-32]** `quic_padding_flood()` использует `PerConnRng` для pad_size, port, payload
- `cargo test` проходит

---

## Задача 15: `desync/tcp.rs` — SynAckSplit integer overflow

**MR:** MR-22
**Severity:** MEDIUM
**Приоритет:** P3

**Что менять:**
- `tcp.sequence + 1` → `tcp.sequence.wrapping_add(1)`
- `tcp.acknowledgment + 1` → `tcp.acknowledgment.wrapping_add(1)`

**Файл:** `src/core/src/desync/tcp.rs` (2103 строки) — тот же файл что задача 5 и 6

**Верификация:**
```bash
grep -n "sequence + 1\b\|acknowledgment + 1\b" src/core/src/desync/tcp.rs
# Ожидаемый: 0 результатов (все должны быть wrapping_add)
```

**Критерий выполнения:**
- Все вычисления SEQ/ACK используют `wrapping_add()`
- Нет bare `+` для u32 SEQ/ACK
- `cargo clippy` без warnings

---

## Сводная таблица: файл → задачи

| Файл | Задачи | Общий MR | Приоритет |
|------|--------|----------|-----------|
| `desync/pool.rs` | 1 | MR-05 | P2 |
| `desync/obfs.rs` | 2 | MR-25, MR-26, MR-33 | P2 |
| `desync/rand.rs` | 3 | MR-23, MR-24, MR-27, MR-28 + reseed | P1 |
| `desync/mod.rs` | 3 (reseed_interval), 4 | MR-12, MR-23 (config) | P1 |
| `desync/tcp.rs` | 5, 6, 15 | MR-09, MR-10, MR-11, MR-13, MR-19, MR-22 | P0+P2 |
| `desync/ip.rs` | 7 | MR-14, MR-15, MR-29 | P0+P1+P3 |
| `conntrack.rs` | 8 | MR-03, MR-04, MR-16 | P1+P2 |
| `engine/mod.rs` | 9 | MR-01, MR-02, MR-08, MR-17, MR-20 | P1+P2+P3 |
| `packet_engine.rs` | 10, 13 (MR-31) | MR-07, MR-31 | P2 |
| `desync/group.rs` | 11 | MR-08, MR-12, MR-34 | P1 |
| `adaptive/hop_tab.rs` | 12 | MR-06 | P3 |
| `infra/event_tag.rs` | 13 | MR-18, MR-31 | P0 |
| `desync/quic.rs` | 14 | MR-21, MR-32 | P2 |

---

## Рекомендуемый порядок выполнения

| Шаг | Задачи (параллельно) | Зависимости | Время |
|-----|---------------------|-------------|-------|
| 1 | 13 (event_tag), 3 (rand.rs) | — | 2ч |
| 2 | 1 (pool.rs), 11 (group.rs) | — | 1ч |
| 3 | 5 (tcp.rs build/checksum), 6 (tcp.rs fakedsplit/tcpseg) | — | 3ч |
| 4 | 7 (ip.rs), 14 (quic.rs) | — | 2ч |
| 5 | 8 (conntrack.rs) | — | 1ч |
| 6 | 9 (engine/mod.rs), 10 (packet_engine.rs) | Шаг 1-5 | 3ч |
| 7 | 2 (obfs.rs), 4 (mod.rs merge), 12 (hop_tab.rs), 15 (tcp.rs overflow) | — | 2ч |

**Общее время:** ~14 часов
**Критические пути:** Шаг 3 (tcp.rs) → Шаг 6 (engine/mod.rs)

---

*End of Implementation Plan*
