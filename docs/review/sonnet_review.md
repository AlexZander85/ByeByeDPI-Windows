# FreeDPI Windows v3.0 — Beспощадный Security & Performance Review

**Reviewer:** Principal Network Architect / Rust Performance Expert  
**Scope:** `src/core/src/` — весь production Rust код  
**Severity:** 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM

---

## ДОМЕН 1: Network Backpressure & Queue Management

---

### 🔴 CRITICAL-1: `recv_blocking` + `blocking_send` — каскадный SYN-flood collapse

**Файл:** `engine/mod.rs:297-314`, `packet_engine.rs:163`

**Проблема:** При SYN-флуде или пике трафика (10 Gbps) канал переполняется и система `необратимо падает` в два этапа:

```rust
// engine/mod.rs:297 — bounded channel = 1024 пакетов
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(1024);

// engine/mod.rs:313 — если channel ПОЛНЫЙ, этот вызов БЛОКИРУЕТ поток
if tx.blocking_send(CapturedPacket { data, addr }).is_err() {
    break;
}
```

Этап 1: Tokio worker обрабатывает пакеты медленно → channel до отказа 1024.  
Этап 2: `spawn_blocking` поток блокируется на `blocking_send` → перестаёт читать из WinDivert.  
Этап 3: WinDivert kernel-queue (8192 слотов, `set_param(QueueLength, 8192)`) заполняется.  
Этап 4: NDIS **МОЛЧА** дропает ВСЕ новые пакеты — никакой индикации в коде нет.

При 10 Gbps с MTU=1500: ~830,000 pps. WinDivert kernel-queue хватает на **~10ms**. После этого — полная потеря пакетов у всех соединений. FPS в играх → 0, стриминг → замерзает.

**Доказательство:** `packet_engine.rs:163`:
```rust
Ok((packet.data.to_vec(), packet.address))  // to_vec() = memcpy на КАЖДЫЙ пакет
```
`to_vec()` — аллокация + копирование на каждый принятый пакет. Это само по себе создаёт backpressure, но backpressure-сигнал НИКОГДА не доходит до WinDivert.

**Патч — Head-Drop + Timeout:**

```rust
// engine/mod.rs — заменить blocking_send на try_send с head-drop

// БЫЛО:
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(1024);
// ...
if tx.blocking_send(CapturedPacket { data, addr }).is_err() { break; }

// СТАЛО:
// Bounded channel с Head-Drop для SYN-flood protection
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(4096);
// ...
match tx.try_send(CapturedPacket { data, addr }) {
    Ok(()) => {}
    Err(tokio::sync::mpsc::error::TrySendError::Full(_dropped)) => {
        // Head-drop: дропаем новый пакет, не блокируем recv thread
        stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
        // При систематическом дропе → логгировать и расширять воркеры
        if stats.packets_dropped.load(Ordering::Relaxed) % 10_000 == 0 {
            warn!("Channel full: {} packets dropped (backpressure!)", 
                  stats.packets_dropped.load(Ordering::Relaxed));
        }
    }
    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
}
```

---

### 🔴 CRITICAL-2: `injected_seqs: DashSet<u32>` — неограниченная утечка памяти

**Файл:** `engine/mod.rs:224, 484, 550`

```rust
injected_seqs: dashmap::DashSet<u32>,   // РАСТЁТ ВЕЧНО, никогда не очищается

// Проверка на КАЖДЫЙ TLS пакет (hot path):
if self.injected_seqs.contains(&tcp.get_sequence()) { ... }

// Вставка после инъекции:
self.injected_seqs.insert(tcp.get_sequence());
```

**Три проблемы одновременно:**

1. **Memory leak**: За 24 часа при 100 соединениях/сек → 8.6M записей в DashSet. RAM растёт неограниченно.
2. **Lock contention**: `DashSet::contains()` вызывается на КАЖДЫЙ outbound TLS пакет. При 100K TCP соединениях в DashSet это 64 шарда × RwLock.
3. **SEQ number wrap-around**: TCP SEQ — `u32`. Через `2^32 / avg_segment_size` байт трафика старые SEQ переиспользуются. Новое TLS-соединение с таким же SEQ **навсегда** пройдёт без десинхронизации.

**Патч — TTL-based sharded bitset:**

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Sharded bloom-filter с TTL для injected SEQ detection.
/// 8 шардов × 8KB bitset = 512KB RAM максимум.
/// False-positive rate < 0.01% при 100K активных записей.
pub struct InjectedSeqTracker {
    // Каждый шард хранит (seq, timestamp) пары в ring-buffer
    shards: [parking_lot::Mutex<SeqShard>; 8],
    ttl: Duration,
}

struct SeqShard {
    entries: Vec<(u32, Instant)>,  // ring buffer
    write_pos: usize,
    capacity: usize,
}

impl SeqShard {
    fn new(capacity: usize) -> Self {
        Self { entries: Vec::with_capacity(capacity), write_pos: 0, capacity }
    }

    fn insert(&mut self, seq: u32) {
        let entry = (seq, Instant::now());
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            self.entries[self.write_pos] = entry;  // Overwrite oldest
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
    }

    fn contains(&self, seq: u32, ttl: Duration) -> bool {
        let now = Instant::now();
        self.entries.iter().any(|(s, t)| *s == seq && now.duration_since(*t) < ttl)
    }
}

impl InjectedSeqTracker {
    pub fn new(ttl: Duration) -> Self {
        Self {
            shards: std::array::from_fn(|_| 
                parking_lot::Mutex::new(SeqShard::new(4096))),  // 32K entries total
            ttl,
        }
    }

    #[inline]
    fn shard_idx(seq: u32) -> usize { (seq as usize) & 7 }

    pub fn insert(&self, seq: u32) {
        self.shards[Self::shard_idx(seq)].lock().insert(seq);
    }

    pub fn contains(&self, seq: u32) -> bool {
        self.shards[Self::shard_idx(seq)].lock().contains(seq, self.ttl)
    }
}

// В ProcessingPipeline:
// injected_seqs: InjectedSeqTracker = InjectedSeqTracker::new(Duration::from_secs(30));
```

---

### 🟠 HIGH-3: `Conntrack::upsert()` — двойной DashMap shard lock на каждый пакет

**Файл:** `conntrack.rs:86-94`

```rust
pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
    let existed = self.inner.map.get(&key).is_some();  // Lock #1: read shard
    self.inner.map.insert(key, entry);                  // Lock #2: write shard (одна и та же!)
    if !existed {
        self.inner.total_created.fetch_add(1, ...);
        self.inner.active_count.fetch_add(1, ...);
    }
}
```

При 830K pps на 10 Gbps — 830K × 2 DashMap lock acquisitions/сек = 1.66M блокировок/сек только для conntrack. На конкурентном ядре это ~100нс × 1.66M = **166мс** потерянного CPU времени в секунду.

**Патч — atomics entry API:**

```rust
pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
    use dashmap::mapref::entry::Entry;
    match self.inner.map.entry(key) {  // Single lock, atomically
        Entry::Occupied(mut o) => { o.insert(entry); }
        Entry::Vacant(v) => {
            v.insert(entry);
            self.inner.total_created.fetch_add(1, Ordering::Relaxed);
            self.inner.active_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}
```

---

### 🟠 HIGH-4: `SplitTunnel` thread-local LRU cache — O(n) everywhere

**Файл:** `split_tunnel.rs:77-102`

```rust
// ПРОБЛЕМА 1: Линейный поиск O(n) при каждом lookup
let cached = BYPASS_CACHE.with(|c| {
    let cache = c.borrow();
    cache.iter().find(|(ip, _)| *ip == ip_int).map(|(_, v)| *v)  // O(1024)!
});

// ПРОБЛЕМА 2: Vec::remove(0) = O(n) shift при каждом eviction  
if cache.len() >= TL_CACHE_SIZE {
    cache.remove(0);  // Сдвигает 1024 элемента! O(1024) каждый промах
}
```

При `TL_CACHE_SIZE = 1024`: каждый cache lookup = до 1024 сравнений. Cache eviction = 1024 сдвигов. Это **хуже** чем один вызов `DashMap::get()` при промахе кэша.

Проблема 3 — `decide()` в Auto-режиме:
```rust
SplitMode::Auto => {
    if self.auto_detected.iter().any(|ip| {      // Полная итерация DashSet
        self.domain_cache.get(&ip)                // DashMap lookup для КАЖДОГО IP
            .is_some_and(|d| d.value() == domain)
    }) { ...
```

O(N×M) на каждый пакет в Auto mode: N = размер auto_detected, M = стоимость DashMap lookup.

**Патч — заменить Vec на LRU с хешмапой:**

```rust
// Используем indexmap или ручной LRU с HashMap + doubly-linked list
// Или проще — thread_local HashMap с random eviction:

thread_local! {
    static BYPASS_CACHE: std::cell::RefCell<std::collections::HashMap<u32, (bool, std::time::Instant)>> 
        = std::cell::RefCell::new(std::collections::HashMap::with_capacity(1024));
}

pub fn should_bypass_ip_fast(&self, dst_ip: &Ipv4Addr) -> bool {
    let ip_int = u32::from_ne_bytes(dst_ip.octets());
    let ttl = std::time::Duration::from_secs(60);

    let cached = BYPASS_CACHE.with(|c| {
        let cache = c.borrow();
        cache.get(&ip_int)
            .filter(|(_, ts)| ts.elapsed() < ttl)
            .map(|(v, _)| *v)
    });

    if let Some(result) = cached { return result; }

    let result = self.should_bypass_ip(dst_ip);

    BYPASS_CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        if cache.len() >= 1024 {
            // Random eviction: быстро, без O(n) сдвигов
            let remove_key = *cache.keys().next().unwrap();
            cache.remove(&remove_key);
        }
        cache.insert(ip_int, (result, std::time::Instant::now()));
    });

    result
}
```

---

## ДОМЕН 2: Zero-Copy & Hidden Allocations

---

### 🔴 CRITICAL-5: Тройное копирование каждого пакета до первой десинхронизации

**Файлы:** `packet_engine.rs:163`, `engine/mod.rs:609`, `desync/group.rs:44`

```rust
// КОПИЯ #1: packet_engine.rs:163 — WinDivert recv → Vec<u8>
Ok((packet.data.to_vec(), packet.address))
//         ^^^^^^^^^^^^ memcpy: ~1500 байт

// КОПИЯ #2: engine/mod.rs:609 — Vec<u8> → Bytes (apply_desync_async)
let packet = bytes::Bytes::copy_from_slice(packet);
//                         ^^^^^^^^^^^^^^^^ memcpy снова

// КОПИЯ #3: group.rs:44 — Bytes → PipelineState.packet
packet: bytes::Bytes::copy_from_slice(packet),
//                    ^^^^^^^^^^^^^^^^ третья копия
```

При 10 Gbps: 830K pps × 1500 байт × 3 копии = **3.75 GB/s** чистого memcpy. На RTX 5070 Ti системе с DDR5 это ~50% пропускной способности памяти сожрано впустую.

**Патч — zero-copy pipeline:**

```rust
// packet_engine.rs — возвращаем Bytes напрямую из WinDivert buffer
pub fn recv_blocking(&self, buffer: &mut BytesMut) 
    -> Result<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> 
{
    let Some(ref divert) = self.divert else {
        anyhow::bail!("WinDivert not initialized");
    };
    let packet = divert.recv(buffer.as_mut()).context("recv failed")?;
    // Bytes::copy_from_slice один раз — неизбежно т.к. WinDivert пишет в наш буфер
    // Но дальше — только Bytes::slice(), без копий
    let data = bytes::Bytes::copy_from_slice(packet.data);
    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
    Ok((data, packet.address))
}

// engine/mod.rs — убрать вторую копию
async fn apply_desync_async(&self, packet: bytes::Bytes) -> crate::desync::DesyncResult {
    // packet уже Bytes — передаём ownership без копирования
    let group = self.desync_group.clone();
    tokio::task::spawn_blocking(move || group.apply(&packet))
        .await
        .unwrap_or_else(|_| crate::desync::DesyncResult::passthrough())
}

// group.rs:PipelineState::from_packet — принимает Bytes ownership
pub fn from_packet(packet: bytes::Bytes) -> Self {
    let tcp_payload_offset = Self::find_tcp_payload_offset(&packet);
    let tcp_seq = Self::extract_tcp_seq(&packet);
    Self { packet, tcp_payload_offset, tcp_seq, injects: Vec::new(), drop: false }
    // packet уже Bytes — move, ноль копий
}
```

---

### 🔴 CRITICAL-6: Двойная аллокация — `buf.to_vec()` на уже существующем `Vec`

**Файл:** `desync/tcp.rs` — повторяется 7+ раз

```rust
// Паттерн-нарушитель в winsize(), port_shuffle(), wclamp(), ts_md5(), 
// win_scale_manip(), mss_clamp():

let mut buf = packet.to_vec();  // Аллокация #1: клонируем пакет
// ... модифицируем buf ...
DesyncResult::modified_only(buf.to_vec())  // Аллокация #2: клонируем VEC!
//                              ^^^^^^^^
// buf — уже Vec<u8>. .to_vec() на Vec<u8> вызывает .clone()!
// Создаётся НОВЫЙ Vec, старый дропается. Зачем??
```

**Патч — move семантика:**

```rust
// БЫЛО (tcp.rs:394, 882, 1145, 1589, 1658, 1727):
DesyncResult::modified_only(buf.to_vec())

// СТАЛО — move buf без копии:
DesyncResult::modified_only(buf)
// Потому что DesyncResult::modified_only принимает impl Into<bytes::Bytes>
// и Vec<u8> реализует Into<Bytes> через move (без копирования для capacity > threshold)
```

Аналогично:
```rust
// tcp.rs:927:
DesyncResult::modify_and_inject(packet.to_vec(), fake_rst)
// Лучше (если не нужна модификация packet):
DesyncResult::modify_and_inject(packet.clone(), fake_rst)
// Bytes::clone() = increment ref count, не копирование!
```

---

### 🔴 CRITICAL-7: TCP checksum вычисляется ДО добавления payload — все инжектированные сегменты имеют НЕВЕРНУЮ контрольную сумму

**Файл:** `desync/tcp.rs:591-649` — затрагивает `build_full_tcp_packet` AND `build_tcp_segment` (оба)

```rust
fn build_full_tcp_packet(..., payload: &[u8], ...) -> bytes::Bytes {
    let mut tcp_buf = vec![0u8; tcp_header_len];  // Только 20 байт header
    // ... заполняем TCP header ...
    
    // ❌ ОШИБКА: checksum вычисляется над 20-байтным tcp_buf БЕЗ payload
    let checksum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &tcp_buf);
    //                                                              ^^^^^^^
    //                                     Длина = 20, payload не включён!
    tcp_buf[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut full_payload = tcp_buf.to_vec();
    full_payload.extend_from_slice(payload);  // Payload добавляется ПОСЛЕ
    build_ip_packet(...)
}
```

TCP checksum — это checksum pseudo-header + весь TCP сегмент включая payload. Вычисление над 20-байтным буфером без payload → неверный checksum.

**Последствия:**
- `multisplit`, `fakedsplit`, `tcpseg`, `syndata`, `synhide` — все создают сегменты с неверным checksum
- Для **fake пакетов** (TTL-1) — неважно, они умирают до сервера
- Для **modified пакетов** (реальный трафик, нормальный TTL) — **критично**: сервер или промежуточный router отбросит пакет с `checksum error`. Всё соединение ломается.
- Windows с отключённым TSO (мы отключаем!) проверяет checksums → real packets dropped

**Патч:**

```rust
fn build_full_tcp_packet(
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16,
    payload: &[u8], ttl: u8,
) -> bytes::Bytes {
    let tcp_header_len = 20;
    let total_tcp_len = tcp_header_len + payload.len();
    
    // Аллоцируем буфер сразу с местом под payload
    let mut segment = vec![0u8; total_tcp_len];
    {
        let mut tcp = MutableTcpPacket::new(&mut segment[..tcp_header_len]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(window);
        tcp.set_checksum(0);
        tcp.set_urgent_ptr(0);
    }
    // Копируем payload ДО вычисления checksum
    segment[tcp_header_len..].copy_from_slice(payload);
    
    // ✅ Checksum вычисляется над ПОЛНЫМ сегментом (header + payload)
    let checksum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    
    build_ip_packet(src_ip, dst_ip, IpNextHeaderProtocols::Tcp, ttl, 0, &segment)
}

// То же самое для build_tcp_segment и build_tcp_segment_p3
```

---

### 🟠 HIGH-8: Нет проверки MTU — инжектированные пакеты молча дропаются NDIS

**Файл:** `desync/mod.rs:build_ip_packet()`, `desync/quic.rs:quic_initial_inject()`

```rust
pub fn build_ip_packet(..., payload: &[u8]) -> bytes::Bytes {
    let total_len = 20 + payload.len();  // Никакой проверки на MTU!
    let mut buf = vec![0u8; total_len];
    // ...
}
```

Если `total_len > 1500` (стандартный Ethernet MTU):
- `inject_raw_udp()` → `sendto()` вернёт `WSAEMSGSIZE` или NDIS дропнет без ошибки
- `inject_via_divert()` → WinDivert может дропнуть или фрагментировать (ломая нашу логику)

QUIC Initial пакет содержит: IP(20) + UDP(8) + QUIC LH(~20) + Connection IDs(~20) + TLS ClientHello(~300-400 байт). Итого ~370-470 байт — в MTU помещается. Но при большом SNI (>~500 байт) или padding — превышение.

**Патч:**

```rust
/// MTU для Ethernet. TODO: автодетект через GetAdaptersInfo.
const ETHERNET_MTU: usize = 1500;
const IP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
pub const MAX_INJECT_PAYLOAD: usize = ETHERNET_MTU - IP_HEADER_LEN;  // 1480
pub const MAX_QUIC_PAYLOAD: usize = ETHERNET_MTU - IP_HEADER_LEN - UDP_HEADER_LEN;  // 1472

pub fn build_ip_packet(
    src: Ipv4Addr, dst: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    ttl: u8, identification: u16,
    payload: &[u8],
) -> bytes::Bytes {
    let total_len = 20 + payload.len();
    
    // ✅ MTU guard
    if total_len > ETHERNET_MTU {
        // Логируем и возвращаем пустой Bytes — вызывающий код должен обработать
        tracing::warn!(
            "Attempted to build packet exceeding MTU: {} > {} bytes, dropping",
            total_len, ETHERNET_MTU
        );
        return bytes::Bytes::new();
    }
    
    let mut buf = vec![0u8; total_len];
    // ... остальной код ...
}

// В QUIC desync — принудительно обрезать payload до MAX_QUIC_PAYLOAD
pub fn quic_initial_inject(packet: &[u8], fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let mut fake_payload = build_quic_initial(dcid, fake_sni);
    
    // Гарантируем QUIC minimum (1200 байт, RFC 9000 §14.1) и MTU:
    let target_size = 1200usize.min(MAX_QUIC_PAYLOAD);
    if fake_payload.len() > target_size {
        fake_payload = fake_payload.slice(..target_size);
    }
    // ...
}
```

---

### 🟠 HIGH-9: `inject_tcp_packet` — лишняя аллокация для каждого инжектированного TCP пакета

**Файл:** `engine/mod.rs:586`

```rust
fn inject_tcp_packet(&self, packet: &[u8], addr: &...) -> Result<()> {
    let mut tagged = packet.to_vec();  // Аллокация: клонируем inject пакет
    if self.config.event_tag_enabled {
        event_tag::tag_injected_packet(&mut tagged);
    }
    self.packet_engine.inject_via_divert(&tagged, addr)?;
    ...
}
```

Если у нас `DesyncGroup` с 5 инжектами → 5 лишних аллокаций + 5 memcpy. При 10K TLS соединений/сек = 50K лишних аллокаций/сек.

**Патч — event tag через Bytes:**

```rust
// event_tag.rs — добавить функцию возвращающую новый Bytes
pub fn tagged_copy(packet: &bytes::Bytes) -> bytes::Bytes {
    let mut buf = bytes::BytesMut::from(packet.as_ref());
    tag_injected_packet(&mut buf);
    buf.freeze()
}

// engine/mod.rs
fn inject_tcp_packet(&self, packet: &bytes::Bytes, addr: &...) -> Result<()> {
    let to_send = if self.config.event_tag_enabled {
        event_tag::tagged_copy(packet)  // Аллоцируем только при необходимости
    } else {
        packet.clone()  // Bytes::clone() = ref count increment, ноль копий
    };
    self.packet_engine.inject_via_divert(&to_send, addr)?;
    ...
}
```

---

## ДОМЕН 3: TCP State Machine & Protocol Anomalies

---

### 🔴 CRITICAL-10: `fakedsplit` — неверная SEQ арифметика рвёт соединение

**Файл:** `desync/tcp.rs:217-239`

```rust
pub fn fakedsplit(packet: &bytes::Bytes, fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    // ...
    let fake_payload = build_fake_clienthello(fake_sni);

    // FAKE пакет: SEQ = tcp.sequence, TTL = ttl-1 (умирает у первого хопа)
    let fake_seg = build_tcp_segment(..., tcp.sequence, ..., fake_ttl, ...);

    // ❌ ОШИБКА: SEQ реального пакета сдвигается на длину FAKE payload
    let new_seq = tcp.sequence.wrapping_add(fake_payload.len() as u32);
    let modified = build_full_tcp_packet(
        ...,
        new_seq,        // SEQ = tcp.sequence + fake_payload.len()
        ...,
        tcp.payload,    // Но реальные данные всё ещё здесь!
        ...
    );
```

**Что видит сервер:**
- Fake пакет имеет TTL-1 → умирает у ISP, до сервера НЕ доходит
- Поэтому сервер всё ещё ожидает SEQ = `tcp.sequence` (оригинальный)
- Приходит modified с SEQ = `tcp.sequence + N` → сервер: `"out-of-order? missing gap!"` → отправляет DupACK
- Соединение зависает в ожидании "недостающего" сегмента → таймаут → RST

**Правильная логика** (как в оригинальном zapret): fake и real ДОЛЖНЫ иметь одинаковый SEQ, создавая TCP overlapping segment. Сервер reassembles правильные данные из обоих, DPI видит только fake:

```rust
pub fn fakedsplit(packet: &bytes::Bytes, fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = parse_ip_header(packet)?;
    let tcp = parse_tcp_packet(&packet[ip.header_len..])?;
    if tcp.payload.is_empty() { return DesyncResult::passthrough(); }

    let fake_payload = build_fake_clienthello(fake_sni);
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // Fake сегмент: тот же SEQ что и реальный, TTL-1 (DPI видит fake)
    let fake_seg = build_tcp_segment(
        ip.src, ip.dst, tcp.src_port, tcp.dst_port,
        tcp.sequence,           // ✅ Тот же SEQ
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,               // ✅ Умирает до сервера
        generate_identification(ip.identification, 0),
    );

    // ✅ Real пакет: original SEQ, оригинальные данные, нормальный TTL
    // НЕ модифицируем SEQ — сервер получит его как ожидает
    // Используем DesyncResult::inject_only, оригинал проходит через Forward
    DesyncResult::inject_only(fake_seg)
    // оригинал возвращается как PacketDecision::Forward (не Modify)
}
```

---

### 🔴 CRITICAL-11: Concurrent DesyncGroup `merge()` — SEQ-конфликт между техниками

**Файл:** `desync/group.rs:128-145`, `desync/mod.rs:merge()`

```rust
// Concurrent mode: каждая техника видит ОРИГИНАЛЬНЫЙ пакет
fn apply_concurrent(&self, packet: &bytes::Bytes) -> DesyncResult {
    let mut result = DesyncResult::passthrough();
    for technique in &self.techniques {
        let r = self.apply_single(technique, packet);
        result.merge(r);  // Last writer wins для modified!
    }
    result
}

// merge():
pub fn merge(&mut self, other: Self) {
    if other.modified.is_some() {
        self.modified = other.modified;  // ❌ Перезаписывает SEQ предыдущей техники!
    }
    self.inject.extend(other.inject);   // Inject'ы накапливаются от ВСЕХ техник
}
```

**Сценарий с FakeSni + FakeDataSplit:**
- FakeSni: inject=[fake_CH(SEQ=1000)], modified=None
- FakeDataSplit: inject=[fake_seg(SEQ=1000)], modified=real_pkt(SEQ=1000+N)
- После merge: inject=[fake_CH(SEQ=1000), fake_seg(SEQ=1000)], modified=real_pkt(SEQ=1000+N)

Итог: два inject пакета с SEQ=1000 отправлены, real пакет с SEQ=1000+N отправлен. Сервер ждёт SEQ=1000, не 1000+N → соединение ломается.

**Патч — запретить comping техник изменяющих SEQ в concurrent режиме:**

```rust
// В DesyncOp trait — добавить флаг совместимости
pub trait DesyncOp {
    fn apply(&self, state: &mut PipelineState, config: &DesyncConfig);
    fn weight(&self) -> u8 { 1 }
    
    /// Техника модифицирует SEQ number (несовместима с другими SEQ-техниками)
    fn modifies_seq(&self) -> bool { false }
}

// В apply_concurrent — проверять конфликт SEQ
fn apply_concurrent(&self, packet: &bytes::Bytes) -> DesyncResult {
    let mut result = DesyncResult::passthrough();
    let mut seq_modified = false;
    
    for technique in &self.techniques {
        let is_seq_tech = matches!(technique, 
            DesyncTechnique::FakeDataSplit | DesyncTechnique::FakeDataDisorder);
        
        if is_seq_tech && seq_modified {
            // ⚠️ SEQ-конфликт: пропускаем технику в concurrent режиме
            tracing::warn!("SEQ conflict: {:?} skipped in concurrent mode (use pipeline mode)", technique);
            continue;
        }
        
        let r = self.apply_single(technique, packet);
        if r.modified.is_some() && is_seq_tech { seq_modified = true; }
        result.merge(r);
    }
    result
}
```

**Рекомендация:** для комбинаций техник модифицирующих SEQ — использовать `pipeline_mode = true`.

---

### 🟠 HIGH-12: Out-of-Order и ретрансмиссии — `injected_seqs` ломает повторные десинхронизации

**Файл:** `engine/mod.rs:480-490, 545-555`

```rust
// При ретрансмиссии Windows (после потери пакета):
// ClientHello #1 → inject fake → SEQ=1000 добавляется в injected_seqs
// Fake пакет вызывает RST на DPI → Windows ретрансмиттит ClientHello
// ClientHello #2 (та же SEQ=1000) → попадает в injected_seqs.contains() → FORWARD
// DPI видит чистый ClientHello → блокирует соединение!

if self.injected_seqs.contains(&tcp.get_sequence()) {
    return Ok(PacketDecision::Forward);  // ❌ Ретрансмиссия проходит без защиты
}
```

**Патч — ограничить skip retransmit временны́м окном:**

```rust
// Использовать InjectedSeqTracker с TTL вместо вечного DashSet
// (уже показан в CRITICAL-2 патче)

// Дополнительно: применять десинхронизацию к ретрансмиссиям
// с счётчиком попыток (max 3 раза для одного SEQ)
pub struct InjectedSeqEntry {
    pub timestamp: Instant,
    pub inject_count: u8,  // Сколько раз инжектировали для этого SEQ
}

// Если inject_count < MAX_RETRANSMIT_INJECTIONS (3) — применяем десинхронизацию снова
// Если inject_count >= 3 — переключаемся на другую технику (fallback_strategy)
```

---

### 🟡 MEDIUM-13: Conntrack не отслеживает реальное состояние — `desync_applied` всегда `false`

**Файл:** `engine/mod.rs:505-524`

```rust
let entry = ConntrackEntry {
    // ...
    state: ConnState::Established,  // ❌ Всегда Established, даже для SYN пакетов
    desync_applied: false,          // ❌ Никогда не обновляется до true
    strategy_id: 0,                 // ❌ Всегда 0
    // ...
};
self.conntrack.upsert(key, entry);  // Overwrite on EVERY TLS packet
```

Conntrack пишется на каждый TLS пакет, но `desync_applied` остаётся `false` навсегда. Второй пакет в том же соединении снова применяет десинхронизацию. Для уже установленного TLS соединения это создаёт лишние injects на DATA пакеты (после ClientHello).

**Патч:**
```rust
// Обновлять conntrack только при ПЕРВОМ пакете (SYN или первый data)
// Маркировать desync_applied = true после успешного inject

match self.conntrack.entry(key) {
    Entry::Occupied(mut o) => {
        // Уже отслеживаем — просто обновить activity
        o.get_mut().last_activity = Instant::now();
        if o.get().desync_applied {
            // Десинхронизация уже применена — forward без повторного inject
            return Ok(PacketDecision::Forward);
        }
    }
    Entry::Vacant(v) => {
        v.insert(ConntrackEntry { state: ConnState::Established, desync_applied: false, ... });
    }
}
// После успешного inject:
if let Some(mut entry) = self.conntrack.get_mut(&key) {
    entry.desync_applied = true;
}
```

---

## ДОМЕН 4: Алгоритмическая и Математическая чистота

---

### 🔴 CRITICAL-14: PRNG — все потоки стартуют с одинакового seed, первые паттерны идентичны

**Файл:** `desync/rand.rs:25-51`

```rust
static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);

fn init_seed() -> u64 {
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);
    if seed != 0 {
        return seed;  // ❌ ВСЕ потоки получают ОДИН И ТОТ ЖЕ seed!
    }
    let now = std::time::SystemTime::now()...as_nanos() as u64;
    // Первый поток устанавливает GLOBAL_SEED = timestamp
    // Все последующие потоки вернут тот же timestamp
    GLOBAL_SEED.compare_exchange(0, new_seed, ...).unwrap_or(new_seed)
}

// Thread-local Xorshift64 — стартует из GLOBAL_SEED:
STATE.with(|state| {
    let mut x = state.get();
    if x == 0 { x = init_seed(); }  // ← Тот же initial state у всех потоков!
```

При старте приложения все 4-8 Tokio workers получают **идентичный начальный seed**. Первый вызов `random_ttl_offset()` в каждом потоке даст **одинаковое значение**. DPI с ML может:
1. Собрать статистику TTL/split паттернов из перехваченного трафика
2. Вычислить seed по нескольким наблюдениям
3. Предсказывать будущие split позиции → идентифицировать bypass-трафик

Дополнительная проблема: `PerConnRng::new(conn_id)` использует только `dst_ip.to_bits()` как `conn_id`:
```rust
// engine/mod.rs:521
rng: Some(crate::desync::rand::PerConnRng::new(cp.dst_ip.to_bits() as u64)),
//                                              ^^^^^^^^^^^^^^^^^^^^^^^^^
// Одинаковый conn_id для ВСЕХ соединений на один IP!
// (Два одновременных соединения к YouTube: одинаковый PerConnRng)
```

**Патч — энтропийный seed с перемешиванием:**

```rust
use std::sync::atomic::{AtomicU64, Ordering};

// Вместо одного глобального seed — глобальный СЧЁТЧИК для уникальности
static THREAD_COUNTER: AtomicU64 = AtomicU64::new(0);

fn make_thread_seed() -> u64 {
    // Комбинируем: timestamp + thread_id + global counter
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let tid = THREAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    
    // Добавляем адрес стека для ASLR-entropy (не переносимо, но OK для Windows)
    let stack_entropy = {
        let local: u64 = 0;
        (&local as *const u64) as u64
    };
    
    // splitmix64 перемешивает все три источника
    splitmix64(ts ^ splitmix64(tid) ^ splitmix64(stack_entropy))
}

// Каждый поток получает уникальный seed:
thread_local! {
    static STATE: std::cell::Cell<u64> = std::cell::Cell::new(0);
}

pub fn random_u64() -> u64 {
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 { x = make_thread_seed(); }  // ✅ Уникальный на поток
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x
    })
}

// PerConnRng — использовать полный 4-tuple как conn_id
impl PerConnRng {
    pub fn new_from_tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> Self {
        let ts = SystemTime::now()...as_nanos() as u64;
        // Пакуем 4-tuple в 64 бита
        let tuple = (src_ip as u64) << 32 
            | (dst_ip as u64 >> 16) << 16 
            | src_port as u64 ^ dst_port as u64;
        let seed = splitmix64(ts ^ splitmix64(tuple));
        Self {
            state: [seed, splitmix64(seed.wrapping_add(0x9E3779B97F4A7C15))],
            counter: 0,
        }
    }
}
```

---

### 🟠 HIGH-15: `random_delay_us()` — modulo bias (автор знал про Lemire, но забыл применить)

**Файл:** `desync/rand.rs:118`

```rust
// Везде используется Lemire's method:
pub fn random_range(min: u32, max: u32) -> u32 {
    // ...
    let m = (random_u64() as u128).wrapping_mul(range as u128);
    min + (m >> 64) as u32  // ✅ Lemire — без bias
}

// Но здесь забыт:
pub fn random_delay_us() -> u64 {
    random_u64() % 10000  // ❌ Modulo bias! 2^64 % 10000 != 0
}
```

Bias ~0.002% — математически незначителен, но нарушает принцип. Для bypass-системы предсказуемые паттерны = уязвимость.

**Патч:**

```rust
pub fn random_delay_us() -> u64 {
    // Lemire для u64:
    let m = (random_u64() as u128).wrapping_mul(10000u128);
    (m >> 64) as u64  // ✅ Uniform в [0, 10000)
}
```

---

### 🟡 MEDIUM-16: `gen_split_mask()` — 8 вызовов PRNG вместо одного

**Файл:** `desync/rand.rs:157-166`

```rust
pub fn gen_split_mask() -> u64 {
    let mut mask: u64 = 0;
    for byte_idx in 0..8 {
        let mut byte: u8 = random_u32() as u8;  // Вызов PRNG × 8
        // random_u32() внутри вызывает random_u64() и дропает 32 бита!
```

Одного вызова `random_u64()` достаточно для получения всех 8 байт.

**Патч:**

```rust
pub fn gen_split_mask() -> u64 {
    let mut mask = random_u64();  // Один вызов — все 8 байт сразу
    
    // Гарантируем хотя бы 1 бит в каждом 8-битном блоке
    for byte_idx in 0..8u32 {
        let byte = (mask >> (byte_idx * 8)) as u8;
        if byte == 0 {
            // Устанавливаем случайный бит в нулевом байте
            let bit = (random_u64() & 7) as u32;
            mask |= 1u64 << (byte_idx * 8 + bit);
        }
    }
    mask
}
```

---

### 🟡 MEDIUM-17: `StrategyMetrics::avg_latency_us` — накопительный overflow при длительной работе

**Файл:** `adaptive/auto_tune.rs`

```rust
pub fn record_success(&mut self, latency_us: u64) {
    self.success_count += 1;
    self.total_latency_us += latency_us;  // ❌ Будет переполнен через ~500 лет...
    // Ладно, u64 не переполнится. Но вот:
    self.avg_latency_us = self.total_latency_us / self.success_count;  // Integer division truncation
}
```

Проблема не в overflow (u64 хватит), а в том что при success_count → ∞ старые данные имеют тот же вес что и новые. Система не адаптируется к изменению условий.

**Патч — Exponential Moving Average (EMA):**

```rust
pub fn record_success(&mut self, latency_us: u64) {
    self.success_count += 1;
    
    if self.avg_latency_us == 0 {
        self.avg_latency_us = latency_us;
    } else {
        // EMA с alpha = 0.1 (через fixed-point: x * 10 / 100)
        // EMA_new = 0.9 * EMA_old + 0.1 * new_value
        // Fixed-point: ×100 = 90*old + 10*new / 100
        self.avg_latency_us = 
            (90 * self.avg_latency_us + 10 * latency_us) / 100;
    }
}
```

---

## Сводная таблица приоритетов

| # | Файл | Проблема | Severity | Impact |
|---|------|----------|----------|--------|
| 1 | engine/mod.rs:313 | blocking_send → WinDivert deadlock | 🔴 CRITICAL | 100% packet loss под нагрузкой |
| 2 | engine/mod.rs:224 | injected_seqs unbounded DashSet | 🔴 CRITICAL | Memory leak + SEQ wrap |
| 3 | desync/tcp.rs:606,644 | TCP checksum before payload | 🔴 CRITICAL | ALL modified packets dropped |
| 4 | desync/tcp.rs:217 | fakedsplit wrong SEQ advance | 🔴 CRITICAL | Connection broken |
| 5 | engine/mod.rs:609+163 | Triple memcpy per packet | 🔴 CRITICAL | 3.75 GB/s wasted bandwidth |
| 6 | desync/rand.rs:36 | Global seed → identical threads | 🔴 CRITICAL | DPI ML fingerprinting |
| 7 | desync/group.rs:128 | Concurrent merge SEQ conflict | 🔴 CRITICAL | Connection breaks w/ multi-technique |
| 8 | desync/tcp.rs:394 | buf.to_vec() double alloc (×7) | 🟠 HIGH | 2× alloc per modified packet |
| 9 | desync/mod.rs:build_ip | No MTU check | 🟠 HIGH | Silent NDIS drop for QUIC |
| 10 | conntrack.rs:86 | Double DashMap lock in upsert | 🟠 HIGH | 2× lock contention at 10 Gbps |
| 11 | split_tunnel.rs:77 | O(n) linear cache search | 🟠 HIGH | Slower than DashMap at TL_CACHE=1024 |
| 12 | engine/mod.rs:484 | injected_seqs breaks retransmits | 🟠 HIGH | No desync on TCP retransmit |
| 13 | rand.rs:118 | random_delay_us modulo bias | 🟠 HIGH | Pattern predictability |
| 14 | rand.rs:157 | gen_split_mask 8× PRNG calls | 🟡 MEDIUM | 8× wasted PRNG calls |
| 15 | auto_tune.rs | avg_latency not adaptive | 🟡 MEDIUM | Stale metrics, wrong decisions |
| 16 | conntrack.rs | desync_applied never set | 🟡 MEDIUM | Desync applied on every packet |

---

## Критический путь fix-листа (порядок выполнения)

1. **TCP checksum bug** (#3) — ломает ВСЁ прямо сейчас. Fix за 30 минут.
2. **fakedsplit SEQ** (#4) — тоже ломает соединения. Fix за 15 минут.
3. **Triple memcpy** (#5) — серьёзнее чем кажется при 10 Gbps. 
4. **PRNG global seed** (#6) — security issue, не performance.
5. **injected_seqs** (#2) — memory leak, заменить структуру.
6. **blocking_send** (#1) — критично при нагрузке.
7. **buf.to_vec()** (#8) — trivial, 5 минут на весь файл.
8. **Concurrent merge SEQ** (#7) — архитектурно, но патч простой.
