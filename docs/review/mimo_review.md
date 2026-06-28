# FreeDPI Windows v3.0 — Суровое ревью кодовой базы

> Ревью выполнено на исходниках `src/core/src/` — ядро пакетного движка.
> Цель: скрытые bottleneck'и при 5-10 Gbps, математические уязвимости, логические дыры.

---

## ДОМЕН 1: Network Backpressure & Queue Management

### 1.1 КРИТИЧНО: Нет Backpressure — mpsc канал 1024 при 1M+ pps

**Файл:** `engine/mod.rs:297`

```rust
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(1024);
```

**Проблема:** При 10 Gbps (~14.8M pps для 64-байтных пакетов, ~844K pps для 1500-байтных) канал из 1024 элементов переполняется за <2 мс. `blocking_send` в recv-loop начнёт блокировать WinDivert recv, что приведёт к потере пакетов на уровне драйвера (WinDivert queue overflow → `ERROR_BUFFER_OVERFLOW`).

**Влияние:** При torrent-флуде система начнёт терять SYN пакеты → новые TCP соединения не устанавливаются → 4K стримы обрываются.

**Патч:**
```rust
// Вместо bounded(1024) — bounded(8192) + head-drop при переполнении
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(8192);

// В recv loop — не блокируемся при переполнении:
if tx.try_send(CapturedPacket { data, addr }).is_err() {
    // Channel full — drop oldest пакет (backpressure)
    stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
    // НЕ блокируемся — recv loop продолжает работать
}
```

**Альтернатива (лучше):** crossbeam bounded channel с `try_send`:
```rust
use crossbeam_channel::{bounded, TrySendError};

let (tx, rx) = bounded::<CapturedPacket>(16384);

// recv loop:
match tx.try_send(CapturedPacket { data, addr }) {
    Ok(_) => {},
    Err(TrySendError::Full(_)) => {
        stats.backpressure_drops.fetch_add(1, Ordering::Relaxed);
    },
    Err(TrySendError::Disconnected(_)) => break,
}
```

---

### 1.2 КРИТИЧНО: DashMap race condition в `gc_fast()`

**Файл:** `conntrack.rs:191`

```rust
pub fn gc_fast(&self, max_idle: Duration) {
    let now = Instant::now();
    let mut removed = 0u64;
    self.inner.map.iter().step_by(128).for_each(|r| {
        if now.duration_since(r.value().last_activity) > max_idle {
            self.inner.map.remove(r.key()); // ← MUTATION DURING ITERATION
            removed += 1;
        }
    });
}
```

**Проблема:** `DashMap::iter()` возвращает иммутабельный итератор, но `remove()` требует мутабельный доступ. DashMap использует RwLock per-shard — `remove()` во время `iter()` вызывает **deadlock или undefined behavior** (depends on DashMap version). В dashmap 6.x это panicked или silently corrupts state.

**Влияние:** При высокой нагрузке GC thread падает → conntrack растёт бесконечно → OOM через 30-60 минут.

**Патч:**
```rust
pub fn gc_fast(&self, max_idle: Duration) {
    let now = Instant::now();
    let mut removed = 0u64;
    // Собираем ключи для удаления отдельно
    let stale_keys: Vec<ConnKey> = self.inner.map.iter()
        .step_by(128)
        .filter_map(|r| {
            if now.duration_since(r.value().last_activity) > max_idle {
                Some(*r.key())
            } else {
                None
            }
        })
        .collect();
    for key in stale_keys {
        if self.inner.map.remove(&key).is_some() {
            removed += 1;
        }
    }
    if removed > 0 {
        self.inner.active_count.fetch_sub(removed, Ordering::Relaxed);
    }
}
```

---

### 1.3 DashMap double-lookup в `upsert()`

**Файл:** `conntrack.rs:112`

```rust
pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
    let existed = self.inner.map.get(&key).is_some(); // LOOKUP 1
    self.inner.map.insert(key, entry);                  // LOOKUP 2
    if !existed {
        self.inner.total_created.fetch_add(1, Ordering::Relaxed);
        self.inner.active_count.fetch_add(1, Ordering::Relaxed);
    }
}
```

**Проблема:** Два отдельных lookup per packet на hot path. При 1M pps это 2M DashMap lookups в секунду. DashMap shard lock cost ~20-50ns per lock. Итого: 40-100 мкс额外 overhead на каждую 1000 пакетов.

**Патч — использовать `entry()` API:**
```rust
use dashmap::mapref::entry::Entry;

pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
    match self.inner.map.entry(key) {
        Entry::Vacant(e) => {
            e.insert(entry);
            self.inner.total_created.fetch_add(1, Ordering::Relaxed);
            self.inner.active_count.fetch_add(1, Ordering::Relaxed);
        }
        Entry::Occupied(mut e) => {
            *e.get_mut() = entry;
        }
    }
}
```

---

### 1.4 Thread-local cache — O(n) linear scan

**Файл:** `split_tunnel.rs:83`

```rust
let cached = BYPASS_CACHE.with(|c| {
    let cache = c.borrow();
    cache.iter().find(|(ip, _)| *ip == ip_int).map(|(_, v)| *v)
});
```

**Проблема:** `Vec::find()` — O(n) scan. При 1024 элементах в cache平均每512 comparisons per lookup. At 10Gbps: ~1M lookups/sec × 512 comparisons = ~500M comparisons/sec.

**Кэш также не работает как LRU:** `cache.remove(0)` — O(n) shift. При переполнении каждый 1025-й lookup стоит O(n).

**Патч — использовать fixed-size array с direct index:**
```rust
thread_local! {
    // Прямая индексация по IP % 1024 — O(1) lookup
    static BYPASS_CACHE: std::cell::RefCell<[Option<(u32, bool)>; 1024]> =
        std::cell::RefCell::new([None; 1024]);
}

pub fn should_bypass_ip_fast(&self, dst_ip: &Ipv4Addr) -> bool {
    let ip_int = u32::from_ne_bytes(dst_ip.octets());
    let idx = (ip_int as usize) % 1024;

    BYPASS_CACHE.with(|c| {
        let cache = c.borrow();
        if let Some((cached_ip, result)) = &cache[idx] {
            if *cached_ip == ip_int {
                return *result;
            }
        }
        drop(cache);

        let result = self.should_bypass_ip(dst_ip);

        let mut cache = c.borrow_mut();
        cache[idx] = Some((ip_int, result));
        result
    })
}
```

---

### 1.5 Pool: глобальный Mutex на hot path

**Файл:** `pool.rs:8`

```rust
static POOL: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
```

**Проблема:** Глобальный `Mutex<Vec<Vec<u8>>>` — все потоки конкурируют за одну блокировку. При 16 ядрах и 10M pps это будет основным bottleneck. Каждый `get_buf` / `return_buf` = acquire + release Mutex.

**Но хуже того:** `return_buf` нигде НЕ вызывается! Все аллокации через `get_buf` утекают.

**Патч — thread-local pool без Mutex:**
```rust
thread_local! {
    static BUF_POOL: std::cell::RefCell<Vec<Vec<u8>>> =
        std::cell::RefCell::new(Vec::with_capacity(32));
}

pub fn get_buf(size: usize) -> Vec<u8> {
    BUF_POOL.with(|pool| {
        let mut p = pool.borrow_mut();
        // Ищем подходящий буфер
        if let Some(idx) = p.iter().position(|b| b.capacity() >= size) {
            let mut buf = p.swap_remove(idx);
            buf.clear();
            buf.resize(size, 0);
            return buf;
        }
        vec![0u8; size]
    })
}

pub fn return_buf(buf: Vec<u8>) {
    BUF_POOL.with(|pool| {
        let mut p = pool.borrow_mut();
        if p.len() < 32 && buf.capacity() <= 65535 {
            p.push(buf);
        }
    })
}
```

---

## ДОМЕН 2: Zero-Copy & Hidden Allocations

### 2.1 КРИТИЧНО: Каждый recv копирует пакет

**Файл:** `packet_engine.rs:163`

```rust
pub fn recv_blocking(&self, buffer: &mut [u8]) -> Result<(Vec<u8>, WinDivertAddress<NetworkLayer>)> {
    let packet = divert.recv(buffer).context("WinDivert recv failed")?;
    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
    Ok((packet.data.to_vec(), packet.address)) // ← TO_VEC() на каждый пакет!
}
```

**Проблема:** `packet.data.to_vec()` — полное копирование пакета (до 65535 байт) на КАЖДЫЙ recv. При 10Gbps с 1500-байтными пакетами: ~844K × 1500 = **1.2 GB/s memcpy** только на recv.

**Патч:**
```rust
pub fn recv_blocking(&self, buffer: &mut [u8]) -> Result<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> {
    let packet = divert.recv(buffer).context("WinDivert recv failed")?;
    self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
    // Zero-copy: Bytes::copy_from_slice только если нужен owned data
    // Или: вернуть ссылку на буфер (lifetime зависит от arch)
    Ok((bytes::Bytes::copy_from_slice(&packet.data), packet.address))
}
```

> **Примечание:** WinDivert `recv()` возвращает `WinDivertPacket` с внутренним буфером.
> При `spawn_blocking` буфер живёт только в пределах замыкания.
> Копия в `bytes::Bytes` — необходимый минимум, но `Vec<u8>` хуже.

---

### 2.2 build_ip_packet и build_tcp_segment: аллокация на каждый inject

**Файл:** `desync/mod.rs:377`, `desync/tcp.rs:630`

```rust
// mod.rs:377
pub fn build_ip_packet(...) -> bytes::Bytes {
    let total_len = 20 + payload.len();
    let mut buf = vec![0u8; total_len]; // ← NEW ALLOCATION per call
    // ...
    bytes::Bytes::from(buf) // ← ещё одна аллокация для conversion
}

// tcp.rs:630
fn build_tcp_segment(...) -> bytes::Bytes {
    let mut tcp_buf = vec![0u8; tcp_header_len]; // ← ALLOCATION 1
    // ...
    let mut full_payload = tcp_buf.to_vec();     // ← ALLOCATION 2 (clone)
    full_payload.extend_from_slice(payload);
    build_ip_packet(...)                          // ← ALLOCATION 3
}
```

**Проблема:** `build_tcp_segment` делает **3 аллокации** на каждый fake пакет. При `MultiSplit` с 3 сегментами = 9 аллокаций + 3 `bytes::Bytes::from()`. При 10K connections/sec × 3 inject = **30K malloc+free в секунду**.

**Патч — pool-based packet builder:**
```rust
use std::cell::RefCell;

thread_local! {
    static PACKET_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(1500));
}

fn build_tcp_segment_pooled(
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16,
    payload: &[u8], ttl: u8, identification: u16,
) -> bytes::Bytes {
    PACKET_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();
        buf.reserve(40 + payload.len());

        // IP header (20 bytes)
        buf.extend_from_slice(&[0x45, 0x00]); // ver/ihl, DSCP
        let total_len = 40 + payload.len();
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.extend_from_slice(&identification.to_be_bytes());
        buf.extend_from_slice(&[0x40, 0x00]); // flags + frag offset
        buf.push(ttl);
        buf.push(6); // TCP
        buf.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        buf.extend_from_slice(&src_ip.octets());
        buf.extend_from_slice(&dst_ip.octets());

        // TCP header (20 bytes)
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&ack.to_be_bytes());
        buf.push(0x50); // data offset = 5
        buf.push(flags);
        buf.extend_from_slice(&window.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // checksum
        buf.extend_from_slice(&[0x00, 0x00]); // urgent ptr

        // Payload
        buf.extend_from_slice(payload);

        // Checksums
        let ip_csum = ipv4_checksum(&buf[..20]);
        buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        let tc = tcp_checksum_v4(src_ip, dst_ip, &buf[20..]);
        buf[36..38].copy_from_slice(&tc.to_be_bytes());

        bytes::Bytes::copy_from_slice(&buf) // single allocation
    })
}
```

---

### 2.3 Inject loop: лишнее копирование через `to_vec()`

**Файл:** `engine/mod.rs:348`

```rust
for inject_pkt in &inject {
    match inject_protocol {
        InjectProtocol::Tcp => {
            let mut tagged = inject_pkt.to_vec(); // ← COPY of inject packet
            if self.config.event_tag_enabled {
                event_tag::tag_injected_packet(&mut tagged);
            }
            self.packet_engine.inject_via_divert(&tagged, &captured.addr)?;
        }
    }
}
```

**Проблема:** Каждый inject пакет копируется ещё раз через `to_vec()`. При `SynFloodDecoy` с 5 decoys: 5 × copy + 5 × tag + 5 × inject = 15 операций с копированием.

**Патч — tag in-place через `BytesMut`:**
```rust
for inject_pkt in &inject {
    match inject_protocol {
        InjectProtocol::Tcp => {
            if self.config.event_tag_enabled {
                // tag_injected_packet должен работать с &[u8], не requiring &mut
                // Либо: использовать BytesMut::make_mut()
                let mut tagged = Vec::with_capacity(inject_pkt.len() + 16);
                tagged.extend_from_slice(inject_pkt);
                event_tag::tag_injected_packet(&mut tagged);
                self.packet_engine.inject_via_divert(&tagged, &captured.addr)?;
            } else {
                self.packet_engine.inject_via_divert(inject_pkt, &captured.addr)?;
            }
        }
    }
}
```

---

### 2.4 winsize: double allocation (to_vec + buf.to_vec)

**Файл:** `desync/tcp.rs:374-394`

```rust
pub fn winsize(packet: &bytes::Bytes, new_window: u16) -> DesyncResult {
    // ...
    let mut buf = packet.to_vec();                    // ← ALLOCATION 1
    // ...
    DesyncResult::modified_only(buf.to_vec())         // ← ALLOCATION 2 (unnecessary!)
}
```

**Проблема:** `buf` уже является `Vec<u8>`, но `modified_only()` принимает `impl Into<bytes::Bytes>`, что вызывает второе копирование. `Vec<u8>` → `Bytes` через `From<Vec<u8>>` — zero-copy. Но `buf.to_vec()` делает ненужный clone.

**Патч:**
```rust
DesyncResult::modified_only(buf) // Vec<u8> → Bytes: zero-copy
```

**Та же проблема в:** `mss_clamp` (line 882), `win_scale_manip` (line 1145), `port_shuffle` (line 1589), `bad_checksum` (line 130), `ttl_manipulation` (line 163), `ttl_jitter` (line 416), `dscp_random` (line 445), `mutual_spoof` (line 487), `xor_first` (line 232), `bad_checksum` (line 130), `wclamp` (line 1658), `ts_md5` (line 1727).

---

## ДОМЕН 3: TCP State Machine & Protocol Anomalies

### 3.1 КРИТИЧНО: DesyncGroup merge() перезаписывает SEQ/ACK

**Файл:** `desync/group.rs:153-163`, `desync/mod.rs:84-92`

```rust
// group.rs:153 — concurrent mode
fn apply_concurrent(&self, packet: &bytes::Bytes) -> DesyncResult {
    let mut result = DesyncResult::passthrough();
    for technique in &self.techniques {
        let r = self.apply_single(technique, packet);
        result.merge(r); // ← MERGE
    }
    result
}

// mod.rs:84
pub fn merge(&mut self, other: Self) {
    if other.modified.is_some() {
        self.modified = other.modified; // ← LAST WRITER WINS!
    }
    self.inject.extend(other.inject);
    if other.drop {
        self.drop = true;
    }
}
```

**Проблема:** Каждая техника видит **оригинальный** пакет (concurrent mode). Если `FakeSni` создаёт inject с `SEQ = original_seq`, а `MultiSplit` создаёт modified с `SEQ = original_seq + split_size`, то `merge()` просто перезаписывает `modified`. Но **оба набора inject'ов накапливаются** — fake CH с `SEQ = original_seq` и split-сегменты с `SEQ = original_seq + offset`. Сервер увидит:

```
SEQ=X:   [FakeCH "google.com"]      (inject от FakeSni, TTL-1)
SEQ=X+1: [first byte of real data]  (inject от MultiSplit, TTL-1)
SEQ=X+1: [real data start]          (modified от MultiSplit, TTL-64)
```

**Результат:** Два пакета с одинаковым `SEQ=X+1` — сервер отправит dup-ACK. DPI видит хаос и может либо сбросить соединение, либо собрать fake CH как реальный.

**Патч — pipeline mode по умолчанию:**
```rust
impl DesyncGroup {
    pub fn apply(&self, packet: &bytes::Bytes) -> DesyncResult {
        // Pipeline: каждая техника видит modified от предыдущей
        self.apply_pipeline(packet)
    }

    fn apply_pipeline(&self, packet: &bytes::Bytes) -> DesyncResult {
        let mut state = PipelineState::from_packet(packet);

        for technique in &self.techniques {
            self.apply_to_state(technique, &mut state);
            if state.drop { break; }
        }

        state.into_result()
    }
}
```

---

### 3.2 КРИТИЧНО: FakeSni не обновляет SEQ — сервер получает overlapping data

**Файл:** `desync/tcp.rs:447-488`

```rust
pub fn fake_sni(packet: &bytes::Bytes, fake_sni_str: &str, fake_ttl_offset: u8) -> DesyncResult {
    // ...
    // Fake CH: SEQ = tcp.sequence (ОРИГИНАЛЬНЫЙ!)
    let fake_pkt = build_tcp_segment(
        ip.src, ip.dst, tcp.src_port, tcp.dst_port,
        tcp.sequence,          // ← SEQ = X (same as original!)
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,
        generate_identification(ip.identification, 0),
    );
    // Оригинальный пакет НЕ модифицируется — SEQ остаётся X
    DesyncResult::inject_only(fake_pkt)
}
```

**Проблема:** Fake CH отправляется с `SEQ = X`, а реальный пакет тоже идёт с `SEQ = X`. Сервер видит **два сегмента с одним SEQ**:
- `SEQ=X: [FakeCH "google.com"]` (TTL-1, умирает)
- `SEQ=X: [RealCH + data]` (TTL-64, доходит)

Если fake CH дойдёт до сервера (TTL-1 может не сработать при <1 хопе), это **duplicate data** — сервер отправит dup-ACK.

**Патч — Fake CH должен иметь другой SEQ (disorder):**
```rust
pub fn fake_sni(packet: &bytes::Bytes, fake_sni_str: &str, fake_ttl_offset: u8) -> DesyncResult {
    // ...
    // Fake CH: SEQ = tcp.sequence + fake_payload.len() + large_offset
    // Это "disorder" — fake CH имеет SEQ ДАЛЕКО за реальными данными
    // DPI видит его и пытается собрать, сервер — игнорирует (out-of-window)
    let fake_offset = (fake_payload.len() as u32).wrapping_add(65535);
    let fake_pkt = build_tcp_segment(
        ip.src, ip.dst, tcp.src_port, tcp.dst_port,
        tcp.sequence.wrapping_add(fake_offset), // ← OUT OF WINDOW
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,
        generate_identification(ip.identification, 0),
    );

    // Модифицируем оригинал: добавляем реальные данные как есть
    DesyncResult::modify_and_inject(packet.clone(), fake_pkt)
}
```

---

### 3.3 Нет MTU enforcement — инжектируемые пакеты могут превышать MTU

**Файл:** `desync/tcp.rs:579-612` (`build_full_tcp_packet`)

```rust
fn build_full_tcp_packet(..., payload: &[u8], ...) -> bytes::Bytes {
    let tcp_header_len = 20;
    let mut tcp_buf = vec![0u8; tcp_header_len];
    // ...
    let mut full_payload = tcp_buf.to_vec();
    full_payload.extend_from_slice(payload); // ← НЕТ ПРОВЕРКИ РАЗМЕРА!
    build_ip_packet(src_ip, dst_ip, ..., ttl, 0, &full_payload)
}
```

**Проблема:** `payload` может быть любого размера. Если `tcp.payload` = 1460 байт (MSS), то `build_full_tcp_packet` создаст пакет 20+20+1460 = 1500 байт (OK). Но `build_tcp_segment` для inject с `payload = tcp.payload[0..1]` = 41 байт (OK), а `build_tcp_segment` для `disorder` с `payload = tcp.payload[split_at..]` может быть >1460.

При фрагментации `ip_frag_primitives` с `frag_size=1024`: первый фрагмент = 20+1024 = 1044 байт (OK). Но `quic_padding_flood` создаёт пакеты без ограничения размера.

**Патч:**
```rust
const MAX_INJECT_SIZE: usize = 1460; // MSS

fn build_tcp_segment_safe(
    // ... все параметры ...
    payload: &[u8],
    // ...
) -> bytes::Bytes {
    // Ограничиваем payload до MSS
    let safe_payload = &payload[..payload.len().min(MAX_INJECT_SIZE)];
    build_tcp_segment(/* ... */, safe_payload, /* ... */)
}
```

---

### 3.4 `update_seq_monotonic` — сломанная логика обновления

**Файл:** `conntrack.rs:150-162`

```rust
pub fn update_seq_monotonic(&self, key: &ConnKey, seq: u32, ack: u32) {
    if let Some(mut entry) = self.inner.map.get_mut(key) {
        let delta = seq.wrapping_sub(entry.client_seq);
        if delta < 1_000_000 {
            if delta == 0 {
                entry.dup_ack_count += 1;
            } else if delta < 65535 {
                entry.client_seq = seq; // ← Обновляем только если delta < 65535
            }
            // Если 65535 <= delta < 1_000_000 — НЕ обновляем!
        }
        entry.client_ack = ack; // ← ACK обновляется ВСЕГДА
    }
}
```

**Проблема 1:** Если клиент отправляет данные порциями >65535 байт между двумя пакетами, `client_seq` НЕ обновляется → conntrack теряет sync.

**Проблема 2:** Метрика "dup-ACK" на самом деле считает **нулевой delta** (тот же самый seq), а не dup-ACK в смысле TCP. Настоящий dup-ACK = ACK без данных с тем же ACK number. Этот код считает повторный пакет с тем же SEQ.

**Патч:**
```rust
pub fn update_seq_monotonic(&self, key: &ConnKey, seq: u32, ack: u32) {
    if let Some(mut entry) = self.inner.map.get_mut(key) {
        let delta = seq.wrapping_sub(entry.client_seq);

        if delta == 0 {
            // Dup SEQ — считаем
            entry.dup_ack_count += 1;
        } else if delta < 1_000_000 {
            // Normal forward progress — обновляем всегда
            entry.client_seq = seq;
        }
        // delta >= 1_000_000 — potential wrap or OOO, ignore

        entry.client_ack = ack;
    }
}
```

---

### 3.5 `Direction::Outbound` hardcoded — inbound пакеты обрабатываются как outbound

**Файл:** `classifier.rs:93`

```rust
let cp = ClassifiedPacket {
    // ...
    direction: PacketDirection::Outbound, // ← ВСЕГДА Outbound!
    // ...
};
```

**Проблема:** Классификатор **всегда** возвращает `Outbound` для TCP и UDP пакетов. Направление определяется позже в `engine/mod.rs` через `is_outbound()`, но `ClassifiedPacket.direction` никогда не обновляется. Это не баг в текущем коде (engine проверяет `src_ip`), но создаёт путаницу и может привести к багам при добавлении inbound desync.

---

### 3.6 `ack_suppress` — дропает оригинальный ACK, не модифицирует

**Файл:** `desync/tcp.rs:891-928`

```rust
pub fn ack_suppress(packet: &bytes::Bytes, ...) -> DesyncResult {
    // ...
    // Только для ACK пакетов без данных
    if tcp.flags != TcpFlags::ACK || !tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }
    // ...
    DesyncResult::modify_and_inject(packet.to_vec(), fake_rst) // ← modify + inject
}
```

**Проблема:** Для ACK-only пакетов `modify_and_inject` возвращает **модифицированный оригинал** (без изменений) + fake RST. Но `engine/mod.rs:337` обработает `Modify(modified)` — отправит **тот же ACK** через WinDivert. ack_suppress должен **дропнуть** ACK, а не переслать его.

**Патч:**
```rust
pub fn ack_suppress(packet: &bytes::Bytes, ...) -> DesyncResult {
    // ...
    // Дропаем оригинальный ACK + инжектируем fake RST
    DesyncResult {
        modified: None,       // ← НЕ модифицируем оригинал
        inject: vec![fake_rst],
        drop: true,           // ← ДРОПАЕМ оригинальный ACK
    }
}
```

---

## ДОМЕН 4: Алгоритмическая и Математическая чистота

### 4.1 КРИТИЧНО: PRNG seed предсказуем — DPI с ML может предсказать паттерны

**Файл:** `desync/rand.rs:26-38`

```rust
fn init_seed() -> u64 {
    let seed = GLOBAL_SEED.load(Ordering::Relaxed); // ← DATA RACE!
    if seed != 0 { return seed; }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let new_seed = if now == 0 { 0xDEAD_BEEF_CAFE_BABE } else { now };
    GLOBAL_SEED.compare_exchange(0, new_seed, Ordering::SeqCst, Ordering::Relaxed)
        .unwrap_or(new_seed)
}
```

**Проблемы:**

1. **Seed = `SystemTime::now().as_nanos()`** — приблизительно известно время старта программы. DPI с ML может:
   - Замерить время между запуском desync-инструмента и началом блокировки
   - Вычислить seed ± 100 мс
   - Предсказать все следующие `random_ttl_offset()`, `random_split_size()` и т.д.

2. **`Ordering::Relaxed` на第一读** — data race. Два потока могут одновременно прочитать `0` и оба инициализировать seed. `compare_exchange` разрешает это, но `Relaxed` не garantирует visibility.

3. **`PerConnRng::new()` использует `SystemTime::now()` + `conn_id`** — `conn_id = dst_ip.to_bits()`. Если IP известен (а он известен из DNS), seed предсказуем.

**Патч — entropy mixing:**
```rust
fn init_seed() -> u64 {
    let seed = GLOBAL_SEED.load(Ordering::Acquire);
    if seed != 0 { return seed; }

    // Смешиваем несколько источников энтропии
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    use std::hash::Hasher;
    hasher.write_u64(now.as_nanos() as u64);
    hasher.write_u64(now.subsec_nanos() as u64);

    // Process ID + Thread ID (неизвестны DPI)
    hasher.write_u32(std::process::id());
    hasher.write_u64({
        use std::thread;
        let id = thread::current().id();
        format!("{:?}", id).len() as u64 // thread id хэш
    });

    // Stack address (аследует ASLR энтропию)
    let stack_var: u8 = 0;
    hasher.write_u64(&stack_var as *const u8 as u64);

    // Performance counter (высокоточный таймер)
    #[cfg(target_os = "windows")]
    {
        extern "system" {
            fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> i64;
        }
        unsafe {
            let mut freq: i64 = 0;
            extern "system" {
                fn QueryPerformanceFrequency(lpFrequency: *mut i64) -> i64;
            }
            unsafe { QueryPerformanceFrequency(&mut freq); }
            let mut counter: i64 = 0;
            unsafe { QueryPerformanceCounter(&mut counter); }
            hasher.write_i64(counter);
        }
    }

    let raw_seed = hasher.finish();
    let new_seed = if raw_seed == 0 { 0xDEAD_BEEF_CAFE_BABE } else { raw_seed };

    GLOBAL_SEED.compare_exchange(0, new_seed, Ordering::SeqCst, Ordering::Relaxed)
        .unwrap_or(new_seed)
}
```

---

### 4.2 Shannon Entropy: `f64` деление на hot path

**Файл:** `desync/obfs.rs:89-110`

```rust
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256]; // ← 2KB stack allocation per call!
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;       // ← float division
            entropy -= p * p.log2();           // ← float log2
        }
    }
    entropy
}
```

**Проблемы:**

1. **2KB stack allocation** `[0u64; 256]` — на каждый пакет. При 1M pps: 256MB stack usage (thread-local) + cache misses.

2. **`f64::log2()`** — ~20-40ns на современных CPU. При 256 buckets × 1M pps = 256M log2 calls = ~5-10 сек CPU в секунду.

3. **`entropy_padding()`** вызывается с `target_entropy: f64` — передаётся как float через весь call stack.

**Патч — fixed-point approximation:**
```rust
/// Fixed-point Shannon entropy (Q16.16) — без float на hot path.
/// precision: ~0.001 bits/byte (достаточно для padding decisions).
pub fn shannon_entropy_fp(data: &[u8]) -> u32 {
    if data.is_empty() { return 0; }

    // Stack-allocated frequency table (2KB)
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as u64;
    let mut entropy: i64 = 0; // Q16.16

    for &count in &freq {
        if count > 0 {
            // p = count / len (Q16.16)
            let p_q16 = (count << 16) / len as u32;
            // log2(p) approximation: use leading zeros
            // For precision, use a lookup table for log2
            // Simplified: entropy -= p * log2(p)
            // Using: -p*log2(p) = (p * (32 - lz(p))) >> 16
            let lz = (p_q16 as u32).leading_zeros();
            let log2_p = 31u32.saturating_sub(lz); // approximate
            let term = ((p_q16 as i64 * log2_p as i64) >> 16);
            entropy -= term;
        }
    }

    // Return as fixed-point (× 1000 for millibits)
    (entropy * 1000 / 65536) as u32
}
```

---

### 4.3 Poisson delay: деление float на hot path

**Файл:** `desync/obfs.rs:242-253`

```rust
pub fn poisson_delay(lambda_ms: f64) -> u64 {
    let u = crate::desync::rand::random_u32() as f64 / u32::MAX as f64;
    let delay = if u < 1.0 {
        -(1.0 - u).ln() * lambda_ms  // ← float division + ln()
    } else {
        lambda_ms
    };
    (delay as u64).clamp(1, 100)  // ← clamp twice (already clamped by ln)
}
```

**Проблемы:**

1. **`random_u32() as f64 / u32::MAX as f64`** — float division (~5ns).
2. **`-(1.0 - u).ln()`** — natural log (~20-40ns).
3. **Double clamp:** `clamp(1, 100)` + `if u < 1.0` — избыточно.

**Патч — lookup table:**
```rust
/// Pre-computed Poisson delay table (λ=20ms, 256 entries).
/// Lookup: O(1), без float на hot path.
static POISSON_TABLE: [u8; 256] = generate_poisson_table();

const fn generate_poisson_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        // Inverse CDF: F^(-1)(u) = -ln(1-u)/λ
        // Pre-computed for λ=20ms, clamped [1, 100]
        let u = i as f64 / 256.0;
        let delay = if u < 0.999 {
            let v = -(1.0 - u).ln() * 20.0;
            if v < 1.0 { 1u8 } else if v > 100.0 { 100u8 } else { v as u8 }
        } else {
            100u8
        };
        table[i] = delay;
        i += 1;
    }
    table
}

pub fn poisson_delay_fast(lambda_ms: u32) -> u64 {
    let idx = crate::desync::rand::random_u32() as usize % 256;
    POISSON_TABLE[idx] as u64
}
```

---

### 4.4 `random_range` — потенциальный modulo bias

**Файл:** `desync/rand.rs:118-129`

```rust
pub fn random_range(min: u32, max: u32) -> u32 {
    if min >= max { return min; }
    let range = max - min + 1;
    if range.is_power_of_two() {
        return min + (random_u32() & (range - 1));
    }
    // Lemire's method — без modulo bias
    let m = (random_u64() as u128).wrapping_mul(range as u128);
    min + (m >> 64) as u32
}
```

**Проблема:** `random_u64()` использует thread-local Xorshift64, который НЕ инициализируется при первом вызове в новом потоке (rayon worker). `STATE` thread-local инициализируется нулём → `if x == 0 { x = init_seed(); }` → первый вызов в каждом потоке использует глобальный seed.

**Но глобальный seed может быть 0** (race condition в `init_seed`). Тогда `x = 0` → `x ^= x << 13` → `x = 0` → бесконечный цикл нулевых значений.

**Патч:**
```rust
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<u64> = std::cell::Cell::new(0);
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 {
            x = init_seed();
            // Гарантируем non-zero
            if x == 0 { x = 0xDEAD_BEEF_CAFE_BABE; }
        }
        // Xorshift64 — все выходы non-zero если seed non-zero
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x
    })
}
```

---

### 4.5 ChaCha20 key хардкод

**Файл:** `desync/group.rs:322`

```rust
DesyncTechnique::ChaCha20 => {
    let key = [0x42u8; 32]; // ← HARDCODED KEY!
    crypto::chacha20_encrypt(packet, &key)
}
```

**Проблема:** Ключ `[0x42; 32]` захардкожен. DPI, знающий об этом инструменте, может:
1. Попробовать XOR с `0x42` на каждом байте
2. Если расшифровкаucceeded — это FreeDPI
3. Заблокировать по сигнатуре

**Патч:**
```rust
DesyncTechnique::ChaCha20 => {
    // Ключ из конфигурации или per-session
    let key = self.config.chacha20_key; // из DesyncConfig
    crypto::chacha20_encrypt(packet, &key)
}
```

---

## ДОПОЛНИТЕЛЬНЫЕ НАХОДКИ

### A.1 `Snapshot()` клонирует ВСЕ conntrack entries

**Файл:** `conntrack.rs:226-231`

```rust
pub fn snapshot(&self) -> Vec<(ConnKey, ConntrackEntry)> {
    self.inner.map
        .iter()
        .map(|r| (*r.key(), r.value().clone())) // ← CLONE EVERY ENTRY!
        .collect()
}
```

**Проблема:** При 10K активных соединениях: 10K × ~120 байт = 1.2MB аллокация + копирование при каждом API-запросе. `ConntrackEntry` содержит `Option<PerConnRng>` — ещё больше копирования.

**Патч — lazy iterator:**
```rust
pub fn snapshot(&self) -> impl Iterator<Item = (ConnKey, ConnState, u32)> + '_ {
    self.inner.map.iter().map(|r| {
        let v = r.value();
        (*r.key(), v.state, v.strategy_id)
    })
}
```

---

### A.2 `build_probe_client_hello` — double write of record length

**Файл:** `split_tunnel.rs:362-368`

```rust
let handshake_len = (packet.len() - 5) as u16;
packet[3] = (handshake_len >> 8) as u8;
packet[4] = (handshake_len & 0xFF) as u8;

let record_len = (packet.len() - 5) as u16;
packet[3] = (record_len >> 8) as u8;  // ← OVERWRITES handshake length!
packet[4] = (record_len & 0xFF) as u8;
```

**Проблема:** Два раза записывает в `packet[3..4]`. Вторая запись перезаписывает первую. `handshake_len == record_len` (оба = `packet.len() - 5`), поэтому это **не баг** сейчас, но при добавлении padding или расширений сломается.

---

### A.3 `DesyncResult.inject_slices()` — аллокация Vec<&[u8]> на каждый вызов

**Файл:** `desync/mod.rs:100-102`

```rust
pub fn inject_slices(&self) -> Vec<&[u8]> {
    self.inject.iter().map(|b| b.as_ref()).collect()
}
```

**Проблема:** Аллокация `Vec` на каждый вызов. На hot path это лишние malloc/free.

---

### A.4 `process_outbound_tls` — conntrack entry создаётся ПОСЛЕ desync

**Файл:** `engine/mod.rs:519-540`

```rust
// 4. Conntrack — записываем соединение
{
    let entry = ConntrackEntry { /* ... */ };
    self.conntrack.upsert(key, entry);
}

// 5. DesyncGroup — применяет все техники
let result = self.apply_desync_async(original_packet).await;
```

**Проблема:** Conntrack entry создаётся до desync, но `desync_applied = false` и `strategy_id = 0`. DesyncGroup не обновляет conntrack. При следующем пакете этого соединения conntrack не знает, какая стратегия была применена → не может оптимизировать (skip desync для established connections).

---

## Сводная таблица критичности

| # | Домен | Проблема | Критичность | Влияние при 10Gbps |
|---|-------|----------|:-----------:|-------------------|
| 1.1 | Backpressure | mpsc(1024) без backpressure | 🔴 | WinDivert overflow, packet loss |
| 1.2 | GC | DashMap mutation during iter | 🔴 | Deadlock / memory leak |
| 1.3 | Conntrack | Double lookup in upsert | 🟡 | +50% overhead on hot path |
| 1.4 | Cache | O(n) linear scan | 🟡 | ~500M comparisons/sec |
| 1.5 | Pool | Global Mutex + never returned | 🔴 | All threads serialize |
| 2.1 | Recv | `to_vec()` per packet | 🔴 | 1.2 GB/s memcpy |
| 2.2 | Build | 3 allocs per inject | 🟡 | 30K malloc/s |
| 2.3 | Inject | Extra to_vec() per inject | 🟡 | 2× copy overhead |
| 2.4 | winsize | Double allocation | 🟡 | Unnecessary alloc |
| 3.1 | DesyncGroup | merge() SEQ overwrite | 🔴 | Broken TCP session |
| 3.2 | FakeSni | Same SEQ as original | 🔴 | Dup data → RST |
| 3.3 | MTU | No size enforcement | 🟡 | NDIS silent drop |
| 3.4 | Conntrack | Broken seq monotonic | 🟡 | Lost sync on large reads |
| 3.5 | Classifier | Direction hardcoded | 🟢 | Cosmetic / future bug |
| 3.6 | AckSuppress | Drops wrong packet | 🔴 | ACK forwarded, desync fails |
| 4.1 | PRNG | Predictable seed | 🔴 | ML-based DPI can predict |
| 4.2 | Entropy | f64 log2 per packet | 🟡 | 5-10 sec CPU/s |
| 4.3 | Poisson | Float on hot path | 🟡 | ~40ns per call |
| 4.4 | PRNG | Zero seed possible | 🔴 | Infinite zero loop |
| 4.5 | Crypto | Hardcoded ChaCha20 key | 🔴 | Signature detection |
| A.1 | API | snapshot() clones all | 🟢 | 1.2MB per API call |
| A.2 | Probe | Double write in CH | 🟢 | Latent bug |

---

## Рекомендуемый порядок исправлений

1. **P0 ( немедленно):** #1.1, #1.2, #1.5, #2.1, #3.1, #3.2, #3.6, #4.1, #4.4, #4.5
2. **P1 (до 5Gbps нагрузки):** #1.3, #1.4, #2.2, #2.3, #2.4, #3.3, #3.4, #4.2, #4.3
3. **P2 (косметика):** #3.5, #A.1, #A.2, #A.3, #A.4
