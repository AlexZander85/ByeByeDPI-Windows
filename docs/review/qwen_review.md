# mimo_review.md

## ДОМЕН 1: Network Backpressure & Queue Management

### 1.1 `spawn_blocking` на Hot Path (Катастрофа пула потоков)
**Уязвимый код:** `engine/mod.rs` (функция `apply_desync_async`)
```rust
async fn apply_desync_async(&self, packet: &[u8]) -> crate::desync::DesyncResult {
    let packet = bytes::Bytes::copy_from_slice(packet);
    let group = self.desync_group.clone();
    tokio::task::spawn_blocking(move || {
        group.apply(&packet)
    }).await.unwrap_or_else(...)
}
```
**Почему это сломает трафик:** При нагрузке 10 Gbps (до 1.5 млн пакетов в секунду) `tokio::task::spawn_blocking` вызывается для каждого пакета. Этот API предназначен для редких блокирующих I/O операций (чтение с диска), а не для CPU-bound математики на каждом пакете. Оверхед на аллокацию таски и контекстное переключение мгновенно исчерпает дефолтный лимит `spawn_blocking` (512 потока). Это приведет к блокировке Tokio Reactor'а, диким задержкам (latency spikes), потере UDP/QUIC пакетов и деградации FPS в играх из-за блокировки сетевого стека Windows.
**Патч:** Убрать `spawn_blocking`. CPU-bound обработка пакетов должна выполняться прямо в async таске (Tokio work-stealing runtime сам распределит их по ядрам) или через выделенный `rayon` пул с bounded каналом, если требуется строгий affinity.
```rust
async fn apply_desync_async(&self, packet: &bytes::Bytes) -> crate::desync::DesyncResult {
    // Group.apply — чисто CPU-bound, выполняем в текущем async контексте
    // или через rayon::spawn если хотим жестко отвязать от реактора.
    self.desync_group.apply(packet)
}
```

### 1.2 Блокирующий Send и отсутствие Head-Drop
**Уязвимый код:** `engine/mod.rs` (цикл WinDivert recv)
```rust
let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(1024);
// ...
match engine.recv_blocking(&mut buf) {
    Ok((data, addr)) => {
        if tx.blocking_send(CapturedPacket { data, addr }).is_err() { break; }
    }
}
```
**Почему это сломает трафик:** При SYN-флуде или торрент-взрыве очередь на 1024 пакета переполняется за микросекунды. `blocking_send()` **блокирует текущий поток** до появления места. Поток `spawn_blocking` зависает. Если зависнут все потоки blocking-пула, WinDivert перестанет вычитывать пакеты из ядра, его внутренняя очередь (8192) переполнится, и NDIS-драйвер начнет молча дропать пакеты на уровне ядра. Пользователь получит "отвал" интернета.
**Патч:** Использовать `try_send()` с реализацией Head-Drop (отбрасывание самых старых пакетов или входящего пакета при переполнении).
```rust
match tx.try_send(CapturedPacket { data: buf.clone(), addr }) {
    Ok(_) => {},
    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        // Head-Drop: rx.try_recv() чтобы выкинуть старый пакет из головы очереди
        let _ = rx.try_recv(); 
        let _ = tx.try_send(CapturedPacket { data: buf.clone(), addr });
    }
    Err(_) => break, // Channel closed
}
```

### 1.3 `SystemTime::now()` в Hot Path и DashMap Contention
**Уязвимый код:** `desync/rand.rs` (`PerConnRng::new`) и `engine/mod.rs` (Conntrack upsert)
```rust
let e = std::time::SystemTime::now().duration_since(...).as_nanos() as u64;
```
**Почему это сломает трафик:** `SystemTime::now()` на Windows — это syscall (`GetSystemTimeAsFileTime`). Вызов syscall при создании каждого нового TCP-соединения в Hot Path создаст огромное прерывание процессора. Более того, разрешение таймера Windows часто составляет 15.6 мс. Если два соединения стартуют в одном тике, seed будет идентичным, что сделает PRNG предсказуемым для DPI.
**Патч:** Использовать Thread-Local PRNG для генерации seed или `getrandom` (RDRAND).
```rust
use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

thread_local! {
    static THREAD_RNG: std::cell::RefCell<ChaCha8Rng> = std::cell::RefCell::new(ChaCha8Rng::from_entropy());
}

pub fn new(conn_id: u64) -> Self {
    let seed = THREAD_RNG.with(|rng| rng.borrow_mut().next_u64() ^ conn_id);
    // ...
}
```

---

## ДОМЕН 2: Zero-Copy & Hidden Allocations

### 2.1 `Bytes::copy_from_slice` уничтожает Zero-Copy
**Уязвимый код:** `engine/mod.rs` (609) и `desync/group.rs` (39)
```rust
// engine/mod.rs
let packet = bytes::Bytes::copy_from_slice(packet);
// desync/group.rs
packet: bytes::Bytes::copy_from_slice(packet),
```
**Почему это сломает трафик:** Крейт `bytes` используется для zero-copy, но `copy_from_slice` делает **полный `memcpy` и аллокацию в куче** для каждого пакета. При 1.5 млн pps это 1.5 млн аллокаций в секунду. Глобальный аллокатор (mimalloc/jemalloc) захлебнется от lock contention, а CPU кэш (L1/L2) будет постоянно инвалидироваться. FPS в играх просядет из-за микро-фризов аллокатора.
**Патч:** Передавать `&bytes::Bytes` по стеку и использовать `.clone()` (это O(1), атомарный инкремент ref count).
```rust
pub fn from_packet(packet: bytes::Bytes) -> Self {
    Self {
        packet, // O(1) clone
        // ...
    }
}
```

### 2.2 Массовые `.to_vec()` в Desync-техниках
**Уязвимый код:** `desync/tcp.rs`, `desync/http.rs` (десятки мест)
```rust
let mut buf = packet.to_vec();
// ... модификация ...
DesyncResult::modified_only(buf.to_vec())
```
**Почему это сломает трафик:** Двойная аллокация и копирование payload'а на каждый чих (Split, FakeSNI). При фрагментации пакета (Split) мы должны делать `Bytes::slice()` (сдвиг указателя + инкремент ref count), а не копировать куски в новые `Vec`.
**Патч:** Использовать `BytesMut` из пула буферов (Buffer Pool) для сборки заголовков и `Bytes::slice()` для payload.
```rust
// Вместо packet.to_vec()
let mut buf = POOL.acquire(); // thread-local pool of BytesMut
buf.extend_from_slice(&header);
buf.extend_from_slice(&packet.slice(payload_offset..));
DesyncResult::modified_only(buf.freeze())
```

---

## ДОМЕН 3: TCP State Machine & Protocol Anomalies

### 3.1 Математический конфликт в Concurrent Mode (Desync Conflicts)
**Уязвимый код:** `desync/group.rs` (`apply_concurrent`)
```rust
fn apply_concurrent(&self, packet: &bytes::Bytes) -> DesyncResult {
    let mut result = DesyncResult::passthrough();
    for technique in &self.techniques {
        let r = self.apply_single(technique, packet);
        result.merge(r);
    }
}
```
**Почему это сломает трафик:** Если `MultiSplit` разбивает пакет, он меняет TCP SEQ оригинала (или генерирует inject'ы с новыми SEQ). Следующая техника (например, `FakeSni`) видит **оригинальный** пакет и генерирует Fake SNI с SEQ, который математически не стыкуется с тем, что сделал `MultiSplit`. При `merge` результаты либо перезатирают друг друга (теряется Split), либо на сервер уйдет каша из неверных SEQ номеров, что вызовет немедленный RST от сервера.
**Патч:** Полностью удалить Concurrent mode. Использовать только Pipeline mode с явным трекингом `seq_delta` и `payload_offset`.
```rust
pub struct PipelineState {
    pub packet: bytes::Bytes,
    pub seq_delta: u32, // Накопленный сдвиг SEQ
    pub payload_offset: usize,
}
```

### 3.2 Race Condition на ретрансмиссиях (Out-of-Order / Retransmits)
**Уязвимый код:** `engine/mod.rs` (process_outbound_tls)
```rust
// 5.1. Запоминаем SEQ инжектированных пакетов (для skip retransmits)
if !result.inject.is_empty() {
    self.injected_seqs.insert(tcp.get_sequence());
}
```
**Почему это сломает трафик:** Если Windows TCP стек делает ретрансмиссию ClientHello (потому что первый пакет потерялся в очереди NDIS), код видит этот SEQ в `injected_seqs` и **пропускает** инъекцию Fake SNI. В результате на сервер уходит чистый, незамаскированный ClientHello, и DPI его блокирует. Соединение виснет (timeout).
**Патч:** Отслеживать не просто факт инъекции, а состояние ACK от сервера. Либо инжектировать Fake SNI на первые N ретрансмиссий.
```rust
// В ConntrackEntry
pub struct ConntrackEntry {
    // ...
    pub fake_ch_inject_count: u8,
}
// В process_outbound_tls:
if entry.fake_ch_inject_count < 3 {
    // Инжектируем Fake CH даже для ретрансмиссии
    entry.fake_ch_inject_count += 1;
}
```

### 3.3 MTU / MSS Mismatch при инъекциях (NDIS Drop)
**Уязвимый код:** `desync/tcp.rs` (`TcpSegmentWriter`)
**Почему это сломает трафик:** `TcpSegmentWriter` собирает пакеты, не проверяя MTU исходящего интерфейса. Если пользователь сидит через PPPoE (MTU 1492) или VPN (MTU 1400), а мы инжектируем Fake SNI размером 1500 байт, Windows NDIS молча дропнет пакет на этапе отправки в Raw Socket (или фрагментирует его на уровне IP, что ломает TCP SEQ evasion).
**Патч:** Запрашивать MTU через WinDivert/Windows API при старте и жестко кламповать `MAX_TCP_PAYLOAD`.
```rust
const MAX_SAFE_MTU: usize = 1400; // Conservative fallback
const MAX_TCP_PAYLOAD: usize = MAX_SAFE_MTU - 40; // IP(20) + TCP(20)
```

---

## ДОМЕН 4: Алгоритмическая и Математическая чистота

### 4.1 `f64` и `log2()` на Hot Path (Shannon Entropy)
**Уязвимый код:** `desync/obfs.rs` (функция `shannon_entropy`)
```rust
pub fn shannon_entropy(data: &[u8]) -> f64 {
    // ...
    let p = count as f64 / len;
    entropy -= p * p.log2(); // <-- FPU yld2x / heavy instruction
}
```
**Почему это сломает трафик:** Вычисление энтропии с использованием `f64`, деления и `log2()` (который компилируется в тяжелую FPU инструкцию `fyl2x`) для каждого пакета при обфускации уничтожит производительность FPU. На 10 Gbps это вызовет тепловой тротлинг и микро-задержки.
**Патч:** Использовать Fixed-Point арифметику и precomputed LUT (Look-Up Table) для логарифмов.
```rust
const LOG2_TABLE: [u32; 256] = { /* precomputed log2(x/256) * 10000 */ };

pub fn shannon_entropy_fixed(data: &[u8]) -> u32 {
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let mut entropy = 0u32;
    let len = data.len() as u32;
    for &c in &counts {
        if c > 0 {
            // p = c / len. Используем целочисленное умножение
            entropy += (c * LOG2_TABLE[c as usize]) / len;
        }
    }
    entropy
}
```

### 4.2 Предсказуемость PRNG (Xorshift128** + Time Seed)
**Уязвимый код:** `desync/rand.rs`
```rust
let e = std::time::SystemTime::now().duration_since(...).as_nanos() as u64;
let seed = splitmix64(e ^ conn_id);
```
**Почему это сломает трафик:** Современные DPI системы используют ML для анализа паттернов FreeDPI. Xorshift128** обратим (reversible). Зная время подключения (с точностью до секунды) и IP, DPI может brute-force'ом восстановить seed за микросекунды и предсказать все Jitter/TTL маскировки.
**Патч:** Использовать `getrandom` (аппаратный `RDRAND`) для инициализации глобального состояния и криптографически стойкий PRNG (например, ChaCha8) для генерации паттернов.
```rust
use rand_core::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub struct SecureRng(ChaCha8Rng);
impl SecureRng {
    pub fn new(conn_hash: [u8; 32]) -> Self {
        Self(ChaCha8Rng::from_seed(conn_hash))
    }
}
```