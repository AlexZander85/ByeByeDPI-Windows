# FreeDPI Windows — Архитектура (Rust, v1.0)

**Всего техник: ~180**
- 45 — портировано из ByeDPI Android (TCP desync, TLS, QUIC, DNS, proxy fallback)
- 15 — из zapret2 (multisplit, fakedsplit, syndata, badsum, synhide, ipfrag...)
- 10 — Windows-эксклюзивных (IP frag overlap, MSS clamp, ACK suppress, reorder, RST selective...)
- 9 — из Nova (geo-routing, proxy chain, strategy evolution, per-app routing, Opera VPN)
- 3 — split tunneling (blacklist/whitelist/auto)
- 8 — из sing-box (TLS Spoof, TLS Record Fragment, uTLS, Reality, FakeIP DNS, Rule Sets...)
- 7 — из NaiveProxy (Chrome JA3, H2 SETTINGS, RST padding, H2 padding, Preamble, Multi-session, PQ)
- 14 — из b4 (Combo frag, SeqOverlap, TLS mutation, Fake QUIC, Detect & Escalate, RST protect, Window manip...)
- 3 — из FakeSIP (SIP masking, custom payload, UDP randomization)
- 4 — из dae концепций (trie, domain bitmap, rule normalization, first-packet cache)
- **4 — из sni-spoofing-rust (SEQ Number Spoofing, TLS CH generator, RawBackend, sniffer-register)**
- **15 — из RIPDPI (DesyncGroup, Plan+Execute, Disorder, MultiDisorder, FakeRst, Entropy padding, Adaptive offset, Fallback chain, Activation filters, TLS choreography, TSval MD5, WinClamp, DropSACK, Lua strategies...)**
- **4 — из autodpi (Probe/Tune/Run, Strategy trait, auto-tune, persistence)**
- **2 — из dpibreak (HopTab, Fake CH with badsum+auto-TTL)**
- **9 — из CandyTunnel (Mutual IP Spoof, ChaCha20, TTL jitter, Random DSCP, Packet padding, XOR FEC, Mux, Port Shuffle, IPIP tunnel)**
- **6 — из DPIReaper (Sentinel file, Task Scheduler, UWP LoopbackExempt, Firewall rules, WinHTTP proxy, PAC server)**
- **3 — из qeli (Poisson shaping, supervisor/worker, multiqueue)**
- **1 — из dpimyass (XOR first N bytes)**
- **3 — из OpenLogi (thread-local hot path, ~event tagging~ impostor flag, interprocess IPC)**
- **2 — из rust-no-dpi-socks (byte-by-byte first packet, unidirectional frag)**
- **2 — из rust-DPI-http-proxy (host-space, title-case HTTP headers)**
- (минус 6 Android-only: Doze, Radio, EnergyAware, Zero-Copy/splice...)

## Обзор

**FreeDPI Windows** — Rust-приложение для обхода DPI-блокировок на Windows 11.
Использует WinDivert + raw sockets для полного контроля над сетевыми пакетами
на уровне, недоступном на Android (VPN sandbox).

**Ключевые требования:**
- Раздельное туннелирование (черный/белый список сайтов)
- Многопроцессорная обработка (все ядра CPU)
- Минимальное потребление памяти (<10 MB под нагрузкой)
- Rust — memory safety + zero-cost abstractions

---

## 1. Выбор языка: Rust

### Почему Rust, а не C или Go

| Критерий | C | Go | Rust |
|----------|---|----|------|
| Производительность | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Memory safety | ❌ Нет | ⭐⭐⭐ (GC) | ⭐⭐⭐⭐⭐ |
| Отсутствие GC пауз | ✅ | ❌ (STW 1-5ms) | ✅ |
| Многопроцессорность | ⭐⭐⭐ (pthreads) | ⭐⭐⭐⭐ (goroutines) | ⭐⭐⭐⭐⭐ (rayon + tokio) |
| Потребление памяти | ~200 KB | ~8-15 MB | ~500 KB runtime |
| WinDivert binding | ✅ Нативный | ⚠️ CGo (~50-200ns overhead) | ✅ `windivert` crate |
| WinAPI интероп | ✅ | ⚠️ CGo | ✅ `windows` crate |
| Packet processing | ✅ | ❌ GC не подходит | ✅ |
| Пакетный менеджер | ❌ | ✅ | ✅ Cargo |
| Размер бинарника | ~200 KB | ~8-15 MB | ~2-5 MB |

### Как будем портировать bye-dpi C ядро (19 файлов)

**Стратегия: FFI → Rust миграция**

```
Фаза P0-P2:  Rust инфраструктура + C FFI bridge
             ┌─────────────────────────────────┐
             │  Rust (tokio, WinDivert, ...)    │
             │       │ unsafe { ... }          │
             │       ▼                         │
             │  bye-dpi.lib (19 C файлов)       │
             └─────────────────────────────────┘

Фаза P8:     Полностью на Rust
             ┌─────────────────────────────────┐
             │  Rust (всё)                      │
             │  - desync.rs                     │
             │  - tls_parrot.rs                 │
             │  - conntrack.rs                  │
             │  - raw_injector.rs               │
             └─────────────────────────────────┘
```

---

## 2. Архитектурная схема (Rust)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FreeDPI-win.exe                               │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                Packet Engine (tokio + WinDivert)                  │   │
│  │                                                                    │   │
│  │  [WinDivert::new("ip && tcp.DstPort == 443")]                     │   │
│  │       │                                                           │   │
│  │       ▼                                                           │   │
│  │  [tokio::spawn: windivert_recv loop]                              │   │
│  │       │                                                           │   │
│  │       ▼                                                           │   │
│  │  [mpsc::channel::<Packet>]  (lock-free канал)                     │   │
│  │       │                                                           │   │
│  │  ┌────┴────────────────────────────────────────────────────────┐ │   │
│  │  │                 Classifier                                   │ │   │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │ │   │
│  │  │  │ TCP:443  │ │ UDP:443  │ │ DNS:53   │ │ Blacklisted  │  │ │   │
│  │  │  │ (desync) │ │ (QUIC)   │ │ (DoH/DoT)│ │ (passthrough)│  │ │   │
│  │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘  │ │   │
│  │  └───────┼────────────┼────────────┼───────────────┘          │ │   │
│  └──────────┼────────────┼────────────┼──────────────────────────────┘   │
│             │            │            │                                  │
│  ┌──────────▼────────────▼────────────▼──────────────────────────────┐ │
│  │              Desync Engine (rayon thread pool)                     │ │
│  │                                                                     │ │
│  │  ┌──────────────────────────────────────────────────────────────┐ │ │
│  │  │  TCP Desync        │ QUIC Desync    │ DNS Engine             │ │ │
│  │  │  ┌────────────────┐│ ┌─────────────┐│ ┌────────────────────┐│ │ │
│  │  │  │ multisplit     ││ │ QUIC Block   ││ │ DoH (WinHTTP)     ││ │ │
│  │  │  │ multidisorder  ││ │ Initial Inj  ││ │ DoT (WinSSL)      ││ │ │
│  │  │  │ hostfakesplit  ││ │ Padding Flood││ │ Cache (TTL evict) ││ │ │
│  │  │  │ fakedsplit     ││ │ Short Header ││ │ Fast Reply        ││ │ │
│  │  │  │ fake SNI       ││ │ GREASE       ││ └────────────────────┘│ │ │
│  │  │  │ syndata        ││ │ udp2icmp     ││                       │ │ │
│  │  │  │ OOB            ││ └─────────────┘│                       │ │ │
│  │  │  │ MSS clamp      ││                 │                       │ │ │
│  │  │  │ IP frag overlap││  Proxy Fallback │                       │ │ │
│  │  │  │ ACK suppress   ││  ┌─────────────┐│                       │ │ │
│  │  │  │ pkt reorder    ││  │ SOCKS5      ││                       │ │ │
│  │  │  │ RST selective  ││  │ Async HS    ││                       │ │ │
│  │  │  │ ... (30+)      ││  │ Free Pool   ││                       │ │ │
│  │  │  └────────────────┘│  │ Crawler     ││                       │ │ │
│  │  │                    │  └─────────────┘│                       │ │ │
│  │  └──────────────────────────────────────────────────────────────┘ │ │
│  └──────────▲────────────▲────────────▲──────────────────────────────┘ │
│             │            │            │                                  │
│  ┌──────────┴────────────┴────────────┴──────────────────────────────┐ │
│  │              Output Layer                                          │ │
│  │  ┌──────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────┐ │ │
│  │  │WinDivert │ │Raw Socket  │ │ WinDivert  │ │Rust-TCP (proxy) │ │ │
│  │  │Send(mod) │ │Inject(fake)│ │Send(inbound)│ │  SOCKS5 client  │ │ │
│  │  └──────────┘ └────────────┘ └────────────┘ └──────────────────┘ │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              Split Tunnel Engine                                  │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌────────────┐                 │   │
│  │  │ Blacklist    │ │ Whitelist   │ │ Auto-Detect │                 │   │
│  │  │ (DashSet)    │ │ (DashSet)   │ │ (prober)   │                 │   │
│  │  └─────────────┘ └─────────────┘ └────────────┘                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  UI (system tray) / Windows Service                               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Ключевые Rust-компоненты

### 3.1 Cargo Workspace

```
FreeDPI-win/
├── Cargo.toml                    # workspace root
├── core/
│   ├── Cargo.toml                # FreeDPI-core crate
│   └── src/
│       ├── lib.rs
│       ├── packet_engine.rs      # WinDivert + raw sockets
│       ├── split_tunnel.rs       # Blacklist/whitelist engine
│       ├── classifier.rs         # Packet classification
│       ├── desync/               # Desync techniques (Rust port)
│       │   ├── mod.rs
│       │   ├── tcp.rs            # TCP-level techniques
│       │   ├── quic.rs           # QUIC/UDP techniques
│       │   ├── ip.rs             # IP-level techniques (frag, TTL)
│       │   ├── tls.rs            # TLS parroting, frag, ECH
│       │   ├── http.rs           # HTTP header tamper
│       │   └── dns.rs            # DNS techniques
│       ├── conntrack.rs          # Connection tracking (DashMap)
│       ├── proxy/                # SOCKS5 fallback
│       │   ├── mod.rs
│       │   ├── fallback.rs
│       │   └── free_pool.rs
│       ├── dns/                  # DNS engine
│       │   ├── mod.rs
│       │   ├── doh.rs
│       │   └── cache.rs
│       └── config.rs             # Configuration loader
├── ffi-bridge/
│   ├── Cargo.toml                # FFI bridge to bye-dpi C
│   ├── build.rs                  # cc crate: compile C files
│   └── src/
│       ├── lib.rs                # safe Rust wrappers
│       └── ffi_gen.rs            # bindgen output
├── service/
│   ├── Cargo.toml                # Windows Service binary
│   └── src/main.rs
├── ui/
│   ├── Cargo.toml                # System tray binary
│   └── src/main.rs
└── vendor/
    ├── windivert/              # WinDivert driver (bundled)
    │   ├── WinDivert64.sys     # Kernel-mode driver
    │   ├── WinDivert.dll       # User-mode library
    │   └── WinDivert.lib       # Static library
    └── byedpi/                 # Original C source (deprecated, not used)
        └── src/...
```

### 3.2 Packet Engine (WinDivert + Raw Socket)

```rust
pub struct PacketEngine {
    divert: Option<WinDivert<NetworkLayer>>,
    raw_sock: Option<RawSocketTx>,
    stats: PacketStats,
    mode: EngineMode,
}

impl PacketEngine {
    pub fn new(filter: &str) -> Result<Self> { /* ... */ }

    /// Блокирующий перехват — возвращает bytes::Bytes (zero-copy)
    pub fn recv_blocking(&self, buffer: &mut [u8]) -> Result<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>;

    /// TCP injection — через WinDivert с Impostor flag (MR-31)
    pub fn inject_via_divert(&self, packet: &[u8], addr: &WinDivertAddress) -> Result<()> {
        let mut impostor_addr = addr.clone();
        impostor_addr.set_impostor(true);  // предотвращает повторный перехват
        // ...
    }

    /// UDP injection — через raw socket
    pub fn inject_raw_udp(&self, packet: &[u8]) -> Result<()>;
}
```

    /// Перехват пакета (non-blocking)
    pub async fn recv(&self) -> Result<(Vec<u8>, WinDivertAddress)> {
        self.divert.recv().await
    }

    /// Инъекция модифицированного пакета
    pub fn send(&self, packet: &[u8], addr: &WinDivertAddress) -> Result<()> {
        self.divert.send(packet, addr)
    }

    /// Инъекция нового пакета через raw socket (не WinDivert)
    pub fn inject_raw(&self, packet: &[u8]) -> Result<()> {
        self.raw_tx.send(packet)
    }

    /// Дроп пакета — просто не вызываем send()
    
    /// Динамическое обновление фильтра при изменении blacklist
    pub fn update_filter(&mut self, tunnel: &SplitTunnel) -> Result<()> {
        let filter = tunnel.build_win_divert_filter();
        self.divert = WinDivert::new(&filter, Network, 0, 0)?;
        Ok(())
    }
}
```

### 3.3 Split Tunneling Engine

```rust
use dashmap::DashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

/// Режим раздельного туннелирования
#[derive(Clone, Debug, PartialEq)]
pub enum SplitMode {
    /// Только домены из whitelist → обход
    WhitelistOnly,
    /// Все домены, кроме blacklist → обход
    BlacklistOnly,
    /// Авто: пробуем, если RST/таймаут → в blacklist
    Auto,
}

/// Движок раздельного туннелирования
pub struct SplitTunnel {
    blacklist_domains: Arc<DashSet<String>>,
    blacklist_ips: Arc<DashSet<Ipv4Addr>>,
    whitelist_domains: Arc<DashSet<String>>,
    whitelist_ips: Arc<DashSet<Ipv4Addr>>,
    auto_detected: Arc<DashSet<String>>,
    mode: SplitMode,
    /// Шардированный счетчик — минимизируем contention
    stats: Arc<SplitTunnelStats>,
}

impl SplitTunnel {
    /// Проверка: нужно ли обходить этот IP?
    #[inline(always)]
    pub fn should_bypass_ip(&self, dst_ip: &Ipv4Addr) -> bool {
        match self.mode {
            SplitMode::WhitelistOnly => self.whitelist_ips.contains(dst_ip),
            SplitMode::BlacklistOnly => !self.blacklist_ips.contains(dst_ip),
            SplitMode::Auto => !self.auto_detected.contains(/* ip→domain map */),
        }
    }

    /// Быстрая проверка с thread-local cache (FIX-1: устраняет 5 DashMap lookups/packet).
    pub fn should_bypass_ip_fast(&self, dst_ip: &Ipv4Addr) -> bool {
        // thread_local! RefCell<Vec<(u32, bool)>> cache (1024 entries)
        // Cache hit → return cached value
        // Cache miss → DashMap lookup → cache result
    }

    /// Построение WinDivert фильтра (эффективное)
    pub fn build_win_divert_filter(&self) -> String {
        // Оптимизация: если blacklist пуст — простой фильтр
        // Если не пуст — добавляем исключения
        
        let base = "ip && (tcp.DstPort == 443 or tcp.SrcPort == 443 \
                     or udp.DstPort == 53 or udp.DstPort == 443)";
        
        match self.mode {
            SplitMode::BlacklistOnly if !self.blacklist_ips.is_empty() => {
                let exclusions: Vec<String> = self.blacklist_ips.iter()
                    .map(|ip| format!("ip.DstAddr != {}", ip))
                    .collect();
                format!("({}) && !({})", base, exclusions.join(" || "))
            }
            _ => base.to_string(),
        }
    }
}

/// Auto-режим: асинхронный prober
pub struct AutoProber {
    /// Probe-соединения через tokio::spawn
    pending: Arc<DashSet<String>>,
}

impl AutoProber {
    /// Проверить доступность сайта
    pub async fn probe(domain: &str, ip: Ipv4Addr) -> ProbeResult {
        // 1. TCP connect с таймаутом 3 сек
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect((ip, 443)),
        ).await;
        
        let Ok(Ok(mut stream)) = stream else {
            return ProbeResult::Blocked;
        };
        
        // 2. Отправляем минимальный ClientHello с SNI
        let ch = build_probe_client_hello(domain);
        let _ = stream.write(&ch).await;
        
        // 3. Ждём ответ 2 сек
        let mut buf = [0u8; 1024];
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            stream.read(&mut buf),
        ).await;
        
        match response {
            Ok(Ok(n)) if n > 0 && buf[0] == 0x16 => ProbeResult::Direct,
            _ => ProbeResult::Blocked,
        }
    }
}
```

### 3.4 Conntrack (DashMap)

```rust
use dashmap::DashMap;
use std::net::Ipv4Addr;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct ConnKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone)]
pub struct ConntrackEntry {
    pub client_isn: u32,
    pub server_isn: u32,
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_ack: u32,
    pub server_ack: u32,
    pub rtt_us: u64,
    pub state: ConnState,
    pub desync_applied: bool,
    pub strategy_id: u32,
    pub last_activity: Instant,
    pub dup_ack_count: u32,
    pub rng: Option<PerConnRng>,
}

pub struct Conntrack {
    map: DashMap<ConnKey, ConntrackEntry>,
    gc_interval: Duration,
}

impl Conntrack {
    /// Вставка через Entry API — один shard lock вместо двух (MR-04)
    pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
        use dashmap::mapref::entry::Entry;
        match self.inner.map.entry(key) {
            Entry::Vacant(e) => { e.insert(entry); /* increment counters */ }
            Entry::Occupied(mut e) => { e.get_mut().last_activity = Instant::now(); }
        }
    }

    /// Two-phase GC: collect stale keys, then remove (MR-03, без deadlock)
    pub fn gc_fast(&self, max_idle: Duration) {
        let to_remove: Vec<ConnKey> = self.map.iter()
            .filter(|r| now.duration_since(r.value().last_activity) > max_idle)
            .map(|r| *r.key())
            .collect();
        for key in to_remove { self.map.remove(&key); }
    }

    /// SEQ update — delta < 2^30, dup_ack_count reset (MR-16)
    pub fn update_seq_monotonic(&self, key: &ConnKey, seq: u32, ack: u32) {
        if let Some(mut entry) = self.map.get_mut(key) {
            let delta = seq.wrapping_sub(entry.client_seq);
            if delta == 0 {
                entry.dup_ack_count = entry.dup_ack_count.saturating_add(1);
            } else if delta < (1u32 << 30) {
                entry.client_seq = seq;
                entry.dup_ack_count = 0;
            }
            entry.last_activity = Instant::now();
        }
    }
}
```

### 3.5 Thread Pool Model

```rust
use rayon::ThreadPoolBuilder;
use tokio::runtime::Builder;

// Модель: 1 tokio runtime + 1 rayon pool
// tokio — для I/O (WinDivert recv, DNS, proxy)
// rayon — для CPU-bound (desync, TLS, frag, checksum)

pub struct Runtime {
    /// tokio runtime: async I/O
    pub io: tokio::runtime::Runtime,
    /// rayon pool: parallel packet processing
    pub cpu: rayon::ThreadPool,
}

impl Runtime {
    pub fn new() -> Self {
        let io = Builder::new_multi_thread()
            .worker_threads(num_cpus::get() / 2)  // половина ядер на I/O
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        
        let cpu = ThreadPoolBuilder::new()
            .num_threads(num_cpus::get().max(2))  // остальные на CPU
            .build()
            .unwrap();
        
        Self { io, cpu }
    }
}

// Использование:
// let rt = Runtime::new();
// rt.cpu.spawn(|| process_tcp_segment(packet));
// rt.io.spawn(async { resolve_dns(domain).await });
```

---

## 4. Полный список техник (~100 шт, ядро)

### 4.1 Техники, портированные из ByeDPI Android (45 активных)

| # | Техника | Rust модуль | Статус |
|---|---------|-------------|:------:|
| 1 | QUIC Blocking + ICMP | `desync::quic` | ✅ |
| 2 | QUIC Initial Injection | `desync::quic` | ✅ |
| 3 | Fake SNI Injection | `desync::tcp` | ✅ (raw socket enhanced) |
| 4 | OOB Injection | `desync::tcp` | ✅ |
| 5 | TCP Preopen | `desync::tcp` | ✅ |
| 7 | Post-Request Padding | `desync::tls` | ✅ |
| 8 | TCP Window Clamping | `desync::tcp` | ✅ (TUN→WinDivert) |
| 9 | TCP Timestamp Options | `desync::tcp` | ✅ |
| 10 | HTTP Header Tamper (7 режимов) | `desync::http` | ✅ |
| 10a | **HTTP Case Mixing** (Demergi) | `desync::http` | ✅ Host → hOsT |
| 11 | DNS Forwarding | `dns` | ✅ |
| 12 | DoH Bridge | `dns::doh` | ✅ (C-native, WinHTTP) |
| 12a | **DoH Retry + backoff** (Demergi) | `dns` | ✅ Exponential backoff + jitter |
| 12b | **Persistent HTTP/2 DoH** (Demergi) | `dns` | ✅ http2_prior_knowledge |
| 12c | **DNS IP Override** (Demergi) | `dns` | ✅ CIDR-based override |
| 12d | **Certificate Pinning** (Demergi) | `dns` | ✅ SPKI hash pinning |
| 14 | Strategy Switcher | `config` | ✅ |
| 15 | TLS Record Fragmentation (5 стратегий) | `desync::tls` | ✅ |
| 15a | **TLS Record Re-wrapping** (GreenTunnel) | `desync::tls` | ✅ Каждый фрагмент получает валидный record header |
| 15b | **TLS Version Spoof** (Demergi) | `desync::tls` | ✅ Record-layer version → TLS 1.3 |
| 15c | **SNI-Targeted Record Frag** (NoDPI) | `desync::tls` | ✅ SNI на 2B chunks с TLS 1.3 headers |
| 18 | Bye-dpi SOCKS5 Core | `proxy` | ✅ (FFI→Rust) |
| 19 | AutoTTL | `desync::ip` | ✅ (enhanced, real recv_ttl) |
| 20 | TLS Fingerprint Parroting | `desync::tls` | ✅ |
| 21 | TCP Chunk Obfuscation | `desync::tcp` | ✅ |
| 22 | Socket Pool | `packet_engine` | ✅ (raw socket pool) |
| 23 | MTU Enforcement | `packet_engine` | ✅ |
| 25 | DNS Cache | `dns::cache` | ✅ (Rust-native, moka LRU) |
| 27 | Micro-TCP TX | `packet_engine` | ✅ (raw socket TX) |
| 28 | Timed Injector | `desync` (tokio timer) | ✅ |
| 29 | Enhanced Conntrack | `conntrack` | ✅ (DashMap) |
| 30 | Jitter Injector (Pareto) | `desync` | ✅ |
| 31 | HPACK-Aware Frame | `desync::http` | ✅ |
| 32 | ECH Fallback Emulation | `desync::tls` | ✅ |
| 35 | External SOCKS5 Fallback | `proxy::fallback` | ✅ |
| 36 | Async SOCKS5 Handshake | `proxy::fallback` | ✅ (tokio) |
| 37 | Free Proxy Pool | `proxy::free_pool` | ✅ |
| 38 | Free Proxy Crawler | `proxy::crawler` | ✅ (reqwest→WinHTTP) |
| 39 | CDN Bypassing | `dns` | ✅ |
| 40 | Hop Cache & Dynamic TTL | `desync::ip` | ✅ |
| 41 | HPACK Table Header Bombing | `desync::http` | ✅ |
| 42 | Payload/SNI Fingerprint Rotator | `desync::tls` | ✅ |
| 43 | QUIC Short Header Poisoning | `desync::quic` | ✅ |
| 44 | QUIC Padding Flood | `desync::quic` | ✅ |
| 45 | UDP Coalescing Pad | `desync::quic` | ✅ |
| 46 | Doppelganger GREASE | `desync::quic` | ✅ |
| 47 | Adversarial Pre-Padding | `desync::tcp` | ✅ |

### 4.2 Исправленные техники (были сломаны на Android)

| # | Техника | Android | Windows (Rust) | Механизм |
|---|---------|:-------:|:--------------:|----------|
| 6 | **SEQ Overlap** (packet-level) | ❌ | ✅ | Raw socket, custom SEQ/ACK |
| 16 | **Data Duplication** | ❌ (broken) | ✅ | Raw socket SEQ overlap |
| 17 | **Hostfakesplit** (packet-level) | ❌ (broken) | ✅ | Raw socket, отдельные сегменты |
| 8 | **IP Fragmentation Overlap** | ❌ | ✅ | Raw socket IP_HDRINCL |
| 9 | **RST Injection (outbound)** | ❌ | ✅ | Raw socket RST+ACK |

### 4.3 Новые техники из zapret2 (15 шт)

| # | Техника | Rust модуль | Описание | Источник |
|---|---------|-------------|----------|:--------:|
| Z1 | **multisplit** | `desync::tcp` | Разделить на N сегментов в заданных позициях | zapret-antidpi.lua |
| Z2 | **multidisorder** | `desync::tcp` | Разделить + отправить в обратном порядке | zapret-antidpi.lua |
| Z3 | **fakedsplit** | `desync::tcp` | Разделить + interleave поддельных сегментов | zapret-antidpi.lua |
| Z4 | **fakeddisorder** | `desync::tcp` | Разделить + обратный порядок + подделки | zapret-antidpi.lua |
| Z5 | **tcpseg** | `desync::tcp` | Replay выбранного диапазона данных | zapret-antidpi.lua |
| Z6 | **syndata** | `desync::tcp` | SYN с payload (fake CH внутри SYN) | zapret-antidpi.lua |
| Z7 | **synack_split** | `desync::tcp` | Разделить SYN+ACK на отдельные SYN и ACK | zapret-antidpi.lua |
| Z8 | **wsize/wssize** | `desync::tcp` | Window size манипуляция (SYN-ACK + data) | zapret-antidpi.lua |
| Z9 | **dht_dn** | `desync::ip` | BitTorrent DHT фальсификация | zapret-antidpi.lua |
| Z10 | **synhide** | `desync::tcp` | Спрятать SYN в существующем соединении | zapret-obfs.lua |
| Z11 | **wgobfs** | `desync::obfs` | WireGuard AES-GCM обфускация | zapret-obfs.lua |
| Z12 | **ippxor** | `desync::obfs` | IP протокол XOR обфускация | zapret-obfs.lua |
| Z13 | **udp2icmp** | `desync::obfs` | Конвертация UDP → ICMP и обратно | zapret-obfs.lua |
| Z14 | **badsum** | `desync::ip` | Намеренно неправильная контрольная сумма | darkmagic.c |
| Z15 | **IP frag primitives** | `desync::ip` | ipfrag, ipfrag_disorder, ipfrag_pos_tcp/udp/icmp | darkmagic.c |

### 4.4 Windows-эксклюзивные техники (10 шт)

| # | Техника | Rust модуль | Описание |
|---|---------|-------------|----------|
| W1 | **IP Fragmentation Overlap** | `desync::ip` | Два фрагмента: fake SNI (offset=0) + real SNI (offset=N) |
| W2 | **MSS Clamping** | `desync::tcp` | Установка MSS=536 в SYN для принудительной фрагментации |
| W3 | **ACK Suppression** | `desync::tcp` | Задержка ACK → DPI не видит established |
| W4 | **Packet Reordering** | `desync::tcp` | Буферизация и реордеринг TCP-сегментов |
| W5 | **Selective RST outbound** | `desync::tcp` | RST между SYN-ACK и ClientHello для DPI |
| W6 | **SYN Flood Decoy** | `desync::tcp` | 5-10 SYN с fake SNI для переполнения conntrack DPI |
| W7 | **Window Scale Manipulation** | `desync::tcp` | Window Scale=0 + Window=1024 → мелкие сегменты |
| W8 | **IPv6 Ext Headers** | `desync::ip` | Вставка Hop-by-Hop/Dest опций в IPv6 |
| W9 | **TCP Fast Open Abuse** | `desync::tcp` | TFO cookie + fake data в SYN |
| W10 | **Adaptive DPI Detection** | `adaptive` | Анализ ответов DPI → авто-выбор стратегии |

### 4.5 Split Tunneling техники (3 шт)

| # | Техника | Rust модуль | Описание |
|---|---------|-------------|----------|
| S1 | **Blacklist mode** | `split_tunnel` | Только blacklist-сайты через обход |
| S2 | **Whitelist mode** | `split_tunnel` | Все, кроме whitelist, через обход |
| S3 | **Auto mode** | `split_tunnel` | Авто-детекция: probe → classify |
| S3a | **Auto-detect persistence** (NoDPI) | `split_tunnel` | ✅ Whitelist кэш + blocked_domains.txt |

---

### 4.6 Новые техники из исследованных Rust DPI-проектов (11 проектов, ~50 техник)

#### 4.6.1 sni-spoofing-rust (4 техники)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| SR1 | **SEQ Number Spoofing** | `desync::tcp::seq_spoof` | Отправка fake ClientHello с SEQ вне окна приёма DPI. Реальный CH идёт следом с корректным SEQ | 🔴 **P0** |
| SR2 | **TLS 1.2 ClientHello Generator** | `desync::tls::ch_gen` | Генерация TLS ClientHello из struct (без дампа): cipher suites, extensions, SNI | 🔴 P0 |
| SR3 | **RawBackend Trait** | `desync::tcp::raw_backend` | Стратегия-интерфейс для отправки: WinDivert / RawSocket / TCP connect | 🟡 P1 |
| SR4 | **Sniffer → Register Flow** | `desync::tcp::sniffer` | Перехват первого SYN, регистрация в conntrack, применение стратегии | 🟡 P2 |

#### 4.6.2 RIPDPI (15 техник)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| RP1 | **DesyncGroup** | `desync::group` | Конкурентное применение нескольких desync-операций к одному пакету | 🔴 P1 |
| RP2 | **Plan+Execute Architecture** | `desync::planner` | Разделение: plan (генерация последовательности операций) + execute (применение) | 🔴 P1 |
| RP3 | **Disorder (TTL-based)** | `desync::tcp::disorder` | Отправка сегментов в обратном порядке с подходящим TTL | 🔴 P3 |
| RP4 | **MultiDisorder** | `desync::tcp::multidisorder` | Множественные disorder-сегменты в одном потоке | 🔴 P3 |
| RP5 | **OOB/DisOOB** | `desync::tcp::disoob` | Out-of-band данные + disorder | 🔴 P3 |
| RP6 | **HostFake** | `desync::tcp::hostfake` | Fake SNI с подменой имени хоста | 🔴 P3 |
| RP7 | **FakeRst** | `desync::tcp::fakerst` | Отправка фейкового RST для сброса состояния DPI | 🔴 P4 |
| RP8 | **Popcount/Shannon Entropy Padding** | `desync::obfs::entropy` | Padding с контролем энтропии через Popcount/Shannon | 🔴 P5 |
| RP9 | **Adaptive Offset Planning** | `desync::planner::offset` | Авто-выбор позиций split на основе размера ClientHello | 🔴 P1 |
| RP10 | **Fallback Chain** | `adaptive::fallback` | Стратегия → запасная → запасная второго уровня | 🔴 P5.5 |
| RP11 | **Activation Filters** | `desync::filter` | Пропуск стратегий, заведомо неприменимых к пакету | 🟡 P2 |
| RP12 | **TLS Record Choreography** | `desync::tls::choreo` | Контроль последовательности TLS-записей (1/2/3/5 RTT паттерны) | 🟡 P5 |
| RP13 | **TCP TSval/Echo MD5** | `desync::tcp::ts_md5` | Манипуляция TCP Timestamp опциями | 🟡 P5 |
| RP14 | **TCP Window Clamp + Drop SACK** | `desync::tcp::wclamp` | Принудительное уменьшение window + запрет SACK | 🟡 P4 |
| RP15 | **Lua Strategy Scripts** | `adaptive::lua` | Пользовательские Lua-скрипты для стратегий | 🟡 P8 |

#### 4.6.3 autodpi (4 техники)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| AD1 | **Probe/Tune/Run Three-Phase** | `adaptive::probe_tune_run` | 3 фазы: Probe (все стратегии) → Tune (лучшие) → Run (победитель) | 🔴 P1 |
| AD2 | **Strategy Trait + Registry** | `adaptive::registry` | Trait-based стратегия: `trait Strategy { fn apply() }` + реестр по ID | 🔴 P0 |
| AD3 | **Auto-tune Parameters** | `adaptive::auto_tune` | Подключён к pipeline (MR-37): `record()` + `recommend()` через `ConfigOverride` → перезапись `split_size`, `split_count`, `fake_ttl_offset`. Thompson sampling — будущий MR. | 🔴 P1 ✅ |
| AD4 | **Strategy Persistence** | `adaptive::persist` | Сохранение лучших стратегий на диск (per-domain) | 🟡 P1 |

#### 4.6.4 dpibreak (2 техники)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| DP1 | **HopTab (auto-TTL cache)** | `adaptive::hop_tab` | Direct-mapped hash table (4096 entries), O(1) lookup. Auto-TTL черезHop Limit/IP TTL. | 🔴 **P0** |
| DP2 | **Fake CH with badsum + auto-TTL** | `desync::tcp::fake_ch_badsum` | Fake ClientHello с заведомо неправильной TCP checksum + auto-TTL из HopTab | 🔴 P1 |

#### 4.6.5 CandyTunnel (9 техник)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| CT1 | **Mutual IP Spoofing** | `desync::ip::mutual_spoof` | Двусторонняя подмена source/dest IP между клиентом и сервером | 🟡 P5 |
| CT2 | **ChaCha20 Per-Packet Obfuscation** | `desync::crypto::chacha20` | ChaCha20 шифрование каждого пакета (chacha20 crate, 0-allocation hot path) | 🔴 P3 |
| CT3 | **TTL Jitter** | `desync::ip::ttl_jitter` | Случайный TTL (TTL ± random(3)) для каждого пакета | 🟡 P3 |
| CT4 | **Per-Connection DSCP** | `conntrack` + `desync::ip::dscp` | DSCP постоянный per-connection (MR-G5): сохраняется в `ConntrackEntry.dscp_spoof`, передаётся через `ConfigOverride` в `DesyncGroup::apply()`. Случайный per-packet — аномалия для ML-DPI. | 🟡 P4 ✅ |
| CT5 | **Packet Size Padding** | `desync::obfs::pad_size` | Дополнение пакета до ближайшего кратного размера (128/256/512/1024) | 🟡 P4 |
| CT6 | **XOR FEC (Forward Error Correction)** | `desync::obfs::xorfec` | XOR-восстановление потерянных пакетов (k из n) | 🟡 P7 |
| CT7 | **Multiplexing** | `proxy::mux` | Несколько логических потоков поверх одного TCP-соединения | 🟡 P7 |
| CT8 | **Port Shuffle** | `desync::tcp::port_shuffle` | Случайная ротация source port в процессе обхода | 🟡 P4 |
| CT9 | **IPIP Tunnel Transport** | `desync::ip::ipip` | Инкапсуляция IP-пакетов в IPIP/GRE туннель (для VPN-like обхода) | 🟡 P7 |

#### 4.6.6 DPIReaper (6 техник)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| DR1 | **Sentinel File System** | `infra::sentinel` | File-based autostop: при появлении/исчезновении файла -> остановка engine. Защита от зависания | 🔴 **P0** |
| DR2 | **Task Scheduler Autostart** | `infra::autostart` | Интеграция с Windows Task Scheduler для автозапуска при старте системы | 🟡 P9 |
| DR3 | **UWP LoopbackExempt** | `infra::uwp_loopback` | `CheckNetIsolation.exe LoopbackExempt -a -n=...` для UWP-приложений | 🟡 P9 |
| DR4 | **Windows Firewall Rules** | `infra::firewall` | Авто-создание правил Windows Firewall для byedpi | 🟡 P9 |
| DR5 | **WinHTTP Proxy Config** | `infra::winhttp_proxy` | Настройка системного WinHTTP прокси для прозрачного обхода | 🟡 P9 |
| DR6 | **PAC Server** | `infra::pac` | Встроенный HTTP-сервер для Proxy Auto-Config (localhost:11338/proxy.pac) | 🟡 P9 |

#### 4.6.7 qeli (3 техники)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| QL1 | **Poisson Traffic Shaping** | `desync::obfs::poisson` | Интервалы между пакетами распределены по Пуассону (λ = 20ms, clamp 1-100ms) | 🟡 P5 |
| QL2 | **Supervisor/Worker Architecture** | `infra::supervisor` | Процесс-супервизор управляет worker-ами, перезапуск при падении | 🟡 P9 |
| QL3 | **Multiqueue Processing** | `packet_engine::multiqueue` | Разделение потоков пакетов по очередям для минимизации блокировок | 🟡 P6 |

#### 4.6.8 dpimyass (1 техника)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| DM1 | **XOR First N Bytes** | `desync::obfs::xor_first` | XOR-обфускация только первых N байт пакета (настраиваемое N) | 🟡 P4 |

#### 4.6.9 OpenLogi (3 техники, 1 удалена MR-18)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| OL1 | **Thread-Local Hot Path** | `packet_engine::tls_hotpath` | thread_local! для WinDivert callback-статистики (keepalive, counters) без блокировок | 🔴 P0 |
| OL2 | **Synthetic Event Tagging** | ~~`infra::event_tag`~~ | **УДАЛЁН (MR-18).** WinDivert `set_impostor(true)` + IP ID tagging достаточны. UUID в TCP payload — fingerprint. | 🔴 **P0** ✅ |
| OL3 | **interprocess + tarpc IPC** | `infra::ipc` | RPC-канал между service (NETWORK SERVICE) и UI (user) через interprocess crate | 🟡 P9 |

#### 4.6.10 rust-no-dpi-socks (2 техники)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| RN1 | **Byte-by-Byte First Packet** | `desync::tcp::byte_by_byte` | Отправка первого TCP-сегмента по 1 байту с задержкой между каждым | 🟡 P4 |
| RN2 | **Unidirectional Fragmentation** | `desync::tcp::unidir_frag` | Фрагментация только на одной стороне (клиент→сервер, без сервер→клиент) | 🟡 P5 |

#### 4.6.11 rust-DPI-http-proxy (2 техники)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| RH1 | **Host-Space HTTP Header** | `desync::http::host_space` | Добавление пробела после `Host:` (Host: example.com) | 🟡 P5 |
| RH2 | **Title-Case HTTP Headers** | `desync::http::title_case` | Преобразование заголовков в Title-Case (Host → Host) | 🟡 P5 |

---

**Итого: ~100 техник ядра + ~60 из 11 Rust-проектов + 10 новых (PLAN2) = ~170 уникальных техник**
(45 Android + 5 исправленных + 15 zapret2 + 10 Windows-эксклюзивных + 3 split tunnel + 10 PLAN2 — 6 Android-only + ~60 новых)

---

## 5. Потребление памяти

### Детальный расчёт

| Компонент | Тип | Размер | Кол-во | Всего |
|-----------|-----|:------:|:------:|:-----:|
| Conntrack entry | `struct` | ~120 байт | 10,000 | 1.2 MB |
| Conntrack map overhead | DashMap | ~64 байт/entry | 10,000 | 640 KB |
| DNS cache entry | `struct` + String | ~256 байт | 1,000 | 256 KB |
| Hop cache entry | `struct` | ~32 байта | 256 | 8 KB |
| Blacklist IPs | `Ipv4Addr` | 4 байта | 10,000 | 40 KB |
| Blacklist domains | `(String, Ipv4Addr)` | ~64 байта | 1,000 | 64 KB |
| Packet buffers pool | `Vec<u8>` | 1500 байт | 128 | 192 KB |
| WinDivert buffers | internal | ~256 KB | 1 | 256 KB |
| Tokio runtime | tasks, I/O | ~1 MB | — | 1 MB |
| Rayon thread stack | 8 KB × N | 8 KB | 16 | 128 KB |
| C FFI bye-dpi (временный) | static lib | ~512 KB | — | 512 KB |
| **Итого под нагрузкой** | | | | **~4.3 MB** |
| **Итого idle** | | | | **~2 MB** |

### Стратегии минимизации

1. **Pre-allocated conntrack pool**: `Vec::with_capacity(10_000)` — без reallocation
2. **TinyVec** для small DNS responses: `tinyvec` crate
3. **bytes::Bytes** вместо Vec: shared reference counting для пакетов
4. **No clone on hot path**: всё через ссылки + Arc
5. **Arena allocator** для ConntrackEntry: `typed-arena` crate (zero-frag)

```rust
// Pre-allocated arena для conntrack
use typed_arena::Arena;

pub struct Conntrack {
    arena: Arena<ConntrackEntry>,  // contiguous memory, zero fragmentation
    map: DashMap<ConnKey, &'a ConntrackEntry>,
}

impl Conntrack {
    pub fn insert(&self, key: ConnKey, entry: ConntrackEntry) {
        let ptr = self.arena.alloc(entry);  // O(1), no alloc after pre-fill
        self.map.insert(key, ptr);
    }
}
```

---

## 6. Многопроцессорность (Multi-core)

### 6.1 Модель потоков

```
┌─────────────────────────────────────────────────────────┐
│  Thread                   CPU    Role                    │
├─────────────────────────────────────────────────────────┤
│  main ()                  0      Startup, config         │
│  WinDivert recv ()        0      Driver recv loop        │
│  tokio-worker-0           0      I/O: DNS, proxy         │
│  tokio-worker-1           1      I/O: WinDivert send     │
│  rayon-worker-0           0      CPU: TCP desync         │
│  rayon-worker-1           1      CPU: TCP desync         │
│  rayon-worker-2           2      CPU: TLS parroting      │
│  rayon-worker-3           3      CPU: IP fragmentation   │
│  GC timer thread          —      Conntrack cleanup       │
│  UI thread (tray)         —      System tray events      │
└─────────────────────────────────────────────────────────┘
```

### 6.2 Почему Rust оптимален

```rust
// Пример: параллельная обработка 1000 пакетов
use rayon::prelude::*;

let packets: Vec<Packet> = recv_batch().await;

// Автоматическое распределение по всем ядрам
// Work-stealing: занятые ядра берут задачи у свободных
packets.par_iter().for_each(|pkt| {
    let desync = DesyncEngine::new();
    let result = desync.process(pkt);
    tx.send(result);  // mpsc канал в output thread
});
```

### 6.3 Lock-free data structures

| Структура | Механизм | Contention | Примечание |
|-----------|----------|:----------:|------------|
| Conntrack | DashMap (64 shards) + Entry API | Низкий | upsert через Entry API — один shard lock. Two-phase GC (collect+remove) без deadlock. |
| Blacklist | DashSet (64 shards) | Низкий | |
| DNS Cache | moka (concurrent LRU) | Очень низкий | |
| Packet ring | crossbeam ArrayQueue (64K slots) | Нулевой | Lock-free MPMC ring с head-drop. Заменяет mpsc::channel. |
| Stats counters | AtomicU64 | Нулевой | |
| Packet buffers | per-call `vec![0u8; total_len]` (1 alloc/call) | Нулевой | Thread-local pool был удалён (MR-10*: Bytes::from(vec) потребляет Vec). |
| SplitTunnel cache | thread-local Vec<(u32, bool)> | Нулевой | `should_bypass_ip_fast()` — O(1) lookup. |
| Inject tracking | Arc\<DashMap\<SeqKey, Instant\>\> | Низкий | DashMap вместо Mutex\<InjectedSeqTracker\> (MR-07). 5-tuple+SEQ ключ, TTL 30s. |
| PerConnRng | Xorshift128** + periodic reseed | Нулевой | getrandom seed, reseed каждые 8192 вызова. |
| HopTab | Direct-mapped hash (4096 entries) | Нулевой | O(1) lookup вместо O(256) linear scan. |
| PRNG seed | getrandom (OS CSPRNG) | Нулевой | Вместо SystemTime::now(). |

---

## 7. WinDivert ↔ Raw Socket разделение труда

> **Важно:** Raw TCP sockets НЕ работают на Windows с XP SP2+.
> Ядро молча дропает TCP через `WSASocket(SOCK_RAW, IPPROTO_RAW)`.
> Raw sockets работают ТОЛЬКО для UDP и ICMP.

| Задача | Механизм | Почему |
|--------|----------|--------|
| Перехват пакетов | WinDivert | Точка входа |
| Модификация проходящих | WinDivert modify + reinject | Нативный |
| Дроп пакетов | WinDivert (не reinject) | Минимальная задержка |
| **TCP inject** (Fake SNI, SEQ Spoof, RST) | **WinDivert send()** | Raw socket НЕ работает для TCP |
| **UDP inject** (QUIC, DNS) | Raw socket (IPPROTO_RAW) | Raw socket работает для UDP |
| IP Fragmentation (TCP) | WinDivert reinject с фрагментами | Raw socket заблокирован для TCP |
| IP Fragmentation (UDP) | Raw socket (IP_HDRINCL) | Полный контроль IP header |
| Loop prevention | WinDivert impostor flag + IP ID tagging (MR-18: event_tag удалён) | TCP inject через WinDivert send() с impostor flag; UDP/raw не проходит через WinDivert filter |

### PacketEngine API

```rust
// TCP injection — через WinDivert (reinject)
engine.inject_via_divert(packet, &addr)?;  // Tagged + WinDivert send

// UDP injection — через raw socket
engine.inject_raw_udp(packet)?;            // Raw socket sendto
```

---

## 8. Windows-specific ограничения

### 8.1 WinDivert Driver Management

**Стратегия (из sing-box/offveil):** Bundled driver + SCM install + auto-cleanup.

```
┌─────────────────────────────────────────────────┐
│ PacketEngine::new(filter)                       │
│                                                  │
│  1. is_driver_loaded()? → sc query WinDivert    │
│     ├── YES → пропускаем установку              │
│     └── NO  → install_driver()                  │
│         ├── bundled_driver_path()                │
│         │   (vendor/windivert/WinDivert64.sys)  │
│         ├── SCM: CreateServiceW → StartServiceW  │
│         ├── Anti-race mutex                      │
│         └── DeleteService (auto-cleanup)         │
│                                                  │
│  2. WinDivert::network(filter) → HANDLE         │
│     ├── OK → WinDivert mode                     │
│     └── ERR → detect error code:                │
│         ├── 577 (ERROR_INVALID_IMAGE_HASH)       │
│         │   → HVCI/Secure Boot block             │
│         ├── 5 (ERROR_ACCESS_DENIED)              │
│         │   → Need admin rights                  │
│         └── 1275 (ERROR_DELAY_LOAD_FAILED)       │
│             → EDR/antivirus block                │
└─────────────────────────────────────────────────┘
```

**Bundled files:**
```
vendor/windivert/
├── WinDivert64.sys    # Kernel-mode driver (~40KB)
├── WinDivert.dll      # User-mode library (~100KB)
└── WinDivert.lib      # Static library for linking
```

**Error handling:**

| Error Code | Причина | Решение для пользователя |
|:----------:|---------|--------------------------|
| 577 | HVCI/Secure Boot | Отключить Core Isolation в Windows Security |
| 5 | Нет admin rights | Запустить от имени Администратора |
| 1275 | EDR/Antivirus block | Добавить WinDivert в исключения безопасности |
| 1056 | Driver уже запущен | OK — продолжаем |

**Driver signing:** Наш bundled WinDivert подписан оригинальным сертификатом автора (WinDivert by Basil). Для production нужен EV Code Signing (~$300-400/год).

### 8.2 Raw TCP Sockets — ЗАБЛОКИРОВАНЫ на Windows

> **КРИТИЧНО:** Raw TCP sockets НЕ работают на Windows с XP SP2+.
> Ядро молча дропает TCP через `WSASocket(SOCK_RAW, IPPROTO_RAW)`.

| Протокол | Raw Socket | Метод инъекции |
|----------|:----------:|----------------|
| **TCP** | ❌ Заблокирован | WinDivert send() (reinject) |
| **UDP** | ✅ Работает | Raw socket sendto() |
| **ICMP** | ✅ Работает | Raw socket sendto() |

**См. раздел 7** для деталей.

### 8.3 TSO/LSO (TCP Segmentation Offload)

NIC с включённым TSO/LSO может "починить" фрагментированные пакеты:
- Перезаписать контрольные суммы
- Собрать фрагменты до отправки в кабель

**Решение:** `PacketEngine::disable_offload()` отключает TCP Chimney, RSS, ECN через `netsh` при старте.

### 8.4 UAC (User Account Control)

Raw sockets и WinDivert требуют прав Администратора.

**Архитектура Service + UI:**
```
┌─────────────────────────────────┐
│ FreeDPI-service.exe (SYSTEM)  │
│ ├── WinDivert recv/send         │
│ ├── Raw socket inject           │
│ ├── HTTP API (localhost:11337)  │
│ └── Named Pipe IPC              │
└───────────┬─────────────────────┘
            │ \\.\pipe\FreeDPI_agent
┌───────────▼─────────────────────┐
│ FreeDPI-ui.exe (User)         │
│ ├── System tray                 │
│ ├── GUI (Tauri v2 + React)      │
│ └── AI Agent API                │
└─────────────────────────────────┘
```

---

## 9. DNS Engine (Rust-native)

```rust
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

pub struct DnsEngine {
    // DoH через reqwest (winhttp backend)
    doh_client: reqwest::Client,
    // DoT через trust-dns
    dot_resolver: Resolver,
    // Fast concurrent cache
    cache: moka::future::Cache<String, DnsResult>,
}

impl DnsEngine {
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        // 1. Cache check (moka: concurrent, TTL-based)
        if let Some(cached) = self.cache.get(domain).await {
            return Some(cached.ip);
        }
        
        // 2. Parallel DoH + DoT (кто первый)
        let doh = self.resolve_doh(domain);
        let dot = self.resolve_dot(domain);
        
        match tokio::select! {
            result = doh => result,
            result = dot => result,
        } {
            Some(ip) => {
                self.cache.insert(domain.to_string(), DnsResult { 
                    ip, ttl: 300 
                }).await;
                Some(ip)
            }
            None => None,
        }
    }
}
```

---

## 9. Технический стек (Rust)

| Слой | Крейт | Версия | Назначение |
|------|-------|:------:|-----------|
| Runtime | `tokio` | 1.40 | Async I/O, timers |
| Parallel CPU | `rayon` | 1.10 | Work-stealing thread pool |
| Packet ring | `crossbeam` | 0.8 | Lock-free ArrayQueue для packet ring |
| Packet interception | `windivert` | 0.5 | WinDivert binding |
| WinAPI | `windows` | 0.58 | Raw sockets, system tray |
| Concurrent maps | `dashmap` | 6.0 | Conntrack, blacklist |
| CSPRNG | `getrandom` | 0.2 | OS CSPRNG для PRNG seed + reseed |
| DNS | `trust-dns` | 0.24 | DoH/DoT client |
| HTTP | `reqwest` | 0.12 | DoH, proxy crawler |
| Packet parsing | `pnet` | 0.35 | IP/TCP/UDP parses |
| Serialization | `serde` + `serde_json` | 1.0 | Config |
| CLI | `clap` | 4.5 | CLI arguments |
| Logging | `tracing` | 0.1 | Structured logging |
| Cache | `moka` | 0.12 | Concurrent DNS cache |
| Bytes | `bytes` | 1.6 | Zero-copy packet buffers |
| Config | `toml` | 0.8 | Config file format |
| TinyVec | `tinyvec` | 1 | Small vector optimization |
| UUID | `uuid` | 1.0 | Config file UUID generation (`config.rs:81`); event_tag удалён (MR-18) |
| ArcSwap | `arc-swap` | 1 | Lock-free atomic swap для WinDivert handle (MR-P2) |

---

## 10. Фазы реализации (обновлено)

| Фаза | Содержание | Техник | Срок |
|------|-----------|:------:|:----:|
| **P0** | Rust workspace + WinDivert binding + tokio reactor + raw socket FFI | 0 | 2 нед |
| **P1** | **Split tunneling** (blacklist/whitelist/auto) + DNS engine (DoH/DoT/cache) | 8 | 2 нед |
| **P2** | Bye-dpi FFI bridge (C→Rust) + desync core + conntrack | 20 | 3 нед |
| **P3** | TCP desync: multisplit, multidisorder, fakedsplit, hostfakesplit, chunk, TLS frag | 15 | 2 нед |
| **P4** | Fake инъекции: syndata, fake SNI, OOB, RST, synhide, preopen | 10 | 2 нед |
| **P5** | **Windows-эксклюзив**: IP frag overlap, MSS clamp, ACK suppress, reorder, RST selective, SYN flood, Window Scale, IPv6 ext | 10 | 3 нед |
| **P6** | QUIC Engine + UDP обфускация (udp2icmp, ippxor, wgobfs) + badsum | 12 | 2 нед |
| **P7** | Proxy Fallback + Free proxy pool + HPACK bomber + Fingerprint rotator | 8 | 2 нед |
| **P8** | Rust-миграция bye-dpi (удаление FFI) + Adaptive DPI | 10 | 2 нед |
| **P9** | System tray + Windows Service + installer + testing | — | 2 нед |
| | **Итого 82 техники (ядро)** | **82** | **~22 нед** |

---

## 11. Ключевые риски (обновлено)

| Риск | Вероятность | Влияние | Митигация |
|------|:----------:|:-------:|-----------|
| `windivert` crate не поддерживает Windows 11 | Low | High | Fallback на `windivert-sys` + raw FFI |
| Raw socket TX требует admin | Certain | Medium | UAC + Windows Service от SYSTEM |
| Windows Defender блокирует | High | High | Code signing + VirusTotal |
| Anti-virus false positive на raw socket | High | Medium | EV signing, документация |
| Rust FFI overhead на hot path | Low | Medium | Batch FFI calls (минимизируем crossings) |
| WinDivert latency > 50µs | Low | Medium | Rayon parallel processing |
| Conntrack memory fragmentation | Low | Low | typed-arena pre-alloc |
| Split tunnel auto-detect false positive | Medium | Low | Manual override, learning |
| Geo-routing может ошибаться (RU→EU) | Medium | Low | 3-уровневый fallback + пользовательские списки |
| Opera VPN прокси могут умереть | High | Low | Bad route cache + auto-fallback + обновление списка |

---

## 12. Исследованные проекты: +24 новые техники

После анализа ByeDPI Android, zapret2 и Nova были дополнительно исследованы 5 проектов.
Итого добавлено **~34 новые техники/концепции**, доводя общий счёт до **~116**.

### 12.1 FakeSIP — протокольная маскировка UDP (3 техники)

[Исходный код](research/FakeSIP) — C, протокольная маскировка трафика под SIP/VoIP.

| # | Техника | Описание | Приоритет |
|---|---------|----------|:---------:|
| FS1 | **SIP Protocol Masking** | UDP трафик маскируется под SIP INVITE (SIP-заголовок + SDP body) | ⭐ Опционально |
| FS2 | **Custom Payload Injection** | `-b file` — загрузка своего дампа пакета для инъекции | ⭐ Опционально |
| FS3 | **UDP Payload Randomization** | Рандомизация байтов внутри легитимного протокола | ⭐⭐ |

**Принцип:** Вместо модификации TLS (как все DPI-bypass инструменты), FakeSIP **маскирует трафик под легитимный протокол**. DPI видит SIP INVITE и пропускает.

### 12.2 sing-box — универсальная прокси-платформа (8 техник)

[Исходный код](research/sing-box) — Go. В первую очередь прокси, но содержит ценные техники обхода.

| # | Техника | Описание | Приоритет |
|---|---------|----------|:---------:|
| SB1 | **TLS Spoof (fake CH)** | Инжекция фейкового ClientHello с **белым SNI** (разрешённым сайтом). DPI думает, что соединение легитимно. Реальный CH идёт следом | 🔴 **Критично** |
| SB2 | **TLS Record Fragment** | Разделение TLS-записей (не TCP-сегментов, а TLS Record Layer) | 🔴 Важно |
| SB3 | **BadTLS (raw TLS control)** | Прямой контроль над TLS record состоянием (чтение/запись записей) | 🟡 Средний |
| SB4 | **Reality (XTLS masking)** | Маскировка прокси-трафика под реальный TLS-сервер (например, `google.com`) | 🟡 Серверная часть |
| SB5 | **Randomized uTLS fingerprints** | Случайный отпечаток браузера (Chrome/Firefox/Safari) на каждое соединение | 🔴 Важно |
| SB6 | **ShadowTLS / AnyTLS** | Протоколы-маскировщики, где трафик выглядит как обычный TLS | 🟡 Опционально |
| SB7 | **FakeIP DNS** | Виртуальные IP для доменов → маршрутизация по доменным именам внутри TUN | 🔴 Важно |
| SB8 | **Rule Sets** | Обновляемые наборы правил маршрутизации (geoip, geosite) | 🟡 Средний |

### 12.3 NaiveProxy — идеальный TLS fingerprint (7 техник)

[Исходный код](research/naiveproxy) — C++ (Chromium net stack). Использует **нативный TLS Chrome** без модификаций.

| # | Техника | Описание | Приоритет |
|---|---------|----------|:---------:|
| NP1 | **Chrome JA3/JA3S (полный стек)** | Идентичный Chrome TLS fingerprint через нативную настройку rustls/BoringSSL | 🔴 **Критично** |
| NP2 | **H2 SETTINGS как в Chrome** | `SETTINGS_INITIAL_WINDOW_SIZE = 64MB` (Chrome-специфичный параметр) | 🔴 Важно |
| NP3 | **RST_STREAM padding** | DATA + PADDED + FIN перед отправкой RST_STREAM | 🔴 Важно |
| NP4 | **HEADERS padding с HPACK non-indexed** | Случайный padding в CONNECT HEADERS, non-indexed HPACK entry | 🟡 Средний |
| NP5 | **Preamble (фейковый веб-сёрфинг)** | Поддельные HTTP запросы на реальные сайты перед CONNECT | 🟡 Опционально |
| NP6 | **Multi-session concurrency** | N параллельных H2/H3 туннелей для мультиплексирования | 🔴 Важно |
| NP7 | **Post-Quantum (X25519MLKEM768)** | Гибридный key agreement как в Chrome 149+ | 🟡 Будущее |

**Ключевое отличие:** NaiveProxy не модифицирует TLS — он предоставляет **нативный TLS стек Chromium** как прокси. Это даёт идеальный fingerprint, но требует Chromium. Наш подход: настройка `rustls`/`BoringSSL` под Chrome-профиль.

### 12.4 b4 — продвинутая фрагментация (14 техник)

[Исходный код](research/b4) — C. **Самый богатый источник новых техник** — 14 уникальных.

| # | Техника | Описание | Приоритет |
|---|---------|----------|:---------:|
| B1 | **Combo fragmentation** | Множественный split (1st byte + ext boundary + mid-SNI) + shuffling | 🔴 **Критично** |
| B2 | **ExtSplit** | Разрез точно на границе extension boundary перед SNI | 🔴 **Критично** |
| B3 | **SeqOverlap (sequence overlap)** | Сдвиг SEQ назад, prepend узора — DPI видит перекрытие сегментов | 🔴 **Критично** |
| B4 | **Fake overlapping segments** | Фейковые TCP-сегменты, перекрывающие реальный SEQ range | 🔴 Важно |
| B5 | **TLS mutation chain** | GREASE + duplicate SNI + extension reorder + fake ALPN + random padding | 🔴 **Критично** |
| B6 | **Fake QUIC Initial generation** | Сборка QUIC Initial с нуля (не из дампа, а программно) | 🔴 Важно |
| B7 | **Detect & Escalate** | Обнаружение DPI-блокировки → автоматическое переключение на агрессивную стратегию | 🔴 **Критично** |
| B8 | **RST protection** | Детекция DPI-инжектированных RST и их игнорирование / маскировка | 🔴 Важно |
| B9 | **Incoming manipulation** | Инъекция пакетов в сторону сервера (не только от клиента к DPI) | 🟡 Средний |
| B10 | **Window manipulation (4 режима)** | Oscillate, zero, random, escalate — манипуляция TCP Window | 🔴 Важно |
| B11 | **Post-desync** | RST burst сразу после отправки ClientHello | 🟡 Средний |
| B12 | **Decoy fragments** | Фейковые фрагменты, отправленные перед реальными | 🟡 Средний |
| B13 | **SYN MD5 option** | Инъекция SYN с TCP MD5 signature option (необычно для DPI) | 🟡 Эксперимент |
| B14 | **Hybrid strategy** | Runtime-выбор стратегии по форме ClientHello (на лету) | 🔴 Важно |

### 12.5 dae — архитектурные концепты (4 концепции)

[Исходный код](research/dae) — Go + eBPF. Linux-only, но концепции применимы на Windows.

| # | Концепция | Описание | Применимость |
|---|-----------|----------|:------------:|
| DA1 | **Succinct trie** для IP/domain matching | Крайне эффективный O(1) поиск по CIDR вместо линейных списков | ✅ `ipnetwork` + trie |
| DA2 | **Domain→IP bitmap через DNS** | Маппинг IP→домен через перехват DNS ответов в реальном времени | ✅ WinDivert DNS |
| DA3 | **Routing rule normalization** | Парсинг → AST → оптимизация → нормализация → исполнение | ✅ Архитектурно |
| DA4 | **First-packet routing cache** | Решение для первого пакета кэшируется на всё соединение | ✅ Conntrack |

### 12.6 Итоговый счёт техник (после 7 проектов)

| Источник | Было | Добавлено | Стало |
|----------|:----:|:---------:|:-----:|
| ByeDPI Android | 45 | — | 45 |
| zapret2 | — | 15 | 15 |
| Windows-эксклюзив | — | 10 | 10 |
| Nova | — | 9 | 9 |
| Split Tunneling | — | 3 | 3 |
| **FakeSIP** | — | **3** | 3 |
| **sing-box** | — | **8** | 8 |
| **NaiveProxy** | — | **7** | 7 |
| **b4** | — | **14** | 14 |
| **dae** (концепции) | — | **4** | 4 |
| **Итого (7 проектов)** | **45** | **~73** | **~118** |

> После дедупликации (пересекающиеся техники между проектами): **~106 уникальных техник**

---

## 13. Исследованные Rust-проекты: +50 новых техник

После анализа 11 дополнительных Rust DPI-проектов добавлено **~50 новых техник/концепций**.
Итоговый счёт: **~160 уникальных техник**.

### 13.1 sni-spoofing-rust — SEQ Number Spoofing (4 техники)

[Исходный код](research/rust_project/sni-spoofing-rust) — Rust. Инжекция fake ClientHello с SEQ вне окна приёма.

**Ключевая идея:** DPI отслеживает TCP SEQ/ACK, чтобы собирать TCP поток. Если отправить fake ClientHello с SEQ, который DPI ещё не ожидает (out-of-window), DPI может принять его за настоящий. Реальный ClientHello идёт следом с корректным SEQ и перезаписывает данные на сервере.

**Математика SEQ Spoofing:**
- Реальный SYN-ACK от сервера: `ISN_server = random()`
- Клиентский ACK после SYN-ACK: `ACK = ISN_server + 1`
- Fake ClientHello: `SEQ_fake = ISN_client + 10000` (far out-of-window)
- DPI видит fake CH и собирает его как "настоящий"
- Реальный CH: `SEQ_real = ISN_client + 1` (корректный)
- Сервер принимает реальный CH (так как SEQ в окне), перезаписывает fake

| # | Техника | Приоритет |
|---|---------|:---------:|
| SR1 | **SEQ Number Spoofing** | 🔴 **P0** |
| SR2 | **TLS 1.2 ClientHello Generator** | 🔴 P0 |
| SR3 | **RawBackend Trait** | 🟡 P1 |
| SR4 | **Sniffer → Register Flow** | 🟡 P2 |

### 13.2 RIPDPI — DesyncGroup + Entropy Padding (15 техник)

[Исходный код](research/rust_project/RIPDPI) — Rust, 40+ крейтов в workspace. **Самый богатый источник** среди всех проектов.

**Ключевое новшество:** DesyncGroup — конкурентное применение нескольких desync-операций к одному пакету. Каждая техника видит оригинальный пакет (не modified). Inject'ы накапливаются.

**Plan+Execute:** RIPDPI разделяет генерацию плана (Plan) от исполнения (Execute). Это позволяет анализировать ClientHello и строить оптимальную последовательность операций перед отправкой.

**Entropy Padding:** Контроль энтропии padding через два алгоритма:
- **Popcount**: количество единичных бит в байтах padding должно быть ~4 (50%)
- **Shannon**: H(padding) ≈ 7.0-7.5 бит/байт

| # | Техника | Приоритет |
|---|---------|:---------:|
| RP1 | **DesyncGroup (concurrent)** | 🔴 P1 |
| RP2 | **Plan+Execute** | 🔴 P1 |
| RP3 | **Disorder (TTL-based)** | 🔴 P3 |
| RP4 | **MultiDisorder** | 🔴 P3 |
| RP5 | **OOB/DisOOB** | 🔴 P3 |
| RP6 | **HostFake** | 🔴 P3 |
| RP7 | **FakeRst** | 🔴 P4 |
| RP8 | **Entropy Padding** | 🔴 P5 |
| RP9 | **Adaptive Offset Planning** | 🔴 P1 |
| RP10 | **Fallback Chain** | 🔴 P5.5 |
| RP11 | Activation Filters | 🟡 P2 |
| RP12 | TLS Record Choreography | 🟡 P5 |
| RP13 | TCP TSval MD5 | 🟡 P5 |
| RP14 | TCP Window Clamp + Drop SACK | 🟡 P4 |
| RP15 | Lua Strategy Scripts | 🟡 P8 |

### 13.3 autodpi — Probe/Tune/Run + Strategy Trait (4 техники)

[Исходный код](research/rust_project/autodpi) — Rust. Три фазы выбора стратегии.

**Probe → Tune → Run:**
1. **Probe**: отправить ClientHello со всеми известными стратегиями параллельно (5 потоков)
2. **Tune**: взять топ-3 успешные стратегии, проверить с разными параметрами
3. **Run**: использовать лучшую стратегию для всех последующих соединений к домену

**Strategy Trait + Registry:**
```rust
trait Strategy: Send + Sync {
    fn id(&self) -> u32;
    fn name(&self) -> &'static str;
    fn apply(&self, pkt: &mut Packet, ctx: &StrategyCtx) -> Result<()>;
    fn applicable(&self, pkt: &Packet) -> bool;  // activation filter
}
```
Стратегии регистрируются в глобальном реестре (`DashMap<u32, Box<dyn Strategy>>`).
Это позволяет добавлять новые стратегии без изменения ядра dispatcher'а.

| # | Техника | Приоритет |
|---|---------|:---------:|
| AD1 | **Probe/Tune/Run** | 🔴 P1 |
| AD2 | **Strategy Trait + Registry** | 🔴 **P0** |
| AD3 | **Auto-tune Parameters** | 🔴 P1 |
| AD4 | **Strategy Persistence** | 🟡 P1 |

### 13.4 dpibreak — HopTab + Fake CH (2 техники)

[Исходный код](research/rust_project/dpibreak) — Rust (~550 строк, 0 зависимостей). HopTab — кэш TTL → hops для auto-TTL.

**HopTab (Hop Table):**
```rust
struct HopTab {
    cache: [(u32, u8); 256],  // (ip_hash → hops) circular buffer
    cursor: AtomicU8,
}
```
- На каждое входящее TCP соединение: считываем `recv_ttl`, вычисляем hops
- Кэшируем {dst_ip → hops} в circular buffer на 256 записей
- Для fake ClientHello: устанавливаем TTL = hops - 1 (чтобы пакет гарантированно НЕ дошёл до сервера)

| # | Техника | Приоритет |
|---|---------|:---------:|
| DP1 | **HopTab (auto-TTL)** | 🔴 **P0** |
| DP2 | **Fake CH + badsum + auto-TTL** | 🔴 P1 |

### 13.5 CandyTunnel — ChaCha20 + TTL Jitter (9 техник)

[Исходный код](research/rust_project/CandyTunnel) — Rust. Полноценный туннель с обфускацией.

**ChaCha20 Per-Packet:** Каждый IP-пакет шифруется ChaCha20 (chacha20 crate) с уникальным nonce (packet counter). DPI видит случайные байты, не может идентифицировать протокол.

**Packet Size Padding:** Дополнение пакета до ближайшего кратного (align=128) чтобы скрыть размер передаваемых данных.

| # | Техника | Приоритет |
|---|---------|:---------:|
| CT1 | Mutual IP Spoofing | 🟡 P5 |
| CT2 | **ChaCha20 Per-Packet** | 🔴 P3 |
| CT3 | TTL Jitter | 🟡 P3 |
| CT4 | Random DSCP | 🟡 P4 |
| CT5 | Packet Size Padding | 🟡 P4 |
| CT6 | XOR FEC | 🟡 P7 |
| CT7 | Multiplexing | 🟡 P7 |
| CT8 | Port Shuffle | 🟡 P4 |
| CT9 | IPIP Tunnel | 🟡 P7 |

### 13.6 DPIReaper — Sentinel + Windows Management (6 техник)

[Исходный код](research/rust_project/DPIReaper) — Rust + Tauri. Управление Windows-интеграцией.

**Sentinel File:** Файл-триггер для аварийной остановки. При запуске engine проверяет: если `C:\ProgramData\ByeDPI\sentinel` существует → engine работает. Если файл удалён → engine останавливается (даже если завис). Ручное восстановление: создать файл заново.

| # | Техника | Приоритет |
|---|---------|:---------:|
| DR1 | **Sentinel File** | 🔴 **P0** |
| DR2 | Task Scheduler Autostart | 🟡 P9 |
| DR3 | UWP LoopbackExempt | 🟡 P9 |
| DR4 | Windows Firewall Rules | 🟡 P9 |
| DR5 | WinHTTP Proxy Config | 🟡 P9 |
| DR6 | PAC Server | 🟡 P9 |

### 13.7 qeli — Poisson Shaping + Supervisor (3 техники)

[Исходный код](research/rust_project/qeli) — Rust. 5 режимов обфускации, TLS 1.3 REALITY, PQ MLKEM.

**Poisson Shaping:** Моделирование интервалов между пакетами как пуассоновский процесс с λ = 20ms. Это делает трафик неотличимым от естественного сетевого трафика по IAT (Inter-Arrival Time).

| # | Техника | Приоритет |
|---|---------|:---------:|
| QL1 | **Poisson Traffic Shaping** | 🟡 P5 |
| QL2 | Supervisor/Worker | 🟡 P9 |
| QL3 | Multiqueue Processing | 🟡 P6 |

### 13.8 dpimyass — XOR First N (1 техника)

[Исходный код](research/rust_project/dpimyass) — Rust. Простая XOR-обфускация UDP с параметром first.

| # | Техника | Приоритет |
|---|---------|:---------:|
| DM1 | **XOR First N Bytes** | 🟡 P4 |

### 13.9 OpenLogi — IPC + Impostor Tagging (3 техники, 1 удалена)

[Исходный код](research/rust_project/OpenLogi) — Rust. Event-driven архитектура с IPC.

**Thread-Local Hot Path:** Использование `thread_local!` для хранения статистики keepalive и packet counters. Никаких блокировок на hot path.

**Synthetic Event Tagging (УДАЛЁН MR-18):** UUID-тег в TCP payload заменён на WinDivert `set_impostor(true)` + IP ID tagging. UUID в payload — fingerprint.

**interprocess + tarpc IPC:** RPC-канал для взаимодействия между Windows Service (работает как NETWORK SERVICE) и GUI (пользовательский процесс).

| # | Техника | Приоритет | Статус |
|---|---------|:---------:|:------:|
| OL1 | **Thread-Local Hot Path** | 🔴 P0 | ✅ |
| OL2 | ~~Synthetic Event Tagging~~ | 🔴 **P0** | ❌ **УДАЛЁН (MR-18)** |
| OL3 | interprocess + tarpc IPC | 🟡 P9 | ⏳ |

### 13.10 rust-no-dpi-socks — Byte-by-Byte (2 техники)

[Исходный код](research/rust_project/rust-no-dpi-socks) — Rust. Фрагментация первого пакета по 1 байту.

| # | Техника | Приоритет |
|---|---------|:---------:|
| RN1 | **Byte-by-Byte First Packet** | 🟡 P4 |
| RN2 | Unidirectional Fragmentation | 🟡 P5 |

### 13.11 rust-DPI-http-proxy — HTTP Header Manip (2 техники)

[Исходный код](research/rust_project/rust-DPI-http-proxy) — Rust. Модификация HTTP-заголовков.

| # | Техника | Приоритет |
|---|---------|:---------:|
| RH1 | **Host-Space HTTP Header** | 🟡 P5 |
| RH2 | **Title-Case HTTP Headers** | 🟡 P5 |

### 13.12 Сводный счёт техник (все 11 + 7 проектов)

| Источник | Техник | Live | Примечание |
|----------|:------:|:----:|------------|
| ByeDPI Android | 45 | 45 | Базовый набор |
| zapret2 | 15 | 15 | Новые на Windows |
| Windows-exclusive | 10 | 10 | Только Windows |
| Nova | 9 | 9 | Geo-routing, эволюция |
| Split Tunneling | 3 | 3 | |
| FakeSIP | 3 | 3 | Протокольная маскировка |
| sing-box | 8 | 8 | TLS Spoof, FakeIP DNS |
| NaiveProxy | 7 | 7 | TLS fingerprint |
| b4 | 14 | 14 | Combo, SeqOverlap |
| dae (концепции) | 4 | 4 | trie, bitmap |
| **sni-spoofing-rust** | **4** | 4 | **SEQ Spoofing** |
| **RIPDPI** | **15** | 12 | **DesyncGroup, Entropy** |
| **autodpi** | **4** | 4 | **Probe/Tune/Run** |
| **dpibreak** | **2** | 2 | **HopTab, Fake CH** |
| **CandyTunnel** | **9** | 6 | **ChaCha20, TTL jitter** |
| **DPIReaper** | **6** | 4 | **Sentinel, UWP** |
| **qeli** | **3** | 2 | **Poisson shaping** |
| **dpimyass** | **1** | 1 | XOR first N |
| **OpenLogi** | **3** | 2 | **~Event tagging~ impostor flag, IPC** |
| **rust-no-dpi-socks** | **2** | 1 | **Byte-by-byte** |
| **rust-DPI-http-proxy** | **2** | 1 | **Host-space** |
| **SpoofDPI** | **6** | 6 | **Segment Plans + Noise, Random Mask, Parallel Dial, Dual-Stack Hop, Domain Trie, Per-Rule Override** |
| **Итого (до дедупликации)** | **~175** | **~159** | |
| **После дедупликации** | **~156** | **~141** | |

### 13.13 Топ-15 техник для первоочередной реализации

Из всех ~150 техник, следующие дадут **наибольший эффект**:

| # | Техника | Из проекта | Эффект | Фаза |
|---|---------|:----------:|--------|:----:|
| 1 | **SNI Sequence Number Spoofing** | sni-spoofing-rust | Fake CH с SEQ вне окна DPI — DPI не может собрать поток правильно | **P0** |
| 2 | **TLS Spoof (fake CH с белым SNI)** | sing-box | DPI видит разрешённый SNI — прорыв | P1 |
| 3 | **Probe/Tune/Run + Strategy Trait** | autodpi | Авто-подбор трёхфазный, trait-based архитектура | **P0** |
| 4 | **DesyncGroup (concurrent)** | RIPDPI | Конкурентное применение [fake → split → reorder] к одному пакету | P1 |
| 5 | **Combo fragmentation** (multi-split + shuffle) | b4 | Максимальная десинхронизация | P3 |
| 6 | **SeqOverlap** (sequence number overlap) | b4 | Настоящий packet-level overlap | P3 |
| 7 | **TLS mutation chain** (GREASE + reorder + fake ALPN) | b4 | DPI не может сопоставить fingerprint | P3 |
| 8 | **Chrome JA3 через rustls/boring** | NaiveProxy | Идеальный TLS fingerprint | P3 |
| 9 | **HopTab + Fake CH with auto-TTL** | dpibreak | Fake CH гарантированно НЕ доходит до сервера | **P0** |
| 10 | **Detect & Escalate** | b4 | Авто-подбор под провайдера | P5.5 |
| 11 | **ChaCha20 Per-Packet Obfuscation** | CandyTunnel | DPI видит только случайные байты | P3 |
| 12 | **Synthetic Event Tagging** | OpenLogi | Нет loop'ов WinDivert на injected пакетах | **P0** |
| 13 | **Entropy Padding (Popcount/Shannon)** | RIPDPI | Padding с контролируемой энтропией | P5 |
| 14 | **FakeIP DNS** | sing-box | Маршрутизация по доменам | P1 |
| 15 | **Adaptive Offset Planning** | RIPDPI | Авто-выбор позиций split под размер ClientHello | P1 |

---

## 13. Geo-Routing Engine (из Nova)

### 13.1 Проблема

DPI bypass и geo-spoofing — **разные задачи**:
- **DPI bypass**: DPI-сенсор блокирует соединение по SNI/IP → нужно десинхронизировать пакеты
- **Geo-spoofing**: сервер (Netflix, OpenAI и т.д.) видит IP из заблокированного региона → отдаёт 403/redirect

Решение Nova: **маршрутизация по доменам/IP с привязкой к региону**.

### 13.2 Архитектура

```
[Packet из WinDivert]
    │
    ▼
[Classifier: domain + IP]
    │
    ▼
[GeoRouter]
│   │
│   ├── Россия/СНГ  ──► Desync Engine (локальный обход DPI)
│   ├── Европа       ──► Opera VPN (EU-IP для geo-spoofing)
│   ├── США          ──► User Proxy / WARP
│   ├── Unknown      ──► Probe: Direct + fallback
│   └── Exclude      ──► Direct passthrough
│
    ▼
[Proxy Chain Manager (failover)]
```

### 13.3 Rust-реализация

```rust
/// Регионы для geo-маршрутизации
#[derive(Debug, Clone, PartialEq)]
pub enum GeoRegion {
    Russia,          // DPI обход локально
    Europe,          // Opera VPN (EU-IP)
    UnitedStates,    // Пользовательский US-прокси
    Global,          // Direct + desync
    Excluded,        // Direct passthrough (банки, госуслуги)
}

/// Результат geo-маршрутизации
pub struct RouteDecision {
    pub region: GeoRegion,
    pub egress_chain: EgressChain,
    pub desync_strategy: Option<Strategy>,
}

/// Движок гео-маршрутизации (заимствован из Nova)
pub struct GeoRouter {
    // Доменные списки (загружаются из файлов)
    ru_domains: HashSet<String>,   // yandex, vk, sberbank...
    eu_domains: HashSet<String>,   // netflix, openai, spotify...
    us_domains: HashSet<String>,
    exclude_domains: HashSet<String>,
    
    // IP CIDR по регионам
    ru_cidrs: Vec<Ipv4Net>,
    eu_cidrs: Vec<Ipv4Net>,
    
    // Кэш domain→region (moka, TTL 1 час)
    route_cache: moka::sync::Cache<String, GeoRegion>,
    
    // Bad route cache (TTL-based, из Nova)
    bad_routes: Arc<DashMap<String, Instant>>,
}

impl GeoRouter {
    /// Основной метод: определить регион и маршрут
    pub fn resolve(&self, domain: &str, ip: Ipv4Addr) -> RouteDecision {
        // 1. Проверяем exclude
        if self.exclude_domains.contains(domain) {
            return RouteDecision {
                region: GeoRegion::Excluded,
                egress_chain: EgressChain::direct(),
                desync_strategy: None,
            };
        }
        
        // 2. Проверяем bad route cache
        let cache_key = format!("{}|{}", domain, ip);
        if self.is_bad_route(&cache_key) {
            return RouteDecision {
                region: GeoRegion::Global, // fallback: direct desync
                egress_chain: EgressChain::direct_with_fallback(),
                desync_strategy: Some(Strategy::default()),
            };
        }
        
        // 3. Определяем регион
        let region = self.route_cache.get(&cache_key).unwrap_or_else(|| {
            let r = self.classify(domain, ip);
            self.route_cache.insert(cache_key, r.clone());
            r
        });
        
        // 4. Выбираем egress chain
        let egress_chain = self.build_egress_chain(&region);
        
        RouteDecision { region, egress_chain, desync_strategy: None }
    }
    
    /// Классификация домена/IP по региону
    fn classify(&self, domain: &str, ip: Ipv4Addr) -> GeoRegion {
        if self.ru_domains.contains(domain)
            || self.ru_cidrs.iter().any(|c| c.contains(ip)) {
            return GeoRegion::Russia;
        }
        if self.eu_domains.contains(domain)
            || self.eu_cidrs.iter().any(|c| c.contains(ip)) {
            return GeoRegion::Europe;
        }
        if self.us_domains.contains(domain) {
            return GeoRegion::UnitedStates;
        }
        GeoRegion::Global
    }
    
    /// Построение egress chain для региона
    fn build_egress_chain(&self, region: &GeoRegion) -> EgressChain {
        match region {
            GeoRegion::Russia => EgressChain::new(vec![
                Egress::Direct { desync: true },  // DPI desync локально
                Egress::Socks5 { host: "127.0.0.1", port: 1370 }, // фолбэк
            ]),
            GeoRegion::Europe => EgressChain::new(vec![
                Egress::Socks5 { host: "127.0.0.1", port: 1371 }, // Opera VPN
                Egress::Direct { desync: true },    // fallback
            ]),
            GeoRegion::UnitedStates => EgressChain::new(vec![
                Egress::UserProxy,                   // пользовательский
                Egress::Direct { desync: true },
            ]),
            GeoRegion::Global | GeoRegion::Excluded => EgressChain::new(vec![
                Egress::Direct { desync: true },
            ]),
        }
    }
    
    /// Проверка bad route (из Nova: TTL-based кэш)
    fn is_bad_route(&self, key: &str) -> bool {
        self.bad_routes.get(key).is_some_and(|expires| {
            *expires.value() > Instant::now()
        })
    }
    
    /// Маркировка route как bad (Nova паттерн)
    pub fn mark_bad_route(&self, key: String, ttl: Duration) {
        self.bad_routes.insert(key, Instant::now() + ttl);
    }
}
```

### 13.4 Региональные списки (из Nova)

```
data/lists/
├── ru_domains.txt      # yandex.ru, vk.com, sberbank.ru...
├── eu_domains.txt      # netflix.com, openai.com, spotify.com...
├── us_domains.txt      # discord.com, reddit.com...
├── exclude_domains.txt # gosuslugi.ru, nalog.ru...
├── ru_cidrs.txt        # 95.213.0.0/16, 37.9.0.0/16...
└── eu_cidrs.txt        # Cloudflare EU PoPs, AWS EU...
```

### 13.5 Авто-детекция региональной блокировки

```rust
/// Определяем, что это geo-block, а не DPI
pub fn detect_geo_block(response: &[u8]) -> bool {
    // Признаки geo-blocking:
    // 1. HTTP 403/451 Forbidden (а не RST/таймаут как при DPI)
    // 2. HTML страница с "not available in your country"
    // 3. Текст "geo-restricted", "region", "country" в ответе
    // 4. TCP соединение успешно, TLS handshake прошёл
    //    НО application-level ответ — отказ
    
    if response.len() < 10 { return false; }
    
    // HTTP ответ с 403
    if response.starts_with(b"HTTP/") {
        let status_line = std::str::from_utf8(&response[..15]).unwrap_or("");
        return status_line.contains("403") || status_line.contains("451");
    }
    
    // TLS Alert level fatal (handshake failure)
    if response[0] == 0x15 && response.len() > 5 {
        return response[5] == 0x28; // TLS alert: handshake failure
    }
    
    false
}
```

---

## 14. Proxy Chain Manager (из Nova)

### 14.1 Отличие от Android proxy fallback

На Android: один прокси → другой прокси (линейно, 2 уровня).
Nova: **цепочка с health checks + bad route cache + parallel failover**.

### 14.2 Архитектура цепочки

```
EgressChain:
┌──────────┐   ┌──────────┐   ┌──────────┐
│  try #1  │──►│  try #2  │──►│  try #3  │
│ warp-socks│   │ opera-http│   │ direct   │
│  :1370   │   │  :1371   │   │ (desync) │
└──────────┘   └──────────┘   └──────────┘
     │               │               │
     │ timeout/error │               │
     └───────────────┘               │
           timeout/error             │
           └─────────────────────────┘
```

### 14.3 Rust-реализация

```rust
/// Тип egress-провайдера
#[derive(Debug, Clone)]
pub enum Egress {
    /// Прямое соединение с DPI desync
    Direct { desync: bool },
    /// SOCKS5 прокси
    Socks5 { host: &'static str, port: u16 },
    /// HTTP CONNECT прокси
    HttpConnect { host: &'static str, port: u16 },
    /// Пользовательский прокси (из конфига)
    UserProxy,
}

/// Цепочка egress-попыток с per-hop таймаутами
#[derive(Debug, Clone)]
pub struct EgressChain {
    steps: Vec<Egress>,
    /// Per-hop timeout (seconds)
    hop_timeout: Duration,
    /// Timeout на первый байт ответа
    first_byte_timeout: Duration,
}

impl EgressChain {
    /// Построить попытку для target
    pub fn build_attempts(&self, target: &Target) -> Vec<Attempt> {
        self.steps.iter().filter_map(|egress| {
            if self.is_bad_route(target, egress) {
                return None; // Пропускаем bad route
            }
            Some(Attempt {
                egress: egress.clone(),
                target: target.clone(),
                timeout: self.hop_timeout,
                first_byte_timeout: self.first_byte_timeout,
            })
        }).collect()
    }
    
    /// Sequential failover с per-attempt timeout
    pub async fn execute(&self, target: &Target) -> Result<ConnResult> {
        let attempts = self.build_attempts(target);
        for attempt in &attempts {
            match tokio::time::timeout(
                attempt.timeout,
                attempt.execute()
            ).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    // Mark as bad route
                    self.mark_bad(target, attempt.egress.label());
                    continue; // Next attempt
                }
                Err(_timeout) => {
                    self.mark_bad(target, attempt.egress.label());
                    continue;
                }
            }
        }
        Err(anyhow!("All egress routes failed"))
    }
}

/// Proxy health checker (Nova keepalive pattern)
pub struct ProxyHealth {
    check_interval: Duration,
}

impl ProxyHealth {
    /// Проверка SOCKS5 прокси (Nova паттерн)
    pub async fn check_socks5(host: &str, port: u16) -> bool {
        let Ok(mut stream) = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect((host, port))
        ).await else { return false; };
        
        // SOCKS5 handshake: greeting
        let _ = stream.write(b"\x05\x01\x00").await;
        let mut buf = [0u8; 2];
        let Ok(Ok(2)) = tokio::time::timeout(
            Duration::from_secs(1),
            stream.read(&mut buf)
        ).await else { return false; };
        
        buf == [0x05, 0x00] // SOCKS5: no auth required
    }
    
    /// Проверка HTTP CONNECT прокси (Nova паттерн)
    pub async fn check_http(host: &str, port: u16) -> bool {
        let Ok(mut stream) = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect((host, port))
        ).await else { return false; };
        
        let req = format!(
            "CONNECT www.gstatic.com:443 HTTP/1.1\r\nHost: www.gstatic.com:443\r\n\r\n"
        );
        let _ = stream.write(req.as_bytes()).await;
        let mut buf = [0u8; 192];
        let Ok(Ok(n)) = tokio::time::timeout(
            Duration::from_secs(1),
            stream.read(&mut buf)
        ).await else { return false; };
        
        buf[..n].starts_with(b"HTTP/") && buf[..n].windows(3).any(|w| w == b"200")
    }
}
```

---

## 15. Strategy Evolution (из Nova)

### 15.1 Проблема

Разные домены/providers требуют разных DPI desync-стратегий. То, что работает для
youtube.com, может не работать для vk.com. Ручной подбор — боль.

### 15.2 Решение Nova

Nova отслеживает visited_domains_stats и strategies_evolution — какие стратегии
работают для каких доменов, автоматически ротирует и адаптирует.

### 15.3 Rust-реализация

```rust
/// Статистика стратегии для домена
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyStats {
    /// Сколько раз стратегия сработала успешно
    pub success_count: u64,
    /// Сколько раз упала
    pub fail_count: u64,
    /// Время последнего успеха
    pub last_success: Option<DateTime<Utc>>,
    /// Текущий уровень (0 = отключена)
    pub level: u32,
}

/// Движок эволюции стратегий
pub struct StrategyEvolution {
    /// per-domain stats: domain → (strategy_id → stats)
    stats: Arc<DashMap<String, HashMap<u32, StrategyStats>>>,
    /// Глобальный счётчик использований
    global_usage: Arc<DashMap<u32, u64>>,
    /// Путь к файлу персистентности
    persist_path: PathBuf,
}

impl StrategyEvolution {
    /// Выбрать лучшую стратегию для домена
    pub fn select_strategy(&self, domain: &str) -> u32 {
        let domain_stats = self.stats.get(domain);
        
        if let Some(stats) = domain_stats {
            // 1. Есть ли стратегия с успехом > 50%?
            if let Some(best) = stats.iter().max_by(|a, b| {
                let a_rate = a.success_rate();
                let b_rate = b.success_rate();
                a_rate.partial_cmp(&b_rate).unwrap_or(std::cmp::Ordering::Equal)
            }) {
                if best.success_rate() > 0.5 {
                    return best.id;
                }
            }
        }
        
        // 2. Если нет — циклическая ротация (как Nova)
        self.rotate_strategy(domain)
    }
    
    /// Записать результат (успех/неудача)
    pub fn record_result(&self, domain: &str, strategy_id: u32, success: bool) {
        self.stats.entry(domain.to_string()).or_default()
            .entry(strategy_id).or_insert_with(|| StrategyStats {
                success_count: 0,
                fail_count: 0,
                last_success: None,
                level: 1,
            });
        
        let mut entry = self.stats.get_mut(domain).unwrap();
        let strat = entry.get_mut(&strategy_id).unwrap();
        
        if success {
            strat.success_count += 1;
            strat.last_success = Some(Utc::now());
            strat.level = (strat.level + 1).min(10);
        } else {
            strat.fail_count += 1;
            strat.level = strat.level.saturating_sub(1);
        }
        
        // Периодическое сохранение на диск
        self.persist();
    }
    
    /// Ротация стратегий (Nova: cycles through hard_1..hard_12)
    fn rotate_strategy(&self, domain: &str) -> u32 {
        let key = format!("rotation:{}", domain);
        let counter = self.rotation_counters
            .entry(key).or_insert(0u32);
        *counter += 1;
        
        // 82 стратегии → циклический перебор
        (*counter % 82) + 1
    }
}
```

---

## 16. Per-App Routing (из Nova)

### 16.1 Идея

Nova определяет, какое приложение создаёт соединение, по имени процесса
(Discord.exe, Telegram.exe, chrome.exe) и применяет разную маршрутизацию.

### 16.2 Реализация

```rust
/// Семейство приложений
#[derive(Debug, Clone, PartialEq)]
pub enum AppFamily {
    /// Браузеры (Chrome, Firefox, Edge)
    Browser,
    /// Мессенджеры
    Messenger,  // Telegram, Discord, WhatsApp
    /// Игры
    Gaming,     // Steam, Battle.net
    /// IDE/терминал
    DevTools,   // VSCode, Git, OpenCode
    /// Системное
    System,     // svchost, Windows Update
    /// Неизвестное
    Unknown,
}

impl AppFamily {
    /// Определить по имени процесса
    pub fn from_process_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("chrome") || lower.contains("firefox") 
           || lower.contains("msedge") || lower.contains("opera") {
            AppFamily::Browser
        } else if lower.contains("telegram") || lower.contains("discord")
                  || lower.contains("whatsapp") {
            AppFamily::Messenger
        } else if lower.contains("steam") || lower.contains("battle") 
                  || lower.contains("epic") {
            AppFamily::Gaming
        } else if lower.contains("code") || lower.contains("terminal")
                  || lower.contains("git") || lower.contains("putty") {
            AppFamily::DevTools
        } else if lower.contains("svchost") || lower.contains("services") {
            AppFamily::System
        } else {
            AppFamily::Unknown
        }
    }
}

/// Per-app routing decision
pub struct AppRouter {
    // app → preferred region override
    overrides: HashMap<AppFamily, GeoRegion>,
}

impl AppRouter {
    pub fn new() -> Self {
        let mut overrides = HashMap::new();
        overrides.insert(AppFamily::Browser, GeoRegion::Global);    // Browser: всё через desync
        overrides.insert(AppFamily::Messenger, GeoRegion::Europe);  // Messenger: через EU
        overrides.insert(AppFamily::Gaming, GeoRegion::Russia);     // Games: локальный обход
        overrides.insert(AppFamily::System, GeoRegion::Excluded);   // System: direct
        Self { overrides }
    }
    
    pub fn resolve_region(&self, app: &AppFamily, geo: &GeoRegion) -> GeoRegion {
        self.overrides.get(app).copied().unwrap_or(geo.clone())
    }
}
```

---

## 17. Сравнение: DPI bypass vs Regional blocking

| Характеристика | DPI bypass | Regional blocking |
|---------------|:----------:|:-----------------:|
| **Кто блокирует** | Провайдер (ТСПУ, DPI-сенсор) | Целевой сервер (Netflix, OpenAI) |
| **Причина** | Запрещённый контент по закону | Лицензионные ограничения по региону |
| **Симптом** | TCP RST / таймаут / HTTP 451 | HTTP 403 / redirect / geo-block page |
| **TLS handshake** | ❌ Обрывается до ServerHello | ✅ Проходит успешно |
| **Решение** | Десинхронизация пакетов (split, frag, fake) | Смена IP на разрешённый регион |
| **Инструмент** | WinDivert + raw sockets | SOCKS5/HTTP прокси из нужного региона |
| **Ресурсы** | Только локальная машина | EU-прокси (Opera VPN) / US-прокси (user) |

### Комбинированный подход

```
1. Пробуем Direct + DPI desync
   │
   ├── Сервер ответил → отдаём клиенту (OK)
   │
   └── Сервер НЕ ответил →
        │
        ├── TCP RST/таймаут → DPI bypass не работает →
        │   └── Пробуем другую стратегию desync
        │
        └── HTTP 403/451/tls alert → Regional block →
            └── Переключаемся на прокси из другого региона
```

---

## 18. Полная техника-карта (~150 шт)

### 18.1 Nova-derived техники (9 шт)

| # | Техника | Rust модуль | Описание |
|---|---------|-------------|----------|
| N1 | **Geo-routing: Russia** | `routing::geo` | RU-домены → desync локально |
| N2 | **Geo-routing: Europe** | `routing::geo` | EU-домены → Opera VPN (geo-spoof) |
| N3 | **Geo-routing: US** | `routing::geo` | US-домены → user proxy |
| N4 | **Proxy Chain with failover** | `routing::chain` | Цепочка egress с health checks |
| N5 | **Bad Route Cache** | `routing::chain` | TTL-based, не повторяем упавшие |
| N6 | **Strategy Evolution** | `routing::evolution` | Авто-подбор desync под домен |
| N7 | **Per-App Routing** | `routing::app` | Discord→EU, Browser→desync, System→direct |
| N8 | **Opera VPN Integration** | `routing::opera` | Бесплатные EU SOCKS5 прокси |
| N9 | **DPI vs Geo-block Detection** | `routing::detect` | Различаем DPI блокировку и geo-block |

### 18.2 Техники из sing-box (8 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| SB1 | **TLS Spoof (fake CH)** | `desync::tls::spoof` | Фейковый ClientHello с белым SNI | 🔴 P3 |
| SB2 | **TLS Record Fragment** | `desync::tls::frag` | Разделение TLS Record Layer (не TCP) | 🔴 P3 |
| SB3 | **BadTLS (raw control)** | `desync::tls::raw` | Прямой контроль TLS record состояния | 🟡 P5 |
| SB4 | **Reality (XTLS mask)** | `proxy::reality` | Маскировка под TLS-сервер | 🟡 P7 |
| SB5 | **uTLS fingerprints** | `desync::tls::utls` | Случайный Chrome/Firefox fingerprint | 🔴 P3 |
| SB6 | **ShadowTLS** | `proxy::shadow` | Протокол-маскировщик TLS | 🟡 P7 |
| SB7 | **FakeIP DNS** | `dns::fakeip` | Виртуальные IP для маршрутизации | 🔴 P1 |
| SB8 | **Rule Sets** | `routing::rules` | Обновляемые geoip/geosite списки | 🟡 P1.5 |

### 18.3 Техники из NaiveProxy (7 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| NP1 | **Chrome JA3 (rustls/boring)** | `desync::tls::fingerprint` | Chrome-идентичный TLS fingerprint | 🔴 P3 |
| NP2 | **H2 SETTINGS Chrome** | `desync::http::h2` | SETTINGS_INITIAL_WINDOW_SIZE = 64MB | 🔴 P3 |
| NP3 | **RST_STREAM padding** | `desync::http::h2` | DATA+PADDED+FIN перед RST | 🔴 P3 |
| NP4 | **HEADERS padding** | `desync::http::h2` | HPACK non-indexed + padding | 🟡 P5 |
| NP5 | **Preamble** | `proxy::preamble` | Фейковые HTTP запросы перед CONNECT | 🟡 P7 |
| NP6 | **Multi-session** | `proxy::multisession` | N параллельных H2/H3 туннелей | 🔴 P7 |
| NP7 | **Post-Quantum X25519MLKEM768** | `desync::tls::pq` | Chrome 149+ hybrid key agreement | 🟡 P8 |

### 18.4 Техники из b4 (14 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| B1 | **Combo fragmentation** | `desync::tcp::combo` | Multi-split + shuffling | 🔴 P3 |
| B2 | **ExtSplit** | `desync::tcp::extsplit` | Разрез на границе extension | 🔴 P3 |
| B3 | **SeqOverlap** | `desync::tcp::seq_overlap` | Sequence number overlap | 🔴 P3 |
| B4 | **Fake overlapping segs** | `desync::tcp::fake_overlap` | Перекрывающиеся фейк-сегменты | 🔴 P4 |
| B5 | **TLS mutation chain** | `desync::tls::mutation` | GREASE + dup SNI + reorder + fake ALPN | 🔴 P3 |
| B6 | **Fake QUIC Initial** | `desync::quic::fake_initial` | QUIC Initial с нуля (не из дампа) | 🔴 P6 |
| B7 | **Detect & Escalate** | `adaptive::escalate` | DPI блокировка → агрессивная стратегия | 🔴 P5.5 |
| B8 | **RST protection** | `adaptive::rst_protect` | Детекция и игнорирование DPI RST | 🔴 P4 |
| B9 | **Incoming manipulation** | `desync::tcp::incoming` | Инъекция в сторону сервера | 🟡 P5 |
| B10 | **Window manipulation** | `desync::tcp::window_manip` | Oscillate/zero/random/escalate | 🔴 P4 |
| B11 | **Post-desync** | `desync::tcp::post_desync` | RST burst после ClientHello | 🟡 P4 |
| B12 | **Decoy fragments** | `desync::tcp::decoy` | Фейковые фрагменты перед реальными | 🟡 P4 |
| B13 | **SYN MD5 option** | `desync::tcp::syn_md5` | SYN с TCP MD5 option | 🟡 P5 |
| B14 | **Hybrid strategy** | `adaptive::hybrid` | Runtime выбор стратегии | 🔴 P5.5 |

### 18.5 Техники из FakeSIP (3 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| FS1 | **SIP Protocol Masking** | `obfs::sip` | Маскировка UDP под SIP INVITE | 🟡 P6 |
| FS2 | **Custom Payload Inject** | `obfs::payload` | Загрузка своего дампа пакета | 🟡 P5 |
| FS3 | **UDP Payload Randomize** | `obfs::udp_random` | Рандомизация байтов UDP | 🟡 P6 |

### 18.6 dae-концепции (4 шт)

| # | Концепция | Rust модуль | Описание | Приоритет |
|---|-----------|-------------|----------|:---------:|
| DA1 | **Succinct trie** | `routing::trie` | O(1) CIDR lookup | 🔴 P1.5 |
| DA2 | **Domain→IP bitmap** | `dns::bitmap` | Маппинг IP→домен через DNS | 🔴 P1 |
| DA3 | **Rule normalization** | `routing::rules` | AST + оптимизация правил | 🟡 P1.5 |
| DA4 | **First-packet cache** | `conntrack` | Кэш решения на всё соединение | ✅ Уже в conntrack |

### 18.7 Техники из sni-spoofing-rust (4 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| SR1 | **SEQ Number Spoofing** | `desync::tcp::seq_spoof` | Fake CH с SEQ вне окна приёма DPI | 🔴 P0 |
| SR2 | **TLS 1.2 ClientHello Gen** | `desync::tls::ch_gen` | Генерация TLS CH из struct | 🔴 P0 |
| SR3 | **RawBackend Trait** | `desync::tcp::raw_backend` | Интерфейс backend'а отправки | 🟡 P1 |
| SR4 | **Sniffer→Register Flow** | `desync::tcp::sniffer` | Перехват SYN + регистрация в conntrack | 🟡 P2 |

### 18.8 Техники из RIPDPI (15 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| RP1 | **DesyncGroup** | `desync::group` | Pipeline desync-операций | 🔴 P1 |
| RP2 | **Plan+Execute** | `desync::planner` | Разделение генерации и исполнения плана | 🔴 P1 |
| RP3 | **Disorder (TTL-based)** | `desync::tcp::disorder` | Реордеринг с TTL контролем | 🔴 P3 |
| RP4 | **MultiDisorder** | `desync::tcp::multidisorder` | Множественные disorder-сегменты | 🔴 P3 |
| RP5 | **OOB/DisOOB** | `desync::tcp::disoob` | OOB + disorder | 🔴 P3 |
| RP6 | **HostFake** | `desync::tcp::hostfake` | Fake SNI | 🔴 P3 |
| RP7 | **FakeRst** | `desync::tcp::fakerst` | Сброс состояния DPI | 🔴 P4 |
| RP8 | **Entropy Padding** | `desync::obfs::entropy` | Popcount/Shannon контроль энтропии | 🔴 P5 |
| RP9 | **Adaptive Offset Planning** | `desync::planner::offset` | Авто-выбор split-позиций | 🔴 P1 |
| RP10 | **Fallback Chain** | `adaptive::fallback` | Каскад стратегий | 🔴 P5.5 |
| RP11 | **Activation Filters** | `desync::filter` | Пропуск неприменимых стратегий | 🟡 P2 |
| RP12 | **TLS Record Choreography** | `desync::tls::choreo` | Контроль RTT-паттернов TLS | 🟡 P5 |
| RP13 | **TCP TSval MD5** | `desync::tcp::ts_md5` | Манипуляция Timestamp опциями | 🟡 P5 |
| RP14 | **TCP Window Clamp + Drop** | `desync::tcp::wclamp` | Принудительное уменьшение window | 🟡 P4 |
| RP15 | **Lua Strategy Scripts** | `adaptive::lua` | Пользовательские Lua-скрипты | 🟡 P8 |

### 18.9 Техники из autodpi (4 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| AD1 | **Probe/Tune/Run** | `adaptive::probe_tune_run` | Трёхфазный выбор стратегии | 🔴 P1 |
| AD2 | **Strategy Trait + Registry** | `adaptive::registry` | Trait-based архитектура стратегий | 🔴 P0 |
| AD3 | **Auto-tune Parameters** | `adaptive::auto_tune` | Подключён к pipeline (MR-37): record() + recommend() → ConfigOverride | 🔴 P1 ✅ |
| AD4 | **Strategy Persistence** | `adaptive::persist` | Сохранение best-стратегий на диск | 🟡 P1 |

### 18.10 Техники из dpibreak (2 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| DP1 | **HopTab (auto-TTL)** | `desync::ip::hop_tab` | Hop-кэш на 256 entries, circular buffer | 🔴 P0 |
| DP2 | **Fake CH + badsum + auto-TTL** | `desync::tcp::fake_ch_badsum` | Fake CH с bad checksum + auto-TTL | 🔴 P1 |

### 18.11 Техники из CandyTunnel (9 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| CT1 | **Mutual IP Spoofing** | `desync::ip::mutual_spoof` | Двусторонняя подмена IP | 🟡 P5 |
| CT2 | **ChaCha20 Per-Packet** | `desync::crypto::chacha20` | Per-packet шифрование (chacha20 crate) | 🔴 P3 |
| CT3 | **TTL Jitter** | `desync::ip::ttl_jitter` | TTL ± random(3) | 🟡 P3 |
| CT4 | **Per-Connection DSCP** | `conntrack::dscp_spoof` | Per-connection constant (MR-G5), хранится в ConntrackEntry, передаётся в DesyncGroup | 🟡 P4 ✅ |
| CT5 | **Packet Size Padding** | `desync::obfs::pad_size` | Padding до кратного размера | 🟡 P4 |
| CT6 | **XOR FEC** | `desync::obfs::xorfec` | Forward Error Correction | 🟡 P7 |
| CT7 | **Multiplexing** | `proxy::mux` | Несколько потоков поверх 1 TCP | 🟡 P7 |
| CT8 | **Port Shuffle** | `desync::tcp::port_shuffle` | Ротация source port | 🟡 P4 |
| CT9 | **IPIP Tunnel** | `desync::ip::ipip` | IP-in-IP/GRE инкапсуляция | 🟡 P7 |

### 18.12 Техники из DPIReaper (6 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| DR1 | **Sentinel File System** | `infra::sentinel` | File-based autostop/autostart | 🔴 P0 |
| DR2 | **Task Scheduler Autostart** | `infra::autostart` | Windows Task Scheduler | 🟡 P9 |
| DR3 | **UWP LoopbackExempt** | `infra::uwp_loopback` | Разрешение loopback для UWP | 🟡 P9 |
| DR4 | **Windows Firewall Rules** | `infra::firewall` | Авто-создание правил firewall | 🟡 P9 |
| DR5 | **WinHTTP Proxy Config** | `infra::winhttp_proxy` | Системный WinHTTP прокси | 🟡 P9 |
| DR6 | **PAC Server** | `infra::pac` | HTTP-сервер proxy.pac на :11338 | 🟡 P9 |

### 18.13 Техники из qeli (3 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| QL1 | **Poisson Traffic Shaping** | `desync::obfs::poisson` | IAT по Пуассону λ=20ms | 🟡 P5 |
| QL2 | **Supervisor/Worker** | `infra::supervisor` | Процесс-супервизор | 🟡 P9 |
| QL3 | **Multiqueue Processing** | `packet_engine::multiqueue` | Разделение пакетов по очередям | 🟡 P6 |

### 18.14 Техники из dpimyass (1 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| DM1 | **XOR First N Bytes** | `desync::obfs::xor_first` | XOR только первых N байт | 🟡 P4 |

### 18.15 Техники из OpenLogi (3 шт, 1 удалена MR-18)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| OL1 | **Thread-Local Hot Path** | `packet_engine::tls_hotpath` | thread_local! статистика, 0 lock'ов | 🔴 P0 |
| OL2 | **Synthetic Event Tagging** | ~~`infra::event_tag`~~ | **УДАЛЁН (MR-18).** Impostor flag + IP ID tagging достаточны. UUID в payload — fingerprint. | 🔴 P0 ✅ |
| OL3 | **interprocess + tarpc IPC** | `infra::ipc` | RPC service↔UI | 🟡 P9 |

### 18.16 Техники из rust-no-dpi-socks (2 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| RN1 | **Byte-by-Byte First Packet** | `desync::tcp::byte_by_byte` | Первый сегмент по 1 байту | 🟡 P4 |
| RN2 | **Unidirectional Frag** | `desync::tcp::unidir_frag` | Фрагментация только на клиенте | 🟡 P5 |

### 18.17 Техники из rust-DPI-http-proxy (2 шт)

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| RH1 | **Host-Space HTTP Header** | `desync::http::host_space` | Пробел после Host: | 🟡 P5 |
| RH2 | **Title-Case HTTP Headers** | `desync::http::title_case` | Преобразование в Title-Case | 🟡 P5 |

### 18.18 HTTP API для агента (8 эндпоинтов)

| # | Метод | Путь | Описание |
|---|-------|------|----------|
| API1 | `GET` | `/api/v1/status` | Статус engine (running/stopped, uptime, stats) |
| API2 | `POST` | `/api/v1/strategies/test` | Протестировать стратегию на домене |
| API3 | `GET` | `/api/v1/strategies/stats` | Статистика стратегий per-domain |
| API4 | `POST` | `/api/v1/strategies/tune` | Изменить параметры стратегии |
| API5 | `GET` | `/api/v1/conntrack` | Список активных соединений |
| API6 | `GET` | `/api/v1/dns/cache` | DNS кэш |
| API7 | `POST` | `/api/v1/routing/override` | Установить override маршрута для домена |
| API8 | `GET` | `/api/v1/health` | Health check (для мониторинга) |

### 18.19 Сводная таблица по всем источникам (18 проектов)

| Категория | Android | zapret2 | Win-excl | Nova | Split | FakeSIP | sing-box | NaiveProxy | b4 | dae | sni-spf | RIPDPI | autodpi | dpibreak | CandyTun | DPIReap | qeli | OpenLogi | **Итого** |
|-----------|:-------:|:-------:|:--------:|:----:|:-----:|:-------:|:--------:|:----------:|:--:|:---:|:-------:|:------:|:-------:|:--------:|:--------:|:-------:|:----:|:--------:|:---------:|
| TCP Split/Disorder | 6 | 6 | — | — | — | — | — | — | 4 | — | — | 4 | — | — | — | — | — | — | **20** |
| Fake Injection | 6 | 3 | — | — | — | — | 1 | — | 3 | — | 1 | 3 | — | 1 | — | — | — | — | **18** |
| TCP Window/MSS | 2 | 2 | 3 | — | — | — | — | — | 2 | — | — | 2 | — | — | — | — | — | — | **11** |
| IP Level | 2 | 2 | 2 | — | — | — | — | — | 1 | — | — | — | — | 1 | 2 | — | — | — | **10** |
| TLS/HTTPS | 5 | — | — | — | — | — | 4 | 4 | 2 | — | 1 | 2 | — | — | — | — | — | — | **18** |
| QUIC/UDP | 7 | — | — | — | — | 3 | — | — | 1 | — | — | — | — | — | — | — | — | — | **11** |
| DNS | 3 | — | — | — | — | — | 1 | — | — | 1 | — | — | — | — | — | — | — | — | **5** |
| Proxy Fallback | 5 | — | — | 4 | — | — | 1 | 2 | — | — | — | — | — | — | 1 | — | — | — | **13** |
| Obfuscation | 3 | 3 | — | — | — | — | — | — | — | — | — | 1 | — | — | 3 | — | 1 | — | **11** |
| Adaptive | 2 | — | — | 2 | — | — | — | — | 2 | — | — | 3 | 3 | — | 1 | — | — | — | **13** |
| Split Tunneling | — | — | — | 3 | 3 | — | — | — | — | — | — | — | — | — | — | — | — | — | **6** |
| Routing/Geo | — | — | — | 3 | — | — | 1 | — | — | 2 | — | — | — | — | — | — | — | — | **6** |
| Infrastructure | 7 | — | — | — | — | — | 1 | 1 | 1 | — | — | — | 1 | — | — | 4 | 1 | 2 | **18** |
| Crypto/Encryption | — | — | — | — | — | — | — | — | — | — | — | — | — | — | 2 | — | — | — | **2** |
| **Итого** | **48** | **16** | **5** | **12** | **3** | **3** | **9** | **7** | **16** | **3** | **2** | **15** | **4** | **2** | **9** | **4** | **2** | **2** | **~162** |

> После дедупликации: **~160 уникальных техник** (45 Android + 15 zapret2 + 10 Win-excl + 9 Nova + 3 Split + 10 PLAN2 + ~68 из 16 других проектов)

### 18.20 Техники из Omoikane (6 шт)

[Omoikane](https://github.com/steven-2/omoikane) — Rust-based Explicit HTTP/HTTPS Proxy с фокусом на TLS-фузинг (GREASE/Padding), TTL-limited injection и HTTP-обфускацию. Работает как прокси (прослушивает 127.0.0.1:8080), обрабатывает только фазу инициализации сессии.

| # | Техника | Rust модуль | Описание | Приоритет |
|--:|---------|-------------|----------|:---------:|
| OM1 | **TLS GREASE Padding Engine** | `desync::tls::grease_pad` | Вероятностная модификация ClientHello: shuffle GREASE, замена Padding→GREASE (15%), random bytes (15%), расширение/сжатие | 🔴 P3 |
| OM2 | **SNI-targeted Microfragmentation** | `desync::tls::sni_microfrag` | Фрагментация только окрестностей SNI (±N байт) чанками 1-6 байт с jitter 1-5ms | 🟡 P4 |
| OM3 | **TTL-Limited Record Header Injection** | `desync::tls::ttl_record_hdr` | Отправка 5 байт TLS Record Header с пониженным TTL (setsockopt per-packet), отбрасывается маршрутизатором | 🔴 P3 |
| OM4 | **HTTP Host Obfuscation** | `desync::http::host_obfs` | Randomized Header Casing + Dot Trick (FQDN.) + Space Trick (multi-space) + Absolute URI | 🟡 P5 |
| OM5 | **TLS Fingerprint Randomization** | `desync::tls::fingerprint_rand` | Мульти-вероятностная модель (4+ параметра) для формирования уникального TLS фингерпринта | 🟡 P3 |
| OM6 | **Xorshift64 Deterministic RNG** | `desync::rand::xorshift64` | Минималистичный RNG (<50ns per call) самописный, без крейта `rand` | 🟡 P5 |

### 18.21 Техники из offveil (9 шт)

[offveil](https://github.com/ArtemSarmogin/offveil) — Windows-only WinDivert-based DPI обходчик на Rust/Tauri. Ключевые новинки: адаптивная per-target эскалация, SNI masking на fake-пакетах, reverse fragment order.

| # | Техника | Rust модуль | Описание | Приоритет |
|--:|---------|-------------|----------|:---------:|
| OF1 | **SNI/Host Masking on Fakes** | `desync::tcp::sni_mask_fake` | Замена hostname → 'a'·len в fake-пакетах (сохранение точек и дефисов) | 🟡 P4 |
| OF2 | **Adaptive Per-Target Escalation** | `adaptive::target_escalate` | Per-SNI счётчик retry (7 → Extreme, 12 → IP:port fallback), TTL 10 минут, burst guard 600ms | 🟡 P4 |
| OF3 | **Reverse Fragment Order** | `desync::tcp::reverse_frag` | Отправка фрагментов в обратном порядке: fragment 2 → fragment 1 | 🟡 P4 |
| OF4 | **Passive RST Drop with IP ID Heuristics** | `infra::rst_drop::ip_id_heuristic` | Дроп RST с IPv4 ID < 0x000F (известная сигнатура DPI injection) | 🟡 P4 |
| OF5 | **DNS TXID-aware Flow Tracking** | `dns::txid_tracker` | Маппинг DNS запросов→ответов через (client_ip, client_port, TXID) | 🟡 P4 |
| OF6 | **Fragment Chunk Mode** | `desync::tcp::frag_chunk` | Деление TCP payload на N сегментов размера S (ChunkSize=8 → много мелких сегментов) | 🟡 P5 |
| OF7 | **Byte-Accurate SNI Split** | `desync::tls::sni_byte_split` | Парсинг TLS ClientHello → точное байтовое смещение SNI value (не SNI extension start) | 🔴 P3 |
| OF8 | **QUIC Long-Header Detection + Drop** | `desync::quic::long_hdr_drop` | Дроп QUIC long-header пакетов с non-zero версией (RFC 9000) | 🟡 P6 |
| OF9 | **Profile Composition Pattern** | `adaptive::profile` | ConfigurableProfile + PacketAction enum (SendOriginal/Modified/Multiple/Drop) как альтернатива Strategy trait | 🟡 P5 |

### 18.22 Техники из Vane (10 шт)

[Vane](https://github.com/luluwux/Vane) (vanetools) — Rust/Tauri GUI-оркестратор для zapret winws/nfqws с уникальной инфраструктурой: Job Object, DoH forwarder, DNS Guard, auto-optimizer, Minisign Ed25519.

| # | Техника | Rust модуль | Описание | Приоритет |
|--:|---------|-------------|----------|:---------:|
| VA1 | **DNS Guard** | `infra::dns_guard` | Авто-проверка DNS при старте, принудительная установка Cloudflare (1.1.1.1) при обнаружении провайдерского DNS | 🟡 P1 |
| VA2 | **Local DoH Forwarder (UDP→HTTPS)** | `infra::doh_forwarder` | Локальный DNS-over-HTTPS прокси на 127.0.0.1:5300, шифрование DNS всей системы без модификации Windows DNS Client | 🟡 P5 |
| VA3 | **Multi-Target Auto-Optimizer** | `adaptive::auto_optimizer` | Перебор встроенных пресетов с real-world тестами (YouTube + Discord + Twitter), эвристический early exit, scoring = success*10000 − latency | 🟡 P5.5 |
| VA4 | **Windows Job Object Cleanup** | `infra::job_object` | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — ядерная гарантия убийства дочерних процессов при аварийном выходе | 🟡 P9 |
| VA5 | **Graceful Shutdown Engine** | `infra::graceful_shutdown` | CTRL_BREAK_EVENT перед force-kill, ожидание 500ms (опрос 10ms) для корректного закрытия WinDivert handles | 🟡 P9 |
| VA6 | **Event-Driven Network Monitor** | `infra::net_monitor` | Win32 message-only window + RegisterDeviceNotificationW + WM_DEVICECHANGE (zero CPU polling) | 🟡 P9 |
| VA7 | **Multi-Layer Arg Sanitization** | `infra::arg_sanitizer` | Defense-in-depth: frontend → backend whitelist (30 префиксов) → shell-char фильтр, MAX_ARG_COUNT=30, MAX_ARG_LEN=128 | 🟡 P9 |
| VA8 | **Minisign Ed25519 Supply-Chain Security** | `infra::minisign_verify` | Верификация удалённых конфигураций/пресетов через Ed25519 подпись, защита от supply-chain атак | 🟡 P9 |
| VA9 | **Auto Cleanup Zombie Processes + WinDivert** | `infra::zombie_cleanup` | taskkill висящих процессов + sc delete WinDivert (STOPPED/START_PENDING) при старте | 🟡 P1 |
| VA10 | **ICMP Health Check + Latency Measurement** | `infra::icmp_health` | ping 1.1.1.1 с парсингом вывода (поддержка разных локалей), измерение реальной задержки без DPI-инфляции | 🟡 P5.5 |

### 18.23 Техники из SpoofDPI (6 шт)

[SpoofDPI](https://github.com/xvzc/SpoofDPI) — Go DPI-bypass tool. Уникальные подходы к фрагментации, DNS оптимизации и маршрутизации. Заимствованы в Rust-реализацию FreeDPI.

**Ключевые отличия от других проектов:**
- TOML-конфигурируемые segment plans с noise-параметром (нет ни в одном другом DPI-bypass)
- Гарантированный split coverage через 64-битную маску (каждый 8-битный блок ≥1 split-точка)
- Parallel dial для DNS (race connection к N IP)
- Wildcard domain trie с `*`/`**` + specificity ranking

| # | Техника | Rust модуль | Описание | Приоритет |
|---|---------|-------------|----------|:---------:|
| SP1 | **Custom Segment Plans + Noise** | `desync::segment_plan` | TOML-конфигурация точных позиций split в ClientHello с параметром noise (±N байт jitter). Планы сортируются по позиции независимо от порядка объявления. Noise делает каждый пакет уникальным — DPI не может натренировать паттерн фрагментации | 🔴 **P11.1** |
| SP2 | **Xorshift Random Split Mask** | `desync::rand::gen_split_mask` | Генерация 64-битной split-маски через Xorshift64 PRNG с guaranteed coverage (≥1 split-точки на каждый 8-битный блок). Маска определяет позиции split: бит N = split на позиции base+N. Недетерминированный, но гарантированный coverage | 🔴 **P11.1** |
| SP3 | **Parallel Dial (Race Connection)** | `dns::parallel_dial` | DNS возвращает N A/AAAA записей → подключаемся ко всем параллельно через tokio::spawn, берём первый успешный (mpsc::channel). Снижает latency на 40-60% при multi-homed доменах (Cloudflare, CDN). Макс. 10 parallel conns, per-addr timeout | 🟡 **P11.2** |
| SP4 | **Dual-Stack Hop Learning** | `adaptive::hop_tab::estimate_udp` | Расширение HopTab для UDP: `estimate_udp(recv_ttl, src_port)` определяет hop count для QUIC/UDP пакетов. Сейчас HopTab работает только с TCP (SYN-ACK). UDP sniffer нужен для fake QUIC Initial TTL | 🟡 **P11.2** |
| SP5 | **Domain Trie (Wildcard Matching)** | `routing::domain_trie` | Patricia trie для доменных имён с wildcard-матчингом: `*` = один уровень (`*.google.com`), `**` = multi-level (`**.ru`). Case-insensitive. Специфичность: `www.google.com` > `*.google.com` > `**.com`. O(1) lookup вместо линейного DashSet | 🟡 **P11.3** |
| SP6 | **Per-Rule Config Override** | `config::rule_override` | Каждый домен или CIDR-блок может переопределять split_size, split_count, disorder, ttl_offset, fake_count, inject_delay_us, skip. Приоритет: domain > cidr > global. Формат TOML: `[[rules]] domain = "*.google.com" split_size = 2 disorder = true` | 🟡 **P11.3** |

**Детали реализации:**

#### SP1: Custom Segment Plans + Noise

```toml
# Пример TOML-конфига
name = "aggressive"
[[plans]]
ref_point = "sni"    # "head" (начало пакета) или "sni" (начало SNI)
offset = 0           # смещение от ref в байтах
lazy = false         # TTL=1 для disorder
noise = 3            # ±random(3) байт jitter

[[plans]]
ref_point = "sni"
offset = 10
lazy = true
noise = 5
```

- `resolve(sni_offset)` → `Vec<SplitPosition>` (отсортированные по position)
- Noise применяется per-packet: `position = base + offset + random(0..=noise)`
- Lazy-сегменты отправляются с TTL=1 (умирают у первого хопа, DPI видит)

#### SP2: Xorshift Random Split Mask

```rust
// Генерация маски
let mask = gen_split_mask(); // 64-битная маска
// Каждый 8-битный блок гарантированно содержит ≥1 бит

// Извлечение позиций
let positions = mask_to_positions(mask, base_offset);
// → [base+2, base+5, base+11, base+14, ...]
```

- Гарантия: каждый 8-битный блок маски содержит ≥1 split-точку
- Если блок пустой → заменяем на случайный бит (fallback)
- ~1ns на генерацию (Xorshift64, без модулей)

#### SP3: Parallel Dial

```rust
let result = dial_fastest(&addrs, 443, Duration::from_secs(3)).await;
// addrs = [142.250.185.46, 142.250.185.78, ...]
// Все IP подключаются параллельно, первый успешный →返回
```

- Все подключения через `tokio::spawn` + `mpsc::channel`
- Первый успешный → `DialResult { addr, stream }`
- Неуспешные автоматически отменяются (dropped sender)

#### SP5: Domain Trie Specificity

```
www.google.com → exact match (false)
mail.google.com → *.google.com (true)
example.com → **.com (false)
```

Алгоритм: exact child > single wildcard > multi wildcard > inherited. Первый `Some()` на возврате → immediately return (нет перезатирания deeper matches).

### 18.24 Сводная таблица по новым проектам (+31 техника)

| Категория | Omoikane | offveil | Vane | SpoofDPI | **Новых** |
|-----------|:--------:|:-------:|:----:|:--------:|:---------:|
| TCP Split/Disorder | 1 (OM2) | 2 (OF3, OF6) | — | 2 (SP1, SP2) | **5** |
| Fake Injection | 1 (OM3) | 2 (OF1, OF2) | — | — | **3** |
| TCP Window/MSS | — | — | — | — | **0** |
| IP Level | — | — | — | — | **0** |
| TLS/HTTPS | 3 (OM1, OM5, OM2) | 1 (OF7) | — | — | **4** |
| QUIC/UDP | — | 1 (OF8) | — | 1 (SP4) | **2** |
| DNS | — | 1 (OF5) | 2 (VA1, VA2) | 1 (SP3) | **4** |
| Proxy Fallback | — | — | — | — | **0** |
| Obfuscation | 1 (OM4) | — | — | — | **1** |
| Adaptive | — | 1 (OF2) | 1 (VA3) | — | **2** |
| Split Tunneling | — | — | — | — | **0** |
| Routing/Geo | — | — | — | 1 (SP5) | **1** |
| Per-Rule Config | — | — | — | 1 (SP6) | **1** |
| Infrastructure | — | — | 5 (VA4-VA7, VA9) | — | **5** |
| Security | — | — | 1 (VA8) | — | **1** |
| Crypto/Encryption | — | — | 1 (VA2) | — | **1** |
| Monitoring | 1 (OM6) | 1 (OF9) | 1 (VA10) | — | **3** |
| **Итого** | **6** | **9** | **10** | **6** | **~31** |

> После дедупликации с существующими 150 техниками: **~170 уникальных техник** (+20 действительно новых)

---

## 19. Фазы реализации (финальные)

| Фаза | Содержание | Техник | Ключевые новинки | Срок |
|------|-----------|:------:|:-----------------:|:----:|
| **P0** | **Rust workspace + WinDivert + raw socket + tokio + rayon + HTTP API + classifier fix | 6 | — | 2 нед |
| **P0.1** | **Sentinel file + Strategy Trait + Thread-Local Hot Path + Synthetic Event Tagging** | 4 | DR1, AD2, OL1, OL2 | 1 нед |
| **P0.2** | **SEQ Number Spoofing + TLS CH Generator + HopTab** | 3 | SR1, SR2, DP1 | 1 нед |
| **P1** | Split tunneling + DNS engine (DoH/DoT/cache) + **FakeIP DNS** + **Probe/Tune/Run** + **Strategy Persistence** + **DNS Guard** + **Zombie Cleanup** | 16 | SB7, DA2, AD1, AD3, AD4, **VA1, VA9** | 3 нед |
| **P1.5** | **DesyncGroup + Plan+Execute + Adaptive Offset Planning** + Geo-routing + Proxy Chain | 12 | RP1, RP2, RP9, N1-N9, DA1, DA3 | 3 нед |
| **P2** | Bye-dpi FFI bridge + desync core + conntrack + **RawBackend + Sniffer** | 22 | SR3, SR4, RP11 | 3 нед |
| **P3** | **TCP desync v2**: Combo, ExtSplit, SeqOverlap, TLS mutation, uTLS, Chrome JA3, **Disorder, MultiDisorder, OOB/DisOOB, HostFake** + **ChaCha20** + **TTL jitter** + **TLS GREASE Padding** + **TTL-Limited Record Injection** + **TLS Fingerprint Randomization** + **Byte-Accurate SNI Split** | 28 | B1-B5, SB1, SB2, SB5, NP1-NP3, RP3-RP6, CT2, CT3, **OM1, OM3, OM5, OF7** | 4 нед |
| **P4** | Fake injection: syndata, SNI, OOB, RST, **FakeRst**, **RST protection**, **Window manip**, **Decoy**, **Post-desync**, **Fake overlap**, **XOR First N**, **Byte-by-byte**, **Port Shuffle**, **Packet size padding**, **Random DSCP** + **SNI masking on fakes** + **Adaptive per-target escalation** + **Reverse frag order** + **Passive RST drop IP ID** + **SNI-targeted microfrag** | 25 | B8, B10-B12, B4, RP7, RP14, DM1, RN1, CT8, CT5, CT4, **OF1-OF4, OM2** | 4 нед |
| **P5** | Windows-эксклюзив: IP frag overlap, MSS clamp, ACK suppress, reorder, **Incoming manip**, **SYN MD5**, **BadTLS**, **NP4**, **Entropy Padding**, **Poisson Shaping**, **TLS Choreography**, **TSval MD5**, **Mutual IP Spoof**, **Unidir Frag**, **Host-space**, **Title-case** + **HTTP Host Obfuscation** + **Fragment Chunk Mode** + **Profile Composition** + **Xorshift64 RNG** + **DoH Forwarder** | 25 | B9, B13, SB3, NP4, RP8, RP12, RP13, QL1, CT1, RN2, RH1, RH2, **OM4, OM6, OF6, OF9, VA2** | 4 нед |
| **P5.5** | **Fallback Chain** + Strategy Evolution + Per-app routing + **Detect & Escalate** + **Hybrid strategy** + **Auto-Optimizer** + **ICMP Health** | 12 | RP10, B7, B14, N6-N9, **VA3, VA10** | 2 нед |
| **P6** | QUIC Engine + **Fake QUIC Initial** + **SIP mask** + UDP обфускация + badsum + **Multiqueue** + **QUIC Long-Header Detection** | 19 | B6, FS1, FS3, QL3, **OF8** | 3 нед |
| **P7** | Proxy Fallback + Free pool + **Multi-session** + **Preamble** + **Reality** + **Multiplexing** + **XOR FEC** + **IPIP tunnel** | 14 | NP5, NP6, SB4, SB6, CT6, CT7, CT9 | 3 нед |
| **P7.5** | **HTTP API v2**: Strategy fine-tuning endpoints + Webhook + Bulk | 4 | API расширение | 1 нед |
| **P8** | Rust-миграция bye-dpi (удаление FFI) + Adaptive DPI + **Post-Quantum** + **Lua strategies** | 14 | NP7, RP15 | 3 нед |
| **P9** | **Supervisor/Worker** + **interprocess IPC** + **Task Scheduler** + **UWP** + **Firewall** + **PAC** + System tray + Windows Service + installer + **Job Object Cleanup** + **Graceful Shutdown** + **Event-Driven Net Monitor** + **Arg Sanitizer** + **Minisign Ed25519** | 15 | QL2, OL3, DR2-DR6, **VA4-VA8** | 3 нед |
| **P10** | **Полноценный GUI** (Tauri v2 + React + i18n) | — | System tray, Dashboard, 5 panels | 2 нед |
| **P11** | **SpoofDPI-derived фичи**: Custom Segment Plans + Noise, Xorshift Random Split Mask, Parallel Dial, Dual-Stack Hop Learning, Domain Trie, Per-Rule Config Override | 6 | SP1-SP6 | 1 нед |
| | **Итого: ~180 техник** | **~206** | **+6 из SpoofDPI** | **~40 нед** |

---

## 20. HTTP API для агента (fine-tuning и тестирование)

### 20.1 Архитектура

Встраиваем HTTP API сервер (Axum) непосредственно в service-крейт.
Агент (OpenCode, другой AI) взаимодействует через REST для тестирования стратегий,
подстройки параметров и мониторинга без GUI.

```
┌─────────────────────────────────────────────┐
│              FreeDPI-win                    │
│                                               │
│  ┌──────────┐   ┌──────────────────────────┐ │
│  │  Engine   │──►│  HTTP API (Axum :11337)  │ │
│  │  (core)   │◄──│                          │ │
│  └──────────┘   │  GET  /api/v1/status      │ │
│                  │  POST /api/v1/strategies/ │ │
│                  │  test                     │ │
│                  │  GET  /api/v1/strategies/ │ │
│                  │       stats               │ │
│                  │  POST /api/v1/strategies/ │ │
│                  │       tune                │ │
│                  │  GET  /api/v1/conntrack   │ │
│                  │  GET  /api/v1/dns/cache   │ │
│                  │  POST /api/v1/routing/    │ │
│                  │       override            │ │
│                  │  GET  /api/v1/health      │ │
│                  └──────────────────────────┘ │
│                                               │
│  ┌──────────────────────────┐                 │
│  │  Auth: API key в заголовке│                 │
│  │  X-API-Key: <key>       │                 │
│  └──────────────────────────┘                 │
└─────────────────────────────────────────────┘
         ▲
         │ HTTP (localhost only)
         │
┌────────┴────────┐
│   AI Agent       │
│  (OpenCode)      │
└─────────────────┘
```

### 20.2 Спецификация эндпоинтов

#### `GET /api/v1/status`

```json
{
  "status": "running",
  "uptime_seconds": 3600,
  "version": "0.1.0",
  "packets_processed": 1500000,
  "active_connections": 342,
  "current_strategy": 12,
  "cpu_usage_percent": 8.2,
  "memory_mb": 4.7
}
```

#### `POST /api/v1/strategies/test`

Тестирование стратегии на конкретном домене. Агент может быстро проверить,
какая стратегия работает без перезапуска.

```json
{
  "domain": "rutracker.org",
  "strategy_id": 42,
  "timeout_ms": 5000,
  "params": {
    "frag_size": 128,
    "split_positions": [1, 200],
    "fake_sni": "www.google.com",
    "ttl": 64
  }
}
```

Ответ:
```json
{
  "test_id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "rutracker.org",
  "strategy_id": 42,
  "success": true,
  "latency_ms": 120,
  "handshake_completed": true,
  "first_byte_ms": 45,
  "notes": "TLS handshake OK, ServerHello received"
}
```

#### `GET /api/v1/strategies/stats`

```json
{
  "domains": {
    "rutracker.org": {
      "best_strategy": 42,
      "total_attempts": 15,
      "success_rate": 0.87,
      "strategies": {
        "42": { "success_count": 12, "fail_count": 3, "level": 5 },
        "17": { "success_count": 1, "fail_count": 5, "level": 1 }
      }
    },
    "youtube.com": {
      "best_strategy": 7,
      "total_attempts": 30,
      "success_rate": 0.93
    }
  },
  "global_rotation_counter": 1523
}
```

#### `POST /api/v1/strategies/tune`

Агент может изменить параметры стратегии на лету (без перезапуска):

```json
{
  "strategy_id": 42,
  "params": {
    "frag_size": 256,
    "delay_us": 500,
    "seq_overlap_bytes": 20,
    "window_manip_mode": "oscillate"
  },
  "persist": true
}
```

#### `GET /api/v1/conntrack`

```json
{
  "total": 342,
  "entries": [
    {
      "src": "192.168.1.100:54321",
      "dst": "1.2.3.4:443",
      "state": "established",
      "strategy_id": 42,
      "age_seconds": 30,
      "bytes_sent": 15000
    }
  ]
}
```

#### `GET /api/v1/dns/cache`

```json
{
  "total": 150,
  "entries": {
    "rutracker.org": "195.82.146.214",
    "youtube.com": "142.250.185.46"
  }
}
```

#### `POST /api/v1/routing/override`

```json
{
  "domain": "netflix.com",
  "region": "europe",
  "ttl_minutes": 60
}
```

Переопределяет geo-маршрут для домена. Полезно, когда агент нашёл,
что Netflix требует EU-IP, но классификатор ошибочно определил его как RU.

#### `GET /api/v1/health`

```json
{
  "healthy": true,
  "windivert_ok": true,
  "raw_socket_ok": true,
  "dns_resolver_ok": true,
  "last_error": null,
  "uptime_seconds": 3600
}
```

### 20.3 Rust-реализация

```rust
// api/src/lib.rs
use axum::{
    Router, Json, extract::State, routing::{get, post},
    middleware,
};
use std::sync::Arc;

/// Состояние API, разделяемое между эндпоинтами
pub struct ApiState {
    pub engine: Arc<EngineHandle>,
    pub config: Arc<Config>,
}

/// Запуск API сервера на указанном порту
pub async fn serve(engine: Arc<EngineHandle>, config: Arc<Config>, port: u16) {
    let state = Arc::new(ApiState { engine, config });
    
    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/strategies/test", post(test_strategy_handler))
        .route("/api/v1/strategies/stats", get(strategy_stats_handler))
        .route("/api/v1/strategies/tune", post(tune_strategy_handler))
        .route("/api/v1/conntrack", get(conntrack_handler))
        .route("/api/v1/dns/cache", get(dns_cache_handler))
        .route("/api/v1/routing/override", post(routing_override_handler))
        .route("/api/v1/health", get(health_handler))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(state);
    
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("API server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Auth middleware: проверяет X-API-Key из конфига
async fn auth_middleware<B>(
    req: axum::http::Request<B>,
    next: middleware::Next<B>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let config = req.extensions().get::<Arc<Config>>();
    if let Some(cfg) = config {
        if let Some(key) = req.headers().get("X-API-Key") {
            if key == cfg.api_key.as_str() {
                return Ok(next.run(req).await);
            }
        }
    }
    Err(axum::http::StatusCode::UNAUTHORIZED)
}
```

### 20.4 Безопасность

- API слушает **только localhost** (127.0.0.1) — не доступен из сети
- Аутентификация через `X-API-Key` (генерируется при первом запуске)
- Rate limiting: 100 req/min для тестовых эндпоинтов
- Все write-операции логируются с аудитом

---

## 21. Обновлённые риски

| Риск | Вероятность | Влияние | Митигация |
|------|:----------:|:-------:|-----------|
| Geo-routing может ошибаться | Medium | Low | 3-уровневый fallback + user override |
| Opera VPN прокси часто умирают | High | Low | Bad route cache + health checks |
| Per-app routing можно обойти | Low | Low | WinDivert перехват всегда работает |
| Strategy evolution долго учится | Medium | Low | Seed-данные из Nova + предзаданные профили |
| **HTTP API без auth** | Low | High | localhost-only + X-API-Key (генерация при первом запуске) |
| **TLS Spoof неправильный SEQ** | Medium | Medium | SeqOverlap отключается при conflict |
| **SeqOverlap + WinDivert race** | Medium | Medium | Raw socket bypass для overlap-пакетов |
| **b4 техники не работают на Windows** | Medium | High | Тестирование на реальном DPI провайдере |
| **SEQ Spoofing не совместим с некоторыми DPI** | Medium | High | Fallback на другие стратегии (Registry) |
| **HopTab неверные hops (NAT/SNI)** | Medium | Medium | Close-host check (hops ≤ 2 → отключить TTL desync) |
| **ChaCha20 latency > 5µs per-packet** | Low | Medium | SIMD-оптимизации, portable fallback |
| **Sentinel file не создаётся (нет ProgramData)** | Low | Medium | Fallback на %APPDATA%/ByeDPI/ |

---

## 22. Новые архитектурные паттерны (из 11 Rust-проектов)

### 22.1 Trait-based Strategy System (autodpi)

```rust
/// Каждая стратегия —独立ный объект с Trait.
/// Реестр позволяет добавлять новые стратегии без изменения dispatcher'а.
pub trait Strategy: Send + Sync {
    fn id(&self) -> u32;
    fn name(&self) -> &'static str;
    fn apply(&self, pkt: &mut Packet, ctx: &StrategyCtx) -> Result<StrategyResult>;
    fn applicable(&self, pkt: &Packet) -> bool;  // activation filter
}

/// Глобальный реестр (singleton)
pub struct StrategyRegistry {
    strategies: DashMap<u32, Box<dyn Strategy>>,
}

impl StrategyRegistry {
    pub fn global() -> &'static Self { /* OnceLock */ }
    pub fn register(&self, s: Box<dyn Strategy>);
    pub fn apply(&self, id: u32, pkt: &mut [u8], ctx: &StrategyCtx) -> Result<StrategyResult>;
}
```

### 22.2 Probe/Tune/Run Three-Phase Strategy Selection (autodpi)

```
Фаза 1: PROBE
├── Открыть N соединений (N = кол-во стратегий)
├── Каждое соединение → своя стратегия
├── Таймаут: 3 секунды на соединение
└── Результат: топ-3 успешных стратегии

Фаза 2: TUNE
├── Взять топ-3 стратегии
├── Для каждой: проверить с 3 разными наборами параметров
├── Таймаут: 2 секунды на вариацию
└── Результат: лучшая стратегия + параметры

Фаза 3: RUN
├── Использовать выбранную стратегию для всех соединений к домену
├── Если стратегия падает 3 раза подряд → вернуться к PROBE
└── Кэшировать результат на 5 минут
```

### 22.3 DesyncGroup Pipeline (RIPDPI)

```rust
/// DesyncGroup: последовательность desync-операций, применяемых к одному пакету.
/// Каждая операция получает на вход результат предыдущей.
pub struct DesyncGroup {
    operations: Vec<Box<dyn DesyncOp>>,
}

impl DesyncGroup {
    pub fn execute(&self, pkt: &mut Packet, ctx: &StrategyCtx) -> Result<()> {
        for op in &self.operations {
            op.apply(pkt, ctx)?;
        }
        Ok(())
    }
}

/// Пример: DesyncGroup для Fake CH + split
let group = DesyncGroup::new(vec![
    Box::new(FakeSniOp::new("www.google.com")),  // 1. Fake SNI
    Box::new(SplitOp::new(&[1, 200, 400])),       // 2. Split в 3 сегмента
    Box::new(ReorderOp::new(&[2, 0, 1])),          // 3. Реордеринг
]);
```

### 22.4 Plan+Execute Architecture (RIPDPI)

Разделение на две фазы:
1. **Plan**: Анализ ClientHello → построение оптимальной последовательности операций
2. **Execute**: Применение плана к пакету

```rust
pub struct Plan {
    operations: Vec<PlanStep>,
}

pub struct Planner;

impl Planner {
    /// Анализ CH → генерация плана
    pub fn plan(ch: &ClientHello, config: &Config) -> Plan {
        let mut ops = Vec::new();
        
        // Adaptive offset: размер CH определяет позиции split
        let ch_len = ch.raw().len();
        if ch_len > 500 {
            ops.push(PlanStep::Split { positions: &[1, 200] });
        } else {
            ops.push(PlanStep::Split { positions: &[1] });
        }
        
        // Если SNI в конце CH → disorder выгоднее
        if ch.sni_position() > ch_len / 2 {
            ops.push(PlanStep::Disorder { segments: 3 });
        }
        
        Plan { operations: ops }
    }
}
```

### 22.5 HopTab — Hop Cache (dpibreak)

Кэш {dst_ip → hops} на 256 записей (circular buffer). Определяет количество хопов 
до сервера по входящему TTL, чтобы выставить fake TTL гарантированно меньше hops.

```rust
pub struct HopTab {
    cache: [(u32, u8); 256],  // (ip_hash → hops)
    cursor: AtomicU8,
}

impl HopTab {
    /// Оценка hops: init_ttl - recv_ttl
    /// init_ttl = 64 (если ≤ 64), 128 (если ≤ 128), 255 (иначе)
    pub fn estimate(recv_ttl: u8) -> u8;
    
    /// Fake TTL: гарантированно < hops, чтобы пакет НЕ дошёл до сервера
    pub fn fake_ttl(&self, dst_ip: u32) -> Option<u8>;
}
```

### 22.6 Synthetic Event Tagging (OpenLogi)

Каждый injected пакет маркируется UUID-тегом (первые 16 байт payload).
WinDivert фильтр: `not ip.DstAddr == 127.0.0.1 and not tcp.PayloadLength < 16` 
плюс проверка тега в callback'е.

```rust
thread_local! {
    static TAG: RefCell<[u8; 16]> = RefCell::new(*Uuid::new_v4().as_bytes());
}

pub fn tag_packet(pkt: &mut [u8]) {
    TAG.with(|tag| { if pkt.len() >= 16 { pkt[..16].copy_from_slice(&tag); }});
}
```

### 22.7 Sentinel File System (DPIReaper)

Механизм file-based безопасной остановки.

```
Принцип работы:
1. При старте engine: создать C:\ProgramData\ByeDPI\sentinel
2. Фоновый поток: каждые 5 сек проверять exists(sentinel)
3. Если файл удалён → engine::stop() (flush, close sockets, exit)
4. recovery: systemctl restart byedpi (или создать файл вручную)

Использование:
- GUI: кнопка "Stop" → удалить sentinel
- Отказ GUI: удалить файл вручную через Проводник
- Краш: sentinel остаётся → при следующем запуске engine продолжает
```

### 22.8 Thread-Local Hot Path (OpenLogi)

```rust
use std::cell::RefCell;

/// Статистика на hot path: 0 блокировок, 0 атомиков
thread_local! {
    pub static PKT_STATS: RefCell<PacketStats> = const { 
        RefCell::new(PacketStats::new()) 
    };
}

/// Вызов на каждый пакет — просто инкремент thread_local счётчика
pub fn record_packet() {
    PKT_STATS.with(|stats| {
        let mut s = stats.borrow_mut();
        s.total += 1;
    });
}

/// Агрегация: сбор статистики со всех потоков
pub fn aggregate_stats() -> PacketStats {
    // Использование: tokio::spawn на каждом rayon worker'е
    unimplemented!("P9: collect from all threads via IPC")
}
```

### 22.9 TCP SEQ Number Spoofing (sni-spoofing-rust)

**Математика:**
```
SYN:      client(SEQ=1000)  → server
SYN-ACK:  client(ACK=1001)  ← server(SEQ=5000)
FAKE CH:  client(SEQ=10000) → DPI (out-of-window!)
REAL CH:  client(SEQ=1001, ACK=5001) → server (correct SEQ)
          DPI собирает fake CH как "ClientHello"
          Сервер принимает real CH, игнорирует fake
```

**Требования для реализации:**
1. Raw socket (IP_HDRINCL) — полный контроль TCP SEQ
2. HopTab для fake TTL — fake CH не должен дойти до сервера
3. ClientHello generator — создание CH без дампа
4. TCP checksum: fake CH с badsum (dpibreak) ИЛИ правильная (sni-spoofing-rust)

### 22.10 ChaCha20 Per-Packet Obfuscation (CandyTunnel)

```rust
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, KeySizeUser};

/// Per-packet: уникальный nonce = packet_counter (64-bit LE)
/// Ключ: глобальный, 256-bit, генерируется при старте
pub fn obfuscate_packet(pkt: &mut [u8], counter: u64) {
    let key = GLOBAL_KEY.load();  // OnceCell<[u8; 32]>
    let nonce = counter.to_le_bytes();
    let mut cipher = ChaCha20::new(key.as_ref().into(), &nonce.into());
    cipher.apply_keystream(pkt);
}

/// DPI видит: случайные байты → не может определить протокол
/// Сервер: дешифрует тем же ключом + nonce = packet_counter
/// Примечание: только для туннельного режима (IPIP/GRE), не для прямых соединений
```

### 22.11 TLS GREASE Padding Engine + Fingerprint Randomization (Omoikane)

Мульти-вероятностная модель модификации TLS ClientHello для создания уникального,
недетектируемого фингерпринта (против DPI, анализирующих JA3/JA3S).

```
┌──────────────────────────────────────────────────────────┐
│                 TLS Fingerprint Randomizer                │
│                                                          │
│  1. Парсинг ClientHello через tls-parser                 │
│  2. Перемешивание GREASE (0x?A?A) в Cipher Suites       │
│     (75% лёгкий профиль: +194..520 байт padding)        │
│     (25% тяжёлый профиль: +780..1850 байт padding)      │
│  3. Замена Padding Extension 0x0015 → GREASE 0x?A?A     │
│     (15% вероятность)                                    │
│  4. Random bytes вместо нулей в padding                  │
│     (15% вероятность, повышение энтропии)                │
│  5. SNI Case Randomization                               │
│     (10% вероятность upper-case для каждой буквы)        │
│  6. Shuffle Supported Groups / Versions                  │
│                                                          │
│  Результат: каждый ClientHello уникален                  │
│  DPI не может составить стабильный JA3 fingerprint       │
└──────────────────────────────────────────────────────────┘
```

```rust
/// Параметры вероятностной модели
pub struct GreaseConfig {
    /// Вероятность лёгкого профиля (75%)
    pub light_profile_ratio: f64,
    /// Вероятность замены Padding→GREASE (15%)
    pub grease_type_ratio: f64,
    /// Вероятность random bytes в padding (15%)
    pub byte_entropy_ratio: f64,
    /// Вероятность upper-case для букв SNI (10%)
    pub sni_case_ratio: f64,
    /// Лёгкий профиль: дельта padding
    pub light_padding_delta: Range<usize>,    // 194..520
    /// Тяжёлый профиль: дельта padding
    pub heavy_padding_delta: Range<usize>,    // 780..1850
}

/// Модификация ClientHello
pub fn transform_client_hello(
    raw_ch: &[u8],
    config: &GreaseConfig,
    rng: &mut Xorshift64,
) -> Result<Vec<u8>> {
    // 1. Парсинг через tls-parser
    let ch = parse_client_hello(raw_ch)?;
    // 2. Выбор профиля padding
    let delta = if rng.gen_f64() < config.light_profile_ratio {
        config.light_padding_delta.sample(rng)
    } else {
        config.heavy_padding_delta.sample(rng)
    };
    // 3. Модификация extensions
    let mut modified = ch.raw().to_vec();
    shuffle_grease(&mut modified, rng);
    maybe_replace_padding_with_grease(&mut modified, config, rng);
    maybe_random_byte_padding(&mut modified, config, rng);
    maybe_randomize_sni_case(&mut modified, config, rng);
    shuffle_supported_groups(&mut modified, rng);
    // 4. Расширение/сжатие padding extension
    adjust_padding_extension(&mut modified, delta);
    Ok(modified)
}
```

### 22.12 TTL-Limited Record Header Injection (Omoikane + offveil hybrid)

Отправка минимального TLS Record заголовка (5 байт) с пониженным TTL, который
гарантированно отбрасывается маршрутизатором, но перехватывается DPI.

```rust
/// TTL-Limited Injection: отправка 5 байт TLS Record с TTL=2.
/// DPI видит начало TLS-рукопожатия и "сбивается" с толку.
/// Сервер НЕ получает этот пакет (TTL истекает на промежуточном узле).
pub fn inject_ttl_limited_record(
    raw_sock: &RawSocket,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    src_ip: Ipv4Addr,
    src_port: u16,
    server_ttl: u8,  // реальный TTL до сервера
) -> Result<()> {
    // Fake TTL: гарантированно < hops до сервера
    let fake_ttl = (server_ttl / 2).max(1).min(5);
    
    // 5-байтовый TLS Record Header: ContentType=0x16, Version=0x0301, Length=0x0000
    let tls_header = vec![0x16, 0x03, 0x01, 0x00, 0x00];
    
    // Сборка TCP+IP пакета с пониженным TTL
    let packet = build_tcp_packet(
        src_ip, dst_ip, src_port, dst_port,
        0u32,       // fake SEQ
        0u32,       // fake ACK
        TCP_SYN,    // flags
        fake_ttl,   // ← пониженный TTL
        &tls_header,
    )?;
    
    raw_sock.send(&packet)
}
```

### 22.13 Adaptive Per-Target Escalation (offveil)

Per-SNI счётчик retry: после N неудачных попыток — автоматическая эскалация
на более агрессивную стратегию. Состояние отслеживается с TTL 10 минут
и burst guard 600ms (предотвращает premature escalation при параллельных
соединениях браузера).

```rust
pub struct TargetEscalation {
    /// Per-target: SNI hostname → счётчик retry
    retry_counters: DashMap<String, RetryState>,
    /// Порог для перехода на Extreme (default: 7)
    extreme_threshold: u32,
    /// Порог для IP:port fallback (default: 12)
    fallback_threshold: u32,
    /// TTL состояния (default: 10 минут)
    state_ttl: Duration,
}

struct RetryState {
    count: u32,
    last_attempt: Instant,
    escalated: bool,
}

impl TargetEscalation {
    /// При неудачной попытке: инкремент счётчика
    pub fn record_failure(&self, target: &str) {
        self.retry_counters.entry(target.to_string())
            .and_modify(|s| {
                s.count += 1;
                s.last_attempt = Instant::now();
            })
            .or_insert(RetryState {
                count: 1,
                last_attempt: Instant::now(),
                escalated: false,
            });
    }
    
    /// Выбор профиля на основе истории retry
    pub fn select_profile(&self, target: &str) -> ProfileLevel {
        if let Some(state) = self.retry_counters.get(target) {
            // Burst guard: если последняя попытка < 600ms — не эскалируем
            if state.last_attempt.elapsed() < Duration::from_millis(600) {
                return ProfileLevel::Normal;
            }
            if state.count >= self.fallback_threshold {
                return ProfileLevel::Fallback;
            }
            if state.count >= self.extreme_threshold {
                return ProfileLevel::Extreme;
            }
        }
        ProfileLevel::Normal
    }
    
    /// Очистка истёкших состояний (фоновая задача)
    pub fn expire_stale(&self) {
        self.retry_counters.retain(|_, state| {
            state.last_attempt.elapsed() < self.state_ttl
        });
    }
}
```

### 22.14 DNS TXID-aware Flow Tracking (offveil)

Маппинг DNS запросов→ответов через (client_ip, client_port, TXID).
Позволяет корректно обрабатывать конкурентные DNS запросы с одного порта.

```rust
/// Ключ: (клиентский IP, клиентский порт, DNS Transaction ID)
type DnsFlowKey = (Ipv4Addr, u16, u16);

/// Состояние DNS потока
struct DnsFlowState {
    original_dns_server: Ipv4Addr,
    original_dns_port: u16,
    timestamp: Instant,
}

/// TXID-aware DNS flow tracker
pub struct DnsTxidTracker {
    flows: DashMap<DnsFlowKey, DnsFlowState>,
    ttl: Duration,
}

impl DnsTxidTracker {
    /// Захват DNS запроса к оригинальному DNS серверу
    pub fn capture_request(
        &self,
        client_ip: Ipv4Addr,
        client_port: u16,
        txid: u16,
        dns_server: Ipv4Addr,
        dns_port: u16,
    ) {
        self.flows.insert(
            (client_ip, client_port, txid),
            DnsFlowState {
                original_dns_server: dns_server,
                original_dns_port: dns_port,
                timestamp: Instant::now(),
            },
        );
    }
    
    /// Маршрутизация DNS ответа к оригинальному серверу
    pub fn resolve_response(
        &self,
        client_ip: Ipv4Addr,
        client_port: u16,
        txid: u16,
    ) -> Option<(Ipv4Addr, u16)> {
        self.flows.get(&(client_ip, client_port, txid))
            .map(|state| (state.original_dns_server, state.original_dns_port))
    }
    
    /// Подмена TXID в DNS ответе (оригинальный → перенаправленный)
    pub fn rewrite_response_txid(
        response: &mut [u8],
        original_txid: u16,
    ) {
        if response.len() >= 2 {
            response[0..2].copy_from_slice(&original_txid.to_be_bytes());
        }
    }
}
```

### 22.15 Passive RST Drop with IP ID Heuristics (offveil)

Многие ISP (особенно РФ) инжектируют RST-пакеты с низким IPv4 ID (0x0000..0x000F)
для принудительного закрытия "запрещённых" соединений. Фильтрация по IP ID
позволяет отличить DPI RST от легитимных RST сервера.

```rust
/// Проверка: является ли RST пакет DPI-инъекцией?
/// Признаки:
/// 1. IPv4 ID в диапазоне 0x0000..0x000F
/// 2. Inbound (src port 80/443)
/// 3. RST флаг установлен
pub fn is_dpi_rst_injection(ip_packet: &[u8], is_inbound: bool) -> bool {
    if !is_inbound {
        return false;
    }
    
    let ip = match Ipv4Packet::new(ip_packet) {
        Some(ip) => ip,
        None => return false,
    };
    
    // DPI RST signature: IPv4 ID < 16
    let ip_id = ip.get_identification();
    if ip_id > 0x000F {
        return false;
    }
    
    // Проверка порта (80/443)
    let header_len = (ip.get_version() as usize) * 4;
    let tcp = match TcpPacket::new(&ip_packet[header_len..]) {
        Some(tcp) => tcp,
        None => return false,
    };
    
    let dst_port = tcp.get_destination();
    let src_port = tcp.get_source();
    let is_web_port = (src_port == 80 || src_port == 443);
    let rst_flag = (tcp.get_flags() & 0x04) != 0; // TCP_RST
    
    rst_flag && is_web_port
}

/// DPI RST Drop: если RST выглядит как DPI-инъекция — дропаем
/// Если легитимный (IP ID > 0x000F) — forward
pub fn handle_rst_packet(packet: &[u8], is_inbound: bool) -> PacketAction {
    if is_dpi_rst_injection(packet, is_inbound) {
        tracing::debug!("Dropping DPI-injected RST (IP ID < 16)");
        PacketAction::Drop
    } else {
        PacketAction::Forward
    }
}
```

### 22.16 Local DoH Forwarder — система шифрования DNS (Vane)

Локальный UDP→HTTPS DNS прокси, шифрующий DNS-трафик всей системы.
Не требует модификации Windows DNS Client service.

```text
┌─────────────┐   UDP:53    ┌──────────────────┐   HTTPS (TLS)    ┌─────────────┐
│ Windows DNS  │───────────▶│  DoH Forwarder    │────────────────▶│  Cloudflare  │
│ Клиент       │◀──────────▶│  127.0.0.1:5300   │◀────────────────│  1.1.1.1/dns-query│
└─────────────┘             └──────────────────┘                  └─────────────┘
                                    │
                                    │ Concurrency limit: 100
                                    │ RAII: ForwarderHandle::stop()
                                    ▼
                            Защита от DNS Spoofing
```

```rust
/// DoH Forwarder: UDP → HTTPS (RFC 8484)
pub struct DohForwarder {
    udp_socket: UdpSocket,       // 127.0.0.1:5300
    http_client: reqwest::Client,
    endpoints: Vec<String>,      // ["https://cloudflare-dns.com/dns-query", ...]
    concurrency: Arc<Semaphore>, // max 100 concurrent
}

impl DohForwarder {
    pub async fn serve(&self) -> Result<()> {
        let mut buf = vec![0u8; 1500];
        loop {
            let (len, src) = self.udp_socket.recv_from(&mut buf).await?;
            let query = buf[..len].to_vec();
            
            let permit = self.concurrency.clone().acquire_owned().await?;
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(response) = self.forward_to_doh(&query).await {
                    self.udp_socket.send_to(&response, src).await.ok();
                }
            });
        }
    }
    
    async fn forward_to_doh(&self, query: &[u8]) -> Option<Vec<u8>> {
        // RFC 8484: POST application/dns-message
        for endpoint in &self.endpoints {
            if let Ok(resp) = self.http_client
                .post(endpoint)
                .header("Content-Type", "application/dns-message")
                .body(query.to_vec())
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                if let Ok(bytes) = resp.bytes().await {
                    return Some(bytes.to_vec());
                }
            }
        }
        None
    }
}

/// RAII handle: гарантирует чистую остановку forwarder'а
pub struct ForwarderHandle {
    cancel: tokio_util::sync::CancellationToken,
}

impl ForwarderHandle {
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}
```

### 22.17 Multi-Target Auto-Optimizer (Vane)

Автоматический перебор встроенных пресетов с real-world HTTP-тестами.
Каждый пресет запускается на 3 секунды, проверяется доступность 3 целей.
Scoring: `score = (success_count × 10000) − avg_latency`.

```rust
pub struct AutoOptimizer {
    presets: Vec<Preset>,
    targets: Vec<OptimizerTarget>,  // YouTube, Discord, Twitter (known IPs)
}

struct OptimizerTarget {
    hostname: &'static str,
    known_ips: &'static [Ipv4Addr],  // обход DNS-блокировок
    port: u16,
}

impl AutoOptimizer {
    /// Запуск оптимизации: перебор всех пресетов
    pub async fn optimize(&self) -> Result<Preset> {
        let mut best_score = 0i64;
        let mut best_preset = None;
        
        for preset in &self.presets {
            // Свежий HTTP-клиент (чтобы избежать false-negative из-за кеша)
            let client = reqwest::Client::builder()
                .no_proxy()
                .build()?;
            
            let mut success_count = 0u32;
            let mut total_latency = 0u64;
            
            for target in &self.targets {
                for ip in target.known_ips {
                    let url = format!("https://{}/", ip);
                    let start = Instant::now();
                    
                    match client.get(&url)
                        .timeout(Duration::from_secs(3))
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            success_count += 1;
                            total_latency += start.elapsed().as_millis() as u64;
                            break;  // одна успешная попытка засчитывается
                        }
                        _ => continue,
                    }
                }
            }
            
            let score = (success_count as i64 * 10000) - total_latency as i64;
            
            // Early exit: все 3 цели доступны с latency < 3s
            if score > 27000 {
                return Ok(preset.clone());
            }
            
            if score > best_score {
                best_score = score;
                best_preset = Some(preset.clone());
            }
        }
        
        best_preset.ok_or_else(|| anyhow!("No working preset found"))
    }
}
```

### 22.18 Windows Job Object — Kernel-Level Process Cleanup (Vane)

Гарантия убийства дочерних процессов даже при аварийном завершении Vane.

```rust
/// Windows Job Object: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
/// При закрытии последнего handle на job → Windows kernel убивает
/// все процессы в job. Гарантия: даже при crash/BSOD/kill процесса
/// дочерние winws.exe процессы не остаются висеть.
pub struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    pub fn new() -> Result<Self> {
        unsafe {
            let job = CreateJobObjectW(None, None);
            if job.is_invalid() {
                anyhow::bail!("CreateJobObject failed: {}", GetLastError());
            }
            
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            
            let result = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            
            if result == 0 {
                anyhow::bail!("SetInformationJobObject failed: {}", GetLastError());
            }
            
            Ok(Self { handle: job })
        }
    }
    
    /// Добавить процесс в job
    pub fn assign_process(&self, process_handle: HANDLE) -> Result<()> {
        unsafe {
            let result = AssignProcessToJobObject(self.handle, process_handle);
            if result == 0 {
                anyhow::bail!("AssignProcessToJobObject failed: {}", GetLastError());
            }
            Ok(())
        }
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle).ok();
            // Windows kernel убивает все процессы в job
        }
    }
}
```

### 22.19 Event-Driven Network Monitor (Vane)

Win32 message-only window + RegisterDeviceNotificationW для мгновенного
получения событий изменения сети (ноль CPU overhead между событиями).

```rust
/// Event-driven network monitor
/// Создаёт скрытое message-only window для получения WM_DEVICECHANGE
pub struct NetworkMonitor {
    hwnd: HWND,
    notify_handle: HDEVNOTIFY,
}

impl NetworkMonitor {
    pub fn new(tx: mpsc::Sender<NetworkEvent>) -> Result<Self> {
        unsafe {
            let instance = GetModuleHandleW(None);
            
            // Регистрируем класс окна
            let class = "NetworkMonitorWindow";
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(Self::window_proc),
                hInstance: instance,
                lpszClassName: class.encode_utf16().collect(),
                ..Default::default()
            };
            RegisterClassW(&wc);
            
            // Создаём message-only window (HWND_MESSAGE)
            let hwnd = CreateWindowExW(
                0,
                class,
                "",
                0,
                0, 0, 0, 0,
                HWND_MESSAGE,  // ← message-only!
                None,
                instance,
                Some(Box::into_raw(Box::new(tx)) as *const c_void),
            );
            
            // Регистрируем Device Notification для сетевых адаптеров
            let dbch = DEV_BROADCAST_DEVICEINTERFACEW {
                dbcc_size: size_of::<DEV_BROADCAST_DEVICEINTERFACEW>() as u32,
                dbcc_devicetype: DBT_DEVTYP_DEVICEINTERFACE,
                dbcc_classguid: GUID_DEVINTERFACE_NET,
            };
            
            let notify = RegisterDeviceNotificationW(
                hwnd,
                &dbch as *const _ as *const c_void,
                DEVICE_NOTIFY_WINDOW_HANDLE,
            );
            
            Ok(Self { hwnd, notify_handle: notify })
        }
    }
    
    /// Window procedure — получает WM_DEVICECHANGE
    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_DEVICECHANGE {
            // De-bounce 500ms
            let tx = &*(GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const mpsc::Sender<NetworkEvent>);
            let _ = tx.send(NetworkEvent::DeviceChanged);
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        unsafe {
            UnregisterDeviceNotification(self.notify_handle);
            DestroyWindow(self.hwnd);
        }
    }
}
```

---

## 22. Review.md Fixes (Performance Optimizations)

### 22.1 FIX-1: SplitTunnel Thread-Local Cache

**Проблема:** 5 DashMap lookups на пакет при 10Gbps → 15% CPU waste.

**Решение:** `thread_local! { RefCell<Vec<(u32, bool)>> }` FIFO cache (1024 entries).
`should_bypass_ip_fast()` — сначала cache lookup, потом DashMap.

### 22.2 FIX-2: Conntrack Probabilistic GC

**Проблема:** Полный итератор DashMap блокирует reactor.

**Решение:** `gc_fast()` с `iter().step_by(128)` — проверяет каждый 128-й entry.

### 22.3 FIX-3: TcpSegmentWriter — удалён (dead code)

**Было:** `TcpSegmentWriter` (struct + impl, 0 вызовов) — неиспользуемый код.

**Решение:** Удалён полностью (MR-10*). `build_ip_tcp_packet` использует `vec![0u8; total_len]`.

### 22.4 FIX-4: OOO/dup-ACK Detection

**Проблема:** Нет проверки на out-of-order и duplicate ACK.

**Решение:** `update_seq_monotonic(key, seq, ack)` — проверка delta < 1M, dup_ack_count++.

### 22.5 FIX-5: Fake CH Race Prevention (replaced by MR-07)

**Проблема:** Async desync + retransmit → fake CH после оригинала.

**Было:** `injected_seqs: DashSet<u32>` — unbounded, коллизии SEQ между разными соединениями.

**Стало (MR-07+E4):** `Arc<DashMap<(u128, u128, u16, u16, u32), Instant>>` — 5-tuple+SEQ ключ, TTL 30s.

### 22.6 FIX-6: MTU Guard

**Проблема:** Payload > MTU → silent NDIS drop.

**Решение:** `MAX_TCP_PAYLOAD = 1460` — проверка перед отправкой.

### 22.7 FIX-7: PerConnRng (Xorshift128**)

**Проблема:** Thread-local Xorshift64, seed = SystemTime → DPI предсказывает.

**Решение:** `PerConnRng` с Xorshift128** (s0 * s1 output), splitmix64 seed из Instant+conn_id. Хранится в `ConntrackEntry.rng`.

### 22.8 FIX-8: Lemire Method

**Проблема:** `random_range()` с modulo bias.

**Решение:** Power-of-two mask + Lemire's method: `min + (next_u64() as u128 * range >> 64) as u32`.

### 22.9 FIX-9: Checksum Unroll

**Проблема:** `ipv4_checksum()` через `chunks(2)` — неоптимально.

**Решение:** 20-byte manual unroll: 5 x 32-bit words → fold → carry propagation.

### 22.10 FIX-10: HashSet Dedup

**Проблема:** `random_split_positions()` O(n²) через `contains()`.

**Решение:** `HashSet` для O(1) dedup: `seen.insert(p)` вместо `positions.contains(&p)`.

---

## 23. Архитектурные изменения (v3.1 — после Meta-Review)

### 23.1 Обзор изменений

Выполнено 34 исправления на основе 9 экспертных ревью (141 находка → 30 уникальных MR). Основные архитектурные сдвиги:

| Что | Было | Стало |
|-----|------|-------|
| Packet ring | `tokio::mpsc::channel(1024)` | `crossbeam::ArrayQueue(65536)` lock-free head-drop |
| Packet type | `Vec<u8>` | `bytes::Bytes` (zero-copy refcount) |
| PRNG seed | `SystemTime::now()` | `getrandom` (OS CSPRNG) + periodic reseed |
| EventTag | `thread_local!` UUID + payload tag | **УДАЛЁН (MR-18)** — WinDivert impostor flag + IP ID tagging |
| Buffer pool | `Mutex<Vec<Vec<u8>>>` | УДАЛЁН (MR-10*): Bytes::from(vec) потребляет Vec, thread-local бесполезен |
| Inject tracking | `DashSet<u32>` (unbounded) → `InjectedSeqTracker` (HashMap+TTL) | `Arc\<DashMap\<SeqKey, Instant\>\>` (MR-07) 5-tuple+SEQ ключ |
| PacketEngine divert | `RwLock<Option<WinDivert>>` | `ArcSwap<Option<WinDivert>>` (MR-P2) — lock-free read hot path |
| DSCP | per-packet random | Per-connection constant (MR-G5) — `ConntrackEntry.dscp_spoof` |
| AutoTune | dead code (не подключён) | Подключён к pipeline (MR-37): record() + recommend() → ConfigOverride |
| HopTab lookup | O(256) linear scan | O(1) direct-mapped hash (4096 entries) |
| Conntrack upsert | 2 DashMap lookups | Entry API — 1 shard lock |
| GC | `iter().remove()` (deadlock) | Two-phase: collect keys → remove |
| SEQ delta limit | `delta < 65535` | `delta < 2^30` (TSO-compatible) |
| TCP checksum | До payload (неверный) | После payload (корректный) |
| build_tcp_segment | 3 аллокации | 1 аллокация (`build_ip_tcp_packet`) |
| DesyncResult::merge | Last-writer-wins без warning | Conflict detection + warning log |
| Pipeline mode | `false` (concurrent) | `true` (pipeline) по умолчанию |

### 23.2 Packet Ring (crossbeam ArrayQueue)

```
WinDivert recv ──→ ArrayQueue<CapturedPacket>(65536) ──→ consumer loop
                     │
                     └── head-drop при переполнении
                         (вытесняет старый пакет, берёт новый)
```

**Преимущества:** Lock-free MPMC, zero contention, head-drop сохраняет свежие пакеты. `try_send` не блокирует WinDivert recv thread.

### 23.3 PRNG Security (Xorshift128** + reseed)

```
getrandom (CSPRNG) ──→ splitmix64 ──→ PerConnRng state[2]
                         │
                         └── periodic reseed каждые 8192 вызова
                             (getrandom → XOR с текущим state)
```

**Защита от ML-DPI:** Даже если DPI восстановил state, reseed разрывает корреляцию. Стоимость: ~0.12ns/packet.

### 23.4 Zero-Copy Pipeline

```
WinDivert recv ──→ bytes::Bytes::copy_from_slice (1 копия)
                       │
                       └── DesyncGroup.apply() ──→ group.apply(packet.clone())
                               │                      (clone = +1 refcount, 0 копий)
                               └── build_ip_tcp_packet() ──→ 1 alloc вместо 3
```

**До:** 3 копии × 1500B × 844K pps = 3.75 GB/s memcpy.
**После:** 1 копия × 1500B × 844K pps = 1.25 GB/s (−67%).

---

## 24. Новые техники (PLAN2 — GreenTunnel/NoDPI/Demergi)

### 24.1 TLS Record Re-wrapping (GreenTunnel)

Текущий `tls_record_frag` делает TCP-level split. Эта техника работает **на TLS record layer** — каждый фрагмент получает валидный 5-byte record header.

```
Было:  [ContentType + Version + Length + FullPayload]
Стало: [CT + V + Len₁ + chunk₁] [CT + V + Len₂ + chunk₂] ... [CT + V + Lenₙ + chunkₙ]
```

**Механизм:** Parces TLS record header → slices payload на chunk_size → обёртка каждого chunk в новый record header с пересчитанным length. Version записывается как TLS 1.3 (0x0304).

**Портфолио:** `desync::tls::tls_record_rewrap()`

### 24.2 SNI-Targeted Record Fragmentation (NoDPI)

Разбиение именно SNI-поля ClientHello на 2-байтные chunks. Каждый chunk оборачивается в TLS 1.3 record header.

**Механизм:** Extension walk для поиска SNI (type=0x0000) → извлечение имени → разбиение на 2B → обёртка в record headers.

**Портфолио:** `desync::tls::sni_record_frag()`

### 24.3 TLS Version Spoof (Demergi)

Перезапись version field в TLS record header на 0x0304 (TLS 1.3). Комбинируется с Record Re-wrapping.

**Портфолио:** `desync::tls::tls_version_overwrite()`

### 24.4 HTTP Header Case Mixing (Demergi)

Чередование регистра в HTTP Host header: `Host` → `hOsT`. Побеждает DPI с fixed-pattern regex.

**Портфолио:** `desync::http::http_case_mix()`

### 24.5 DNS Improvements

| Компонент | Описание |
|---|---|
| DoH Retry | 3 попытки с exponential backoff + jitter (2^n × 20ms + random) |
| Persistent HTTP/2 | `http2_prior_knowledge()` — переиспользование сессии |
| IP Override | CIDR-based override через `ipnet` crate |
| Certificate Pinning | SPKI hash pinning для DoH серверов |

**Портфолио:** `dns::mod.rs`

### 24.6 Auto-detect Persistence (NoDPI)

`AutoProber` теперь сохраняет результаты:
- **Whitelist** (DashSet): успешные TLS handshake → не блокировать повторно
- **Blacklist** (файл): timeout → запись в `blocked_domains.txt`
- **Load on start**: загрузка blocked доменов при старте

**Портфолио:** `split_tunnel.rs`
