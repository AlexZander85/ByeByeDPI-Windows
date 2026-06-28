# FreeDPI Windows — План реализации (Rust, v3.0)

## 1. Добавленные техники

По сравнению с Android, добавлено **~130 новых техник**:
- **15** из zapret2 (multisplit, fakedsplit, syndata, synhide, badsum, ipfrag...)
- **10** Windows-эксклюзивных (IP frag overlap, MSS clamp, ACK suppress...)
- **9** из Nova (geo-routing, proxy chain, strategy evolution, per-app, Opera VPN)
- **3** split tunneling (blacklist/whitelist/auto)
- **8** из sing-box (TLS Spoof, TLS Record Fragment, uTLS, FakeIP DNS...)
- **7** из NaiveProxy (Chrome JA3, H2 SETTINGS, RST padding, Multi-session...)
- **14** из b4 (Combo frag, SeqOverlap, TLS mutation, Detect & Escalate...)
- **3** из FakeSIP (SIP mask, custom payload, UDP random)
- **4** из dae концепций (trie, domain bitmap, rule norm...)
- **4** из sni-spoofing-rust (SEQ Spoof, TLS CH gen, RawBackend, Sniffer)
- **15** из RIPDPI (DesyncGroup, Plan+Execute, Disorder, Entropy padding...)
- **4** из autodpi (Probe/Tune/Run, Strategy trait, auto-tune, persistence)
- **2** из dpibreak (HopTab, Fake CH badsum+auto-TTL)
- **9** из CandyTunnel (ChaCha20, TTL jitter, DSCP, padding, FEC, Mux...)
- **6** из DPIReaper (Sentinel, Task Scheduler, UWP, Firewall, PAC...)
- **3** из qeli (Poisson shaping, supervisor, multiqueue)
- **1** из dpimyass (XOR first N)
- **3** из OpenLogi (thread-local, event tagging, IPC)
- **2** из rust-no-dpi-socks (byte-by-byte, unidir frag)
- **2** из rust-DPI-http-proxy (host-space, title-case)
- **6** из **Omoikane** (TLS GREASE, SNI microfrag, TTL-limited injection, HTTP obfuscation, Fingerprint Rand, Xorshift64 RNG)
- **9** из **offveil** (SNI masking, adaptive escalation, reverse frag, RST drop, TXID tracking, chunk mode, SNI split, QUIC detect, profile composition)
- **10** из **Vane** (DNS Guard, DoH forwarder, auto-optimizer, Job Object, graceful shutdown, net monitor, arg sanitizer, Minisign, zombie cleanup, ICMP health)

**Итого: ~165 техник** (45 Android + 105 базовых новых + 25 из 3 новых проектов − 10 Android-only)

### Приоритетные техники (реализуются первыми)

На основе анализа всех 21 проекта, следующие 18 техник имеют **наивысший эффект**:

| # | Техника | Из | Эффект | Фаза |
|---|---------|:--:|--------|:----:|
| 1 | **SNI Sequence Number Spoofing** | sni-spoofing-rust | Fake CH с SEQ вне окна DPI | **P0.2** |
| 2 | **TLS Spoof** (fake CH с белым SNI) | sing-box | DPI видит разрешённый SNI | P3 |
| 3 | **Strategy Trait + Registry** | autodpi | Trait-based архитектура стратегий | **P0.1** |
| 4 | **HopTab + Fake CH badsum + auto-TTL** | dpibreak | Fake CH НЕ доходит до сервера | **P0.2** |
| 5 | **Synthetic Event Tagging** | OpenLogi | Нет WinDivert loop'ов | **P0.1** |
| 6 | **Sentinel File System** | DPIReaper | File-based autostop | **P0.1** |
| 7 | **Probe/Tune/Run** | autodpi | Трёхфазный выбор стратегии | P1 |
| 8 | **DesyncGroup (pipeline)** | RIPDPI | Цепочка desync-операций | P1.5 |
| 9 | **Plan+Execute + Adaptive Offset** | RIPDPI | Умный split | P1.5 |
| 10 | **TLS mutation chain** | b4 | Неопределимый fingerprint | P3 |
| 11 | **Combo fragmentation** | b4 | Максимальная десинхронизация | P3 |
| 12 | **TLS GREASE Padding Engine** | Omoikane | Уникальный JA3 per-connection | P3 |
| 13 | **SeqOverlap** | b4 | Packet-level overlap | P3 |
| 14 | **Detect & Escalate** | b4 | Авто-эскалация | P5.5 |
| 15 | **Entropy Padding (Popcount/Shannon)** | RIPDPI | Контролируемая энтропия | P5 |
| 16 | **Passive RST Drop IP ID Heuristics** | offveil | Дроп DPI-инжектированных RST | P4 |
| 17 | **Adaptive Per-Target Escalation** | offveil | Auto-эскалация по retry count | P4 |
| 18 | **Multi-Target Auto-Optimizer** | Vane | Подбор пресета реальными тестами | P5.5 |

---

## 2. Фаза P0: Rust инфраструктура + критические новинки (3 недели)

### ✅ Что сделано

- **Cargo workspace** из 5 крейтов (core, api, service, ui, ffi-bridge) — компилируется
- **WinDivert.lib** сгенерирован из `.def` через `lib.exe` / `build.rs`
- **pnet → pnet_packet** (избежана WinPcap/Packet.lib зависимость)
- **`windivert-sys` 0.11.0-beta.2** — реальная версия в Cargo.lock
- **Auth middleware исправлен**: `from_fn` → `from_fn_with_state(state.clone(), auth_middleware)`
- **Classifier header_len исправлен**: `get_version()*4` → `get_header_length()*4` (IHL)
- **Missing deps**: tracing-subscriber, serde_json, num_cpus — добавлены
- **Все pre-existing warnings**: устранены (unused, dead_code, mut)
- **cargo test: 30/30 pass**; cargo clippy: 0 warnings
- **Проанализированы 11 Rust DPI-проектов** — ~50 новых техник

### P0.0: Cargo workspace

```bash
FreeDPI-win/
├── Cargo.toml                    # [workspace]
│   members = ["core", "ffi-bridge", "api", "service", "ui"]
├── core/                         # Основной Rust-крейт
│   ├── Cargo.toml
│   │   dependencies = [
│   │     "windivert", "windows", "tokio", "rayon",
│   │     "dashmap", "pnet_packet", "trust-dns", "reqwest",
│   │     "moka", "serde", "clap", "tracing", "bytes",
│   │     "chacha20", "interprocess", "tarpc"
│   │   ]
│   └── src/
│       ├── lib.rs                # Runtime (tokio + rayon)
│       ├── packet_engine.rs      # WinDivert + raw socket
│       ├── split_tunnel.rs       # Blacklist/whitelist
│       ├── classifier.rs         # Packet routing
│       ├── conntrack.rs          # Connection tracking
│       ├── config.rs             # Config loader
│       ├── desync/               # Desync techniques directory
│       │   ├── mod.rs
│       │   ├── tcp.rs
│       │   ├── tls.rs
│       │   ├── ip.rs
│       │   ├── http.rs
│       │   ├── quic.rs
│       │   ├── obfs.rs
│       │   └── crypto.rs         # NEW: ChaCha20, XOR FEC
│       ├── adaptive/             # NEW: Strategy trait, registry
│       │   ├── mod.rs
│       │   ├── strategy.rs       # Strategy trait + registry
│       │   ├── probe_tune_run.rs # 3-phase strategy
│       │   └── persist.rs
│       └── infra/                # NEW: Sentinel, IPC, firewall
│           ├── mod.rs
│           ├── sentinel.rs
│           └── ipc.rs
├── ffi-bridge/                   # C → Rust FFI
│   ├── build.rs                  # cc crate
│   │   sources = ["vendor/byedpi/src/*.c"]
│   └── src/lib.rs
├── api/                          # HTTP API для AI агента
│   ├── Cargo.toml
│   │   dependencies = [
│   │     "axum", "tower", "serde", "uuid", "chrono"
│   │   ]
│   └── src/lib.rs                # Axum router + handlers
├── service/                      # Windows Service
│   └── src/main.rs               # Service entry + API server
├── ui/                           # System tray
│   └── src/main.rs
└── vendor/
    ├── WinDivert/x64/WinDivert.dll
    └── byedpi/src/               # Bye-dpi C source (19 files)
```

### P0.2: API crate (HTTP API для агента)

```rust
// api/src/lib.rs

use axum::{
    Router, Json, extract::State, http::StatusCode,
    routing::{get, post}, middleware,
    response::IntoResponse,
};
use std::sync::Arc;
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

/// Состояние API
pub struct ApiState {
    pub engine: Arc<EngineHandle>,
    pub api_key: String,
}

/// Запуск API сервера
pub async fn serve(engine: Arc<EngineHandle>, api_key: String, port: u16) {
    let state = Arc::new(ApiState { engine, api_key });
    
    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/strategies/test", post(test_strategy))
        .route("/api/v1/strategies/stats", get(strategy_stats))
        .route("/api/v1/strategies/tune", post(tune_strategy))
        .route("/api/v1/conntrack", get(conntrack_handler))
        .route("/api/v1/dns/cache", get(dns_cache_handler))
        .route("/api/v1/routing/override", post(routing_override))
        .route("/api/v1/health", get(health_handler))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(state);
    
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("API server listening on {}", addr);
    
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app,
    ).await.unwrap();
}

/// Auth: X-API-Key
async fn auth_middleware<B>(
    req: axum::http::Request<B>,
    next: middleware::Next<B>,
) -> Result<axum::response::Response, StatusCode> {
    let state = req.extensions().get::<Arc<ApiState>>().unwrap();
    let key = req.headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key == state.api_key {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Эндпоинты
async fn status_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.engine.uptime(),
        "packets_processed": state.engine.packets_processed(),
        "active_connections": state.engine.active_connections(),
    }))
}

async fn health_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "healthy": true,
        "windivert_ok": state.engine.windivert_ok(),
        "raw_socket_ok": state.engine.raw_socket_ok(),
    }))
}

async fn test_strategy(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<StrategyTestParams>,
) -> impl IntoResponse {
    match state.engine.test_strategy(&params).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap())),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))),
    }
}

async fn strategy_stats(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(state.engine.strategy_stats())
}

async fn tune_strategy(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<TuneParams>,
) -> impl IntoResponse {
    state.engine.tune_strategy(&params).await;
    Json(serde_json::json!({"tuned": true}))
}

async fn conntrack_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(state.engine.conntrack_snapshot())
}

async fn dns_cache_handler(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    Json(state.engine.dns_cache_snapshot())
}

async fn routing_override(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<RoutingOverride>,
) -> impl IntoResponse {
    state.engine.set_routing_override(&params).await;
    Json(serde_json::json!({"overridden": true}))
}
```

### P0.3: Packet Engine (windivert + raw socket)

| Файл | Содержание | Зависимости |
|------|-----------|-------------|
| `packet_engine.rs` | `struct PacketEngine` — WinDivert handle + raw socket | `windivert`, `windows` |
| | `recv()` → `(Packet, Address)` | |
| | `send()` → модифицированный пакет обратно | |
| | `inject_raw()` → raw socket инъекция | |
| | `update_filter()` → динамический WinDivert filter | |

**Ключевой код:**

```rust
// core/src/packet_engine.rs

use windivert::{WinDivert, Layer, Address};
use windows::Win32::Networking::WinSock::*;
use anyhow::Result;

/// Абстракция над WinDivert + raw socket
pub struct PacketEngine {
    divert: WinDivert,
    raw_sock: SOCKET,  // WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW)
}

impl PacketEngine {
    /// Создаём WinDivert + raw socket
    pub fn new(filter: &str) -> Result<Self> {
        // WinDivert handle
        let divert = WinDivert::new(filter, Layer::Network, 0, 0)?;
        divert.set_param(windivert::Param::QueueLength, 8192)?;
        divert.set_param(windivert::Param::QueueTime, 2000)?;
        
        // Raw socket для инъекций (требует admin)
        let raw_sock = unsafe {
            let sock = WSASocketW(
                AF_INET as i32,
                SOCK_RAW as i32,
                IPPROTO_RAW as i32,
                None, 0, 0,
            );
            if sock == INVALID_SOCKET {
                anyhow::bail!("WSASocket failed: {}", WSAGetLastError())
            }
            let opt: u32 = 1;
            setsockopt(sock, IPPROTO_IP.0 as i32,
                       IP_HDRINCL as i32,
                       Some(&opt as *const _ as *const u8,
                       std::mem::size_of::<u32>() as i32));
            sock
        };
        
        Ok(Self { divert, raw_sock })
    }
    
    /// Перехват пакета (async, через tokio)
    pub async fn recv(&self) -> Result<(Vec<u8>, Address)> {
        let (buf, addr) = self.divert.recv().await?;
        Ok((buf.to_vec(), addr))
    }
    
    /// Отправка модифицированного пакета
    pub fn send(&self, packet: &[u8], addr: &Address) -> Result<()> {
        self.divert.send(packet, addr)?;
        Ok(())
    }
    
    /// Инъекция raw пакета (обходит WinDivert)
    pub fn inject_raw(&self, packet: &[u8]) -> Result<()> {
        unsafe {
            let addr = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: std::mem::zeroed() },
                sin_zero: [0; 8],
            };
            let sent = sendto(
                self.raw_sock,
                packet.as_ptr() as *const _,
                packet.len() as i32,
                0,
                &addr as *const _ as *const _,
                std::mem::size_of::<SOCKADDR_IN>() as i32,
            );
            if sent == SOCKET_ERROR {
                anyhow::bail!("sendto failed: {}", WSAGetLastError())
            }
        }
        Ok(())
    }
}
```

### P0.4: Sentinel File System (из DPIReaper)

**Файл:** `core/src/infra/sentinel.rs`

```rust
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Sentinel: файл-триггер для безопасной остановки engine.
/// Если sentinel файл существует — engine работает.
/// Если файл удалён (вручную или системой) — engine останавливается.
pub struct Sentinel {
    path: PathBuf,
    running: AtomicBool,
    check_interval: Duration,
}

impl Sentinel {
    /// Создать sentinel в %ProgramData%/ByeDPI/sentinel
    pub fn create() -> Self {
        let path = PathBuf::from(
            std::env::var("ProgramData").unwrap_or_default()
        ).join("ByeDPI").join("sentinel");
        
        // Создаём директорию и файл
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, b"running").ok();
        
        Self {
            path,
            running: AtomicBool::new(true),
            check_interval: Duration::from_secs(5),
        }
    }
    
    /// Проверка: работает ли engine?
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
    
    /// Фоновый поток проверки sentinel
    pub fn start_monitor(self: Arc<Self>) {
        std::thread::spawn(move || {
            while self.running.load(Ordering::Acquire) {
                if !self.path.exists() {
                    tracing::warn!("Sentinel file deleted — stopping engine");
                    self.running.store(false, Ordering::Release);
                }
                std::thread::sleep(self.check_interval);
            }
        });
    }
    
    /// Ручная остановка (удаление sentinel)
    pub fn stop(&self) {
        std::fs::remove_file(&self.path).ok();
        self.running.store(false, Ordering::Release);
    }
}
```

### P0.5: Synthetic Event Tagging (из OpenLogi)

**Файл:** `core/src/packet_engine/event_tag.rs`

```rust
use uuid::Uuid;
use std::cell::RefCell;

thread_local! {
    /// UUID тег для injected пакетов (первые 16 байт payload)
    static INJECTION_TAG: RefCell<[u8; 16]> = RefCell::new(
        *Uuid::new_v4().as_bytes()
    );
}

/// Маркировка injected пакета UUID-тегом.
/// WinDivert фильтр будет исключать пакеты с этим тегом → нет loop'ов.
pub fn tag_injected_packet(packet: &mut [u8]) {
    INJECTION_TAG.with(|tag| {
        let tag = tag.borrow();
        if packet.len() >= 16 {
            packet[..16].copy_from_slice(&tag);
        }
    });
}

/// Проверка: это наш собственный injected пакет?
pub fn is_injected_packet(packet: &[u8]) -> bool {
    if packet.len() < 16 { return false; }
    INJECTION_TAG.with(|tag| {
        let tag = tag.borrow();
        &packet[..16] == &tag[..]
    })
}
```

### P0.6: Strategy Trait + Registry (из autodpi)

**Файл:** `core/src/adaptive/strategy.rs`

```rust
use std::sync::Arc;

/// Контекст для применения стратегии
pub struct StrategyCtx {
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub client_hello: Vec<u8>,
    pub packet: Vec<u8>,
    pub conntrack: Arc<Conntrack>,
    pub hop_tab: Arc<HopTab>,
}

/// Результат применения стратегии
pub enum StrategyResult {
    /// Пакет модифицирован, можно отправлять
    Modified(Vec<u8>),
    /// Пакет дропнуть (не отправлять)
    Drop,
    /// Пропустить (пакет не требует модификации)
    Passthrough,
}

/// Trait для всех стратегий
#[async_trait]
pub trait Strategy: Send + Sync {
    fn id(&self) -> u32;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn category(&self) -> StrategyCategory;
    
    /// Применить стратегию к пакету
    fn apply(&self, pkt: &mut [u8], ctx: &StrategyCtx) -> Result<StrategyResult>;
    
    /// Проверка применимости (activation filter)
    fn applicable(&self, pkt: &[u8]) -> bool;
}

/// Реестр всех стратегий (глобальный singleton)
pub struct StrategyRegistry {
    strategies: DashMap<u32, Box<dyn Strategy>>,
}

impl StrategyRegistry {
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<StrategyRegistry> = OnceLock::new();
        INSTANCE.get_or_init(|| StrategyRegistry {
            strategies: DashMap::new(),
        })
    }
    
    pub fn register(&self, strategy: Box<dyn Strategy>) {
        self.strategies.insert(strategy.id(), strategy);
    }
    
    pub fn get(&self, id: u32) -> Option<impl Deref<Target = Box<dyn Strategy>>> {
        self.strategies.get(&id)
    }
    
    pub fn apply(&self, id: u32, pkt: &mut [u8], ctx: &StrategyCtx) -> Result<StrategyResult> {
        if let Some(strategy) = self.strategies.get(&id) {
            strategy.apply(pkt, ctx)
        } else {
            Err(anyhow!("Strategy {} not found", id))
        }
    }
}
```

### P0.7: HopTab — Auto-TTL Cache (из dpibreak)

**Файл:** `core/src/desync/ip/hop_tab.rs`

```rust
/// HopTab: кэш {dst_ip → hops} на 256 записей (circular buffer).
/// Определяет количество хопов до сервера по входящему TTL.
/// Для fake ClientHello: TTL = hops - 1 (чтобы НЕ дошёл до сервера).
pub struct HopTab {
    cache: [(u32, u8); 256],  // (ip_hash → hops)
    cursor: AtomicU8,
}

impl HopTab {
    pub fn new() -> Self {
        Self {
            cache: [(0, 0); 256],
            cursor: AtomicU8::new(0),
        }
    }
    
    /// Оценить hops по входящему TTL
    pub fn estimate(dst_ip: u32, recv_ttl: u8) -> u8 {
        let init_ttl = if recv_ttl <= 64 { 64 }
                       else if recv_ttl <= 128 { 128 }
                       else { 255 };
        init_ttl.saturating_sub(recv_ttl)
    }
    
    /// Записать hops для IP
    pub fn insert(&self, dst_ip: u32, hops: u8) {
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % 256;
        self.cache[idx] = (dst_ip, hops);
    }
    
    /// Получить hops для IP (из кэша)
    pub fn get(&self, dst_ip: u32) -> Option<u8> {
        self.cache.iter()
            .find(|(ip, _)| *ip == dst_ip)
            .map(|(_, hops)| *hops)
    }
    
    /// Вычислить fake TTL: должен быть < hops, чтобы пакет НЕ дошёл до сервера
    pub fn fake_ttl(&self, dst_ip: u32) -> Option<u8> {
        self.get(dst_ip).map(|hops| {
            if hops <= 2 { return 0; }  // Disable для близких хостов
            (hops - 1).max(2).min(64)
        })
    }
}
```

### P0.8: Runtime (tokio + rayon)

```rust
// core/src/lib.rs
use rayon::ThreadPoolBuilder;
use tokio::runtime::Builder;

/// Единый runtime для всего приложения
pub struct Runtime {
    pub io: tokio::runtime::Runtime,
    pub cpu: rayon::ThreadPool,
}

impl Runtime {
    pub fn new() -> Self {
        let cpus = num_cpus::get().max(2);
        
        let io = Builder::new_multi_thread()
            .worker_threads(cpus / 2 + 1)
            .enable_io()
            .enable_time()
            .build()
            .expect("tokio runtime");
            
        let cpu = ThreadPoolBuilder::new()
            .num_threads(cpus.max(2))
            .thread_name(|i| format!("desync-{}", i))
            .build()
            .expect("rayon pool");
        
        Self { io, cpu }
    }
}
```

---

## 3. Фаза P1: Split Tunneling + DNS (2 недели)

### P1.1: Split Tunnel Engine

```rust
// core/src/split_tunnel.rs

use dashmap::{DashSet, DashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

/// Режим раздельного туннелирования
#[derive(Debug, Clone)]
pub enum SplitMode {
    /// Только указанные домены — через обход
    WhitelistOnly,
    /// Все, кроме указанных — через обход  
    BlacklistOnly,
    /// Автоматический режим
    Auto,
}

/// Движок раздельного туннелирования
pub struct SplitTunnel {
    // Пользовательские списки
    pub whitelist_domains: Arc<DashSet<String>>,
    pub blacklist_domains: Arc<DashSet<String>>,
    // Кэш IP → domain
    domain_cache: Arc<DashMap<Ipv4Addr, String>>,
    // Авто-детекция
    pub auto_detected: Arc<DashSet<Ipv4Addr>>,
    mode: SplitMode,
}

impl SplitTunnel {
    /// Проверка: нужен ли обход для этого IP?
    pub fn should_bypass(&self, dst_ip: &Ipv4Addr) -> bool {
        match self.mode {
            SplitMode::WhitelistOnly => {
                let domain = self.domain_cache.get(dst_ip);
                domain.map_or(false, |d| self.whitelist_domains.contains(d.value()))
            }
            SplitMode::BlacklistOnly => {
                !self.blacklist_ips.contains(dst_ip) // cached IP variant
            }
            SplitMode::Auto => {
                !self.auto_detected.contains(dst_ip)
            }
        }
    }
    
    /// Построение WinDivert фильтра (оптимизация)
    pub fn build_filter(&self) -> String {
        let base = "ip && (tcp.DstPort == 443 or udp.DstPort == 443 or udp.DstPort == 53)";
        match self.mode {
            SplitMode::BlacklistOnly => {
                let ips: Vec<String> = self.blacklist_ips.iter()
                    .take(64) // WinDivert лимит длины фильтра
                    .map(|ip| format!("ip.DstAddr != {}", ip))
                    .collect();
                if ips.is_empty() { base.to_string() }
                else { format!("({}) && ({})", base, ips.join(" && ")) }
            }
            _ => base.to_string(),
        }
    }
}

/// Асинхронный prober для Auto-режима
pub struct AutoProber;

impl AutoProber {
    pub async fn probe(domain: &str, ip: Ipv4Addr) -> ProbeResult {
        // TCP connect + ClientHello + ждём ответ
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect((ip, 443)),
        ).await {
            Ok(Ok(s)) => s,
            _ => return ProbeResult::Blocked,
        };
        
        let ch = build_minimal_client_hello(domain);
        if stream.write(&ch).await.is_err() {
            return ProbeResult::Blocked;
        }
        
        let mut buf = [0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 5 && buf[0] == 0x16 => ProbeResult::Direct,
            _ => ProbeResult::Blocked,
        }
    }
}
```

### P1.2: DNS Engine

```rust
// core/src/dns/mod.rs
use moka::future::Cache;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

pub struct DnsEngine {
    doh_client: reqwest::Client,     // WinHTTP backend
    dot_resolver: TokioAsyncResolver, // DoT через TLS
    cache: Cache<String, DnsResult>, // moka concurrent cache
}

impl DnsEngine {
    pub async fn resolve(&self, domain: &str) -> Option<IpAddr> {
        // Check cache first
        if let Some(cached) = self.cache.get(domain).await {
            return Some(cached.ip);
        }
        
        // Parallel DoH + DoT
        let doh = self.resolve_doh(domain);
        let dot = self.resolve_dot(domain);
        
        let result = tokio::select! {
            r = doh => r,
            r = dot => r,
        };
        
        if let Some(ip) = result {
            self.cache.insert(
                domain.to_string(),
                DnsResult { ip, ttl: 300 }
            ).await;
        }
        result
    }
}
```

---

## 3.5 Фаза P1.5: Geo-Routing + Proxy Chain (3 недели)

### 3.5.1 Geo-Routing Engine (из Nova)

**Цель:** Маршрутизация трафика по региону домена/IP.

**Задачи:**

- [ ] `routing/geo.rs` — `GeoRouter` struct
  - [ ] `classify(domain, ip) → GeoRegion` — определение региона
  - [ ] `resolve(domain, ip) → RouteDecision` — полный маршрут
  - [ ] Загрузка списков из файлов (`ru_domains.txt`, `eu_domains.txt`, ...)
  - [ ] CIDR matching для IP-диапазонов
  - [ ] moka cache для результатов (TTL 1 час)
- [ ] `routing/detect.rs` — DPI vs Geo-block детекция
  - [ ] Анализ ответа: RST/таймаут → DPI; HTTP 403/451 → Geo-block
  - [ ] `detect_geo_block(response: &[u8]) → bool`
- [ ] Региональные списки (data/lists/):
  - [ ] `ru_domains.txt` — 100+ доменов (yandex, vk, sberbank...)
  - [ ] `eu_domains.txt` — 100+ доменов (netflix, openai, spotify...)
  - [ ] `us_domains.txt` — 50+ доменов
  - [ ] `exclude_domains.txt` — банки, госуслуги
  - [ ] `ru_cidrs.txt` — IP-диапазоны РФ
  - [ ] `eu_cidrs.txt` — IP-диапазоны ЕС

### 3.5.2 Proxy Chain Manager (из Nova)

**Цель:** Интеллектуальная цепочка egress-провайдеров с failover.

**Задачи:**

- [ ] `routing/chain.rs` — `EgressChain`
  - [ ] `build_attempts(target) → Vec<Attempt>` — построение попыток
  - [ ] `execute(target) → Result<ConnResult>` — sequential failover
  - [ ] Per-hop timeout + first-byte timeout
  - [ ] Bad route cache (TTL-based, DashMap)
  - [ ] Маркировка bad route при ошибке/таймауте
- [ ] `routing/health.rs` — Proxy health checks
  - [ ] `check_socks5(host, port) → bool` — SOCKS5 handshake probe
  - [ ] `check_http(host, port) → bool` — HTTP CONNECT probe
  - [ ] Фоновый health checker (каждые 30 сек)

### 3.5.3 Opera VPN Integration (из Nova)

**Цель:** Бесплатные EU-прокси без регистрации.

**Задачи:**

- [ ] `routing/opera.rs` — Opera VPN provider
  - [ ] Авто-детекция списка Opera VPN SOCKS5 прокси
  - [ ] Health check при старте
  - [ ] Интеграция с Proxy Chain как `Egress::OperaVpn`
  - [ ] Периодическое обновление (каждые 5 мин)

**Ключевой код:**

```rust
// routing/geo.rs — GeoRouter
impl GeoRouter {
    pub fn resolve(&self, domain: &str, ip: Ipv4Addr) -> RouteDecision {
        if self.exclude_domains.contains(domain) {
            return RouteDecision::excluded();
        }
        if self.is_bad_route(&format!("{}|{}", domain, ip)) {
            return RouteDecision::fallback();
        }
        let region = self.classify(domain, ip);
        let chain = self.build_egress_chain(&region);
        RouteDecision { region, egress_chain: chain }
    }
    
    fn classify(&self, domain: &str, ip: Ipv4Addr) -> GeoRegion {
        if self.ru_domains.contains(domain) 
           || self.ru_cidrs.iter().any(|c| c.contains(ip)) {
            GeoRegion::Russia       // → desync локально
        } else if self.eu_domains.contains(domain)
                  || self.eu_cidrs.iter().any(|c| c.contains(ip)) {
            GeoRegion::Europe       // → Opera VPN (geo-spoof)
        } else if self.us_domains.contains(domain) {
            GeoRegion::UnitedStates // → user proxy
        } else {
            GeoRegion::Global       // → direct desync
        }
    }
    
    fn build_egress_chain(&self, region: &GeoRegion) -> EgressChain {
        match region {
            GeoRegion::Russia => EgressChain::new(vec![
                Egress::Direct { desync: true },
                Egress::Socks5 { host: "127.0.0.1", port: 1370 },
            ]),
            GeoRegion::Europe => EgressChain::new(vec![
                Egress::OperaVpn,
                Egress::Direct { desync: true },
            ]),
            GeoRegion::UnitedStates => EgressChain::new(vec![
                Egress::UserProxy,
                Egress::Direct { desync: true },
            ]),
            GeoRegion::Global | GeoRegion::Excluded => EgressChain::new(vec![
                Egress::Direct { desync: true },
            ]),
        }
    }
}
```

---

## 3.6 Per-App Routing (из Nova)

**Цель:** Разная маршрутизация для разных приложений.

**Задачи:**

- [ ] `routing/app.rs` — `AppRouter`
  - [ ] `from_process_name(name) → AppFamily`
  - [ ] `resolve_region(app, geo) → GeoRegion`
  - [ ] Browser → Global, Messenger → Europe, Gaming → Russia, System → Excluded
  - [ ] Интеграция с WinDivert: получение PID процесса через WFP

### 3.6.1 Ключевой код

```rust
pub enum AppFamily {
    Browser,    // Chrome, Firefox, Edge
    Messenger,  // Telegram, Discord, WhatsApp
    Gaming,     // Steam, Battle.net
    DevTools,   // VSCode, Git, OpenCode
    System,     // svchost, Windows Update
    Unknown,
}

impl AppFamily {
    pub fn from_process_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("chrome") || lower.contains("firefox") || lower.contains("msedge") {
            AppFamily::Browser
        } else if lower.contains("telegram") || lower.contains("discord") || lower.contains("whatsapp") {
            AppFamily::Messenger
        } else if lower.contains("steam") || lower.contains("battle") {
            AppFamily::Gaming
        } else if lower.contains("svchost") || lower.contains("services") {
            AppFamily::System
        } else {
            AppFamily::Unknown
        }
    }
}
```

---

## 3.7 Strategy Evolution (из Nova)

**Цель:** Авто-подбор DPI desync стратегий под конкретный домен/IP.

**Задачи:**

- [ ] `routing/evolution.rs` — `StrategyEvolution`
  - [ ] `select_strategy(domain) → u32` — выбор лучшей стратегии
  - [ ] `record_result(domain, strategy_id, success)` — запись результата
  - [ ] `rotate_strategy()` — циклическая ротация если нет данных
  - [ ] Persist на диск: `data/strategy_stats.json`
  - [ ] Per-domain: success_count, fail_count, last_success, level

---

## 4. Фаза P2: Bye-dpi FFI Bridge (3 недели)

### 4.1 build.rs — компиляция C кода

```rust
// ffi-bridge/build.rs
fn main() {
    let mut build = cc::Build::new();
    
    // Все 19 C-файлов bye-dpi ядра
    let sources = [
        "conev.c", "desync.c", "extend.c", "packets.c",
        "proxy.c", "mpool.c", "main.c",
        // + 12 файлов из byedpi/
    ];
    
    for src in &sources {
        build.file(format!("vendor/byedpi/src/{}", src));
    }
    
    build.include("vendor/byedpi/include")
         .compile("byedpi");
    
    // Генерация Rust FFI bindings
    let bindings = bindgen::Builder::default()
        .header("vendor/byedpi/include/desync.h")
        .header("vendor/byedpi/include/proxy.h")
        .allowlist_function("dpi_desync_packet")
        .allowlist_function("proxy_start")
        .allowlist_function("proxy_stop")
        .generate()
        .expect("bindgen");
    
    bindings.write_to_file("src/ffi_gen.rs")
        .expect("write bindings");
}
```

### 4.2 Rust-safe wrappers

```rust
// ffi-bridge/src/lib.rs
mod ffi_gen;

/// Rust-safe обёртка над C desync engine
pub struct DesyncEngine {
    inner: *mut ffi_gen::desync_ctx,
}

impl DesyncEngine {
    pub fn new(config: &Config) -> Result<Self> {
        let ctx = unsafe {
            ffi_gen::desync_init(
                config.desync_mode,
                config.ttl,
                config.frag_size,
            )
        };
        if ctx.is_null() {
            anyhow::bail!("desync_init failed")
        }
        Ok(Self { inner: ctx })
    }
    
    /// Обработка пакета через C desync engine
    pub fn process_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let mut out_len = 0u32;
        let mut out_buf = vec![0u8; packet.len() * 2]; // max expansion
        
        let result = unsafe {
            ffi_gen::dpi_desync_packet(
                self.inner,
                packet.as_ptr(),
                packet.len() as u32,
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        
        if result != 0 {
            anyhow::bail!("desync failed: {}", result)
        }
        
        out_buf.truncate(out_len as usize);
        Ok(out_buf)
    }
}

impl Drop for DesyncEngine {
    fn drop(&mut self) {
        unsafe { ffi_gen::desync_free(self.inner) }
    }
}
```

---

## 5. Фаза P3-P7: Техники (10 недель)

### 5.1 Структура модуля desync (с новыми модулями из 11 проектов)

```
core/src/
├── desync/                    # Core desync techniques
│   ├── mod.rs                 # DesyncEngine — единый диспетчер
│   ├── tcp.rs                 # TCP техники (30 шт)
│   │   ├── multisplit()           # [Z1]
│   │   ├── multidisorder()        # [Z2]
│   │   ├── hostfakesplit()        # [Z3]
│   │   ├── fakedsplit()           # [Z4]
│   │   ├── fakeddisorder()        # [Z5]
│   │   ├── tcpseg()               # [Z6]
│   │   ├── syndata()              # [Z7]
│   │   ├── synack_split()         # [Z8]
│   │   ├── wsize()                # [Z9]
│   │   ├── synhide()              # [Z10]
│   │   ├── fake_sni()             # [03]
│   │   ├── oob_injection()        # [04]
│   │   ├── tcp_preopen()          # [05]
│   │   ├── mss_clamp()            # [W2]
│   │   ├── ack_suppress()         # [W3]
│   │   ├── pkt_reorder()          # [W4]
│   │   ├── rst_selective()        # [W5]
│   │   ├── syn_flood_decoy()      # [W6]
│   │   ├── win_scale_manip()      # [W7]
│   │   ├── seq_spoof()            # [SR1] SEQ Number Spoofing
│   │   ├── disorder()             # [RP3] TTL-based disorder
│   │   ├── multidisorder_new()    # [RP4] MultiDisorder
│   │   ├── disoob()               # [RP5] OOB+Disorder
│   │   ├── hostfake()             # [RP6] HostFake
│   │   ├── fakerst()              # [RP7] FakeRst
│   │   ├── fake_ch_badsum()       # [DP2] Fake CH + badsum + auto-TTL
│   │   ├── byte_by_byte()         # [RN1] Byte-by-byte first packet
│   │   ├── unidir_frag()          # [RN2] Unidirectional frag
│   │   ├── port_shuffle()         # [CT8] Port Shuffle
│   │   ├── wclamp()               # [RP14] Window clamp + Drop SACK
│   │   ├── ts_md5()               # [RP13] TSval/Echo manipulation
│   │   ├── sni_mask_fake()        # [OF1] SNI masking on fakes (offveil)
│   │   ├── reverse_frag()         # [OF3] Reverse fragment order (offveil)
│   │   └── frag_chunk()           # [OF6] Fragment chunk mode (offveil)
│   ├── tls.rs                 # TLS техники (20 шт)
│   │   ├── tls_parrot()           # [20] Chrome fingerprint
│   │   ├── tls_frag()             # [15] Record fragmentation
│   │   ├── tls_record_pad()       # [07] Post-request padding
│   │   ├── ech_fallback()         # [32] ECH emulation
│   │   ├── chunk_obfuscation()    # [21] TCP chunk
│   │   ├── payload_rotator()      # [42] SNI rotator
│   │   ├── ch_gen()               # [SR2] TLS CH Generator
│   │   ├── spoof()                # [SB1] TLS Spoof
│   │   ├── mutation()             # [B5] TLS mutation chain
│   │   ├── utls()                 # [SB5] uTLS fingerprints
│   │   ├── fingerprint()          # [NP1] Chrome JA3
│   │   ├── choreo()               # [RP12] TLS Record choreography
│   │   ├── grease_pad()           # [OM1] GREASE Padding Engine (Omoikane)
│   │   ├── ttl_record_hdr()       # [OM3] TTL-limited Record Injection (Omoikane)
│   │   ├── fingerprint_rand()     # [OM5] TLS Fingerprint Randomization (Omoikane)
│   │   ├── sni_byte_split()       # [OF7] Byte-accurate SNI split (offveil)
│   │   └── sni_microfrag()        # [OM2] SNI-targeted microfrag (Omoikane)
│   ├── ip.rs                  # IP-level техники (12 шт)
│   │   ├── frag_overlap()         # [W1]
│   │   ├── ip_frag_primitives()   # [Z15]
│   │   ├── ttl_manipulation()     # [19]
│   │   ├── hop_cache()            # [40]
│   │   ├── badsum()               # [Z14]
│   │   ├── ipv6_ext_headers()     # [W8]
│   │   ├── dht_falsification()    # [Z9]
│   │   ├── hop_tab()              # [DP1] HopTab auto-TTL cache
│   │   ├── ttl_jitter()           # [CT3] TTL jitter
│   │   ├── dscp()                 # [CT4] Random DSCP
│   │   ├── mutual_spoof()         # [CT1] Mutual IP Spoofing
│   │   └── ipip()                 # [CT9] IPIP tunnel
│   ├── http.rs                # HTTP техники (11 шт)
│   │   ├── header_tamper()        # [10]
│   │   ├── h2_hpack_aware()       # [31]
│   │   ├── hpack_bomber()         # [41]
│   │   ├── host_space()           # [RH1] Host-Space
│   │   ├── title_case()           # [RH2] Title-Case
│   │   └── host_obfs()            # [OM4] HTTP Host Obfuscation (Omoikane)
│   ├── quic.rs                # QUIC/UDP техники (11 шт)
│   │   ├── quic_block_icmp()
│   │   ├── quic_initial_inject()
│   │   ├── quic_short_header()
│   │   ├── quic_padding_flood()
│   │   ├── udp_coalescing()
│   │   ├── doppelganger_grease()
│   │   ├── quic_normalizer()
│   │   └── long_hdr_drop()        # [OF8] QUIC Long-Header Detection (offveil)
│   ├── obfs.rs                # Обфускация (8 шт)
│   │   ├── udp2icmp()             # [Z13]
│   │   ├── ippxor()               # [Z12]
│   │   ├── wgobfs()               # [Z11]
│   │   ├── entropy()              # [RP8] Popcount/Shannon padding
│   │   ├── pad_size()             # [CT5] Packet size padding
│   │   ├── xor_first()            # [DM1] XOR first N bytes
│   │   └── poisson()              # [QL1] Poisson traffic shaping
│   ├── crypto.rs              # Крипто-обфускация
│   │   ├── chacha20()             # [CT2] ChaCha20 per-packet
│   │   └── xorfec()               # [CT6] XOR FEC
│   ├── rand.rs                # [OM6] Xorshift64 RNG (Omoikane)
│   ├── group.rs               # [RP1] DesyncGroup pipeline
│   ├── planner.rs             # [RP2] Plan+Execute
│   └── jitter.rs              # [30] Pareto jitter injector
├── adaptive/                  # Адаптивные стратегии
│   ├── mod.rs
│   ├── strategy.rs               # Strategy trait + registry
│   ├── probe_tune_run.rs         # 3-phase probe/tune/run
│   ├── tune.rs                   # Auto-tune parameters
│   ├── persist.rs                # Strategy persistence
│   ├── fallback.rs               # Fallback chain
│   ├── escalate.rs               # Detect & Escalate
│   ├── target_escalate.rs        # [OF2] Per-target escalation (offveil)
│   ├── auto_optimizer.rs         # [VA3] Multi-target optimizer (Vane)
│   ├── profile.rs                # [OF9] Profile composition (offveil)
│   ├── hybrid.rs                 # Hybrid strategy
│   ├── rst_protect.rs            # RST protection
│   └── lua.rs                    # Lua strategy scripts [RP15]
├── dns/
│   ├── mod.rs
│   ├── fakeip.rs                 # FakeIP DNS manager
│   └── txid_tracker.rs           # [OF5] DNS TXID-aware flow tracking (offveil)
├── infra/                     # Инфраструктура
│   ├── mod.rs
│   ├── sentinel.rs               # Sentinel file system
│   ├── supervisor.rs             # Supervisor/Worker
│   ├── ipc.rs                    # interprocess + tarpc
│   ├── autostart.rs              # Task Scheduler
│   ├── uwp_loopback.rs           # UWP LoopbackExempt
│   ├── firewall.rs               # Windows Firewall
│   ├── winhttp_proxy.rs          # WinHTTP proxy config
│   ├── pac.rs                    # PAC server
│   ├── dns_guard.rs              # [VA1] DNS Guard (Vane)
│   ├── doh_forwarder.rs          # [VA2] DoH Forwarder (Vane)
│   ├── job_object.rs             # [VA4] Job Object cleanup (Vane)
│   ├── graceful_shutdown.rs      # [VA5] Graceful shutdown (Vane)
│   ├── net_monitor.rs            # [VA6] Event-driven net monitor (Vane)
│   ├── arg_sanitizer.rs          # [VA7] Arg sanitization (Vane)
│   ├── minisign_verify.rs        # [VA8] Minisign Ed25519 (Vane)
│   ├── zombie_cleanup.rs         # [VA9] Zombie process cleanup (Vane)
│   └── icmp_health.rs            # [VA10] ICMP health check (Vane)
├── routing/
│   ├── mod.rs
│   ├── geo.rs                    # GeoRouter
│   ├── chain.rs                  # EgressChain
│   ├── detect.rs                 # GeoBlockDetector
│   ├── health.rs                 # HealthChecker
│   └── opera.rs                  # Opera VPN provider
└── packet_engine/
    ├── mod.rs
    ├── event_tag.rs           # Synthetic event tagging
    ├── rst_drop.rs             # [OF4] RST drop IP ID heuristics (offveil)
    └── multiqueue.rs          # Multiqueue processing
```

### 5.2 Пример: IP Fragmentation Overlap [W1]

```rust
// core/src/desync/ip.rs

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;

/// Техника W1: IP Fragmentation Overlap
/// Отправляем два перекрывающихся фрагмента.
/// DPI собирает fake SNI (фрагмент 1).
/// Сервер собирает real SNI (фрагмент 2 — имеет большший offset).
pub fn frag_overlap(
    raw_tx: &RawSocketTx,
    original_packet: &[u8],
    fake_client_hello: &[u8],
) -> Result<()> {
    let ip = Ipv4Packet::new(original_packet)
        .ok_or(anyhow!("not an IPv4 packet"))?;
    
    let payload_start = (ip.get_version() as usize) * 4; // IHL
    let original_payload = &original_packet[payload_start..];
    
    // Размер fake CH с TCP header (без IP header)
    let frag1_payload_len = fake_client_hello.len();
    
    // Фрагмент 1: fake ClientHello
    // offset=0, More Fragments=1
    let mut frag1 = vec![0u8; 20 + frag1_payload_len];
    {
        let mut pkt = MutableIpv4Packet::new(&mut frag1).unwrap();
        pkt.set_version(4);
        pkt.set_header_length(5);
        pkt.set_total_length((20 + frag1_payload_len) as u16);
        pkt.set_identification(ip.get_identification().wrapping_add(1));
        pkt.set_flags(1); // MF=1 (More Fragments)
        pkt.set_fragment_offset(0);
        pkt.set_ttl(ip.get_ttl().saturating_sub(1));
        pkt.set_next_level_protocol(ip.get_next_level_protocol());
        pkt.set_source(ip.get_source());
        pkt.set_destination(ip.get_destination());
        // Payload: fake ClientHello
        let payload = pkt.payload_mut();
        payload[..frag1_payload_len].copy_from_slice(fake_client_hello);
    }
    // Checksum
    let checksum = ipv4_checksum(&frag1);
    {
        let mut pkt = MutableIpv4Packet::new(&mut frag1).unwrap();
        pkt.set_header_checksum(checksum);
    }
    
    // Фрагмент 2: real payload
    // offset=20 (overlap!), More Fragments=0
    let frag2_offset = 20; // Перекрываем байты 20+ фрагмента 1
    let frag2_payload_len = original_payload.len();
    let mut frag2 = vec![0u8; 20 + frag2_payload_len];
    {
        let mut pkt = MutableIpv4Packet::new(&mut frag2).unwrap();
        pkt.set_version(4);
        pkt.set_header_length(5);
        pkt.set_total_length((20 + frag2_payload_len) as u16);
        pkt.set_identification(ip.get_identification().wrapping_add(1));
        pkt.set_flags(0); // MF=0 (Last)
        pkt.set_fragment_offset(frag2_offset / 8); // в 8-байтовых единицах
        pkt.set_ttl(ip.get_ttl());
        pkt.set_next_level_protocol(ip.get_next_level_protocol());
        pkt.set_source(ip.get_source());
        pkt.set_destination(ip.get_destination());
        pkt.payload_mut().copy_from_slice(original_payload);
    }
    let checksum = ipv4_checksum(&frag2);
    {
        let mut pkt = MutableIpv4Packet::new(&mut frag2).unwrap();
        pkt.set_header_checksum(checksum);
    }
    
    // Отправляем фрагмент 1
    raw_tx.send(&frag1)?;
    // Задержка 1-5ms (реализация через tokio::time)
    std::thread::sleep(Duration::from_micros(1000));
    // Отправляем фрагмент 2
    raw_tx.send(&frag2)?;
    
    Ok(())
}
```

---

## 5.3 Фаза P4: Fake Injection + offveil техники + Omoikane microfrag (4 недели)

### 5.3.1 SNI/Host Masking on Fakes (offveil [OF1])

Замена hostname на 'a'·len в fake-пакетах. DPI видит "aaaaaaa..." вместо реального домена.
Сервер игнорирует fake-пакет (low TTL / badsum / badseq).

```rust
/// Маскировка SNI: замена hostname на 'a' повторяющееся len раз
pub fn mask_sni_in_client_hello(ch: &mut [u8], sni: &str) -> Option<usize> {
    // Поиск SNI в TLS ClientHello
    // Формат: extension_type(2) + length(2) + sni_list_length(2) + sni_type(1) + sni_length(2) + sni_value
    if ch.len() < 50 { return None; }
    
    // Поиск SNI extension (type=0x0000)
    let sni_ext_start = find_sni_extension(ch)?;
    let sni_value_start = sni_ext_start + 9; // extension header + sni_list header
    let sni_len_bytes = &ch[sni_ext_start + 7..sni_ext_start + 9];
    let sni_len = u16::from_be_bytes([sni_len_bytes[0], sni_len_bytes[1]]) as usize;
    
    // Замена hostname на 'a'*len с сохранением точек и дефисов
    for i in 0..sni_len {
        let byte = ch[sni_value_start + i];
        if byte == b'.' || byte == b'-' {
            continue; // сохраняем разделители
        }
        ch[sni_value_start + i] = b'a';
    }
    
    Some(sni_len)
}

/// Маскировка HTTP Host: замена hostname в заголовке Host:
pub fn mask_http_host(packet: &mut [u8]) -> Option<usize> {
    let pkt_str = std::str::from_utf8(packet).ok()?;
    let host_start = pkt_str.find("Host: ")? + 6;
    let host_end = pkt_str[host_start..].find("\r\n")? + host_start;
    let hostname = &pkt_str[host_start..host_end];
    
    for (i, byte) in hostname.bytes().enumerate() {
        if byte == b'.' || byte == b'-' {
            continue;
        }
        packet[host_start + i] = b'a';
    }
    
    Some(hostname.len())
}
```

### 5.3.2 Reverse Fragment Order (offveil [OF3])

Отправка TCP фрагментов в обратном порядке: Fragment 2 → Fragment 1.
DPI не может собрать корректный поток; сервер собирает корректно (TCP reassembly).

```rust
/// Отправка фрагментов в обратном порядке
pub fn send_reverse_fragments(
    raw_tx: &RawSocketTx,
    fragments: Vec<Vec<u8>>,
    delay_us: u64,
) -> Result<()> {
    let count = fragments.len();
    if count < 2 { return Ok(()); }
    
    // Отправляем в обратном порядке: count-1, count-2, ..., 0
    for i in (0..count).rev() {
        raw_tx.send(&fragments[i])?;
        if i > 0 && delay_us > 0 {
            std::thread::sleep(Duration::from_micros(delay_us));
        }
    }
    Ok(())
}

/// Сборка фрагментов: [frag1, frag2, ...] → реверс
pub fn build_reverse_fragments(tcp_payload: &[u8], split_positions: &[usize], mtu: usize) -> Vec<Vec<u8>> {
    let fragments = build_normal_fragments(tcp_payload, split_positions, mtu);
    fragments.into_iter().rev().collect()
}
```

### 5.3.3 Passive RST Drop with IP ID Heuristics (offveil [OF4])

Многие ISP (РФ) инжектируют RST-пакеты с IPv4 ID < 0x000F. Дроп таких RST предотвращает
принудительное закрытие соединений DPI.

```rust
/// DPI RST Dropper: анализирует входящие RST пакеты
pub fn handle_inbound_rst(packet: &[u8]) -> PacketDecision {
    if packet.len() < 20 { return PacketDecision::Forward; }
    
    let ip_id = u16::from_be_bytes([packet[4], packet[5]]);
    let is_dpi_rst = ip_id <= 0x000F;  // DPI signature
    
    if is_dpi_rst {
        debug!("DPI RST dropped (IP ID={})", ip_id);
        PacketDecision::Drop
    } else {
        PacketDecision::Forward
    }
}
```

### 5.3.4 Adaptive Per-Target Escalation (offveil [OF2])

Per-SNI счётчик retry с TTL 10 минут. После 7 неудач — автоматическая эскалация
на более агрессивную стратегию (Extreme: 8-byte chunks вместо split).

См. `adaptive::target_escalate` — полная реализация и ключевой код в ARCHITECTURE.md 22.13.

### 5.3.5 DNS TXID-aware Flow Tracking (offveil [OF5])

Маппинг DNS запросов→ответов через (client_ip, client_port, TXID) для корректной
маршрутизации ответов к оригинальному DNS серверу при конкурентных запросах.

См. `dns::txid_tracker` — полная реализация в ARCHITECTURE.md 22.14.

### 5.3.6 SNI-targeted Microfragmentation (Omoikane [OM2])

Фрагментация только окрестностей SNI (±N байт) чанками 1-6 байт с jitter 1-5ms.
В отличие от полной фрагментации, минимизирует задержку и количество сегментов.

```rust
/// SNI-targeted microfragmentation
pub fn sni_microfragment(
    packet: &[u8],
    config: &MicrofragConfig,
    rng: &mut Xorshift64,
) -> Result<DesyncResult> {
    // 1. Парсинг TLS ClientHello
    let ch = parse_client_hello(packet)?;
    let sni_range = ch.sni_byte_range()
        .ok_or_else(|| anyhow!("No SNI in ClientHello"))?;
    
    // 2. Определяем зону фрагментации: SNI ± offset
    let frag_start = sni_range.start.saturating_sub(config.sni_offset);
    let frag_end = (sni_range.end + config.sni_offset).min(packet.len());
    
    // 3. Отправляем до SNI зоны одним куском
    let before_sni = &packet[..frag_start];
    
    // 4. SNI зону — микро-чанками (1-6 байт) с jitter
    let sni_zone = &packet[frag_start..frag_end];
    let mut pos = 0;
    let mut inject = Vec::new();
    
    while pos < sni_zone.len() {
        let chunk_size = rng.gen_range(
            config.min_chunk_size,
            config.max_chunk_size + 1,
        ).min(sni_zone.len() - pos);
        
        let chunk = &sni_zone[pos..pos + chunk_size];
        inject.push(build_tcp_segment(chunk, &ch, config.fake_ttl));
        
        pos += chunk_size;
    }
    
    // 5. Отправляем остаток
    let after_sni = &packet[frag_end..];
    inject.push(build_tcp_segment(after_sni, &ch, ch.ttl));
    
    Ok(DesyncResult::inject_many(inject))
}
```

---

## 5.4 Фаза P5: HTTP Host Obfuscation + Fragment Chunk + DoH Forwarder (4 недели)

### 5.4.1 HTTP Host Obfuscation (Omoikane [OM4])

Четыре техники обфускации HTTP-заголовков:
- **Randomized Casing**: каждая буква Host с 50% вероятностью → upper case
- **Dot Trick**: добавление точки в конец hostname (`example.com.` — валидный FQDN)
- **Space Trick**: 1-3 пробела между методом и URL в request line
- **Absolute URI**: `GET http://example.com/path HTTP/1.1` вместо `GET /path HTTP/1.1`

```rust
/// HTTP Host Obfuscation
pub fn obfuscate_http_request(request: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut result = Vec::with_capacity(request.len() + 64);
    
    // 1. Space Trick: multiple spaces between method and URI
    let space_count = 1 + (rng.gen_u32() % 3) as usize;  // 1-3 spaces
    
    // 2. Absolute URI
    let request_str = String::from_utf8_lossy(request);
    if let Some(host) = extract_host(&request_str) {
        // Rewrite: "GET /path HTTP/1.1" → "GET  http://host/path HTTP/1.1"
        let (method, rest) = request_str.split_once(' ').unwrap_or(("", ""));
        let spaces = " ".repeat(space_count);
        let absolute_uri = format!("{}{}http://{}/{}", method, spaces, host, rest.trim_start());
        result.extend_from_slice(absolute_uri.as_bytes());
    } else {
        result.extend_from_slice(request);
    }
    
    // 3. Randomized Casing for Host header
    let host_marker = b"Host: ";
    if let Some(pos) = result.windows(host_marker.len()).position(|w| w == host_marker) {
        let value_start = pos + host_marker.len();
        let value_end = result[value_start..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| value_start + p)
            .unwrap_or(result.len());
        
        for i in value_start..value_end {
            if rng.gen_f64() < 0.5 {
                result[i] = result[i].to_ascii_uppercase();
            }
        }
    }
    
    // 4. Dot Trick: если hostname не заканчивается на точку
    let dot = b'.';
    if result.last() != Some(&dot) {
        result.push(dot);  // example.com. → валидный FQDN
    }
    
    result
}
```

### 5.4.2 Fragment Chunk Mode (offveil [OF6])

Деление TCP payload на N сегментов равного размера S (ChunkSize=8 → много мелких сегментов).
Максимальная десинхронизация для DPI, анализирующих первые N байт потока.

```rust
/// Chunk fragmentation: деление на сегменты размера chunk_size
pub fn chunk_fragment(payload: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut pos = 0;
    
    while pos < payload.len() {
        let end = (pos + chunk_size).min(payload.len());
        chunks.push(payload[pos..end].to_vec());
        pos = end;
    }
    
    chunks
}
```

### 5.4.3 Local DoH Forwarder (Vane [VA2])

Локальный UDP→HTTPS DNS прокси на 127.0.0.1:5300, шифрующий DNS-трафик всей системы
через DNS-over-HTTPS (Cloudflare/Google). Concurrency limit: 100 запросов.

См. `infra::doh_forwarder` — полная реализация в ARCHITECTURE.md 22.16.

### 5.4.4 Сводка техник T1–T12 (маппинг)

| # | Техника | Проект | Наш ID | Раздел в ARCHITECTURE.md | Раздел в IMPLEMENTATION_PLAN.md |
|:-:|---------|--------|:------:|:------------------------:|:-------------------------------:|
| T1 | **Adaptive Auto-Escalation** | offveil | **OF2** | 18.21 табл., 22.13 (код) | 5.3.4 |
| T2 | **Masked SNI** (на fake-пакетах) | offveil | **OF1** | 18.21 табл. | 5.3.1 (код) |
| T3 | **GREASE + Padding + Shuffle TLS** | Omoikane | **OM1+OM5** | 18.20 табл., 22.11 (код) | 5.1 (модуль) |
| T4 | **HTTP техники** (Dot/Space/Case/Shuffle) | Omoikane | **OM4** | 18.20 табл. | 5.4.1 (код) |
| T5 | **Fake TTL Injection** (5 байт с TTL=1) | Omoikane | **OM3** | 18.20 табл., 22.12 (код) | 5.1 (модуль) |
| T6 | **DNS TXID-based mapping** | offveil | **OF5** | 18.21 табл., 22.14 (код) | 5.3.5 |
| T7 | **SNI-ориентированная фрагментация + jitter** | Omoikane | **OM2** | 18.20 табл. | 5.3.6 (код) |
| T8 | **RST Passive Detection** (по IPv4 ID) | offveil | **OF4** | 18.21 табл., 22.15 (код) | 5.3.3 (код) |
| T9 | **Reverse ordering фрагментов** | offveil | **OF3** | 18.21 табл. | 5.3.2 (код) |
| T10 | **Windows Job Object** | Vane | **VA4** | 18.22 табл., 22.18 (код) | 5.1 (модуль) |
| T11 | **DoH Forwarder** (UDP→HTTPS прокси) | Vane | **VA2** | 18.22 табл., 22.16 (код) | 5.4.3 |
| T12 | **Xorshift64 RNG** | Omoikane | **OM6** | 18.20 табл. | 5.1 (модуль) |

### 5.4.5 Блоки для copy-paste из исходников

Следующие блоки кода можно скопировать **дословно** из исходных проектов (адаптация только нейминга и импортов).

#### 🔥 offveil adaptive.rs — Adaptive Auto-Escalation (T1/OF2)

Из `offveil/src-tauri/src/dpi/profiles/adaptive.rs`. Эскалация: level 0 = Universal, level ≥ 1 = Extreme.

```rust
// После N неудачных попыток по хосту — автоматически усиливаем
fn auto_level_for_target(&self, parsed: &SlicedPacket) -> u8 {
    // SNI-based: 7 попыток, IP:port fallback: 12 попыток
    // Burst guard: 600ms — не считает параллельные соединения браузера
    // TTL: 10 минут — автоочистка
    let retry_key = extract_retry_key(parsed); // SNI hostname | HTTP Host | "ip:port"
    let mut state = self.retry_map.entry(retry_key).or_insert(RetryState {
        count: 0,
        last: Instant::now(),
    });
    
    // Burst guard: если последняя попытка < 600ms — не эскалируем
    if state.last.elapsed() < Duration::from_millis(600) {
        return 0;
    }
    
    state.count += 1;
    state.last = Instant::now();
    
    // Очистка истёкших записей (каждые 60 сек)
    if state.count % 5 == 0 {
        self.retry_map.retain(|_, s| s.last.elapsed() < Duration::from_secs(600));
    }
    
    if state.count >= 12 {
        2 // Fallback: IP:port-based, совсем плохо
    } else if state.count >= 7 {
        1 // Extreme: chunk mode (8-byte segments)
    } else {
        0 // Universal: normal split
    }
}
```

#### 🔥 offveil tls.rs:216-247 — Masked SNI (T2/OF1)

Из `offveil/src-tauri/src/dpi/techniques/tls.rs`. Замена SNI на `aaaaa.aaa` с сохранением точек и дефисов.

```rust
pub fn mask_tls_sni_hostname(payload: &mut [u8]) -> bool {
    // Формат SNI: extension_type(2) + length(2) + sni_list_length(2) + sni_type(1) + sni_len(2) + sni_value
    if payload.len() < 50 { return false; }
    
    // Ищем SNI extension (0x0000) в TLS ClientHello
    let mut pos = 43; // typical start of extensions
    while pos + 4 < payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        
        if ext_type == 0x0000 { // SNI extension
            // SNI list entry: sni_type(1) + sni_len(2) + sni_value
            let sni_start = pos + 4 + 3; // ext header + sni_type
            let sni_len = u16::from_be_bytes([payload[sni_start - 1], payload[sni_start]]) as usize;
            
            // Mask: заменяем все на 'a', сохраняя '.' и '-'
            for i in 0..sni_len {
                let b = payload[sni_start + i];
                if b != b'.' && b != b'-' {
                    payload[sni_start + i] = b'a';
                }
            }
            return true;
        }
        pos += 4 + ext_len;
    }
    false
}

// Пример: "example.com" → "aaaaaaa.aaa"
// DPI видит безобидный hostname
```

#### 🔥 Omoikane rand.rs — Xorshift64 RNG (T12/OM6)

Из `Omoikane/src/rand.rs`. Полный самописный RNG (122 строки) — можно скопировать целиком.

```rust
/// Самописный Xorshift64 RNG.
/// Быстрее крейта `rand` за счёт отсутствия дженериков и трейтов.
/// latency: <50ns per call.
pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    /// Создание с seed из времени + адреса стека
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
            ^ (std::ptr::addr_of!(Xorshift64::new) as u64);
        Self { state: seed }
    }
    
    /// 64-bit случайное число (Core RNG)
    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
    
    /// 32-bit случайное число
    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    
    /// Случайное f64 в [0.0, 1.0)
    pub fn gen_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / 9007199254740992.0)
    }
    
    /// Случайное целое в [lo, hi) — unbiased (Lemire method)
    pub fn gen_range_u64(&mut self, lo: u64, hi: u64) -> u64 {
        if lo >= hi { return lo; }
        let range = hi - lo;
        let mut x = self.next_u64();
        let mut m = (x as u128) * (range as u128);
        let mut l = m as u64;
        if l >= range {
            return lo + l;
        }
        let threshold = (!range + 1) as u64;
        while l < threshold {
            x = self.next_u64();
            m = (x as u128) * (range as u128);
            l = m as u64;
        }
        lo + l
    }
    
    pub fn gen_range_usize(&mut self, lo: usize, hi: usize) -> usize {
        self.gen_range_u64(lo as u64, hi as u64) as usize
    }
    
    /// bool с вероятностью p
    pub fn gen_bool(&mut self, p: f64) -> bool {
        self.gen_f64() < p
    }
    
    /// Перемешивание массива (Fisher-Yates)
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.gen_range_usize(0, i + 1);
            slice.swap(i, j);
        }
    }
    
    /// Перемешивание байтового буфера
    pub fn shuffle_bytes(&mut self, buf: &mut [u8]) {
        for i in (1..buf.len()).rev() {
            let j = self.gen_range_usize(0, i + 1);
            buf.swap(i, j);
        }
    }
}
```

#### 🔥 Omoikane tls.rs:79-113 — Fake TTL Injection (T5/OM3)

Из `Omoikane/src/tls.rs`. Отправка 5 байт TLS-заголовка с пониженным TTL.

```rust
use socket2::{SockRef, TcpKeepalive};

/// Инъекция 5 байт TLS Record Header с пониженным TTL.
/// 1. Сохранить текущий TTL сокета
/// 2. Установить TTL = 1 (или ttl_value)
/// 3. Отправить 5 байт (первые байты TLS-заголовка)
/// 4. Восстановить оригинальный TTL
pub fn inject_ttl_limited_prefix(
    stream: &TcpStream,
    ttl_value: u8,
) -> std::io::Result<()> {
    let sock_ref = SockRef::from(stream);
    let original_ttl = sock_ref.ttl_v4().unwrap_or(64);
    
    // Устанавливаем пониженный TTL
    sock_ref.set_ttl_v4(ttl_value)?;
    
    // Отправляем 5 байт: TLS Record Header (ContentType=0x16, Version=0x0301, Length=0x0000)
    // DPI видит начало TLS рукопожатия, но пакет не доходит до сервера (TTL истекает)
    let fake_header = [0x16, 0x03, 0x01, 0x00, 0x00];
    
    // Используем write_all для гарантированной отправки
    let mut written = 0;
    while written < fake_header.len() {
        written += stream.write(&fake_header[written..])?;
    }
    stream.flush()?;
    
    // Восстанавливаем оригинальный TTL
    sock_ref.set_ttl_v4(original_ttl)?;
    
    tracing::debug!(
        "TTL-limited injection: sent 5 bytes with TTL={} (original={})",
        ttl_value, original_ttl
    );
    
    Ok(())
}

/// Альтернатива: пакетная инъекция через raw socket (для WinDivert режима)
pub fn inject_ttl_limited_raw(
    raw_tx: &RawSocketTx,
    src: Ipv4Addr, dst: Ipv4Addr,
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32,
    ttl: u8,
) -> Result<()> {
    // 5 байт TLS Record Header
    let payload = vec![0x16, 0x03, 0x01, 0x00, 0x00];
    let packet = build_tcp_packet(src, dst, src_port, dst_port, seq, ack, TCP_ACK, ttl, &payload)?;
    raw_tx.send(&packet)
}
```

### 5.5.1 Strategy Evolution (из Nova)

**Цель:** Авто-подбор DPI desync стратегий по домену.

- [ ] `routing/evolution.rs`:
  - [ ] `select_strategy(domain) -> u32` -- лучшая стратегия для домена
  - [ ] `record_result(domain, strategy, success)` -- обновление статистики
  - [ ] `rotate_strategy()` -- циклическая ротация (106 стратегий)
  - [ ] `data/strategy_stats.json` -- персистентность на диск
  - [ ] Per-domain metrics: success_count, fail_count, last_success, level

### 5.5.2 Per-App Routing (из Nova)

**Цель:** Разная маршрутизация для Chrome, Telegram, Steam, системных процессов.

- [ ] `routing/app.rs`:
  - [ ] `AppFamily::from_process_name(name)` -- определение приложения
  - [ ] Browser -> Global (desync), Messenger -> Europe (Opera VPN),
        Gaming -> Russia (desync), System -> Excluded (direct)
  - [ ] WinDivert -> PID -> process name -> routing decision

### 5.5.3 DPI vs Geo-block Detection (из Nova + b4 B7)

**Цель:** Отличать блокировку DPI от региональной блокировки + escalate.

- [ ] `routing/detect.rs`:
  - [ ] `detect_geo_block(response: &[u8]) -> bool` -- анализ ответа
  - [ ] Признаки DPI: RST, таймаут, обрыв после SYN-ACK
  - [ ] Признаки Geo-block: HTTP 403/451, TLS alert, HTML-страница
  - [ ] Авто-переключение: DPI -> другая стратегия; Geo -> другой прокси
- [ ] **b4 B7: Detect & Escalate**:
  - [ ] `adaptive::escalate` — обнаружение DPI-блокировки → агрессивная стратегия
  - [ ] Триггеры: RST из DPI, таймаут > 5s, повторы сброса
  - [ ] Escalation levels: level 1 (split) → level 2 (frag) → level 3 (overlap)
  - [ ] Per-provider profile (Ростелеком vs МТС vs Билайн)

### 5.5.4 b4 B14: Hybrid Strategy

**Цель:** Runtime-выбор стратегии по форме ClientHello.

- [ ] `adaptive::hybrid`:
  - [ ] Анализ ClientHello: размер, extensions, cipher suites
  - [ ] Выбор стратегии на основе анализа (без истории)
  - [ ] Интеграция с StrategyEvolution как fallback для новых доменов
  - [ ] Быстрый старт: seed-данные из b4 default profiles

### 5.5.5 Opera VPN Integration (из Nova)

**Цель:** Бесплатные EU-прокси для geo-spoofing без регистрации.

- [ ] `routing/opera.rs`:
  - [ ] Список известных Opera VPN SOCKS5 прокси
  - [ ] Health check (SOCKS5 handshake) при старте
  - [ ] Интеграция с EgressChain как `Egress::OperaVpn`
  - [ ] Периодическое обновление (фоновая проверка каждые 30 сек)

### 5.5.6 Multi-Target Auto-Optimizer (Vane [VA3])

**Цель:** Автоматический подбор оптимального пресета DPI-обхода через real-world тесты.

- [ ] `adaptive::auto_optimizer`:
  - [ ] Перебор встроенных пресетов с тестами YouTube (known IP: 142.250.0.0/16), Discord, Twitter
  - [ ] Каждый пресет запускается на 3 секунды, проверяется доступность 3 целей
  - [ ] Система оценки: `score = (success_count × 10000) − avg_latency`
  - [ ] Early exit при score > 27000 (все цели доступны с latency < 3s)
  - [ ] Свежий HTTP-клиент для каждого пресета (избегание false-negative из-за кеша)
  - [ ] Результат сохраняется в `optimizer_state.json` для автозапуска

### 5.5.7 ICMP Health Check (Vane [VA10])

**Цель:** Измерение реальной задержки (ping) для диагностики DPI vs сетевые проблемы.

- [ ] `infra::icmp_health`:
  - [ ] ping 1.1.1.1 с парсингом вывода (поддержка разных локалей)
  - [ ] Отличие DPI блокировки (RST/таймаут) от сетевых проблем (потеря пакетов)
  - [ ] Интеграция с дэшбордом и логами

---

## 7.5 Фаза P7.5: HTTP API v2 — Fine-tuning + Webhook (1 неделя)

### 7.5.1 Расширение API для агента

**Цель:** Полноценное API для AI-агента (OpenCode) для автоматического тестирования
стратегий, анализа результатов и fine-tuning параметров.

- [ ] `api/src/endpoints/strategies.rs`:
  - [ ] `POST /api/v1/strategies/quick-test` — быстрый тест N стратегий на домене
  - [ ] `GET /api/v1/strategies/{id}/params` — текущие параметры стратегии
  - [ ] `PUT /api/v1/strategies/{id}/params` — полное обновление параметров
  - [ ] `GET /api/v1/strategies/ranking` — рейтинг стратегий (по success rate)
- [ ] `api/src/endpoints/domains.rs`:
  - [ ] `GET /api/v1/domains/{domain}` — полная статистика по домену
  - [ ] `POST /api/v1/domains/{domain}/reset` — сброс статистики домена
  - [ ] `GET /api/v1/domains/top-blocked` — топ-10 самых блокируемых доменов
- [ ] `api/src/endpoints/config.rs`:
  - [ ] `GET /api/v1/config` — текущая конфигурация
  - [ ] `PUT /api/v1/config` — обновление конфигурации (без перезапуска)
  - [ ] `POST /api/v1/config/reload` — перезагрузка из файла

### 7.5.2 Webhook для результатов

- [ ] `api/src/webhook.rs`:
  - [ ] POST webhook URL после каждого теста стратегии
  - [ ] Формат: `{ domain, strategy_id, success, latency, timestamp }`
  - [ ] Configurable URL + rate limit
  - [ ] Retry с backoff при ошибке

### 7.5.3 Bulk operations

- [ ] `POST /api/v1/bulk/test-strategies` — тест N стратегий на M доменов
  - [ ] Агент отправляет: `{ strategies: [1..20], domains: ["x.com", "y.com"] }`
  - [ ] Возвращает матрицу результатов: `{ "x.com": { 1: true, 2: false, ... } }`
- [ ] `POST /api/v1/bulk/analyze` — анализ паттернов блокировки
  - [ ] Авто-кластеризация результатов по провайдеру
  - [ ] Рекомендация оптимальной стратегии для каждого провайдера

### 7.5.4 Rust-реализация

```rust
// api/src/endpoints/strategies.rs
use axum::{Json, extract::{State, Path}};

/// Быстрый тест: N стратегий на одном домене
pub async fn quick_test(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<QuickTestParams>,
) -> Json<QuickTestResult> {
    let mut results = Vec::with_capacity(params.strategy_ids.len());
    
    for strategy_id in &params.strategy_ids {
        let start = std::time::Instant::now();
        let result = state.engine.test_strategy_with_timeout(
            &params.domain,
            *strategy_id,
            params.timeout_ms,
        ).await;
        
        results.push(StrategyTestResult {
            strategy_id: *strategy_id,
            success: result.is_ok(),
            latency_ms: start.elapsed().as_millis() as u64,
            error: result.err().map(|e| e.to_string()),
        });
    }
    
    Json(QuickTestResult {
        domain: params.domain,
        results,
    })
}

/// Рейтинг стратегий
pub async fn strategy_ranking(
    State(state): State<Arc<ApiState>>,
) -> Json<Vec<StrategyRanking>> {
    let mut rankings: Vec<_> = state.engine.strategy_stats()
        .iter()
        .map(|(id, stats)| StrategyRanking {
            strategy_id: *id,
            success_rate: stats.success_rate(),
            total_attempts: stats.total(),
            level: stats.level,
        })
        .collect();
    
    rankings.sort_by(|a, b| b.success_rate.partial_cmp(&a.success_rate).unwrap());
    Json(rankings.into_iter().take(20).collect())
}
```

---

## 9. Фаза P8: Rust-миграция bye-dpi (3 недели)

### Постепенное замещение C → Rust

```
Неделя 1:                 Неделя 2:
┌───────────────────┐    ┌───────────────────┐
│ C через FFI       │    │ C через FFI       │
│   ┌─────────────┐ │    │   ┌─────────────┐ │
│   │ desync.rs   │◄┼┼──────┤ desync.rs   │ │
│   │ (NEW) ☑️    │ │    │   │ (100% ☑️)   │ │
│   ├─────────────┤ │    │   ├─────────────┤ │
│   │ tls.rs      │◄┼┼──────┤ tls.rs      │ │
│   │ (NEW) ☑️    │ │    │   │ (100% ☑️)   │ │
│   ├─────────────┤ │    │   ├─────────────┤ │
│   │ conntrack.rs│ │    │   │ conntrack.rs│ │
│   │ (100% ☑️)   │ │    │   │ (100% ☑️)   │ │
│   └─────────────┘ │    │   └─────────────┘ │
│        ...        │    │        ...        │
│ C: 12 файлов     │    │ C: 0 файлов       │
│ C: desync.c      │    │ C: УДАЛЁН         │
│ C: proxy.c       │    │ C: УДАЛЁН         │
└───────────────────┘    └───────────────────┘
```

---

## 10. Фаза P9: GUI + Service (3 недели)

### Windows Service (с API сервером)

```rust
// service/src/main.rs

use windows_service::{
    service::*, service_control_handler::*,
    service_manager::*,
};

static ENGINE: OnceLock<Arc<EngineHandle>> = OnceLock::new();

fn service_main(_args: Vec<String>) {
    let handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                ENGINE.get().map(|e| e.shutdown());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    
    let status_handle = register_service_control_handler(
        "FreeDPI", handler
    ).unwrap();
    
    status_handle.set_service_status(
        ServiceStatus::running()
    ).unwrap();
    
    let rt = Runtime::new();
    let engine = Arc::new(EngineHandle::new());
    let engine_clone = engine.clone();
    ENGINE.set(engine).ok();
    
    // Запуск API сервера в отдельном tokio task
    let api_key = load_or_generate_api_key();
    let api_port = 11337;
    rt.io.spawn(async move {
        FreeDPI_api::serve(
            engine_clone,
            api_key,
            api_port,
        ).await;
    });
    
    // Запуск ядра
    rt.io.block_on(run_engine_forever());
}
```

### System Tray

```rust
// ui/src/main.rs

use tray_item::{TrayItem, IconSource};
use std::sync::mpsc;

fn main() {
    let (tx, rx) = mpsc::channel();
    
    let mut tray = TrayItem::new("FreeDPI", IconSource::Resource("icon"))
        .unwrap();
    
    tray.add_menu_item("Start/Stop", move || {
        tx.send("toggle").ok();
    }).unwrap();
    tray.add_menu_item("Status", move || {
        tx.send("status").ok();
    }).unwrap();
    tray.add_menu_item("Exit", move || {
        tx.send("exit").ok();
    }).unwrap();
    
    loop {
        match rx.recv() {
            Ok("toggle") => toggle_engine(),
            Ok("status") => show_status(),
            Ok("exit") => break,
            _ => {}
        }
    }
}
```

---

## 11. Сборка и установка

### requirements

- Rust 1.80+ (nightly для Windows features)
- Visual Studio 2022 Build Tools (C++ для WinDivert)
- Windows 11 SDK

### Команды

```bash
# Разработка
cargo build --release

# Запуск (требует admin)
.\target\release\FreeDPI-service.exe install
.\target\release\FreeDPI-service.exe start

# UI (системный трей)
.\target\release\FreeDPI-ui.exe
```

### Пайплайн CI

```yaml
# .github/workflows/build.yml
build:
  runs-on: windows-2022
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo build --release
    - run: cargo test
    - uses: actions/upload-artifact@v4
      with:
        path: target/release/*.exe
```

---

## 12. Ключевые риски (обновлено с учётом 21 проекта)

| Риск | Вероятность | Влияние | Митигация |
|------|:----------:|:-------:|-----------|
| **SEQ Spoofing работает не со всеми DPI** | Medium | High | Fallback на другие стратегии (Strategy Registry) |
| **HopTab даёт неверные hops (NAT)** | Medium | Medium | Close-host check (hops <= 2 → отключить TTL desync) |
| **ChaCha20 per-packet latency > 5µs** | Low | Medium | Проверить: chacha20 crate на portable vs SIMD. SIMD fallback |
| **Synthetic event tagging не работает (пакет слишком мал)** | Low | Low | tag в TCP options, не payload |
| **Sentinel file на ProgramData не создаётся (No Admin)** | Low | Medium | Fallback на %APPDATA%/ByeDPI/sentinel |
| **WinDivert не видит injected пакеты (tagging не нужен)** | Medium | Low | WinDivert не перехватывает raw socket пакеты — всегда так. Но для модифицированных через WinDivert send — нужно tagging |
| **interprocess IPC race condition** | Low | High | tarpc + backpressure. Очередь с bounded channel |
| **Poisson shaping + EWMA конфликт** | Low | Low | Poisson применяется только после EWMA-анализа |
| **DesyncGroup pipeline слишком медленный** | Medium | Medium | Max 3 операции в pipeline, timeout на каждую |
| **Strategy Registry memory (150 стратегий)** | Low | Low | Box<dyn Strategy> ~ 16 байт на запись, 150 → ~2.4 KB |
| **UWP LoopbackExempt требует перезапуска UWP** | High | Low | CheckNetIsolation.exe после каждого изменения |
| **PAC server создаёт поверхностный прокси** | Low | Low | PAC только для автоматической настройки браузера |
| **Supervisor/Worker — лишняя сложность?** | Medium | Low | Отложить на P9. Sentinel достаточно для P0-P8 |
| **TLS GREASE Padding ломает некоторые TLS handshake** | Low | Medium | Тестирование на 100+ сайтах, fallback на vanilla CH |
| **TTL-Limited Injection не доходит до удалённого DPI** | Medium | Low | DPI на первом хопе (ISP), TTL=2 достаточно |
| **SNI Microfragmentation не работает с DPI на IP уровне** | Low | Medium | Fallback на IP frag overlap при неудаче |
| **Adaptive Per-Target Escalation ложные срабатывания (burst)** | Medium | Low | Burst guard 600ms + минимальный TTL 10 мин |
| **RST Drop IP ID Heuristics — ложные срабатывания на легитимные RST** | Low | Medium | Только inbound RST на 80/443; IPv4 ID = 0xFFxx для легитимных |
| **DNS TXID Tracker — утечка памяти при большом кол-ве запросов** | Low | Low | TTL-очистка каждые 60 сек |
| **DoH Forwarder — single point of failure для DNS** | Medium | Medium | Fallback на системный DNS при ошибке DoH |
| **Job Object — не все процессы можно добавить в job** | Low | Low | Windows ограничение: процесс уже в job → создаём новый процесс |
| **Minisign Ed25519 — компрометация приватного ключа** | Low | High | Key rotation, multiple signers, HTTPS fallback |

## 13. Контрольные точки (Milestones)

| Milestone | Фазы | Критерий приёмки |
|-----------|:----:|-------------------|
| **M1: Workspace compiles** | ✅ P0 | `cargo build` — 0 errors, `cargo test` — 30/30 pass ✅ **ГОТОВО** |
| **M2: Strategy registry + Sentinel** | P0.1 | `StrategyRegistry::global()` работает, sentinel файл создаётся/удаляется |
| **M3: SEQ Spoofing + HopTab** | P0.2 | Wireshark: fake CH с SEQ вне окна, TTL = hops-1 |
| **M4: Split tunnel + DNS + Probe/Tune/Run** | P1 | curl rutracker.org через whitelist mode |
| **M5: DesyncGroup + Plan+Execute** | P1.5 | Pipeline из 3 операций: fake → split → reorder |
| **M6: TCP desync v2 (18 техник)** | P3 | Все 18 техник (вкл. TLS GREASE, TTL-limited injection, Fingerprint Rand) проходят тест |
| **M7: Fake injection + Window manip + offveil P4** | P4 | SNI masking, reverse frag, IP ID RST drop, per-target escalation в Wireshark |
| **M8: Windows-exclusive + Omoikane obfs + DoH** | P5 | HTTP obfuscation, chunk mode, DoH forwarder на реальном провайдере |
| **M9: QUIC + Obfuscation + Entropy** | P6 | QUIC Initial через WinDivert, entropy padding 6.5-7.5 |
| **M10: Proxy + Multi-session + IPC** | P7 | SOCKS5 chain, multiplexing, RPC service↔UI |
| **M11: Full Rust migration** | P8 | `vendor/byedpi/` удалён, всё на Rust |
| **M12: GUI + Installer + CI** | P9 | MSI installer, system tray, CI build |

## 14. Справочник: что портировать из каждого проекта

### sni-spoofing-rust (D:\ByeDPI\research\rust_project\sni-spoofing-rust)
- **SEQ Spoofing** — P0.2: fake CH с SEQ вне окна
- **TLS CH Generator** — P0.2: конструктор CH из struct
- **RawBackend** — архитектура: trait для разных backend'ов отправки

### RIPDPI (D:\ByeDPI\research\rust_project\RIPDPI\native\rust\)
- **DesyncGroup** — P1.5: pipeline операций (desync_runtime.rs)
- **Plan+Execute** — P1.5: planner.rs
- **Disorder / MultiDisorder / OOB** — P3: tcp_manip.rs
- **Entropy padding** — P5: popcount_entropy.rs, shannon_entropy.rs
- **FakeRst / Fallback chain** — P4/P5.5

### autodpi (D:\ByeDPI\research\rust_project\autodpi)
- **Strategy Trait + Registry** — P0.1: прямая адаптация
- **Probe/Tune/Run** — P1: трёхфазный выбор

### dpibreak (D:\ByeDPI\research\rust_project\dpibreak)
- **HopTab** — P0.2: ~550 строк, полный копи-пейст с адаптацией под WinDivert

### CandyTunnel (D:\ByeDPI\research\rust_project\CandyTunnel)
- **ChaCha20** — P3: chacha20 crate, per-packet с unique nonce
- **TTL Jitter / DSCP** — P3/P4: побайтовая модификация IP header

### DPIReaper (D:\ByeDPI\research\rust_project\DPIReaper)
- **Sentinel** — P0.1: file-based autostop
- **UWP / Firewall / Task Scheduler** — P9

### OpenLogi (D:\ByeDPI\research\rust_project\OpenLogi\crates)
- **Event tagging** — P0.1: UUID-тег injected пакетов
- **interprocess IPC** — P9: замена HTTP API на RPC

### qeli (D:\ByeDPI\research\rust_project\qeli\qeli)
- **Poisson shaping** — P5: пуассоновский IAT

### dpimyass / rust-no-dpi-socks / rust-DPI-http-proxy
- XOR first N / Byte-by-byte / Host-space — P4-P5

### Omoikane (D:\ByeDPI\research\rust_project\Omoikane)
- **TLS GREASE Padding Engine** — P3: мульти-вероятностная модель модификации ClientHello
- **SNI-targeted Microfragmentation** — P4: фрагментация только окрестностей SNI
- **TTL-Limited Record Header Injection** — P3: 5 байт TLS Record с ttl=2
- **HTTP Host Obfuscation** — P5: Randomized Casing, Dot Trick, Space Trick, Absolute URI
- **TLS Fingerprint Randomization** — P3: 4+ вероятностных параметра GREASE
- **Xorshift64 Deterministic RNG** — P5: самописный RNG (<50ns)

### offveil (D:\ByeDPI\research\rust_project\offveil)
- **SNI/Host Masking on Fakes** — P4: замена hostname → 'a'·len в fake-пакетах
- **Adaptive Per-Target Escalation** — P4: 7 retry → Extreme, 10 min TTL
- **Reverse Fragment Order** — P4: fragment 2 → fragment 1
- **Passive RST Drop IP ID Heuristics** — P4: дроп RST с IPv4 ID < 16
- **DNS TXID-aware Flow Tracking** — P4: (client_ip, port, TXID) маппинг
- **Fragment Chunk Mode** — P5: деление на N сегментов размера S
- **Byte-Accurate SNI Split** — P3: точное байтовое смещение SNI value
- **QUIC Long-Header Detection** — P6: дроп QUIC с non-zero версией
- **Profile Composition Pattern** — P5: PacketAction enum + ConfigurableProfile

### Vane (D:\ByeDPI\research\rust_project\Vane)
- **DNS Guard** — P1: авто-установка Cloudflare DNS при старте
- **Local DoH Forwarder** — P5: UDP→HTTPS DNS прокси на 127.0.0.1:5300
- **Multi-Target Auto-Optimizer** — P5.5: real-world тесты 3 целей, эвристический scoring
- **Windows Job Object Cleanup** — P9: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
- **Graceful Shutdown** — P9: CTRL_BREAK_EVENT + 500ms ожидание
- **Event-Driven Network Monitor** — P9: Win32 message loop, zero CPU polling
- **Multi-Layer Arg Sanitizer** — P9: frontend → whitelist → shell-char фильтр
- **Minisign Ed25519 Supply-Chain Security** — P9: верификация подписей пресетов
- **Auto Zombie Cleanup** — P1: taskkill + sc delete WinDivert на старте
- **ICMP Health Check** — P5.5: ping 1.1.1.1 с парсингом вывода

---

## 15. Фаза P10: Полноценный GUI (Tauri v2 + React + i18n)

### Обзор

Полноценное окно с графиками, настройками, статусом и таблицами. Берётся за основу UI из **offveil** (Tauri v2 + React 19 + Tailwind v4 + shadcn/ui). Добавляется i18n (Русский + Английский) с live-switching.

### Архитектура

```
src/ui/                          # Tauri v2 проект (вне workspace)
├── package.json                 # React 19, Tauri v2, Tailwind v4, recharts, i18next
├── vite.config.ts
├── index.html
├── src/
│   ├── main.tsx                 # Entry point
│   ├── App.tsx                  # ThemeProvider > I18nProvider > Dashboard
│   ├── index.css                # Theme CSS vars (dark/light/system)
│   ├── i18n/
│   │   ├── index.ts             # i18next init
│   │   ├── en.json              # ~150 ключей
│   │   └── ru.json              # ~150 ключей
│   ├── contexts/
│   │   ├── ThemeContext.tsx      # Dark/light/system (из offveil)
│   │   ├── I18nContext.tsx       # Language switcher
│   │   └── EngineContext.tsx     # Engine state polling
│   ├── hooks/
│   │   ├── useEngine.ts         # Polls /api/v1/status, /health
│   │   ├── useSettings.ts       # Config read/write
│   │   └── useTheme.ts
│   ├── lib/
│   │   ├── api.ts               # HTTP client для FreeDPI API
│   │   └── utils.ts             # cn()
│   ├── components/
│   │   ├── Dashboard.tsx        # Главный view (tabs)
│   │   ├── StatusPanel.tsx      # Uptime, packets, connections
│   │   ├── StatsGraph.tsx       # Recharts LineChart
│   │   ├── StrategyPanel.tsx    # 55+ техник с toggle
│   │   ├── SettingsPanel.tsx    # Config editor
│   │   ├── ConntrackPanel.tsx   # Connections table
│   │   ├── GeoPanel.tsx         # Region visualization
│   │   ├── LanguageSwitcher.tsx # RU/EN toggle
│   │   └── ui/                  # shadcn/ui components
│   └── assets/
├── src-tauri/
│   ├── tauri.conf.json
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── lib.rs               # Tauri commands: get_status, get_config, save_config
│       └── commands/
```

### Ключевые решения

| Решение | Выбор | Почему |
|---------|-------|--------|
| GUI framework | Tauri v2 + React | Нативное окно, tray, installer |
| Styling | Tailwind v4 + CSS vars | Из offveil |
| Charts | Recharts | Declarative, React-friendly |
| i18n | i18next + react-i18next | Live-switching, lazy loading |
| State | React Context + localStorage | Из offveil |
| Component lib | shadcn/ui | Из offveil |
| Package manager | npm | Широко доступен |

### Задачи

| # | Задача | Файлы |
|---|--------|-------|
| 1 | Scaffolding Tauri v2 + React | package.json, vite.config.ts, tauri.conf.json |
| 2 | i18n (RU/EN) | i18n/index.ts, en.json, ru.json, LanguageSwitcher.tsx |
| 3 | Theme system (из offveil) | ThemeContext.tsx, index.css |
| 4 | Dashboard + tabs | Dashboard.tsx, App.tsx |
| 5 | StatusPanel + StatsGraph | StatusPanel.tsx, StatsGraph.tsx |
| 6 | StrategyPanel | StrategyPanel.tsx |
| 7 | SettingsPanel | SettingsPanel.tsx |
| 8 | ConntrackPanel | ConntrackPanel.tsx |
| 9 | GeoPanel | GeoPanel.tsx |
| 10 | Tauri commands (Rust) | lib.rs, commands/*.rs |
| 11 | System tray | tray integration |
| 12 | Удаление старого ui crate | Обновление workspace |

### Источник UI

**offveil** (D:\ByeDPI\research\rust_project\offveil):
- Tauri v2 + React 19 + Tailwind v4 + Vite 7
- shadcn/ui компоненты
- ThemeContext (dark/light/system)
- Монолитный Dashboard.tsx (overlay-panels)
- NSIS installer
- System tray с blur-to-hide

---

## 16. Фаза P11: SpoofDPI-derived фичи (6 техник)

### Обзор

6 функций, заимствованных из анализа SpoofDPI. Повышают эффективность обхода DPI
за счёт нетривиальных методов фрагментации, оптимизации DNS и маршрутизации.

### Источник

**SpoofDPI** (D:\ByeDPI\research\SpoofDPI) — Go DPI bypass tool.

### Задачи

| # | Задача | Модуль | Описание |
|---|--------|--------|----------|
| 1 | **Custom Segment Plans + Noise** | `desync/segment_plan.rs` | TOML-конфигурация точных позиций split с параметром noise (jitter ±N байт). Каждый пакет фрагментируется по-разному → DPI не может натренировать паттерн |
| 2 | **Xorshift Random Split Mask** | `desync/rand.rs` (extend) | Генерация 64-битной маски через Xorshift PRNG с гарантией ≥1 split-точки на каждый 8-битный блок. Недетерминированный coverage |
| 3 | **Parallel Dial (Race)** | `dns/parallel_dial.rs` | DNS возвращает N IP → подключаемся ко всем параллельно, берём первый успешный. Снижает latency на 40-60% |
| 4 | **Dual-Stack Hop Learning** | `adaptive/hop_tab.rs` (extend) | UDP sniffer для QUIC hop count. Сейчас есть только TCP |
| 5 | **Domain Trie (Wildcard)** | `routing/domain_trie.rs` | Patricia trie с wildcard-матчингом (`*` = один уровень, `**` = multi-level) вместо линейного DashSet |
| 6 | **Per-Rule Config Override** | `config/rule_override.rs` | Каждый домен/CIDR может переопределять split-mode, fake-count, disorder, ttl_offset |

### Приоритет

| # | Приоритет | Эффект |
|---|-----------|--------|
| 1 | 🔴 P11.1 | Нетривиальная фрагментация с jitter |
| 2 | 🔴 P11.1 | Guaranteed split coverage |
| 3 | 🟡 P11.2 | Latency reduction |
| 4 | 🟡 P11.2 | QUIC fake packet TTL |
| 5 | 🟡 P11.3 | O(1) wildcard domain matching |
| 6 | 🟡 P11.3 | Per-domain strategy customization |
