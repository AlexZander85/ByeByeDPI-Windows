# IMPLEMENTATION PLAN: DPI Probe Module

> **Цель:** Модуль превентивного определения типа DPI-блокировки для конкретного домена/IP,
> с выводом рекомендации по стратегии desync.
> Модуль полностью автономен, не зависит от WinDivert, работает через обычные TCP/TLS/HTTP/DNS.

---

## Архитектура модуля

```
core/src/probe/
├── mod.rs              # ProbeModule orchestrator + public API
├── dns_probe.rs        # Phase 1: DNS integrity (UDP vs DoH cross-validation)
├── tcp_probe.rs        # Phase 2: TCP connectivity + parallel race
├── tls_probe.rs        # Phase 3: TLS staged handshake (1.3 → 1.2)
├── http_probe.rs       # Phase 4: HTTP application layer
├── tcp16_probe.rs      # Phase 5: Data-volume detection (16×4KB)
├── classifier.rs       # FailureCode enum (23+ типов) + stage tracking
├── discriminator.rs    # Server-active vs Path-active
├── accumulator.rs      # 24h temporal accumulation + eTLD+1
├── strategy_map.rs     # ProbeResult → StrategyRecommendation
├── config.rs           # ProbeConfig (timeouts, servers, thresholds)
└── rkn_stub.rs         # ISP stub page detection (RKN substrings)
```

---

## Задачи по фазам

### Фаза P-1: Ядро модуля (classifier + config)

#### T1.1: FailureCode enum — централизованный классификатор ошибок

**Приоритет:** P0 | **Сложность:** Низкая | **Срок:** 1 день

**Описание:**
Создать `classifier.rs` с enum `FailureCode`, покрывающим 23+ типов блокировок.
Каждый код содержит: категорию (Dns/Tcp/Tls/Http), confidence level, описание.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsFailureCode {
    Poisoned,           // UDP возвращает другие IP чем DoH
    NxdomainSpoof,      // UDP NXDOMAIN, DoH резолвит
    EmptySpoof,         // UDP пустой ответ, DoH резолвит
    Intercepted,        // UDP timeout, DoH работает
    DohBlocked,         // Все DoH недоступны
    Unresolvable,       // Ни UDP, ни DoH не резолвит
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpFailureCode {
    ConnectOk,          // TCP handshake прошёл
    Reset,              // ConnectionResetError
    Timeout,            // socket.timeout
    Refused,            // ConnectionRefusedError
    Unreachable,        // ICMP unreachable
    DataVolumeCut,      // Связь обрывается на N КБ
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsFailureCode {
    HandshakeOk,        // TLS handshake прошёл
    Version13Ok,        // TLS 1.3 работает
    Version12Only,      // TLS 1.3 fail, 1.2 ok (ClientHello DPI!)
    Reset,              // RST во время TLS handshake
    Garbage,            // Wrong version / record overflow / decode error
    Alert,              // Fake TLS alert (SNI block, handshake failure)
    AlertSniblock,      // TLS alert: unrecognized_name
    AlertHandshake,     // TLS alert: handshake_failure
    AlertProtocol,      // TLS alert: protocol_version
    Mitm,               // Сертификат подменён (expired/self-signed/mismatch)
    MitmExpired,        // Certificate expired
    MitmSelfSigned,     // Self-signed certificate
    MitmHostnameMismatch, // Hostname mismatch
    Eof,                // Unexpected EOF (partial data)
    SilentDrop,         // TLS hang до timeout (TCP ok, TLS timeout)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpFailureCode {
    Ok,                 // HTTP 200
    Cutoff,             // Response обрезан (данные оборваны)
    Http451,            // Legal block
    RedirectSame,       // Редирект на тот же домен (ok)
    RedirectForeign,    // Редирект на чужой домен (ISP page)
    Timeout,            // HTTP timeout
    StubPage,           // RKN-заглушка в HTML
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionStage {
    TcpConnect,
    TcpConnected,
    TlsHandshake,
    TlsConnected,
    SendingData,
    ReadingData,
}
```

**Файлы:** `core/src/probe/classifier.rs`
**Зависимости:** Нет (чистый enum + serde)

---

#### T1.2: ProbeConfig — конфигурация модуля

**Приоритет:** P0 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Создать `config.rs` с провайдерами по умолчанию и таймаутами.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    // DNS
    pub dns_udp_servers: Vec<String>,     // ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    pub dns_doh_urls: Vec<String>,        // ["https://cloudflare-dns.com/dns-query"]
    pub dns_timeout: Duration,            // 3s
    pub dns_test_domains: Vec<String>,    // ["google.com", "youtube.com", "telegram.org"]

    // TCP
    pub tcp_connect_timeout: Duration,    // 3s
    pub tcp_race_count: usize,            // 3 IP для parallel race

    // TLS
    pub tls_connect_timeout: Duration,    // 5s
    pub tls_read_timeout: Duration,       // 5s

    // HTTP
    pub http_read_timeout: Duration,      // 8s
    pub http_max_bytes: usize,            // 32KB

    // TCP16
    pub tcp16_requests: usize,            // 16
    pub tcp16_pad_size: usize,            // 4KB per request
    pub tcp16_min_kb: u64,               // 12
    pub tcp16_max_kb: u64,               // 69
    pub tcp16_timeout_factor: f64,        // 3.0 (rtt × factor)
    pub tcp16_min_timeout: Duration,      // 1.5s

    // Accumulation
    pub hot_ttl: Duration,               // 24h
    pub probe_interval: Duration,         // 5 min
    pub promote_threshold: u32,           // 50 blocked verdicts
    pub family_threshold: usize,          // 10 subdomains → eTLD+1 expansion

    // RKN stub
    pub rkn_stub_substrings: Vec<String>, // 10 known substrings
}
```

**Файлы:** `core/src/probe/config.rs`
**Зависимости:** T1.1 (FailureCode)

---

#### T1.3: ISP Stub Page Detection (RKN substrings)

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Модуль `rkn_stub.rs` — проверяет HTTP response body на наличие 10 известных подстрок РКН.

```rust
const RKN_STUBS: &[&str] = &[
    "роcкомнaдзop",
    "poiskman",
    "blockpage",
    "заблокир",
    "ограничен",
    "restricted",
    "roskomsvoboda",
    "internet-zapret",
    "technique-of-blocking",
    "decision of",
];

pub fn is_rkn_stub(body: &[u8]) -> bool {
    let lower = body.to_ascii_lowercase();
    RKN_STUBS.iter().any(|stub| lower.windows(stub.len()).any(|w| w == stub.as_bytes()))
}
```

**Файлы:** `core/src/probe/rkn_stub.rs`
**Зависимости:** Нет

---

### Фаза P-2: Phase 1 — DNS Probe

#### T2.1: DNS Integrity Probe (UDP vs DoH cross-validation)

**Приоритет:** P0 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Реализовать `dns_probe.rs` — двуфазный probe DNS:

**Phase 1.1:** Быстрый ping — 1 домен через все серверы параллельно
**Phase 1.2:** Полный тест — только для серверов, которые молчали в Phase 1.1

Методика cross-validation (из dpi-detector):
1. Запросить A-запись через UDP/53 (Google, Cloudflare, Quad9)
2. Запросить ту же A-запись через DoH (Cloudflare, Google)
3. Сравнить результаты:
   - UDP IPs ⊂ DoH IPs → OK
   - UDP IPs ∩ DoH IPs = ∅ → **Poisoned**
   - UDP timeout, DoH ok → **Intercepted**
   - UDP NXDOMAIN, DoH ok → **NxdomainSpoof**
   - UDP пустой, DoH ok → **EmptySpoof**
   - Все DoH timeout → **DohBlocked**

**Дополнительно:** Fake-IP range detection (198.18.0.0/15, 100.64.0.0/10).

**Ключевая зависимость:** `trust-dns-resolver` (UDP) + `reqwest` (DoH).

```rust
pub struct DnsProbe {
    config: ProbeConfig,
    udp_resolver: AsyncResolver<...>,
    doh_client: reqwest::Client,
}

impl DnsProbe {
    pub async fn probe(&self, domain: &str) -> DnsProbeResult {
        // 1. Parallel: UDP + DoH
        // 2. Cross-validate
        // 3. Return DnsProbeResult { verdict, udp_ips, doh_ips, latency_us }
    }
}
```

**Файлы:** `core/src/probe/dns_probe.rs`
**Зависимости:** T1.1 (FailureCode), T1.2 (ProbeConfig)

---

### Фаза P-3: Phase 2 — TCP Probe

#### T3.1: TCP Connectivity Probe + Parallel Dial Racing

**Приоритет:** P0 | **Сложность:** Низкая | **Срок:** 1 день

**Описание:**
Реализовать `tcp_probe.rs` — TCP connect к домену с parallel race по N IP.

```rust
pub struct TcpProbe {
    config: ProbeConfig,
}

impl TcpProbe {
    /// Parallel race: N IP параллельно, первый успешный
    pub async fn probe(&self, ips: &[Ipv4Addr], port: u16) -> TcpProbeResult {
        let futs: Vec<_> = ips.iter().take(self.config.tcp_race_count)
            .map(|ip| self.probe_single(*ip, port))
            .collect();

        match futures::future::select_ok(futs).await {
            Ok(result) => result,
            Err(_) => TcpProbeResult { verdict: TcpFailureCode::Timeout, rtt_us: 0 },
        }
    }

    async fn probe_single(&self, ip: Ipv4Addr, port: u16) -> Result<TcpProbeResult> {
        let start = Instant::now();
        let stream = tokio::time::timeout(
            self.config.tcp_connect_timeout,
            TcpStream::connect((ip, port)),
        ).await??;
        let rtt = start.elapsed().as_micros() as u64;
        Ok(TcpProbeResult { verdict: TcpFailureCode::ConnectOk, rtt_us: rtt })
    }
}
```

**Файлы:** `core/src/probe/tcp_probe.rs`
**Зависимости:** T1.1, T1.2

---

### Фаза P-4: Phase 3 — TLS Probe

#### T4.1: TLS Staged Handshake (1.3 → 1.2) + Stage Tracking

**Приоритет:** P0 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Реализовать `tls_probe.rs` — staged TLS handshake с отслеживанием stage.

**Stage tracking** (из dpi-detector, 6 stages):
```rust
pub enum TlsStage {
    TcpConnected,      // SYN-ACK получен
    TlsHandshakeSent,  // ClientHello отправлен
    TlsConnected,      // Handshake завершён
}
```

**Attempt 1:** TLS 1.3 (Chrome fingerprint через rustls)
**Attempt 2:** TLS 1.2 (fallback если 1.3 fail)

**TLS version split detection** (из Ladon):
```rust
if tls13_result.is_fail() && tls12_result.is_ok() {
    return TlsFailureCode::Version12Only;  // DPI атакует ClientHello!
}
```

**Stage-aware classification:**
- RST во время `TlsHandshakeSent` → `TlsFailureCode::Reset`
- Timeout на `TlsHandshakeSent` → `TlsFailureCode::SilentDrop`
- garbage bytes на `TlsConnected` → `TlsFailureCode::Garbage`

**TLS MITM detection** (из dpi-detector):
- `verify_code == 10` → `MitmExpired`
- `verify_code in (18, 19)` → `MitmSelfSigned`
- `verify_code == 62` → `MitmHostnameMismatch`

**Ключевой крейт:** `rustls` + `webpki-roots` для TLS, `rustls-pemfile` для cert parsing.

```rust
pub struct TlsProbe {
    config: ProbeConfig,
    http_client: reqwest::Client,
}

impl TlsProbe {
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> TlsProbeResult {
        // Attempt 1: TLS 1.3
        let r13 = self.probe_version(ip, domain, TlsVersion::V13).await;

        // Attempt 2: TLS 1.2 (если 1.3 fail)
        if r13.verdict.is_fail() {
            let r12 = self.probe_version(ip, domain, TlsVersion::V12).await;
            // TLS version split detection
            if r13.verdict.is_tls_fail() && r12.verdict == TlsFailureCode::HandshakeOk {
                return TlsProbeResult { verdict: TlsFailureCode::Version12Only, .. };
            }
            return r12;
        }

        r13
    }
}
```

**Файлы:** `core/src/probe/tls_probe.rs`
**Зависимости:** T1.1, T1.2, T3.1 (TCP needed first)

---

#### T4.2: Server-active vs Path-active Discriminator

**Приоритет:** P0 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Создать `discriminator.rs` — определение: это блокировка от сервера или от DPI?

**Правила** (из Ladon):
```rust
pub fn discriminate(tls: &TlsFailureCode, http: &HttpFailureCode) -> Verdict {
    match tls {
        // Server-active: сервер сам ответил → это НЕ DPI
        TlsFailureCode::AlertSniblock
        | TlsFailureCode::AlertHandshake
        | TlsFailureCode::AlertProtocol
        | TlsFailureCode::Mitm
        | TlsFailureCode::MitmExpired
        | TlsFailureCode::MitmSelfSigned
        | TlsFailureCode::MitmHostnameMismatch
        => Verdict::Clear,

        // Path-active: что-то между клиентом и сервером
        TlsFailureCode::Reset
        | TlsFailureCode::Garbage
        | TlsFailureCode::SilentDrop
        | TlsFailureCode::Eof
        => Verdict::Blocked,

        // Timeout — неоднозначно, перепробовать
        TlsFailureCode::Version12Only  // ← это fingerprint, не timeout
        => Verdict::Blocked,

        _ => Verdict::Ambiguous,
    }
}

pub enum Verdict {
    Clear,       // Сервер доступен, DPI не блокирует
    Blocked,     // DPI блокирует
    Ambiguous,   // Неоднозначно, нужен re-probe
}
```

**Файлы:** `core/src/probe/discriminator.rs`
**Зависимости:** T1.1

---

### Фаза P-5: Phase 4 — HTTP Probe

#### T5.1: HTTP Application Layer Probe

**Приоритет:** P0 | **Сложность:** Низкая | **Срок:** 1 день

**Описание:**
Реализовать `http_probe.rs` — отправка GET / и чтение до 32KB.

**Детектируемые блокировки:**
- HTTP 451 → `HttpFailureCode::Http451`
- Response обрезан (< 1000 байт) → `HttpFailureCode::Cutoff`
- Редирект на чужой домен → `HttpFailureCode::RedirectForeign`
- RKN-заглушка в body → `HttpFailureCode::StubPage`
- Timeout → `HttpFailureCode::Timeout`

```rust
pub struct HttpProbe {
    config: ProbeConfig,
    http_client: reqwest::Client,
}

impl HttpProbe {
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> HttpProbeResult {
        let url = format!("https://{}/", domain);
        let resp = tokio::time::timeout(
            self.config.http_read_timeout,
            self.http_client.get(&url)
                .header("Host", domain)
                .send(),
        ).await??;

        // 1. HTTP 451
        if resp.status().as_u16() == 451 {
            return HttpProbeResult { verdict: HttpFailureCode::Http451, .. };
        }

        // 2. Read up to 32KB
        let body = resp.bytes().await?;

        // 3. Redirect check
        if let Some(location) = resp.headers().get("location") {
            let target = parse_redirect_domain(location);
            if target != domain && !target.ends_with(domain) {
                return HttpProbeResult { verdict: HttpFailureCode::RedirectForeign, .. };
            }
        }

        // 4. RKN stub check
        if is_rkn_stub(&body) {
            return HttpProbeResult { verdict: HttpFailureCode::StubPage, .. };
        }

        // 5. Cutoff check
        if body.len() < 1000 {
            return HttpProbeResult { verdict: HttpFailureCode::Cutoff, .. };
        }

        HttpProbeResult { verdict: HttpFailureCode::Ok, bytes_read: body.len() as u64 }
    }
}
```

**Файлы:** `core/src/probe/http_probe.rs`
**Зависимости:** T1.1, T1.2, T1.3 (rkn_stub)

---

### Фаза P-6: Phase 5 — Data-Volume Probe

#### T6.1: TCP 16-20KB Data-Volume Detection

**Приоритет:** P1 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Реализовать `tcp16_probe.rs` — обнаружение DPI, который обрывает соединение после N КБ данных.

**Методика** (из dpi-detector):
1. Открыть keep-alive соединение
2. Отправить 16 HEAD запросов с X-Pad заголовком (4KB random каждый)
3. RTT замеряется первыми 2 запросами
4. Dynamic timeout: `max(rtt × 3.0, 1.5s)`, capped at 12s
5. Если соединение падает на запросе N → blocking detected at N × 4KB

```rust
pub struct Tcp16Probe {
    config: ProbeConfig,
}

impl Tcp16Probe {
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> Tcp16ProbeResult {
        let stream = TcpStream::connect((ip, 443)).await?;
        let rtt = measure_rtt(&stream).await;

        let timeout_per_req = Duration::from_secs_f64(
            (rtt.as_secs_f64() * self.config.tcp16_timeout_factor)
                .max(self.config.tcp16_min_timeout.as_secs_f64())
                .min(12.0),
        );

        for i in 0..self.config.tcp16_requests {
            let padding = generate_padding(self.config.tcp16_pad_size);
            let req = format!(
                "HEAD / HTTP/1.1\r\nHost: {}\r\nX-Pad: {}\r\n\r\n",
                domain, hex_encode(&padding)
            );

            match tokio::time::timeout(timeout_per_req, stream.write_all(req.as_bytes())).await {
                Ok(Ok(())) => {}
                _ => return Tcp16ProbeResult {
                    detected: true,
                    detected_at_kb: (i as u64 * self.config.tcp16_pad_size as u64) / 1024,
                },
            }
        }

        Tcp16ProbeResult { detected: false, detected_at_kb: 0 }
    }
}
```

**Файлы:** `core/src/probe/tcp16_probe.rs`
**Зависимости:** T1.1, T1.2, T3.1

---

### Фаза P-7: Orchestrator + Accumulator

#### T7.1: ProbeModule Orchestrator — связывание 5 phases

**Приоритет:** P0 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Создать `mod.rs` — оркестратор, который запускает phases и собирает результат.

```rust
pub struct ProbeModule {
    config: ProbeConfig,
    dns: DnsProbe,
    tcp: TcpProbe,
    tls: TlsProbe,
    http: HttpProbe,
    tcp16: Tcp16Probe,
    accumulator: Accumulator,
}

impl ProbeModule {
    pub async fn probe(&self, domain: &str) -> ProbeResult {
        // Phase 1: DNS
        let dns = self.dns.probe(domain).await;

        // Resolve IPs (из Phase 1 или кэша)
        let ips = self.resolve_ips(domain, &dns).await;

        // Phase 2: TCP
        let tcp = self.tcp.probe(&ips, 443).await;

        if tcp.verdict != TcpFailureCode::ConnectOk {
            return ProbeResult { domain: domain.to_string(), blocked: true, .. };
        }

        // Phase 3: TLS
        let tls = self.tls.probe(ips[0], domain).await;

        // Phase 4: HTTP
        let http = self.http.probe(ips[0], domain).await;

        // Phase 5: Data-volume (опционально, если Phase 2-4 показали cutoff)
        let tcp16 = if matches!(http.verdict, HttpFailureCode::Cutoff) {
            Some(self.tcp16.probe(ips[0], domain).await)
        } else {
            None
        };

        // Discriminate
        let verdict = discriminate(&tls.verdict, &http.verdict);

        // Accumulate
        self.accumulator.record(domain, &verdict).await;

        ProbeResult {
            domain: domain.to_string(),
            dns, tcp, tls, http, tcp16,
            verdict,
            timestamp: Utc::now(),
        }
    }
}
```

**Файлы:** `core/src/probe/mod.rs`
**Зависимости:** T2.1, T3.1, T4.1, T4.2, T5.1, T6.1

---

#### T7.2: Accumulator — 24h temporal accumulation + eTLD+1

**Приоритет:** P1 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Создать `accumulator.rs` — хранение истории verdict'ов с 24h окном.

**Механизм:**
- Per-domain hot state с 24h TTL
- Re-probe каждые 5 минут
- 50+ blocked verdicts в 24h окне → permanent cache
- eTLD+1 expansion: 10+ поддоменов заблокированы → весь family

```rust
pub struct Accumulator {
    hot_entries: DashMap<String, HotEntry>,      // domain → entry
    cache_entries: DashSet<String>,               // permanent blocked
    family_entries: DashMap<String, FamilyEntry>, // eTLD+1 → expanded
}

struct HotEntry {
    blocked_count: AtomicU32,
    total_probes: AtomicU32,
    first_seen: Instant,
    last_probe: Instant,
}

pub struct ProbeVerdict {
    pub blocked: bool,
    pub confidence: f64,  // blocked_count / total_probes
    pub should_tunnel: bool,  // blocked AND confidence > 0.8
}
```

**Файлы:** `core/src/probe/accumulator.rs`
**Зависимости:** T1.1

---

### Фаза P-8: Strategy Map — Detection → Desync Recommendation

#### T8.1: ProbeResult → StrategyRecommendation mapping

**Приоритет:** P0 | **Сложность:** Средняя | **Срок:** 1 день

**Описание:**
Создать `strategy_map.rs` — связка типа блокировки с рекомендуемой стратегией.

```rust
pub struct StrategyRecommendation {
    pub strategy_id: u32,
    pub strategy_name: &'static str,
    pub category: StrategyCategory,
    pub confidence: f64,
    pub rationale: &'static str,
}

pub fn recommend(result: &ProbeResult) -> Vec<StrategyRecommendation> {
    let mut recs = Vec::new();

    // DNS poisoned → DoH mandatory
    if result.dns.verdict == DnsFailureCode::Poisoned {
        recs.push(StrategyRecommendation {
            strategy_id: 100,  // DoH DNS
            strategy_name: "doh_dns",
            category: StrategyCategory::Dns,
            confidence: 0.95,
            rationale: "DNS poisoned — force DoH resolver",
        });
    }

    // TCP RST → Fake CH + split
    if result.tcp.verdict == TcpFailureCode::Reset {
        recs.push(StrategyRecommendation {
            strategy_id: 1,  // TCP split
            strategy_name: "tcp_split",
            category: StrategyCategory::Tcp,
            confidence: 0.85,
            rationale: "TCP RST — DPI inspecting SYN/CH, apply split",
        });
    }

    // TLS 1.3 blocked, 1.2 works → Force TLS 1.2 + frag
    if result.tls.verdict == TlsFailureCode::Version12Only {
        recs.push(StrategyRecommendation {
            strategy_id: 15,  // TLS record frag
            strategy_name: "tls_record_frag",
            category: StrategyCategory::Tls,
            confidence: 0.90,
            rationale: "TLS 1.3 blocked, 1.2 works — DPI attacks ClientHello, force TLS 1.2 + frag",
        });
    }

    // TLS garbage → SEQ spoof + disorder
    if result.tls.verdict == TlsFailureCode::Garbage {
        recs.push(StrategyRecommendation {
            strategy_id: 6,  // SEQ spoof
            strategy_name: "seq_number_spoof",
            category: StrategyCategory::Tcp,
            confidence: 0.85,
            rationale: "TLS garbage injection — DPI injecting fake records, use SEQ spoof",
        });
    }

    // HTTP cutoff → TCP desync (data-volume aware)
    if result.http.verdict == HttpFailureCode::Cutoff {
        recs.push(StrategyRecommendation {
            strategy_id: 8,  // TCP window clamp
            strategy_name: "tcp_window_clamp",
            category: StrategyCategory::Tcp,
            confidence: 0.80,
            rationale: "HTTP cutoff at data phase — DPI counting packets, use window clamp",
        });
    }

    // CIDR whitelist (github fails, ya.ru works) → proxy required
    if is_cidr_whitelist(result) {
        recs.push(StrategyRecommendation {
            strategy_id: 35,  // SOCKS5 fallback
            strategy_name: "socks5_fallback",
            category: StrategyCategory::General,
            confidence: 0.95,
            rationale: "CIDR whitelist — only domestic IPs allowed, proxy required",
        });
    }

    recs
}
```

**Файлы:** `core/src/probe/strategy_map.rs`
**Зависимости:** T1.1, T4.2 (discriminator)

---

### Фаза P-9: API + Config Integration

#### T9.1: HTTP API endpoint для probe

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 1 день

**Описание:**
Добавить эндпоинт в `api/` для запуска probe.

```
POST /api/v1/probe
{
    "domain": "rutracker.org",
    "full": true  // false = quick (DNS + TCP + TLS), true = full (+ HTTP + TCP16)
}

Response:
{
    "domain": "rutracker.org",
    "verdict": "blocked",
    "confidence": 0.87,
    "dns": { "verdict": "ok", "latency_us": 45000 },
    "tcp": { "verdict": "connect_ok", "rtt_us": 12000, "ip": "195.82.146.214" },
    "tls": { "verdict": "version_12_only", "tls13_ok": false, "tls12_ok": true },
    "http": { "verdict": "ok", "bytes_read": 15000 },
    "recommendations": [
        { "strategy": "tls_record_frag", "confidence": 0.90, "rationale": "..." }
    ]
}
```

**Файлы:** `api/src/handlers/probe.rs`
**Зависимости:** T7.1

---

#### T9.2: Config.toml integration

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Добавить секцию `[probe]` в конфигурацию.

```toml
[probe]
enabled = true
auto_probe_domains = ["youtube.com", "telegram.org", "rutracker.org"]
auto_probe_interval = 300  # seconds
dns_udp_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
dns_doh_urls = ["https://cloudflare-dns.com/dns-query"]
tcp_connect_timeout = 3000  # ms
tls_connect_timeout = 5000  # ms
http_read_timeout = 8000    # ms
tcp16_enabled = false       # heavy, opt-in
accumulation_enabled = true
promote_threshold = 50
hot_ttl = 86400             # 24h in seconds
```

**Файлы:** `core/src/probe/config.rs` (расширить), `config.toml.example`
**Зависимости:** T1.2

---

#### T9.3: Тесты

**Приоритет:** P0 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Unit-тесты для каждого модуля + integration test.

| Модуль | Тесты |
|--------|-------|
| `classifier.rs` | FailureCode equality, serialization |
| `discriminator.rs` | Server-active vs Path-active по каждой комбинации |
| `dns_probe.rs` | Mock DNS responses (poisoned, nxdomain, ok) |
| `tcp_probe.rs` | Mock TCP connect (ok, reset, timeout) |
| `tls_probe.rs` | Mock TLS (version split, garbage, mitm) |
| `http_probe.rs` | Mock HTTP (ok, 451, cutoff, redirect, stub) |
| `tcp16_probe.rs` | Mock data-volume (detected at 16KB) |
| `accumulator.rs` | 24h window, promote threshold, eTLD+1 expansion |
| `strategy_map.rs` | Each failure code → correct recommendation |
| `rkn_stub.rs` | All 10 substrings detected |

**Файлы:** `core/src/probe/*.rs` (в каждом `#[cfg(test)] mod tests`)
**Зависимости:** Все T1.x–T8.x

---

## Сводная таблица задач

| ID | Задача | Фаза | Приоритет | Сложность | Срок | Зависимости |
|----|--------|:----:|:---------:|:---------:|:----:|:-----------:|
| T1.1 | FailureCode enum | P-1 | P0 | Низкая | 1d | — |
| T1.2 | ProbeConfig | P-1 | P0 | Низкая | 0.5d | T1.1 |
| T1.3 | RKN stub detection | P-1 | P1 | Низкая | 0.5d | — |
| T2.1 | DNS Integrity Probe | P-2 | P0 | Средняя | 2d | T1.1, T1.2 |
| T3.1 | TCP Probe + Race | P-3 | P0 | Низкая | 1d | T1.1, T1.2 |
| T4.1 | TLS Staged Handshake | P-4 | P0 | Средняя | 2d | T1.1, T1.2, T3.1 |
| T4.2 | Server-vs-Path Discriminator | P-4 | P0 | Низкая | 0.5d | T1.1 |
| T5.1 | HTTP Application Layer | P-5 | P0 | Низкая | 1d | T1.1, T1.2, T1.3 |
| T6.1 | TCP 16-20KB Data-Volume | P-6 | P1 | Средняя | 2d | T1.1, T1.2, T3.1 |
| T7.1 | ProbeModule Orchestrator | P-7 | P0 | Средняя | 2d | T2.1–T6.1 |
| T7.2 | Accumulator (24h + eTLD+1) | P-7 | P1 | Средняя | 2d | T1.1 |
| T8.1 | Strategy Map | P-8 | P0 | Средняя | 1d | T1.1, T4.2 |
| T9.1 | HTTP API endpoint | P-9 | P1 | Низкая | 1d | T7.1 |
| T9.2 | Config.toml integration | P-9 | P1 | Низкая | 0.5d | T1.2 |
| T9.3 | Тесты | P-9 | P0 | Средняя | 2d | Все |

**Итого: 15 задач, ~20 рабочих дней**

---

## Дорожная карта

```
Неделя 1 (P-1, P-2, P-3):
├── T1.1 FailureCode enum .............. 1d
├── T1.2 ProbeConfig ................... 0.5d
├── T1.3 RKN stub ...................... 0.5d
├── T2.1 DNS Probe ..................... 2d
└── T3.1 TCP Probe + Race .............. 1d

Неделя 2 (P-4, P-5):
├── T4.1 TLS Staged Handshake .......... 2d
├── T4.2 Discriminator ................. 0.5d
└── T5.1 HTTP Probe .................... 1d

Неделя 3 (P-6, P-7, P-8):
├── T6.1 TCP16 Probe ................... 2d
├── T7.1 Orchestrator .................. 2d
└── T8.1 Strategy Map .................. 1d

Неделя 4 (P-9):
├── T7.2 Accumulator ................... 2d
├── T9.1 API endpoint .................. 1d
├── T9.2 Config integration ............ 0.5d
└── T9.3 Тесты ......................... 2d
```

---

## Ключевые зависимости (crates)

| Крейт | Версия | Назначение |
|--------|:------:|-----------|
| `rustls` | 0.23 | TLS handshake (1.3 + 1.2) с stage tracking |
| `webpki-roots` | 0.26 | CA certificates |
| `tokio` | 1.52 | Async runtime (TCP, timers) |
| `reqwest` | 0.12 | HTTP client (DoH, HTTP probe) |
| `trust-dns-resolver` | 0.23 | UDP DNS resolver |
| `pnet_packet` | 0.35 | Packet parsing (если нужен raw) |
| `dashmap` | 6 | Concurrent maps (accumulator) |
| `serde` + `serde_json` | 1.0 | Serialization (API) |
| `anyhow` | 1 | Error handling |
| `tracing` | 0.1 | Structured logging |

---

## Интеграция с существующим кодом

### Связь с `adaptive/strategy.rs`

ProbeModule recommendations подключаются к `StrategyRegistry`:

```rust
// При старте engine:
let probe = ProbeModule::new(config);
let recommendations = probe.probe("rutracker.org").await;

for rec in strategy_map::recommend(&recommendations) {
    if StrategyRegistry::global().contains(rec.strategy_id) {
        tracing::info!(
            "Domain {} → strategy {} (confidence: {:.0}%)",
            recommendations.domain,
            rec.strategy_name,
            rec.confidence * 100.0,
        );
    }
}
```

### Связь с `split_tunnel.rs`

Accumulator feed'ит `SplitTunnel`:

```rust
// Accumulator обновляет blacklist:
if verdict.should_tunnel {
    split_tunnel.add_to_blacklist(domain);
}
```

### Связь с `conntrack.rs`

ProbeResult сохраняется в conntrack entry:

```rust
conntrack.upsert(key, ConntrackEntry {
    probe_verdict: Some(verdict),
    recommended_strategy: Some(strategy_id),
    ..default
});
```

---

## Фаза P-10: GUI Integration (Tauri + React)

### T10.1: Tauri command — `run_probe`

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 1 день

**Описание:**
Добавить Tauri command в `src/ui/src-tauri/src/commands/mod.rs`:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub domain: String,
    pub verdict: String,          // "clear" | "blocked" | "ambiguous"
    pub confidence: f64,
    pub dns: PhaseResult,
    pub tcp: PhaseResult,
    pub tls: PhaseResult,
    pub http: PhaseResult,
    pub tcp16: Option<PhaseResult>,
    pub recommendations: Vec<RecommendationResponse>,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseResult {
    pub phase: String,            // "dns" | "tcp" | "tls" | "http" | "tcp16"
    pub status: String,           // "ok" | "blocked" | "error"
    pub detail: String,           // "version_12_only" | "reset" | ...
    pub latency_us: Option<u64>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecommendationResponse {
    pub strategy_id: u32,
    pub strategy_name: String,
    pub confidence: f64,
    pub rationale: String,
}

#[tauri::command]
pub async fn run_probe(
    domain: String,
    full: bool,
    api_port: Option<u16>,
) -> Result<ProbeResponse, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe", port);

    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .json(&serde_json::json!({ "domain": domain, "full": full }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Probe request failed: {}", e))?;

    resp.json::<ProbeResponse>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn get_probe_history(api_port: Option<u16>) -> Result<Vec<ProbeResponse>, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe/history", port);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    resp.json::<Vec<ProbeResponse>>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}
```

**Файлы:** `src/ui/src-tauri/src/commands/mod.rs`
**Зависимости:** T9.1 (API endpoint)

---

### T10.2: React компонент `ProbePanel.tsx`

**Приоритет:** P1 | **Сложность:** Средняя | **Срок:** 2 дня

**Описание:**
Основная панель с визуализацией probe pipeline.

```tsx
// src/ui/src/components/ProbePanel.tsx

interface ProbePanelProps {}

export function ProbePanel({}: ProbePanelProps) {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProbeResponse | null>(null);
  const [history, setHistory] = useState<ProbeResponse[]>([]);

  const handleProbe = async (full: boolean) => {
    setLoading(true);
    try {
      const res = await invoke<ProbeResponse>("run_probe", {
        domain,
        full,
      });
      setResult(res);
      setHistory((prev) => [res, ...prev].slice(0, 50));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="probe-panel">
      {/* Input */}
      <div className="probe-input">
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
        />
        <button onClick={() => handleProbe(false)} disabled={loading}>
          Быстрая проверка
        </button>
        <button onClick={() => handleProbe(true)} disabled={loading}>
          Полная проверка
        </button>
      </div>

      {/* Pipeline visualization */}
      {result && (
        <div className="probe-pipeline">
          <PhaseCard phase={result.dns} />
          <Arrow />
          <PhaseCard phase={result.tcp} />
          <Arrow />
          <PhaseCard phase={result.tls} />
          <Arrow />
          <PhaseCard phase={result.http} />
          {result.tcp16 && (
            <>
              <Arrow />
              <PhaseCard phase={result.tcp16} />
            </>
          )}
        </div>
      )}

      {/* Verdict */}
      {result && (
        <div className={`probe-verdict ${result.verdict}`}>
          <h3>
            {result.verdict === "blocked"
              ? "BLOCKED"
              : result.verdict === "clear"
              ? "CLEAR"
              : "AMBIGUOUS"}
          </h3>
          <p>Confidence: {(result.confidence * 100).toFixed(0)}%</p>
        </div>
      )}

      {/* Recommendations */}
      {result?.recommendations && result.recommendations.length > 0 && (
        <div className="probe-recommendations">
          <h4>Рекомендуемые стратегии:</h4>
          {result.recommendations.map((rec, i) => (
            <div key={i} className="recommendation-card">
              <span className="strategy-name">{rec.strategy_name}</span>
              <span className="confidence">
                {(rec.confidence * 100).toFixed(0)}%
              </span>
              <p className="rationale">{rec.rationale}</p>
            </div>
          ))}
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="probe-history">
          <h4>История проверок:</h4>
          <table>
            <thead>
              <tr>
                <th>Домен</th>
                <th>Вердикт</th>
                <th>Тип блокировки</th>
                <th>Время</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i} className={h.verdict}>
                  <td>{h.domain}</td>
                  <td>{h.verdict}</td>
                  <td>{h.tls?.detail || h.tcp?.detail}</td>
                  <td>{new Date(h.timestamp).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Подкомпонент для отображения одной фазы
function PhaseCard({ phase }: { phase: PhaseResult }) {
  const statusColors: Record<string, string> = {
    ok: "#22c55e",
    blocked: "#ef4444",
    error: "#eab308",
  };

  return (
    <div
      className="phase-card"
      style={{ borderColor: statusColors[phase.status] }}
    >
      <div className="phase-name">{phase.phase.toUpperCase()}</div>
      <div className="phase-status" style={{ color: statusColors[phase.status] }}>
        {phase.status}
      </div>
      <div className="phase-detail">{phase.detail}</div>
      {phase.latency_us && (
        <div className="phase-latency">{(phase.latency_us / 1000).toFixed(1)}ms</div>
      )}
    </div>
  );
}

function Arrow() {
  return <div className="pipeline-arrow">→</div>;
}
```

**Файлы:** `src/ui/src/components/ProbePanel.tsx`
**Зависимости:** T10.1

---

### T10.3: Стили для ProbePanel

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
CSS-стили для pipeline визуализации.

```css
/* src/ui/src/components/ProbePanel.css */

.probe-panel {
  padding: 1rem;
}

.probe-input {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}

.probe-input input {
  flex: 1;
  padding: 0.5rem 1rem;
  border: 1px solid #374151;
  border-radius: 0.5rem;
  background: #1f2937;
  color: #f9fafb;
  font-size: 0.875rem;
}

.probe-input button {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 0.5rem;
  background: #3b82f6;
  color: white;
  cursor: pointer;
  font-size: 0.875rem;
}

.probe-input button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.probe-pipeline {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  overflow-x: auto;
  padding: 1rem 0;
}

.phase-card {
  min-width: 120px;
  padding: 0.75rem;
  border: 2px solid #374151;
  border-radius: 0.5rem;
  background: #1f2937;
  text-align: center;
}

.phase-name {
  font-size: 0.75rem;
  font-weight: 600;
  color: #9ca3af;
  margin-bottom: 0.25rem;
}

.phase-status {
  font-size: 1rem;
  font-weight: 700;
  text-transform: uppercase;
}

.phase-detail {
  font-size: 0.75rem;
  color: #d1d5db;
  margin-top: 0.25rem;
}

.phase-latency {
  font-size: 0.75rem;
  color: #6b7280;
  margin-top: 0.125rem;
}

.pipeline-arrow {
  font-size: 1.5rem;
  color: #6b7280;
}

.probe-verdict {
  padding: 1rem;
  border-radius: 0.5rem;
  margin-bottom: 1.5rem;
  text-align: center;
}

.probe-verdict.blocked {
  background: #7f1d1d;
  border: 1px solid #ef4444;
}

.probe-verdict.clear {
  background: #14532d;
  border: 1px solid #22c55e;
}

.probe-verdict.ambiguous {
  background: #713f12;
  border: 1px solid #eab308;
}

.probe-verdict h3 {
  font-size: 1.25rem;
  margin: 0 0 0.25rem 0;
}

.probe-recommendations {
  margin-bottom: 1.5rem;
}

.recommendation-card {
  padding: 0.75rem;
  border: 1px solid #374151;
  border-radius: 0.5rem;
  background: #1f2937;
  margin-bottom: 0.5rem;
}

.strategy-name {
  font-weight: 600;
  color: #60a5fa;
}

.confidence {
  float: right;
  font-weight: 600;
  color: #34d399;
}

.rationale {
  font-size: 0.75rem;
  color: #9ca3af;
  margin: 0.25rem 0 0 0;
}

.probe-history table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.probe-history th {
  text-align: left;
  padding: 0.5rem;
  border-bottom: 1px solid #374151;
  color: #9ca3af;
}

.probe-history td {
  padding: 0.5rem;
  border-bottom: 1px solid #1f2937;
}

.probe-history tr.blocked td {
  color: #ef4444;
}

.probe-history tr.clear td {
  color: #22c55e;
}
```

**Файлы:** `src/ui/src/components/ProbePanel.css`
**Зависимости:** T10.2

---

### T10.4: Навигация — добавить ProbePanel в main layout

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Добавить вкладку "DPI Probe" в навигацию приложения.

```tsx
// src/ui/src/App.tsx — изменения:

import { ProbePanel } from "./components/ProbePanel";

// В navigation добавить:
{ id: "probe", label: "DPI Probe", icon: "🔍" }

// В main content area:
case "probe":
  return <ProbePanel />;
```

**Файлы:** `src/ui/src/App.tsx`
**Зависимости:** T10.2

---

### T10.5: System Tray — пункт "Проверить DPI"

**Приоритет:** P2 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Добавить пункт в system tray context menu.

```rust
// src/ui/src-tauri/src/tray.rs — изменения:

use tauri::Manager;

pub fn create_tray(app: &tauri::App) -> Result<tauri::TrayIcon, Box<dyn std::error::Error>> {
    let tray = app.tray_by_id("main")?;

    // Добавить пункт "Проверить DPI"
    tray.set_menu(Some(
        tauri::menu::MenuBuilder::new(app)
            .item(&tauri::menu::MenuItem::with_id(
                app,
                "check_dpi",
                "Проверить DPI",
                true,
                None::<&str>,
            )?)
            .build()?,
    ))?;

    Ok(tray)
}

// В обработчике событий tray:
pub fn on_menu_event(app: &tauri::App, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        "check_dpi" => {
            // Открыть окно с ProbePanel
            if let Some(window) = app.get_webview_window("main") {
                window.show().ok();
                window.set_focus().ok();
                // Навигировать на вкладку probe
                window.emit("navigate-to", "probe").ok();
            }
        }
        _ => {}
    }
}
```

**Файлы:** `src/ui/src-tauri/src/tray.rs`
**Зависимости:** T10.2

---

### T10.6: Dashboard widget — авто-probe статус

**Приоритет:** P2 | **Сложность:** Средняя | **Срок:** 1 день

**Описание:**
Добавить мини-виджет на Dashboard с результатами последнего probe.

```tsx
// src/ui/src/components/Dashboard.tsx — добавить:

function ProbeWidget() {
  const [lastProbe, setLastProbe] = useState<ProbeResponse | null>(null);

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const history = await invoke<ProbeResponse[]>("get_probe_history");
        if (history.length > 0) {
          setLastProbe(history[0]);
        }
      } catch {}
    }, 30000); // обновлять каждые 30 сек

    return () => clearInterval(interval);
  }, []);

  if (!lastProbe) return null;

  return (
    <div className="probe-widget">
      <h4>DPI Status</h4>
      <div className={`status-dot ${lastProbe.verdict}`} />
      <span>{lastProbe.domain}</span>
      <span className="verdict-label">{lastProbe.verdict}</span>
      {lastProbe.recommendations[0] && (
        <span className="strategy-label">
          → {lastProbe.recommendations[0].strategy_name}
        </span>
      )}
    </div>
  );
}
```

**Файлы:** `src/ui/src/components/Dashboard.tsx`
**Зависимости:** T10.1

---

### T10.7: Tauri registration — подключить commands

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Зарегистрировать новые commands в Tauri invoke handler.

```rust
// src/ui/src-tauri/src/lib.rs — изменения:

mod commands;

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_health,
            commands::get_conntrack,
            commands::get_config,
            commands::save_config,
            commands::run_probe,         // ← добавить
            commands::get_probe_history, // ← добавить
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

**Файлы:** `src/ui/src-tauri/src/lib.rs`
**Зависимости:** T10.1

---

### T10.8: Preset domain lists — готовые списки для тестирования

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 1 день

**Описание:**
Добавить встроенные списки доменов из ByeByeDPI (`D:\ByeDPI\research\ByeByeDPI\app\src\main\assets\proxytest_*.sites`) в модуль probe.

**Источник:** ByeByeDPI проект, 8 списков:

| Список | Файл | Кол-во доменов | Назначение |
|--------|------|:--------------:|------------|
| youtube | `proxytest_youtube.sites` | 13 | YouTube + Google video CDN |
| googlevideo | `proxytest_googlevideo.sites` | 19 | Google Video edge servers (rr*.googlevideo.com) |
| telegram | `proxytest_telegram.sites` | 52 | Telegram все поддомены |
| discord | `proxytest_discord.sites` | 21 | Discord все сервисы |
| social | `proxytest_social.sites` | 16 | Facebook, Instagram, LinkedIn, X, Snapchat, Proton |
| general | `proxytest_general.sites` | 6 | Торрент-трекеры, speedtest |
| cloudflare | `proxytest_cloudflare.sites` | 4 | Cloudflare CDN |
| türkiye | `proxytest_türkiye.sites` | 8 | Roblox, Wattpad, Pastebin (TR-specific) |

**Реализация в Rust:**

```rust
// core/src/probe/presets.rs

/// Встроенные списки доменов для probe'а.
/// Источник: ByeByeDPI (proxytest_*.sites)
pub struct PresetDomainList {
    pub id: &'static str,
    pub name: &'static str,
    pub domains: &'static [&'static str],
    pub category: PresetCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetCategory {
    Video,
    Messenger,
    Social,
    Cdn,
    General,
    RegionSpecific,
}

pub const PRESET_LISTS: &[PresetDomainList] = &[
    PresetDomainList {
        id: "youtube",
        name: "YouTube",
        category: PresetCategory::Video,
        domains: &[
            "youtube.com", "youtu.be", "i.ytimg.com", "i9.ytimg.com",
            "yt3.ggpht.com", "yt4.ggpht.com", "googleapis.com",
            "jnn-pa.googleapis.com", "googleusercontent.com",
            "signaler-pa.youtube.com", "youtubei.googleapis.com",
            "manifest.googlevideo.com", "yt3.googleusercontent.com",
        ],
    },
    PresetDomainList {
        id: "googlevideo",
        name: "Google Video CDN",
        category: PresetCategory::Video,
        domains: &[
            "rr1---sn-4axm-n8vs.googlevideo.com",
            "rr1---sn-gvnuxaxjvh-o8ge.googlevideo.com",
            "rr1---sn-ug5onuxaxjvh-p3ul.googlevideo.com",
            "rr1---sn-ug5onuxaxjvh-n8v6.googlevideo.com",
            "rr4---sn-q4flrnsl.googlevideo.com",
            "rr10---sn-gvnuxaxjvh-304z.googlevideo.com",
            "rr14---sn-n8v7kn7r.googlevideo.com",
            "rr16---sn-axq7sn76.googlevideo.com",
            "rr1---sn-8ph2xajvh-5xge.googlevideo.com",
            "rr1---sn-gvnuxaxjvh-5gie.googlevideo.com",
            "rr12---sn-gvnuxaxjvh-bvwz.googlevideo.com",
            "rr5---sn-n8v7knez.googlevideo.com",
            "rr1---sn-u5uuxaxjvhg0-ocje.googlevideo.com",
            "rr2---sn-q4fl6ndl.googlevideo.com",
            "rr5---sn-gvnuxaxjvh-n8vk.googlevideo.com",
            "rr4---sn-jvhnu5g-c35d.googlevideo.com",
            "rr1---sn-q4fl6n6y.googlevideo.com",
            "rr2---sn-hgn7ynek.googlevideo.com",
            "rr1---sn-xguxaxjvh-gufl.googlevideo.com",
        ],
    },
    PresetDomainList {
        id: "telegram",
        name: "Telegram",
        category: PresetCategory::Messenger,
        domains: &[
            "telegram.org", "core.telegram.org", "web.telegram.org",
            "webk.telegram.org", "my.telegram.org", "api.telegram.org",
            "telegram.me", "telegram.dog", "telegra.ph",
            "voice.telegram.org", "cdn.telegram.org",
            "desktop.telegram.org", "macos.telegram.org",
            "ios.telegram.org", "android.telegram.org",
            "premium.telegram.org", "fragment.telegram.org",
            "ton.telegram.org", "wallet.telegram.org",
            "venus.web.telegram.org", "pluto.web.telegram.org",
            "aurora.web.telegram.org", "vesta.web.telegram.org",
            "zws1.web.telegram.org", "zws2.web.telegram.org",
            // ... ещё 27 поддоменов
        ],
    },
    PresetDomainList {
        id: "discord",
        name: "Discord",
        category: PresetCategory::Messenger,
        domains: &[
            "discord.com", "discord.gg", "discord.app", "discord.dev",
            "discord.new", "discord.gift", "discord.gifts", "discord.media",
            "discord.store", "discord.design", "discord.co", "dis.gd",
            "discordapp.com", "discordcdn.com", "discordactivities.com",
            "discordpartygames.com", "discordmerch.com",
            "stable.dl2.discordapp.net",
        ],
    },
    PresetDomainList {
        id: "social",
        name: "Social Media",
        category: PresetCategory::Social,
        domains: &[
            "facebook.com", "fb.com", "fb.me", "fbcdn.net",
            "instagram.com", "static.cdninstagram.com",
            "x.com", "twitter.com",
            "linkedin.com", "snapchat.com", "snap.com",
            "medium.com", "soundcloud.com", "proton.me",
        ],
    },
    PresetDomainList {
        id: "general",
        name: "General",
        category: PresetCategory::General,
        domains: &[
            "rutracker.org", "nyaa.si", "rutor.org",
            "nnmclub.to", "speedtest.net", "ookla.com",
        ],
    },
    PresetDomainList {
        id: "cloudflare",
        name: "Cloudflare",
        category: PresetCategory::Cdn,
        domains: &[
            "cloudflare.com", "cloudflare.net",
            "cloudflarecn.net", "cloudflare-ech.com",
        ],
    },
    PresetDomainList {
        id: "turkiye",
        name: "Türkiye",
        category: PresetCategory::RegionSpecific,
        domains: &[
            "roblox.com", "wattpad.com", "pastebin.com",
            "4shared.com", "wikileaks.org", "bitly.com",
            "cutt.ly", "t2m.io",
        ],
    },
];

/// Получить список по ID
pub fn get_preset(id: &str) -> Option<&'static PresetDomainList> {
    PRESET_LISTS.iter().find(|l| l.id == id)
}

/// Получить все домены из активных списков
pub fn get_active_domains(active_ids: &[&str]) -> Vec<&'static str> {
    PRESET_LISTS.iter()
        .filter(|l| active_ids.contains(&l.id))
        .flat_map(|l| l.domains.iter().copied())
        .collect()
}
```

**Файлы:** `core/src/probe/presets.rs`
**Зависимости:** Нет (чистые данные)

---

### T10.9: ProbePanel — выбор preset списков

**Приоритет:** P1 | **Сложность:** Средняя | **Срок:** 1 день

**Описание:**
Обновить `ProbePanel.tsx` — добавить выпадающий список с preset'ами и кнопку "Проверить все".

```tsx
// ProbePanel.tsx — дополнения:

interface PresetList {
  id: string;
  name: string;
  category: string;
  domain_count: number;
}

// В компоненте:
const [presets, setPresets] = useState<PresetList[]>([]);
const [selectedPresets, setSelectedPresets] = useState<string[]>([]);
const [batchResults, setBatchResults] = useState<ProbeResponse[]>([]);

// Загрузка presets при монтировании
useEffect(() => {
  invoke<PresetList[]>("get_preset_lists").then(setPresets);
}, []);

// Batch probe — проверить все домены из выбранных списков
const handleBatchProbe = async () => {
  setLoading(true);
  try {
    const results = await invoke<ProbeResponse[]>("run_batch_probe", {
      presetIds: selectedPresets,
    });
    setBatchResults(results);
  } catch (err) {
    console.error(err);
  } finally {
    setLoading(false);
  }
};

// JSX — добавить секцию presets:
return (
  <div className="probe-panel">
    {/* Preset selector */}
    <div className="preset-selector">
      <h4>Готовые списки:</h4>
      <div className="preset-chips">
        {presets.map((p) => (
          <button
            key={p.id}
            className={`preset-chip ${selectedPresets.includes(p.id) ? "active" : ""}`}
            onClick={() => togglePreset(p.id)}
          >
            {p.name} ({p.domain_count})
          </button>
        ))}
      </div>
      <button
        className="batch-probe-btn"
        onClick={handleBatchProbe}
        disabled={selectedPresets.length === 0 || loading}
      >
        Проверить выбранные ({selectedPresets.length})
      </button>
    </div>

    {/* Batch results — таблица */}
    {batchResults.length > 0 && (
      <div className="batch-results">
        <h4>Результаты проверки:</h4>
        <div className="results-summary">
          <span className="clear">
            {batchResults.filter((r) => r.verdict === "clear").length} OK
          </span>
          <span className="blocked">
            {batchResults.filter((r) => r.verdict === "blocked").length} Blocked
          </span>
          <span className="ambiguous">
            {batchResults.filter((r) => r.verdict === "ambiguous").length} Ambiguous
          </span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Домен</th>
              <th>Список</th>
              <th>DNS</th>
              <th>TCP</th>
              <th>TLS</th>
              <th>HTTP</th>
              <th>Вердикт</th>
            </tr>
          </thead>
          <tbody>
            {batchResults.map((r, i) => (
              <tr key={i} className={r.verdict}>
                <td>{r.domain}</td>
                <td>{getPresetName(r.domain)}</td>
                <td className={r.dns.status}>{r.dns.detail}</td>
                <td className={r.tcp.status}>{r.tcp.detail}</td>
                <td className={r.tls.status}>{r.tls.detail}</td>
                <td className={r.http.status}>{r.http.detail}</td>
                <td className={`verdict-${r.verdict}`}>{r.verdict}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}

    {/* Single domain probe (existing) */}
    {/* ... */}
  </div>
);
```

**Файлы:** `src/ui/src/components/ProbePanel.tsx` (расширить)
**Зависимости:** T10.2, T10.8

---

### T10.10: Tauri commands — presets + batch probe

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Добавить Tauri commands для работы с presets.

```rust
// commands/mod.rs — дополнения:

#[derive(Debug, Serialize, Deserialize)]
pub struct PresetListResponse {
    pub id: String,
    pub name: String,
    pub category: String,
    pub domain_count: usize,
}

#[tauri::command]
pub async fn get_preset_lists() -> Result<Vec<PresetListResponse>, String> {
    let url = "http://127.0.0.1:11337/api/v1/probe/presets";
    let resp = reqwest::get(url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;
    resp.json::<Vec<PresetListResponse>>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn run_batch_probe(
    preset_ids: Vec<String>,
    api_port: Option<u16>,
) -> Result<Vec<ProbeResponse>, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe/batch", port);

    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .json(&serde_json::json!({ "preset_ids": preset_ids }))
        .timeout(std::time::Duration::from_secs(120))  // больше таймаут для batch
        .send()
        .await
        .map_err(|e| format!("Batch probe request failed: {}", e))?;

    resp.json::<Vec<ProbeResponse>>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}
```

**Файлы:** `src/ui/src-tauri/src/commands/mod.rs`
**Зависимости:** T10.1, T10.8

---

### T10.11: API endpoints — presets + batch

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Добавить эндпоинты в service API.

```
GET /api/v1/probe/presets

Response:
[
  { "id": "youtube", "name": "YouTube", "category": "video", "domain_count": 13 },
  { "id": "telegram", "name": "Telegram", "category": "messenger", "domain_count": 52 },
  ...
]

POST /api/v1/probe/batch
{
    "preset_ids": ["youtube", "telegram"],
    "full": false
}

Response: Vec<ProbeResult>  // по одному на каждый домен
```

**Файлы:** `api/src/handlers/probe.rs`
**Зависимости:** T9.1, T10.8

---

### T10.12: Custom domain lists — создание и управление пользовательскими списками

**Приоритет:** P1 | **Сложность:** Средняя | **Срок:** 1.5 дня

**Описание:**
Пользователь создаёт собственные списки доменов, редактирует, удаляет, сохраняет.
Выбор для probe: один список, несколько, или все.

**Backend — Tauri commands:**

```rust
// commands/mod.rs — дополнения:

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomDomainList {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[tauri::command]
pub async fn get_custom_lists() -> Result<Vec<CustomDomainList>, String> {
    let path = custom_lists_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("Read error: {}", e))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn save_custom_list(list: CustomDomainList) -> Result<(), String> {
    let path = custom_lists_path();
    let mut lists = get_custom_lists().await.unwrap_or_default();

    if let Some(idx) = lists.iter().position(|l| l.id == list.id) {
        lists[idx] = list;
    } else {
        lists.push(list);
    }

    let data = serde_json::to_string_pretty(&lists)
        .map_err(|e| format!("Serialize error: {}", e))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, data)
        .map_err(|e| format!("Write error: {}", e))
}

#[tauri::command]
pub async fn delete_custom_list(id: String) -> Result<(), String> {
    let path = custom_lists_path();
    let mut lists = get_custom_lists().await.unwrap_or_default();
    lists.retain(|l| l.id != id);

    let data = serde_json::to_string_pretty(&lists)
        .map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Write error: {}", e))
}

#[tauri::command]
pub async fn import_domains_from_text(text: String) -> Result<Vec<String>, String> {
    Ok(text.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

fn custom_lists_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_default()
        .join("FreeDPI")
        .join("custom_probe_lists.json")
}
```

**Frontend — расширение ProbePanel.tsx:**

```tsx
// Новые интерфейсы:
interface CustomList {
  id: string;
  name: string;
  domains: string[];
  created_at: string;
  updated_at: string;
}

// State:
const [customLists, setCustomLists] = useState<CustomList[]>([]);
const [showCreateModal, setShowCreateModal] = useState(false);
const [editingList, setEditingList] = useState<CustomList | null>(null);
const [selectedLists, setSelectedLists] = useState<string[]>([]); // preset + custom IDs

// Modal создания/редактирования списка:
function ListEditorModal({
  list,
  onSave,
  onClose,
}: {
  list: CustomList | null;
  onSave: (list: CustomList) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(list?.name || "");
  const [domainText, setDomainText] = useState(
    list?.domains.join("\n") || ""
  );

  const handleSave = async () => {
    const domains = await invoke<string[]>("import_domains_from_text", {
      text: domainText,
    });
    onSave({
      id: list?.id || crypto.randomUUID(),
      name,
      domains,
      created_at: list?.created_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
  };

  return (
    <div className="modal-overlay">
      <div className="modal">
        <h3>{list ? "Редактировать список" : "Новый список"}</h3>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Название списка"
        />
        <textarea
          value={domainText}
          onChange={(e) => setDomainText(e.target.value)}
          placeholder={"example.com\nyoutube.com\ntelegram.org\n\n# комментарии игнорируются"}
          rows={15}
        />
        <div className="modal-info">
          Доменов: {domainText.split("\n").filter((l) => l.trim() && !l.startsWith("#")).length}
        </div>
        <div className="modal-actions">
          <button onClick={onClose}>Отмена</button>
          <button onClick={handleSave} disabled={!name.trim()}>
            Сохранить
          </button>
        </div>
      </div>
    </div>
  );
}

// В JSX ProbePanel — секция "Мои списки":
<div className="my-lists-section">
  <div className="section-header">
    <h4>Мои списки:</h4>
    <button onClick={() => setShowCreateModal(true)}>+ Создать</button>
  </div>
  {customLists.map((list) => (
    <div key={list.id} className="custom-list-card">
      <div className="list-info">
        <span
          className={`list-check ${selectedLists.includes(`custom:${list.id}`) ? "active" : ""}`}
          onClick={() => toggleCustomList(list.id)}
        >
          ☑
        </span>
        <span className="list-name">{list.name}</span>
        <span className="list-count">{list.domains.length} доменов</span>
      </div>
      <div className="list-actions">
        <button onClick={() => setEditingList(list)}>✏️</button>
        <button onClick={() => handleDeleteList(list.id)}>🗑️</button>
      </div>
    </div>
  ))}
</div>

// Импорт из текста/файла:
<div className="import-section">
  <button onClick={handleImportFromFile}>Импорт из файла</button>
  <span className="import-hint">.txt, по одному домену на строку</span>
</div>
```

**CSS — стили модала и списков:**

```css
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.modal {
  background: #1f2937;
  border: 1px solid #374151;
  border-radius: 0.75rem;
  padding: 1.5rem;
  width: 500px;
  max-height: 80vh;
  overflow-y: auto;
}

.modal input, .modal textarea {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #374151;
  border-radius: 0.375rem;
  background: #111827;
  color: #f9fafb;
  margin-bottom: 0.75rem;
  font-family: monospace;
  font-size: 0.875rem;
}

.modal-info {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-bottom: 0.75rem;
}

.modal-actions {
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
}

.my-lists-section {
  margin-bottom: 1.5rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.custom-list-card {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0.75rem;
  border: 1px solid #374151;
  border-radius: 0.375rem;
  margin-bottom: 0.375rem;
  background: #1f2937;
}

.list-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.list-check {
  cursor: pointer;
  font-size: 1.1rem;
}

.list-check.active {
  color: #22c55e;
}

.list-count {
  font-size: 0.75rem;
  color: #6b7280;
}

.list-actions button {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.25rem;
}

.import-section {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.import-hint {
  font-size: 0.75rem;
  color: #6b7280;
}
```

**API endpoint:**

```
POST /api/v1/probe/custom-lists
GET /api/v1/probe/custom-lists
DELETE /api/v1/probe/custom-lists/{id}

POST /api/v1/probe/batch
{
    "preset_ids": ["youtube", "telegram"],        // встроенные
    "custom_list_ids": ["my-list-1", "my-list-2"], // пользовательские
    "full": false
}
```

**Файлы:**
- `src/ui/src-tauri/src/commands/mod.rs`
- `src/ui/src/components/ProbePanel.tsx`
- `src/ui/src/components/ProbePanel.css`
- `api/src/handlers/probe.rs`

**Зависимости:** T10.2, T10.8, T10.11

---

### T10.13: Preset + Custom выбор — объединённый селектор

**Приоритет:** P1 | **Сложность:** Низкая | **Срок:** 0.5 дня

**Описание:**
Объединить выбор preset и custom списков в один UI с подсчётом доменов.

```tsx
// Пример UI — "Что проверить":

<div className="probe-target-selector">
  <h4>Что проверить:</h4>

  {/* Встроенные списки */}
  <div className="preset-group">
    <span className="group-label">Готовые:</span>
    {presets.map((p) => (
      <Chip
        key={p.id}
        label={`${p.name} (${p.domain_count})`}
        active={selectedIds.includes(p.id)}
        onClick={() => toggle(p.id)}
      />
    ))}
  </div>

  {/* Пользовательские списки */}
  {customLists.length > 0 && (
    <div className="custom-group">
      <span className="group-label">Мои:</span>
      {customLists.map((l) => (
        <Chip
          key={l.id}
          label={`${l.name} (${l.domains.length})`}
          active={selectedIds.includes(`custom:${l.id}`)}
          onClick={() => toggle(`custom:${l.id}`)}
        />
      ))}
    </div>
  )}

  {/* Итого */}
  <div className="selected-summary">
    Выбрано: {totalDomains} доменов из {selectedIds.length} списков
    <button
      onClick={handleBatchProbe}
      disabled={totalDomains === 0 || loading}
    >
      Проверить
    </button>
  </div>
</div>
```

**Файлы:** `src/ui/src/components/ProbePanel.tsx` (расширить)
**Зависимости:** T10.2, T10.9, T10.12

---

## Обновлённая сводная таблица задач

| ID | Задача | Фаза | Приоритет | Сложность | Срок | Зависимости |
|----|--------|:----:|:---------:|:---------:|:----:|:-----------:|
| T1.1 | FailureCode enum | P-1 | P0 | Низкая | 1d | — |
| T1.2 | ProbeConfig | P-1 | P0 | Низкая | 0.5d | T1.1 |
| T1.3 | RKN stub detection | P-1 | P1 | Низкая | 0.5d | — |
| T2.1 | DNS Integrity Probe | P-2 | P0 | Средняя | 2d | T1.1, T1.2 |
| T3.1 | TCP Probe + Race | P-3 | P0 | Низкая | 1d | T1.1, T1.2 |
| T4.1 | TLS Staged Handshake | P-4 | P0 | Средняя | 2d | T1.1, T1.2, T3.1 |
| T4.2 | Server-vs-Path Discriminator | P-4 | P0 | Низкая | 0.5d | T1.1 |
| T5.1 | HTTP Application Layer | P-5 | P0 | Низкая | 1d | T1.1, T1.2, T1.3 |
| T6.1 | TCP 16-20KB Data-Volume | P-6 | P1 | Средняя | 2d | T1.1, T1.2, T3.1 |
| T7.1 | ProbeModule Orchestrator | P-7 | P0 | Средняя | 2d | T2.1–T6.1 |
| T7.2 | Accumulator (24h + eTLD+1) | P-7 | P1 | Средняя | 2d | T1.1 |
| T8.1 | Strategy Map | P-8 | P0 | Средняя | 1d | T1.1, T4.2 |
| T9.1 | HTTP API endpoint | P-9 | P1 | Низкая | 1d | T7.1 |
| T9.2 | Config.toml integration | P-9 | P1 | Низкая | 0.5d | T1.2 |
| T9.3 | Тесты | P-9 | P0 | Средняя | 2d | Все |
| T10.1 | Tauri command `run_probe` | P-10 | P1 | Низкая | 1d | T9.1 |
| T10.2 | ProbePanel.tsx | P-10 | P1 | Средняя | 2d | T10.1 |
| T10.3 | ProbePanel.css | P-10 | P1 | Низкая | 0.5d | T10.2 |
| T10.4 | Навигация (вкладка Probe) | P-10 | P1 | Низкая | 0.5d | T10.2 |
| T10.5 | System Tray "Проверить DPI" | P-10 | P2 | Низкая | 0.5d | T10.2 |
| T10.6 | Dashboard probe widget | P-10 | P2 | Средняя | 1d | T10.1 |
| T10.7 | Tauri registration | P-10 | P1 | Низкая | 0.5d | T10.1 |
| **T10.8** | **Preset domain lists (8 списков, 139 доменов)** | **P-10** | **P1** | **Низкая** | **1d** | **—** |
| **T10.9** | **ProbePanel — batch probe UI** | **P-10** | **P1** | **Средняя** | **1d** | **T10.2, T10.8** |
| **T10.10** | **Tauri commands — presets + batch** | **P-10** | **P1** | **Низкая** | **0.5d** | **T10.1, T10.8** |
| **T10.11** | **API endpoints — presets + batch** | **P-10** | **P1** | **Низкая** | **0.5d** | **T9.1, T10.8** |
| **T10.12** | **Custom domain lists — создание/импорт/удаление** | **P-10** | **P1** | **Средняя** | **1.5d** | **T10.2, T10.8, T10.11** |
| **T10.13** | **Объединённый селектор (preset + custom)** | **P-10** | **P1** | **Низкая** | **0.5d** | **T10.2, T10.9, T10.12** |

**Итого: 29 задач, ~31 рабочий день**

---

## Обновлённая дорожная карта

```
Неделя 1 (P-1, P-2, P-3):
├── T1.1 FailureCode enum .............. 1d
├── T1.2 ProbeConfig ................... 0.5d
├── T1.3 RKN stub ...................... 0.5d
├── T2.1 DNS Probe ..................... 2d
└── T3.1 TCP Probe + Race .............. 1d

Неделя 2 (P-4, P-5):
├── T4.1 TLS Staged Handshake .......... 2d
├── T4.2 Discriminator ................. 0.5d
└── T5.1 HTTP Probe .................... 1d

Неделя 3 (P-6, P-7, P-8):
├── T6.1 TCP16 Probe ................... 2d
├── T7.1 Orchestrator .................. 2d
└── T8.1 Strategy Map .................. 1d

Неделя 4 (P-9):
├── T7.2 Accumulator ................... 2d
├── T9.1 API endpoint .................. 1d
├── T9.2 Config integration ............ 0.5d
└── T9.3 Тесты ......................... 2d

Неделя 5 (P-10):
├── T10.8 Preset domain lists .......... 1d
├── T10.11 API presets + batch ......... 0.5d
├── T10.12 Custom lists backend ........ 1.5d
├── T10.1 Tauri command ................ 1d
├── T10.10 Tauri commands presets ...... 0.5d
├── T10.7 Tauri registration ........... 0.5d
├── T10.2 ProbePanel.tsx ............... 2d
├── T10.9 ProbePanel batch UI .......... 1d
├── T10.13 Объединённый селектор ....... 0.5d
├── T10.3 ProbePanel.css ............... 0.5d
├── T10.4 Навигация .................... 0.5d
├── T10.5 System Tray .................. 0.5d
└── T10.6 Dashboard widget ............. 1d
```
