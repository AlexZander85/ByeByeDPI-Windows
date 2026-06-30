# Модуль определения типа DPI-блокировки: сравнительный анализ 4 проектов

## Обзор проектов

| Проект | Язык | Подход | Фокус |
|--------|------|--------|-------|
| **Ladon** | Go | Реактивный: мониторит DNS → probe → ipset | Router-level, Linux |
| **dpi-checkers** | Go + Python + JS | Мультиинструмент: TUI + скрипты + браузер | Комплексный аудит |
| **rkn-block-checker** | Python | Простой probe: DNS + TCP + TLS + HTTP | Быстрый одноцелевой |
| **dpi-detector** | Python | Async probe: 7 тестов с Rich UI | Самый подробный классификатор |

---

## Полный каталог техник детекции по проектам

### 1. DNS-уровень

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **DNS poisoning** (UDP возвращает другие IP чем DoH) | ❌ | ✅ (org()-проверка) | ✅ (cross-validation) | ✅ (cross-validation, 9 UDP + 7 DoH JSON + 12 DoH Wire) |
| **DNS NXDOMAIN spoofing** | ❌ | ✅ | ❌ | ✅ |
| **DNS empty response spoofing** | ❌ | ❌ | ❌ | ✅ |
| **DNS interception** (UDP timeout, DoH работает) | ❌ | ❌ | ❌ | ✅ |
| **DoH blocking** (все DoH недоступны) | ❌ | ✅ (DoH bootstrap spoofing) | ❌ | ✅ |
| **DNS server availability** (latency per provider) | ❌ | ❌ | ❌ | ✅ (21 сервер, warmup) |
| **CNAME chain attribution** | ✅ | ❌ | ❌ | ❌ |

### 2. TCP-уровень

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **TCP RST injection** | ✅ (`tcp_reset`) | ❌ | ✅ (`ConnectionResetError`) | ✅ (errno + exception chain) |
| **TCP SYN drop** | ❌ | ❌ | ✅ (`socket.timeout`) | ✅ (stage: `tcp_connect`) |
| **TCP 16-20KB data cutoff** | ❌ | ✅ (L4-25, 64KB POST) | ❌ | ✅ (16 HEAD × 4KB, RTT-based dynamic timeout) |
| **Connection-count blocking** (Siberian) | ❌ | ✅ (N parallel conns) | ❌ | ❌ |
| **CIDR whitelist** (домашние vs иностранные IP) | ❌ | ✅ (max.ru vs github.com) | ❌ | ❌ |
| **Connection timeout** (TCP level) | ✅ (`tcp_timeout`) | ❌ | ✅ | ✅ (`SYN DROP`) |
| **TCP parallel dial racing** (3 IP) | ✅ | ❌ | ❌ | ❌ |

### 3. TLS-уровень

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **TLS RST injection** (RST во время handshake) | ✅ (`tls_reset`) | ❌ | ✅ (SNI-based reset) | ✅ (stage: `tls_handshake` + `tls_connected`) |
| **TLS version split detection** (1.3 fail / 1.2 OK) | ✅ (`tls13_block`) | ❌ | ❌ | ❌ |
| **TLS garbage/spoof injection** (malformed records) | ✅ (`tls_garbage`) | ❌ | ✅ (`SSLError`) | ✅ (wrong version, overflow, decode error) |
| **TLS Alert injection** (fake alerts) | ✅ (`tls_alert`) | ❌ | ✅ (SSLError) | ✅ (SNI block, handshake failure, protocol version) |
| **TLS MITM** (certificate substitution) | ❌ | ❌ | ❌ | ✅ (expired, self-signed, hostname mismatch) |
| **TLS EOF** (quiet disconnect) | ✅ (`tls_eof`) | ❌ | ❌ | ✅ ("empty deque" / BrokenResource) |
| **SNI-based blocking** (конкретный SNI) | ❌ | ❌ | ✅ (reset + silent drop + tls error) | ✅ (188 whitelist SNIs, batch brute-force) |
| **uTLS fingerprint** (Chrome-targeted) | ❌ | ✅ (Chrome fingerprint) | ❌ | ❌ |

### 4. HTTP-уровень

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **HTTP 451** (legal block) | ✅ (`http_451`) | ❌ | ✅ | ✅ |
| **HTTP cutoff** (response обрезан на 32KB) | ✅ (`http_cutoff`) | ❌ | ❌ | ❌ |
| **ISP stub page injection** (RKN-заглушки) | ❌ | ❌ | ✅ (10 known substrings) | ✅ (stub IP matching) |
| **Suspicious redirect** (редирект на чужой домен) | ❌ | ❌ | ❌ | ✅ (парсинг target domain) |

### 5. Сервер vs Путь (Discrimination)

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **Server-active vs Path-active** (TLS alert от сервера ≠ DPI) | ✅ | ❌ | ❌ | ❌ |
| **mTLS detection** (сервер требует клиентский cert) | ✅ (`mtls_required`) | ❌ | ❌ | ❌ |

### 6. Накопление и эвристики

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **20+ typed failure codes** | ✅ | Partial (5-10) | ❌ | ✅ (23+ типа) |
| **24h temporal accumulation** (50+ verdicts → permanent) | ✅ | ❌ | ❌ | ❌ |
| **eTLD+1 family expansion** (10+ subdomains → entire family) | ✅ | ❌ | ❌ | ❌ |
| **Exit-compare** (второй probe server) | ✅ | ❌ | ❌ | ❌ |
| **CNAME chain attribution** | ✅ | ❌ | ❌ | ❌ |
| **Inline fast-path** (мгновенный probe из DNS tailer) | ✅ | ❌ | ❌ | ❌ |
| **Whitelist SNI brute-force** (188 RU SNIs) | ❌ | ❌ | ❌ | ✅ |

### 7. Специфические платформы

| Техника | Ladon | dpi-checkers | rkn-block-checker | dpi-detector |
|---------|:-----:|:------------:|:------------------:|:------------:|
| **Telegram throttle detection** (download/upload/DC ping) | ❌ | ❌ | ❌ | ✅ (31MB DL + 10MB UL + 5 DC) |
| **Fake-IP range detection** (198.18.0.0/15) | ❌ | ❌ | ❌ | ✅ |
| **CGNAT range detection** (100.64.0.0/10) | ❌ | ❌ | ❌ | ✅ |
| **ipset management** (kernel IP sets) | ✅ | ❌ | ❌ | ❌ |

---

## Сравнение архитектур

### Pipeline (стадии пробы)

| Проект | Стадии | Параллелизм | Кэш/состояние |
|--------|--------|-------------|----------------|
| **Ladon** | DNS → TCP:443 (3 IP race) → TLS (1.3→1.2 retry) → HTTP (32KB read) | 8 concurrent inline + batch worker | SQLite WAL + hot/cache states |
| **dpi-checkers** | TLS (uTLS) → POST 64KB → read timeout | Sequential per test | Нет |
| **rkn-block-checker** | DNS (system + DoH) → TCP → TLS → HTTP GET | Sequential | Нет |
| **dpi-detector** | DNS (9 UDP + 7 DoH JSON + 12 DoH Wire) → TLS 1.3/1.2 → HTTP HEAD → TCP16 → SNI brute-force → Telegram | 100 concurrent (semaphore) | Stub IP collection |

### Классификация ошибок

| Проект | Кол-во типов | Подход |
|--------|:------------:|--------|
| **Ladon** | 20+ | FailureCode enum: dns_nxdomain, tcp_reset, tls_garbage, http_cutoff, tls13_block, mtls_required... |
| **dpi-checkers** | 5-10 | Simple: ErrDnsResolveSpoofing, ErrTcpWriteTimeout, ErrSiberianBlock... |
| **rkn-block-checker** | 6-8 | Exception-based: DNS poison, TCP RST, SNI reset/drop/error, HTTP 451, stub page |
| **dpi-detector** | 23+ | 3 classifier functions: classify_ssl_error, classify_connect_error, classify_read_error. Stage-aware (6 stages). |

### Вердикт (Blocked vs Clear)

| Проект | Механизм |
|--------|----------|
| **Ladon** | `Classify()` → Blocked/Clear. Server-reachable (tls_alert, mtls) → Clear. Path-active (tcp_reset, tls_garbage) → Blocked. |
| **dpi-checkers** | Pass/Fail per test. 5-level: not-detected/probable/possible/unlikely. |
| **rkn-block-checker** | HIGH/MEDIUM/LOW confidence. Items 1-3 + 7-8 = HIGH. Items 4-6 = MEDIUM. Items 9-11 = LOW. |
| **dpi-detector** | Per-domain: ok/blocked/timeout/dns_fail. Per-test: tally-based classification. Summary panel с color coding. |

---

## Что лучшего в каждом проекте для интеграции в FreeDPI

### Ladon — лучшее

| # | Что | Почему ценно для FreeDPI |
|---|-----|--------------------------|
| 1 | **4-stage pipeline** (DNS→TCP→TLS→HTTP) | Гранулярная диагностика. Наш AutoProber делает только TCP+minimal CH |
| 2 | **TLS version split** (1.3 fail / 1.2 OK) | Signature ТСПУ в России. 1 строка кода — огромная ценность |
| 3 | **Server-active vs Path-active** | Если TLS alert от сервера → НЕ DPI, не тратить ресурсы на desync |
| 4 | **24h temporal accumulation** | Устойчивость к ложным срабатываниям. 50+ verdicts → permanent cache |
| 5 | **eTLD+1 family expansion** | Экономия probes: vk.com → m.vk.com, api.vk.com, static.vk.com |
| 6 | **Exit-compare** | Валидация: local fail + remote OK = реальная DPI |

### dpi-checkers — лучшее

| # | Что | Почему ценно для FreeDPI |
|---|-----|--------------------------|
| 1 | **L4-25 / TCP 16-20KB cutoff** | Детекция data-volume DPI (ТСПУ считает пакеты). У нас нет |
| 2 | **Siberian / Connection-count blocking** | DPI считает количество TLS handshake к одному серверу. Уникальная техника |
| 3 | **CIDR whitelist** (домашние vs иностранные IP) | Быстрая проверка: если github.com падает а ya.ru работает = whitelist |
| 4 | **DNS org()-проверка** | Проверяет принадлежит ли IP ожидаемой организации (google → google IP ranges) |

### rkn-block-checker — лучшее

| # | Что | Почему ценно для FreeDPI |
|---|-----|--------------------------|
| 1 | **ISP stub page detection** (10 known RKN substrings) | Прямое распознавание заглушек РКН в HTML |
| 2 | **DNS transparent rewriting** (zero overlap IP sets) | Тонкая детекция: оба resolver возвращают IP, но разные |
| 3 | **Simple, lightweight** (~500 строк) | Легко портировать на Rust |
| 4 | **Silent drop detection** (TLS hangs до timeout) | Тихий drop хуже RST — harder to detect |

### dpi-detector — лучшее

| # | Что | Почему ценно для FreeDPI |
|---|-----|--------------------------|
| 1 | **Stage-aware classification** (6 stages) | Точно определяет ГДЕ DPI вмешивается: SYN/TLS handshake/connected/data |
| 2 | **TLS MITM detection** (cert substitution) | DPI подменяет сертификаты. У нас нет этой детекции |
| 3 | **TCP 16-20KB с dynamic RTT timeout** | Adaptive timeout = fewer false positives |
| 4 | **SNI brute-force** (188 whitelist SNIs) | Автопоиск рабочего SNI |
| 5 | **Fake-IP / CGNAT range detection** | Детекция VPN stub IPs |
| 6 | **23+ failure codes** с exception chain analysis | Самый подробный классификатор |
| 7 | **Telegram-specific** (DL/UL/DC ping) | Специфика для RU-пользователей |
| 8 | **DoH cross-validation** (9 UDP + 19 DoH) | Самое широкое покрытие DNS-серверов |

---

## Рекомендация: что интегрировать в FreeDPI

### Архитектура: свой DPI Probe Module

Не брать один проект за основу — взять **pipeline от Ladon** + **классификатор от dpi-detector** + **уникальные техники из dpi-checkers**.

```
┌─────────────────────────────────────────────────────────────┐
│                  DPI Probe Module (FreeDPI)                   │
│                                                               │
│  Phase 1: DNS Integrity                                      │
│  ├── UDP/53 → 3 резолвера (Google, Cloudflare, Quad9)       │
│  ├── DoH → 2 endpoint (Cloudflare, Google)                   │
│  ├── Cross-validation: UDP vs DoH                            │
│  └── Verdict: poison / nxdomain / empty / intercept / ok     │
│                                                               │
│  Phase 2: TCP Connectivity                                   │
│  ├── TCP:443 → 3 IP parallel race                           │
│  ├── Verdict: connect_ok / reset / timeout / refuse          │
│  └── Метрика: RTT (для dynamic timeout в Phase 4)           │
│                                                               │
│  Phase 3: TLS Handshake (staged)                             │
│  ├── Attempt 1: TLS 1.3 (Chrome fingerprint)                │
│  ├── Attempt 2: TLS 1.2 (fallback если 1.3 fail)            │
│  ├── Stage tracking: tcp_connected → tls_handshake → ...     │
│  ├── Verdict: ok / reset / garbage / alert / mitm / drop     │
│  └── TLS version split: 1.3 fail + 1.2 ok = ClientHello DPI │
│                                                               │
│  Phase 4: HTTP Application Layer                             │
│  ├── GET / → read 32KB                                       │
│  ├── Verdict: ok / cutoff / http_451 / redirect / timeout    │
│  └── Redirect check: same domain = ok, foreign = ISP page    │
│                                                               │
│  Phase 5: Data-Volume (optional, triggered by Phase 2-4)    │
│  ├── TCP 16-20KB: 16 HEAD × 4KB padding                     │
│  ├── Dynamic timeout: max(rtt × 3.0, 1.5s)                  │
│  └── Verdict: ok / detected_at_N_KB                          │
│                                                               │
│  Discriminator: Server-active vs Path-active                 │
│  ├── tls_alert (от сервера) → Clear (НЕ DPI)                │
│  ├── mtls_required → Clear (НЕ DPI)                         │
│  ├── tcp_reset / tls_garbage / http_cutoff → Blocked         │
│  └── tcp_timeout / tls_timeout → Ambiguous → re-probe       │
│                                                               │
│  Accumulation (per-domain)                                   │
│  ├── Hot state: 24h TTL, re-probe каждые 5 мин             │
│  ├── Cache: 50+ blocked verdicts в окне → permanent         │
│  └── eTLD+1 expansion: 10+ subdomains → family tunnel       │
│                                                               │
│  Output: Strategy Recommendation                             │
│  ├── DNS poisoned → DoH mandatory                           │
│  ├── TCP RST → Fake CH + split                              │
│  ├── TLS 1.3 blocked → Force TLS 1.2 + frag                │
│  ├── TLS garbage → SEQ spoof + disorder                     │
│  ├── HTTP cutoff → TCP desync (data-volume)                 │
│  ├── SNI-based → Fake SNI + MSS clamp                       │
│  └── CIDR whitelist → Proxy required                        │
└─────────────────────────────────────────────────────────────┘
```

### Код для интеграции (Rust, модуль `core/src/probe/`)

```
core/src/probe/
├── mod.rs              # ProbeModule orchestrator
├── dns_probe.rs        # Phase 1: DNS integrity
├── tcp_probe.rs        # Phase 2: TCP connectivity + parallel race
├── tls_probe.rs        # Phase 3: TLS staged handshake
├── http_probe.rs       # Phase 4: HTTP application layer
├── tcp16_probe.rs      # Phase 5: Data-volume detection
├── classifier.rs       # 23+ failure codes (from dpi-detector)
├── discriminator.rs    # Server-active vs Path-active (from Ladon)
├── accumulator.rs      # 24h temporal accumulation + eTLD+1
└── strategy_map.rs     # Probe result → desync strategy recommendation
```

### Топ-15 техник для интеграции (приоритет)

| # | Техника | Из проекта | Приоритет | Сложность |
|---|---------|:----------:|:---------:|:---------:|
| 1 | **4-stage pipeline** (DNS→TCP→TLS→HTTP) | Ladon | P0 | Средняя |
| 2 | **Stage-aware classification** (6 stages) | dpi-detector | P0 | Низкая |
| 3 | **TLS version split** (1.3 fail / 1.2 ok) | Ladon | P0 | Низкая |
| 4 | **Server-active vs Path-active** | Ladon | P0 | Низкая |
| 5 | **DNS cross-validation** (UDP vs DoH) | dpi-detector | P1 | Средняя |
| 6 | **TLS MITM detection** (cert substitution) | dpi-detector | P1 | Низкая |
| 7 | **TCP 16-20KB data cutoff** | dpi-checkers | P1 | Средняя |
| 8 | **23+ failure codes** | dpi-detector | P1 | Средняя |
| 9 | **ISP stub page detection** | rkn-block-checker | P2 | Низкая |
| 10 | **SNI brute-force** (whitelist SNIs) | dpi-detector | P2 | Средняя |
| 11 | **24h accumulation + eTLD+1** | Ladon | P2 | Средняя |
| 12 | **TCP parallel dial racing** (3 IP) | Ladon | P2 | Низкая |
| 13 | **CIDR whitelist detection** | dpi-checkers | P3 | Низкая |
| 14 | **Siberian connection-count** | dpi-checkers | P3 | Средняя |
| 15 | **Redirect-to-foreign detection** | dpi-detector | P3 | Низкая |

---

## Сравнительная матрица: покрытие детекции

| Категория | Ladon | dpi-checkers | rkn-block-checker | dpi-detector | **FreeDPI (план)** |
|-----------|:-----:|:------------:|:------------------:|:------------:|:-------------------:|
| DNS | ⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| TCP | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| TLS | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| HTTP | ⭐⭐⭐ | ⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Discrimination | ⭐⭐⭐⭐⭐ | ⭐ | ⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Accumulation | ⭐⭐⭐⭐⭐ | ⭐ | ⭐ | ⭐⭐ | ⭐⭐⭐⭐ |
| **Итого** | **⭐⭐⭐⭐** | **⭐⭐** | **⭐⭐** | **⭐⭐⭐⭐** | **⭐⭐⭐⭐⭐** |
