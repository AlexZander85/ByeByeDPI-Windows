# Исследование проектов: техники для интеграции в FreeDPI

> **Проект Ladon исключён из этого документа — обсуждается отдельно.**

---

## 1. zyrln (Go — туннель через Google Apps Script)

**Исходный код:** `D:\ByeDPI\research\zyrln`

### Обзор
Туннелирует трафик через Google Apps Script (доменный фронтинг) + Cloudflare Workers как запасной relay. Включает Android VPN с userspace TCP стеком. Минимальные зависимости — только `golang.org/x/mobile`.

### Найденные техники

| # | Техника | Описание | Уже в FreeDPI? |
|---|---------|----------|:---------------:|
| 1 | **Domain Fronting через Google Apps Script** | TLS handshake с googleapis.com (разрешённый SNI), HTTP Host: script.google.com — DPI видит Google | ❌ |
| 2 | **TCP micro-fragmentation: 87 сегментов по 1 байту, 5ms spacing** | Первый пакет разбивается на 87 micro-segments через TCP_NODELAY | Partial (byte-by-byte есть, но без spacing) |
| 3 | **Cloudflare Worker tunnel** | Durable Objects — stateful relay на edge, 128 pools, 128KB chunks | ❌ |
| 4 | **MITM-proxied coalescer** | Localhost proxy с MITM (.terminateTLS) + request batching перед отправкой | ❌ |
| 5 | **Userspace TCP stack (TUN)** | Полный userspace TCP/IP через Go на Android | ❌ |

### Рекомендации по интеграции

**P2 — TCP micro-fragmentation с spacing:**
- Наш `byte_by_byte` отправляет сегменты без задержки между ними
- zyrln добавляет 5ms spacing между 87 сегментами
- Против time-based DPI (ТСПУ собирает пакеты по временным окнам) spacing критичен
- Реализация: `tokio::time::sleep(Duration::from_millis(5))` между send() каждого байта

**P3 — Domain Fronting relay:**
- Запасной egress через Google/Cloudflare CDN
- Когда прямой desync не работает, трафик уходит через легитимный CDN
- TLS handshake с googleapis.com, HTTP Host: script.google.com
- Cloudflare Workers как stateless edge compute (бесплатный tier)

---

## 2. phoenix (Go — маскировка трафика под HTTP/2)

**Исходный код:** `D:\ByeDPI\research\phoenix`

### Обзор
Маскирует proxy трафик (SOCKS5, UDP, Shadowsocks, SSH) под легитимный HTTP/2 или HTTP/1.1. Работает как клиент + сервер (relay). Использует uTLS, Ed25519, mTLS.

### Найденные техники

| # | Техника | Описание | Уже в FreeDPI? |
|---|---------|----------|:---------------:|
| 1 | **uTLS fingerprint spoofing** | Chrome/Firefox/Safari/Edge мимикрия через utls | Partial (TLS parroting есть, но статичный) |
| 2 | **mTLS anti-probing** | Сервер требует клиентский сертификат — если клиент не знает ключ, отклоняется. Защита от active probing | ❌ |
| 3 | **Ed25519 certificate pinning** | Пиннинг по Ed25519 публичному ключу вместо X.509 | ❌ |
| 4 | **Zombie connection recovery** | Автовосстановление оборванных соединений с exponential backoff | ❌ |
| 5 | **Shadowsocks AEAD** | aes-256-gcm / chacha20-ietf-poly1305 authenticated encryption | Partial (ChaCha20 есть, но не AEAD) |
| 6 | **Multi-transport** | h2, http1, ssh транспорт — выбор по сети | ❌ |
| 7 | **Token authentication** | Каждое соединение авторизуется через токен | ❌ |
| 8 | **SNI whitelist на сервере** | Сервер отклоняет соединения с неразрешёнными SNI | ❌ |
| 9 | **Exponential backoff для reconnection** | Последовательное увеличение задержки между попытками переподключения | ❌ |

### Рекомендации по интеграции

**P1 — uTLS fingerprints:**
- Интеграция `utls` crate (или Rust-аналог `rustls` с uTLS-профилями)
- Наши текущие TLS parroting делает статичный fingerprint
- uTLS позволяет ротировать Chrome/Firefox/Edge профили per-connection
- DPI не может составить стабильный JA3 fingerprint

**P2 — Zombie connection recovery:**
- Автоматическое восстановление оборванных соединений
- Критично для стабильности: если desync не сработал → auto-retry другой стратегией
- Exponential backoff: 100ms → 200ms → 400ms → 800ms → max 5s
- Порог: 3 неудачных попытки → переключение стратегии

**P3 — mTLS anti-probing:**
- Защита SOCKS5 fallback прокси от active probing
- DPI может проверять, является ли upstream proxy настоящим прокси или DPI-bypass сервером
- mTLS: клиент отправляет сертификат, сервер проверяет CN/serial

---

## 3. dropweb (Flutter/Go — VPN клиент на mihomo/Clash.Meta)

**Исходный код:** `D:\ByeDPI\research\dropweb`

### Обзор
Полноценный VPN-клиент с GUI на Flutter, ядром mihomo (Clash.Meta). Поддерживает VLESS/VMess/Trojan/Hysteria2/WireGuard и десятки протоколов. Включает TLS fragment toggle и post-quantum fingerprints.

### Найденные техники

| # | Техника | Описание | Уже в FreeDPI? |
|---|---------|----------|:---------------:|
| 1 | **TLS ClientHello fragmentation (toggle)** | Встроенный toggle в mihomo ядре | Partial (TLS frag есть, но не через toggle) |
| 2 | **Post-quantum X25519MLKEM768 fingerprints** | Firefox 148 + Safari 26 профили с PQ key exchange | ❌ |
| 3 | **FD pressure protection** | Отклонение новых соединений при 75% FD usage | ❌ |
| 4 | **Go heap bounding** | `debug.SetMemoryLimit(192MB)` + aggressive GC | Partial (есть memory limits в ARCHITECTURE.md) |
| 5 | **Semaphore-bounded JNI callbacks** | Ограничение concurrent JNI calls через weighted semaphore (4) | ❌ |
| 6 | **Byte-preserving YAML splicing** | Точечное редактирование YAML без потери форматирования | N/A (у нас TOML) |
| 7 | **Emergency pool / disconeko** | Автоматический fallback на запасные узлы через HTTP header | Partial (proxy fallback есть) |
| 8 | **Smart ML routing** | LightGBM-based выбор прокси (отключён из-за 90s download) | ❌ |
| 9 | **Geo data lazy bootstrap** | Only GeoIP/GeoSite bundled, остальное загружается из профиля | ❌ |
| 10 | **Config caching with hash** | Пропуск переконфигурации при неизменённом хеше | ❌ |

### Рекомендации по интеграции

**P1 — FD pressure protection:**
- На Windows при большом количестве соединений (10K+) можно исчерпать handle limit
- Реализация: `GetProcessHandleCount()` / `GetProcessWorkingSetSize()` с auto-throttle
- При 75% usage → отклонение новых соединений до освобождения
- dropweb реализует: `if fdUsage > maxFdCount * 3 / 4 { reject }`

**P2 — Config hash caching:**
- Пропуск перезапуска engine если конфиг не изменился
- У нас `arc-swap` уже есть для hot-reload, но нет hash-based diffing
- Реализация: SHA-256 хеш конфига → сравнение с предыдущим → skip если идентичен

**P3 — Post-quantum fingerprints:**
- X25519MLKEM768 уже поддерживается в Chrome 149+
- Наш `pqlib` крейт может это обеспечить
- Firefox 148 и Safari 26 профили в dropweb содержат PQ key exchange

**P2 — Emergency failover pool:**
- Расширить proxy fallback с автоматическим discovery запасных прокси
- dropweb использует HTTP header `dropweb-disconeko` для URL emergency pool
- Парсинг YAML subscription → извлечение узлов → auto-select лучшего

---

## 4. gecit (Go + eBPF — MSS shrinking + fake CH)

**Исходный код:** `D:\ByeDPI\research\gecit`

### Обзор
Обход DPI через комбинацию: (1) eBPF sock_ops для MSS shrinking на Linux, (2) TUN+gVisor для macOS/Windows, (3) fake ClientHello с низким TTL. На Windows использует Npcap для raw socket injection (обёртка в Ethernet frame).

### Найденные техники

| # | Техника | Описание | Уже в FreeDPI? |
|---|---------|----------|:---------------:|
| 1 | **eBPF sock_ops MSS shrinking** | Ядерный hook: автоматическая фрагментация ClientHello через MSS=88 | N/A (Linux only) |
| 2 | **MSS restore after N bytes** | После 600 байт MSS восстанавливается до 1460 — только CH фрагментируется | ❌ |
| 3 | **Fake CH × 3 с 2ms spacing** | Три fake ClientHello подряд перед реальным | Partial (fake CH есть, но не triple) |
| 4 | **pcap-based seq/ack tracking** | Отслеживание TCP sequence через pcap для корректной инъекции | Partial (conntrack есть, но не через pcap) |
| 5 | **Built-in DoH resolver** | Локальный DNS сервер на 127.0.0.1:53 с DoH upstream + fallback | Partial (DoH клиент есть, но не сервер) |
| 6 | **IP-to-domain queue** | Маппинг IP→домен через DNS response tracking | Partial (DNS cache есть) |
| 7 | **Npcap Ethernet frame injection** | Обёртка IP+TCP в Ethernet frame для отправки через pcap_sendpacket | ❌ (не нужно — используем WinDivert) |

### Рекомендации по интеграции

**P1 — MSS restore after N bytes:**
- Ключевая идея! Наш MSS clamp ставит MSS=536 на **всё** соединение → замедление
- gecit: MSS=88 только на первые 600 байт (ClientHello), потом MSS=1460
- Реализация: начальный MSS=536 → после отправки CH → новое TCP window update с MSS=1460
- Эффект: CH фрагментируется + rest-of-data на полной скорости

**P1 — Triple fake CH с spacing:**
- Три fake ClientHello с 2ms spacing перед реальным
- DPI может пропустить один fake, но три подряд надёжнее десинхронизируют conntrack
- Реализация: `inject_fake_ch(ttl=2)` × 3 через raw socket, `tokio::time::sleep(2ms)` между ними

**P2 — DoH forwarder (UDP→HTTPS прокси):**
- Локальный DNS прокси на 127.0.0.1:53
- Шифрует DNS всей системы через DoH без модификации Windows DNS Client
- gecit: 5 presets (cloudflare, google, quad9, nextdns, adguard) + fallback
- Реализация: `UdpSocket::bind("127.0.0.1:53")` → forward через reqwest → ответ клиенту

---

## Сводная таблица: приоритеты интеграции

| # | Техника | Из проекта | Приоритет | Сложность | Эффект |
|---|---------|:----------:|:---------:|:---------:|:------:|
| 1 | **MSS restore after N bytes** | gecit | P1 | Средняя | Fast data + fragmented CH |
| 2 | **Triple fake CH с spacing** | gecit | P1 | Низкая | Надёжная десинхронизация |
| 3 | **uTLS fingerprints** | phoenix | P1 | Средняя | Ротация browser fingerprint |
| 4 | **TCP micro-fragmentation с spacing** | zyrln | P2 | Низкая | Против time-based DPI |
| 5 | **Zombie connection recovery** | phoenix | P2 | Низкая | Стабильность соединений |
| 6 | **FD pressure protection** | dropweb | P2 | Низкая | Защита от handle exhaustion |
| 7 | **Config hash caching** | dropweb | P2 | Низкая | Экономия переконфигурации |
| 8 | **Emergency failover pool** | dropweb | P2 | Средняя | Автоматический fallback |
| 9 | **mTLS anti-probing** | phoenix | P3 | Средняя | Защита proxy от probing |
| 10 | **Post-quantum fingerprints** | dropweb | P3 | Средняя | Будущее: Chrome 149+ PQ |
| 11 | **Domain Fronting relay** | zyrln | P3 | Высокая | Запасной egress через CDN |
| 12 | **DoH forwarder (local DNS)** | gecit | P3 | Средняя | Шифрование DNS всей системы |

---

## Сравнение архитектур: gecit vs FreeDPI (Npcap vs WinDivert)

### Почему gecit использует Npcap

gecit **не имеет kernel-mode driver**. На Windows для двух задач нужен внешний механизм:
1. **Перехват SYN-ACK** — извлечение seq/ack через pcap с BPF-фильтром
2. **Инъекция TCP** — raw TCP sockets заблокированы (XP SP2+), pcap_sendpacket с Ethernet frame

gecit оборачивает IP+TCP в Ethernet-фрейм (dst MAC + src MAC + EtherType) и отправляет через Npcap. Для этого парсит ARP-таблицу шлюза.

### Почему FreeDPI обходится без Npcap

FreeDPI использует **WinDivert** — kernel-mode network filter driver:
- **Перехват**: `WinDivert::recv()` с BPF-подобным фильтром (kernel-level)
- **TCP инъекция**: `WinDivert::send()` с `set_impostor(true)` — kernel-level reinject без Ethernet frame
- **UDP/ICMP инъекция**: Raw socket (`WSASocket` + `IPPROTO_RAW`)

### Преимущества подхода FreeDPI

| Аспект | gecit (Npcap) | FreeDPI (WinDivert) |
|--------|---------------|---------------------|
| Установка | Требует Npcap от пользователя | Автоустановка через SCM |
| Уровень | User-space (NDIS filter) | Kernel-mode driver |
| TCP инъекция | Ethernet frame wrapper | Impostor flag (без wrapper) |
| Производительность | Копирование через NDC | Direct kernel call |
| Зависимости | libpcap.dll (Npcap) | WinDivert64.sys + .dll (bundled) |
