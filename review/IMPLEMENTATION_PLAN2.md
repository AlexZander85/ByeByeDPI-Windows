# FreeDPI v3.1 — Implementation Plan 2 (P0-P2 Features)

**Источник:** Анализ GreenTunnel, NoDPI, Demergi
**Дата:** 2026-06-28
**Принцип:** каждая задача = минимально затронутые файлы, верификация через grep + cargo check

---

## P0 — Критичные (новые техники, которых нет в проекте)

---

### Задача 1: TLS Record Re-wrapping (GreenTunnel)

**Суть:** Каждый фрагмент TLS ClientHello получает **новый валидный TLS record header** с пересчитанным length field. Отличие от текущего `tls_record_frag` — тот делает TCP-level split, а эта техника работает на TLS record layer.

**Файл:** `src/core/src/desync/tls.rs` — новая функция `tls_record_rewrap()`

**Что делаем:**
1. Добавляем `pub fn tls_record_rewrap(packet: &[u8], chunk_size: usize, fake_ttl_offset: u8) -> DesyncResult`
2. Парсим TLS record header: `content_type = payload[0]`, `version = payload[1..3]`, `length = u16::from_be_bytes(payload[3..5])`
3. Разбиваем payload[5..] на `chunk_size` байтные куски
4. Каждый кусок оборачиваем: `[content_type, version, len_hi, len_lo, ...chunk]`
5. Склеиваем все mini-records в один TCP payload
6. Инжектируем через `build_tcp_with_payload()`

**Регистрация:**
- `desync/mod.rs` — добавить `TlsRecordRewrap` в `DesyncTechnique` enum
- `desync/group.rs` — добавить match arm в `apply_single()`
- `desync/config.rs` — добавить `tls_record_rewrap_chunk_size: usize` (default 100)

**Верификация:**
```bash
grep -n "tls_record_rewrap" src/core/src/desync/tls.rs
# Ожидаемый: pub fn + test

grep -n "TlsRecordRewrap" src/core/src/desync/mod.rs
# Ожидаемый: enum variant
```

**Критерий:** фрагменты содержат валидные TLS record headers (0x16 + version + length)

---

### Задача 2: SNI-Targeted Fragmentation (NoDPI)

**Суть:** Разбиение именно SNI-поля ClientHello на 2-байтные куски с TLS 1.3 record headers. Отличие от `sni_masking` — тот XOR-ит байты, а эта техника делает structural fragmentation.

**Файл:** `src/core/src/desync/tls.rs` — новая функция `sni_record_frag()`

**Что делаем:**
1. Парсим ClientHello: ищем SNI extension (type=0x0000) через handshake type check + extension walk
2. Вычисляем offsets: `pre_sni_start`, `sni_start`, `sni_end`, `pre_sni`, `sni`, `post_sni`
3. Разбиваем `sni` на 2-байтные chunks
4. Каждый chunk оборачиваем в TLS 1.3 record header: `[0x16, 0x03, 0x04, len_hi, len_lo, ...chunk]`
5. Склеиваем: `pre_sni_records + sni_chunk_records + post_sni_records`
6. Инжектируем

**Регистрация:**
- `desync/mod.rs` — добавить `SniRecordFrag` в enum
- `desync/group.rs` — добавить match arm

**Верификация:**
```bash
grep -n "sni_record_frag" src/core/src/desync/tls.rs
grep -n "SniRecordFrag" src/core/src/desync/mod.rs
```

**Критерий:** каждый 2B chunk SNI содержит валидный TLS record header; оригинальный ClientHello не повреждён

---

### Задача 3: TLS Version Overwrite (Demergi)

**Суть:** Перезапись version field в TLS record header на `0x0304` (TLS 1.3). Тривиальная 3-byte правка, но создаёт комбинированный эффект с фрагментацией.

**Файл:** `src/core/src/desync/tls.rs` — новая функция `tls_version_overwrite()`

**Что делаем:**
1. Находим начало TCP payload
2. Проверяем: `payload[0] == 0x16` (TLS Handshake) && `payload.len() >= 5`
3. Записываем `payload[1..3] = [0x03, 0x04]` (TLS 1.3)
4. Возвращаем `DesyncResult::modified_only(modified)`

**Регистрация:**
- `desync/mod.rs` — добавить `TlsVersionSpoof` в enum
- `desync/group.rs` — добавить match arm

**Верификация:**
```bash
grep -n "tls_version_overwrite\|TlsVersionSpoof" src/core/src/desync/tls.rs
grep -n "TlsVersionSpoof" src/core/src/desync/mod.rs
```

**Критерий:** record header bytes [1..3] == [0x03, 0x04] для TLS handshake packets

---

## P1 — Средние (улучшения существующих subsystems)

---

### Задача 4: HTTP Header Case Mixing (Demergi)

**Суть:** Чередование регистра в HTTP headers: `Host` → `hOsT`. Побеждает DPI с fixed-pattern regex.

**Файл:** `src/core/src/desync/http.rs` — новая функция `http_case_mix()`

**Что делаем:**
1. Ищем в TCP payload строку `Host:` (или `host:`)
2. Чередуем регистр: `H` → `h`, `o` → `O`, `s` → `s`, `t` → `T` (индекс % 2)
3. Возвращаем `DesyncResult::modified_only(modified)`

**Регистрация:**
- `desync/mod.rs` — добавить `HttpCaseMix` в enum
- `desync/group.rs` — добавить match arm

**Верификация:**
```bash
grep -n "http_case_mix\|HttpCaseMix" src/core/src/desync/http.rs
grep -n "HttpCaseMix" src/core/src/desync/mod.rs
```

**Критерий:** `Host:` заменён на `hOsT:` в TCP payload

---

### Задача 5: DoH Retry с exponential backoff (Demergi)

**Суть:** Повтор DoH запросов при REFUSED_STREAM с экспоненциальной задержкой + jitter.

**Файл:** `src/core/src/dns/mod.rs` — модификация `resolve_doh()`

**Что делаем:**
1. Добавляем `max_retries: u8` (default 3) в `DnsEngine`
2. Оборачиваем DoH запрос в loop с counter
3. При ошибке: `sleep(2^(retry) * 20ms + random(0..20ms))`
4. При success — break
5. При exhausted retries — return None

**Верификация:**
```bash
grep -n "retry\|backoff" src/core/src/dns/mod.rs
```

**Критерий:** DoH retry работает; при 3 failed attempts — возвращает None

---

### Задача 6: Persistent HTTP/2 DoH (Demergi)

**Суть:** Переиспользование HTTP/2 сессии для повторных DoH запросов.

**Файл:** `src/core/src/dns/mod.rs` — оптимизация `resolve_doh()`

**Что делаем:**
1. `reqwest::Client` уже поддерживает HTTP/2 connection pooling (ALPN h2)
2. Убеждаемся что `reqwest::Client::builder().http2_prior_knowledge(true)` или `.http2_adaptive_retry(true)` установлены
3. Добавляем `doh_persistent: bool` в `DnsConfig`

**Верификация:**
```bash
grep -n "http2\|persistent" src/core/src/dns/mod.rs
```

**Критерий:** повторные DoH запросы переиспользуют соединение (видно в логах: нет TLS handshake)

---

### Задача 7: DNS IP Override (Demergi)

**Суть:** CIDR-based IP override для обхода IP-блокировок CDN.

**Файл:** `src/core/src/dns/mod.rs` — новая функция `apply_ip_overrides()`

**Что делаем:**
1. Добавляем `ip_overrides: Vec<(ipnet::IpNet, Ipv4Addr)>` в `DnsEngine`
2. После DNS resolution: проверяем попадает ли IP в override CIDR
3. Если да — заменяем на указанный IP

**Регистрация:**
- `config.rs` — добавить `dns_ip_overrides: Vec<String>` (формат: `"1.2.3.0/24=5.6.7.8"`)

**Верификация:**
```bash
grep -n "ip_override\|IpNet" src/core/src/dns/mod.rs
grep -n "ip_override" src/core/src/config.rs
```

**Критерий:** override применяется к DNS результатам

---

### Задача 8: Certificate Pinning для DoH (Demergi)

**Суть:** SPKI hash pinning для DoH серверов.

**Файл:** `src/core/src/dns/mod.rs` — модификация `resolve_doh()`

**Что делаем:**
1. Добавляем `doh_pins: Vec<String>` (base64-encoded SHA256 SPKI hashes) в `DnsConfig`
2. При создании `reqwest::Client`: добавляем `.add_root_certificate()` или `.identity()` с pinned cert
3. Альтернатива: используем `reqwest::Certificate::from_pem()` для pinned root CA

**Верификация:**
```bash
grep -n "pin\|certificate" src/core/src/dns/mod.rs
```

**Критерий:** DoH соединение отклоняет невалидные сертификаты

---

## P2 — Полезные (оптимизации, security hardening)

---

### Задача 9: TLS Record Re-wrapping + Version Spoof комбинация

**Суть:** Автоматическое применение version overwrite при record re-wrapping.

**Файл:** `src/core/src/desync/tls.rs` — модификация `tls_record_rewrap()`

**Что делаем:**
1. В `tls_record_rewrap()`: при создании каждого mini-record header записываем version = `[0x03, 0x04]`
2. Это комбинирует P0-задачи 1 и 3 в одну функцию

**Верификация:**
```bash
grep -n "0x03.*0x04\|tls_version" src/core/src/desync/tls.rs | grep -c "0x03"
# Ожидаемый: ≥1 (в tls_record_rewrap)
```

**Критерий:** mini-record headers содержат TLS 1.3 version

---

### Задача 10: Auto-detect enhancement (NoDPI persistence)

**Суть:** Сохранение auto-detected blocked domains в файл + whitelist cache.

**Файл:** `src/core/src/split_tunnel.rs` — модификация `AutoBlacklistManager`

**Что делаем:**
1. При successful TLS handshake → добавляем домен в whitelist ( DashSet )
2. При timeout → добавляем в blacklist + записываем в файл `blocked_domains.txt`
3. При старте → загружаем `blocked_domains.txt` в blacklist

**Верификация:**
```bash
grep -n "blocked_domains\|whitelist" src/core/src/split_tunnel.rs
```

**Критерий:** auto-detected domains сохраняются между перезапусками

---

## Сводная таблица

| Задача | Приоритет | Файлы | MR | Сложность |
|---|:---:|---|---|:---:|
| 1. TLS Record Re-wrapping | P0 | tls.rs, mod.rs, group.rs | Новый | Средняя |
| 2. SNI-Targeted Fragmentation | P0 | tls.rs, mod.rs, group.rs | Новый | Средняя |
| 3. TLS Version Overwrite | P0 | tls.rs, mod.rs, group.rs | Новый | Низкая |
| 4. HTTP Header Case Mixing | P1 | http.rs, mod.rs, group.rs | Новый | Низкая |
| 5. DoH Retry + backoff | P1 | dns/mod.rs | Новый | Низкая |
| 6. Persistent HTTP/2 DoH | P1 | dns/mod.rs | Новый | Низкая |
| 7. DNS IP Override | P1 | dns/mod.rs, config.rs | Новый | Средняя |
| 8. Certificate Pinning | P1 | dns/mod.rs | Новый | Средняя |
| 9. Record Re-wrап + Version комбинация | P2 | tls.rs | Новый | Низкая |
| 10. Auto-detect persistence | P2 | split_tunnel.rs | Новый | Низкая |

---

## Порядок выполнения

| Шаг | Задачи | Время |
|---|---|:---:|
| 1 | 3 (TLS Version Overwrite) | 30 мин |
| 2 | 1 (TLS Record Re-wrapping) | 2 часа |
| 3 | 2 (SNI-Targeted Fragmentation) | 2 часа |
| 4 | 4 (HTTP Case Mixing) | 30 мин |
| 5 | 5, 6 (DoH retry + persistent) | 1 час |
| 6 | 7, 8 (DNS override + pinning) | 1.5 часа |
| 7 | 9, 10 (комбинация + persistence) | 1 час |

**Общее время:** ~8.5 часов
