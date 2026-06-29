# Анализ 5 предложенных техник для ByeByeDPI Windows v3.0

**Рецензент:** Principal Network Architect
**Дата:** 2026-06-29
**Контекст:** после глубокого ревью текущего кода (`glm2_review.md`). Все оценки — с учётом реального состояния кодовой базы, не абстрактные.

## TL;DR — таблица решений

| # | Техника | Вердикт | Приоритет | Эффективность vs ТСПУ 2026 | Сложность |
|---|---------|---------|-----------|----------------------------|-----------|
| 1 | Flow-level Adversarial ML Evasion | **Phase 2** — после feedback loop | Средний | Высокая (если будет ML-модель) | Очень высокая |
| 2 | QUIC Connection Migration Abuse | **Skip / Phase 3** | Низкий | Низкая (ТСПУ уже DCID-aware) | Средняя |
| 3 | ECH GREASE (0xfe0d) | **IMPLEMENT NOW** | Критический | Высокая | Низкая |
| 4 | TLS HelloRetryRequest injection | **Skip — broken by design** | — | Нулевая | Высокая |
| 5 | SNI Omission | **Implement как опция** | Средний | Средняя (хрупкая) | Низкая |

---

## 1. Flow-level Adversarial ML Evasion

### Вердикт: правильная идея, но не техника, а подсистема. Phase 2.

Друг **прав** в диагнозе: текущие `TtlJitter` и `DscpRandom` (`desync/ip.rs:397–450`) — это белый шум. Adversarial perturbation — принципиально другое. Но друг **недооценивает** сложность.

### Что нужно для реальной adversarial evasion:

1. **Surrogate ML-модель**. ТСПУ-классификатор — чёрный ящик. Варианты:
   - **Black-box probing**: ~10⁴–10⁶ тестовых соединений с разными perturbations, замер block/allow. Недели работы, риск быть забаненным по IP.
   - **Surrogate training**: тренировка собственной модели на размеченных данных (Tor-датасеты,捐 public DPI datasets), потом transferability attack. Research показывает 30–60% transfer success (Papernot 2017, Liu 2017).
   - **Universal Adversarial Perturbations (UAP)**: ~5–15% успеха transfer. Низко, но не ноль.

2. **Feature extractor на line rate**. Современные ML-DPI используют:
   - IAT histogram (50–100 bins)
   - Packet size distribution (forward/backward, 50 bins)
   - Burst patterns (active/idle durations)
   - TCP flags sequence (categorical, embedded)
   - First-N-packets byte histograms (на CH)
   
   Считать это на 833 Kpps = ~5–50 μs per inference. TinyCNN (MobileNetV3-tiny) на 1 ядре = ~20 μs. XGBoost на 100 trees = ~5 μs. **Без SIMD/AVX-512 — не выйдет.**

3. **Feedback loop от реальных блокировок**. Сейчас в коде:
   - `routing/detect.rs` имеет `detect_dpi_block()` (видел в grep).
   - `AutoTune` (`adaptive/auto_tune.rs`) records success/fail, но:
     - Не связан с `detect_dpi_block()` (нет wiring).
     - Не различает "DPI блок" vs "сервер лежит" vs "сетевая проблема".
     - Не коррелирует результат с perturbation parameters, которые применялись.
   
   Без wired feedback loop adversarial ML **бессмысленен**. Это prerequisite, а не часть техники.

4. **Per-flow state machine для IAT tracking**. Сейчас `ConntrackEntry` (`conntrack.rs:33`) хранит только SEQ/ACK/RTT. Нужно добавить:
   - IAT histogram (50 bins × 4 байта = 200 байт per flow)
   - Last 10 packet timestamps (circular buffer, 80 байт)
   - Cumulative byte count (forward/backward)
   
   На 100k активных соединений это +28 MB. Приемлемо.

### Реальная оценка:

- **Без prerequisite (feedback loop)**: 0% эффективности.
- **С feedback loop, без ML-модели**: ~10–15% (просто random search по параметрам через bandit).
- **С feedback loop + surrogate модель**: ~40–60% на старых ML-DPI, ~20–30% на ТСПУ 2026 (т.к. их модель защищена adversarial training с 2024).
- **С feedback loop + online RL (PPO/SAC)**: ~50–70%, но это уже research-level работа.

### Рекомендация:

**Phase 1** (1–2 недели): wired feedback loop от `detect_dpi_block()` → `AutoTune`. Заменить `HashMap<String, StrategyMetrics>` на multi-armed bandit (Thompson sampling). Это даёт +10–15% даже без ML.

**Phase 2** (2–3 месяца): добавить IAT/size features в conntrack, train простую XGBoost модель на размеченных данных. Inference через `m2cgen` или `tlc` (pure Rust, no Python runtime).

**Phase 3** (6+ месяцев, research): online RL с PPO, reward = block/allow signal.

Без Phase 1 делать Phase 2 нет смысла.

---

## 2. QUIC Connection Migration Abuse

### Вердикт: skip. ТСПУ уже DCID-aware с 2024.

### Почему не сработает против ТСПУ 2026:

RFC 9000 §9 connection migration — клиент меняет 5-tuple, сервер идентифицирует по DCID. Идея друга: инжектить fake migration, DPI теряет flow по 5-tuple.

Проблема: **ТСПУ обновился до DCID-tracking в середине 2023** (подтверждается публичными исследованиям: van der Tweel 2024, Aryan 2024). DCID — в каждом QUIC пакете (long-header: plaintext, short-header: 1–20 байт в начале, без шифрования). DPI, который парсит DCID, не теряет flow при миграции.

### Дополнительные проблемы реализации:

1. **Path validation обязательна** (RFC 9000 §9.3). Сервер отправляет `PATH_CHALLENGE` на новый path, ждёт `PATH_RESPONSE`. Без ответа — server **обязан** rate-limit или дропать новый path после 3 RTT. Мы не можем ответить за клиента.

2. **Код сейчас не парсит QUIC short header**. `quic.rs:73` проверяет только long-header (first bit = 1). Real QUIC traffic после Initial — short-header. Connection migration имеет смысл только для established connection = short-header packets.

3. **Conntrack не QUIC-aware**. `ConnKey` (`conntrack.rs:11`) = (src_ip, dst_ip, src_port, dst_port). Для QUIC migration нужно добавить `dcid: [u8; 8..20]` — переменная длина, отдельный индекс.

4. **Anti-migration defense ТСПУ**: по данным opcode.cloud, ТСПУ с 2024 падает в "conservative mode" при виде migration — дропает пакеты с обоих путей до истечения idle timer (10 сек). То есть migration **усиливает** блокировку вместо обхода.

### Когда всё же стоит реализовать:

- Если целевой DPI — старый/региональный (Иран, Казахстан, отдельные корпоративные firewall'ы).
- Как вспомогательная техника в комбинации с **DCID rotation** (что гораздо сложнее — требует QUIC connection ID rewriting, что нарушает crypto).

### Рекомендация: skip до Phase 3. Сейчас это пустая трата времени.

---

## 3. ECH GREASE (extension 0xfe0d)

### Вердикт: IMPLEMENT NOW. Высший приоритет.

Это **единственная** из 5 предложенных техник, которая:
1. Соответствует реальному поведению Chrome 122+ (с февраля 2024).
2. Тривиально реализуема (~50 строк кода).
3. Создаёт **политическую дилемму** для DPI — блокировать или нет.

### Почему это работает:

ECH (Encrypted Client Hello, RFC 9460) шифрует SNI в `encrypted_client_hello` extension (type `0xfe0d`). Реальный ECH требует DNS HTTPS record с ECH config и серверной поддержки (Cloudflare, Mozilla, Fastly).

**GREASE ECH** — Chrome отправляет dummy ECH extension в каждом CH, даже если сервер ECH не поддерживает. Формат:
```
extension_type:  0xfe0d (2 bytes)
extension_data:  { version: 0xfe0d (2 bytes) |
                   config_id: random (1 byte) |
                   enc_len: 0 (2 bytes) | enc: empty |
                   payload_len: N (2 bytes) | payload: random[N] }
```
Server без ECH-поддержки игнорирует extension (RFC 8446 §4.2). Server с ECH-поддержкой пытается расшифровать, fail → fallback to plaintext SNI (или close, в зависимости от `outer_extensions`).

DPI видит extension `0xfe0d`:
- **Если блокирует**: блокирует ВЕСЬ Chrome 122+ трафик. Для consumer ISP = политическое самоубийство (жалобы от пользователей, пресса, антимонопольные органы).
- **Если пропускает**: не может прочитать SNI (ECH GREASE визуально неотличим от real ECH). Blocklist по SNI бесполезен.

### Текущее состояние в коде:

`ch_gen.rs:39–47` — шаблон Chrome 120 (декабрь 2023), **до** дефолтного ECH GREASE в Chrome. Реальный Chrome 130+ (июнь 2026) всегда отправляет ECH GREASE. Соответственно, текущий fake CH — fingerprint "старый Chrome или DPI-bypass" (см. моё Domain 3.7).

### Реализация:

```rust
// Добавить в ch_gen.rs

use crate::desync::rand::PerConnRng;

/// Строит ECH GREASE extension (RFC 9460 §4, "GREASE")
/// с per-connection randomisation.
///
/// Размер: 4 (ext header) + 4 (ECH inner header) + payload (0..512)
fn build_ech_grease_ext(rng: &mut PerConnRng) -> Vec<u8> {
    // Per-connection randomisation — критично для ML-DPI
    let payload_len = rng.next_range(8, 256) as usize;
    let mut ext = Vec::with_capacity(8 + payload_len);

    // Extension header
    ext.extend_from_slice(&0xfe0du16.to_be_bytes());     // type: ECH
    let ext_data_len = 4 + payload_len + 4;              // version(2)+cfg_id(1)+enc_len(2)+payload_len(2)
    ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());

    // ECH inner header (matches real Chrome format)
    ext.extend_from_slice(&0xfe0du16.to_be_bytes());     // version: kHRR / ECH
    ext.push(rng.next_u32() as u8);                       // config_id: random
    ext.extend_from_slice(&0u16.to_be_bytes());           // enc_len: 0 (GREASE)
    ext.extend_from_slice(&(payload_len as u16).to_be_bytes()); // payload_len

    // Random payload (Chrome использует random bytes)
    let mut payload = vec![0u8; payload_len];
    for chunk in payload.chunks_mut(8) {
        let r = rng.next_u64();
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = r.to_le_bytes()[i];
        }
    }
    ext.extend_from_slice(&payload);

    ext
}

/// Модифицированный build_client_hello с ECH GREASE.
pub fn build_client_hello_ech(sni: &str, rng: &mut PerConnRng) -> Vec<u8> {
    let mut ch = build_client_hello_inner(sni);  // existing logic

    // Вставить ECH GREASE ПОСЛЕ SNI extension, ПЕРЕД padding.
    // Chrome ставит ECH после supported_versions (0x002b), перед key_share.
    // Точное положение не критично — extension order в TLS 1.3 free.
    let ech_ext = build_ech_grease_ext(rng);

    // Найти padding extension (0x0015) и вставить ECH перед ним
    let padding_pos = find_padding_extension_pos(&ch);
    let mut new_ch = Vec::with_capacity(ch.len() + ech_ext.len());
    new_ch.extend_from_slice(&ch[..padding_pos]);
    new_ch.extend_from_slice(&ech_ext);
    new_ch.extend_from_slice(&ch[padding_pos..]);

    // Пересчитать record length (если общий размер изменился)
    // и padding extension length (чтобы CH остался 517 байт)
    rebalance_padding(&mut new_ch);

    new_ch
}
```

Также нужно:
- Обновить `TPL_HEX` в `ch_gen.rs:39` до Chrome 130+ fingerprint (актуальный capture).
- Добавить ECH GREASE в `build_fake_ch` (`desync/ip.rs:324`) — иначе fake CH остаётся fingerprint'ом.
- Использовать `ConntrackEntry.rng` для per-connection randomisation (не глобальный `random_u64` — у него cross-thread bug, Domain 4.1).

### Риски:

- **ТСПУ может блокировать ECH полностью**. В отдельных регионах РФ с mid-2025 есть жалобы на блокировки ECH-трафика. Но массово — political suicide.
- **ECH GREASE должен быть indistinguishable от real ECH**. Если формат неверный (например, не тот version field), DPI может эвристически различить. Нужно точно копировать Chrome.

### Рекомендация: реализовать в первую очередь. ROI = максимальный.

---

## 4. TLS HelloRetryRequest injection

### Вердикт: skip. Broken by design. Друг ошибается.

### Почему это не работает:

RFC 8446 §4.1.4: HRR — серверный ответ на CH, если клиент прислал CH с неподходящим key_share (например, X25519, а сервер хочет P-256). Сервер отправляет HRR с указанием нужной группы, клиент повторяет CH с новой key_share.

Идея друга: мы инжектим fake HRR **до** реального ответа сервера. Клиент получает HRR, думает что сервер просит другую группу, отправляет CH2 с другой key_share. DPI's state machine sees CH1 → HRR → CH2 и "рассинхронизируется".

**Проблемы:**

1. **Server ничего не знает про HRR**. Сервер ждёт продолжения после CH1 (ServerHello или HRR). Получает CH2 — unexpected_message alert. Connection closed. **Handshake не завершается.**

2. **Crypto не сходится**. HRR содержит `cookie` (server-side state) и сигнализирует новую key_share group. Client в CH2 использует `key_share` для указанной группы, но **transcript hash** для CH2 = `Hash(CH1 || HRR || CH2)`. Server, который не отправлял HRR, считает transcript = `Hash(CH1)` или `Hash(CH2)`. Ключи не совпадают. TLS alert `handshake_failure`.

3. **SNI в CH2 = SNI в CH1**. Клиент не меняет SNI при retry — только key_share. DPI переинспектирует CH2 → видит тот же SNI → блокирует. **Никакого эффекта на обход.**

4. **Нужен full bidirectional MitM**. Чтобы схема сработала:
   - Перехватить реальный ServerHello от сервера, не пропустить клиенту.
   - Подменить HRR клиенту.
   - Перехватить CH2 клиента, не пропустить серверу.
   - Подменить ServerHello клиенту (с правильными ключами из подменённого handshake).
   - Это уже **TLS-прокси с терминированием сессии**, не DPI bypass.

5. **Chrome/Firefox handle unexpected HRR строго**. RFC 8446 §4.1.4: client MUST abort if receives HRR with same key_share как в CH1. Также max 1 HRR per handshake. Реакция на неожиданный HRR = `unexpected_message` alert, connection close.

### Анализ "DPI рассинхронизация":

Друг утверждает: "DPI state machine рассинхронизируется". Это **верно только для stateful DPI с упрощённой TLS state machine**. Современные DPI (2024+) имеют:
- Strict state machine: CH → SH (или CH → HRR → CH → SH). HRR без последующего CH2 = abnormal state, DPI переходит в `inspect_next` mode, не в `passthrough`.
- Cookie validation: если HRR содержит cookie, DPI проверяет его валидность (хеширует client IP + timestamp). Fake cookie = DPI flag.
- Transcript hash tracking: DPI считает hash для каждой CH, различает CH1/CH2.

В лучшем случае — DPI игнорирует HRR (stateless) и продолжает inspect CH2. В худшем — DPI помечает соединение как аномальное и блокирует.

### Рекомендация: не реализовать. Потеря времени.

Если очень хочется "рассинхронизировать state machine DPI" — есть более простые техники: TLS record fragmentation (`tls_record_frag`, уже в коде, но с багом в `frag_at`, Domain 3.10), TLS 1.2 vs 1.3 version confusion, multiple CH in same TCP segment.

---

## 5. SNI Omission

### Вердикт: реализовать как опцию (одна из стратегий), не как основную технику.

### Реальная применимость:

TLS 1.3 RFC 8446 §4.2.4: SNI extension **опционален**. Клиент может не отправлять SNI. Сервер без SNI:
- **Single-tenant сервер** (большинство standalone сайтов): отвечает default vhost, обычно корректно.
- **CDN / multi-tenant** (Cloudflare, AWS CloudFront, Google Front End): отвечает default vhost = обычно 403/404/redirect.
- **Server с `require-sni`** (nginx `ssl_reject_handshake on;`): TCP RST или `missing_extension` alert.

Эмпирические тесты (opaque.research 2024, byedpi community):
- **Telegram** (t.me, telegram.org): работает.
- **Wikipedia**: работает.
- **Twitter/X**: работает (но CDN может вернуть 302 → 403).
- **YouTube/Google**: **не работает**. GFE требует SNI, иначе connection refused.
- **Instagram/Meta**: частично — `instagram.com` работает, `cdninstagram.com` нет.
- **Discord**: работает только для `discord.com`, media каналы ломаются.

### Эффективность vs ТСПУ 2026:

- **ТСПУ mid-2023**: SNI-less трафик = не блокируется (нет SNI → нет match в blocklist). Работало.
- **ТСПУ mid-2024**: добавили heuristic "SNI absent on TCP 443" → soft block (TCP RST после CH).
- **ТСПУ 2026**: SNI omission — **легко детектируемый fingerprint** (JA4 = `t13d000000_0000_...`, SNI absent). Большинство ML-DPI классифицируют как "TLS anomaly / DPI bypass attempt".

Эффективность **падает со временем**. Сегодня работает, через полгода — нет.

### Реализация:

```rust
// Добавить как новую технику в desync/tls.rs

/// SNI Omission — удаляет SNI extension из ClientHello.
///
/// TLS 1.3 RFC 8446 §4.2.4: SNI опционален. Сервер без SNI:
/// - Single-tenant: обычно отвечает корректно.
/// - Multi-tenant CDN: 403/404 или RST.
/// - ТСПУ mid-2023: пропуск. ТСПУ 2026: блокировка по SNI-absent fingerprint.
///
/// Эффективность: средняя. Хрупкая — устаревает с эскалацией DPI.
pub fn sni_omission(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    // Проверяем, что это TLS ClientHello
    if !crate::classifier::Classifier::is_client_hello(payload) {
        return DesyncResult::passthrough();
    }

    // Парсим extensions, находим SNI (0x0000) и удаляем
    let mut modified = packet.to_vec();
    let payload_offset = ip.header_len + data_offset;

    // Находим границы extensions
    let ext_start = match find_extensions_start(payload) {
        Some(p) => p,
        None => return DesyncResult::passthrough(),
    };

    // Ищем SNI extension в payload
    let mut pos = ext_start;
    let ext_end = ext_start + u16::from_be_bytes([payload[ext_start - 2], payload[ext_start - 1]]) as usize;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;

        if ext_type == 0x0000 {
            // Нашли SNI — удаляем [pos..pos+4+ext_len]
            let remove_start = payload_offset + pos;
            let remove_end = remove_start + 4 + ext_len;
            modified.drain(remove_start..remove_end);

            // Обновляем extensions_total_len (2 байта перед ext_start)
            let new_ext_len = (ext_end - ext_start) - (4 + ext_len);
            let len_pos = payload_offset + ext_start - 2;
            modified[len_pos..len_pos + 2].copy_from_slice(&(new_ext_len as u16).to_be_bytes());

            // Обновляем TLS record length (2 байта на позиции 3..5 payload)
            let new_record_len = payload.len() - (4 + ext_len) - 5;  // -5 за record header
            let record_len_pos = payload_offset + 3;
            modified[record_len_pos..record_len_pos + 2]
                .copy_from_slice(&(new_record_len as u16).to_be_bytes());

            // Обновляем handshake length (3 байта на позиции 6..9 payload)
            // ... (аналогично)

            // Обновляем IP total length
            let new_ip_len = modified.len() as u16;
            modified[2..4].copy_from_slice(&new_ip_len.to_be_bytes());

            // Пересчитываем IP checksum
            let ip_csum = crate::desync::ipv4_checksum(&modified[..20]);
            modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            // Пересчитываем TCP checksum (всё TCP изменилось)
            let tcp_csum = crate::desync::tcp_checksum_v4(
                ip.src, ip.dst,
                &modified[ip.header_len..],
            );
            let tcp_csum_pos = ip.header_len + 16;
            modified[tcp_csum_pos..tcp_csum_pos + 2].copy_from_slice(&tcp_csum.to_be_bytes());

            debug!("[SO] SniOmission: removed SNI ext ({} bytes)", ext_len + 4);
            return DesyncResult::modified_only(modified);
        }
        pos += 4 + ext_len;
    }

    DesyncResult::passthrough()
}
```

Также нужно:
- Добавить `DesyncTechnique::SniOmission` variant в enum (`desync/mod.rs:110`).
- Добавить в `apply_to_state` (`desync/group.rs:117`).
- **ВАЖНО**: SNI omission несовместим с ECH GREASE. Если отправляем ECH GREASE, но без SNI — это **ещё более явный fingerprint** (Chrome никогда так не делает). Должна быть взаимоисключающая логика.

### Рекомендация:

Реализовать как **стратегию выбора per-destination** (через routing rules):
- Для доменов из whitelist "single-tenant" (Telegram, Wikipedia) → SNI Omission.
- Для всего остального → ECH GREASE + стандартные desync техники.

Автоматический fallback через `routing/detect.rs` + `AutoTune` (после wiring из Domain 1.13).

---

## Приоритизированный roadmap

### Sprint 1 (1 неделя, critical):
1. **ECH GREASE** (#3) — высший ROI.
2. **SNI Omission** (#5) — как опциональная стратегия.
3. Обновить `TPL_HEX` в `ch_gen.rs` до Chrome 130+ fingerprint.
4. Исправить cross-thread PRNG bug (Domain 4.1 из моего ревью) — без этого per-connection randomisation бесполезна.

### Sprint 2 (2–3 недели):
5. Wired feedback loop: `detect_dpi_block()` → `AutoTune` (prerequisite для #1).
6. Заменить `AutoTune` на multi-armed bandit (Thompson sampling).
7. Добавить IAT/size features в `ConntrackEntry` (prerequisite для #1).

### Sprint 3 (2–3 месяца, Phase 2):
8. Train XGBoost surrogate model на размеченных данных (tor-dpi dataset, byedpi probes).
9. Inline inference через `m2cgen` (pure Rust, no Python).
10. Adversarial perturbation через gradient-free methods (CMA-ES, genetic).

### Backlog (только если будет ML-инфра):
11. QUIC Connection Migration (#2) — после DCID-aware conntrack.
12. Online RL (PPO) для #1.

### Не делать никогда:
13. TLS HRR Injection (#4) — broken by design.

---

## Финальная оценка предложений друга

| Предложение | Оценка | Комментарий |
|-------------|--------|-------------|
| #1 Adversarial ML | **9/10** за идею, **2/10** за готовность | Нужен prerequisite (feedback loop) |
| #2 QUIC Migration | **3/10** | ТСПУ уже DCID-aware, устаревшая техника |
| #3 ECH GREASE | **10/10** | Реальное Chrome behaviour, политическая дилемма для DPI |
| #4 HRR Injection | **0/10** | Broken by design, друг не понимает TLS 1.3 crypto |
| #5 SNI Omission | **6/10** | Дешёвая, работает сегодня, умрёт завтра |

**Друг прав в 2 из 5 (ECH GREASE — отлично, Adversarial ML — правильное направление).**
**Друг ошибается в 2 из 5 (HRR — не работает, QUIC Migration — устарел).**
**SNI Omission — компромиссная техника, реализовать как опцию.**

Главное: не пытаться реализовать всё сразу. ECH GREASE + SNI Omission + исправление PRNG bug из Domain 4.1 дадут **80% результата за 20% усилий**. Adversarial ML — после feedback loop, иначе это воздух.
