Integration Guide

## Что включено

Четыре техники, встроенные в конструктор fake ClientHello:

1. **#2 GREASE Rotation** — per-connection GREASE values (0x?A?A) в cipher_suites, extensions, supported_groups, supported_versions. Позиции строго first-slot (как реальный Chrome).

2. **#3 Padding Randomization** — padding extension (0x0015) с random multiple-of-16 размером в диапазоне [512, 4096]. Заменяет фиксированные 517 байт.

3. **#1 PQ Key Share (X25519MLKEM768)** — группа `0x11EC` в supported_groups + 1184-байтный key share entry. Fake CH никогда не доходит до сервера (TTL=1), поэтому key share = random bytes (криптографическая валидность не нужна, DPI не может отличить).

4. **ECH GREASE (0xFE0D)** — dummy ECH extension в формате RFC 9460 §4 ECHClientHello с per-connection random config_id + P-256 key + random payload. Соответствует реальному поведению Chrome 122+ с февраля 2024. Создаёт политическую дилемму для DPI: блокировать = заблокировать весь Chrome 122+ трафик.

**Критический prerequisite:** фикс cross-thread PRNG bug в `rand.rs`. Без этого per-connection randomisation бесполезна — все потоки получают одинаковый seed.

## Файлы

```
sprint1/
├── README.md              — этот файл
├── ch_gen.rs              — ПОЛНАЯ замена src/core/src/adaptive/ch_gen.rs
├── rand.rs                — ПОЛНАЯ замена src/core/src/desync/rand.rs
├── ip.rs.patch            — патч для src/core/src/desync/ip.rs (заменить build_fake_ch)
├── seq_spoof.rs.patch     — патч для src/core/src/adaptive/seq_spoof.rs (передать RNG)
└── engine_mod.rs.patch    — патч для src/core/src/engine/mod.rs (4-tuple conn_id для RNG)
```

## Порядок интеграции

1. Скопировать `rand.rs` → `src/core/src/desync/rand.rs`
2. Скопировать `ch_gen.rs` → `src/core/src/adaptive/ch_gen.rs`
3. Применить `ip.rs.patch` (заменить локальную `build_fake_ch` на вызов `ch_gen::build_client_hello`)
4. Применить `seq_spoof.rs.patch` (передать `PerConnRng` в `build_client_hello`)
5. Применить `engine_mod.rs.patch` (использовать 4-tuple для conn_id)

## Что изменилось архитектурно

### ch_gen.rs — полный rewrite

**Удалено:**
- `TPL_HEX` (захардкоженный Chrome 120 шаблон с SNI "mci.ir")
- `TEMPLATE_SNI = "mci.ir"`
- `TEMPLATE_BYTES` (LazyLock парсинг hex)
- `CLIENT_HELLO_SIZE = 517` (фиксированный размер = fingerprint)
- `hex` модуль
- Захардкоженные offsets в `parse_sni` (125, 126, 127)

**Добавлено:**
- `build_client_hello(sni, rng)` — структурированная сборка CH из компонентов
- `build_client_hello_default(sni)` — fallback без явного RNG (создаёт временный PerConnRng)
- `generate_grease_set(rng)` — 4 per-connection GREASE values
- `compute_padding_size(body_len, rng)` — random multiple-of-16 padding
- `build_ech_grease_extension(rng)` — ECH GREASE extension (RFC 9460 §4, Chrome 122+)
- `parse_sni` переписан — proper extension parsing вместо hardcoded offsets
- Константы: `GREASE_VALUES`, TLS group IDs, cipher suite IDs, extension type IDs, HPKE constants

### rand.rs — фикс cross-thread bug

**Удалено:**
- `GLOBAL_SEED: AtomicU64` — причина катастрофы (все потоки получали один seed)
- `init_seed()` — использовал GLOBAL_SEED
- Xorshift64 в `random_u64()` (проходит только SmallCrush)

**Добавлено:**
- `random_u64()` на xoshiro256++ (passes BigCrush, fresh entropy per thread)
- `PerConnRng::fill_bytes(&mut [u8])` — efficient bulk random fill
- `PerConnRng::pick_grease()` — выбирает random GREASE value
- `PerConnRng::next_range_u8/min/max` helpers для удобства

## Проверка после интеграции

```bash
# Компиляция
cd src && cargo build -p byebyedpi-core

# Тесты
cargo test -p byebyedpi-core -- ch_gen
cargo test -p byebyedpi-core -- rand

# Проверка fingerprint (внешний инструмент)
# Сгенерировать fake CH и проверить через ja3er.com или本地 tshark:
# - JA3 должен меняться per-connection (GREASE rotation)
# - JA4 должен быть t13d... (TLS 1.3)
# - Размер CH должен быть variable (padding randomization)
# - supported_groups должен включать 0x11EC (X25519MLKEM768)
# - extensions должен включать 0xFE0D (ECH GREASE) — Chrome 122+ behavior
```

## Риски и mitigation

1. **Размер CH вырос с 517 до ~1500-4096 байт** (PQ key share 1184 + ECH GREASE ~100-300).
   - Mitigation: TCP stack фрагментирует автоматически. Fake CH всё равно умирает на первом хопе.
   - Если используется TCP segmentation desync, учитывайте больший размер.

2. **parse_sni теперь парсит extensions properly** — медленнее на ~100ns per call.
   - Mitigation: вызывается только для fake CH (1-2 раза per connection), не на hot path.

3. **PerConnRng::new() вызывает getrandom (syscall)** — ~50-200ns per connection.
   - Mitigation: приемлемо, 1 вызов per connection.

4. **pqcrypto crate НЕ нужен** — PQ key share = random bytes для fake CH.
   - Если в будущем потребуется real PQ handshake (для proxy mode), добавить `pqcrypto-mlkem = "0.4"`.

5. **ECH GREASE может блокироваться некоторыми DPI** — если ТСПУ блокирует весь трафик с ECH extension.
   - Mitigation: большинство consumer ISP не блокирует (политически невыгодно). Если блокирует — отключить ECH GREASE через config flag.
   - Chrome 122+ тоже использует ECH GREASE, так что блокировка = блокировка Chrome.

6. **ECH config_id должен быть per-connection random**, не per-packet.
   - Mitigation: используется `ConntrackEntry.rng` (per-connection PRNG), не глобальный `random_u64()`.
   - Если PRNG не передан (fallback), каждый вызов создаёт новый PerConnRng = новая randomisation per fake CH. Допустимо, но менее эффективно.
