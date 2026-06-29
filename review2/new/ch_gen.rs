//! TLS ClientHello Generator — Chrome 130+ structured construction.
//!
//! ## Что изменилось (Sprint 1)
//!
//! **Удалено:**
//! - `TPL_HEX` — статический hex-шаблон Chrome 120 (декабрь 2023)
//! - `TEMPLATE_SNI = "mci.ir"` — захардкоженный SNI (= мгновенный fingerprint)
//! - `CLIENT_HELLO_SIZE = 517` — фиксированный размер (= fingerprint по одному сравнению)
//! - Hardcoded offsets в `parse_sni` (125, 126, 127)
//!
//! **Добавлено:**
//! - `build_client_hello(sni, rng)` — структурированная сборка из компонентов
//! - Per-connection GREASE rotation (RFC 8701) — 4 значения, все first-slot
//! - X25519MLKEM768 (0x11EC) в supported_groups + key_share (PQ hybrid)
//! - Random padding: multiple of 16 в [512, 4096] (Chrome 130+ behavior)
//! - Per-connection random fields: TLS random, session_id, key shares
//! - `parse_sni` — proper extension parsing вместо hardcoded offsets
//! - **ECH GREASE extension (0xFE0D)** — Chrome 122+ default behavior,
//!   создаёт политическую дилемму для DPI (блокировать = заблокировать
//!   весь Chrome 122+ трафик)
//!
//! ## Архитектура
//!
//! Fake CH строится из структурированных компонентов, не из hex-шаблона.
//! Все random-поля заполняются через PerConnRng — per-connection уникальны.
//!
//! ```text
//! build_client_hello(sni, rng)
//!   ├── generate_grease_set(rng)     → 4 GREASE values
//!   ├── build_ch_body(sni, rng, grease)
//!   │   ├── TLS random (32 bytes, rng)
//!   │   ├── session_id (32 bytes, rng)
//!   │   ├── cipher_suites (GREASE + 3 standard + GREASE)
//!   │   ├── extensions:
//!   │   │   ├── GREASE ext (first, empty)
//!   │   │   ├── SNI (0x0000)
//!   │   │   ├── extended_master_secret (0x0017)
//!   │   │   ├── renegotiation_info (0xFF01)
//!   │   │   ├── supported_groups (0x000A) — GREASE + X25519MLKEM768 + X25519 + secp256r1 + secp384r1
//!   │   │   ├── session_ticket (0x0023)
//!   │   │   ├── ALPN (0x0010) — h2, http/1.1
//!   │   │   ├── SCT (0x0012)
//!   │   │   ├── signature_algorithms (0x000D)
//!   │   │   ├── key_share (0x0033) — X25519MLKEM768 (1184 bytes) + X25519 (32 bytes)
//!   │   │   ├── PSK kex modes (0x002D)
//!   │   │   ├── supported_versions (0x002B) — GREASE + TLS 1.3 + TLS 1.2
//!   │   │   ├── compress_certificate (0x001B)
//!   │   │   ├── application_settings (0x4469)
//!   │   │   ├── ECH GREASE (0xFE0D) — Chrome 122+ default, random config_id + P-256 key + payload
//!   │   │   ├── GREASE ext (second, before padding)
//!   │   │   └── padding (0x0015) — random multiple of 16
//!   │   └── (lengths updated after padding computation)
//!   ├── wrap in handshake header
//!   └── wrap in TLS record layer
//! ```
//!
//! ## Важно
//! Этот CH предназначен для **fake injection** (TTL=1, не доходит до сервера).
//! PQ key share = random bytes — криптографическая валидность не требуется,
//! DPI не может отличить от реального ML-KEM-768 public key без encapsulation.

use crate::desync::rand::PerConnRng;

// ============================================================================
// Константы — TLS 1.3 / Chrome 130+
// ============================================================================

/// Минимальная длина SNI.
const MIN_SNI_LEN: usize = 1;

/// Максимальная длина SNI (ограничение здравого смысла + DNS label rules).
const MAX_SNI_LEN: usize = 253;

// TLS extension types
const EXT_SNI: u16 = 0x0000;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_SIG_ALGS: u16 = 0x000D;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PSK_KEX_MODES: u16 = 0x002D;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001B;
const EXT_APPLICATION_SETTINGS: u16 = 0x4469;
const EXT_PADDING: u16 = 0x0015;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xFE0D; // ECH GREASE (RFC 9460, Chrome 122+)

// TLS cipher suites (Chrome 130+ default set)
const CS_TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const CS_TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const CS_TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// TLS named groups
const GROUP_X25519MLKEM768: u16 = 0x11EC;
const GROUP_X25519: u16 = 0x001D;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

/// Размер ML-KEM-768 публичного ключа (NIST FIPS 203).
const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;

/// Размер X25519 публичного ключа.
const X25519_PUBLIC_KEY_SIZE: usize = 32;

// HPKE constants (RFC 9180) — используются в ECH GREASE config
const HPKE_KEM_P256: u16 = 0x0010; // DHKEM(P-256)
const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
const P256_PUBLIC_KEY_SIZE: usize = 65; // 0x04 prefix + 32 X + 32 Y

// ============================================================================
// Публичный API
// ============================================================================

/// Строит TLS 1.3 ClientHello в стиле Chrome 130+.
///
/// Все random-поля генерируются через per-connection RNG:
/// - TLS random (32 bytes)
/// - Session ID (32 bytes)
/// - X25519MLKEM768 key share (1184 bytes)
/// - X25519 key share (32 bytes)
/// - 4 GREASE values (cipher, ext, group, version)
/// - Padding size (random multiple of 16)
/// - ECH GREASE extension (config_id, public_key, payload — all random)
///
/// # Arguments
/// * `sni` — доменное имя для SNI extension
/// * `rng` — per-connection PRNG (из ConntrackEntry)
///
/// # Panics
/// Паникует если SNI длиннее 253 байта или короче 1 байта.
///
/// # Returns
/// Vec<u8> — полный TLS record (ContentType + Version + Length + Handshake + CH)
pub fn build_client_hello(sni: &str, rng: &mut PerConnRng) -> Vec<u8> {
    assert!(
        sni.len() >= MIN_SNI_LEN && sni.len() <= MAX_SNI_LEN,
        "SNI length {} out of range [{}, {}]",
        sni.len(),
        MIN_SNI_LEN,
        MAX_SNI_LEN
    );

    let grease = rng.generate_grease_set();

    // 1. Build extensions (without padding — padding added last)
    let extensions = build_extensions(sni, rng, grease);

    // 2. Build ClientHello body
    let body = build_ch_body(rng, grease, &extensions);

    // 3. Compute padding and add it
    let body_with_padding = add_padding(body, rng);

    // 4. Wrap in handshake header
    let handshake = wrap_handshake(&body_with_padding);

    // 5. Wrap in TLS record layer
    let record = wrap_record(&handshake);

    record
}

/// Fallback — строит ClientHello с временным PerConnRng.
/// Менее эффективен (syscall per call), но совместим со старыми вызовами.
pub fn build_client_hello_default(sni: &str) -> Vec<u8> {
    let conn_id = crate::desync::rand::random_u64();
    let mut rng = PerConnRng::new(conn_id);
    build_client_hello(sni, &mut rng)
}

/// Проверяет, является ли буфер TLS ClientHello.
pub fn is_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 6
        && buf[0] == 0x16 // ContentType: Handshake
        && buf[1] == 0x03 // Version major: TLS
        && buf[5] == 0x01 // HandshakeType: ClientHello
}

/// Парсит SNI из TLS ClientHello.
///
/// Proper extension parsing — работает с CH любого размера и порядка extensions.
/// Заменяет старую версию с hardcoded offsets (125, 126, 127).
pub fn parse_sni(client_hello: &[u8]) -> Option<String> {
    if !is_client_hello(client_hello) {
        return None;
    }

    // Skip TLS record header (5 bytes) + handshake header (4 bytes)
    if client_hello.len() < 9 {
        return None;
    }
    let mut pos = 5; // after TLS record header

    // Handshake header: type(1) + length(3)
    if client_hello[pos] != 0x01 {
        return None; // Not ClientHello
    }
    pos += 4; // skip handshake header

    // ClientHello body: version(2) + random(32) + session_id(1+N) + cipher_suites(2+M) + compression(1+K) + extensions
    if pos + 35 > client_hello.len() {
        return None;
    }
    pos += 2; // legacy_version
    pos += 32; // random

    // session_id
    if pos >= client_hello.len() {
        return None;
    }
    let sid_len = client_hello[pos] as usize;
    pos += 1 + sid_len;

    // cipher_suites
    if pos + 2 > client_hello.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression_methods
    if pos >= client_hello.len() {
        return None;
    }
    let comp_len = client_hello[pos] as usize;
    pos += 1 + comp_len;

    // extensions
    if pos + 2 > client_hello.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total_len;
    if ext_end > client_hello.len() {
        return None;
    }

    // Iterate extensions to find SNI (0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            return None;
        }

        if ext_type == EXT_SNI {
            return parse_sni_extension(&client_hello[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

fn parse_sni_extension(ext_data: &[u8]) -> Option<String> {
    if ext_data.len() < 5 {
        return None;
    }
    // ServerNameList: list_len(2) + entries
    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
    if 2 + list_len > ext_data.len() {
        return None;
    }
    // First entry: name_type(1) + name_len(2) + name
    let name_type = ext_data[2];
    if name_type != 0 {
        return None; // Only host_name type
    }
    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
    if 5 + name_len > ext_data.len() {
        return None;
    }
    String::from_utf8(ext_data[5..5 + name_len].to_vec()).ok()
}

/// [OF1] Маскировка SNI — генерирует новый CH с белым доменом.
pub fn mask_sni(_client_hello: &[u8], white_domain: &str) -> Option<Vec<u8>> {
    if !is_client_hello(_client_hello) {
        return None;
    }
    Some(build_client_hello_default(white_domain))
}

// ============================================================================
// Internal: structured CH construction
// ============================================================================

/// Строит все extensions кроме padding.
///
/// Порядок extensions соответствует Chrome 130+:
/// GREASE → SNI → EMS → Renego → Groups → Ticket → ALPN → SCT → SigAlgs →
/// KeyShare → PSK_KEX → Versions → CompressCert → AppSettings → GREASE
fn build_extensions(
    sni: &str,
    rng: &mut PerConnRng,
    grease: (u16, u16, u16, u16),
) -> Vec<u8> {
    let (cipher_g, ext_g, group_g, ver_g) = grease;
    let mut ext = Vec::with_capacity(1400);

    // 1. GREASE extension (first, empty data — Chrome behavior)
    ext.extend_from_slice(&ext_g.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());

    // 2. SNI (0x0000)
    push_sni_extension(&mut ext, sni);

    // 3. extended_master_secret (0x0017)
    push_empty_extension(&mut ext, EXT_EXTENDED_MASTER_SECRET);

    // 4. renegotiation_info (0xFF01)
    ext.extend_from_slice(&EXT_RENEGOTIATION_INFO.to_be_bytes());
    ext.extend_from_slice(&1u16.to_be_bytes());
    ext.push(0x00);

    // 5. supported_groups (0x000A) — includes X25519MLKEM768
    push_supported_groups(&mut ext, group_g);

    // 6. session_ticket (0x0023) — empty
    push_empty_extension(&mut ext, EXT_SESSION_TICKET);

    // 7. ALPN (0x0010) — h2, http/1.1
    push_alpn_extension(&mut ext);

    // 8. signed_certificate_timestamp (0x0012)
    push_empty_extension(&mut ext, EXT_SCT);

    // 9. signature_algorithms (0x000D)
    push_sig_algs_extension(&mut ext);

    // 10. key_share (0x0033) — X25519MLKEM768 + X25519
    push_key_share_extension(&mut ext, rng);

    // 11. psk_key_exchange_modes (0x002D)
    ext.extend_from_slice(&EXT_PSK_KEX_MODES.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.push(1); // list length
    ext.push(1); // psk_dhe_ke

    // 12. supported_versions (0x002B) — GREASE + TLS 1.3 + TLS 1.2
    push_supported_versions(&mut ext, ver_g);

    // 13. compress_certificate (0x001B)
    ext.extend_from_slice(&EXT_COMPRESS_CERTIFICATE.to_be_bytes());
    ext.extend_from_slice(&5u16.to_be_bytes()); // ext data len
    ext.extend_from_slice(&3u16.to_be_bytes()); // algorithms list len
    ext.push(0x02); // brotli
    ext.push(0x01); // zlib
    ext.push(0x00); // none

    // 14. application_settings (0x4469) — Chrome-specific
    ext.extend_from_slice(&EXT_APPLICATION_SETTINGS.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes()); // empty settings

    // 15. ECH GREASE (0xfe0d) — Chrome 122+ default behavior.
    //
    // Реальный Chrome отправляет dummy ECH extension в КАЖДОМ ClientHello,
    // даже если сервер ECH не поддерживает. Это создаёт политическую
    // дилемму для DPI: блокировать = заблокировать весь Chrome 122+ трафик
    // (политическое самоубийство для consumer ISP), пропускать = не читать
    // SNI (ECH визуально неотличим от real ECH без попытки расшифровки).
    //
    // Структура: RFC 9460 §4 ECHClientHello с config_id, public_key, payload —
    // все random. DPI не может отличить без private key.
    let ech_ext = build_ech_grease_extension(rng);
    ext.extend_from_slice(&ech_ext);

    // 16. GREASE extension (second, before padding)
    let grease2 = rng.pick_grease();
    ext.extend_from_slice(&grease2.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());

    ext
}

/// Строит ECH GREASE extension (type 0xFE0D) в формате Chrome 124+.
///
/// Структура (RFC 9460 §4 ECHClientHello):
/// ```text
/// Extension:
///   type: 0xFE0D (2 bytes)
///   length: N (2 bytes)
///
/// ECHClientHello:
///   ECHConfig:
///     version: 0xFE0D (2 bytes)
///     length: M (2 bytes)
///     config_id: random (1 byte)
///     kem_id: 0x0010 (DHKEM P-256)
///     public_key_len: 65 (2 bytes)
///     public_key: 65 bytes (0x04 + 64 random — выглядит как P-256 point)
///     cipher_suites_len: 4 (2 bytes)
///     cipher_suite: kdf=0x0001 (HKDF-SHA256), aead=0x0001 (AES-128-GCM)
///     max_name_length: 0 (1 byte)
///     public_name_len: 0 (1 byte)
///     extensions_len: 0 (2 bytes)
///   enc_len: 0 (2 bytes) — empty for GREASE
///   payload_len: random(16, 256) (2 bytes)
///   payload: N random bytes
/// ```
///
/// Fake CH умирает на первом хопе (TTL=1), сервер не видит extension →
/// криптографическая валидность не требуется. Структурная валидность
/// обязательна (DPI парсит format).
fn build_ech_grease_extension(rng: &mut PerConnRng) -> Vec<u8> {
    let config_id = rng.next_u32() as u8;

    // Random P-256 uncompressed point (0x04 prefix + 64 random bytes)
    let mut pub_key = [0u8; P256_PUBLIC_KEY_SIZE];
    rng.fill_bytes(&mut pub_key);
    pub_key[0] = 0x04; // Uncompressed point format

    // Random payload (Chrome uses 16-256 bytes for GREASE)
    let payload_len = rng.next_range(16, 256) as usize;
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);

    // Build ECHConfigContents
    let mut config_contents = Vec::with_capacity(85);
    config_contents.push(config_id);
    config_contents.extend_from_slice(&HPKE_KEM_P256.to_be_bytes());
    config_contents.extend_from_slice(&(P256_PUBLIC_KEY_SIZE as u16).to_be_bytes());
    config_contents.extend_from_slice(&pub_key);
    config_contents.extend_from_slice(&4u16.to_be_bytes()); // cipher_suites_len
    config_contents.extend_from_slice(&HPKE_KDF_HKDF_SHA256.to_be_bytes());
    config_contents.extend_from_slice(&HPKE_AEAD_AES_128_GCM.to_be_bytes());
    config_contents.push(0); // max_name_length
    config_contents.push(0); // public_name_len (empty name)
    config_contents.extend_from_slice(&0u16.to_be_bytes()); // extensions_len

    // Wrap config_contents in ECHConfig
    let mut config = Vec::with_capacity(4 + config_contents.len());
    config.extend_from_slice(&0xFE0Du16.to_be_bytes()); // version
    config.extend_from_slice(&(config_contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&config_contents);

    // Build ECHClientHello (config + enc + payload)
    let mut ech = Vec::with_capacity(config.len() + 4 + payload_len);
    ech.extend_from_slice(&config);
    ech.extend_from_slice(&0u16.to_be_bytes()); // enc_len (empty for GREASE)
    ech.extend_from_slice(&(payload_len as u16).to_be_bytes());
    ech.extend_from_slice(&payload);

    // Wrap in extension header
    let mut ext = Vec::with_capacity(4 + ech.len());
    ext.extend_from_slice(&EXT_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
    ext.extend_from_slice(&(ech.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ech);

    ext
}

fn push_sni_extension(ext: &mut Vec<u8>, sni: &str) {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len() as u16;
    let list_len = sni_len + 3; // name_type(1) + name_len(2) + name
    let ext_data_len = list_len + 2; // + list_len field

    ext.extend_from_slice(&EXT_SNI.to_be_bytes());
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.push(0x00); // name_type: host_name
    ext.extend_from_slice(&sni_len.to_be_bytes());
    ext.extend_from_slice(sni_bytes);
}

fn push_empty_extension(ext: &mut Vec<u8>, ext_type: u16) {
    ext.extend_from_slice(&ext_type.to_be_bytes());
    ext.extend_from_slice(&0u16.to_be_bytes());
}

fn push_supported_groups(ext: &mut Vec<u8>, grease_group: u16) {
    let groups: [u16; 5] = [
        grease_group,
        GROUP_X25519MLKEM768,
        GROUP_X25519,
        GROUP_SECP256R1,
        GROUP_SECP384R1,
    ];
    let list_len = (groups.len() * 2) as u16;
    let ext_data_len = list_len + 2; // + list_len field

    ext.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    for &g in &groups {
        ext.extend_from_slice(&g.to_be_bytes());
    }
}

fn push_alpn_extension(ext: &mut Vec<u8>) {
    let h2 = b"h2";
    let http11 = b"http/1.1";
    let protocols_len = (1 + h2.len() + 1 + http11.len()) as u16;
    let ext_data_len = protocols_len + 2; // + list_len field

    ext.extend_from_slice(&EXT_ALPN.to_be_bytes());
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&protocols_len.to_be_bytes());
    ext.push(h2.len() as u8);
    ext.extend_from_slice(h2);
    ext.push(http11.len() as u8);
    ext.extend_from_slice(http11);
}

fn push_sig_algs_extension(ext: &mut Vec<u8>) {
    let sig_algs: [u16; 8] = [
        0x0804, // rsa_pss_rsae_sha256
        0x0403, // ecdsa_secp256r1_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0503, // ecdsa_secp384r1_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0601, // rsa_pkcs1_sha512
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
    ];
    let list_len = (sig_algs.len() * 2) as u16;
    let ext_data_len = list_len + 2;

    ext.extend_from_slice(&EXT_SIG_ALGS.to_be_bytes());
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    for &sa in &sig_algs {
        ext.extend_from_slice(&sa.to_be_bytes());
    }
}

fn push_key_share_extension(ext: &mut Vec<u8>, rng: &mut PerConnRng) {
    // X25519MLKEM768 key share (1184 bytes random — fake CH, server never sees)
    let mut pq_key = vec![0u8; MLKEM768_PUBLIC_KEY_SIZE];
    rng.fill_bytes(&mut pq_key);

    // X25519 key share (32 bytes random)
    let mut x25519_key = [0u8; X25519_PUBLIC_KEY_SIZE];
    rng.fill_bytes(&mut x25519_key);

    // ClientShares list
    let mut shares = Vec::with_capacity(4 + MLKEM768_PUBLIC_KEY_SIZE + 4 + X25519_PUBLIC_KEY_SIZE);

    // X25519MLKEM768 entry
    shares.extend_from_slice(&GROUP_X25519MLKEM768.to_be_bytes());
    shares.extend_from_slice(&(MLKEM768_PUBLIC_KEY_SIZE as u16).to_be_bytes());
    shares.extend_from_slice(&pq_key);

    // X25519 entry
    shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
    shares.extend_from_slice(&(X25519_PUBLIC_KEY_SIZE as u16).to_be_bytes());
    shares.extend_from_slice(&x25519_key);

    let shares_len = shares.len() as u16;
    let ext_data_len = shares_len + 2; // + client_shares_len field

    ext.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&shares_len.to_be_bytes());
    ext.extend_from_slice(&shares);
}

fn push_supported_versions(ext: &mut Vec<u8>, grease_version: u16) {
    let versions: [u16; 3] = [grease_version, 0x0304, 0x0303]; // GREASE + TLS 1.3 + TLS 1.2
    let list_len = (versions.len() * 2) as u8;
    let ext_data_len = list_len as u16 + 1; // + list_len field (1 byte)

    ext.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.push(list_len);
    for &v in &versions {
        ext.extend_from_slice(&v.to_be_bytes());
    }
}

/// Строит ClientHello body (без padding extension).
fn build_ch_body(rng: &mut PerConnRng, grease: (u16, u16, u16, u16), extensions: &[u8]) -> Vec<u8> {
    let (cipher_g, _, _, _) = grease;
    let mut body = Vec::with_capacity(200 + extensions.len());

    // legacy_version: TLS 1.2 (0x0303) — RFC 8446 requires this
    body.extend_from_slice(&[0x03, 0x03]);

    // random (32 bytes)
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    body.extend_from_slice(&random);

    // session_id (32 bytes — Chrome uses 32-byte session ID)
    let mut sess_id = [0u8; 32];
    rng.fill_bytes(&mut sess_id);
    body.push(32); // session_id length
    body.extend_from_slice(&sess_id);

    // cipher_suites: GREASE + 3 standard + GREASE (Chrome puts GREASE at both ends)
    let cipher_suites: [u16; 5] = [
        cipher_g,
        CS_TLS_AES_128_GCM_SHA256,
        CS_TLS_AES_256_GCM_SHA384,
        CS_TLS_CHACHA20_POLY1305_SHA256,
        cipher_g, // Chrome adds GREASE at end too
    ];
    let cs_len = (cipher_suites.len() * 2) as u16;
    body.extend_from_slice(&cs_len.to_be_bytes());
    for &cs in &cipher_suites {
        body.extend_from_slice(&cs.to_be_bytes());
    }

    // compression_methods: null only
    body.push(1); // list length
    body.push(0x00); // null compression

    // extensions
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);

    body
}

/// Добавляет padding extension (0x0015) для доведения CH до random multiple of 16.
///
/// Chrome 130+ behavior: pad to random multiple of 16 in [512, 4096].
fn add_padding(mut body: Vec<u8>, rng: &mut PerConnRng) -> Vec<u8> {
    // Current body includes extensions_len(2) + extensions, but NOT padding ext yet.
    // We need to:
    // 1. Compute current body size (including everything except padding ext)
    // 2. Compute target size = random multiple of 16 in [512, 4096]
    // 3. pad_data_len = target - current_body - 4 (ext type + ext len)
    // 4. Add padding extension
    // 5. Update extensions_len in body

    let current_body_len = body.len();
    // body includes: version(2) + random(32) + session_id(33) + cipher_suites(2+10) +
    //                compression(2) + ext_len(2) + extensions
    // The ext_len field at position (2+32+33+12+2) = 81..83 contains current extensions length

    let target_body_len = compute_padded_body_size(current_body_len, rng);

    // Padding extension: type(2) + len(2) + pad_data(N)
    // target_body_len = current_body_len + 4 + pad_data_len
    let pad_data_len = target_body_len.saturating_sub(current_body_len + 4);

    // Build padding extension
    let mut pad_ext = Vec::with_capacity(4 + pad_data_len);
    pad_ext.extend_from_slice(&EXT_PADDING.to_be_bytes());
    pad_ext.extend_from_slice(&(pad_data_len as u16).to_be_bytes());
    pad_ext.resize(4 + pad_data_len, 0x00); // fill with zeros

    // Find extensions_len position and update it
    // Position: after version(2) + random(32) + session_id_len(1) + session_id(32) +
    //           cipher_suites_len(2) + cipher_suites(10) + compression_len(1) + compression(1)
    let ext_len_pos = 2 + 32 + 1 + 32 + 2 + 10 + 1 + 1; // = 81
    let current_ext_len = u16::from_be_bytes([body[ext_len_pos], body[ext_len_pos + 1]]);
    let new_ext_len = current_ext_len as usize + pad_ext.len();
    body[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(new_ext_len as u16).to_be_bytes());

    // Append padding extension
    body.extend_from_slice(&pad_ext);

    body
}

/// Вычисляет целевой размер body с padding.
///
/// Chrome 130+: pad to random multiple of 16 in [512, 4096].
/// Если current_body_len > 4096, не добавляем padding (pad_data_len = 0).
///
/// ВАЖНО: target включает padding extension header (4 байта).
/// target = current_body + 4 (ext header) + pad_data_len
/// target должно быть multiple of 16.
fn compute_padded_body_size(current_body_len: usize, rng: &mut PerConnRng) -> usize {
    const MIN_PADDED: usize = 512;
    const MAX_PADDED: usize = 4096;
    const ALIGN: usize = 16;
    const PAD_EXT_HEADER: usize = 4; // type(2) + len(2)

    // Account for padding extension header — we want the TOTAL body
    // (current + padding ext) to be a multiple of 16.
    let with_ext_header = current_body_len + PAD_EXT_HEADER;

    if with_ext_header >= MAX_PADDED {
        // Already too large — minimal padding (pad_data_len = 0)
        return current_body_len + PAD_EXT_HEADER;
    }

    let base = with_ext_header.max(MIN_PADDED);
    let aligned = base.next_multiple_of(ALIGN);

    // Add random extra padding: 0..(MAX_PADDED - aligned) in multiples of 16
    let max_extra = MAX_PADDED.saturating_sub(aligned);
    let extra_steps = max_extra / ALIGN;
    let extra = if extra_steps > 0 {
        (rng.next_range(0, extra_steps as u64) * ALIGN as u64) as usize
    } else {
        0
    };

    aligned + extra
}

/// Оборачивает body в handshake header: type(1) + length(3) + body
fn wrap_handshake(body: &[u8]) -> Vec<u8> {
    let body_len = body.len();
    let mut hs = Vec::with_capacity(4 + body_len);
    hs.push(0x01); // ClientHello
    // 3-byte length
    hs.push(((body_len >> 16) & 0xFF) as u8);
    hs.push(((body_len >> 8) & 0xFF) as u8);
    hs.push((body_len & 0xFF) as u8);
    hs.extend_from_slice(body);
    hs
}

/// Оборачивает handshake в TLS record: type(1) + version(2) + length(2) + handshake
fn wrap_record(handshake: &[u8]) -> Vec<u8> {
    let hs_len = handshake.len();
    let mut record = Vec::with_capacity(5 + hs_len);
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version (legacy)
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(handshake);
    record
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rng() -> PerConnRng {
        PerConnRng::new(42)
    }

    #[test]
    fn test_build_client_hello_basic() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);
        assert!(ch.len() >= 512, "CH too small: {} bytes", ch.len());
        assert!(ch.len() <= 4096, "CH too large: {} bytes", ch.len());
        assert_eq!(ch[0], 0x16); // TLS Handshake
        assert_eq!(ch[5], 0x01); // ClientHello
    }

    #[test]
    fn test_build_client_hello_size_variable() {
        // Multiple CHs should have variable sizes (padding randomization)
        let mut sizes = Vec::new();
        for i in 0..20 {
            let mut rng = PerConnRng::new(i);
            let ch = build_client_hello("test.com", &mut rng);
            sizes.push(ch.len());
        }
        let unique = sizes.iter().collect::<std::collections::HashSet<_>>().len();
        assert!(
            unique > 1,
            "All CHs have same size — padding not randomized: {:?}",
            sizes
        );
    }

    #[test]
    fn test_build_client_hello_multiple_of_16() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);
        // TLS record: header(5) + handshake
        // Handshake: header(4) + body
        // Body (with padding) should be multiple of 16 (Chrome behavior)
        let body_len = ch.len() - 5 - 4;
        assert_eq!(
            body_len % 16,
            0,
            "Body not multiple of 16: {} bytes (CH total: {})",
            body_len,
            ch.len()
        );
    }

    #[test]
    fn test_parse_sni_roundtrip() {
        let mut rng = test_rng();
        let ch = build_client_hello("security.vercel.com", &mut rng);
        let sni = parse_sni(&ch).expect("SNI should be parseable");
        assert_eq!(sni, "security.vercel.com");
    }

    #[test]
    fn test_parse_sni_short() {
        let mut rng = test_rng();
        let ch = build_client_hello("a.b", &mut rng);
        let sni = parse_sni(&ch).expect("SNI should be parseable");
        assert_eq!(sni, "a.b");
    }

    #[test]
    fn test_parse_sni_long() {
        let mut rng = test_rng();
        let long_sni = "subdomain.example.co.uk";
        let ch = build_client_hello(long_sni, &mut rng);
        let sni = parse_sni(&ch).expect("SNI should be parseable");
        assert_eq!(sni, long_sni);
    }

    #[test]
    fn test_grease_values_present() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);

        // Check that at least one GREASE value appears in the CH
        let has_grease = GREASE_VALUES
            .iter()
            .any(|g| ch.windows(2).any(|w| w == g.to_be_bytes()));
        assert!(has_grease, "No GREASE value found in CH");
    }

    #[test]
    fn test_pq_group_present() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);

        // Check that X25519MLKEM768 (0x11EC) appears in the CH
        let pq_group_bytes = GROUP_X25519MLKEM768.to_be_bytes();
        let has_pq = ch.windows(2).any(|w| w == pq_group_bytes);
        assert!(has_pq, "X25519MLKEM768 group not found in CH");
    }

    #[test]
    fn test_ech_grease_present() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);

        // ECH extension type 0xFE0D должна присутствовать в CH
        let ech_type_bytes = EXT_ENCRYPTED_CLIENT_HELLO.to_be_bytes();
        let has_ech = ch.windows(2).any(|w| w == ech_type_bytes);
        assert!(has_ech, "ECH GREASE extension (0xFE0D) not found in CH");
    }

    #[test]
    fn test_ech_grease_structure() {
        let mut rng = test_rng();
        let ech_ext = build_ech_grease_extension(&mut rng);

        // Extension header: type(2) + length(2)
        assert_eq!(ech_ext[0..2], [0xFE, 0x0D], "Wrong ECH extension type");
        let ext_len = u16::from_be_bytes([ech_ext[2], ech_ext[3]]) as usize;
        assert_eq!(ech_ext.len(), 4 + ext_len, "Extension length mismatch");

        // ECHConfig version (0xFE0D)
        assert_eq!(ech_ext[4..6], [0xFE, 0x0D], "Wrong ECHConfig version");

        // KEM ID (P-256 = 0x0010) at offset 4 + 4 (config version + length) + 1 (config_id)
        let kem_offset = 4 + 4 + 1;
        assert_eq!(ech_ext[kem_offset..kem_offset + 2], [0x00, 0x10], "Wrong KEM ID");
    }

    #[test]
    fn test_ech_grease_varies_per_connection() {
        // ECH config_id и payload должны быть разными per-connection
        let mut rng1 = PerConnRng::new(1);
        let mut rng2 = PerConnRng::new(2);
        let ech1 = build_ech_grease_extension(&mut rng1);
        let ech2 = build_ech_grease_extension(&mut rng2);

        // config_id (at offset 4+4 = 8) должен различаться с высокой вероятностью
        let config_id_1 = ech1[8];
        let config_id_2 = ech2[8];

        // payload (последние N байт) должен различаться
        let differences = ech1
            .iter()
            .zip(ech2.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differences > 5,
            "ECH extensions too similar — per-conn randomisation broken (config_id_1={}, config_id_2={}, diffs={})",
            config_id_1,
            config_id_2,
            differences
        );
    }

    #[test]
    fn test_ech_grease_payload_random() {
        // Payload должен быть random, не all-zeros
        let mut rng = test_rng();
        let ech_ext = build_ech_grease_extension(&mut rng);

        // Парсим payload: пропускаем extension header (4) + ECHConfig (4 + config_contents) + enc_len (2)
        // config_contents = config_id(1) + kem(2) + pk_len(2) + pk(65) + cs_len(2) + cs(4) + mnl(1) + pnl(1) + ext_len(2) = 80
        let config_contents_len = 80;
        let enc_len_pos = 4 + 4 + config_contents_len;
        let payload_len_pos = enc_len_pos + 2;
        let payload_start = payload_len_pos + 2;

        let payload_len = u16::from_be_bytes([
            ech_ext[payload_len_pos],
            ech_ext[payload_len_pos + 1],
        ]) as usize;
        assert!(payload_len >= 16 && payload_len <= 256, "Payload length out of range");

        let payload = &ech_ext[payload_start..payload_start + payload_len];
        let non_zero = payload.iter().filter(|&&b| b != 0).count();
        assert!(
            non_zero > payload_len / 2,
            "Payload too many zeros — may not be properly randomised"
        );
    }

    #[test]
    fn test_grease_varies_per_connection() {
        // Different connections should have different GREASE values
        let mut rng1 = PerConnRng::new(1);
        let mut rng2 = PerConnRng::new(2);
        let ch1 = build_client_hello("example.com", &mut rng1);
        let ch2 = build_client_hello("example.com", &mut rng2);

        // CHs should differ (different random fields + different GREASE)
        let differences = ch1
            .iter()
            .zip(ch2.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differences > 10,
            "CHs too similar — per-conn randomisation may be broken: {} differences",
            differences
        );
    }

    #[test]
    fn test_tls_version_fields() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);

        assert_eq!(ch[0], 0x16); // ContentType: Handshake
        assert_eq!(ch[1], 0x03); // Record version major
        assert_eq!(ch[2], 0x01); // Record version minor (TLS 1.0 legacy)
        assert_eq!(ch[5], 0x01); // HandshakeType: ClientHello

        // legacy_version in CH body (after record header 5 + handshake header 4 = 9)
        assert_eq!(ch[9], 0x03); // TLS 1.2 major
        assert_eq!(ch[10], 0x03); // TLS 1.2 minor
    }

    #[test]
    fn test_alpn_present() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);

        // Check for "h2" in CH
        let has_h2 = ch.windows(2).any(|w| w == b"h2");
        assert!(has_h2, "ALPN h2 not found in CH");

        // Check for "http/1.1"
        let has_http11 = ch.windows(8).any(|w| w == b"http/1.1");
        assert!(has_http11, "ALPN http/1.1 not found in CH");
    }

    #[test]
    fn test_key_share_size() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);

        // X25519MLKEM768 key share = 1184 bytes + ECH GREASE ~100 bytes
        // This makes the CH significantly larger than old 517 bytes
        assert!(
            ch.len() > 1300,
            "CH too small — PQ key share or ECH GREASE may be missing: {} bytes",
            ch.len()
        );
    }

    #[test]
    fn test_is_client_hello_detection() {
        let mut rng = test_rng();
        let ch = build_client_hello("example.com", &mut rng);
        assert!(is_client_hello(&ch));

        let not_ch = vec![0x16, 0x03, 0x01, 0x00, 0x02, 0x02]; // ServerHello
        assert!(!is_client_hello(&not_ch));
    }

    #[test]
    fn test_build_client_hello_default() {
        let ch = build_client_hello_default("example.com");
        assert!(is_client_hello(&ch));
        assert!(parse_sni(&ch).is_some());
    }

    #[test]
    fn test_mask_sni() {
        let mut rng = test_rng();
        let original = build_client_hello("blocked.com", &mut rng);
        let masked = mask_sni(&original, "www.google.com").expect("mask should work");
        assert!(is_client_hello(&masked));
        let sni = parse_sni(&masked).expect("SNI should be parseable");
        assert_eq!(sni, "www.google.com");
    }

    #[test]
    fn test_sni_too_long_panics() {
        let mut rng = test_rng();
        let long_sni = "a".repeat(254);
        let result = std::panic::catch_unwind(move || {
            build_client_hello(&long_sni, &mut rng);
        });
        assert!(result.is_err(), "Should panic on SNI > 253 bytes");
    }
}
