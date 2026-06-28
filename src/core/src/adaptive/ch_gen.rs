//! TLS ClientHello Generator — генерация TLS 1.2/1.3 ClientHello из struct.
//!
//! ## Назначение
//! Генерация TLS ClientHello без перехвата реального (без дампа).
//! Используется для:
//! - SEQ Number Spoofing (fake CH с произвольным SNI)
//! - TLS Spoof (fake CH с белым SNI)
//! - Probe/Tune/Run (тестовые CH для проверки DPI)
//!
//! ## Механизм
//! Используется шаблон реального Chrome TLS 1.3 ClientHello (517 байт).
//! SNI заменяется на целевой домен. Random, session_id, key_share
//! генерируются случайно при каждом вызове.
//!
//! ## Размер
//! Всегда 517 байт (фиксированный размер для Chrome TLS 1.3).
//! Максимальная длина SNI: 219 байт.
//!
//! ## Источник
//! Адаптировано из [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust) —
//! модуль `packet/tls.rs`.

use rand::RngCore;

/// Фиксированный размер ClientHello (517 байт — Chrome TLS 1.3).
pub const CLIENT_HELLO_SIZE: usize = 517;

/// Минимальная длина SNI.
const MIN_SNI_LEN: usize = 1;

/// Максимальная длина SNI (219 байт — ограничение шаблона).
const MAX_SNI_LEN: usize = 219;

/// Шаблон SNI в hex-шаблоне.
const TEMPLATE_SNI: &[u8] = b"mci.ir";

/// TLS 1.3 ClientHello template (Chrome 120+, hex).
/// Захвачен из реального Chrome на Windows 11.
const TPL_HEX: &str = "\
1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b\
20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c0\
2cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b0009000006\
6d63692e6972000b000403000102000a00160014001d0017001e00190018010001010102010301040023\
00000010000e000c02683208687474702f312e310016000000170000000d002a00280403050306030807\
08080809080a080b080408050806040105010601030303010302040205020602002b0005040304030300\
2d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efda\
a98693d217001500d5";

/// Декодер hex (без внешних зависимостей).
mod hex {
    /// Декодирует hex-строку в Vec<u8>.
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return Err("hex string has odd length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

use std::sync::LazyLock;

/// Распарсенный шаблон ClientHello (ленивая инициализация).
static TEMPLATE_BYTES: LazyLock<Vec<u8>> =
    LazyLock::new(|| hex::decode(TPL_HEX).expect("Invalid TLS template hex"));

/// Строит TLS 1.3 ClientHello с указанным SNI.
///
/// Использует Chrome-шаблон с заменой:
/// - Random (32 байта) — случайные
/// - Session ID (32 байта) — случайные
/// - SNI extension — подставляется целевой домен
/// - Key share (32 байта) — случайные
/// - Padding — подстраивается под размер SNI (общий размер = 517)
///
/// # Arguments
/// * `sni` — доменное имя для SNI extension
///
/// # Panics
/// Паникует если SNI длиннее 219 байт.
///
/// # Returns
/// Vec<u8> длиной ровно 517 байт.
///
/// # Пример
/// ```rust
/// use freedpi_core::adaptive::ch_gen::build_client_hello;
/// let ch = build_client_hello("example.com");
/// assert_eq!(ch.len(), 517);
/// assert_eq!(ch[0], 0x16); // TLS record: Handshake
/// ```
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    assert!(
        sni.len() <= MAX_SNI_LEN,
        "SNI too long: {} bytes (max {})",
        sni.len(),
        MAX_SNI_LEN
    );
    assert!(
        sni.len() >= MIN_SNI_LEN,
        "SNI too short: {} bytes (min {})",
        sni.len(),
        MIN_SNI_LEN
    );

    let tpl = &*TEMPLATE_BYTES;
    let sni_bytes = sni.as_bytes();
    let tpl_sni_len = TEMPLATE_SNI.len();

    // Сегменты шаблона (до SNI, после random, после session_id, после SNI, до key_share)
    let static1 = &tpl[..11];          // TLS record header + handshake header
    let static3 = &tpl[76..120];       // cipher suites + compression + extensions header
    let static4 = &tpl[127 + tpl_sni_len..262 + tpl_sni_len]; // после SNI до key_share

    // Случайные данные
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    let mut sess_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut sess_id);
    rng.fill_bytes(&mut key_share);

    // Padding: ClientHello должен быть 517 байт
    let pad_len = MAX_SNI_LEN - sni_bytes.len();

    let mut out = Vec::with_capacity(CLIENT_HELLO_SIZE);

    // 1. TLS record header + handshake header (11 байт)
    out.extend_from_slice(static1);
    // 2. Random (32 байта)
    out.extend_from_slice(&random);
    // 3. Session ID length + session ID (33 байта)
    out.push(0x20);
    out.extend_from_slice(&sess_id);
    // 4. Cipher suites + compression + extensions header
    out.extend_from_slice(static3);
    // 5. SNI extension
    let sni_ext_len = (sni_bytes.len() + 5) as u16; // type(2) + len(2) + list_len(2) + name_type(1) + name_len(2) + name
    let sni_list_len = (sni_bytes.len() + 3) as u16; // name_type(1) + name_len(2) + name
    let sni_len = sni_bytes.len() as u16;
    out.extend_from_slice(&sni_ext_len.to_be_bytes());
    out.extend_from_slice(&sni_list_len.to_be_bytes());
    out.push(0x00); // name_type: host_name
    out.extend_from_slice(&sni_len.to_be_bytes());
    out.extend_from_slice(sni_bytes);
    // 6. Остальные extensions (без SNI)
    out.extend_from_slice(static4);
    // 7. Key share (32 байта)
    out.extend_from_slice(&key_share);
    // 8. Padding extension
    out.extend_from_slice(&[0x00, 0x15]); // extension type: padding
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    out.extend_from_slice(&vec![0x00; pad_len]);

    debug_assert_eq!(
        out.len(),
        CLIENT_HELLO_SIZE,
        "ClientHello generated with wrong size: {} (expected {})",
        out.len(),
        CLIENT_HELLO_SIZE,
    );

    out
}

/// Парсит SNI из TLS ClientHello.
///
/// Работает только с ClientHello, сгенерированными `build_client_hello()`
/// (совместимый формат).
///
/// # Arguments
/// * `client_hello` — полный TLS ClientHello (TLS record + handshake)
///
/// # Returns
/// `Some(sni_string)` если SNI найден, `None` если формат не распознан.
///
/// # Пример
/// ```rust
/// use freedpi_core::adaptive::ch_gen::{build_client_hello, parse_sni};
/// let ch = build_client_hello("example.com");
/// assert_eq!(parse_sni(&ch), Some("example.com".to_string()));
/// ```
pub fn parse_sni(client_hello: &[u8]) -> Option<String> {
    if client_hello.len() < CLIENT_HELLO_SIZE {
        return None;
    }
    let sni_len = u16::from_be_bytes([client_hello[125], client_hello[126]]) as usize;
    if 127 + sni_len > client_hello.len() {
        return None;
    }
    String::from_utf8(client_hello[127..127 + sni_len].to_vec()).ok()
}

/// [OF1] Маскировка SNI в существующем TLS ClientHello.
///
/// ## Принцип
/// Заменяет реальный SNI в ClientHello на белый домен (`white_domain`).
/// DPI видит белый SNI (неблокируемый) и пропускает трафик.
/// Реальный SNI остаётся только в зашифрованном TLS-расширении ECH
/// (если сервер поддерживает), которое DPI не может прочитать.
///
/// Использует `build_client_hello(white_domain)` для генерации нового CH
/// с указанным белым доменом. Параметры (случайные данные) генерируются
/// заново, что повышает энтропию и анти-DPI стойкость.
///
/// ## Аргументы
/// * `_client_hello` — оригинальный TLS ClientHello (для валидации формата)
/// * `white_domain` — белый домен для маскировки (например, "www.google.com")
///
/// ## Returns
/// `Some(Vec<u8>)` — новый ClientHello с белым SNI (517 байт)
/// `None` — если формат не распознан
///
/// ## Источник
/// offveil [OF1] — SNI Masking
pub fn mask_sni(client_hello: &[u8], white_domain: &str) -> Option<Vec<u8>> {
    if !is_client_hello(client_hello) {
        return None;
    }

    // Просто генерируем новый CH с белым доменом
    // Это проще и надёжнее, чем патчить существующий CH
    Some(build_client_hello(white_domain))
}

/// Проверяет, является ли буфер валидным TLS ClientHello.
pub fn is_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 5
        && buf[0] == 0x16 // ContentType: Handshake
        && (buf[1] == 0x03) // Version major: TLS
        && buf[5] == 0x01 // HandshakeType: ClientHello
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_size() {
        let ch = build_client_hello("example.com");
        assert_eq!(ch.len(), CLIENT_HELLO_SIZE);
    }

    #[test]
    fn test_client_hello_sni() {
        let ch = build_client_hello("security.vercel.com");
        let sni = parse_sni(&ch).unwrap();
        assert_eq!(sni, "security.vercel.com");
    }

    #[test]
    fn test_client_hello_short_sni() {
        let ch = build_client_hello("a.b");
        assert_eq!(ch.len(), CLIENT_HELLO_SIZE);
        let sni = parse_sni(&ch).unwrap();
        assert_eq!(sni, "a.b");
    }

    #[test]
    fn test_client_hello_long_sni() {
        let sni = "a".repeat(219);
        let ch = build_client_hello(&sni);
        assert_eq!(ch.len(), CLIENT_HELLO_SIZE);
        let parsed = parse_sni(&ch).unwrap();
        assert_eq!(parsed, sni);
    }

    #[test]
    fn test_tls_record_header() {
        let ch = build_client_hello("test.com");
        assert_eq!(ch[0], 0x16); // Handshake
        assert_eq!(ch[1], 0x03); // TLS major version
        assert_eq!(ch[5], 0x01); // ClientHello
    }

    #[test]
    fn test_is_client_hello() {
        let ch = build_client_hello("example.com");
        assert!(is_client_hello(&ch));
        assert!(!is_client_hello(&[0u8; 10]));
    }

    #[test]
    fn test_parse_sni_invalid() {
        assert!(parse_sni(&[0u8; 100]).is_none());
        assert!(parse_sni(&vec![0u8; 500]).is_none());
    }

    #[test]
    fn test_randomness() {
        // Два последовательных вызова должны дать разные CH
        let ch1 = build_client_hello("example.com");
        let ch2 = build_client_hello("example.com");
        // Random, session_id, key_share должны различаться
        let rand1 = &ch1[11..43];
        let rand2 = &ch2[11..43];
        assert_ne!(rand1, rand2);
    }

    #[test]
    fn test_sni_not_in_random() {
        // SNI не должен появляться в random части
        let ch = build_client_hello("sensitive-domain.com");
        let random = &ch[11..43];
        assert!(!random.windows(5).any(|w| w == b"sensi"));
    }

    #[test]
    #[should_panic(expected = "SNI too long")]
    fn test_sni_too_long() {
        build_client_hello(&"a".repeat(220));
    }

    #[test]
    #[should_panic(expected = "SNI too short")]
    fn test_sni_empty() {
        build_client_hello("");
    }

    // === OF1: SNI Masking tests ===

    #[test]
    fn test_mask_sni_basic() {
        let ch = build_client_hello("example.com");
        let masked = mask_sni(&ch, "www.google.com").unwrap();
        assert_eq!(masked.len(), CLIENT_HELLO_SIZE);
        let parsed = parse_sni(&masked).unwrap();
        assert_eq!(parsed, "www.google.com");
    }

    #[test]
    fn test_mask_sni_same_length() {
        let ch = build_client_hello("abcdefgh.abc");
        let masked = mask_sni(&ch, "www.google.com").unwrap();
        assert_eq!(masked.len(), CLIENT_HELLO_SIZE);
        let parsed = parse_sni(&masked).unwrap();
        assert_eq!(parsed, "www.google.com");
    }

    #[test]
    fn test_mask_sni_shorter() {
        let ch = build_client_hello("very-long-domain-name.com");
        let masked = mask_sni(&ch, "x.co").unwrap();
        assert_eq!(masked.len(), CLIENT_HELLO_SIZE);
        let parsed = parse_sni(&masked).unwrap();
        assert_eq!(parsed, "x.co");
    }

    #[test]
    fn test_mask_sni_longer() {
        let ch = build_client_hello("x.co");
        let masked = mask_sni(&ch, "very-long-domain-name.com").unwrap();
        assert_eq!(masked.len(), CLIENT_HELLO_SIZE);
        let parsed = parse_sni(&masked).unwrap();
        assert_eq!(parsed, "very-long-domain-name.com");
    }

    #[test]
    fn test_mask_sni_invalid_input() {
        assert!(mask_sni(&[0u8; 100], "test.com").is_none());
        assert!(mask_sni(&vec![0u8; 500], "test.com").is_none());
    }

    #[test]
    fn test_mask_sni_tls_record_valid() {
        let ch = build_client_hello("blocked-site.com");
        let masked = mask_sni(&ch, "www.cloudflare.com").unwrap();
        assert_eq!(masked[0], 0x16); // Handshake
        assert_eq!(masked[5], 0x01); // ClientHello
    }

    #[test]
    fn test_mask_sni_roundtrip() {
        // Маскировка не должна сломать ClientHello
        let ch = build_client_hello("original.com");
        let masked = mask_sni(&ch, "masked.com").unwrap();
        assert_eq!(masked[0], 0x16);
        assert_eq!(masked[5], 0x01);
        // Повторная маскировка
        let re_masked = mask_sni(&masked, "another.com").unwrap();
        let parsed = parse_sni(&re_masked).unwrap();
        assert_eq!(parsed, "another.com");
    }

    #[test]
    fn test_mask_sni_preserves_randomness() {
        let ch1 = build_client_hello("site1.com");
        let ch2 = build_client_hello("site2.com");
        let masked1 = mask_sni(&ch1, "white.gov").unwrap();
        let masked2 = mask_sni(&ch2, "white.gov").unwrap();

        // Random части должны различаться (разные CH)
        let rand1 = &masked1[11..43];
        let rand2 = &masked2[11..43];
        assert_ne!(rand1, rand2);
    }
}
