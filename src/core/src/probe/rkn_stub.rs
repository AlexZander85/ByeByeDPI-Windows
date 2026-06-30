//! RKN Stub Page Detection — распознавание заглушек РКН в HTTP response body.
//!
//! Проверяет HTTP response body на наличие 10 известных подстрок,
//! которые встречаются в заглушках Роскомнадзора.

use crate::probe::config::ProbeConfig;

/// Известные подстроки RKN заглушек (lowercase).
const DEFAULT_RKN_STUBS: &[&str] = &[
    "роскомнадзор",
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

/// Проверяет, является ли HTTP body заглушкой РКН.
///
/// Использует подстроки из конфигурации. Поиск регистронезависимый.
pub fn is_rkn_stub(body: &[u8], config: &ProbeConfig) -> bool {
    if body.is_empty() {
        return false;
    }
    let lower: Vec<u8> = body.iter().map(|b| b.to_ascii_lowercase()).collect();
    config
        .rkn_stub_substrings
        .iter()
        .any(|stub| contains_subsequence(&lower, stub.as_bytes()))
}

/// Проверяет body с дефолтными подстроками (для тестов и fallback).
pub fn is_rkn_stub_default(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let lower: Vec<u8> = body.iter().map(|b| b.to_ascii_lowercase()).collect();
    DEFAULT_RKN_STUBS
        .iter()
        .any(|stub| contains_subsequence(&lower, stub.as_bytes()))
}

/// Поиск подпоследовательности в haystack (простой алгоритм O(n*m)).
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rkn_stub_detected() {
        let body = b"This page is blocked by Roskomnadzor. The content is restricted.";
        assert!(is_rkn_stub_default(body));
    }

    #[test]
    fn test_rkn_stub_russian() {
        let body = "Доступ к данному ресурсу заблокирован по решению Роскомнадзора.".as_bytes();
        assert!(is_rkn_stub_default(body));
    }

    #[test]
    fn test_rkn_stub_blockpage() {
        let body = b"<html><title>BlockPage</title><body>Access denied</body></html>";
        assert!(is_rkn_stub_default(body));
    }

    #[test]
    fn test_rkn_stub_poiskman() {
        let body = b"<html><body>PoiskMan block page</body></html>";
        assert!(is_rkn_stub_default(body));
    }

    #[test]
    fn test_rkn_stub_internet_zapret() {
        let body = b"internet-zapret project blocking";
        assert!(is_rkn_stub_default(body));
    }

    #[test]
    fn test_no_stub_clean_page() {
        let body = b"<html><title>Example</title><body>Hello World</body></html>";
        assert!(!is_rkn_stub_default(body));
    }

    #[test]
    fn test_no_stub_empty() {
        assert!(!is_rkn_stub_default(b""));
    }

    #[test]
    fn test_contains_subsequence_basic() {
        assert!(contains_subsequence(b"hello world", b"world"));
        assert!(!contains_subsequence(b"hello world", b"xyz"));
    }

    #[test]
    fn test_contains_subsequence_empty_needle() {
        assert!(contains_subsequence(b"hello", b""));
    }
}
