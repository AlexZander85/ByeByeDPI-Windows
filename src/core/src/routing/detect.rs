//! DPI vs Geo-block детекция.
//!
//! ## Подход
//! Анализ ответа сервера для определения причины блокировки:
//!
//! | Симптом | Причина | Детектор |
//! |---------|---------|----------|
//! | RST / Connection reset / Timeout | DPI | `detect_dpi_block()` |
//! | HTTP 403 Forbidden | Geo-block | `detect_geo_block()` |
//! | HTTP 451 Unavailable For Legal Reasons | Geo-block | `detect_geo_block()` |
//! | TCP half-open / SYN timeout | DPI | `detect_dpi_block()` |
//! | TLS handshake timeout / certificate error | DPI | `detect_dpi_block()` |
//! | HTTP 3xx redirect to block page | DPI/Geo | `detect_redirect_block()` |
//!
//! ## Использование
//! Результаты передаются в `GeoRouter.mark_bad_route()` или
//! `ProbeTuneRun.record_apply()` для адаптации стратегий.
//!
//! ## Источник
//! Адаптировано из [Nova](https://github.com/patrykkalinowski/nova)
//! — geo-block detection.

/// HTTP статус-коды, указывающие на geo-блокировку.
const GEO_BLOCK_CODES: &[u16] = &[403, 451];

/// Детектор типа блокировки (DPI vs Geo).
pub struct GeoBlockDetector;

impl GeoBlockDetector {
    /// Анализирует HTTP ответ на предмет geo-блокировки.
    ///
    /// ## Критерии
    /// - HTTP 403 Forbidden
    /// - HTTP 451 Unavailable For Legal Reasons
    /// - HTML страница с ключевыми словами "block", "unavailable", "restricted"
    /// - Заголовки: `Location`, `X-Block-Reason`
    ///
    /// ## Пример
    /// ```rust
    /// use freedpi_core::routing::detect::GeoBlockDetector;
    ///
    /// let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
    /// assert!(GeoBlockDetector::detect_geo_block(response));
    ///
    /// let ok = b"HTTP/1.1 200 OK\r\n\r\n";
    /// assert!(!GeoBlockDetector::detect_geo_block(ok));
    /// ```
    pub fn detect_geo_block(response: &[u8]) -> bool {
        if response.is_empty() {
            return false;
        }

        // Парсим HTTP статус-код
        if let Ok(status_str) = std::str::from_utf8(response) {
            if let Some(status_line) = status_str.lines().next() {
                let parts: Vec<&str> = status_line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(code) = parts[1].parse::<u16>() {
                        if GEO_BLOCK_CODES.contains(&code) {
                            return true;
                        }
                    }
                }
            }

            // Проверяем тело на ключевые слова geo-блока
            if let Some(body_start) = status_str.find("\r\n\r\n") {
                let body = &status_str[body_start + 4..];
                let body_lower = body.to_lowercase();
                if body_lower.contains("blocked")
                    || body_lower.contains("unavailable in your")
                    || body_lower.contains("not available in your")
                    || body_lower.contains("restricted in your")
                    || body_lower.contains("geo-restricted")
                    || body_lower.contains("this content is not available")
                {
                    return true;
                }
            }

            // Проверяем заголовки на geo-bock индикаторы
            for line in status_str.lines().skip(1) {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("x-block-reason:")
                    || line_lower.starts_with("x-geo-block:")
                    || (line_lower.starts_with("location:")
                        && (line_lower.contains("block") || line_lower.contains("error")))
                {
                    return true;
                }
            }
        }

        false
    }

    /// Анализирует ошибку соединения на предмет DPI-блокировки.
    ///
    /// ## Критерии
    /// - Connection reset (RST)
    /// - Connection refused (если порт точно открыт)
    /// - TLS handshake failure без видимой причины
    /// - Timeout при установке соединения
    ///
    /// ## Пример
    /// ```rust
    /// use freedpi_core::routing::detect::GeoBlockDetector;
    ///
    /// // Connection reset — типичный DPI
    /// assert!(GeoBlockDetector::detect_dpi_block("connection reset by peer"));
    /// // DNS resolution failure — не DPI
    /// assert!(!GeoBlockDetector::detect_dpi_block("no address found"));
    /// ```
    pub fn detect_dpi_block(error: &str) -> bool {
        let lower = error.to_lowercase();

        // Типичные DPI-индикаторы
        lower.contains("connection reset")
            || lower.contains("rst")
            || lower.contains("tls handshake timeout")
            || lower.contains("tls handshake failure")
            || lower.contains("timed out")
            || lower.contains("connection closed before")
            || lower.contains("broken pipe")
            || lower.contains("unexpected eof")
            // DPI часто обрывает на середине TLS handshake
            || (lower.contains("ssl") && lower.contains("error"))
            // TCP half-open detection
            || lower.contains("connection attempt failed")
    }

    /// Определяет, является ли проблема DPI или geo-блоком.
    ///
    /// ## Returns
    /// - `Some(true)` — geo-block (HTTP 403/451)
    /// - `Some(false)` — DPI block (RST/timeout/EOF)
    /// - `None` — не удалось определить
    pub fn classify(error: &str, response: Option<&[u8]>) -> Option<bool> {
        // Сначала проверяем HTTP ответ
        if let Some(resp) = response {
            if Self::detect_geo_block(resp) {
                return Some(true); // geo-block
            }
        }

        // Затем проверяем ошибку соединения
        if Self::detect_dpi_block(error) {
            return Some(false); // DPI block
        }

        None // неопределено
    }
}
