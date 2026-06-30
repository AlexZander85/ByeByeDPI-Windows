//! Discriminator — Server-active vs Path-active classification.
//!
//! Определяет: является ли блокировка от сервера (geo-block, mTLS) или от DPI
//! (RST injection, garbage injection, etc.).
//!
//! Ключевое правило (из Ladon):
//! - Server-active: TLS alert от сервера → Clear (НЕ DPI)
//! - Path-active: RST/garbage/cutoff → Blocked (DPI)
//! - MITM certificates → Clear (сервер доступен, middlebox подменяет cert)
//! - SilentDrop → Blocked (DPI обрывает соединение)
//! - Alert (generic) → Ambiguous (неоднозначно)
//! - Version12Only → Blocked (DPI атакует ClientHello)
//!
//! Это критическое различие: если сервер сам отвечает TLS alert,
//! не нужно тратить ресурсы на desync — это geo-block, а не DPI.

use crate::probe::classifier::{HttpFailureCode, ProbeVerdict, TlsFailureCode};
use serde::{Deserialize, Serialize};

/// Тип происхождения блокировки.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOrigin {
    /// Блокировка от сервера (geo-block, mTLS, rate limit)
    ServerActive,
    /// Блокировка на пути (DPI, middlebox)
    PathActive,
    /// Неоднозначно
    Ambiguous,
}

/// Результат дискриминации.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscriminationResult {
    pub origin: BlockOrigin,
    pub verdict: ProbeVerdict,
    pub confidence: f64,
    pub rationale: String,
}

/// Дискриминация server-active vs path-active.
///
/// Основана на эвристике Ladon:
/// - TLS alert от сервера → сервер доступен → не DPI
/// - RST/garbage/timeout → middlebox → DPI
/// - MITM → сервер доступен (сертификат подменён, но соединение проходит)
/// - SilentDrop → DPI обрывает соединение
/// - Version12Only → DPI атакует ClientHello
pub fn discriminate(tls: &TlsFailureCode, http: &HttpFailureCode) -> DiscriminationResult {
    match tls {
        // ─── Server-active: сервер сам ответил → Clear (НЕ DPI) ──────────
        TlsFailureCode::AlertSniblock => DiscriminationResult {
            origin: BlockOrigin::ServerActive,
            verdict: ProbeVerdict::Clear,
            confidence: 0.90,
            rationale: "TLS alert from server: SNI rejected. Server is reachable, not DPI.".into(),
        },
        TlsFailureCode::AlertHandshake => DiscriminationResult {
            origin: BlockOrigin::ServerActive,
            verdict: ProbeVerdict::Clear,
            confidence: 0.85,
            rationale: "TLS alert from server: handshake failure. Server rejects this client."
                .into(),
        },
        TlsFailureCode::AlertProtocol => DiscriminationResult {
            origin: BlockOrigin::ServerActive,
            verdict: ProbeVerdict::Clear,
            confidence: 0.80,
            rationale: "TLS alert from server: protocol version not supported.".into(),
        },

        // ─── MITM: сервер доступен, cert подменён → Clear (ServerActive) ─
        // Если middlebox делает MITM, значит соединение проходит до сервера.
        // DPI не блокирует — он перехватывает. Сервер доступен.
        TlsFailureCode::Mitm
        | TlsFailureCode::MitmExpired
        | TlsFailureCode::MitmSelfSigned
        | TlsFailureCode::MitmHostnameMismatch => DiscriminationResult {
            origin: BlockOrigin::ServerActive,
            verdict: ProbeVerdict::Clear,
            confidence: 0.85,
            rationale: "Certificate substitution detected but server is reachable. Middlebox intercepting TLS, not blocking.".into(),
        },

        // ─── Path-active: DPI injection → Blocked ────────────────────────
        TlsFailureCode::Reset => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.85,
            rationale: "TCP RST during TLS — DPI killing connection.".into(),
        },
        TlsFailureCode::Garbage => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.80,
            rationale: "TLS garbage data — DPI injecting malformed records.".into(),
        },
        TlsFailureCode::Eof => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.75,
            rationale: "TLS EOF after handshake — DPI cutting connection.".into(),
        },

        // ─── SilentDrop: DPI обрывает соединение → Blocked ───────────────
        // SilentDrop означает TCP прошёл, но TLS завис до timeout.
        // Это классическая атака DPI: обрыв на уровне TLS.
        TlsFailureCode::SilentDrop => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.75,
            rationale: "TLS hang/timeout — DPI silently dropping connection after TCP.".into(),
        },

        // ─── Alert (generic): неоднозначно → Ambiguous ───────────────────
        // Generic alert может быть от сервера или от DPI. Нужен re-probe.
        TlsFailureCode::Alert => DiscriminationResult {
            origin: BlockOrigin::Ambiguous,
            verdict: ProbeVerdict::Ambiguous,
            confidence: 0.50,
            rationale: "Generic TLS alert — ambiguous, could be server or DPI. Re-probe recommended.".into(),
        },

        // ─── Version12Only: DPI атакует ClientHello → Blocked ────────────
        // TLS 1.3 заблокирован, 1.2 работает — DPI атакует ClientHello.
        TlsFailureCode::Version12Only => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.90,
            rationale: "TLS 1.3 blocked, 1.2 works — DPI attacking ClientHello fingerprint.".into(),
        },

        // ─── TLS worked — check HTTP for further clues ───────────────────
        TlsFailureCode::HandshakeOk | TlsFailureCode::Version13Ok => {
            discriminate_http(http)
        }
    }
}

/// Дополнительная дискриминация по HTTP phase.
fn discriminate_http(http: &HttpFailureCode) -> DiscriminationResult {
    match http {
        HttpFailureCode::Ok | HttpFailureCode::RedirectSame => DiscriminationResult {
            origin: BlockOrigin::Ambiguous,
            verdict: ProbeVerdict::Clear,
            confidence: 0.60,
            rationale: "TLS and HTTP both OK — no blocking detected at this layer.".into(),
        },
        HttpFailureCode::Cutoff => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.80,
            rationale: "HTTP response truncated — DPI cutting data stream.".into(),
        },
        HttpFailureCode::Http451 => DiscriminationResult {
            origin: BlockOrigin::ServerActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.95,
            rationale: "HTTP 451: legal block. Server explicitly refusing.".into(),
        },
        HttpFailureCode::RedirectForeign => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.85,
            rationale: "Redirect to foreign domain — ISP block page.".into(),
        },
        HttpFailureCode::StubPage => DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.90,
            rationale: "RKN stub page detected in response body.".into(),
        },
        HttpFailureCode::Timeout => DiscriminationResult {
            origin: BlockOrigin::Ambiguous,
            verdict: ProbeVerdict::Ambiguous,
            confidence: 0.40,
            rationale: "HTTP timeout — ambiguous, could be DPI or server issue.".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_active_alert_sniblock() {
        let result = discriminate(&TlsFailureCode::AlertSniblock, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::ServerActive);
        assert_eq!(result.verdict, ProbeVerdict::Clear);
    }

    #[test]
    fn test_path_active_reset() {
        let result = discriminate(&TlsFailureCode::Reset, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::PathActive);
        assert_eq!(result.verdict, ProbeVerdict::Blocked);
    }

    #[test]
    fn test_path_active_garbage() {
        let result = discriminate(&TlsFailureCode::Garbage, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::PathActive);
        assert_eq!(result.verdict, ProbeVerdict::Blocked);
    }

    #[test]
    fn test_tls_ok_http_cutoff() {
        let result = discriminate(&TlsFailureCode::HandshakeOk, &HttpFailureCode::Cutoff);
        assert_eq!(result.origin, BlockOrigin::PathActive);
        assert_eq!(result.verdict, ProbeVerdict::Blocked);
    }

    #[test]
    fn test_tls_ok_http_ok() {
        let result = discriminate(&TlsFailureCode::HandshakeOk, &HttpFailureCode::Ok);
        assert_eq!(result.verdict, ProbeVerdict::Clear);
    }

    #[test]
    fn test_mitm_is_clear_not_blocked() {
        // MITM = server reachable, cert substituted → Clear (ServerActive)
        let result = discriminate(&TlsFailureCode::MitmSelfSigned, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::ServerActive);
        assert_eq!(result.verdict, ProbeVerdict::Clear);
    }

    #[test]
    fn test_mitm_expired_is_clear() {
        let result = discriminate(&TlsFailureCode::MitmExpired, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::ServerActive);
        assert_eq!(result.verdict, ProbeVerdict::Clear);
    }

    #[test]
    fn test_mitm_hostname_mismatch_is_clear() {
        let result = discriminate(&TlsFailureCode::MitmHostnameMismatch, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::ServerActive);
        assert_eq!(result.verdict, ProbeVerdict::Clear);
    }

    #[test]
    fn test_silent_drop_is_blocked() {
        // SilentDrop = DPI silently dropping → Blocked
        let result = discriminate(&TlsFailureCode::SilentDrop, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::PathActive);
        assert_eq!(result.verdict, ProbeVerdict::Blocked);
    }

    #[test]
    fn test_generic_alert_is_ambiguous() {
        // Generic Alert → Ambiguous (could be server or DPI)
        let result = discriminate(&TlsFailureCode::Alert, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::Ambiguous);
        assert_eq!(result.verdict, ProbeVerdict::Ambiguous);
    }

    #[test]
    fn test_version12only_is_blocked() {
        // Version12Only = DPI attacks ClientHello → Blocked
        let result = discriminate(&TlsFailureCode::Version12Only, &HttpFailureCode::Ok);
        assert_eq!(result.origin, BlockOrigin::PathActive);
        assert_eq!(result.verdict, ProbeVerdict::Blocked);
        assert!(result.confidence >= 0.85);
    }

    #[test]
    fn test_http_451_legal() {
        let result = discriminate(&TlsFailureCode::HandshakeOk, &HttpFailureCode::Http451);
        assert_eq!(result.origin, BlockOrigin::ServerActive);
        assert_eq!(result.verdict, ProbeVerdict::Blocked);
    }

    #[test]
    fn test_serialization() {
        let result = DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.85,
            rationale: "test".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: DiscriminationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.origin, BlockOrigin::PathActive);
    }
}
