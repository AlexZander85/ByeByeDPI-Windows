//! Classifier — централизованный классификатор ошибок DPI-блокировок.
//!
//! Каждый FailureCode содержит категорию (Dns/Tcp/Tls/Http), confidence level
//! и описание. Используется для определения типа блокировки и рекомендации
//! стратегии desync.

use serde::{Deserialize, Serialize};

/// Вердикт probe'а: заблокировано, доступно или неоднозначно.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeVerdict {
    /// Сервер доступен, DPI не блокирует
    Clear,
    /// DPI блокирует соединение
    Blocked,
    /// Неоднозначно, нужен re-probe
    Ambiguous,
}

impl ProbeVerdict {
    /// Определить вердикт по комбинации фаз.
    pub fn from_phases(dns: &DnsFailureCode, tcp: &TcpFailureCode) -> Self {
        match (dns, tcp) {
            // DNS работает + TCP подключился → проверяем дальше (TCP phase не финальный)
            (DnsFailureCode::Ok, TcpFailureCode::ConnectOk) => Self::Ambiguous,
            // DNS отравлен — это блокировка на уровне DNS
            (DnsFailureCode::Poisoned, _) => Self::Blocked,
            (DnsFailureCode::NxdomainSpoof, _) => Self::Blocked,
            (DnsFailureCode::EmptySpoof, _) => Self::Blocked,
            (DnsFailureCode::Intercepted, _) => Self::Blocked,
            (DnsFailureCode::DohBlocked, _) => Self::Blocked,
            // DNS не резолвит — может быть блокировка или ошибка сервера
            (DnsFailureCode::Unresolvable, _) => Self::Ambiguous,
            // TCP RST/timeout/refused — это блокировка
            (_, TcpFailureCode::Reset) => Self::Blocked,
            (_, TcpFailureCode::Timeout) => Self::Blocked,
            (_, TcpFailureCode::Refused) => Self::Ambiguous,
            (_, TcpFailureCode::Unreachable) => Self::Ambiguous,
            // Data-volume cutoff — DPI обрывает на N КБ
            (_, TcpFailureCode::DataVolumeCut) => Self::Blocked,
        }
    }
}

/// Типы DNS-блокировок.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFailureCode {
    /// UDP возвращает другие IP чем DoH (DNS poisoning)
    Poisoned,
    /// UDP NXDOMAIN, DoH резолвит (NXDOMAIN spoof)
    NxdomainSpoof,
    /// UDP пустой ответ, DoH резолвит (empty spoof)
    EmptySpoof,
    /// UDP timeout, DoH работает (DNS interception)
    Intercepted,
    /// Все DoH недоступны (DoH blocked)
    DohBlocked,
    /// Ни UDP, ни DoH не резолвит (unresolvable)
    Unresolvable,
    /// DNS работает корректно
    Ok,
}

impl DnsFailureCode {
    /// Является ли это ошибкой (не OK).
    pub fn is_error(&self) -> bool {
        *self != DnsFailureCode::Ok
    }

    /// Описание на русском.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Poisoned => "DNS poisoned — UDP возвращает другие IP чем DoH",
            Self::NxdomainSpoof => "NXDOMAIN spoof — UDP NXDOMAIN, DoH работает",
            Self::EmptySpoof => "Empty spoof — UDP пустой ответ, DoH работает",
            Self::Intercepted => "DNS intercepted — UDP timeout, DoH работает",
            Self::DohBlocked => "DoH blocked — все DoH недоступны",
            Self::Unresolvable => "Unresolvable — ни UDP, ни DoH не резолвит",
            Self::Ok => "DNS OK",
        }
    }
}

/// Типы TCP-блокировок.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpFailureCode {
    /// TCP handshake прошёл успешно
    ConnectOk,
    /// ConnectionResetError (TCP RST injection)
    Reset,
    /// socket.timeout (SYN drop или timeout)
    Timeout,
    /// ConnectionRefusedError
    Refused,
    /// ICMP unreachable
    Unreachable,
    /// Связь обрывается на N КБ (data-volume detection)
    DataVolumeCut,
}

impl TcpFailureCode {
    pub fn is_error(&self) -> bool {
        *self != TcpFailureCode::ConnectOk
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::ConnectOk => "TCP connect OK",
            Self::Reset => "TCP RST injection",
            Self::Timeout => "TCP timeout (SYN drop?)",
            Self::Refused => "Connection refused",
            Self::Unreachable => "ICMP unreachable",
            Self::DataVolumeCut => "Data-volume cut: connection drops at N KB",
        }
    }
}

/// Типы TLS-блокировок.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsFailureCode {
    /// TLS handshake прошёл
    HandshakeOk,
    /// TLS 1.3 работает
    Version13Ok,
    /// TLS 1.3 fail, 1.2 ok — ClientHello DPI
    Version12Only,
    /// RST во время TLS handshake
    Reset,
    /// Wrong version / record overflow / decode error
    Garbage,
    /// Fake TLS alert
    Alert,
    /// TLS alert: unrecognized_name (SNI block)
    AlertSniblock,
    /// TLS alert: handshake_failure
    AlertHandshake,
    /// TLS alert: protocol_version
    AlertProtocol,
    /// Сертификат подменён (expired/self-signed/mismatch)
    Mitm,
    /// Certificate expired
    MitmExpired,
    /// Self-signed certificate
    MitmSelfSigned,
    /// Hostname mismatch
    MitmHostnameMismatch,
    /// Unexpected EOF (partial data)
    Eof,
    /// TLS hang до timeout (TCP ok, TLS timeout)
    SilentDrop,
}

impl TlsFailureCode {
    pub fn is_error(&self) -> bool {
        !matches!(
            self,
            Self::HandshakeOk | Self::Version13Ok | Self::Version12Only
        )
    }

    pub fn is_tls_fail(&self) -> bool {
        !matches!(
            self,
            Self::HandshakeOk | Self::Version13Ok | Self::Version12Only
        )
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HandshakeOk => "TLS handshake OK",
            Self::Version13Ok => "TLS 1.3 OK",
            Self::Version12Only => "TLS 1.3 blocked, 1.2 works (ClientHello DPI!)",
            Self::Reset => "TLS RST injection",
            Self::Garbage => "TLS garbage injection",
            Self::Alert => "Fake TLS alert",
            Self::AlertSniblock => "TLS alert: SNI block",
            Self::AlertHandshake => "TLS alert: handshake_failure",
            Self::AlertProtocol => "TLS alert: protocol_version",
            Self::Mitm => "TLS MITM: certificate substitution",
            Self::MitmExpired => "TLS MITM: certificate expired",
            Self::MitmSelfSigned => "TLS MITM: self-signed certificate",
            Self::MitmHostnameMismatch => "TLS MITM: hostname mismatch",
            Self::Eof => "TLS EOF: unexpected disconnect",
            Self::SilentDrop => "TLS silent drop: hang until timeout",
        }
    }
}

/// Типы HTTP-блокировок.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFailureCode {
    /// HTTP 200 OK
    Ok,
    /// Response обрезан (данные оборваны)
    Cutoff,
    /// HTTP 451 legal block
    Http451,
    /// Редирект на тот же домен (нормально)
    RedirectSame,
    /// Редирект на чужой домен (ISP page)
    RedirectForeign,
    /// HTTP timeout
    Timeout,
    /// RKN-заглушка в HTML
    StubPage,
}

impl HttpFailureCode {
    pub fn is_error(&self) -> bool {
        !matches!(self, Self::Ok | Self::RedirectSame)
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Ok => "HTTP OK",
            Self::Cutoff => "HTTP cutoff: response truncated",
            Self::Http451 => "HTTP 451: legal block",
            Self::RedirectSame => "HTTP redirect: same domain (ok)",
            Self::RedirectForeign => "HTTP redirect: foreign domain (ISP page)",
            Self::Timeout => "HTTP timeout",
            Self::StubPage => "HTTP stub page: RKN block page detected",
        }
    }
}

/// Этап TCP/TLS соединения (stage tracking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStage {
    /// TCP connect (SYN phase)
    TcpConnect,
    /// SYN-ACK получен
    TcpConnected,
    /// ClientHello отправлен, ожидаем ServerHello
    TlsHandshake,
    /// TLS handshake завершён
    TlsConnected,
    /// HTTP request отправляется
    SendingData,
    /// HTTP response читается
    ReadingData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_verdict_from_phases() {
        assert_eq!(
            ProbeVerdict::from_phases(&DnsFailureCode::Ok, &TcpFailureCode::ConnectOk),
            ProbeVerdict::Ambiguous // needs TLS/HTTP phases
        );
        assert_eq!(
            ProbeVerdict::from_phases(&DnsFailureCode::Poisoned, &TcpFailureCode::ConnectOk),
            ProbeVerdict::Blocked
        );
        assert_eq!(
            ProbeVerdict::from_phases(&DnsFailureCode::Ok, &TcpFailureCode::Reset),
            ProbeVerdict::Blocked
        );
        assert_eq!(
            ProbeVerdict::from_phases(&DnsFailureCode::Ok, &TcpFailureCode::Timeout),
            ProbeVerdict::Blocked
        );
    }

    #[test]
    fn test_dns_failure_description() {
        assert!(!DnsFailureCode::Poisoned.description().is_empty());
        assert_eq!(DnsFailureCode::Ok.description(), "DNS OK");
    }

    #[test]
    fn test_tcp_failure_is_error() {
        assert!(!TcpFailureCode::ConnectOk.is_error());
        assert!(TcpFailureCode::Reset.is_error());
        assert!(TcpFailureCode::Timeout.is_error());
    }

    #[test]
    fn test_tls_failure_is_tls_fail() {
        assert!(!TlsFailureCode::HandshakeOk.is_tls_fail());
        assert!(!TlsFailureCode::Version13Ok.is_tls_fail());
        assert!(!TlsFailureCode::Version12Only.is_tls_fail()); // it's a split, not a fail
        assert!(TlsFailureCode::Reset.is_tls_fail());
        assert!(TlsFailureCode::Garbage.is_tls_fail());
    }

    #[test]
    fn test_http_failure_is_error() {
        assert!(!HttpFailureCode::Ok.is_error());
        assert!(!HttpFailureCode::RedirectSame.is_error());
        assert!(HttpFailureCode::Cutoff.is_error());
        assert!(HttpFailureCode::Http451.is_error());
        assert!(HttpFailureCode::StubPage.is_error());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let code = DnsFailureCode::Poisoned;
        let json = serde_json::to_string(&code).unwrap();
        let back: DnsFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}
