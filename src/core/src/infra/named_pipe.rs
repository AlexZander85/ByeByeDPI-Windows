//! Named Pipes — защищённый IPC для AI агента.
//!
//! Использует Windows Named Pipes (`\\.\pipe\FreeDPI_agent`)
//! вместо HTTP REST API для взаимодействия с AI агентом.
//!
//! Преимущества над HTTP:
//! - Нет TCP port open (нет MITM вектора)
//! - Только локальные процессы могут подключиться
//! - Windows ACL контролирует доступ
//!
//! ## Статус
//! Интерфейс полностью определён. Полная реализация через Windows API
//! требует точных signatures для CreateNamedPipeW/ConnectNamedPipe
//! (windows crate v0.62 имеет отличия от v0.48).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Имя pipe для AI агента.
pub const PIPE_NAME: &str = "\\\\.\\pipe\\FreeDPI_agent";

/// Сообщение от AI агента.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipeMessage {
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "get_status")]
    GetStatus,
    #[serde(rename = "get_stats")]
    GetStats,
    #[serde(rename = "test_strategy")]
    TestStrategy { domain: String, technique: String },
}

/// Ответ на сообщение агента.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeResponse {
    pub success: bool,
    pub data: serde_json::Value,
}

/// Обработчик сообщений от AI агента.
pub trait PipeHandler: Send + Sync {
    fn handle(&self, msg: &PipeMessage) -> PipeResponse;
}

/// Сервер Named Pipe.
///
/// ## Реализация
/// Полная реализация требует точных WinAPI signatures:
/// - CreateNamedPipeW (pipe creation)
/// - ConnectNamedPipe (wait for client)
/// - ReadFile / WriteFile (communication)
/// - DisconnectNamedPipe (cleanup)
///
/// Текущая версия логирует попытку запуска.
/// Используйте HTTP API (`api/` crate) как fallback.
pub struct PipeServer {
    pipe_path: String,
}

impl PipeServer {
    pub fn new() -> Self {
        Self {
            pipe_path: PIPE_NAME.to_string(),
        }
    }

    pub fn pipe_path(&self) -> &str {
        &self.pipe_path
    }

    /// Запускает сервер (блокирующий).
    ///
    /// ## TODO
    /// Полная реализация через Windows API или `interprocess` crate v2.
    pub fn run<H: PipeHandler + Send + Sync + 'static>(self, _handler: H) -> Result<()> {
        info!(
            "Named Pipe server: {} — using HTTP API as primary interface",
            self.pipe_path
        );
        info!("For Named Pipe support, implement CreateNamedPipeW/ConnectNamedPipe");
        Ok(())
    }
}

impl Default for PipeServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler;
    impl PipeHandler for TestHandler {
        fn handle(&self, msg: &PipeMessage) -> PipeResponse {
            match msg {
                PipeMessage::Ping => PipeResponse {
                    success: true,
                    data: serde_json::json!({"pong": true}),
                },
                PipeMessage::GetStatus => PipeResponse {
                    success: true,
                    data: serde_json::json!({"status": "running"}),
                },
                PipeMessage::GetStats => PipeResponse {
                    success: true,
                    data: serde_json::json!({"packets": 0}),
                },
                PipeMessage::TestStrategy { domain, .. } => PipeResponse {
                    success: true,
                    data: serde_json::json!({"domain": domain}),
                },
            }
        }
    }

    #[test]
    fn test_pipe_message_serialization() {
        let msg = PipeMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ping"));

        let msg = PipeMessage::TestStrategy {
            domain: "example.com".into(),
            technique: "FakeSni".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_pipe_handler() {
        let handler = TestHandler;
        let resp = handler.handle(&PipeMessage::Ping);
        assert!(resp.success);
        assert_eq!(resp.data["pong"], true);
    }
}
