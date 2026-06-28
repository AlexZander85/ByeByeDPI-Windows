//! HTTP API для AI-агента.
//!
//! Предоставляет REST API для тестирования стратегий, fine-tuning параметров
//! и мониторинга состояния движка. Слушает ТОЛЬКО localhost:11337.
//!
//! # Аутентификация
//! Все запросы требуют заголовок `X-API-Key: <key>`.
//!
//! # Эндпоинты
//! - `GET /api/v1/status` — статус движка
//! - `POST /api/v1/strategies/test` — тест стратегии
//! - `GET /api/v1/strategies/stats` — статистика стратегий
//! - `POST /api/v1/strategies/tune` — изменение параметров
//! - `GET /api/v1/conntrack` — активные соединения
//! - `GET /api/v1/dns/cache` — DNS кэш
//! - `POST /api/v1/routing/override` — override маршрута
//! - `GET /api/v1/health` — health check

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

// ─── Типы данных ───────────────────────────────────────────────────────────

/// Состояние API, разделяемое между эндпоинтами.
pub struct ApiState {
    pub engine: Arc<dyn EngineHandle + Send + Sync>,
    pub api_key: String,
}

/// Хендл к движку (core).
///
/// Предоставляет методы, необходимые API.
/// Реализуется в service-крейте.
pub trait EngineHandle {
    fn uptime(&self) -> u64;
    fn packets_processed(&self) -> u64;
    fn active_connections(&self) -> u64;
    fn windivert_ok(&self) -> bool;
    fn raw_socket_ok(&self) -> bool;
    fn strategy_stats(&self) -> serde_json::Value;
    fn conntrack_snapshot(&self) -> serde_json::Value;
    fn dns_cache_snapshot(&self) -> serde_json::Value;
    fn shutdown(&self);
    fn test_strategy(&self, params: &StrategyTestParams) -> Result<StrategyTestResult, String>;
    fn tune_strategy(&self, params: &TuneParams);
    fn set_routing_override(&self, params: &RoutingOverride);
}

// ─── Request/Response типы ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StrategyTestParams {
    pub domain: String,
    pub strategy_id: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    pub params: Option<serde_json::Value>,
}

fn default_timeout() -> u64 {
    5000
}

#[derive(Debug, Serialize)]
pub struct StrategyTestResult {
    pub test_id: String,
    pub domain: String,
    pub strategy_id: u32,
    pub success: bool,
    pub latency_ms: u64,
    pub handshake_completed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TuneParams {
    pub strategy_id: u32,
    pub params: serde_json::Value,
    #[serde(default)]
    pub persist: bool,
}

#[derive(Debug, Deserialize)]
pub struct RoutingOverride {
    pub domain: String,
    pub region: String,
    #[serde(default = "default_ttl")]
    pub ttl_minutes: u64,
}

fn default_ttl() -> u64 {
    60
}

// ─── API Server ────────────────────────────────────────────────────────────

/// Запускает HTTP API сервер.
///
/// Слушает на `127.0.0.1:{port}`. Все эндпоинты требуют `X-API-Key`.
pub async fn serve(engine: Arc<dyn EngineHandle + Send + Sync>, api_key: String, port: u16) {
    let state = Arc::new(ApiState { engine, api_key });

    let app = Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/strategies/test", post(test_strategy_handler))
        .route("/api/v1/strategies/stats", get(strategy_stats_handler))
        .route("/api/v1/strategies/tune", post(tune_strategy_handler))
        .route("/api/v1/conntrack", get(conntrack_handler))
        .route("/api/v1/dns/cache", get(dns_cache_handler))
        .route("/api/v1/routing/override", post(routing_override_handler))
        .route("/api/v1/health", get(health_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("API server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ─── Auth Middleware ───────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if key == state.api_key {
        Ok(next.run(req).await)
    } else {
        warn!("API auth failed: invalid key");
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ─── Handlers ──────────────────────────────────────────────────────────────

/// `GET /api/v1/status` — статус движка.
async fn status_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.engine.uptime(),
        "packets_processed": state.engine.packets_processed(),
        "active_connections": state.engine.active_connections(),
        "api_port": 11337,
    }))
}

/// `POST /api/v1/strategies/test` — тестирование стратегии.
async fn test_strategy_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<StrategyTestParams>,
) -> impl IntoResponse {
    match state.engine.test_strategy(&params) {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap())),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": e
            })),
        ),
    }
}

/// `GET /api/v1/strategies/stats` — статистика стратегий.
async fn strategy_stats_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.strategy_stats())
}

/// `POST /api/v1/strategies/tune` — настройка стратегии.
async fn tune_strategy_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<TuneParams>,
) -> impl IntoResponse {
    state.engine.tune_strategy(&params);
    Json(serde_json::json!({
        "tuned": true,
        "strategy_id": params.strategy_id,
    }))
}

/// `GET /api/v1/conntrack` — список активных соединений.
async fn conntrack_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.conntrack_snapshot())
}

/// `GET /api/v1/dns/cache` — содержимое DNS кэша.
async fn dns_cache_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(state.engine.dns_cache_snapshot())
}

/// `POST /api/v1/routing/override` — override маршрута для домена.
async fn routing_override_handler(
    State(state): State<Arc<ApiState>>,
    Json(params): Json<RoutingOverride>,
) -> impl IntoResponse {
    state.engine.set_routing_override(&params);
    Json(serde_json::json!({
        "overridden": true,
        "domain": params.domain,
        "region": params.region,
    }))
}

/// `GET /api/v1/health` — health check.
async fn health_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "healthy": true,
        "windivert_ok": state.engine.windivert_ok(),
        "raw_socket_ok": state.engine.raw_socket_ok(),
        "uptime_seconds": state.engine.uptime(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEngine;

    impl EngineHandle for MockEngine {
        fn uptime(&self) -> u64 {
            3600
        }
        fn packets_processed(&self) -> u64 {
            1000000
        }
        fn active_connections(&self) -> u64 {
            342
        }
        fn windivert_ok(&self) -> bool {
            true
        }
        fn raw_socket_ok(&self) -> bool {
            true
        }
        fn strategy_stats(&self) -> serde_json::Value {
            serde_json::json!({"total": 106, "active": 42})
        }
        fn conntrack_snapshot(&self) -> serde_json::Value {
            serde_json::json!({"total": 342, "entries": []})
        }
        fn dns_cache_snapshot(&self) -> serde_json::Value {
            serde_json::json!({"total": 150, "entries": {}})
        }
        fn shutdown(&self) {}
        fn test_strategy(
            &self,
            _params: &StrategyTestParams,
        ) -> Result<StrategyTestResult, String> {
            Ok(StrategyTestResult {
                test_id: "test-1".to_string(),
                domain: "example.com".to_string(),
                strategy_id: 42,
                success: true,
                latency_ms: 120,
                handshake_completed: true,
                error: None,
            })
        }
        fn tune_strategy(&self, _params: &TuneParams) {}
        fn set_routing_override(&self, _params: &RoutingOverride) {}
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let engine = Arc::new(MockEngine);
        let state = Arc::new(ApiState {
            engine,
            api_key: "test-key".to_string(),
        });

        let response = status_handler(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_strategy_test_params() {
        let json = serde_json::json!({
            "domain": "example.com",
            "strategy_id": 42,
            "timeout_ms": 3000,
        });
        let params: StrategyTestParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.domain, "example.com");
        assert_eq!(params.strategy_id, 42);
        assert_eq!(params.timeout_ms, 3000);
    }
}
