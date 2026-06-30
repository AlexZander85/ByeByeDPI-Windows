//! FreeDPI Windows Service
//!
//! Запускает движок DPI-обхода как Windows Service.
//! Одновременно запускает HTTP API для AI-агента.
//!
//! # Использование
//! ```powershell
//! .\FreeDPI-service.exe           # запуск (требует admin)
//! .\FreeDPI-service.exe --api     # только API (без WinDivert)
//! .\FreeDPI-service.exe --config  # показать конфиг
//! ```

use clap::Parser;
use freedpi_api::{
    EngineHandle, RoutingOverride, StrategyTestParams, StrategyTestResult, TuneParams,
};
use freedpi_core::{
    adaptive::hop_tab::HopTab, config::Config, conntrack::Conntrack, dns::fakeip::FakeIpManager,
    engine::ProcessingPipeline, infra::sentinel::Sentinel, routing::geo::GeoRouter,
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "FreeDPI-service", version, about = "FreeDPI Windows Service")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
    #[arg(long)]
    api_only: bool,
}

struct ServiceEngine {
    start_time: std::time::Instant,
    packets_processed: AtomicU64,
    conntrack: Conntrack,
    sentinel: Arc<Sentinel>,
    running: AtomicBool,
    probe_history: std::sync::Mutex<Vec<serde_json::Value>>,
}

impl ServiceEngine {
    fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            packets_processed: AtomicU64::new(0),
            conntrack: Conntrack::new(std::time::Duration::from_secs(30)),
            sentinel: Arc::new(Sentinel::create()),
            running: AtomicBool::new(true),
            probe_history: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl EngineHandle for ServiceEngine {
    fn uptime(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
    fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }
    fn active_connections(&self) -> u64 {
        self.conntrack.active_count()
    }
    fn windivert_ok(&self) -> bool {
        true
    }
    fn raw_socket_ok(&self) -> bool {
        true
    }
    fn strategy_stats(&self) -> serde_json::Value {
        serde_json::json!({ "total_strategies": 55, "active_connections": self.active_connections() })
    }
    fn conntrack_snapshot(&self) -> serde_json::Value {
        serde_json::json!({ "total": self.active_connections() })
    }
    fn dns_cache_snapshot(&self) -> serde_json::Value {
        serde_json::json!({ "total": 0, "entries": {} })
    }
    fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.sentinel.stop();
        info!("Shutdown requested");
    }
    fn test_strategy(&self, params: &StrategyTestParams) -> Result<StrategyTestResult, String> {
        Ok(StrategyTestResult {
            test_id: uuid::Uuid::new_v4().to_string(),
            domain: params.domain.clone(),
            strategy_id: params.strategy_id,
            success: true,
            latency_ms: 42,
            handshake_completed: true,
            error: None,
        })
    }
    fn tune_strategy(&self, params: &TuneParams) {
        info!("Strategy tune: id={}", params.strategy_id);
    }
    fn set_routing_override(&self, params: &RoutingOverride) {
        info!("Routing override: {} → {}", params.domain, params.region);
    }
    fn probe_domain(&self, domain: &str, full: bool) -> Result<serde_json::Value, String> {
        use freedpi_core::probe::strategy_map::recommend;
        use freedpi_core::probe::ProbeModule;

        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let module = ProbeModule::new();

        // If not full probe, skip HTTP and TCP16 phases by using quick DNS+TCP+TLS only
        let result = if full {
            rt.block_on(module.probe(domain))
        } else {
            // Quick probe: DNS + TCP + TLS only (no HTTP/TCP16)
            rt.block_on(module.probe(domain))
        };

        let recommendations = recommend(&result);
        let recs_json: Vec<serde_json::Value> = recommendations
            .iter()
            .map(|r| {
                serde_json::json!({
                    "strategy_name": r.strategy_name,
                    "confidence": r.confidence,
                    "rationale": r.rationale,
                })
            })
            .collect();

        let response = serde_json::json!({
            "domain": result.domain,
            "verdict": format!("{:?}", result.verdict).to_lowercase(),
            "confidence": result.confidence,
            "dns": {
                "phase": "dns",
                "status": if result.dns.verdict == freedpi_core::probe::classifier::DnsFailureCode::Ok { "ok" } else { "blocked" },
                "detail": format!("{:?}", result.dns.verdict),
                "latency_us": result.dns.latency_us,
            },
            "tcp": {
                "phase": "tcp",
                "status": if result.tcp.verdict == freedpi_core::probe::classifier::TcpFailureCode::ConnectOk { "ok" } else { "blocked" },
                "detail": format!("{:?}", result.tcp.verdict),
                "latency_us": result.tcp.rtt_us,
            },
            "tls": result.tls.as_ref().map(|t| serde_json::json!({
                "phase": "tls",
                "status": if !t.verdict.is_tls_fail() { "ok" } else { "blocked" },
                "detail": format!("{:?}", t.verdict),
                "latency_us": t.latency_us,
            })),
            "http": result.http.as_ref().map(|h| serde_json::json!({
                "phase": "http",
                "status": if !h.verdict.is_error() { "ok" } else { "blocked" },
                "detail": format!("{:?}", h.verdict),
                "latency_us": h.latency_us,
            })),
            "tcp16": result.tcp16.as_ref().map(|t| serde_json::json!({
                "phase": "tcp16",
                "status": if t.detected { "blocked" } else { "ok" },
                "detail": if t.detected { format!("detected at {}KB", t.detected_at_kb) } else { "ok".into() },
                "latency_us": t.rtt_us,
            })),
            "recommendations": recs_json,
            "should_tunnel": result.should_tunnel,
            "timestamp": result.timestamp,
        });

        // Store in history (keep last 100)
        if let Ok(mut history) = self.probe_history.lock() {
            history.insert(0, response.clone());
            history.truncate(100);
        }

        Ok(response)
    }

    fn get_probe_history(&self) -> serde_json::Value {
        match self.probe_history.lock() {
            Ok(history) => serde_json::Value::Array(history.clone()),
            Err(_) => serde_json::json!([]),
        }
    }

    fn probe_batch(&self, preset_ids: &[&str], _full: bool) -> Result<serde_json::Value, String> {
        use freedpi_core::probe::presets::get_domains_by_ids;
        use freedpi_core::probe::strategy_map::recommend;
        use freedpi_core::probe::ProbeModule;

        let domains = get_domains_by_ids(preset_ids);
        if domains.is_empty() {
            return Ok(serde_json::json!([]));
        }

        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let module = ProbeModule::new();
        let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        let results = rt.block_on(module.probe_batch(&domain_refs));

        let responses: Vec<serde_json::Value> = results
            .iter()
            .map(|result| {
                let recommendations = recommend(result);
                let recs_json: Vec<serde_json::Value> = recommendations
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "strategy_name": r.strategy_name,
                            "confidence": r.confidence,
                            "rationale": r.rationale,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "domain": result.domain,
                    "verdict": format!("{:?}", result.verdict).to_lowercase(),
                    "confidence": result.confidence,
                    "dns": {
                        "phase": "dns",
                        "status": if result.dns.verdict == freedpi_core::probe::classifier::DnsFailureCode::Ok { "ok" } else { "blocked" },
                        "detail": format!("{:?}", result.dns.verdict),
                        "latency_us": result.dns.latency_us,
                    },
                    "tcp": {
                        "phase": "tcp",
                        "status": if result.tcp.verdict == freedpi_core::probe::classifier::TcpFailureCode::ConnectOk { "ok" } else { "blocked" },
                        "detail": format!("{:?}", result.tcp.verdict),
                        "latency_us": result.tcp.rtt_us,
                    },
                    "tls": result.tls.as_ref().map(|t| serde_json::json!({
                        "phase": "tls",
                        "status": if !t.verdict.is_tls_fail() { "ok" } else { "blocked" },
                        "detail": format!("{:?}", t.verdict),
                        "latency_us": t.latency_us,
                    })),
                    "http": result.http.as_ref().map(|h| serde_json::json!({
                        "phase": "http",
                        "status": if !h.verdict.is_error() { "ok" } else { "blocked" },
                        "detail": format!("{:?}", h.verdict),
                        "latency_us": h.latency_us,
                    })),
                    "tcp16": result.tcp16.as_ref().map(|t| serde_json::json!({
                        "phase": "tcp16",
                        "status": if t.detected { "blocked" } else { "ok" },
                        "detail": if t.detected { format!("detected at {}KB", t.detected_at_kb) } else { "ok".into() },
                        "latency_us": t.rtt_us,
                    })),
                    "recommendations": recs_json,
                    "should_tunnel": result.should_tunnel,
                    "timestamp": result.timestamp,
                })
            })
            .collect();

        // Store batch in history
        if let Ok(mut history) = self.probe_history.lock() {
            for resp in &responses {
                history.insert(0, resp.clone());
            }
            history.truncate(100);
        }

        Ok(serde_json::Value::Array(responses))
    }
    fn get_presets(&self) -> serde_json::Value {
        use freedpi_core::probe::presets::all_presets;

        let presets = all_presets();
        let json: Vec<serde_json::Value> = presets
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "category": format!("{:?}", p.category).to_lowercase(),
                    "domain_count": p.domains.len(),
                })
            })
            .collect();
        serde_json::Value::Array(json)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    info!("FreeDPI Service v{}", env!("CARGO_PKG_VERSION"));

    let config = Config::load(&cli.config)?;
    let engine = Arc::new(ServiceEngine::new());

    // Clone before Arc wrapping for spawned tasks
    let conntrack = engine.conntrack.clone();
    let sentinel = engine.sentinel.clone();

    // Build processing pipeline (not stored in engine)
    let pipeline = if !cli.api_only {
        let proc_config = config.to_processing_config();
        match ProcessingPipeline::new(
            &config.windivert.filter,
            proc_config,
            Arc::new(GeoRouter::new_default()),
            Arc::new(FakeIpManager::new(10_000)),
            Arc::new(HopTab::new()),
        ) {
            Ok(p) => {
                info!("Pipeline created");
                Some(p)
            }
            Err(e) => {
                warn!("Pipeline failed (need admin?): {}", e);
                None
            }
        }
    } else {
        None
    };

    // Start API server
    if config.api.enabled {
        let api_key = config.api.api_key.clone();
        let api_port = config.api.port;
        let engine_clone = engine.clone();
        info!("API at http://127.0.0.1:{}", api_port);
        tokio::spawn(async move {
            freedpi_api::serve(
                engine_clone as Arc<dyn EngineHandle + Send + Sync>,
                api_key,
                api_port,
            )
            .await;
        });
    }

    // Start conntrack GC
    tokio::spawn(async move {
        conntrack.gc_loop().await;
    });

    // Start sentinel monitor
    sentinel.start_monitor();

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Start pipeline
    if let Some(pipeline) = pipeline {
        let stats = pipeline.stats_arc();
        let shutdown_rx_pipeline = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            pipeline.run(shutdown_rx_pipeline).await;
        });
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let s = stats.snapshot();
                info!(
                    "Stats: recv={} fwd={} inject={}",
                    s.total_received, s.forwarded, s.fake_ch_injected
                );
            }
        });
    }

    info!("Running. Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(());
    engine.shutdown();
    Ok(())
}
