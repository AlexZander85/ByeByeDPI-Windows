use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub packets_processed: u64,
    pub active_connections: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub healthy: bool,
    pub windivert_ok: bool,
    pub raw_socket_ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub domain: String,
    pub verdict: String,
    pub confidence: f64,
    pub dns: PhaseResult,
    pub tcp: PhaseResult,
    pub tls: Option<PhaseResult>,
    pub http: Option<PhaseResult>,
    pub recommendations: Vec<Recommendation>,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PhaseResult {
    pub phase: String,
    pub status: String,
    pub detail: String,
    pub latency_us: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Recommendation {
    pub strategy_name: String,
    pub confidence: f64,
    pub rationale: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresetList {
    pub id: String,
    pub name: String,
    pub category: String,
    pub domain_count: usize,
}

#[tauri::command]
pub async fn get_status(api_port: Option<u16>) -> Result<StatusResponse, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/status", port);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    resp.json::<StatusResponse>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn get_health(api_port: Option<u16>) -> Result<HealthResponse, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/health", port);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    resp.json::<HealthResponse>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn get_conntrack(api_port: Option<u16>) -> Result<serde_json::Value, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/conntrack", port);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn get_config() -> Result<serde_json::Value, String> {
    let config_path = dirs::config_dir()
        .unwrap_or_default()
        .join("FreeDPI")
        .join("config.toml");

    if !config_path.exists() {
        return Ok(serde_json::json!({}));
    }

    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("Read error: {}", e))?;

    // Simple TOML to JSON conversion for the UI
    Ok(serde_json::json!({ "raw": content }))
}

#[tauri::command]
pub async fn save_config(raw: String) -> Result<(), String> {
    let config_path = dirs::config_dir()
        .unwrap_or_default()
        .join("FreeDPI")
        .join("config.toml");

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Create dir error: {}", e))?;
    }

    std::fs::write(&config_path, &raw)
        .map_err(|e| format!("Write error: {}", e))
}

#[tauri::command]
pub async fn run_probe(domain: String, full: bool, api_port: Option<u16>) -> Result<ProbeResponse, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe", port);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "domain": domain, "full": full }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Probe request failed: {}", e))?;

    resp.json::<ProbeResponse>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn get_probe_presets(api_port: Option<u16>) -> Result<Vec<PresetList>, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe/presets", port);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    resp.json::<Vec<PresetList>>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn get_probe_history(api_port: Option<u16>) -> Result<Vec<ProbeResponse>, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe/history", port);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    resp.json::<Vec<ProbeResponse>>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn run_batch_probe(
    preset_ids: Vec<String>,
    full: bool,
    api_port: Option<u16>,
) -> Result<Vec<ProbeResponse>, String> {
    let port = api_port.unwrap_or(11337);
    let url = format!("http://127.0.0.1:{}/api/v1/probe/batch", port);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "preset_ids": preset_ids, "full": full }))
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| format!("Batch probe request failed: {}", e))?;

    resp.json::<Vec<ProbeResponse>>()
        .await
        .map_err(|e| format!("Parse error: {}", e))
}

// ─── Custom Domain Lists ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomDomainList {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn custom_lists_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_default()
        .join("FreeDPI")
        .join("custom_probe_lists.json")
}

#[tauri::command]
pub async fn get_custom_lists() -> Result<Vec<CustomDomainList>, String> {
    let path = custom_lists_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = std::fs::read_to_string(&path).map_err(|e| format!("Read error: {}", e))?;
    serde_json::from_str(&data).map_err(|e| format!("Parse error: {}", e))
}

#[tauri::command]
pub async fn save_custom_list(list: CustomDomainList) -> Result<(), String> {
    let path = custom_lists_path();
    let mut lists = get_custom_lists().await.unwrap_or_default();

    if let Some(idx) = lists.iter().position(|l| l.id == list.id) {
        lists[idx] = list;
    } else {
        lists.push(list);
    }

    let data =
        serde_json::to_string_pretty(&lists).map_err(|e| format!("Serialize error: {}", e))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, data).map_err(|e| format!("Write error: {}", e))
}

#[tauri::command]
pub async fn delete_custom_list(id: String) -> Result<(), String> {
    let path = custom_lists_path();
    let mut lists = get_custom_lists().await.unwrap_or_default();
    lists.retain(|l| l.id != id);

    let data =
        serde_json::to_string_pretty(&lists).map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, data).map_err(|e| format!("Write error: {}", e))
}

#[tauri::command]
pub async fn import_domains_from_text(text: String) -> Result<Vec<String>, String> {
    Ok(text
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}
