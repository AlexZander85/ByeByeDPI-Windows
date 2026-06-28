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
