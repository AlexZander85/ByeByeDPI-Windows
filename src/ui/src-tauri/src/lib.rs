mod commands;
mod tray;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_health,
            commands::get_conntrack,
            commands::get_config,
            commands::save_config,
            commands::run_probe,
            commands::get_probe_presets,
            commands::get_probe_history,
            commands::run_batch_probe,
            commands::get_custom_lists,
            commands::save_custom_list,
            commands::delete_custom_list,
            commands::import_domains_from_text,
        ])
        .setup(|app| {
            tray::setup_tray(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
