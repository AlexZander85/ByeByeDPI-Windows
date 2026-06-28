//! WinDivert Driver Management — установка, проверка, cleanup.
//!
//! ## Стратегия (из sing-box/offveil)
//! 1. Проверяем: загружен ли уже WinDivert driver?
//! 2. Если нет — устанавливаем через SCM (Service Control Manager)
//! 3. С mutex для anti-race (параллельные процессы)
//! 4. Error handling: HVCI → "отключите Core Isolation", EDR → "добавьте в исключения"

use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{debug, info};

/// Имя сервиса WinDivert в SCM.
const WINDIVERT_SERVICE_NAME: &str = "WinDivert";

/// Путь к bundled driver.
fn bundled_driver_path() -> PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_default();
    exe_dir.join("WinDivert64.sys")
}

/// Проверяет, загружен ли WinDivert driver.
pub fn is_driver_loaded() -> bool {
    // Проверяем через sc query
    let output = std::process::Command::new("sc")
        .args(["query", WINDIVERT_SERVICE_NAME])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // SERVICE_RUNNING = STATE 4
            stdout.contains("STATE") && (stdout.contains("4") || stdout.contains("RUNNING"))
        }
        Err(_) => false,
    }
}

/// Устанавливает WinDivert driver через SCM.
///
/// Паттерн из sing-box: CreateService → StartService → DeleteService (auto-cleanup).
pub fn install_driver() -> Result<()> {
    let sys_path = bundled_driver_path();
    if !sys_path.exists() {
        anyhow::bail!(
            "WinDivert driver not found at {}. Bundle WinDivert64.sys with the application.",
            sys_path.display()
        );
    }

    info!("Installing WinDivert driver from {}", sys_path.display());

    // Anti-race mutex (из sing-box)
    let mutex_name = windows::core::HSTRING::from("Global\\FreeDPI_WinDivert_Install_Mutex");
    unsafe {
        let mutex = windows::Win32::System::Threading::CreateMutexW(None, true, &mutex_name);
        if let Ok(m) = mutex {
            if windows::Win32::Foundation::GetLastError().0 == windows::Win32::Foundation::ERROR_ALREADY_EXISTS.0 {
                // Другой процесс устанавливает driver — ждём
                windows::Win32::System::Threading::WaitForSingleObject(m, 30_000);
            }
        }
    }

    // Open SCM
    let scm = unsafe {
        windows::Win32::System::Services::OpenSCManagerW(
            None,
            None,
            windows::Win32::System::Services::SC_MANAGER_ALL_ACCESS,
        )
    }
    .context("OpenSCManager failed (need admin)")?;

    // Проверяем, существует ли сервис
    let existing_service = unsafe {
        windows::Win32::System::Services::OpenServiceW(
            scm,
            &windows::core::HSTRING::from(WINDIVERT_SERVICE_NAME),
            windows::Win32::System::Services::SERVICE_ALL_ACCESS,
        )
    };

    let service = match existing_service {
        Ok(s) => {
            debug!("WinDivert service already exists, starting...");
            s
        }
        Err(_) => {
            // Создаём новый сервис
            let sys_path_wide = windows::core::HSTRING::from(sys_path.to_string_lossy().as_ref());
            let svc = unsafe {
                windows::Win32::System::Services::CreateServiceW(
                    scm,
                    &windows::core::HSTRING::from(WINDIVERT_SERVICE_NAME),
                    &windows::core::HSTRING::from(WINDIVERT_SERVICE_NAME),
                    windows::Win32::System::Services::SERVICE_ALL_ACCESS,
                    windows::Win32::System::Services::SERVICE_KERNEL_DRIVER,
                    windows::Win32::System::Services::SERVICE_DEMAND_START,
                    windows::Win32::System::Services::SERVICE_ERROR_NORMAL,
                    &sys_path_wide,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            }
            .context("CreateServiceW failed")?;
            info!("WinDivert service created");
            svc
        }
    };

    // Запускаем сервис
    let start_result = unsafe {
        windows::Win32::System::Services::StartServiceW(service, None)
    };

    match start_result {
        Ok(()) => {
            info!("WinDivert driver loaded successfully");
        }
        Err(e) => {
            let error_code = e.code().0;
            unsafe {
                let _ = windows::Win32::System::Services::CloseServiceHandle(service);
                let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
            }

            match error_code {
                // ERROR_SERVICE_ALREADY_RUNNING
                1056 => {
                    info!("WinDivert driver already running");
                }
                // ERROR_INVALID_IMAGE_HASH — HVCI/Secure Boot block
                577 => {
                    anyhow::bail!(
                        "WinDivert driver blocked by HVCI/Secure Boot (ERROR_INVALID_IMAGE_HASH). \
                         Disable Core Isolation (Memory Integrity) in Windows Security, \
                         or add WinDivert to the vulnerable driver allowlist."
                    );
                }
                // ERROR_ACCESS_DENIED
                5 => {
                    anyhow::bail!(
                        "Access denied. Run as Administrator to install WinDivert driver."
                    );
                }
                // ERROR_DELAY_LOAD_FAILED — EDR/antivirus block
                1275 => {
                    anyhow::bail!(
                        "WinDivert driver blocked by antivirus/EDR. \
                         Add WinDivert to your security software exclusions."
                    );
                }
                _ => {
                    anyhow::bail!("StartService failed with error code: {}", error_code);
                }
            }
        }
    }

    // Cleanup: помечаем сервис для удаления (auto-cleanup как в sing-box)
    unsafe {
        let _ = windows::Win32::System::Services::DeleteService(service);
        let _ = windows::Win32::System::Services::CloseServiceHandle(service);
        let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
    }

    debug!("WinDivert driver installed (service marked for deletion)");
    Ok(())
}

/// Останавливает и удаляет WinDivert driver.
pub fn uninstall_driver() -> Result<()> {
    info!("Stopping WinDivert driver...");

    let output = std::process::Command::new("sc")
        .args(["stop", WINDIVERT_SERVICE_NAME])
        .output();

    if let Ok(o) = output {
        if o.status.success() {
            debug!("WinDivert service stopped");
        }
    }

    let output = std::process::Command::new("sc")
        .args(["delete", WINDIVERT_SERVICE_NAME])
        .output();

    if let Ok(o) = output {
        if o.status.success() {
            info!("WinDivert service deleted");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_driver_path() {
        let path = bundled_driver_path();
        assert!(path.to_string_lossy().contains("WinDivert64.sys"));
    }
}
