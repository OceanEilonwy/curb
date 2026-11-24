use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use curb_core::auth::hash_password;
use curb_core::config::EnforcementMode;
use curb_core::store::{default_data_dir, load_auth, load_config, save_auth, save_config};

#[derive(Debug, Parser)]
#[command(
    name = "curb-cli",
    about = "Elevated Windows Administrator management & recovery tool for Curb"
)]
struct Cli {
    /// Override Curb data directory (defaults to C:\ProgramData\Curb on Windows).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Show current Curb enforcement mode, rule count, and password status.
    Status,
    /// Set or reset the Curb admin password (requires Windows Administrator access to ProgramData).
    #[command(alias = "reset-password", alias = "change-password")]
    SetPassword {
        /// Optional password value (if omitted, prompts interactively with confirmation).
        #[arg(long)]
        password: Option<String>,
    },
    /// Emergency recovery: disables Curb enforcement so full network access is restored.
    EmergencyDisable,
    /// Re-enables default-deny enforcement.
    Enable,
    /// Register CurbService with the Windows Service Control Manager (LocalSystem, auto-start).
    Install {
        /// Path to curb-service.exe (defaults to sibling of curb-cli.exe).
        #[arg(long)]
        service_bin: Option<PathBuf>,
        /// Optional Standard Mode data directory to migrate config.json and auth.json from.
        #[arg(long)]
        migrate_from: Option<PathBuf>,
        /// Reset existing Curb configuration, rules, password, and DNS backup before starting.
        #[arg(long)]
        reset: bool,
    },
    /// Reset Curb configuration, rules, password, WFP filters, and DNS backups for a clean start.
    Reset,
    /// Stop and unregister CurbService from Windows SCM.
    Uninstall,
}

fn main() {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(default_data_dir);

    match cli.command {
        Commands::Status => {
            let cfg = load_config(&data_dir).unwrap_or_default();
            let auth = load_auth(&data_dir).ok().flatten();
            println!("Curb Data Dir : {}", data_dir.display());
            println!("Mode          : {:?}", cfg.mode);
            println!(
                "Steam Preset  : {}",
                if cfg.presets.steam.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("Custom Rules  : {}", cfg.rules.len());
            println!(
                "Admin Password: {}",
                if auth.is_some() {
                    "configured"
                } else {
                    "not set"
                }
            );
        }

        Commands::SetPassword { password } => {
            let pwd = match password {
                Some(p) => p,
                None => {
                    print!("Enter new Curb admin password: ");
                    let _ = io::stdout().flush();
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).expect("read password");
                    let first = input.trim().to_string();

                    print!("Confirm new Curb admin password: ");
                    let _ = io::stdout().flush();
                    let mut confirm = String::new();
                    io::stdin().read_line(&mut confirm).expect("read confirm");
                    if first != confirm.trim() {
                        eprintln!("Error: Passwords do not match.");
                        std::process::exit(1);
                    }
                    first
                }
            };
            match hash_password(&pwd).and_then(|rec| save_auth(&data_dir, &rec)) {
                Ok(()) => println!("Curb admin password updated successfully."),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::EmergencyDisable => {
            let mut cfg = load_config(&data_dir).unwrap_or_default();
            cfg.mode = EnforcementMode::Disabled;
            if let Err(e) = save_config(&data_dir, &cfg) {
                eprintln!("Failed to update config: {e}");
                std::process::exit(1);
            }
            #[cfg(windows)]
            {
                let _ = win_scm::stop_service_if_running();
            }
            match curb_core::cleanup::purge_all_curb_wfp_objects() {
                Ok(n) => println!("Removed {n} Curb WFP firewall filters."),
                Err(e) => eprintln!("Warning: WFP cleanup reported: {e}"),
            }
            if let Err(e) = curb_core::cleanup::restore_adapter_dns_clean(&data_dir) {
                eprintln!("Warning: DNS restore reported: {e}");
            }
            println!("Curb disabled and network settings restored.");
        }

        Commands::Enable => {
            let mut cfg = load_config(&data_dir).unwrap_or_default();
            cfg.mode = EnforcementMode::Enforcing;
            if let Err(e) = save_config(&data_dir, &cfg) {
                eprintln!("Failed to update config: {e}");
                std::process::exit(1);
            }
            println!("Curb mode set to Enforcing.");
            #[cfg(windows)]
            {
                if let Err(e) = win_scm::start_service() {
                    eprintln!("Warning: could not start CurbService: {e}");
                }
            }
        }

        Commands::Install {
            service_bin,
            migrate_from,
            reset,
        } => {
            #[cfg(windows)]
            {
                let source_service = service_bin.unwrap_or_else(|| {
                    std::env::current_exe()
                        .unwrap_or_default()
                        .with_file_name("curb-service.exe")
                });

                // Place service binary in admin-locked ProgramData\Curb\bin so a standard user
                // who installed Curb in %LOCALAPPDATA% cannot replace or delete the service binary.
                let bin_dir = data_dir.join("bin");
                if let Err(e) = std::fs::create_dir_all(&bin_dir) {
                    eprintln!("Failed to create {}: {e}", bin_dir.display());
                    std::process::exit(1);
                }

                // Stop any prior CurbService instance and wait for it to release the binary.
                let _ = win_scm::stop_service_if_running();

                if reset {
                    reset_data_dir(&data_dir);
                }

                let installed_service = bin_dir.join("curb-service.exe");
                if source_service != installed_service {
                    if let Err(e) = win_scm::copy_with_retry(
                        &source_service,
                        &installed_service,
                        std::time::Duration::from_secs(5),
                    ) {
                        eprintln!(
                            "Failed to copy {} to {}: {e}",
                            source_service.display(),
                            installed_service.display()
                        );
                        std::process::exit(1);
                    }
                }
                if let Ok(self_exe) = std::env::current_exe() {
                    let target_cli = bin_dir.join("curb-cli.exe");
                    if self_exe != target_cli {
                        let _ = win_scm::copy_with_retry(
                            &self_exe,
                            &target_cli,
                            std::time::Duration::from_secs(5),
                        );
                    }
                }

                // Optionally migrate config & password from Standard Mode (%LOCALAPPDATA%\Curb)
                // unless the user explicitly requested a clean reset.
                if !reset {
                    if let Some(src_dir) = migrate_from {
                        for filename in ["config.json", "auth.json"] {
                            let src = src_dir.join(filename);
                            let dst = data_dir.join(filename);
                            if src.exists() && !dst.exists() {
                                let _ = std::fs::copy(&src, &dst);
                            }
                        }
                    }
                }

                // Lock down ProgramData\Curb ACLs using locale-independent well-known SIDs:
                // SYSTEM (*S-1-5-18) & Administrators (*S-1-5-32-544) full control,
                // Users (*S-1-5-32-545) read-only.
                let dir_str = data_dir.to_string_lossy().to_string();
                let _ = std::process::Command::new("icacls.exe")
                    .args([
                        &dir_str,
                        "/inheritance:r",
                        "/grant:r",
                        "*S-1-5-18:(OI)(CI)F",
                        "/grant:r",
                        "*S-1-5-32-544:(OI)(CI)F",
                        "/grant:r",
                        "*S-1-5-32-545:(OI)(CI)RX",
                    ])
                    .status();

                match win_scm::install_and_start_service(&installed_service) {
                    Ok(()) => {
                        if reset {
                            println!("Curb configuration reset; CurbService installed and started.");
                        } else {
                            println!("CurbService installed and started.");
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to install or start CurbService: {e}\nRun from an elevated Administrator prompt."
                        );
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (service_bin, migrate_from, reset);
                eprintln!("Windows service installation is only supported on Windows.");
            }
        }

        Commands::Reset => {
            #[cfg(windows)]
            {
                let _ = win_scm::stop_service_if_running();
            }
            reset_data_dir(&data_dir);
            println!("Curb configuration, rules, password, and DNS backups have been reset.");
        }

        Commands::Uninstall => {
            #[cfg(windows)]
            {
                if let Err(e) = win_scm::uninstall_service() {
                    eprintln!("Warning: service removal reported: {e}");
                }

                // Always purge persistent WFP default-deny filters & restore original adapter DNS!
                match curb_core::cleanup::purge_all_curb_wfp_objects() {
                    Ok(n) => println!("Removed {n} Curb WFP firewall filters."),
                    Err(e) => eprintln!("Warning: WFP cleanup reported: {e}"),
                }
                if let Err(e) = curb_core::cleanup::restore_adapter_dns_clean(&data_dir) {
                    eprintln!("Warning: DNS restore reported: {e}");
                }

                // Clean up installed service binaries in ProgramData\Curb\bin
                win_scm::remove_dir_with_retry(
                    &data_dir.join("bin"),
                    std::time::Duration::from_secs(5),
                );
                println!("CurbService removed and all Windows firewall & DNS settings restored.");
            }
            #[cfg(not(windows))]
            {
                eprintln!("Windows service uninstallation is only supported on Windows.");
            }
        }
    }
}

/// Purges Curb WFP filters, restores original adapter DNS settings, and removes
/// persisted `config.json`, `auth.json`, and `dns_backup.json` from `data_dir`.
fn reset_data_dir(data_dir: &std::path::Path) {
    if let Err(e) = curb_core::cleanup::purge_all_curb_wfp_objects() {
        eprintln!("Warning: WFP cleanup reported: {e}");
    }
    if let Err(e) = curb_core::cleanup::restore_adapter_dns_clean(data_dir) {
        eprintln!("Warning: DNS restore reported: {e}");
    }
    for file in [
        curb_core::store::config_path(data_dir),
        curb_core::store::auth_path(data_dir),
        curb_core::store::dns_backup_path(data_dir),
    ] {
        if file.exists() {
            let _ = std::fs::remove_file(&file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_data_dir_removes_config_auth_and_dns_backup() {
        let dir = std::env::temp_dir().join(format!("curb_cli_reset_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(curb_core::store::config_path(&dir), b"{}").unwrap();
        std::fs::write(curb_core::store::auth_path(&dir), b"{}").unwrap();
        std::fs::write(curb_core::store::dns_backup_path(&dir), b"[]").unwrap();

        reset_data_dir(&dir);

        assert!(!curb_core::store::config_path(&dir).exists());
        assert!(!curb_core::store::auth_path(&dir).exists());
        assert!(!curb_core::store::dns_backup_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(windows)]
mod win_scm {
    use std::ffi::{OsStr, OsString};
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_service::service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
        ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
        ServiceStartType, ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    const SERVICE_NAME: &str = "CurbService";
    const SERVICE_DISPLAY_NAME: &str = "Curb Internet Limiter Service";
    const SERVICE_DESCRIPTION: &str =
        "Default-deny Windows Firewall and DNS enforcement service for Curb.";

    pub fn stop_service_if_running() -> Result<(), String> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .map_err(|e| format!("OpenSCManager failed: {e}"))?;

        let Ok(service) = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        ) else {
            return Ok(());
        };

        stop_and_wait(&service, Duration::from_secs(10))
    }

    pub fn start_service() -> Result<(), String> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .map_err(|e| format!("OpenSCManager failed: {e}"))?;

        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| format!("OpenService({SERVICE_NAME}) failed: {e}"))?;

        start_and_wait(&service, Duration::from_secs(10))
    }

    pub fn install_and_start_service(executable_path: &Path) -> Result<(), String> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| format!("OpenSCManager failed: {e}"))?;

        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable_path.to_path_buf(),
            launch_arguments: Vec::new(),
            // Ensure Windows Base Filtering Engine (WFP) is started before CurbService at boot.
            dependencies: vec![ServiceDependency::Service(OsString::from("BFE"))],
            account_name: None, // LocalSystem
            account_password: None,
        };

        let access = ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START
            | ServiceAccess::QUERY_STATUS;

        // Prefer updating an existing service in place so reinstall/repair succeeds even if
        // services.msc is open (which would otherwise cause DeleteService -> ERROR 1072).
        let service = match manager.open_service(SERVICE_NAME, access) {
            Ok(existing) => {
                existing
                    .change_config(&info)
                    .map_err(|e| format!("ChangeServiceConfig failed: {e}"))?;
                existing
            }
            Err(_) => manager
                .create_service(&info, access)
                .map_err(|e| format!("CreateService failed: {e}"))?,
        };

        let _ = service.set_description(SERVICE_DESCRIPTION);

        // Configure SCM automatic restart on unexpected crash/exit so the machine is never
        // left stranded with persistent WFP default-deny filters or 127.0.0.1 adapter DNS.
        let recovery = ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(2),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(10),
                },
            ]),
        };
        let _ = service.update_failure_actions(recovery);
        let _ = service.set_failure_actions_on_non_crash_failures(true);

        start_and_wait(&service, Duration::from_secs(10))
    }

    pub fn uninstall_service() -> Result<(), String> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .map_err(|e| format!("OpenSCManager failed: {e}"))?;

        let Ok(service) = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        ) else {
            return Ok(());
        };

        let _ = stop_and_wait(&service, Duration::from_secs(10));
        service
            .delete()
            .map_err(|e| format!("DeleteService failed: {e}"))
    }

    fn stop_and_wait(service: &Service, timeout: Duration) -> Result<(), String> {
        let status = service
            .query_status()
            .map_err(|e| format!("QueryServiceStatus failed: {e}"))?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }

        if status.current_state != ServiceState::StopPending {
            let _ = service.stop();
        }

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(st) = service.query_status() {
                if st.current_state == ServiceState::Stopped {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_millis(200));
        }

        Err("Timed out waiting for CurbService to stop".into())
    }

    fn start_and_wait(service: &Service, timeout: Duration) -> Result<(), String> {
        let status = service
            .query_status()
            .map_err(|e| format!("QueryServiceStatus failed: {e}"))?;
        if status.current_state == ServiceState::Running {
            return Ok(());
        }

        service
            .start(&[] as &[&OsStr])
            .map_err(|e| format!("StartService failed: {e}"))?;

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(st) = service.query_status() {
                match st.current_state {
                    ServiceState::Running => return Ok(()),
                    ServiceState::Stopped => {
                        return Err(format!(
                            "CurbService stopped immediately after start (exit_code={:?})",
                            st.exit_code
                        ));
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(200));
        }

        Err("Timed out waiting for CurbService to reach Running state".into())
    }

    /// Copies `src` to `dst`, retrying briefly on transient Windows file-lock errors
    /// (ERROR_SHARING_VIOLATION = 32 / ERROR_ACCESS_DENIED = 5) while a freshly stopped
    /// `curb-service.exe` process finishes tearing down its executable image mapping.
    pub fn copy_with_retry(src: &Path, dst: &Path, timeout: Duration) -> std::io::Result<u64> {
        const ERROR_ACCESS_DENIED: i32 = 5;
        const ERROR_SHARING_VIOLATION: i32 = 32;

        let deadline = Instant::now() + timeout;
        loop {
            match std::fs::copy(src, dst) {
                Ok(n) => return Ok(n),
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(ERROR_SHARING_VIOLATION | ERROR_ACCESS_DENIED)
                    ) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Best-effort recursive removal with short retries while a stopped service releases file locks.
    pub fn remove_dir_with_retry(dir: &Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while dir.exists() {
            if std::fs::remove_dir_all(dir).is_ok() || Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}
