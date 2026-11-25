use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use curb_core::adaptors::ServiceManager as CurbServiceManager;
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

/// Windows Service Control Manager (`CurbService`) adaptor.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsServiceManager;

impl CurbServiceManager for WindowsServiceManager {
    fn install(
        &self,
        data_dir: &Path,
        service_bin: Option<PathBuf>,
        migrate_from: Option<PathBuf>,
        reset: bool,
    ) -> Result<(), String> {
        let source_service = service_bin.unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap_or_default()
                .with_file_name("curb-service.exe")
        });

        let bin_dir = data_dir.join("bin");
        std::fs::create_dir_all(&bin_dir)
            .map_err(|e| format!("Failed to create {}: {e}", bin_dir.display()))?;

        let _ = self.stop_if_running();

        let installed_service = bin_dir.join("curb-service.exe");
        if source_service != installed_service {
            copy_with_retry(&source_service, &installed_service, Duration::from_secs(5)).map_err(
                |e| {
                    format!(
                        "Failed to copy {} to {}: {e}",
                        source_service.display(),
                        installed_service.display()
                    )
                },
            )?;
        }
        if let Ok(self_exe) = std::env::current_exe() {
            let target_cli = bin_dir.join("curb-cli.exe");
            if self_exe != target_cli {
                let _ = copy_with_retry(&self_exe, &target_cli, Duration::from_secs(5));
            }
        }

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

        install_and_start_service(&installed_service)
    }

    fn uninstall(&self, data_dir: &Path) -> Result<(), String> {
        let res = uninstall_service();
        remove_dir_with_retry(&data_dir.join("bin"), Duration::from_secs(5));
        res
    }

    fn start(&self) -> Result<(), String> {
        start_service()
    }

    fn stop_if_running(&self) -> Result<(), String> {
        stop_service_if_running()
    }

    fn upgrade_if_installed(
        &self,
        data_dir: &Path,
        service_bin: Option<PathBuf>,
    ) -> Result<bool, String> {
        let installed_service = data_dir.join("bin").join("curb-service.exe");
        if !installed_service.exists() {
            return Ok(false);
        }
        self.install(data_dir, service_bin, None, false)?;
        Ok(true)
    }
}

pub fn stop_service_if_running() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
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
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
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
        dependencies: vec![ServiceDependency::Service(OsString::from("BFE"))],
        account_name: None,
        account_password: None,
    };

    let access =
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;

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
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
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

pub fn remove_dir_with_retry(dir: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while dir.exists() {
        if std::fs::remove_dir_all(dir).is_ok() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}
