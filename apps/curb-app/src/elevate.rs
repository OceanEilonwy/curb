use std::path::PathBuf;

use curb_core::adaptors::DesktopIntegration;

fn desktop_adaptor() -> Option<Box<dyn DesktopIntegration>> {
    #[cfg(windows)]
    {
        Some(Box::new(curb_windows::WindowsDesktopIntegration))
    }

    #[cfg(target_os = "linux")]
    {
        Some(Box::new(curb_xdg::XdgDesktopIntegration))
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        None
    }
}

/// Triggers a single native elevation prompt (Windows UAC or Linux Polkit `pkexec`)
/// to install & start Curb's system service.
pub fn launch_elevated_service_install() -> Result<(), String> {
    let Some(adaptor) = desktop_adaptor() else {
        return Err("Full Protection system service is only available on Windows and Linux.".into());
    };
    let migrate_dir = adaptor.user_data_dir();
    adaptor.launch_elevated_install(&migrate_dir)
}

/// Returns true if a running Curb service reports a different version than this `curb-app` build.
pub fn is_service_outdated(reported_version: &str) -> bool {
    reported_version != env!("CARGO_PKG_VERSION")
}

/// Triggers a single native elevation prompt to stop and unregister Curb's system service.
pub fn launch_elevated_service_uninstall() -> Result<(), String> {
    let Some(adaptor) = desktop_adaptor() else {
        return Err("Only available on Windows and Linux.".into());
    };
    adaptor.launch_elevated_uninstall()
}

/// Registers `curb-app` to start quietly in the system tray on login.
pub fn ensure_tray_autostart() {
    if let Some(adaptor) = desktop_adaptor() {
        adaptor.ensure_tray_autostart();
    }
}

/// Enables or disables the per-user Standard Mode HTTP proxy via the active desktop adaptor.
pub fn set_user_proxy(enable: bool, port: u16) {
    if let Some(adaptor) = desktop_adaptor() {
        adaptor.set_user_proxy(enable, port);
    }
}

/// Returns the per-user Standard Mode data directory for this OS.
pub fn user_data_dir() -> PathBuf {
    if let Some(adaptor) = desktop_adaptor() {
        return adaptor.user_data_dir();
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/curb-user");
    }
    PathBuf::from("/tmp/curb-user")
}
