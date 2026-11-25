#[cfg(target_os = "linux")]
mod imp {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use curb_core::adaptors::ServiceManager;

    const RUNIT_SV_DIR: &str = "/etc/sv/curb";
    const RUNIT_ACTIVE_LINK: &str = "/var/service/curb";
    const RUNIT_LOG_DIR: &str = "/var/log/curb";
    const INSTALL_LIBEXEC_DIR: &str = "/usr/local/libexec/curb";

    /// Linux `runit` service lifecycle adaptor (Void Linux and other runit distros).
    #[derive(Debug, Default, Clone, Copy)]
    pub struct RunitServiceManager;

    /// Returns `true` when the host appears to be managed by `runit` (e.g. Void Linux).
    pub fn is_runit_system() -> bool {
        is_runit_paths(
            Path::new("/run/runit"),
            Path::new("/etc/runit"),
            Path::new("/var/service"),
        )
    }

    pub(crate) fn is_runit_paths(run_runit: &Path, etc_runit: &Path, var_service: &Path) -> bool {
        run_runit.exists() || (etc_runit.is_dir() && var_service.is_dir())
    }

    fn ensure_root() -> Result<(), String> {
        if unsafe { libc::geteuid() != 0 } {
            return Err("Root privileges required. Re-run with sudo, doas, or pkexec.".into());
        }
        Ok(())
    }

    /// Generates the executable `/etc/sv/curb/run` script for `runit`.
    pub fn build_run_script(service_bin: &Path, data_dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             exec 2>&1\n\
             mkdir -p /run/curb\n\
             chmod 0755 /run/curb\n\
             exec \"{}\" --data-dir \"{}\"\n",
            service_bin.display(),
            data_dir.display(),
        )
    }

    /// Generates the executable `/etc/sv/curb/log/run` script using `svlogd` when available.
    pub fn build_log_run_script(log_dir: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             mkdir -p \"{0}\"\n\
             if command -v svlogd >/dev/null 2>&1; then\n\
             \texec svlogd -tt \"{0}\"\n\
             fi\n\
             exec cat >/dev/null\n",
            log_dir.display(),
        )
    }

    impl ServiceManager for RunitServiceManager {
        fn install(
            &self,
            data_dir: &Path,
            service_bin: Option<PathBuf>,
            migrate_from: Option<PathBuf>,
            reset: bool,
        ) -> Result<(), String> {
            ensure_root()?;

            let source_service = service_bin.unwrap_or_else(|| {
                let candidates = [
                    std::env::current_exe()
                        .unwrap_or_default()
                        .with_file_name("curb-service"),
                    PathBuf::from("/usr/libexec/curb/curb-service"),
                    PathBuf::from("/usr/lib/curb/curb-service"),
                    PathBuf::from("/usr/local/libexec/curb/curb-service"),
                ];
                candidates
                    .into_iter()
                    .find(|p| p.exists())
                    .unwrap_or_else(|| PathBuf::from("/usr/local/libexec/curb/curb-service"))
            });

            if !source_service.exists() {
                return Err(format!(
                    "Could not find curb-service binary at {}",
                    source_service.display()
                ));
            }

            let _ = self.stop_if_running();

            let installed_service = if source_service.starts_with("/usr/") {
                source_service
            } else {
                let libexec = PathBuf::from(INSTALL_LIBEXEC_DIR);
                fs::create_dir_all(&libexec)
                    .map_err(|e| format!("Failed to create {}: {e}", libexec.display()))?;
                let target = libexec.join("curb-service");
                if source_service != target {
                    fs::copy(&source_service, &target).map_err(|e| {
                        format!(
                            "Failed to copy {} to {}: {e}",
                            source_service.display(),
                            target.display()
                        )
                    })?;
                    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o755));
                }
                target
            };

            fs::create_dir_all(data_dir)
                .map_err(|e| format!("Failed to create {}: {e}", data_dir.display()))?;
            let _ = fs::set_permissions(data_dir, fs::Permissions::from_mode(0o755));

            if !reset {
                if let Some(src_dir) = migrate_from {
                    for filename in ["config.json", "auth.json"] {
                        let src = src_dir.join(filename);
                        let dst = data_dir.join(filename);
                        if src.exists() && !dst.exists() {
                            let _ = fs::copy(&src, &dst);
                            if filename == "auth.json" {
                                let _ =
                                    fs::set_permissions(&dst, fs::Permissions::from_mode(0o600));
                            }
                        }
                    }
                }
            }

            let sv_dir = Path::new(RUNIT_SV_DIR);
            let log_sv_dir = sv_dir.join("log");
            fs::create_dir_all(&log_sv_dir)
                .map_err(|e| format!("Failed to create {}: {e}", log_sv_dir.display()))?;
            let _ = fs::create_dir_all(RUNIT_LOG_DIR);

            let run_path = sv_dir.join("run");
            fs::write(&run_path, build_run_script(&installed_service, data_dir))
                .map_err(|e| format!("Failed to write {}: {e}", run_path.display()))?;
            fs::set_permissions(&run_path, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to chmod {}: {e}", run_path.display()))?;

            let log_run_path = log_sv_dir.join("run");
            fs::write(&log_run_path, build_log_run_script(Path::new(RUNIT_LOG_DIR)))
                .map_err(|e| format!("Failed to write {}: {e}", log_run_path.display()))?;
            fs::set_permissions(&log_run_path, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("Failed to chmod {}: {e}", log_run_path.display()))?;

            let active_link = Path::new(RUNIT_ACTIVE_LINK);
            if let Some(parent) = active_link.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
            }
            if active_link.symlink_metadata().is_ok() {
                let _ = fs::remove_file(active_link);
            }
            symlink(sv_dir, active_link).map_err(|e| {
                format!(
                    "Failed to symlink {} -> {}: {e}",
                    sv_dir.display(),
                    active_link.display()
                )
            })?;

            // Give runsvdir a moment to supervise the new service link, then bring it up.
            for _ in 0..10 {
                let ok = Command::new("sv")
                    .args(["up", "curb"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(250));
            }

            Ok(())
        }

        fn uninstall(&self, _data_dir: &Path) -> Result<(), String> {
            ensure_root()?;
            let _ = Command::new("sv").args(["down", "curb"]).status();
            let active_link = Path::new(RUNIT_ACTIVE_LINK);
            if active_link.symlink_metadata().is_ok() {
                let _ = fs::remove_file(active_link);
            }
            let sv_dir = Path::new(RUNIT_SV_DIR);
            if sv_dir.exists() {
                let _ = fs::remove_dir_all(sv_dir);
            }
            let libexec = Path::new(INSTALL_LIBEXEC_DIR);
            if libexec.exists() {
                let _ = fs::remove_dir_all(libexec);
            }
            Ok(())
        }

        fn start(&self) -> Result<(), String> {
            let out = Command::new("sv")
                .args(["up", "curb"])
                .output()
                .map_err(|e| format!("Failed to invoke `sv up curb`: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
            }
        }

        fn stop_if_running(&self) -> Result<(), String> {
            let _ = Command::new("sv").args(["down", "curb"]).status();
            Ok(())
        }

        fn upgrade_if_installed(
            &self,
            _data_dir: &Path,
            _service_bin: Option<PathBuf>,
        ) -> Result<bool, String> {
            ensure_root()?;
            if Path::new(RUNIT_ACTIVE_LINK).symlink_metadata().is_err() {
                return Ok(false);
            }
            let status_out = Command::new("sv").args(["status", "curb"]).output();
            let is_running = status_out
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).starts_with("run:"))
                .unwrap_or(false);
            if !is_running {
                return Ok(false);
            }
            let out = Command::new("sv")
                .args(["restart", "curb"])
                .output()
                .map_err(|e| format!("Failed to invoke `sv restart curb`: {e}"))?;
            if out.status.success() {
                Ok(true)
            } else {
                Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn renders_runit_run_script() {
            let script = build_run_script(
                Path::new("/usr/libexec/curb/curb-service"),
                Path::new("/var/lib/curb"),
            );
            assert!(script.starts_with("#!/bin/sh\n"));
            assert!(script.contains("mkdir -p /run/curb"));
            assert!(script.contains(
                "exec \"/usr/libexec/curb/curb-service\" --data-dir \"/var/lib/curb\""
            ));
        }

        #[test]
        fn renders_runit_log_script() {
            let script = build_log_run_script(Path::new("/var/log/curb"));
            assert!(script.starts_with("#!/bin/sh\n"));
            assert!(script.contains("svlogd -tt \"/var/log/curb\""));
        }

        #[test]
        fn detects_runit_paths() {
            let tmp = std::env::temp_dir().join(format!("curb_runit_test_{}", std::process::id()));
            let _ = fs::remove_dir_all(&tmp);
            let run_runit = tmp.join("run/runit");
            let etc_runit = tmp.join("etc/runit");
            let var_service = tmp.join("var/service");

            assert!(!is_runit_paths(&run_runit, &etc_runit, &var_service));

            fs::create_dir_all(&etc_runit).unwrap();
            assert!(!is_runit_paths(&run_runit, &etc_runit, &var_service));

            fs::create_dir_all(&var_service).unwrap();
            assert!(is_runit_paths(&run_runit, &etc_runit, &var_service));

            let _ = fs::remove_dir_all(&tmp);
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::{build_log_run_script, build_run_script, is_runit_system, RunitServiceManager};
