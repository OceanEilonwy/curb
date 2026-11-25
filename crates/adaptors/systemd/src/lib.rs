#[cfg(target_os = "linux")]
mod imp {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use curb_core::adaptors::ServiceManager;

    const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/curb.service";
    const INSTALL_LIBEXEC_DIR: &str = "/usr/local/libexec/curb";

    /// Linux `systemd` service lifecycle adaptor (`curb.service`).
    #[derive(Debug, Default, Clone, Copy)]
    pub struct SystemdServiceManager;

    fn ensure_root() -> Result<(), String> {
        if unsafe { libc::geteuid() != 0 } {
            return Err("Root privileges required. Re-run with sudo or pkexec.".into());
        }
        Ok(())
    }

    pub fn build_unit_file(service_bin: &Path, data_dir: &Path) -> String {
        format!(
            "[Unit]\n\
             Description=Curb Default-Deny Application Firewall Service\n\
             After=network-pre.target nftables.service firewalld.service ufw.service\n\
             Wants=network-pre.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={} --data-dir {}\n\
             ExecStopPost=-/bin/sh -c 'nft delete table inet curb 2>/dev/null || true'\n\
             Restart=on-failure\n\
             RestartSec=2\n\
             RuntimeDirectory=curb\n\
             RuntimeDirectoryMode=0755\n\
             StateDirectory=curb\n\
             StateDirectoryMode=0755\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            service_bin.display(),
            data_dir.display(),
        )
    }

    impl ServiceManager for SystemdServiceManager {
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

            let unit_contents = build_unit_file(&installed_service, data_dir);
            fs::write(SYSTEMD_UNIT_PATH, unit_contents)
                .map_err(|e| format!("Failed to write {SYSTEMD_UNIT_PATH}: {e}"))?;

            for args in [
                vec!["daemon-reload"],
                vec!["enable", "--now", "curb.service"],
            ] {
                let out = Command::new("systemctl")
                    .args(&args)
                    .output()
                    .map_err(|e| format!("Failed to invoke systemctl {:?}: {e}", args))?;
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    return Err(format!("systemctl {:?} failed: {}", args, stderr.trim()));
                }
            }

            Ok(())
        }

        fn uninstall(&self, _data_dir: &Path) -> Result<(), String> {
            ensure_root()?;
            let _ = Command::new("systemctl")
                .args(["disable", "--now", "curb.service"])
                .status();
            if Path::new(SYSTEMD_UNIT_PATH).exists() {
                let _ = fs::remove_file(SYSTEMD_UNIT_PATH);
            }
            let _ = Command::new("systemctl").args(["daemon-reload"]).status();
            let libexec = Path::new(INSTALL_LIBEXEC_DIR);
            if libexec.exists() {
                let _ = fs::remove_dir_all(libexec);
            }
            Ok(())
        }

        fn start(&self) -> Result<(), String> {
            let out = Command::new("systemctl")
                .args(["start", "curb.service"])
                .output()
                .map_err(|e| format!("Failed to invoke systemctl: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
            }
        }

        fn stop_if_running(&self) -> Result<(), String> {
            let _ = Command::new("systemctl")
                .args(["stop", "curb.service"])
                .status();
            Ok(())
        }

        fn upgrade_if_installed(
            &self,
            _data_dir: &Path,
            _service_bin: Option<PathBuf>,
        ) -> Result<bool, String> {
            ensure_root()?;
            if !Path::new("/run/systemd/system").is_dir() {
                return Ok(false);
            }
            let _ = Command::new("systemctl").args(["daemon-reload"]).status();
            let active = Command::new("systemctl")
                .args(["is-active", "--quiet", "curb.service"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !active {
                return Ok(false);
            }
            let out = Command::new("systemctl")
                .args(["restart", "curb.service"])
                .output()
                .map_err(|e| format!("Failed to invoke `systemctl restart curb.service`: {e}"))?;
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
        fn renders_systemd_unit_file() {
            let unit = build_unit_file(
                Path::new("/usr/libexec/curb/curb-service"),
                Path::new("/var/lib/curb"),
            );
            assert!(unit.contains("ExecStart=/usr/libexec/curb/curb-service --data-dir /var/lib/curb"));
            assert!(unit.contains("ExecStopPost=-/bin/sh -c 'nft delete table inet curb 2>/dev/null || true'"));
            assert!(unit.contains("RuntimeDirectory=curb"));
            assert!(unit.contains("After=network-pre.target nftables.service firewalld.service ufw.service"));
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::{build_unit_file, SystemdServiceManager};
