use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use curb_core::adaptors::{DnsManager, FirewallManager, ServiceManager};
use curb_core::auth::hash_password;
use curb_core::config::EnforcementMode;
use curb_core::store::{load_auth, load_config, save_auth, save_config};

#[derive(Debug, Parser)]
#[command(
    name = "curb-cli",
    about = "Elevated Administrator / root management & recovery tool for Curb"
)]
struct Cli {
    /// Override Curb data directory (defaults to C:\ProgramData\Curb on Windows, /var/lib/curb on Linux).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Show current Curb enforcement mode, rule count, and password status.
    Status,
    /// Set or reset the Curb admin password (requires Administrator/root access).
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
    /// Install and start Curb's system service (Windows SCM or Linux systemd).
    Install {
        /// Path to curb-service binary (defaults to sibling of curb-cli).
        #[arg(long)]
        service_bin: Option<PathBuf>,
        /// Optional Standard Mode data directory to migrate config.json and auth.json from.
        #[arg(long)]
        migrate_from: Option<PathBuf>,
        /// Reset existing Curb configuration, rules, password, and DNS backup before starting.
        #[arg(long)]
        reset: bool,
    },
    /// Reset Curb configuration, rules, password, firewall rules, and DNS backups for a clean start.
    Reset,
    /// Stop and unregister Curb's system service (Windows SCM or Linux systemd).
    Uninstall,
}

struct CliAdaptors {
    service: Box<dyn ServiceManager>,
    firewall: Box<dyn FirewallManager>,
    dns: Box<dyn DnsManager>,
    default_data_dir: PathBuf,
}

fn build_adaptors() -> Option<CliAdaptors> {
    #[cfg(windows)]
    {
        Some(CliAdaptors {
            service: Box::new(curb_windows::WindowsServiceManager),
            firewall: Box::new(curb_windows::WindowsFirewallManager),
            dns: Box::new(curb_windows::WindowsDnsManager),
            default_data_dir: curb_windows::default_data_dir(),
        })
    }

    #[cfg(target_os = "linux")]
    {
        Some(CliAdaptors {
            service: Box::new(curb_systemd::SystemdServiceManager),
            firewall: Box::new(curb_nftables::NftablesFirewall),
            dns: Box::new(curb_linux::LinuxDnsManager),
            default_data_dir: curb_linux::default_data_dir(),
        })
    }

    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        None
    }
}

fn main() {
    let cli = Cli::parse();
    let adaptors = build_adaptors();
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        adaptors
            .as_ref()
            .map(|a| a.default_data_dir.clone())
            .unwrap_or_else(|| PathBuf::from("/tmp/curb-data"))
    });

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
            if let Some(a) = &adaptors {
                let _ = a.service.stop_if_running();
                match a.firewall.purge_all() {
                    Ok(n) => println!("Removed {n} Curb firewall object(s)."),
                    Err(e) => eprintln!("Warning: firewall cleanup reported: {e}"),
                }
                if let Err(e) = a.dns.restore_clean(&data_dir) {
                    eprintln!("Warning: DNS restore reported: {e}");
                }
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
            if let Some(a) = &adaptors {
                if let Err(e) = a.service.start() {
                    eprintln!("Warning: could not start Curb service: {e}");
                }
            }
        }

        Commands::Install {
            service_bin,
            migrate_from,
            reset,
        } => {
            let Some(a) = &adaptors else {
                eprintln!("System service installation is only supported on Windows and Linux.");
                std::process::exit(1);
            };
            let _ = a.service.stop_if_running();
            if reset {
                reset_data_dir(&data_dir, Some(a));
            }
            match a.service.install(&data_dir, service_bin, migrate_from, reset) {
                Ok(()) => {
                    if reset {
                        println!("Curb configuration reset; Curb service installed and started.");
                    } else {
                        println!("Curb service installed and started.");
                    }
                }
                Err(e) => {
                    eprintln!("Failed to install or start Curb service: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Reset => {
            if let Some(a) = &adaptors {
                let _ = a.service.stop_if_running();
            }
            reset_data_dir(&data_dir, adaptors.as_ref());
            println!("Curb configuration, rules, password, and DNS backups have been reset.");
        }

        Commands::Uninstall => {
            let Some(a) = &adaptors else {
                eprintln!("System service uninstallation is only supported on Windows and Linux.");
                std::process::exit(1);
            };
            if let Err(e) = a.service.uninstall(&data_dir) {
                eprintln!("Warning: service removal reported: {e}");
            }
            match a.firewall.purge_all() {
                Ok(n) => println!("Removed {n} Curb firewall object(s)."),
                Err(e) => eprintln!("Warning: firewall cleanup reported: {e}"),
            }
            if let Err(e) = a.dns.restore_clean(&data_dir) {
                eprintln!("Warning: DNS restore reported: {e}");
            }
            println!("Curb service removed and firewall & DNS settings restored.");
        }
    }
}

/// Purges Curb firewall objects, restores original DNS settings, and removes
/// persisted `config.json`, `auth.json`, and `dns_backup.json` from `data_dir`.
fn reset_data_dir(data_dir: &Path, adaptors: Option<&CliAdaptors>) {
    if let Some(a) = adaptors {
        if let Err(e) = a.firewall.purge_all() {
            eprintln!("Warning: firewall cleanup reported: {e}");
        }
        if let Err(e) = a.dns.restore_clean(data_dir) {
            eprintln!("Warning: DNS restore reported: {e}");
        }
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

        reset_data_dir(&dir, None);

        assert!(!curb_core::store::config_path(&dir).exists());
        assert!(!curb_core::store::auth_path(&dir).exists());
        assert!(!curb_core::store::dns_backup_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
