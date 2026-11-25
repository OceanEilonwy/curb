mod profile;

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use curb_core::adaptors::{DnsManager, FirewallManager, ServiceManager};
use curb_core::auth::hash_password;
use curb_core::config::EnforcementMode;
use curb_core::presets::{DefaultPresetHost, PresetHost};
use curb_core::store::{load_auth, load_config, load_usage, save_auth, save_config, save_usage};

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
enum PlaytimeCommands {
    /// Show current playtime budgets and today's usage across all limited games.
    Status,
    /// Reset today's playtime usage and overtime debt for a game (or 'all').
    Reset {
        /// Rule name substring or "all".
        target: String,
    },
    /// Disable all playtime limits globally across all games.
    DisableAll,
    /// Re-enable all playtime limits globally across all games.
    EnableAll,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Show current Curb enforcement mode, rule count, and password status.
    Status,
    /// Interactively profile a Steam game across Menu, Lobby, and Playing states
    /// to calibrate match-aware playtime detectors.
    Profile {
        /// Steam AppID or alias (e.g. "halo", "mcc", "976730", "astro", "4178190").
        game: String,
        /// Do not auto-launch the game via steam://rungameid/<appid>.
        #[arg(long)]
        no_launch: bool,
        /// Optional output JSON file path (defaults to curb-profile-<appid>-<timestamp>.json).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Seconds trimmed BEFORE each state transition marker to account for alt-tab delay.
        #[arg(long, default_value_t = 8.0)]
        pre_guard: f64,
        /// Seconds trimmed AFTER each state transition marker to allow state settling.
        #[arg(long, default_value_t = 3.0)]
        post_guard: f64,
    },
    /// Manage playtime limits (status, reset, or globally disable/enable all limits).
    Playtime {
        #[command(subcommand)]
        action: PlaytimeCommands,
    },
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
    /// Install and start Curb's system service (Windows SCM, Linux systemd, or Void runit).
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
    /// Refresh service definitions and restart Curb's system service if already active (used by package upgrades).
    Upgrade {
        /// Path to curb-service binary (used on Windows upgrades; defaults to sibling of curb-cli).
        #[arg(long)]
        service_bin: Option<PathBuf>,
    },
    /// Stop and unregister Curb's system service and clean up applied config.
    Uninstall {
        /// Also remove all saved Curb data (/var/lib/curb, /var/log/curb, %ProgramData%\Curb, and per-user data).
        #[arg(long)]
        purge: bool,
        /// Clean up per-user desktop settings only (autostart, proxy, Standard Mode flag) without requiring Administrator/root privileges.
        #[arg(long)]
        user_only: bool,
    },
}

struct CliAdaptors {
    service: Box<dyn ServiceManager>,
    firewall: Box<dyn FirewallManager>,
    dns: Box<dyn DnsManager>,
    preset_host: Box<dyn PresetHost>,
    default_data_dir: PathBuf,
}

#[cfg(target_os = "linux")]
fn detect_linux_service_manager() -> Box<dyn ServiceManager> {
    if Path::new("/run/systemd/system").is_dir() {
        Box::new(curb_systemd::SystemdServiceManager)
    } else if curb_runit::is_runit_system() {
        Box::new(curb_runit::RunitServiceManager)
    } else {
        Box::new(curb_systemd::SystemdServiceManager)
    }
}

fn build_adaptors() -> Option<CliAdaptors> {
    #[cfg(windows)]
    {
        Some(CliAdaptors {
            service: Box::new(curb_windows::WindowsServiceManager),
            firewall: Box::new(curb_windows::WindowsFirewallManager),
            dns: Box::new(curb_windows::WindowsDnsManager),
            preset_host: Box::new(curb_windows::WindowsPresetHost),
            default_data_dir: curb_windows::default_data_dir(),
        })
    }

    #[cfg(target_os = "linux")]
    {
        Some(CliAdaptors {
            service: detect_linux_service_manager(),
            firewall: Box::new(curb_nftables::NftablesFirewall),
            dns: Box::new(curb_linux::LinuxDnsManager),
            preset_host: Box::new(curb_linux::LinuxPresetHost),
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
            println!(
                "Playtime Limit: {}",
                if cfg.playtime_limits_enabled {
                    "enabled"
                } else {
                    "disabled (all games)"
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

        Commands::Profile {
            game,
            no_launch,
            output,
            pre_guard,
            post_guard,
        } => {
            let default_host = DefaultPresetHost::default();
            let host_ref: &dyn PresetHost = adaptors
                .as_ref()
                .map(|a| a.preset_host.as_ref())
                .unwrap_or(&default_host);
            profile::run_profile(
                profile::ProfileArgs {
                    game,
                    no_launch,
                    output,
                    pre_guard_secs: pre_guard,
                    post_guard_secs: post_guard,
                },
                host_ref,
            );
        }

        Commands::Playtime { action } => match action {
            PlaytimeCommands::Status => {
                let cfg = load_config(&data_dir).unwrap_or_default();
                let mut ledger = load_usage(&data_dir).unwrap_or_default();
                let now = chrono::Local::now();
                let registry = curb_games::DetectorRegistry::default();
                println!(
                    "Global Playtime Limits: {}",
                    if cfg.playtime_limits_enabled {
                        "ENABLED"
                    } else {
                        "DISABLED"
                    }
                );
                let mut found = false;
                for rule in &cfg.rules {
                    let Some(limit) = &rule.playtime_limit else {
                        continue;
                    };
                    found = true;
                    let (rem, daily, exempt) = ledger.remaining_today(rule.id, limit, now);
                    let app_id = match &rule.matcher {
                        curb_core::config::ExecutableMatcher::SteamGame { app_id, .. } => {
                            Some(*app_id)
                        }
                        _ => None,
                    };
                    let fc = app_id.is_some_and(|id| registry.is_first_class(id));
                    println!(
                        " - {} [{}] : {}/{} min left today{}",
                        rule.name,
                        if fc { "Match-aware" } else { "Timer-only" },
                        rem / 60,
                        daily / 60,
                        if exempt { " (Exempt today)" } else { "" }
                    );
                }
                if !found {
                    println!("No rules have playtime limits configured.");
                }
            }
            PlaytimeCommands::Reset { target } => {
                let cfg = load_config(&data_dir).unwrap_or_default();
                let mut ledger = load_usage(&data_dir).unwrap_or_default();
                let now = chrono::Local::now();
                if target.eq_ignore_ascii_case("all") {
                    ledger.reset_all(now);
                    if let Err(e) = save_usage(&data_dir, &ledger) {
                        eprintln!("Failed to save usage.json: {e}");
                        std::process::exit(1);
                    }
                    println!("Reset playtime limits & overtime debt for all games.");
                } else {
                    let needle = target.to_ascii_lowercase();
                    let matched: Vec<_> = cfg
                        .rules
                        .iter()
                        .filter(|r| r.name.to_ascii_lowercase().contains(&needle))
                        .collect();
                    if matched.is_empty() {
                        eprintln!("No rule matching '{target}'.");
                        std::process::exit(1);
                    }
                    for r in matched {
                        ledger.reset_rule(r.id, now);
                        println!("Reset today's playtime limit & debt for '{}'.", r.name);
                    }
                    if let Err(e) = save_usage(&data_dir, &ledger) {
                        eprintln!("Failed to save usage.json: {e}");
                        std::process::exit(1);
                    }
                }
            }
            PlaytimeCommands::DisableAll => {
                let mut cfg = load_config(&data_dir).unwrap_or_default();
                cfg.playtime_limits_enabled = false;
                if let Err(e) = save_config(&data_dir, &cfg) {
                    eprintln!("Failed to update config: {e}");
                    std::process::exit(1);
                }
                println!("All playtime limits disabled across all games.");
            }
            PlaytimeCommands::EnableAll => {
                let mut cfg = load_config(&data_dir).unwrap_or_default();
                cfg.playtime_limits_enabled = true;
                if let Err(e) = save_config(&data_dir, &cfg) {
                    eprintln!("Failed to update config: {e}");
                    std::process::exit(1);
                }
                println!("Playtime limits re-enabled across all games.");
            }
        },

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

        Commands::Upgrade { service_bin } => {
            let Some(a) = &adaptors else {
                eprintln!("System service upgrade is only supported on Windows and Linux.");
                std::process::exit(1);
            };
            match a.service.upgrade_if_installed(&data_dir, service_bin) {
                Ok(true) => println!("Curb service upgraded and restarted."),
                Ok(false) => println!("Curb service is not active; nothing to restart."),
                Err(e) => {
                    eprintln!("Failed to upgrade Curb service: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Uninstall { purge, user_only } => {
            #[cfg(windows)]
            {
                for item in curb_windows::cleanup_user_desktop_config(purge) {
                    println!("{item}");
                }
            }

            #[cfg(target_os = "linux")]
            {
                for item in curb_xdg::cleanup_invoking_user_desktop_config(purge) {
                    println!("{item}");
                }
            }

            if user_only {
                println!("Per-user Curb desktop settings cleaned up.");
                return;
            }

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

            if purge {
                reset_data_dir(&data_dir, None);
                if data_dir.exists() {
                    let _ = std::fs::remove_dir_all(&data_dir);
                    println!("Removed {}", data_dir.display());
                }
                #[cfg(target_os = "linux")]
                {
                    for extra in ["/var/log/curb", "/run/curb"] {
                        let p = Path::new(extra);
                        if p.exists() {
                            let _ = std::fs::remove_dir_all(p);
                            println!("Removed {extra}");
                        }
                    }
                    if let Some(pkg_cmd) = detect_linux_package_remove_cmd() {
                        println!(
                            "Curb binaries are managed by your distro package manager. Finish removing the package with:\n  {pkg_cmd}"
                        );
                    } else {
                        for removed in remove_unmanaged_linux_files() {
                            println!("Removed {removed}");
                        }
                    }
                }
                println!(
                    "Curb service, firewall, DNS, desktop config, and all saved data have been removed."
                );
            } else {
                println!("Curb service removed and firewall, DNS, & desktop settings restored.");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_package_remove_cmd() -> Option<&'static str> {
    use std::process::Command;

    let checks: &[(&str, &[&str], &str)] = &[
        ("dpkg", &["-S", "/usr/bin/curb-cli"], "sudo apt purge curb"),
        ("rpm", &["-qf", "/usr/bin/curb-cli"], "sudo dnf remove curb"),
        ("pacman", &["-Qo", "/usr/bin/curb-cli"], "sudo pacman -Rns curb"),
        ("xbps-query", &["-o", "/usr/bin/curb-cli"], "sudo xbps-remove -R curb"),
    ];
    for (bin, args, remove_cmd) in checks {
        if Command::new(bin)
            .args(*args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(*remove_cmd);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn remove_unmanaged_linux_files() -> Vec<&'static str> {
    let mut removed = Vec::new();
    for path in [
        "/usr/bin/curb-app",
        "/usr/libexec/curb/curb-service",
        "/usr/lib/systemd/system/curb.service",
        "/usr/share/applications/curb.desktop",
        "/usr/share/polkit-1/actions/org.curb.policy",
        "/usr/share/icons/hicolor/128x128/apps/curb.png",
        "/usr/share/icons/hicolor/32x32/apps/curb.png",
        "/usr/bin/curb-cli",
    ] {
        let p = Path::new(path);
        if p.exists() && std::fs::remove_file(p).is_ok() {
            removed.push(path);
        }
    }
    let _ = std::fs::remove_dir("/usr/libexec/curb");
    removed
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
