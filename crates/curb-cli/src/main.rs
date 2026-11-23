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
    },
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
            println!("Curb mode set to Disabled.");
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("sc.exe")
                    .args(["stop", "CurbService"])
                    .status();
                println!("Stopped CurbService. Run `curb-cli enable` when ready to resume.");
            }
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
                let _ = std::process::Command::new("sc.exe")
                    .args(["start", "CurbService"])
                    .status();
            }
        }

        Commands::Install {
            service_bin,
            migrate_from,
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

                // Stop any prior CurbService instance before replacing binaries.
                let _ = std::process::Command::new("sc.exe")
                    .args(["stop", "CurbService"])
                    .status();
                std::thread::sleep(std::time::Duration::from_millis(400));

                let installed_service = bin_dir.join("curb-service.exe");
                if let Err(e) = std::fs::copy(&source_service, &installed_service) {
                    eprintln!(
                        "Failed to copy {} to {}: {e}",
                        source_service.display(),
                        installed_service.display()
                    );
                    std::process::exit(1);
                }
                if let Ok(self_exe) = std::env::current_exe() {
                    let _ = std::fs::copy(&self_exe, bin_dir.join("curb-cli.exe"));
                }

                // Optionally migrate config & password from Standard Mode (%LOCALAPPDATA%\Curb).
                if let Some(src_dir) = migrate_from {
                    for filename in ["config.json", "auth.json"] {
                        let src = src_dir.join(filename);
                        let dst = data_dir.join(filename);
                        if src.exists() && !dst.exists() {
                            let _ = std::fs::copy(&src, &dst);
                        }
                    }
                }

                // Lock down ProgramData\Curb ACLs: SYSTEM & Administrators full control, Users read-only.
                let dir_str = data_dir.to_string_lossy().to_string();
                let _ = std::process::Command::new("icacls.exe")
                    .args([
                        &dir_str,
                        "/inheritance:r",
                        "/grant:r",
                        "SYSTEM:(OI)(CI)F",
                        "/grant:r",
                        "Administrators:(OI)(CI)F",
                        "/grant:r",
                        "Users:(OI)(CI)RX",
                    ])
                    .status();

                let _ = std::process::Command::new("sc.exe")
                    .args(["delete", "CurbService"])
                    .status();
                std::thread::sleep(std::time::Duration::from_millis(300));

                let bin_arg = format!("binPath= \"{}\"", installed_service.display());
                let status = std::process::Command::new("sc.exe")
                    .args([
                        "create",
                        "CurbService",
                        &bin_arg,
                        "start=",
                        "auto",
                        "DisplayName=",
                        "Curb Internet Limiter Service",
                    ])
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        let _ = std::process::Command::new("sc.exe")
                            .args(["start", "CurbService"])
                            .status();
                        println!("CurbService installed and started.");
                    }
                    _ => {
                        eprintln!("Failed to install CurbService. Run from an elevated Administrator prompt.");
                        std::process::exit(1);
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (service_bin, migrate_from);
                eprintln!("Windows service installation is only supported on Windows.");
            }
        }

        Commands::Uninstall => {
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("sc.exe")
                    .args(["stop", "CurbService"])
                    .status();
                let _ = std::process::Command::new("sc.exe")
                    .args(["delete", "CurbService"])
                    .status();
                println!("CurbService removed.");
            }
            #[cfg(not(windows))]
            {
                eprintln!("Windows service uninstallation is only supported on Windows.");
            }
        }
    }
}
