use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use curb_core::auth::{hash_password, verify_password, AuthRecord, SessionManager};
use curb_core::config::Config;
use curb_core::dns::domain_matches_any;
use curb_core::ipc::{
    BlockedEvent, IpcRequest, IpcResponse, ProtectionTier, ServiceSnapshot,
};
use curb_core::steam::{discover_steam_games, find_default_steam_root};
use curb_core::store::{load_auth, load_config, save_auth, save_config};
use curb_core::verify::inspect_binary;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use uuid::Uuid;

pub const LOCAL_PROXY_PORT: u16 = 48921;
const MAX_BLOCKED: usize = 100;

/// Returns the per-user Curb data directory (`%LOCALAPPDATA%\Curb` on Windows).
pub fn user_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("Curb");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/curb-user");
    }
    PathBuf::from("/tmp/curb-user")
}

pub fn standard_mode_marker(dir: &Path) -> PathBuf {
    dir.join("standard_mode.flag")
}

pub fn is_standard_mode_configured() -> bool {
    standard_mode_marker(&user_data_dir()).exists()
}

pub struct LocalEngineState {
    pub data_dir: PathBuf,
    pub config: Config,
    pub auth: Option<AuthRecord>,
    pub sessions: SessionManager,
    pub blocked_events: VecDeque<BlockedEvent>,
    pub proxy_started: bool,
}

#[derive(Clone)]
pub struct LocalStandardRuntime {
    pub state: Arc<Mutex<LocalEngineState>>,
    rt_handle: Handle,
}

impl LocalStandardRuntime {
    pub fn load(rt_handle: Handle) -> Self {
        let data_dir = user_data_dir();
        let config = load_config(&data_dir).unwrap_or_default();
        let auth = load_auth(&data_dir).ok().flatten();
        Self {
            state: Arc::new(Mutex::new(LocalEngineState {
                data_dir,
                config,
                auth,
                sessions: SessionManager::default(),
                blocked_events: VecDeque::with_capacity(MAX_BLOCKED),
                proxy_started: false,
            })),
            rt_handle,
        }
    }

    /// Initializes Standard Mode (writes marker, sets initial password, starts local proxy + HKCU proxy).
    pub fn activate(&self, initial_password: &str) -> Result<String, String> {
        let mut guard = self.state.lock().unwrap();
        let record = hash_password(initial_password).map_err(|e| e.to_string())?;
        save_auth(&guard.data_dir, &record).map_err(|e| e.to_string())?;
        save_config(&guard.data_dir, &guard.config).map_err(|e| e.to_string())?;
        let _ = std::fs::write(standard_mode_marker(&guard.data_dir), b"standard");

        let token = guard
            .sessions
            .unlock(initial_password, &record)
            .map_err(|e| e.to_string())?;
        guard.auth = Some(record);

        let should_start = !guard.proxy_started;
        guard.proxy_started = true;
        let enforcing = guard.config.mode.is_actively_enforcing(Utc::now());
        drop(guard);

        if should_start {
            self.spawn_proxy();
        }
        set_windows_user_proxy(enforcing);
        Ok(token)
    }

    /// Ensures the local proxy is running when launching in an already-configured Standard Mode.
    pub fn ensure_started(&self) {
        let (should_start, enforcing) = {
            let mut guard = self.state.lock().unwrap();
            let start = !guard.proxy_started;
            guard.proxy_started = true;
            (start, guard.config.mode.is_actively_enforcing(Utc::now()))
        };
        if should_start {
            self.spawn_proxy();
        }
        set_windows_user_proxy(enforcing);
    }

    /// Disables the HKCU proxy (called when exiting the tray or upgrading to Full Protection).
    pub fn deactivate_proxy(&self) {
        set_windows_user_proxy(false);
    }

    /// Disables Standard Mode's HKCU proxy and removes `standard_mode.flag` once
    /// Full Protection (`CurbService`) is active so the two modes never conflict.
    pub fn clear_standard_mode_for_full_service(&self) {
        set_windows_user_proxy(false);
        let _ = std::fs::remove_file(standard_mode_marker(&user_data_dir()));
    }

    fn spawn_proxy(&self) {
        let runtime = self.clone();
        self.rt_handle.spawn(async move {
            let addr = format!("127.0.0.1:{LOCAL_PROXY_PORT}");
            let Ok(listener) = TcpListener::bind(&addr).await else {
                return;
            };
            while let Ok((stream, _)) = listener.accept().await {
                let rt = runtime.clone();
                tokio::spawn(async move {
                    let _ = handle_proxy_conn(stream, rt).await;
                });
            }
        });
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        let guard = self.state.lock().unwrap();
        if !guard.config.mode.is_actively_enforcing(Utc::now()) {
            return true;
        }
        let mut allowed_domains = guard.config.presets.steam.webhelper_domains();
        for rule in &guard.config.rules {
            if rule.enabled {
                match &rule.network.dns_whitelist {
                    Some(domains) => allowed_domains.extend(domains.iter().cloned()),
                    None => return true,
                }
            }
        }
        if guard.config.baseline.ncsi {
            allowed_domains.push("www.msftconnecttest.com".into());
            allowed_domains.push("www.msftncsi.com".into());
        }
        domain_matches_any(host, &allowed_domains)
    }

    fn record_blocked(&self, host: String) {
        let mut guard = self.state.lock().unwrap();
        if guard.blocked_events.len() >= MAX_BLOCKED {
            guard.blocked_events.pop_back();
        }
        let is_steam_community = host.to_ascii_lowercase().contains("steamcommunity.com");
        guard.blocked_events.push_front(BlockedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            app_name: if is_steam_community {
                "Steam Community".into()
            } else {
                "Browser / App".into()
            },
            exe: "proxy".into(),
            path: String::new(),
            destination: host,
            signed: false,
            signer: None,
            is_steam_community,
        });
    }

    pub fn snapshot(&self, configured: bool) -> ServiceSnapshot {
        let guard = self.state.lock().unwrap();
        ServiceSnapshot {
            config: guard.config.clone(),
            password_configured: guard.auth.is_some(),
            blocked_events: guard.blocked_events.iter().cloned().collect(),
            active_wfp_filters: 0,
            protection_tier: if configured {
                ProtectionTier::StandardUser
            } else {
                ProtectionTier::Unconfigured
            },
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn handle_request(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::GetSnapshot => IpcResponse::Snapshot {
                data: self.snapshot(is_standard_mode_configured()),
            },
            IpcRequest::ListRunningApps { visible_pids } => {
                let blocked_snapshot = {
                    let guard = self.state.lock().unwrap();
                    guard.blocked_events.iter().cloned().collect::<Vec<_>>()
                };
                let apps = curb_core::processes::collect_running_apps(
                    &blocked_snapshot,
                    visible_pids.as_deref(),
                );
                IpcResponse::RunningApps { apps }
            }
            IpcRequest::ListSteamGames => {
                let games = find_default_steam_root()
                    .and_then(|root| discover_steam_games(&root).ok())
                    .unwrap_or_default();
                IpcResponse::SteamGames { games }
            }
            IpcRequest::InspectExecutable { path } => match inspect_binary(Path::new(&path)) {
                Ok(identity) => IpcResponse::Inspected { identity },
                Err(e) => IpcResponse::Error {
                    message: format!("Could not inspect file: {e}"),
                },
            },
            IpcRequest::Unlock { password } => {
                let mut guard = self.state.lock().unwrap();
                let Some(record) = guard.auth.clone() else {
                    return match hash_password(&password) {
                        Ok(new_record) => {
                            let _ = save_auth(&guard.data_dir, &new_record);
                            let token = guard.sessions.unlock(&password, &new_record).unwrap();
                            guard.auth = Some(new_record);
                            IpcResponse::Unlocked { token }
                        }
                        Err(e) => IpcResponse::Error {
                            message: e.to_string(),
                        },
                    };
                };
                match guard.sessions.unlock(&password, &record) {
                    Ok(token) => IpcResponse::Unlocked { token },
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            IpcRequest::Lock { token } => {
                self.state.lock().unwrap().sessions.lock(&token);
                IpcResponse::Ok
            }
            IpcRequest::SetMode { token, mode } => {
                let resp = self.mutate(&token, |cfg| cfg.mode = mode);
                if matches!(resp, IpcResponse::Snapshot { .. }) {
                    let enforcing = self
                        .state
                        .lock()
                        .unwrap()
                        .config
                        .mode
                        .is_actively_enforcing(Utc::now());
                    set_windows_user_proxy(enforcing);
                }
                resp
            }
            IpcRequest::UpdateSteamPreset { token, steam } => {
                self.mutate(&token, |cfg| cfg.presets.steam = steam)
            }
            IpcRequest::UpdateBaseline { token, baseline } => {
                self.mutate(&token, |cfg| cfg.baseline = baseline)
            }
            IpcRequest::UpsertRule { token, rule } => self.mutate(&token, |cfg| {
                if let Some(existing) = cfg.rules.iter_mut().find(|r| r.id == rule.id) {
                    *existing = rule;
                } else {
                    cfg.rules.insert(0, rule);
                }
            }),
            IpcRequest::DeleteRule { token, id } => {
                self.mutate(&token, |cfg| cfg.rules.retain(|r| r.id != id))
            }
            IpcRequest::ChangePassword {
                token,
                current_password,
                new_password,
            } => {
                let mut guard = self.state.lock().unwrap();
                if !guard.sessions.validate_and_refresh(&token) {
                    return IpcResponse::Error {
                        message: "Admin session expired. Please unlock again.".into(),
                    };
                }
                if let Some(record) = &guard.auth {
                    if !verify_password(&current_password, record) {
                        return IpcResponse::Error {
                            message: "Current password is incorrect.".into(),
                        };
                    }
                }
                match hash_password(&new_password) {
                    Ok(new_record) => {
                        if let Err(e) = save_auth(&guard.data_dir, &new_record) {
                            return IpcResponse::Error {
                                message: format!("Failed to save password: {e}"),
                            };
                        }
                        guard.auth = Some(new_record);
                        guard.sessions.lock_all_except(&token);
                        IpcResponse::Ok
                    }
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
        }
    }

    fn mutate<F: FnOnce(&mut Config)>(&self, token: &str, f: F) -> IpcResponse {
        let mut guard = self.state.lock().unwrap();
        if !guard.sessions.validate_and_refresh(token) {
            return IpcResponse::Error {
                message: "Admin session locked or expired. Please unlock again.".into(),
            };
        }
        f(&mut guard.config);
        if let Err(e) = save_config(&guard.data_dir, &guard.config) {
            return IpcResponse::Error {
                message: format!("Failed to save config: {e}"),
            };
        }
        drop(guard);
        IpcResponse::Snapshot {
            data: self.snapshot(true),
        }
    }
}

async fn handle_proxy_conn(
    mut client: TcpStream,
    runtime: LocalStandardRuntime,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut client);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }

    // Drain remaining request headers
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line);
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    let (host, port) = if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = target.rsplit_once(':').unwrap_or((target, "443"));
        (h.to_string(), p.parse::<u16>().unwrap_or(443))
    } else {
        let stripped = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
            .unwrap_or(target);
        let authority = stripped.split('/').next().unwrap_or(stripped);
        let (h, p) = authority.rsplit_once(':').unwrap_or((authority, "80"));
        (h.to_string(), p.parse::<u16>().unwrap_or(80))
    };

    drop(reader);

    if !runtime.is_host_allowed(&host) {
        runtime.record_blocked(host);
        let _ = client
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by Curb (Standard Mode)\r\n",
            )
            .await;
        return Ok(());
    }

    let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
    if method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        upstream.write_all(request_line.as_bytes()).await?;
        for h in headers {
            upstream.write_all(h.as_bytes()).await?;
        }
        upstream.write_all(b"\r\n").await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Configures Windows per-user proxy settings in HKCU (requires zero admin rights).
fn set_windows_user_proxy(enable: bool) {
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
            REG_DWORD, REG_SZ,
        };

        let subkey: Vec<u16> =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
                .encode_utf16()
                .collect();
        unsafe {
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
            .is_ok()
            {
                let enable_name: Vec<u16> = "ProxyEnable\0".encode_utf16().collect();
                let enable_val: u32 = if enable { 1 } else { 0 };
                let _ = RegSetValueExW(
                    hkey,
                    PCWSTR(enable_name.as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&enable_val.to_le_bytes()),
                );

                if enable {
                    let server_name: Vec<u16> = "ProxyServer\0".encode_utf16().collect();
                    let server_val: Vec<u16> = format!("127.0.0.1:{LOCAL_PROXY_PORT}\0")
                        .encode_utf16()
                        .collect();
                    let bytes = std::slice::from_raw_parts(
                        server_val.as_ptr() as *const u8,
                        server_val.len() * 2,
                    );
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(server_name.as_ptr()),
                        0,
                        REG_SZ,
                        Some(bytes),
                    );

                    let override_name: Vec<u16> = "ProxyOverride\0".encode_utf16().collect();
                    let override_val: Vec<u16> =
                        "localhost;127.0.0.1;<local>\0".encode_utf16().collect();
                    let obytes = std::slice::from_raw_parts(
                        override_val.as_ptr() as *const u8,
                        override_val.len() * 2,
                    );
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(override_name.as_ptr()),
                        0,
                        REG_SZ,
                        Some(obytes),
                    );
                }
                let _ = RegCloseKey(hkey);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = enable;
    }
}
