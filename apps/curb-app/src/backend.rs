use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use curb_core::config::{
    BaselinePolicy, Config, EnforcementMode, ExecutableMatcher, NetworkPolicy, PresetsConfig, Rule,
    SubprocessPolicy, VerificationMethod, CURRENT_SCHEMA_VERSION,
};
use curb_core::ipc::{
    BlockedEvent, IpcRequest, IpcResponse, ProtectionTier, RunningAppInfo, ServiceSnapshot,
};
use curb_core::presets::SteamPresetConfig;
use curb_core::steam::DiscoveredSteamGame;
use curb_core::verify::BinaryIdentity;
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

use crate::elevate;
use crate::ipc_client;
use crate::local_mode::{is_standard_mode_configured, LocalStandardRuntime};
use crate::remote::{RemotePeerStore, SavedRemotePeer};

static AUTO_UPGRADE_ATTEMPTED: AtomicBool = AtomicBool::new(false);

struct DemoState {
    snapshot: ServiceSnapshot,
    password: Option<String>,
    running_apps: Vec<RunningAppInfo>,
    steam_games: Vec<DiscoveredSteamGame>,
}

impl DemoState {
    fn new() -> Self {
        let now = Utc::now();
        Self {
            password: None,
            snapshot: ServiceSnapshot {
                password_configured: true,
                has_any_admin: true,
                active_wfp_filters: 14,
                protection_tier: ProtectionTier::FullService,
                service_version: env!("CARGO_PKG_VERSION").to_string(),
                playtime_statuses: Vec::new(),
                remote_status: curb_core::sync::RemoteStatus {
                    device_name: "This PC".into(),
                    relay_url: curb_core::sync::DEFAULT_RELAY_URL.into(),
                    relay_connected: true,
                    relay_state: curb_core::sync::RelayConnectionState::Connected,
                    encrypted_backup_enabled: true,
                    ..Default::default()
                },
                config: Config {
                    schema_version: CURRENT_SCHEMA_VERSION,
                    mode: EnforcementMode::Enforcing,
                    baseline: BaselinePolicy::default(),
                    presets: PresetsConfig {
                        steam: SteamPresetConfig {
                            enabled: true,
                            store_and_library: true,
                            community_and_workshop: false,
                            friends_and_voice: false,
                        },
                        ..Default::default()
                    },
                    playtime_limits_enabled: true,
                    rules: vec![
                        Rule {
                            id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
                            name: "Deep Rock Galactic".into(),
                            enabled: true,
                            exe_hint: "FSD-Win64-Shipping.exe".into(),
                            exe_path: Some(
                                r"D:\SteamLibrary\steamapps\common\Deep Rock Galactic\FSD-Win64-Shipping.exe"
                                    .into(),
                            ),
                            playtime_limit: None,
                            created_at: now,
                            matcher: ExecutableMatcher::SteamGame {
                                app_id: 548430,
                                install_dir: "Deep Rock Galactic".into(),
                                verification: VerificationMethod::Signature {
                                    subject_cn: "Ghost Ship Games ApS".into(),
                                    issuer_cn: None,
                                    product_name: None,
                                    original_filename: Some("FSD-Win64-Shipping.exe".into()),
                                },
                            },
                            network: NetworkPolicy {
                                allow_tcp: true,
                                allow_udp: true,
                                dns_whitelist: None,
                            },
                            subprocesses: SubprocessPolicy::SameSignerOrDir,
                        },
                        Rule {
                            id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
                            name: "Balatro".into(),
                            enabled: true,
                            exe_hint: "Balatro.exe".into(),
                            exe_path: Some(
                                r"C:\Program Files (x86)\Steam\steamapps\common\Balatro\Balatro.exe"
                                    .into(),
                            ),
                            playtime_limit: None,
                            created_at: now,
                            matcher: ExecutableMatcher::SteamGame {
                                app_id: 2379780,
                                install_dir: "Balatro".into(),
                                verification: VerificationMethod::Hash {
                                    sha256: "9f4a82d17c1090ab44e1c21e00a19f02".into(),
                                    filename_hint: "Balatro.exe".into(),
                                },
                            },
                            network: NetworkPolicy {
                                allow_tcp: true,
                                allow_udp: false,
                                dns_whitelist: None,
                            },
                            subprocesses: SubprocessPolicy::Disabled,
                        },
                    ],
                },
                blocked_events: vec![
                    BlockedEvent {
                        id: Uuid::new_v4(),
                        timestamp: now,
                        app_name: "Microsoft Edge".into(),
                        exe: "msedge.exe".into(),
                        path: r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".into(),
                        destination: "youtube.com".into(),
                        signed: true,
                        signer: Some("Microsoft Corporation".into()),
                        is_steam_community: false,
                    },
                    BlockedEvent {
                        id: Uuid::new_v4(),
                        timestamp: now - ChronoDuration::minutes(1),
                        app_name: "Steam Community".into(),
                        exe: "steamwebhelper.exe".into(),
                        path: r"C:\Program Files (x86)\Steam\bin\cef\steamwebhelper.exe".into(),
                        destination: "steamcommunity.com".into(),
                        signed: true,
                        signer: Some("Valve Corp.".into()),
                        is_steam_community: true,
                    },
                    BlockedEvent {
                        id: Uuid::new_v4(),
                        timestamp: now - ChronoDuration::minutes(4),
                        app_name: "Discord".into(),
                        exe: "Discord.exe".into(),
                        path: r"C:\Users\Alex\AppData\Local\Discord\app-1.0.9162\Discord.exe".into(),
                        destination: "discord.gg".into(),
                        signed: true,
                        signer: Some("Discord Inc.".into()),
                        is_steam_community: false,
                    },
                ],
            },
            running_apps: vec![
                RunningAppInfo {
                    key: "run-obsidian".into(),
                    name: "Obsidian".into(),
                    exe: "Obsidian.exe".into(),
                    path: r"C:\Users\Alex\AppData\Local\Obsidian\Obsidian.exe".into(),
                    process_count: 4,
                    background: false,
                    tried_connect: true,
                    tried_host: Some("sync.obsidian.md".into()),
                    signed: true,
                    signer: Some("Dynalist Inc.".into()),
                    sha256: "2b01aa9100ee8811".into(),
                },
                RunningAppInfo {
                    key: "run-discord".into(),
                    name: "Discord".into(),
                    exe: "Discord.exe".into(),
                    path: r"C:\Users\Alex\AppData\Local\Discord\app-1.0.9162\Discord.exe".into(),
                    process_count: 6,
                    background: false,
                    tried_connect: true,
                    tried_host: Some("discord.gg".into()),
                    signed: true,
                    signer: Some("Discord Inc.".into()),
                    sha256: "78cc12ab009911ff".into(),
                },
                RunningAppInfo {
                    key: "run-prism".into(),
                    name: "Prism Launcher".into(),
                    exe: "prismlauncher.exe".into(),
                    path: r"C:\Users\Alex\AppData\Local\Programs\PrismLauncher\prismlauncher.exe".into(),
                    process_count: 1,
                    background: false,
                    tried_connect: false,
                    tried_host: None,
                    signed: false,
                    signer: None,
                    sha256: "6c3a9f2d8e411c9a".into(),
                },
                RunningAppInfo {
                    key: "run-spotify".into(),
                    name: "Spotify".into(),
                    exe: "Spotify.exe".into(),
                    path: r"C:\Users\Alex\AppData\Roaming\Spotify\Spotify.exe".into(),
                    process_count: 5,
                    background: false,
                    tried_connect: false,
                    tried_host: None,
                    signed: true,
                    signer: Some("Spotify AB".into()),
                    sha256: "44ff01ab33229911".into(),
                },
                RunningAppInfo {
                    key: "run-onedrive".into(),
                    name: "Microsoft OneDrive".into(),
                    exe: "OneDrive.exe".into(),
                    path: r"C:\Program Files\Microsoft OneDrive\OneDrive.exe".into(),
                    process_count: 2,
                    background: true,
                    tried_connect: true,
                    tried_host: Some("onedrive.live.com".into()),
                    signed: true,
                    signer: Some("Microsoft Corporation".into()),
                    sha256: "99aa1122bb334455".into(),
                },
                RunningAppInfo {
                    key: "run-tailscale".into(),
                    name: "Tailscale".into(),
                    exe: "tailscaled.exe".into(),
                    path: r"C:\Program Files\Tailscale\tailscaled.exe".into(),
                    process_count: 2,
                    background: true,
                    tried_connect: false,
                    tried_host: None,
                    signed: true,
                    signer: Some("Tailscale Inc.".into()),
                    sha256: "554433221100aabb".into(),
                },
            ],
            steam_games: vec![
                DiscoveredSteamGame {
                    app_id: 1145350,
                    name: "Hades II".into(),
                    install_dir: r"D:\SteamLibrary\steamapps\common\Hades II".into(),
                    exe_path: r"D:\SteamLibrary\steamapps\common\Hades II\Hades2.exe".into(),
                    exe_name: "Hades2.exe".into(),
                    signed: true,
                    signer: Some("Supergiant Games, LLC".into()),
                    sha256: "1029384756abcdef".into(),
                },
                DiscoveredSteamGame {
                    app_id: 553850,
                    name: "HELLDIVERS 2".into(),
                    install_dir: r"D:\SteamLibrary\steamapps\common\Helldivers 2".into(),
                    exe_path: r"D:\SteamLibrary\steamapps\common\Helldivers 2\bin\helldivers2.exe".into(),
                    exe_name: "helldivers2.exe".into(),
                    signed: true,
                    signer: Some("Arrowhead Game Studios AB".into()),
                    sha256: "abcdef1234567890".into(),
                },
                DiscoveredSteamGame {
                    app_id: 413150,
                    name: "Stardew Valley".into(),
                    install_dir: r"C:\Program Files (x86)\Steam\steamapps\common\Stardew Valley".into(),
                    exe_path: r"C:\Program Files (x86)\Steam\steamapps\common\Stardew Valley\Stardew Valley.exe".into(),
                    exe_name: "Stardew Valley.exe".into(),
                    signed: false,
                    signer: None,
                    sha256: "4b8291a033445566".into(),
                },
            ],
        }
    }
}

#[derive(Clone)]
pub struct CurbBackend {
    rt: Arc<Runtime>,
    local: LocalStandardRuntime,
    demo: Option<Arc<Mutex<DemoState>>>,
    remote_store: Arc<Mutex<RemotePeerStore>>,
    active_remote: Arc<Mutex<Option<SavedRemotePeer>>>,
}

impl CurbBackend {
    pub fn new(demo_mode: bool) -> Self {
        let rt = Arc::new(
            Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(1024 * 1024)
                .thread_name("curb-io")
                .enable_all()
                .build()
                .expect("Failed to create Curb async runtime"),
        );
        let local = LocalStandardRuntime::load(rt.handle().clone());
        let demo = if demo_mode {
            Some(Arc::new(Mutex::new(DemoState::new())))
        } else {
            None
        };
        let remote_store = Arc::new(Mutex::new(RemotePeerStore::load_default()));
        Self {
            rt,
            local,
            demo,
            remote_store,
            active_remote: Arc::new(Mutex::new(None)),
        }
    }

    pub fn saved_remote_peers(&self) -> Vec<SavedRemotePeer> {
        self.remote_store.lock().unwrap().peers().to_vec()
    }

    pub fn active_remote_peer(&self) -> Option<SavedRemotePeer> {
        self.active_remote.lock().unwrap().clone()
    }

    pub fn set_active_remote_peer(&self, peer_id: Option<Uuid>) {
        let target = peer_id.and_then(|id| self.remote_store.lock().unwrap().find_by_id(id));
        *self.active_remote.lock().unwrap() = target;
    }

    pub fn spawn<F>(&self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.rt.spawn(fut);
    }

    /// Starts the Standard Mode local proxy at startup if previously configured and FullService is not running.
    pub fn maybe_autostart_standard_proxy(&self) {
        if self.demo.is_some() || !is_standard_mode_configured() {
            return;
        }
        let local = self.local.clone();
        self.spawn(async move {
            if ipc_client::send_request(&IpcRequest::GetSnapshot)
                .await
                .is_err()
            {
                local.ensure_started();
            }
        });
    }

    pub fn deactivate_proxy(&self) {
        if self.demo.is_none() {
            self.local.deactivate_proxy();
        }
    }

    /// Sends an E2E-encrypted remote IPC request to `target_peer_id` via `relay_url`.
    /// When local `curb-service` is running (Full Protection), proxies the already-encrypted
    /// frame through `curb-service` over local IPC so WFP/NFQUEUE never blocks `curb-app`
    /// from reaching the relay while protection is active. Falls back to a direct WebSocket
    /// connection when running without `curb-service` (Standard/Local mode).
    async fn send_remote_p2p(
        &self,
        relay_url: &str,
        target_peer_id: &str,
        req: &IpcRequest,
    ) -> Result<IpcResponse, String> {
        let identity = self.remote_store.lock().unwrap().identity().clone();
        let (request_id, ciphertext) =
            curb_p2p::seal_remote_request(&identity, target_peer_id, req)
                .map_err(|e| e.to_string())?;

        let proxy_req = IpcRequest::RelayForward {
            relay_url: relay_url.to_string(),
            from_peer_id: identity.peer_id(),
            target_peer_id: target_peer_id.to_string(),
            payload: ciphertext.clone(),
        };

        let reply_payload = match ipc_client::send_request(&proxy_req).await {
            Ok(IpcResponse::RelayForwarded { payload }) => payload,
            Ok(IpcResponse::Error { message })
                if !message.starts_with("Malformed IPC request") =>
            {
                return Err(message);
            }
            // Local curb-service not running (Standard/Local mode) or older service without RelayForward:
            // connect directly from curb-app.
            _ => curb_p2p::forward_relay_frame(
                relay_url,
                &identity.peer_id(),
                target_peer_id,
                &ciphertext,
            )
            .await
            .map_err(|e| e.to_string())?,
        };

        curb_p2p::open_remote_response(&identity, target_peer_id, request_id, &reply_payload)
            .map_err(|e| e.to_string())
    }

    /// Dispatches an IPC request to the currently selected target:
    /// - If a remote friend's device is active, sends over E2E-encrypted P2P via `curb-p2p`.
    /// - Otherwise sends to local `CurbService`, falling back to `LocalStandardRuntime`.
    async fn dispatch_request(&self, req: IpcRequest) -> Result<IpcResponse, String> {
        if let Some(peer) = self.active_remote_peer() {
            return self
                .send_remote_p2p(&peer.relay_url, &peer.peer_id, &req)
                .await;
        }
        if let Ok(resp) = ipc_client::send_request(&req).await {
            self.local.clear_standard_mode_for_full_service();
            return Ok(resp);
        }
        let rt = self.local.clone();
        tokio::task::spawn_blocking(move || rt.handle_request(req))
            .await
            .map_err(|e| format!("Internal error: {e}"))
    }

    pub async fn get_snapshot(&self) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            return Ok(demo.lock().unwrap().snapshot.clone());
        }
        match self.dispatch_request(IpcRequest::GetSnapshot).await? {
            IpcResponse::Snapshot { data } => {
                if data.protection_tier == ProtectionTier::FullService
                    && elevate::is_service_outdated(&data.service_version)
                    && !AUTO_UPGRADE_ATTEMPTED.swap(true, Ordering::SeqCst)
                {
                    if tokio::task::spawn_blocking(elevate::launch_elevated_service_install)
                        .await
                        .is_ok_and(|r| r.is_ok())
                    {
                        for _ in 0..24 {
                            if let Ok(IpcResponse::Snapshot { data: upgraded }) =
                                ipc_client::send_request(&IpcRequest::GetSnapshot).await
                            {
                                if !elevate::is_service_outdated(&upgraded.service_version) {
                                    return Ok(upgraded);
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }
                }
                Ok(data)
            }
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn setup_full_protection(&self) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.protection_tier = ProtectionTier::FullService;
            return Ok(g.snapshot.clone());
        }

        tokio::task::spawn_blocking(elevate::launch_elevated_service_install)
            .await
            .map_err(|e| format!("Internal error: {e}"))??;
        elevate::ensure_tray_autostart();

        for _ in 0..24 {
            if let Ok(IpcResponse::Snapshot { data }) =
                ipc_client::send_request(&IpcRequest::GetSnapshot).await
            {
                if !elevate::is_service_outdated(&data.service_version) {
                    self.local.clear_standard_mode_for_full_service();
                    return Ok(data);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Err(
            "CurbService did not start within 12 seconds. Check Windows Services or try again."
                .into(),
        )
    }

    pub async fn uninstall_full_protection(&self) -> Result<(), String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.protection_tier = ProtectionTier::Unconfigured;
            return Ok(());
        }
        tokio::task::spawn_blocking(elevate::launch_elevated_service_uninstall)
            .await
            .map_err(|e| format!("Internal error: {e}"))?
    }

    pub async fn setup_standard_mode(
        &self,
        password: String,
    ) -> Result<(String, ServiceSnapshot), String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.password = Some(password);
            g.snapshot.password_configured = true;
            g.snapshot.protection_tier = ProtectionTier::StandardUser;
            return Ok(("demo-session-token".into(), g.snapshot.clone()));
        }

        let rt = self.local.clone();
        let token = tokio::task::spawn_blocking(move || rt.activate(&password))
            .await
            .map_err(|e| format!("Internal error: {e}"))??;
        elevate::ensure_tray_autostart();
        let snapshot = self.local.snapshot(true);
        Ok((token, snapshot))
    }

    pub async fn list_running_apps(&self) -> Result<Vec<RunningAppInfo>, String> {
        if let Some(demo) = &self.demo {
            return Ok(demo.lock().unwrap().running_apps.clone());
        }
        let adaptors = crate::elevate::service_adaptors();
        let visible_pids = tokio::task::spawn_blocking(move || adaptors.processes.visible_window_pids())
            .await
            .map_err(|e| format!("Internal error: {e}"))?;
        match self
            .dispatch_request(IpcRequest::ListRunningApps {
                visible_pids: Some(visible_pids),
            })
            .await?
        {
            IpcResponse::RunningApps { apps } => Ok(apps),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn list_steam_games(&self) -> Result<Vec<DiscoveredSteamGame>, String> {
        if let Some(demo) = &self.demo {
            return Ok(demo.lock().unwrap().steam_games.clone());
        }
        match self.dispatch_request(IpcRequest::ListSteamGames).await? {
            IpcResponse::SteamGames { games } => Ok(games),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn inspect_executable(&self, path: String) -> Result<BinaryIdentity, String> {
        if self.demo.is_some() {
            let filename = path
                .rsplit(['\\', '/'])
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or("app.exe")
                .to_string();
            let product = filename
                .strip_suffix(".exe")
                .or_else(|| filename.strip_suffix(".EXE"))
                .unwrap_or(&filename)
                .to_string();
            return Ok(BinaryIdentity {
                path,
                filename: filename.clone(),
                sha256: "3f88c01b9d1244aa".into(),
                signature: None,
                product_name: Some(product),
                original_filename: Some(filename),
                file_description: None,
            });
        }
        match self
            .dispatch_request(IpcRequest::InspectExecutable { path })
            .await?
        {
            IpcResponse::Inspected { identity } => Ok(identity),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn unlock(&self, password: String) -> Result<String, String> {
        if let Some(demo) = &self.demo {
            if password.trim().is_empty() {
                return Err("Please enter your Curb password.".into());
            }
            let mut g = demo.lock().unwrap();
            if let Some(expected) = &g.password {
                if expected != &password {
                    return Err("Incorrect Curb password.".into());
                }
            } else {
                g.password = Some(password);
                g.snapshot.password_configured = true;
            }
            return Ok("demo-session-token".into());
        }
        let req = if self.active_remote_peer().is_some() {
            let my_peer_id = self.remote_store.lock().unwrap().identity().peer_id();
            IpcRequest::UnlockAsPeer {
                peer_id: my_peer_id,
                password,
            }
        } else {
            IpcRequest::Unlock { password }
        };
        match self.dispatch_request(req).await? {
            IpcResponse::Unlocked { token } => Ok(token),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn lock(&self, token: String) -> Result<(), String> {
        if self.demo.is_some() {
            return Ok(());
        }
        match self.dispatch_request(IpcRequest::Lock { token }).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    /// Renames the currently active device.
    /// - For a remote friend's device, updates the local display name immediately (no unlock required).
    /// - For the local PC, calls `IpcRequest::RenameDevice` on `curb-service`.
    pub async fn rename_active_device(
        &self,
        token: Option<String>,
        new_name: String,
    ) -> Result<String, String> {
        let trimmed = new_name.trim().to_string();
        if trimmed.is_empty() {
            return Err("Device name cannot be empty.".into());
        }
        if let Some(peer) = self.active_remote_peer() {
            let mut store = self.remote_store.lock().unwrap();
            store.rename_peer(peer.id, &trimmed);
            if let Some(updated) = store.find_by_id(peer.id) {
                *self.active_remote.lock().unwrap() = Some(updated);
            }
            return Ok(trimmed);
        }
        if let Some(demo) = &self.demo {
            demo.lock().unwrap().snapshot.remote_status.device_name = trimmed.clone();
            return Ok(trimmed);
        }
        let token = token.ok_or_else(|| "Unlock Curb first to rename this PC.".to_string())?;
        match self
            .dispatch_request(IpcRequest::RenameDevice {
                token,
                name: trimmed.clone(),
            })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data.remote_status.device_name),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    /// Generates a single-use short invite code (or `curb://join?...` link) for adding a friend admin.
    /// `token` may be `None` during initial setup before any admin has been configured.
    pub async fn create_friend_invite(&self, token: Option<String>) -> Result<String, String> {
        if self.demo.is_some() {
            return Ok("DEMO-1234-5678-ABCD".into());
        }
        match self
            .dispatch_request(IpcRequest::CreateInvite {
                token: token.unwrap_or_default(),
                kind: curb_core::sync::InviteKind::FriendAdmin,
            })
            .await?
        {
            IpcResponse::InviteCreated { short_uri, uri, .. } => {
                if !short_uri.trim().is_empty() {
                    Ok(short_uri)
                } else {
                    Ok(uri)
                }
            }
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    async fn fetch_invite_descriptor_proxied(
        &self,
        relay_url: &str,
        code: &str,
    ) -> Result<curb_core::sync::InviteDescriptor, String> {
        let slot_id = curb_core::sync::invite_slot_id(code);
        let proxy_req = IpcRequest::RelayFetchInvite {
            relay_url: relay_url.to_string(),
            slot_id: slot_id.clone(),
        };
        let blob_b64 = match ipc_client::send_request(&proxy_req).await {
            Ok(IpcResponse::RelayInviteData { blob_b64 }) => blob_b64,
            Ok(IpcResponse::Error { message })
                if !message.starts_with("Malformed IPC request") =>
            {
                return Err(message);
            }
            _ => curb_p2p::fetch_invite_descriptor_b64(relay_url, &slot_id)
                .await
                .map_err(|e| e.to_string())?,
        };
        curb_p2p::decrypt_invite_descriptor_b64(code, &blob_b64).map_err(|e| e.to_string())
    }

    async fn submit_invite_claim_proxied(
        &self,
        relay_url: &str,
        code: &str,
        from_peer_id: &str,
        payload: &str,
    ) -> Result<(), String> {
        let slot_id = curb_core::sync::invite_slot_id(code);
        let proxy_req = IpcRequest::RelayClaimInvite {
            relay_url: relay_url.to_string(),
            slot_id: slot_id.clone(),
            from_peer_id: from_peer_id.to_string(),
            payload: payload.to_string(),
        };
        match ipc_client::send_request(&proxy_req).await {
            Ok(IpcResponse::Ok) => Ok(()),
            Ok(IpcResponse::Error { message })
                if !message.starts_with("Malformed IPC request") =>
            {
                Err(message)
            }
            _ => curb_p2p::submit_invite_claim(relay_url, &slot_id, from_peer_id, payload)
                .await
                .map_err(|e| e.to_string()),
        }
    }

    /// Queries online/last-seen presence for all saved remote peers grouped by their relay URL.
    pub async fn check_saved_peers_presence(
        &self,
    ) -> std::collections::HashMap<String, curb_core::sync::PeerPresence> {
        let mut result = std::collections::HashMap::new();
        if self.demo.is_some() {
            return result;
        }
        let saved = self.saved_remote_peers();
        if saved.is_empty() {
            return result;
        }
        let mut by_relay: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for p in saved {
            if !p.relay_url.trim().is_empty() {
                by_relay.entry(p.relay_url).or_default().push(p.peer_id);
            }
        }
        for (relay_url, peer_ids) in by_relay {
            let proxy_req = IpcRequest::RelayCheckPresence {
                relay_url: relay_url.clone(),
                peer_ids: peer_ids.clone(),
            };
            let peers = match ipc_client::send_request(&proxy_req).await {
                Ok(IpcResponse::RelayPresence { peers }) => Ok(peers),
                _ => curb_p2p::fetch_peers_presence(&relay_url, &peer_ids).await,
            };
            if let Ok(list) = peers {
                for p in list {
                    result.insert(p.peer_id.clone(), p);
                }
            }
        }
        result
    }

    /// Redeems a one-time short code, `curb://join?...` link, or legacy `curb://invite?...` link.
    /// Attempts instant online redemption first; if the host PC is offline, stores an E2E-encrypted
    /// claim in `curb-relay`'s invite dropbox so the host applies it automatically on wake.
    ///
    /// Returns `(saved_peer, pending_offline)`.
    pub async fn connect_with_invite(
        &self,
        invite_input: String,
        my_name: String,
        my_password: String,
    ) -> Result<(SavedRemotePeer, bool), String> {
        let parsed = curb_core::sync::ParsedInviteInput::parse(&invite_input)
            .map_err(|e| e.to_string())?;
        let (code, relay_url, target_peer_id, fallback_device_name) = match parsed {
            curb_core::sync::ParsedInviteInput::Full(tok) => (
                tok.code,
                tok.relay_url,
                tok.target_peer_id,
                tok.device_name,
            ),
            curb_core::sync::ParsedInviteInput::Short { code, relay_url } => {
                let desc = self
                    .fetch_invite_descriptor_proxied(&relay_url, &code)
                    .await?;
                (code, relay_url, desc.target_peer_id, desc.device_name)
            }
        };

        let identity = self.remote_store.lock().unwrap().identity().clone();
        let req = IpcRequest::RedeemInvite {
            code: code.clone(),
            peer_id: identity.peer_id(),
            name: my_name,
            password: my_password,
        };

        match self
            .send_remote_p2p(&relay_url, &target_peer_id, &req)
            .await
        {
            Ok(IpcResponse::InviteRedeemed {
                device_name,
                peer_id,
                ..
            }) => {
                let saved = self.remote_store.lock().unwrap().upsert_peer(
                    device_name,
                    peer_id,
                    relay_url,
                );
                *self.active_remote.lock().unwrap() = Some(saved.clone());
                Ok((saved, false))
            }
            Ok(IpcResponse::Error { message }) => Err(message),
            Ok(_) => Err("Unexpected response while redeeming invite".into()),
            Err(err) if err.contains("offline") || err.contains("Timed out") => {
                // Host PC is offline — fall back to the relay's zero-knowledge offline claim dropbox.
                let (_, ciphertext) =
                    curb_p2p::seal_remote_request(&identity, &target_peer_id, &req)
                        .map_err(|e| e.to_string())?;
                self.submit_invite_claim_proxied(
                    &relay_url,
                    &code,
                    &identity.peer_id(),
                    &ciphertext,
                )
                .await?;
                let saved = self.remote_store.lock().unwrap().upsert_peer(
                    fallback_device_name,
                    target_peer_id,
                    relay_url,
                );
                Ok((saved, true))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn remove_admin(
        &self,
        token: String,
        admin_id: Uuid,
    ) -> Result<ServiceSnapshot, String> {
        match self
            .dispatch_request(IpcRequest::RemoveAdmin { token, admin_id })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn remove_local_password(&self, token: String) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.password = None;
            g.snapshot.password_configured = false;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::RemoveLocalPassword { token })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn set_relay_config(
        &self,
        token: String,
        relay_url: String,
        encrypted_backup_enabled: bool,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            let trimmed = relay_url.trim().to_string();
            g.snapshot.remote_status.relay_url = trimmed.clone();
            g.snapshot.remote_status.relay_connected = !trimmed.is_empty();
            g.snapshot.remote_status.relay_state = if trimmed.is_empty() {
                curb_core::sync::RelayConnectionState::Disabled
            } else {
                curb_core::sync::RelayConnectionState::Connected
            };
            g.snapshot.remote_status.relay_error = None;
            g.snapshot.remote_status.encrypted_backup_enabled = encrypted_backup_enabled;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::SetRelayConfig {
                token,
                relay_url,
                encrypted_backup_enabled,
            })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn retry_relay_connection(&self) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            let has_url = !g.snapshot.remote_status.relay_url.trim().is_empty();
            g.snapshot.remote_status.relay_connected = has_url;
            g.snapshot.remote_status.relay_state = if has_url {
                curb_core::sync::RelayConnectionState::Connected
            } else {
                curb_core::sync::RelayConnectionState::Disabled
            };
            g.snapshot.remote_status.relay_error = None;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::RetryRelayConnection)
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn set_mode(
        &self,
        token: String,
        mode: EnforcementMode,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.config.mode = mode;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::SetMode { token, mode })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn update_steam_preset(
        &self,
        token: String,
        steam: SteamPresetConfig,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.config.presets.steam = steam;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::UpdateSteamPreset { token, steam })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn update_baseline(
        &self,
        token: String,
        baseline: BaselinePolicy,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.config.baseline = baseline;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::UpdateBaseline { token, baseline })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn upsert_rule(&self, token: String, rule: Rule) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            let exe_lower = rule.exe_hint.to_ascii_lowercase();
            if let Some(existing) = g
                .snapshot
                .config
                .rules
                .iter_mut()
                .find(|r| r.id == rule.id)
            {
                *existing = rule;
            } else {
                g.snapshot.config.rules.insert(0, rule);
            }
            g.snapshot
                .blocked_events
                .retain(|b| b.exe.to_ascii_lowercase() != exe_lower);
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::UpsertRule { token, rule })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn delete_rule(&self, token: String, id: Uuid) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.config.rules.retain(|r| r.id != id);
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::DeleteRule { token, id })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn set_playtime_limits_enabled(
        &self,
        token: String,
        enabled: bool,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            g.snapshot.config.playtime_limits_enabled = enabled;
            return Ok(g.snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::SetPlaytimeLimitsEnabled { token, enabled })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn reset_playtime_limit(
        &self,
        token: String,
        rule_id: Uuid,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            return Ok(demo.lock().unwrap().snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::ResetPlaytimeLimit { token, rule_id })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn reset_all_playtime_limits(
        &self,
        token: String,
    ) -> Result<ServiceSnapshot, String> {
        if let Some(demo) = &self.demo {
            return Ok(demo.lock().unwrap().snapshot.clone());
        }
        match self
            .dispatch_request(IpcRequest::ResetAllPlaytimeLimits { token })
            .await?
        {
            IpcResponse::Snapshot { data } => Ok(data),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }

    pub async fn change_password(
        &self,
        token: String,
        current_password: String,
        new_password: String,
    ) -> Result<(), String> {
        if let Some(demo) = &self.demo {
            let mut g = demo.lock().unwrap();
            if let Some(expected) = &g.password {
                if expected != &current_password {
                    return Err("Current password is incorrect.".into());
                }
            }
            if new_password.len() < 4 {
                return Err("Password must be at least 4 characters.".into());
            }
            g.password = Some(new_password);
            return Ok(());
        }
        match self
            .dispatch_request(IpcRequest::ChangePassword {
                token,
                current_password,
                new_password,
            })
            .await?
        {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error { message } => Err(message),
            _ => Err("Unexpected response from Curb".into()),
        }
    }
}
