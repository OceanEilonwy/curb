mod elevate;
mod ipc_client;
mod local_mode;

use std::time::Duration;

use curb_core::config::{BaselinePolicy, EnforcementMode, Rule};
use curb_core::ipc::{IpcRequest, IpcResponse, RunningAppInfo, ServiceSnapshot};
use curb_core::presets::SteamPresetConfig;
use curb_core::steam::DiscoveredSteamGame;
use curb_core::verify::BinaryIdentity;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder};
use uuid::Uuid;

use crate::local_mode::{is_standard_mode_configured, LocalStandardRuntime};

/// Dispatches an IPC request to `CurbService` (Full Protection) when available,
/// transparently falling back to the embedded `LocalStandardRuntime` (Standard Mode
/// or Unconfigured first-run state).
async fn dispatch_request(
    req: IpcRequest,
    local: &LocalStandardRuntime,
) -> Result<IpcResponse, String> {
    if let Ok(resp) = ipc_client::send_request(&req).await {
        return Ok(resp);
    }
    let rt = local.clone();
    tokio::task::spawn_blocking(move || rt.handle_request(req))
        .await
        .map_err(|e| format!("Internal error: {e}"))
}

#[tauri::command]
async fn get_snapshot(local: State<'_, LocalStandardRuntime>) -> Result<ServiceSnapshot, String> {
    match dispatch_request(IpcRequest::GetSnapshot, &local).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn setup_full_protection(
    app: AppHandle,
    local: State<'_, LocalStandardRuntime>,
) -> Result<ServiceSnapshot, String> {
    elevate::launch_elevated_service_install(&app)?;
    elevate::ensure_tray_autostart();

    // Wait briefly for CurbService to start and open its Named Pipe.
    for _ in 0..24 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(IpcResponse::Snapshot { data }) =
            ipc_client::send_request(&IpcRequest::GetSnapshot).await
        {
            // Cleanly turn off Standard Mode's HKCU proxy now that Full Protection is live.
            local.deactivate_proxy();
            return Ok(data);
        }
    }

    Err(
        "CurbService did not start within 12 seconds. Check Windows Services or try again."
            .into(),
    )
}

#[tauri::command]
async fn uninstall_full_protection(app: AppHandle) -> Result<(), String> {
    elevate::launch_elevated_service_uninstall(&app)
}

#[tauri::command]
async fn setup_standard_mode(
    password: String,
    local: State<'_, LocalStandardRuntime>,
) -> Result<(String, ServiceSnapshot), String> {
    let rt = local.inner().clone();
    let token = tokio::task::spawn_blocking(move || rt.activate(&password))
        .await
        .map_err(|e| format!("Internal error: {e}"))??;
    elevate::ensure_tray_autostart();
    let snapshot = local.snapshot(true);
    Ok((token, snapshot))
}

#[tauri::command]
async fn list_running_apps(
    local: State<'_, LocalStandardRuntime>,
) -> Result<Vec<RunningAppInfo>, String> {
    let visible_pids = tokio::task::spawn_blocking(curb_core::processes::visible_window_pids)
        .await
        .map_err(|e| format!("Internal error: {e}"))?;
    match dispatch_request(
        IpcRequest::ListRunningApps {
            visible_pids: Some(visible_pids),
        },
        &local,
    )
    .await?
    {
        IpcResponse::RunningApps { apps } => Ok(apps),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn list_steam_games(
    local: State<'_, LocalStandardRuntime>,
) -> Result<Vec<DiscoveredSteamGame>, String> {
    match dispatch_request(IpcRequest::ListSteamGames, &local).await? {
        IpcResponse::SteamGames { games } => Ok(games),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn inspect_executable(
    path: String,
    local: State<'_, LocalStandardRuntime>,
) -> Result<BinaryIdentity, String> {
    match dispatch_request(IpcRequest::InspectExecutable { path }, &local).await? {
        IpcResponse::Inspected { identity } => Ok(identity),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn unlock(
    password: String,
    local: State<'_, LocalStandardRuntime>,
) -> Result<String, String> {
    match dispatch_request(IpcRequest::Unlock { password }, &local).await? {
        IpcResponse::Unlocked { token } => Ok(token),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn lock(token: String, local: State<'_, LocalStandardRuntime>) -> Result<(), String> {
    match dispatch_request(IpcRequest::Lock { token }, &local).await? {
        IpcResponse::Ok => Ok(()),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn set_mode(
    token: String,
    mode: EnforcementMode,
    local: State<'_, LocalStandardRuntime>,
) -> Result<ServiceSnapshot, String> {
    match dispatch_request(IpcRequest::SetMode { token, mode }, &local).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn update_steam_preset(
    token: String,
    steam: SteamPresetConfig,
    local: State<'_, LocalStandardRuntime>,
) -> Result<ServiceSnapshot, String> {
    match dispatch_request(IpcRequest::UpdateSteamPreset { token, steam }, &local).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn update_baseline(
    token: String,
    baseline: BaselinePolicy,
    local: State<'_, LocalStandardRuntime>,
) -> Result<ServiceSnapshot, String> {
    match dispatch_request(IpcRequest::UpdateBaseline { token, baseline }, &local).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn upsert_rule(
    token: String,
    rule: Rule,
    local: State<'_, LocalStandardRuntime>,
) -> Result<ServiceSnapshot, String> {
    match dispatch_request(IpcRequest::UpsertRule { token, rule }, &local).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn delete_rule(
    token: String,
    id: Uuid,
    local: State<'_, LocalStandardRuntime>,
) -> Result<ServiceSnapshot, String> {
    match dispatch_request(IpcRequest::DeleteRule { token, id }, &local).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn change_password(
    token: String,
    current_password: String,
    new_password: String,
    local: State<'_, LocalStandardRuntime>,
) -> Result<(), String> {
    match dispatch_request(
        IpcRequest::ChangePassword {
            token,
            current_password,
            new_password,
        },
        &local,
    )
    .await?
    {
        IpcResponse::Ok => Ok(()),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb".into()),
    }
}

#[tauri::command]
async fn hide_to_tray(
    app: AppHandle,
    token: Option<String>,
    local: State<'_, LocalStandardRuntime>,
) -> Result<(), String> {
    if let Some(t) = token {
        let _ = dispatch_request(IpcRequest::Lock { token: t }, &local).await;
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.destroy();
    }
    Ok(())
}

fn open_or_focus_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }

    let _ = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Curb")
        .inner_size(480.0, 600.0)
        .resizable(false)
        .decorations(false)
        .center()
        .build();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let local_runtime = LocalStandardRuntime::load();
    let tray_runtime = local_runtime.clone();

    tauri::Builder::default()
        .manage(local_runtime)
        .setup(move |app| {
            // If Standard Mode was previously selected (and Full Service is not running), start proxy now.
            if is_standard_mode_configured() {
                let rt = tray_runtime.clone();
                tauri::async_runtime::spawn(async move {
                    if ipc_client::send_request(&IpcRequest::GetSnapshot)
                        .await
                        .is_err()
                    {
                        rt.ensure_started();
                    }
                });
            }

            let open_item = MenuItem::with_id(app, "open", "Open Curb", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "Exit Tray Icon", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .tooltip("Curb — Internet Limiter")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => open_or_focus_main_window(app),
                    "quit" => {
                        app.state::<LocalStandardRuntime>().deactivate_proxy();
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        open_or_focus_main_window(tray.app_handle());
                    }
                });

            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }
            let _ = tray_builder.build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            setup_full_protection,
            uninstall_full_protection,
            setup_standard_mode,
            list_running_apps,
            list_steam_games,
            inspect_executable,
            unlock,
            lock,
            set_mode,
            update_steam_preset,
            update_baseline,
            upsert_rule,
            delete_rule,
            change_password,
            hide_to_tray,
        ])
        .build(tauri::generate_context!())
        .expect("error building Curb Tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                } else {
                    app_handle.state::<LocalStandardRuntime>().deactivate_proxy();
                }
            }
        });
}
