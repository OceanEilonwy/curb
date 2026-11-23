mod ipc_client;

use curb_core::config::{BaselinePolicy, EnforcementMode, Rule};
use curb_core::ipc::{IpcRequest, IpcResponse, RunningAppInfo, ServiceSnapshot};
use curb_core::presets::SteamPresetConfig;
use curb_core::steam::DiscoveredSteamGame;
use curb_core::verify::BinaryIdentity;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use uuid::Uuid;

#[tauri::command]
async fn get_snapshot() -> Result<ServiceSnapshot, String> {
    match ipc_client::send_request(&IpcRequest::GetSnapshot).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn list_running_apps() -> Result<Vec<RunningAppInfo>, String> {
    match ipc_client::send_request(&IpcRequest::ListRunningApps).await? {
        IpcResponse::RunningApps { apps } => Ok(apps),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn list_steam_games() -> Result<Vec<DiscoveredSteamGame>, String> {
    match ipc_client::send_request(&IpcRequest::ListSteamGames).await? {
        IpcResponse::SteamGames { games } => Ok(games),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn inspect_executable(path: String) -> Result<BinaryIdentity, String> {
    match ipc_client::send_request(&IpcRequest::InspectExecutable { path }).await? {
        IpcResponse::Inspected { identity } => Ok(identity),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn unlock(password: String) -> Result<String, String> {
    match ipc_client::send_request(&IpcRequest::Unlock { password }).await? {
        IpcResponse::Unlocked { token } => Ok(token),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn lock(token: String) -> Result<(), String> {
    match ipc_client::send_request(&IpcRequest::Lock { token }).await? {
        IpcResponse::Ok => Ok(()),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn set_mode(token: String, mode: EnforcementMode) -> Result<ServiceSnapshot, String> {
    match ipc_client::send_request(&IpcRequest::SetMode { token, mode }).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn update_steam_preset(
    token: String,
    steam: SteamPresetConfig,
) -> Result<ServiceSnapshot, String> {
    match ipc_client::send_request(&IpcRequest::UpdateSteamPreset { token, steam }).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn update_baseline(
    token: String,
    baseline: BaselinePolicy,
) -> Result<ServiceSnapshot, String> {
    match ipc_client::send_request(&IpcRequest::UpdateBaseline { token, baseline }).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn upsert_rule(token: String, rule: Rule) -> Result<ServiceSnapshot, String> {
    match ipc_client::send_request(&IpcRequest::UpsertRule { token, rule }).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn delete_rule(token: String, id: Uuid) -> Result<ServiceSnapshot, String> {
    match ipc_client::send_request(&IpcRequest::DeleteRule { token, id }).await? {
        IpcResponse::Snapshot { data } => Ok(data),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

#[tauri::command]
async fn change_password(
    token: String,
    current_password: String,
    new_password: String,
) -> Result<(), String> {
    match ipc_client::send_request(&IpcRequest::ChangePassword {
        token,
        current_password,
        new_password,
    })
    .await?
    {
        IpcResponse::Ok => Ok(()),
        IpcResponse::Error { message } => Err(message),
        _ => Err("Unexpected response from Curb service".into()),
    }
}

/// Revokes any active admin token and destroys the WebView2 window so Curb
/// uses near-zero RAM while sitting quietly in the taskbar tray.
#[tauri::command]
async fn hide_to_tray(app: AppHandle, token: Option<String>) -> Result<(), String> {
    if let Some(t) = token {
        let _ = ipc_client::send_request(&IpcRequest::Lock { token: t }).await;
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.destroy();
    }
    Ok(())
}

/// Opens or focuses the compact 480x600 Curb window on demand from the tray icon.
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
    tauri::Builder::default()
        .setup(|app| {
            let open_item = MenuItem::with_id(app, "open", "Open Curb", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "Exit Tray Icon", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_item, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::new()
                .tooltip("Curb — Internet Limiter")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => open_or_focus_main_window(app),
                    "quit" => app.exit(0),
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
        .run(|_app_handle, event| {
            // Keep the tray app alive when the main WebView window is destroyed.
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}
