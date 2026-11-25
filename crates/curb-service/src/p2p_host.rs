use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use curb_core::sync::SyncBundle;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::engine::ServiceEngine;

/// Background P2P host & optional encrypted backup supervisor for `curb-service`.
///
/// Watches `ServiceEngine`'s `RemoteSyncConfig`:
/// - Whenever `relay_url` is non-empty, maintains a P2P host connection to `curb-relay`
///   dispatching E2E-encrypted remote IPC requests directly into `ServiceEngine`.
/// - Whenever the config revision advances and `encrypted_backup_enabled` is true,
///   uploads an XChaCha20-Poly1305 encrypted backup bundle to the relay.
pub async fn run_p2p_supervisor(
    engine: ServiceEngine,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut active_relay: Option<String> = None;
    let mut host_shutdown: Option<watch::Sender<bool>> = None;
    let mut last_backed_up_rev: u64 = 0;

    let mut poll = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    if let Some(tx) = host_shutdown.take() {
                        let _ = tx.send(true);
                    }
                    break;
                }
            }
            _ = poll.tick() => {
                let (relay_url, backup_enabled, rev, identity, maybe_bundle, group_key) = {
                    let guard = engine.state.lock().unwrap();
                    let relay = guard.sync_config.relay_url.trim().to_string();
                    let backup_on = guard.sync_config.encrypted_backup_enabled;
                    let rev = guard.sync_config.revision;
                    let id = guard.peer_identity.clone();
                    let need_backup = backup_on && !relay.is_empty() && rev > last_backed_up_rev;
                    let (bundle, key) = if need_backup {
                        let b = SyncBundle {
                            revision: rev,
                            updated_at: Utc::now(),
                            origin_device_name: guard.sync_config.device_name.clone(),
                            config: guard.config.clone(),
                            admins: guard
                                .auth
                                .as_ref()
                                .map(|a| a.admins.clone())
                                .unwrap_or_default(),
                        };
                        (Some(b), guard.sync_config.group_key_bytes().ok())
                    } else {
                        (None, None)
                    };
                    (relay, backup_on, rev, id, bundle, key)
                };

                // Start/restart/stop the P2P host when relay_url changes.
                let desired = if relay_url.is_empty() { None } else { Some(relay_url.clone()) };
                if desired != active_relay {
                    if let Some(tx) = host_shutdown.take() {
                        let _ = tx.send(true);
                    }
                    active_relay = desired.clone();
                    if let Some(url) = desired {
                        let (tx, rx) = watch::channel(false);
                        host_shutdown = Some(tx);
                        let eng = engine.clone();
                        tokio::spawn(curb_p2p::run_p2p_host(
                            identity,
                            url,
                            rx,
                            Arc::new(move |_from_peer, req| eng.handle_request(req)),
                        ));
                    }
                }

                // Upload E2E-encrypted settings backup if revision advanced.
                if backup_enabled {
                    if let (Some(bundle), Some(key)) = (maybe_bundle, group_key) {
                        match curb_p2p::upload_encrypted_backup(&relay_url, &key, &bundle).await {
                            Ok(()) => {
                                debug!(rev, "Uploaded E2E-encrypted settings backup to relay");
                                last_backed_up_rev = rev;
                            }
                            Err(e) => {
                                warn!(rev, error = %e, "Encrypted backup upload failed (will retry)");
                            }
                        }
                    }
                }
            }
        }
    }
}
