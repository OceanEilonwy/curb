use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use curb_core::ipc::IpcResponse;
use curb_core::sync::{InviteDescriptor, PendingInviteRecord, RelayConnectionState, SyncBundle};
use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

use crate::engine::{LockExt, ServiceEngine};

/// Background P2P host, invite dropbox publisher/poller, and optional encrypted backup supervisor
/// for `curb-service`.
///
/// Watches `ServiceEngine`'s `RemoteSyncConfig` and `pending_invites`:
/// - Whenever `relay_url` is non-empty, maintains an X25519-authenticated P2P host connection
///   to `curb-relay` dispatching E2E-encrypted remote IPC requests directly into `ServiceEngine`.
/// - Publishes any unpublished pending invites to `curb-relay`'s zero-knowledge invite dropbox
///   and polls for offline friend claims so invites work even while this PC was asleep/offline.
/// - Whenever the config revision advances and `encrypted_backup_enabled` is true,
///   uploads an XChaCha20-Poly1305 encrypted backup bundle to the relay.
pub async fn run_p2p_supervisor(
    engine: ServiceEngine,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut active_relay: Option<String> = None;
    let mut host_shutdown: Option<watch::Sender<bool>> = None;
    let mut host_retry: Option<Arc<Notify>> = None;
    let active_gen = Arc::new(AtomicU64::new(0));
    let mut last_backed_up_rev: u64 = 0;
    let mut last_claim_poll = Instant::now() - Duration::from_secs(60);

    let mut poll = tokio::time::interval(Duration::from_secs(2));
    loop {
        let manual_wakeup = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    if let Some(tx) = host_shutdown.take() {
                        let _ = tx.send(true);
                    }
                    break;
                }
                false
            }
            _ = engine.relay_notify.notified() => true,
            _ = poll.tick() => false,
        };

        let (
            relay_url,
            backup_enabled,
            rev,
            identity,
            device_name,
            pending_invites,
            maybe_bundle,
            group_key,
        ) = {
            let guard = engine.state.lock_or_recover();
            let relay = guard.sync_config.relay_url.trim().to_string();
            let backup_on = guard.sync_config.encrypted_backup_enabled;
            let rev = guard.sync_config.revision;
            let id = guard.peer_identity.clone();
            let dev_name = guard.sync_config.device_name.clone();
            let now = Utc::now();
            let invites: Vec<PendingInviteRecord> = guard
                .pending_invites
                .values()
                .filter(|inv| inv.expires_at > now)
                .cloned()
                .collect();
            let need_backup = backup_on && !relay.is_empty() && rev > last_backed_up_rev;
            let (bundle, key) = if need_backup {
                let b = SyncBundle {
                    revision: rev,
                    updated_at: now,
                    origin_device_name: dev_name.clone(),
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
            (relay, backup_on, rev, id, dev_name, invites, bundle, key)
        };

        // Start/restart/stop the P2P host when relay_url changes.
        let desired = if relay_url.is_empty() {
            None
        } else {
            Some(relay_url.clone())
        };
        if desired != active_relay {
            if let Some(tx) = host_shutdown.take() {
                let _ = tx.send(true);
            }
            host_retry = None;
            active_relay = desired.clone();
            let my_gen = active_gen.fetch_add(1, Ordering::SeqCst) + 1;

            if let Some(url) = desired {
                let (tx, rx) = watch::channel(false);
                let retry_notify = Arc::new(Notify::new());
                host_shutdown = Some(tx);
                host_retry = Some(retry_notify.clone());

                let eng_status = engine.clone();
                let gen_ref = active_gen.clone();
                let on_status = Arc::new(move |state: RelayConnectionState, err: Option<String>| {
                    if gen_ref.load(Ordering::SeqCst) == my_gen {
                        eng_status.set_relay_status(state, err);
                    }
                });

                let eng_handler = engine.clone();
                let id_for_host = identity.clone();
                tokio::spawn(curb_p2p::run_p2p_host_with_status(
                    id_for_host,
                    url,
                    rx,
                    retry_notify,
                    on_status,
                    Arc::new(move |from_peer: String, req| {
                        eng_handler.handle_remote_request(&from_peer, req)
                    }),
                ));
            } else {
                engine.set_relay_status(RelayConnectionState::Disabled, None);
            }
        } else if manual_wakeup {
            if let Some(retry) = &host_retry {
                retry.notify_waiters();
            }
        }

        // Publish unpublished invites to the relay's zero-knowledge dropbox and poll for offline claims.
        if !relay_url.is_empty() && !pending_invites.is_empty() {
            let host_peer_id = identity.peer_id();
            for inv in &pending_invites {
                if !inv.published {
                    let remaining_secs = (inv.expires_at - Utc::now()).num_seconds().max(60) as u64;
                    let desc = InviteDescriptor {
                        kind: inv.kind,
                        target_peer_id: host_peer_id.clone(),
                        device_name: device_name.clone(),
                        expires_at: inv.expires_at,
                    };
                    match curb_p2p::publish_invite_descriptor(
                        &relay_url,
                        &inv.code,
                        &host_peer_id,
                        &desc,
                        remaining_secs,
                    )
                    .await
                    {
                        Ok(()) => {
                            debug!("Published encrypted invite descriptor to relay dropbox");
                            engine.mark_invite_published(&inv.code);
                        }
                        Err(e) => {
                            debug!(error = %e, "Failed to publish invite descriptor (will retry)");
                        }
                    }
                }
            }

            if manual_wakeup || last_claim_poll.elapsed() >= Duration::from_secs(6) {
                last_claim_poll = Instant::now();
                for inv in &pending_invites {
                    match curb_p2p::poll_invite_claim(&relay_url, &inv.code, &host_peer_id).await {
                        Ok(Some(claim)) => {
                            match curb_p2p::open_remote_request(
                                &identity,
                                &claim.from_peer_id,
                                &claim.payload,
                            ) {
                                Ok(req) => {
                                    let eng = engine.clone();
                                    let from = claim.from_peer_id.clone();
                                    let resp = tokio::task::spawn_blocking(move || {
                                        eng.handle_remote_request(&from, req)
                                    })
                                    .await;
                                    match resp {
                                        Ok(IpcResponse::InviteRedeemed { .. }) => {
                                            info!(
                                                peer = %claim.from_peer_id,
                                                "Applied offline friend invite claim from relay"
                                            );
                                            let _ = curb_p2p::delete_invite_slot(
                                                &relay_url,
                                                &inv.code,
                                                &host_peer_id,
                                            )
                                            .await;
                                        }
                                        Ok(IpcResponse::Error { message }) => {
                                            warn!(
                                                peer = %claim.from_peer_id,
                                                error = %message,
                                                "Offline invite claim rejected"
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        peer = %claim.from_peer_id,
                                        error = %e,
                                        "Dropped undecryptable offline invite claim"
                                    );
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            debug!(error = %e, "Offline invite claim poll failed (will retry)");
                        }
                    }
                }
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
