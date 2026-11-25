use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Default maximum size of an E2E-encrypted settings backup blob (256 KiB).
pub const DEFAULT_MAX_BACKUP_BYTES: usize = 256 * 1024;

/// Configuration for [`RelayServer`].
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Directory where encrypted backup blobs are persisted (`None` = in-memory only).
    pub backup_dir: Option<PathBuf>,
    /// Set `false` to run as a 100% stateless P2P relay without backup storage.
    pub backup_enabled: bool,
    /// Maximum allowed ciphertext payload size in bytes.
    pub max_backup_bytes: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            backup_dir: None,
            backup_enabled: true,
            max_backup_bytes: DEFAULT_MAX_BACKUP_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
struct StoredBackup {
    revision: u64,
    ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct RelayState {
    config: RelayConfig,
    peers: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
    backups: Arc<RwLock<HashMap<String, StoredBackup>>>,
}

impl RelayState {
    pub fn new(config: RelayConfig) -> Self {
        if let Some(dir) = &config.backup_dir {
            if config.backup_enabled {
                let _ = std::fs::create_dir_all(dir);
            }
        }
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            backups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn disk_path(&self, slot_id: &str) -> Option<PathBuf> {
        self.config
            .backup_dir
            .as_ref()
            .map(|d| d.join(format!("{slot_id}.bin")))
    }

    fn disk_meta_path(&self, slot_id: &str) -> Option<PathBuf> {
        self.config
            .backup_dir
            .as_ref()
            .map(|d| d.join(format!("{slot_id}.rev")))
    }

    async fn load_backup(&self, slot_id: &str) -> Option<StoredBackup> {
        if let Some(found) = self.backups.read().await.get(slot_id).cloned() {
            return Some(found);
        }
        let bin_path = self.disk_path(slot_id)?;
        let rev_path = self.disk_meta_path(slot_id)?;
        let ciphertext = tokio::fs::read(&bin_path).await.ok()?;
        let rev_str = tokio::fs::read_to_string(&rev_path).await.ok()?;
        let revision = rev_str.trim().parse::<u64>().ok()?;
        let stored = StoredBackup {
            revision,
            ciphertext,
        };
        self.backups
            .write()
            .await
            .insert(slot_id.to_string(), stored.clone());
        Some(stored)
    }

    async fn save_backup(&self, slot_id: &str, backup: StoredBackup) -> std::io::Result<()> {
        if let (Some(bin_path), Some(rev_path)) =
            (self.disk_path(slot_id), self.disk_meta_path(slot_id))
        {
            let tmp_bin = bin_path.with_extension("bin.tmp");
            tokio::fs::write(&tmp_bin, &backup.ciphertext).await?;
            tokio::fs::rename(&tmp_bin, &bin_path).await?;
            tokio::fs::write(&rev_path, backup.revision.to_string()).await?;
        }
        self.backups
            .write()
            .await
            .insert(slot_id.to_string(), backup);
        Ok(())
    }
}

/// Wire messages exchanged over `GET /v1/relay/{peer_id}` WebSockets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMessage {
    /// Sent by a peer to forward an opaque (E2E-encrypted) payload to another peer.
    Forward {
        to: String,
        #[serde(default)]
        from: Option<String>,
        payload: String,
    },
    /// Query whether a peer is currently connected to the relay.
    Presence { peer_id: String },
    /// Response to [`RelayMessage::Presence`].
    PresenceResult { peer_id: String, online: bool },
    /// Returned when a `Forward` target is not currently connected.
    PeerOffline { peer_id: String },
    /// Keepalive ping/pong.
    Ping,
    Pong,
}

/// Builds the Axum [`Router`] for `curb-relay`.
pub fn build_router(config: RelayConfig) -> Router {
    let state = RelayState::new(config);
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/relay/{peer_id}", get(relay_ws_handler))
        .route(
            "/v1/backup/{slot_id}",
            put(put_backup_handler).get(get_backup_handler),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    backup_enabled: bool,
    connected_peers: usize,
}

async fn health_handler(State(state): State<RelayState>) -> Json<HealthResponse> {
    let connected_peers = state.peers.read().await.len();
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        backup_enabled: state.config.backup_enabled,
        connected_peers,
    })
}

fn is_valid_hex_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn relay_ws_handler(
    ws: WebSocketUpgrade,
    Path(peer_id): Path<String>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    if !is_valid_hex_id(&peer_id) {
        return (StatusCode::BAD_REQUEST, "Invalid peer_id").into_response();
    }
    ws.on_upgrade(move |socket| handle_peer_socket(socket, peer_id, state))
}

async fn handle_peer_socket(socket: WebSocket, peer_id: String, state: RelayState) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    {
        let mut peers = state.peers.write().await;
        peers.insert(peer_id.clone(), tx);
    }
    debug!(peer = %peer_id, "Peer connected to curb-relay");

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(frame)) = ws_rx.next().await {
        match frame {
            Message::Text(text) => {
                let Ok(msg) = serde_json::from_str::<RelayMessage>(&text) else {
                    continue;
                };
                match msg {
                    RelayMessage::Forward { to, payload, .. } => {
                        let target_tx = state.peers.read().await.get(&to).cloned();
                        if let Some(target_tx) = target_tx {
                            let delivered = RelayMessage::Forward {
                                to: to.clone(),
                                from: Some(peer_id.clone()),
                                payload,
                            };
                            if let Ok(json) = serde_json::to_string(&delivered) {
                                let _ = target_tx.send(json);
                            }
                        } else if let Some(self_tx) = state.peers.read().await.get(&peer_id).cloned()
                        {
                            let offline = RelayMessage::PeerOffline { peer_id: to };
                            if let Ok(json) = serde_json::to_string(&offline) {
                                let _ = self_tx.send(json);
                            }
                        }
                    }
                    RelayMessage::Presence { peer_id: query_id } => {
                        let online = state.peers.read().await.contains_key(&query_id);
                        if let Some(self_tx) = state.peers.read().await.get(&peer_id).cloned() {
                            let reply = RelayMessage::PresenceResult {
                                peer_id: query_id,
                                online,
                            };
                            if let Ok(json) = serde_json::to_string(&reply) {
                                let _ = self_tx.send(json);
                            }
                        }
                    }
                    RelayMessage::Ping => {
                        if let Some(self_tx) = state.peers.read().await.get(&peer_id).cloned() {
                            if let Ok(json) = serde_json::to_string(&RelayMessage::Pong) {
                                let _ = self_tx.send(json);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    send_task.abort();
    {
        let mut peers = state.peers.write().await;
        peers.remove(&peer_id);
    }
    debug!(peer = %peer_id, "Peer disconnected from curb-relay");
}

async fn put_backup_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !state.config.backup_enabled {
        return (StatusCode::NOT_FOUND, "Encrypted backup storage is disabled").into_response();
    }
    if !is_valid_hex_id(&slot_id) || slot_id.len() != 64 {
        return (StatusCode::BAD_REQUEST, "Invalid slot_id").into_response();
    }
    if body.is_empty() || body.len() > state.config.max_backup_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Backup payload out of bounds").into_response();
    }
    let Some(rev) = headers
        .get("x-curb-revision")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return (StatusCode::BAD_REQUEST, "Missing or invalid X-Curb-Revision").into_response();
    };
    let sig_ok = headers
        .get("x-curb-sig")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false);
    if !sig_ok {
        return (StatusCode::BAD_REQUEST, "Missing or invalid X-Curb-Sig").into_response();
    }

    if let Some(existing) = state.load_backup(&slot_id).await {
        if rev <= existing.revision {
            return (
                StatusCode::CONFLICT,
                format!("Stale revision {rev} <= {}", existing.revision),
            )
                .into_response();
        }
    }

    let stored = StoredBackup {
        revision: rev,
        ciphertext: body.to_vec(),
    };
    if let Err(e) = state.save_backup(&slot_id, stored).await {
        warn!(error = %e, slot = %slot_id, "Failed to persist encrypted backup");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to persist backup").into_response();
    }

    info!(slot = %slot_id, rev, bytes = body.len(), "Stored encrypted backup");
    (
        StatusCode::OK,
        [(header::ETAG, format!("\"{rev}\""))],
        "ok",
    )
        .into_response()
}

async fn get_backup_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.config.backup_enabled {
        return (StatusCode::NOT_FOUND, "Encrypted backup storage is disabled").into_response();
    }
    if !is_valid_hex_id(&slot_id) || slot_id.len() != 64 {
        return (StatusCode::BAD_REQUEST, "Invalid slot_id").into_response();
    }

    let Some(stored) = state.load_backup(&slot_id).await else {
        return (StatusCode::NOT_FOUND, "No backup found").into_response();
    };

    let etag = format!("\"{}\"", stored.revision);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        == Some(etag.as_str())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::ETAG, etag),
            (
                header::HeaderName::from_static("x-curb-revision"),
                stored.revision.to_string(),
            ),
        ],
        stored.ciphertext,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curb_core::config::Config;
    use curb_core::sync::{
        backup_slot_id, backup_write_signature, decrypt_sync_bundle, encrypt_sync_bundle,
        RemoteSyncConfig, SyncBundle,
    };
    use tokio::net::TcpListener;

    async fn spawn_test_relay(cfg: RelayConfig) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(cfg);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn relay_forwards_opaque_frames_between_peers_and_reports_presence() {
        let base = spawn_test_relay(RelayConfig::default()).await;
        let ws_base = base.replacen("http://", "ws://", 1);

        let peer_a = "aaaa1111bbbb2222";
        let peer_b = "cccc3333dddd4444";

        let (mut ws_a, _) =
            tokio_tungstenite::connect_async(format!("{ws_base}/v1/relay/{peer_a}"))
                .await
                .unwrap();
        let (mut ws_b, _) =
            tokio_tungstenite::connect_async(format!("{ws_base}/v1/relay/{peer_b}"))
                .await
                .unwrap();

        // Check presence of peer_b from peer_a
        let presence_req = serde_json::to_string(&RelayMessage::Presence {
            peer_id: peer_b.into(),
        })
        .unwrap();
        ws_a.send(tokio_tungstenite::tungstenite::Message::Text(
            presence_req.into(),
        ))
        .await
        .unwrap();
        let reply = ws_a.next().await.unwrap().unwrap().into_text().unwrap();
        let parsed: RelayMessage = serde_json::from_str(&reply).unwrap();
        assert!(matches!(
            parsed,
            RelayMessage::PresenceResult { online: true, .. }
        ));

        // Forward opaque ciphertext from A -> B
        let fwd = serde_json::to_string(&RelayMessage::Forward {
            to: peer_b.into(),
            from: None,
            payload: "opaque-ciphertext-xyz".into(),
        })
        .unwrap();
        ws_a.send(tokio_tungstenite::tungstenite::Message::Text(fwd.into()))
            .await
            .unwrap();

        let received = ws_b.next().await.unwrap().unwrap().into_text().unwrap();
        let parsed: RelayMessage = serde_json::from_str(&received).unwrap();
        match parsed {
            RelayMessage::Forward { from, payload, .. } => {
                assert_eq!(from.as_deref(), Some(peer_a));
                assert_eq!(payload, "opaque-ciphertext-xyz");
            }
            other => panic!("Unexpected relay message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn encrypted_backup_put_get_and_etag_304() {
        let base = spawn_test_relay(RelayConfig::default()).await;
        let client = reqwest::Client::new();

        let sync_cfg = RemoteSyncConfig::new_default("Jordan's PC");
        let key = sync_cfg.group_key_bytes().unwrap();
        let slot = backup_slot_id(&key);

        let bundle = SyncBundle {
            revision: 3,
            updated_at: chrono::Utc::now(),
            origin_device_name: "Jordan's PC".into(),
            config: Config::default(),
            admins: Vec::new(),
        };
        let blob = encrypt_sync_bundle(&key, &bundle).unwrap();
        let sig = backup_write_signature(&key, 3, &blob);

        let put_res = client
            .put(format!("{base}/v1/backup/{slot}"))
            .header("x-curb-revision", "3")
            .header("x-curb-sig", &sig)
            .body(blob.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);

        // Stale revision rejected with 409 Conflict
        let stale_res = client
            .put(format!("{base}/v1/backup/{slot}"))
            .header("x-curb-revision", "2")
            .header("x-curb-sig", &sig)
            .body(blob)
            .send()
            .await
            .unwrap();
        assert_eq!(stale_res.status(), StatusCode::CONFLICT);

        // GET returns ciphertext that decrypts cleanly
        let get_res = client
            .get(format!("{base}/v1/backup/{slot}"))
            .send()
            .await
            .unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let etag = get_res
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let bytes = get_res.bytes().await.unwrap();
        let recovered = decrypt_sync_bundle(&key, &bytes).unwrap();
        assert_eq!(recovered.revision, 3);
        assert_eq!(recovered.origin_device_name, "Jordan's PC");

        // Conditional GET returns 304 Not Modified
        let not_mod = client
            .get(format!("{base}/v1/backup/{slot}"))
            .header(header::IF_NONE_MATCH, etag)
            .send()
            .await
            .unwrap();
        assert_eq!(not_mod.status(), StatusCode::NOT_MODIFIED);
    }
}
