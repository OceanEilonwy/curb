use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

/// Default maximum size of an E2E-encrypted settings backup blob (256 KiB).
pub const DEFAULT_MAX_BACKUP_BYTES: usize = 256 * 1024;

/// Default maximum size of an E2E-encrypted invite descriptor blob (8 KiB).
pub const MAX_INVITE_DESCRIPTOR_BYTES: usize = 8 * 1024;

/// Default maximum size of an E2E-encrypted invite claim payload (16 KiB).
pub const MAX_INVITE_CLAIM_BYTES: usize = 16 * 1024;

/// Default host WebSocket inactivity/heartbeat timeout (seconds).
/// Hosts send a `Ping` every 25s; missing 2+ beats marks them offline cleanly.
pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 65;

/// Default TTL for an invite dropbox entry (24 hours).
pub const DEFAULT_INVITE_TTL_SECS: u64 = 86_400;

/// Maximum TTL allowed for an invite dropbox entry (7 days).
pub const MAX_INVITE_TTL_SECS: u64 = 7 * 86_400;

/// Maximum number of `last_seen` entries retained in memory.
const MAX_LAST_SEEN_ENTRIES: usize = 10_000;

/// Maximum number of active invite dropbox slots retained in memory.
const MAX_INVITE_SLOTS: usize = 10_000;

/// Configuration for [`RelayServer`].
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Directory where encrypted backup blobs are persisted (`None` = in-memory only).
    pub backup_dir: Option<PathBuf>,
    /// Set `false` to run as a 100% stateless P2P relay without backup storage.
    pub backup_enabled: bool,
    /// Maximum allowed ciphertext payload size in bytes.
    pub max_backup_bytes: usize,
    /// Seconds of WebSocket silence before a host peer is dropped as offline.
    pub heartbeat_timeout_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            backup_dir: None,
            backup_enabled: true,
            max_backup_bytes: DEFAULT_MAX_BACKUP_BYTES,
            heartbeat_timeout_secs: DEFAULT_HEARTBEAT_TIMEOUT_SECS,
        }
    }
}

#[derive(Debug, Clone)]
struct StoredBackup {
    revision: u64,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PeerEntry {
    conn_id: u64,
    tx: mpsc::UnboundedSender<String>,
    authenticated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredClaim {
    pub from_peer_id: String,
    pub payload: String,
    pub claimed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct StoredInvite {
    owner_token: String,
    descriptor_ciphertext: Vec<u8>,
    expires_at: DateTime<Utc>,
    claim: Option<StoredClaim>,
}

#[derive(Clone)]
pub struct RelayState {
    config: RelayConfig,
    next_conn_id: Arc<AtomicU64>,
    /// Persistent host peer connections (keyed by `peer_id`).
    peers: Arc<RwLock<HashMap<String, PeerEntry>>>,
    /// Ephemeral client connections (`?role=client`), keyed by `from_peer_id`.
    /// Never overwrites host slots and supports concurrent client requests cleanly.
    clients: Arc<RwLock<HashMap<String, Vec<(u64, mpsc::UnboundedSender<String>)>>>>,
    /// Bounded `last_seen_at` timestamps for peers that have connected to this relay.
    last_seen: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    /// E2E-encrypted settings backups.
    backups: Arc<RwLock<HashMap<String, StoredBackup>>>,
    /// Zero-knowledge invite dropbox slots (keyed by 64-hex `slot_id`).
    invites: Arc<RwLock<HashMap<String, StoredInvite>>>,
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
            next_conn_id: Arc::new(AtomicU64::new(1)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            clients: Arc::new(RwLock::new(HashMap::new())),
            last_seen: Arc::new(RwLock::new(HashMap::new())),
            backups: Arc::new(RwLock::new(HashMap::new())),
            invites: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn record_last_seen(&self, peer_id: &str) {
        let mut map = self.last_seen.write().await;
        if map.len() >= MAX_LAST_SEEN_ENTRIES && !map.contains_key(peer_id) {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        map.insert(peer_id.to_string(), Utc::now());
    }

    async fn presence_of(&self, peer_id: &str) -> PresenceInfo {
        let online = self.peers.read().await.contains_key(peer_id);
        let last_seen_at = if online {
            Some(Utc::now())
        } else {
            self.last_seen.read().await.get(peer_id).copied()
        };
        PresenceInfo {
            peer_id: peer_id.to_string(),
            online,
            last_seen_at,
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
    /// Sent by the relay on authenticated host connections (`?auth=true`).
    AuthChallenge {
        server_pub: String,
        nonce: String,
    },
    /// Sent by the host proving possession of the X25519 private key for `peer_id`.
    AuthProof {
        proof: String,
    },
    /// Sent by the relay after verifying [`RelayMessage::AuthProof`].
    AuthOk,
    /// Sent by the relay when host authentication fails or a slot is protected.
    AuthError {
        message: String,
    },
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
    PresenceResult {
        peer_id: String,
        online: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_seen_at: Option<DateTime<Utc>>,
    },
    /// Returned when a `Forward` target is not currently connected.
    PeerOffline { peer_id: String },
    /// Keepalive ping/pong.
    Ping,
    Pong,
}

/// Presence response payload for HTTP `GET /v1/presence/{peer_id}` and `POST /v1/presence`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceInfo {
    pub peer_id: String,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct BatchPresenceRequest {
    peer_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BatchPresenceResponse {
    peers: Vec<PresenceInfo>,
}

#[derive(Debug, Deserialize)]
struct ClaimInviteBody {
    from_peer_id: String,
    payload: String,
}

#[derive(Debug, Default, Deserialize)]
struct RelayQuery {
    /// `"client"` for ephemeral request/response connections; omitted or `"host"` for persistent hosts.
    role: Option<String>,
    /// When `true`, performs an X25519 challenge-response proving ownership of `peer_id`.
    auth: Option<bool>,
}

/// Computes the expected X25519 challenge-response MAC for `peer_id` + `nonce`.
pub fn compute_relay_auth_proof(shared_secret: &[u8; 32], peer_id: &str, nonce: &str) -> String {
    let mut input = Vec::with_capacity(20 + peer_id.len() + 1 + nonce.len());
    input.extend_from_slice(b"curb-relay-auth-v1:");
    input.extend_from_slice(peer_id.as_bytes());
    input.push(b':');
    input.extend_from_slice(nonce.as_bytes());
    blake3::keyed_hash(shared_secret, &input)
        .to_hex()
        .to_string()
}

/// Builds the Axum [`Router`] for `curb-relay`.
pub fn build_router(config: RelayConfig) -> Router {
    let state = RelayState::new(config);
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/relay/{peer_id}", get(relay_ws_handler))
        .route("/v1/presence/{peer_id}", get(get_presence_handler))
        .route("/v1/presence", post(batch_presence_handler))
        .route(
            "/v1/invites/{slot_id}",
            put(put_invite_handler)
                .get(get_invite_handler)
                .delete(delete_invite_handler),
        )
        .route(
            "/v1/invites/{slot_id}/claim",
            post(post_invite_claim_handler).get(get_invite_claim_handler),
        )
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

fn is_valid_64_hex(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn get_presence_handler(
    Path(peer_id): Path<String>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    if !is_valid_hex_id(&peer_id) {
        return (StatusCode::BAD_REQUEST, "Invalid peer_id").into_response();
    }
    Json(state.presence_of(&peer_id).await).into_response()
}

async fn batch_presence_handler(
    State(state): State<RelayState>,
    Json(req): Json<BatchPresenceRequest>,
) -> impl IntoResponse {
    if req.peer_ids.len() > 64 {
        return (StatusCode::BAD_REQUEST, "Too many peer_ids (max 64)").into_response();
    }
    let mut peers = Vec::with_capacity(req.peer_ids.len());
    for pid in &req.peer_ids {
        if !is_valid_hex_id(pid) {
            return (StatusCode::BAD_REQUEST, "Invalid peer_id in batch").into_response();
        }
        peers.push(state.presence_of(pid).await);
    }
    Json(BatchPresenceResponse { peers }).into_response()
}

async fn relay_ws_handler(
    ws: WebSocketUpgrade,
    Path(peer_id): Path<String>,
    Query(query): Query<RelayQuery>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    if !is_valid_hex_id(&peer_id) {
        return (StatusCode::BAD_REQUEST, "Invalid peer_id").into_response();
    }
    let is_client = query.role.as_deref() == Some("client");
    let require_auth = !is_client && query.auth.unwrap_or(false);
    if require_auth && !is_valid_64_hex(&peer_id) {
        return (
            StatusCode::BAD_REQUEST,
            "Authenticated peer_id must be a 64-char hex X25519 public key",
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| {
        handle_peer_socket(socket, peer_id, is_client, require_auth, state)
    })
}

async fn perform_ws_auth(
    ws_tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    peer_id: &str,
) -> Result<(), &'static str> {
    let peer_bytes = hex::decode(peer_id).map_err(|_| "Invalid peer_id hex")?;
    let peer_arr: [u8; 32] = peer_bytes
        .try_into()
        .map_err(|_| "peer_id must be 32 bytes")?;
    let peer_pub = PublicKey::from(peer_arr);

    let server_sk = StaticSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&server_sk);
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    let challenge = RelayMessage::AuthChallenge {
        server_pub: hex::encode(server_pub.as_bytes()),
        nonce: nonce.clone(),
    };
    let challenge_json = serde_json::to_string(&challenge).map_err(|_| "Serialize error")?;
    ws_tx
        .send(Message::Text(challenge_json.into()))
        .await
        .map_err(|_| "Failed sending auth challenge")?;

    let shared = server_sk.diffie_hellman(&peer_pub).to_bytes();
    let expected = compute_relay_auth_proof(&shared, peer_id, &nonce);

    let reply = tokio::time::timeout(Duration::from_secs(8), ws_rx.next())
        .await
        .map_err(|_| "Timed out waiting for auth proof")?
        .ok_or("Connection closed before auth proof")?
        .map_err(|_| "WebSocket error during auth")?;

    let Message::Text(text) = reply else {
        return Err("Expected text AuthProof frame");
    };
    let Ok(RelayMessage::AuthProof { proof }) = serde_json::from_str::<RelayMessage>(&text) else {
        return Err("Malformed AuthProof frame");
    };
    if proof.trim().eq_ignore_ascii_case(&expected) {
        let ok_json = serde_json::to_string(&RelayMessage::AuthOk).map_err(|_| "Serialize error")?;
        ws_tx
            .send(Message::Text(ok_json.into()))
            .await
            .map_err(|_| "Failed sending AuthOk")?;
        Ok(())
    } else {
        Err("Invalid X25519 authentication proof")
    }
}

async fn handle_peer_socket(
    socket: WebSocket,
    peer_id: String,
    is_client: bool,
    require_auth: bool,
    state: RelayState,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let mut authenticated = false;
    if !is_client {
        if require_auth {
            if let Err(reason) = perform_ws_auth(&mut ws_tx, &mut ws_rx, &peer_id).await {
                if let Ok(err_json) = serde_json::to_string(&RelayMessage::AuthError {
                    message: reason.to_string(),
                }) {
                    let _ = ws_tx.send(Message::Text(err_json.into())).await;
                }
                let _ = ws_tx.close().await;
                debug!(peer = %peer_id, reason, "Rejected unauthenticated host peer");
                return;
            }
            authenticated = true;
        } else {
            // Never allow an unauthenticated connection to evict an authenticated host slot.
            let slot_protected = state
                .peers
                .read()
                .await
                .get(&peer_id)
                .is_some_and(|e| e.authenticated);
            if slot_protected {
                if let Ok(err_json) = serde_json::to_string(&RelayMessage::AuthError {
                    message: "This peer slot requires X25519 authentication.".into(),
                }) {
                    let _ = ws_tx.send(Message::Text(err_json.into())).await;
                }
                let _ = ws_tx.close().await;
                debug!(peer = %peer_id, "Blocked unauthenticated overwrite of authenticated host");
                return;
            }
        }
    }

    let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    if is_client {
        state
            .clients
            .write()
            .await
            .entry(peer_id.clone())
            .or_default()
            .push((conn_id, tx.clone()));
        debug!(peer = %peer_id, conn_id, "Ephemeral client connected to curb-relay");
    } else {
        state.peers.write().await.insert(
            peer_id.clone(),
            PeerEntry {
                conn_id,
                tx: tx.clone(),
                authenticated,
            },
        );
        state.record_last_seen(&peer_id).await;
        debug!(peer = %peer_id, conn_id, authenticated, "Host peer connected to curb-relay");
    }

    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    let idle_timeout = Duration::from_secs(state.config.heartbeat_timeout_secs.max(5));

    loop {
        let next_frame = tokio::time::timeout(idle_timeout, ws_rx.next()).await;
        let frame = match next_frame {
            Ok(Some(Ok(f))) => f,
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => {
                debug!(peer = %peer_id, conn_id, "Peer heartbeat timed out; closing");
                break;
            }
        };

        if !is_client {
            state.record_last_seen(&peer_id).await;
        }

        match frame {
            Message::Text(text) => {
                let Ok(msg) = serde_json::from_str::<RelayMessage>(&text) else {
                    continue;
                };
                match msg {
                    RelayMessage::Forward { to, payload, .. } => {
                        let delivered = RelayMessage::Forward {
                            to: to.clone(),
                            from: Some(peer_id.clone()),
                            payload,
                        };
                        let Ok(json) = serde_json::to_string(&delivered) else {
                            continue;
                        };
                        let mut delivered_any = false;
                        if let Some(entry) = state.peers.read().await.get(&to).cloned() {
                            if entry.tx.send(json.clone()).is_ok() {
                                delivered_any = true;
                            }
                        }
                        if let Some(client_list) = state.clients.read().await.get(&to).cloned() {
                            for (_, client_tx) in client_list {
                                if client_tx.send(json.clone()).is_ok() {
                                    delivered_any = true;
                                }
                            }
                        }
                        if !delivered_any {
                            let offline = RelayMessage::PeerOffline { peer_id: to };
                            if let Ok(offline_json) = serde_json::to_string(&offline) {
                                let _ = tx.send(offline_json);
                            }
                        }
                    }
                    RelayMessage::Presence { peer_id: query_id } => {
                        let info = state.presence_of(&query_id).await;
                        let reply = RelayMessage::PresenceResult {
                            peer_id: info.peer_id,
                            online: info.online,
                            last_seen_at: info.last_seen_at,
                        };
                        if let Ok(json) = serde_json::to_string(&reply) {
                            let _ = tx.send(json);
                        }
                    }
                    RelayMessage::Ping => {
                        if let Ok(json) = serde_json::to_string(&RelayMessage::Pong) {
                            let _ = tx.send(json);
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
    if is_client {
        let mut clients = state.clients.write().await;
        if let Some(list) = clients.get_mut(&peer_id) {
            list.retain(|(id, _)| *id != conn_id);
            if list.is_empty() {
                clients.remove(&peer_id);
            }
        }
        debug!(peer = %peer_id, conn_id, "Ephemeral client disconnected from curb-relay");
    } else {
        let mut peers = state.peers.write().await;
        if peers.get(&peer_id).is_some_and(|e| e.conn_id == conn_id) {
            peers.remove(&peer_id);
        }
        drop(peers);
        state.record_last_seen(&peer_id).await;
        debug!(peer = %peer_id, conn_id, "Host peer disconnected from curb-relay");
    }
}

// --- Zero-Knowledge Invite Dropbox ---

async fn put_invite_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !is_valid_64_hex(&slot_id) {
        return (StatusCode::BAD_REQUEST, "Invalid invite slot_id").into_response();
    }
    if body.is_empty() || body.len() > MAX_INVITE_DESCRIPTOR_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Invite descriptor out of bounds",
        )
            .into_response();
    }
    let Some(owner_token) = headers
        .get("x-curb-owner-token")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_64_hex(s))
        .map(str::to_string)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid X-Curb-Owner-Token",
        )
            .into_response();
    };
    let ttl_secs = headers
        .get("x-curb-ttl-secs")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INVITE_TTL_SECS)
        .clamp(60, MAX_INVITE_TTL_SECS);

    let now = Utc::now();
    let mut invites = state.invites.write().await;
    invites.retain(|_, inv| inv.expires_at > now);

    if let Some(existing) = invites.get(&slot_id) {
        if existing.owner_token != owner_token {
            return (StatusCode::CONFLICT, "Invite slot already exists").into_response();
        }
    } else if invites.len() >= MAX_INVITE_SLOTS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Invite dropbox capacity reached",
        )
            .into_response();
    }

    let existing_claim = invites.get(&slot_id).and_then(|i| i.claim.clone());
    invites.insert(
        slot_id.clone(),
        StoredInvite {
            owner_token,
            descriptor_ciphertext: body.to_vec(),
            expires_at: now + ChronoDuration::seconds(ttl_secs as i64),
            claim: existing_claim,
        },
    );
    info!(slot = %slot_id, ttl_secs, "Stored zero-knowledge invite descriptor");
    (StatusCode::OK, "ok").into_response()
}

async fn get_invite_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    if !is_valid_64_hex(&slot_id) {
        return (StatusCode::BAD_REQUEST, "Invalid invite slot_id").into_response();
    }
    let now = Utc::now();
    let invites = state.invites.read().await;
    let Some(invite) = invites.get(&slot_id) else {
        return (StatusCode::NOT_FOUND, "Invite not found or expired").into_response();
    };
    if invite.expires_at <= now {
        return (StatusCode::NOT_FOUND, "Invite not found or expired").into_response();
    }
    if invite.claim.is_some() {
        return (StatusCode::CONFLICT, "Invite has already been claimed").into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        invite.descriptor_ciphertext.clone(),
    )
        .into_response()
}

async fn post_invite_claim_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    Json(body): Json<ClaimInviteBody>,
) -> impl IntoResponse {
    if !is_valid_64_hex(&slot_id) {
        return (StatusCode::BAD_REQUEST, "Invalid invite slot_id").into_response();
    }
    if !is_valid_64_hex(&body.from_peer_id) {
        return (StatusCode::BAD_REQUEST, "Invalid from_peer_id").into_response();
    }
    if body.payload.is_empty() || body.payload.len() > MAX_INVITE_CLAIM_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Claim payload out of bounds").into_response();
    }
    let now = Utc::now();
    let mut invites = state.invites.write().await;
    invites.retain(|_, inv| inv.expires_at > now);

    let Some(invite) = invites.get_mut(&slot_id) else {
        return (StatusCode::NOT_FOUND, "Invite not found or expired").into_response();
    };
    if invite.claim.is_some() {
        return (StatusCode::CONFLICT, "Invite has already been claimed").into_response();
    }
    invite.claim = Some(StoredClaim {
        from_peer_id: body.from_peer_id,
        payload: body.payload,
        claimed_at: now,
    });
    info!(slot = %slot_id, "Stored offline invite claim");
    (StatusCode::OK, "ok").into_response()
}

async fn get_invite_claim_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_valid_64_hex(&slot_id) {
        return (StatusCode::BAD_REQUEST, "Invalid invite slot_id").into_response();
    }
    let Some(owner_token) = headers
        .get("x-curb-owner-token")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_64_hex(s))
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid X-Curb-Owner-Token",
        )
            .into_response();
    };
    let now = Utc::now();
    let invites = state.invites.read().await;
    let Some(invite) = invites.get(&slot_id) else {
        return (StatusCode::NOT_FOUND, "Invite not found or expired").into_response();
    };
    if invite.expires_at <= now {
        return (StatusCode::NOT_FOUND, "Invite not found or expired").into_response();
    }
    if invite.owner_token != owner_token {
        return (StatusCode::FORBIDDEN, "Invalid owner token").into_response();
    }
    match &invite.claim {
        Some(claim) => (StatusCode::OK, Json(claim.clone())).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn delete_invite_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_valid_64_hex(&slot_id) {
        return (StatusCode::BAD_REQUEST, "Invalid invite slot_id").into_response();
    }
    let Some(owner_token) = headers
        .get("x-curb-owner-token")
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_64_hex(s))
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid X-Curb-Owner-Token",
        )
            .into_response();
    };
    let mut invites = state.invites.write().await;
    if let Some(existing) = invites.get(&slot_id) {
        if existing.owner_token != owner_token {
            return (StatusCode::FORBIDDEN, "Invalid owner token").into_response();
        }
        invites.remove(&slot_id);
    }
    StatusCode::NO_CONTENT.into_response()
}

// --- Encrypted Settings Backup ---

async fn put_backup_handler(
    Path(slot_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !state.config.backup_enabled {
        return (StatusCode::NOT_FOUND, "Encrypted backup storage is disabled").into_response();
    }
    if !is_valid_64_hex(&slot_id) {
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
        .map(is_valid_64_hex)
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
    if !is_valid_64_hex(&slot_id) {
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
        backup_slot_id, backup_write_signature, decrypt_invite_descriptor, decrypt_sync_bundle,
        encrypt_invite_descriptor, encrypt_sync_bundle, generate_invite_code, invite_owner_token,
        invite_slot_id, InviteDescriptor, InviteKind, RemoteSyncConfig, SyncBundle,
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
    async fn authenticated_host_blocks_unauthenticated_hijack_and_survives_old_disconnect() {
        let base = spawn_test_relay(RelayConfig::default()).await;
        let ws_base = base.replacen("http://", "ws://", 1);

        let host_sk = StaticSecret::random_from_rng(OsRng);
        let host_pub = PublicKey::from(&host_sk);
        let host_id = hex::encode(host_pub.as_bytes());

        // Connect host #1 with X25519 auth
        let (mut ws1, _) =
            tokio_tungstenite::connect_async(format!("{ws_base}/v1/relay/{host_id}?auth=true"))
                .await
                .unwrap();
        let ch_txt = ws1.next().await.unwrap().unwrap().into_text().unwrap();
        let RelayMessage::AuthChallenge { server_pub, nonce } =
            serde_json::from_str(&ch_txt).unwrap()
        else {
            panic!("expected AuthChallenge");
        };
        let srv_arr: [u8; 32] = hex::decode(server_pub).unwrap().try_into().unwrap();
        let shared = host_sk.diffie_hellman(&PublicKey::from(srv_arr)).to_bytes();
        let proof = compute_relay_auth_proof(&shared, &host_id, &nonce);
        ws1.send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&RelayMessage::AuthProof { proof })
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
        let ok_txt = ws1.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayMessage>(&ok_txt).unwrap(),
            RelayMessage::AuthOk
        ));

        // Attacker tries unauthenticated connect to same host_id -> rejected with AuthError
        let (mut attacker, _) =
            tokio_tungstenite::connect_async(format!("{ws_base}/v1/relay/{host_id}"))
                .await
                .unwrap();
        let err_txt = attacker.next().await.unwrap().unwrap().into_text().unwrap();
        assert!(matches!(
            serde_json::from_str::<RelayMessage>(&err_txt).unwrap(),
            RelayMessage::AuthError { .. }
        ));

        // Host reconnects (ws2) before ws1 closes; closing ws1 must NOT mark host offline!
        let (mut ws2, _) =
            tokio_tungstenite::connect_async(format!("{ws_base}/v1/relay/{host_id}?auth=true"))
                .await
                .unwrap();
        let ch2 = ws2.next().await.unwrap().unwrap().into_text().unwrap();
        let RelayMessage::AuthChallenge { server_pub, nonce } =
            serde_json::from_str(&ch2).unwrap()
        else {
            panic!("expected AuthChallenge");
        };
        let srv_arr2: [u8; 32] = hex::decode(server_pub).unwrap().try_into().unwrap();
        let shared2 = host_sk.diffie_hellman(&PublicKey::from(srv_arr2)).to_bytes();
        let proof2 = compute_relay_auth_proof(&shared2, &host_id, &nonce);
        ws2.send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&RelayMessage::AuthProof { proof: proof2 })
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
        let _ = ws2.next().await.unwrap().unwrap();

        // Close old ws1
        let _ = ws1.close(None).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // HTTP presence still reports online!
        let client = reqwest::Client::new();
        let pres: PresenceInfo = client
            .get(format!("{base}/v1/presence/{host_id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(pres.online);
        assert!(pres.last_seen_at.is_some());

        // Close ws2 -> now offline with last_seen_at preserved
        let _ = ws2.close(None).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let pres2: PresenceInfo = client
            .get(format!("{base}/v1/presence/{host_id}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(!pres2.online);
        assert!(pres2.last_seen_at.is_some());
    }

    #[tokio::test]
    async fn invite_dropbox_put_get_claim_single_use_and_delete() {
        let base = spawn_test_relay(RelayConfig::default()).await;
        let client = reqwest::Client::new();

        let code = generate_invite_code();
        let host_peer_id = hex::encode([0x11u8; 32]);
        let friend_peer_id = hex::encode([0x22u8; 32]);
        let slot = invite_slot_id(&code);
        let owner = invite_owner_token(&code, &host_peer_id);

        let desc = InviteDescriptor {
            kind: InviteKind::FriendAdmin,
            target_peer_id: host_peer_id.clone(),
            device_name: "Jordan's PC".into(),
            expires_at: Utc::now() + ChronoDuration::hours(24),
        };
        let blob = encrypt_invite_descriptor(&code, &desc).unwrap();

        // Host uploads encrypted descriptor
        let put_res = client
            .put(format!("{base}/v1/invites/{slot}"))
            .header("x-curb-owner-token", &owner)
            .header("x-curb-ttl-secs", "3600")
            .body(blob)
            .send()
            .await
            .unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);

        // Before claim, host polling claim gets 204 No Content
        let no_claim = client
            .get(format!("{base}/v1/invites/{slot}/claim"))
            .header("x-curb-owner-token", &owner)
            .send()
            .await
            .unwrap();
        assert_eq!(no_claim.status(), StatusCode::NO_CONTENT);

        // Friend fetches & decrypts descriptor
        let get_res = client
            .get(format!("{base}/v1/invites/{slot}"))
            .send()
            .await
            .unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let fetched_bytes = get_res.bytes().await.unwrap();
        let recovered = decrypt_invite_descriptor(&code, &fetched_bytes).unwrap();
        assert_eq!(recovered.target_peer_id, host_peer_id);
        assert_eq!(recovered.device_name, "Jordan's PC");

        // Friend posts offline claim
        let claim_res = client
            .post(format!("{base}/v1/invites/{slot}/claim"))
            .json(&serde_json::json!({
                "from_peer_id": friend_peer_id,
                "payload": "opaque-encrypted-redeem",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(claim_res.status(), StatusCode::OK);

        // Second claim is rejected with 409 Conflict
        let replay = client
            .post(format!("{base}/v1/invites/{slot}/claim"))
            .json(&serde_json::json!({
                "from_peer_id": friend_peer_id,
                "payload": "replay",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);

        // Wrong owner token cannot read claim
        let wrong_owner = hex::encode([0x99u8; 32]);
        let forbidden = client
            .get(format!("{base}/v1/invites/{slot}/claim"))
            .header("x-curb-owner-token", &wrong_owner)
            .send()
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        // Host reads claim and deletes slot
        let claim: StoredClaim = client
            .get(format!("{base}/v1/invites/{slot}/claim"))
            .header("x-curb-owner-token", &owner)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(claim.from_peer_id, friend_peer_id);
        assert_eq!(claim.payload, "opaque-encrypted-redeem");

        let del = client
            .delete(format!("{base}/v1/invites/{slot}"))
            .header("x-curb-owner-token", &owner)
            .send()
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::NO_CONTENT);
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
            updated_at: Utc::now(),
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
