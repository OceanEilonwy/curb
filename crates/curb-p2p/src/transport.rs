use std::sync::Arc;
use std::time::Duration;

use curb_core::ipc::{IpcRequest, IpcResponse};
use curb_core::sync::RelayConnectionState;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Notify};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::crypto::{decrypt_from_peer, encrypt_for_peer};
use crate::identity::PeerIdentity;
use crate::{P2pError, Result};

/// Wire message format shared with `curb-relay`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RelayWireMessage {
    AuthChallenge {
        server_pub: String,
        nonce: String,
    },
    AuthProof {
        proof: String,
    },
    AuthOk,
    AuthError {
        message: String,
    },
    Forward {
        to: String,
        #[serde(default)]
        from: Option<String>,
        payload: String,
    },
    Presence {
        peer_id: String,
    },
    PresenceResult {
        peer_id: String,
        online: bool,
    },
    PeerOffline {
        peer_id: String,
    },
    Ping,
    Pong,
}

fn compute_auth_proof(identity: &PeerIdentity, server_pub: &str, nonce: &str) -> Result<String> {
    let shared = identity.diffie_hellman(server_pub)?;
    let peer_id = identity.peer_id();
    let mut input = Vec::with_capacity(20 + peer_id.len() + 1 + nonce.len());
    input.extend_from_slice(b"curb-relay-auth-v1:");
    input.extend_from_slice(peer_id.as_bytes());
    input.push(b':');
    input.extend_from_slice(nonce.as_bytes());
    Ok(blake3::keyed_hash(&shared, &input).to_hex().to_string())
}

/// Encrypted inner envelope sent inside `RelayWireMessage::Forward.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PeerEnvelope {
    Request {
        request_id: Uuid,
        request: IpcRequest,
    },
    Response {
        request_id: Uuid,
        response: IpcResponse,
    },
}

fn http_to_ws_relay_url(relay_url: &str, peer_id: &str, query: &str) -> String {
    let trimmed = relay_url.trim().trim_end_matches('/');
    let ws_base = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        trimmed.to_string()
    } else {
        format!("wss://{trimmed}")
    };
    if query.is_empty() {
        format!("{ws_base}/v1/relay/{peer_id}")
    } else {
        format!("{ws_base}/v1/relay/{peer_id}?{query}")
    }
}

/// Runs the `curb-service` host loop connected to `relay_url`, automatically
/// reconnecting on network blips and dispatching E2E-encrypted remote IPC
/// requests to `handler(from_peer_id, request)`.
pub async fn run_p2p_host<F>(
    identity: PeerIdentity,
    relay_url: String,
    shutdown: watch::Receiver<bool>,
    handler: Arc<F>,
) where
    F: Fn(String, IpcRequest) -> IpcResponse + Send + Sync + 'static,
{
    run_p2p_host_with_status(
        identity,
        relay_url,
        shutdown,
        Arc::new(Notify::new()),
        Arc::new(|_, _| {}),
        handler,
    )
    .await;
}

/// Like [`run_p2p_host`], but also reports live [`RelayConnectionState`] transitions
/// (and any last error message) to `on_status` and wakes immediately when `retry` is notified.
pub async fn run_p2p_host_with_status<F, S>(
    identity: PeerIdentity,
    relay_url: String,
    mut shutdown: watch::Receiver<bool>,
    retry: Arc<Notify>,
    on_status: Arc<S>,
    handler: Arc<F>,
) where
    F: Fn(String, IpcRequest) -> IpcResponse + Send + Sync + 'static,
    S: Fn(RelayConnectionState, Option<String>) + Send + Sync + 'static,
{
    let ws_url = http_to_ws_relay_url(&relay_url, &identity.peer_id(), "auth=true");
    let mut backoff = Duration::from_secs(1);

    loop {
        if *shutdown.borrow() {
            break;
        }

        on_status(RelayConnectionState::Connecting, None);

        let connect_outcome = tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
                continue;
            }
            _ = retry.notified() => {
                backoff = Duration::from_secs(1);
                continue;
            }
            res = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::connect_async(&ws_url)) => res,
        };

        match connect_outcome {
            Ok(Ok((ws_stream, _))) => {
                let (mut tx, mut rx) = ws_stream.split();

                // Complete X25519 challenge-response if the relay issues an AuthChallenge.
                let mut auth_failed: Option<String> = None;
                if let Ok(Some(Ok(Message::Text(first_text)))) =
                    tokio::time::timeout(Duration::from_secs(3), rx.next()).await
                {
                    if let Ok(first_msg) = serde_json::from_str::<RelayWireMessage>(&first_text) {
                        match first_msg {
                            RelayWireMessage::AuthChallenge { server_pub, nonce } => {
                                match compute_auth_proof(&identity, &server_pub, &nonce) {
                                    Ok(proof) => {
                                        let proof_json = serde_json::to_string(
                                            &RelayWireMessage::AuthProof { proof },
                                        )
                                        .unwrap_or_default();
                                        if let Err(e) = tx.send(Message::Text(proof_json.into())).await
                                        {
                                            auth_failed = Some(format!("Relay auth send failed: {e}"));
                                        } else {
                                            match tokio::time::timeout(
                                                Duration::from_secs(5),
                                                rx.next(),
                                            )
                                            .await
                                            {
                                                Ok(Some(Ok(Message::Text(ack)))) => {
                                                    match serde_json::from_str::<RelayWireMessage>(
                                                        &ack,
                                                    ) {
                                                        Ok(RelayWireMessage::AuthOk) => {}
                                                        Ok(RelayWireMessage::AuthError {
                                                            message,
                                                        }) => {
                                                            auth_failed = Some(message);
                                                        }
                                                        _ => {
                                                            auth_failed = Some(
                                                                "Unexpected relay auth response"
                                                                    .into(),
                                                            );
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    auth_failed =
                                                        Some("Relay auth timed out".into());
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        auth_failed = Some(format!("Relay auth error: {e}"));
                                    }
                                }
                            }
                            RelayWireMessage::AuthError { message } => {
                                auth_failed = Some(message);
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(reason) = auth_failed {
                    warn!(relay = %relay_url, reason = %reason, "Relay host authentication failed");
                    let _ = tx.close().await;
                    on_status(RelayConnectionState::Disconnected, Some(reason));
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                break;
                            }
                        }
                        _ = retry.notified() => {
                            backoff = Duration::from_secs(1);
                        }
                        _ = tokio::time::sleep(backoff) => {
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                        }
                    }
                    continue;
                }

                info!(relay = %relay_url, peer = %identity.peer_id(), "Connected to curb-relay as P2P host");
                on_status(RelayConnectionState::Connected, None);
                backoff = Duration::from_secs(1);

                let mut ping_interval = tokio::time::interval(Duration::from_secs(20));
                ping_interval.tick().await; // consume immediate first tick
                let mut awaiting_pong = false;
                let mut manual_retry = false;
                let mut disconnect_reason: Option<String> = None;
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                let _ = tx.close().await;
                                return;
                            }
                        }
                        _ = retry.notified() => {
                            let _ = tx.close().await;
                            backoff = Duration::from_secs(1);
                            manual_retry = true;
                            break;
                        }
                        _ = ping_interval.tick() => {
                            if awaiting_pong {
                                disconnect_reason = Some("Relay heartbeat timed out".into());
                                let _ = tx.close().await;
                                break;
                            }
                            if let Ok(json) = serde_json::to_string(&RelayWireMessage::Ping) {
                                if let Err(e) = tx.send(Message::Text(json.into())).await {
                                    disconnect_reason = Some(format!("Relay ping failed: {e}"));
                                    break;
                                }
                                awaiting_pong = true;
                            }
                        }
                        incoming = rx.next() => {
                            let Some(frame_res) = incoming else {
                                disconnect_reason = Some("Relay closed the connection".into());
                                break;
                            };
                            let frame = match frame_res {
                                Ok(f) => f,
                                Err(e) => {
                                    disconnect_reason = Some(format!("Relay connection error: {e}"));
                                    break;
                                }
                            };
                            awaiting_pong = false;
                            let Message::Text(text) = frame else {
                                continue;
                            };
                            let Ok(msg) = serde_json::from_str::<RelayWireMessage>(&text) else {
                                continue;
                            };
                            let RelayWireMessage::Forward { from: Some(from_peer), payload, .. } = msg else {
                                continue;
                            };

                            let plaintext = match decrypt_from_peer(&identity, &from_peer, &payload) {
                                Ok(pt) => pt,
                                Err(e) => {
                                    debug!(peer = %from_peer, error = %e, "Dropped undecryptable P2P frame");
                                    continue;
                                }
                            };
                            let Ok(PeerEnvelope::Request { request_id, request }) =
                                serde_json::from_slice::<PeerEnvelope>(&plaintext)
                            else {
                                continue;
                            };

                            let h = Arc::clone(&handler);
                            let caller_peer = from_peer.clone();
                            let response = tokio::task::spawn_blocking(move || h(caller_peer, request))
                                .await
                                .unwrap_or_else(|e| IpcResponse::Error {
                                    message: format!("Internal service error: {e}"),
                                });

                            let reply_env = PeerEnvelope::Response { request_id, response };
                            if let Ok(reply_bytes) = serde_json::to_vec(&reply_env) {
                                if let Ok(ct) = encrypt_for_peer(&identity, &from_peer, &reply_bytes) {
                                    let fwd = RelayWireMessage::Forward {
                                        to: from_peer,
                                        from: None,
                                        payload: ct,
                                    };
                                    if let Ok(json) = serde_json::to_string(&fwd) {
                                        if let Err(e) = tx.send(Message::Text(json.into())).await {
                                            disconnect_reason = Some(format!("Relay send failed: {e}"));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if manual_retry {
                    continue;
                }
                on_status(
                    RelayConnectionState::Disconnected,
                    disconnect_reason.or_else(|| Some("Relay connection lost".into())),
                );
            }
            Ok(Err(e)) => {
                warn!(relay = %relay_url, error = %e, "Could not connect to curb-relay; retrying");
                on_status(RelayConnectionState::Disconnected, Some(e.to_string()));
            }
            Err(_) => {
                warn!(relay = %relay_url, "Timed out connecting to curb-relay; retrying");
                on_status(
                    RelayConnectionState::Disconnected,
                    Some("Connection timed out".into()),
                );
            }
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = retry.notified() => {
                backoff = Duration::from_secs(1);
            }
            _ = tokio::time::sleep(backoff) => {
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Encrypts an [`IpcRequest`] into an opaque E2E-encrypted payload for `target_peer_id`,
/// returning `(request_id, base64_ciphertext)`.
pub fn seal_remote_request(
    my_identity: &PeerIdentity,
    target_peer_id: &str,
    request: &IpcRequest,
) -> Result<(Uuid, String)> {
    let request_id = Uuid::new_v4();
    let env = PeerEnvelope::Request {
        request_id,
        request: request.clone(),
    };
    let plaintext = serde_json::to_vec(&env)?;
    let ciphertext = encrypt_for_peer(my_identity, target_peer_id, &plaintext)?;
    Ok((request_id, ciphertext))
}

/// Decrypts an opaque E2E-encrypted reply payload from `target_peer_id` and verifies
/// that its `request_id` matches `expected_request_id`.
pub fn open_remote_response(
    my_identity: &PeerIdentity,
    target_peer_id: &str,
    expected_request_id: Uuid,
    payload: &str,
) -> Result<IpcResponse> {
    let pt = decrypt_from_peer(my_identity, target_peer_id, payload)?;
    match serde_json::from_slice::<PeerEnvelope>(&pt)? {
        PeerEnvelope::Response {
            request_id,
            response,
        } if request_id == expected_request_id => Ok(response),
        _ => Err(P2pError::Network(
            "Unexpected or mismatched P2P response envelope".into(),
        )),
    }
}

/// Decrypts an opaque E2E-encrypted [`PeerEnvelope::Request`] sent by `from_peer_id`
/// (used for offline invite claims stored on `curb-relay`).
pub fn open_remote_request(
    my_identity: &PeerIdentity,
    from_peer_id: &str,
    payload: &str,
) -> Result<IpcRequest> {
    let pt = decrypt_from_peer(my_identity, from_peer_id, payload)?;
    match serde_json::from_slice::<PeerEnvelope>(&pt)? {
        PeerEnvelope::Request { request, .. } => Ok(request),
        _ => Err(P2pError::Network(
            "Unexpected P2P envelope (expected Request)".into(),
        )),
    }
}

/// Forwards an already E2E-encrypted payload to `target_peer_id` via `relay_url` as
/// `from_peer_id` and awaits the opaque encrypted reply payload from `target_peer_id`.
pub async fn forward_relay_frame(
    relay_url: &str,
    from_peer_id: &str,
    target_peer_id: &str,
    payload: &str,
) -> Result<String> {
    let ws_url = http_to_ws_relay_url(relay_url, from_peer_id, "role=client");
    let (ws_stream, _) = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_tungstenite::connect_async(&ws_url),
    )
    .await
    .map_err(|_| P2pError::Network("Timed out connecting to relay server".into()))?
    .map_err(|e| P2pError::Network(format!("Could not connect to relay: {e}")))?;

    let (mut tx, mut rx) = ws_stream.split();
    let fwd = RelayWireMessage::Forward {
        to: target_peer_id.to_string(),
        from: None,
        payload: payload.to_string(),
    };
    let json = serde_json::to_string(&fwd)?;
    tx.send(Message::Text(json.into()))
        .await
        .map_err(|e| P2pError::Network(format!("Failed sending P2P frame: {e}")))?;

    let reply = tokio::time::timeout(Duration::from_secs(12), async {
        while let Some(frame) = rx.next().await {
            let Ok(Message::Text(text)) = frame else {
                continue;
            };
            let Ok(msg) = serde_json::from_str::<RelayWireMessage>(&text) else {
                continue;
            };
            match msg {
                RelayWireMessage::PeerOffline { .. } => {
                    return Err(P2pError::PeerOffline);
                }
                RelayWireMessage::Forward {
                    from: Some(from),
                    payload,
                    ..
                } if from == target_peer_id => {
                    return Ok(payload);
                }
                _ => {}
            }
        }
        Err(P2pError::Network(
            "Relay closed before response arrived".into(),
        ))
    })
    .await
    .map_err(|_| P2pError::Network("Timed out waiting for remote device response".into()))?;

    let _ = tx.close().await;
    reply
}

/// Sends a single E2E-encrypted [`IpcRequest`] to a remote `curb-service` peer
/// via `relay_url` and awaits the decrypted [`IpcResponse`].
pub async fn send_remote_request(
    my_identity: &PeerIdentity,
    relay_url: &str,
    target_peer_id: &str,
    request: &IpcRequest,
) -> Result<IpcResponse> {
    let (request_id, ciphertext) = seal_remote_request(my_identity, target_peer_id, request)?;
    let reply_ct =
        forward_relay_frame(relay_url, &my_identity.peer_id(), target_peer_id, &ciphertext)
            .await?;
    open_remote_response(my_identity, target_peer_id, request_id, &reply_ct)
}

/// Checks whether `target_peer_id` is currently online on `relay_url`.
pub async fn check_peer_online(
    my_identity: &PeerIdentity,
    relay_url: &str,
    target_peer_id: &str,
) -> Result<bool> {
    if let Ok(peers) =
        crate::invites::fetch_peers_presence(relay_url, &[target_peer_id.to_string()]).await
    {
        if let Some(p) = peers.into_iter().find(|p| p.peer_id == target_peer_id) {
            return Ok(p.online);
        }
    }

    let ws_url = http_to_ws_relay_url(relay_url, &my_identity.peer_id(), "role=client");
    let (ws_stream, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(&ws_url),
    )
    .await
    .map_err(|_| P2pError::Network("Timed out connecting to relay".into()))?
    .map_err(|e| P2pError::Network(format!("Could not connect to relay: {e}")))?;

    let (mut tx, mut rx) = ws_stream.split();
    let req = serde_json::to_string(&RelayWireMessage::Presence {
        peer_id: target_peer_id.to_string(),
    })?;
    tx.send(Message::Text(req.into()))
        .await
        .map_err(|e| P2pError::Network(e.to_string()))?;

    let online = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(Message::Text(text))) = rx.next().await {
            if let Ok(RelayWireMessage::PresenceResult { peer_id, online }) =
                serde_json::from_str::<RelayWireMessage>(&text)
            {
                if peer_id == target_peer_id {
                    return Ok(online);
                }
            }
        }
        Ok(false)
    })
    .await
    .unwrap_or(Ok(false));

    let _ = tx.close().await;
    online
}
