use std::sync::Arc;
use std::time::Duration;

use curb_core::ipc::{IpcRequest, IpcResponse};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
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

fn http_to_ws_relay_url(relay_url: &str, peer_id: &str) -> String {
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
    format!("{ws_base}/v1/relay/{peer_id}")
}

/// Runs the `curb-service` host loop connected to `relay_url`, automatically
/// reconnecting on network blips and dispatching E2E-encrypted remote IPC
/// requests to `handler(from_peer_id, request)`.
pub async fn run_p2p_host<F>(
    identity: PeerIdentity,
    relay_url: String,
    mut shutdown: watch::Receiver<bool>,
    handler: Arc<F>,
) where
    F: Fn(String, IpcRequest) -> IpcResponse + Send + Sync + 'static,
{
    let ws_url = http_to_ws_relay_url(&relay_url, &identity.peer_id());
    let mut backoff = Duration::from_secs(1);

    loop {
        if *shutdown.borrow() {
            break;
        }

        match tokio_tungstenite::connect_async(&ws_url).await {
            Ok((ws_stream, _)) => {
                info!(relay = %relay_url, peer = %identity.peer_id(), "Connected to curb-relay as P2P host");
                backoff = Duration::from_secs(1);
                let (mut tx, mut rx) = ws_stream.split();

                let mut ping_interval = tokio::time::interval(Duration::from_secs(25));
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                let _ = tx.close().await;
                                return;
                            }
                        }
                        _ = ping_interval.tick() => {
                            if let Ok(json) = serde_json::to_string(&RelayWireMessage::Ping) {
                                if tx.send(Message::Text(json.into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                        incoming = rx.next() => {
                            let Some(Ok(frame)) = incoming else {
                                break;
                            };
                            let Message::Text(text) = frame else {
                                continue;
                            };
                            let Ok(RelayWireMessage::Forward { from: Some(from_peer), payload, .. }) =
                                serde_json::from_str::<RelayWireMessage>(&text)
                            else {
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
                                        if tx.send(Message::Text(json.into())).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(relay = %relay_url, error = %e, "Could not connect to curb-relay; retrying");
            }
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(backoff) => {
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Sends a single E2E-encrypted [`IpcRequest`] to a remote `curb-service` peer
/// via `relay_url` and awaits the decrypted [`IpcResponse`].
pub async fn send_remote_request(
    my_identity: &PeerIdentity,
    relay_url: &str,
    target_peer_id: &str,
    request: &IpcRequest,
) -> Result<IpcResponse> {
    let ws_url = http_to_ws_relay_url(relay_url, &my_identity.peer_id());
    let (ws_stream, _) = tokio::time::timeout(
        Duration::from_secs(8),
        tokio_tungstenite::connect_async(&ws_url),
    )
    .await
    .map_err(|_| P2pError::Network("Timed out connecting to relay server".into()))?
    .map_err(|e| P2pError::Network(format!("Could not connect to relay: {e}")))?;

    let (mut tx, mut rx) = ws_stream.split();
    let request_id = Uuid::new_v4();
    let env = PeerEnvelope::Request {
        request_id,
        request: request.clone(),
    };
    let plaintext = serde_json::to_vec(&env)?;
    let ciphertext = encrypt_for_peer(my_identity, target_peer_id, &plaintext)?;
    let fwd = RelayWireMessage::Forward {
        to: target_peer_id.to_string(),
        from: None,
        payload: ciphertext,
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
                    let pt = decrypt_from_peer(my_identity, target_peer_id, &payload)?;
                    if let Ok(PeerEnvelope::Response {
                        request_id: rid,
                        response,
                    }) = serde_json::from_slice::<PeerEnvelope>(&pt)
                    {
                        if rid == request_id {
                            return Ok(response);
                        }
                    }
                }
                _ => {}
            }
        }
        Err(P2pError::Network("Relay closed before response arrived".into()))
    })
    .await
    .map_err(|_| P2pError::Network("Timed out waiting for remote device response".into()))?;

    let _ = tx.close().await;
    reply
}

/// Checks whether `target_peer_id` is currently online on `relay_url`.
pub async fn check_peer_online(
    my_identity: &PeerIdentity,
    relay_url: &str,
    target_peer_id: &str,
) -> Result<bool> {
    let ws_url = http_to_ws_relay_url(relay_url, &my_identity.peer_id());
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
