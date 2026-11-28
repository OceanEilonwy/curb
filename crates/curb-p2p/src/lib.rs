pub mod backup;
pub mod crypto;
pub mod identity;
pub mod invites;
pub mod transport;

use thiserror::Error;

pub use backup::{download_encrypted_backup, upload_encrypted_backup};
pub use identity::PeerIdentity;
pub use invites::{
    decrypt_invite_descriptor_b64, delete_invite_slot, fetch_invite_descriptor,
    fetch_invite_descriptor_b64, fetch_invite_descriptor_raw, fetch_peers_presence,
    poll_invite_claim, publish_invite_descriptor, submit_invite_claim, InviteClaim,
};
pub use transport::{
    check_peer_online, forward_relay_frame, open_remote_request, open_remote_response,
    run_p2p_host, run_p2p_host_with_status, seal_remote_request, send_remote_request,
};

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Remote device is offline")]
    PeerOffline,
}

pub type Result<T> = std::result::Result<T, P2pError>;

#[cfg(test)]
mod tests {
    use super::*;
    use curb_core::ipc::{IpcRequest, IpcResponse};
    use curb_relay::{build_router, RelayConfig};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    #[tokio::test]
    async fn e2e_encrypted_ipc_round_trip_through_relay() {
        // Start an in-process zero-knowledge curb-relay
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay_url = format!("http://{addr}");
        tokio::spawn(async move {
            axum::serve(listener, build_router(RelayConfig::default()))
                .await
                .unwrap();
        });

        let host_id = PeerIdentity::generate();
        let friend_id = PeerIdentity::generate();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let host_peer_id = host_id.peer_id();
        let expected_friend = friend_id.peer_id();

        let host_handle = tokio::spawn(run_p2p_host(
            host_id,
            relay_url.clone(),
            shutdown_rx,
            Arc::new(move |from_peer, req| {
                assert_eq!(from_peer, expected_friend);
                match req {
                    IpcRequest::UnlockAsPeer { peer_id, password } => {
                        assert_eq!(peer_id, from_peer);
                        if password == "alex-secret" {
                            IpcResponse::Unlocked {
                                token: "sess-123".into(),
                            }
                        } else {
                            IpcResponse::Error {
                                message: "Incorrect password".into(),
                            }
                        }
                    }
                    _ => IpcResponse::Ok,
                }
            }),
        ));

        // Give host a brief moment to register on relay
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        assert!(check_peer_online(&friend_id, &relay_url, &host_peer_id)
            .await
            .unwrap());

        let resp = send_remote_request(
            &friend_id,
            &relay_url,
            &host_peer_id,
            &IpcRequest::UnlockAsPeer {
                peer_id: friend_id.peer_id(),
                password: "alex-secret".into(),
            },
        )
        .await
        .unwrap();

        assert!(matches!(resp, IpcResponse::Unlocked { token } if token == "sess-123"));

        let _ = shutdown_tx.send(true);
        let _ = host_handle.await;
    }
}
