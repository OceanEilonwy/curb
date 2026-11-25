use std::path::PathBuf;

use curb_p2p::PeerIdentity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A paired remote device (e.g. a friend's PC) stored locally in `curb-app`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedRemotePeer {
    pub id: Uuid,
    /// User-editable friendly display name (e.g. "Jordan's PC").
    pub name: String,
    /// Hex-encoded X25519 public key of the remote `curb-service`.
    pub peer_id: String,
    /// Relay proxy URL used to reach this peer.
    pub relay_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RemotePeersFile {
    #[serde(default)]
    peers: Vec<SavedRemotePeer>,
}

/// Manages this user's local P2P identity and saved remote friends' devices.
pub struct RemotePeerStore {
    config_dir: PathBuf,
    identity: PeerIdentity,
    peers: Vec<SavedRemotePeer>,
}

impl RemotePeerStore {
    pub fn load_default() -> Self {
        let dir = default_user_config_dir();
        Self::load_from(dir)
    }

    pub fn load_from(config_dir: PathBuf) -> Self {
        let identity = PeerIdentity::load_or_create(&config_dir.join("client_identity.json"))
            .unwrap_or_else(|_| PeerIdentity::generate());
        let peers_path = config_dir.join("remote_peers.json");
        let peers = std::fs::read_to_string(&peers_path)
            .ok()
            .and_then(|s| serde_json::from_str::<RemotePeersFile>(&s).ok())
            .map(|f| f.peers)
            .unwrap_or_default();
        Self {
            config_dir,
            identity,
            peers,
        }
    }

    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    pub fn peers(&self) -> &[SavedRemotePeer] {
        &self.peers
    }

    pub fn find_by_id(&self, id: Uuid) -> Option<SavedRemotePeer> {
        self.peers.iter().find(|p| p.id == id).cloned()
    }

    pub fn upsert_peer(&mut self, name: String, peer_id: String, relay_url: String) -> SavedRemotePeer {
        if let Some(existing) = self.peers.iter_mut().find(|p| p.peer_id == peer_id) {
            existing.name = name;
            existing.relay_url = relay_url;
            let cloned = existing.clone();
            self.persist();
            return cloned;
        }
        let entry = SavedRemotePeer {
            id: Uuid::new_v4(),
            name,
            peer_id,
            relay_url,
        };
        self.peers.push(entry.clone());
        self.persist();
        entry
    }

    pub fn rename_peer(&mut self, id: Uuid, new_name: &str) -> bool {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.name = trimmed.to_string();
            self.persist();
            return true;
        }
        false
    }

    #[allow(dead_code)]
    pub fn remove_peer(&mut self, id: Uuid) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.id != id);
        let removed = self.peers.len() != before;
        if removed {
            self.persist();
        }
        removed
    }

    fn persist(&self) {
        let _ = std::fs::create_dir_all(&self.config_dir);
        let path = self.config_dir.join("remote_peers.json");
        let file = RemotePeersFile {
            peers: self.peers.clone(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&file) {
            let _ = std::fs::write(path, json);
        }
    }
}

fn default_user_config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("Curb");
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("curb");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("curb");
    }
    std::env::temp_dir().join("curb-client")
}
