use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::fmt;

/// NodeId represents a unique identifier for a node, typically hash(public_key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// RoomId represents a unique identifier for a room
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoomId(pub [u8; 16]);

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// SessionId represents a temporary session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// PacketId is a monotonic counter for packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PacketId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    Open,
    Cone,
    Symmetric,
    Unknown,
}

impl fmt::Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// InviteData contains all information needed to join a room
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteData {
    pub version: u8,
    pub primary_supernode: String,
    #[serde(default)]
    pub fallback_supernodes: Vec<String>,
    pub supernode_addr: String,
    pub room_id: RoomId,
    pub room_pub_key: [u8; 32],
    pub virtual_cidr: Option<String>,
    pub token: Option<String>,
    pub expires_at: Option<u64>,
    pub signature: Option<Vec<u8>>,
}

impl InviteData {
    pub const VERSION: u8 = 2;

    pub fn primary_supernode_addr(&self) -> &str {
        if self.primary_supernode.is_empty() {
            &self.supernode_addr
        } else {
            &self.primary_supernode
        }
    }

    pub fn all_supernodes(&self) -> Vec<String> {
        let mut nodes = Vec::new();
        let primary = self.primary_supernode_addr();
        if !primary.is_empty() {
            nodes.push(primary.to_string());
        }
        for node in &self.fallback_supernodes {
            if !node.is_empty() && !nodes.contains(node) {
                nodes.push(node.clone());
            }
        }
        nodes
    }

    pub fn sign(&mut self, key: &ed25519_dalek::SigningKey) {
        self.signature = None;
        let bytes = postcard::to_stdvec(self).unwrap_or_default();
        let sig = key.sign(&bytes);
        self.signature = Some(sig.to_vec());
    }

    pub fn verify(&self, pub_key: &ed25519_dalek::VerifyingKey) -> bool {
        let mut check = self.clone();
        let sig_bytes = match check.signature.take() {
            Some(s) => s,
            None => return false,
        };
        let bytes = postcard::to_stdvec(&check).unwrap_or_default();
        let sig = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        pub_key.verify(&bytes, &sig).is_ok()
    }

    pub fn encode(&self) -> String {
        let bytes = postcard::to_stdvec(self).unwrap_or_default();
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, bytes)
    }

    pub fn decode(s: &str) -> Option<Self> {
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, s).ok()?;
        postcard::from_bytes(&bytes).ok()
    }
}

/// InviteCode is used to share room access
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCode(pub String);

impl fmt::Display for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// VirtualIp represents an IPv4 address within the virtual network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VirtualIp(pub [u8; 4]);

impl fmt::Display for VirtualIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip_preserves_signature() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verify_key = signing_key.verifying_key();
        let mut invite = InviteData {
            version: InviteData::VERSION,
            primary_supernode: "127.0.0.1:7777".to_string(),
            fallback_supernodes: vec!["127.0.0.2:7777".to_string()],
            supernode_addr: "127.0.0.1:7777".to_string(),
            room_id: RoomId([9u8; 16]),
            room_pub_key: [3u8; 32],
            virtual_cidr: Some("10.66.1.0/24".to_string()),
            token: Some("token-123".to_string()),
            expires_at: Some(123456),
            signature: None,
        };
        invite.sign(&signing_key);
        assert!(invite.verify(&verify_key));

        let encoded = invite.encode();
        let decoded = InviteData::decode(&encoded).expect("decode invite");
        assert_eq!(decoded.room_id, invite.room_id);
        assert_eq!(decoded.token, invite.token);
        assert_eq!(decoded.virtual_cidr, invite.virtual_cidr);
        assert_eq!(decoded.primary_supernode_addr(), "127.0.0.1:7777");
        assert_eq!(
            decoded.all_supernodes(),
            vec!["127.0.0.1:7777".to_string(), "127.0.0.2:7777".to_string()]
        );
        assert!(decoded.verify(&verify_key));
    }
}

pub mod ipc {
    pub fn ipc_path() -> String {
        if let Ok(path) = std::env::var("R2N_IPC_PATH") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        #[cfg(unix)]
        {
            let user = std::env::var("USER").unwrap_or_else(|_| "default".to_string());
            format!("/tmp/r2n_ipc_{}.sock", user)
        }
        #[cfg(windows)]
        {
            r"\\.\pipe\r2n_ipc".to_string()
        }
    }
}
