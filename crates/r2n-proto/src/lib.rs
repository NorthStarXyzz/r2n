use r2n_common::{NatType, NodeId, PacketId, RoomId, SessionId, VirtualIp};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::net::SocketAddr;
use std::ops::Range;
use thiserror::Error;

/// Current protocol version
pub const PROTOCOL_VERSION: u8 = 2;
pub const CONTROL_MAGIC: [u8; 4] = *b"R2NC";
pub const DATA_MAGIC: [u8; 4] = *b"R2ND";
pub const DATA_HEADER_SIZE: usize = 148;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateKind {
    HostLan,
    HostIpv6,
    ServerReflexive,
    PortPredicted,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateSource {
    LocalInterface,
    StunPrimary,
    StunSecondary,
    PortMapping,
    PeerReflexive,
    PortPrediction,
    RelayFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub source: CandidateSource,
    pub addr: SocketAddr,
    pub priority: u32,
    pub rtt_hint_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlFrame {
    Hello {
        node_id: NodeId,
        version: u8,
    },
    CreateRoom {
        name: String,
    },
    RoomCreated {
        room_id: RoomId,
        assigned_ip: VirtualIp,
        virtual_cidr: String,
        invite_code: String,
    },
    JoinRoom {
        room_id: RoomId,
        token: Option<String>,
        room_name: Option<String>,
    },
    JoinAccept {
        room_id: RoomId,
        assigned_ip: VirtualIp,
        virtual_cidr: String,
        room_name: Option<String>,
    },
    JoinReject {
        reason: String,
    },
    RegisterNode {
        node_id: NodeId,
        nat_type: NatType,
        external_addr: Option<SocketAddr>,
        public_key: [u8; 32],
        candidates: Vec<Candidate>,
        nickname: String,
        local_networks: Vec<String>,
    },
    RegisterOk,
    PeerList {
        peers: Vec<PeerInfo>,
    },
    PeerUpdate {
        peer: PeerInfo,
        action: PeerAction,
    },
    PunchRequest {
        target: NodeId,
        candidates: Vec<Candidate>,
    },
    PunchCandidate {
        from: NodeId,
        candidates: Vec<Candidate>,
    },
    RelayOffer {
        target: NodeId,
    },
    RelayAccept {
        relay_id: String,
    },
    Heartbeat,
    LeaveRoom {
        room_id: RoomId,
    },
    Handshake {
        from: NodeId,
        payload: Vec<u8>,
    },
    Error {
        code: u16,
        message: String,
    },
    QueryRooms,
    RoomsList {
        rooms: Vec<RoomDescription>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomDescription {
    pub room_id: RoomId,
    pub name: String,
    pub member_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub virtual_ip: VirtualIp,
    pub nickname: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PeerAction {
    Add,
    Remove,
    Update,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataPacketType {
    IPv4,
    IPv6,
    Broadcast,
    Multicast,
    Discovery,
    Keepalive,
    Ping,
    Pong,
    Ethernet,
}

impl DataPacketType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::IPv4 => 0,
            Self::IPv6 => 1,
            Self::Broadcast => 2,
            Self::Multicast => 3,
            Self::Discovery => 4,
            Self::Keepalive => 5,
            Self::Ping => 6,
            Self::Pong => 7,
            Self::Ethernet => 8,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::IPv4),
            1 => Some(Self::IPv6),
            2 => Some(Self::Broadcast),
            3 => Some(Self::Multicast),
            4 => Some(Self::Discovery),
            5 => Some(Self::Keepalive),
            6 => Some(Self::Ping),
            7 => Some(Self::Pong),
            8 => Some(Self::Ethernet),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    pub version: u8,
    pub flags: u8,
    pub packet_type: DataPacketType,
    pub reserved: u8,
    pub ttl: u8,
    pub room_id: RoomId,
    pub src_node: NodeId,
    pub dst_node: NodeId,
    pub origin_node: NodeId,
    pub session_id: SessionId,
    pub nonce: u64,
    pub packet_id: PacketId,
    pub payload_len: u16,
}

#[derive(Debug, Error)]
pub enum DataHeaderError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid data magic")]
    InvalidMagic,
    #[error("invalid packet type")]
    InvalidPacketType,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("payload length mismatch")]
    InvalidPayloadLength,
}

impl DataHeader {
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<(), DataHeaderError> {
        if buf.len() < DATA_HEADER_SIZE {
            return Err(DataHeaderError::BufferTooShort);
        }

        buf[0..4].copy_from_slice(&DATA_MAGIC);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6] = self.packet_type.as_u8();
        buf[7] = self.ttl;
        buf[8..24].copy_from_slice(&self.room_id.0);
        buf[24..56].copy_from_slice(&self.src_node.0);
        buf[56..88].copy_from_slice(&self.dst_node.0);
        buf[88..120].copy_from_slice(&self.origin_node.0);
        buf[120..128].copy_from_slice(&self.session_id.0.to_be_bytes());
        buf[128..136].copy_from_slice(&self.nonce.to_be_bytes());
        buf[136..144].copy_from_slice(&self.packet_id.0.to_be_bytes());
        buf[144..146].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[146] = self.reserved;
        buf[147] = 0;
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DataHeaderError> {
        if buf.len() < DATA_HEADER_SIZE {
            return Err(DataHeaderError::BufferTooShort);
        }
        if buf[0..4] != DATA_MAGIC {
            return Err(DataHeaderError::InvalidMagic);
        }
        if buf[4] != PROTOCOL_VERSION {
            return Err(DataHeaderError::UnsupportedVersion);
        }

        let packet_type =
            DataPacketType::from_u8(buf[6]).ok_or(DataHeaderError::InvalidPacketType)?;
        Ok(Self {
            version: buf[4],
            flags: buf[5],
            packet_type,
            reserved: buf[146],
            ttl: buf[7],
            room_id: RoomId(buf[8..24].try_into().expect("room id slice length")),
            src_node: NodeId(buf[24..56].try_into().expect("src node slice length")),
            dst_node: NodeId(buf[56..88].try_into().expect("dst node slice length")),
            origin_node: NodeId(buf[88..120].try_into().expect("origin node slice length")),
            session_id: SessionId(u64::from_be_bytes(
                buf[120..128].try_into().expect("session id slice length"),
            )),
            nonce: u64::from_be_bytes(buf[128..136].try_into().expect("nonce slice length")),
            packet_id: PacketId(u64::from_be_bytes(
                buf[136..144].try_into().expect("packet id slice length"),
            )),
            payload_len: u16::from_be_bytes(
                buf[144..146]
                    .try_into()
                    .expect("payload length slice length"),
            ),
        })
    }

    pub fn payload_range(&self) -> Range<usize> {
        DATA_HEADER_SIZE..DATA_HEADER_SIZE + self.payload_len as usize
    }

    pub fn frame_len(&self) -> usize {
        DATA_HEADER_SIZE + self.payload_len as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_header_roundtrip() {
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0x11,
            packet_type: DataPacketType::IPv4,
            reserved: 0,
            ttl: 1,
            room_id: RoomId([7u8; 16]),
            src_node: NodeId([1u8; 32]),
            dst_node: NodeId([2u8; 32]),
            origin_node: NodeId([1u8; 32]),
            session_id: SessionId(42),
            nonce: 99,
            packet_id: PacketId(123),
            payload_len: 512,
        };

        let mut buf = [0u8; DATA_HEADER_SIZE];
        header.encode_into(&mut buf).expect("encode header");
        let decoded = DataHeader::decode(&buf).expect("decode header");
        assert_eq!(decoded, header);
        assert_eq!(
            decoded.payload_range(),
            DATA_HEADER_SIZE..DATA_HEADER_SIZE + 512
        );
    }

    #[test]
    fn rejects_old_data_header_version() {
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type: DataPacketType::IPv4,
            reserved: 0,
            ttl: 1,
            room_id: RoomId([7u8; 16]),
            src_node: NodeId([1u8; 32]),
            dst_node: NodeId([2u8; 32]),
            origin_node: NodeId([1u8; 32]),
            session_id: SessionId(42),
            nonce: 99,
            packet_id: PacketId(123),
            payload_len: 512,
        };

        let mut buf = [0u8; DATA_HEADER_SIZE];
        header.encode_into(&mut buf).expect("encode header");
        buf[4] = 1;
        let err = DataHeader::decode(&buf).expect_err("old header version rejected");
        assert!(matches!(err, DataHeaderError::UnsupportedVersion));
    }

    #[test]
    fn rejects_invalid_magic_and_packet_type() {
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type: DataPacketType::Ethernet,
            reserved: 0,
            ttl: 1,
            room_id: RoomId([7u8; 16]),
            src_node: NodeId([1u8; 32]),
            dst_node: NodeId([2u8; 32]),
            origin_node: NodeId([1u8; 32]),
            session_id: SessionId(42),
            nonce: 99,
            packet_id: PacketId(123),
            payload_len: 512,
        };

        let mut buf = [0u8; DATA_HEADER_SIZE];
        header.encode_into(&mut buf).expect("encode header");
        buf[0] = b'X';
        let err = DataHeader::decode(&buf).expect_err("invalid magic rejected");
        assert!(matches!(err, DataHeaderError::InvalidMagic));

        header.encode_into(&mut buf).expect("encode header");
        buf[6] = 99;
        let err = DataHeader::decode(&buf).expect_err("invalid packet type rejected");
        assert!(matches!(err, DataHeaderError::InvalidPacketType));
    }
}
