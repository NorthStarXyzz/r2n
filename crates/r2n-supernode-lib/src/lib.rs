use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use ipnet::Ipv4Net;
use r2n_common::{InviteData, NatType, NodeId, RoomId, VirtualIp};
use r2n_config::SupernodeConfig;
use r2n_proto::{Candidate, ControlFrame, PeerAction, PeerInfo};
use r2n_room::{Member, MemberRole, Room, RoomAddressPool};
use r2n_transport::{TransportPacket, UdpTransport};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct Supernode {
    transport: Arc<UdpTransport>,
    nodes: DashMap<NodeId, NodeInfo>,
    addr_to_node: DashMap<SocketAddr, NodeId>,
    rooms: DashMap<RoomId, Room>,
    invite_signing_key: SigningKey,
    slab: Arc<r2n_slab::PacketSlab>,
    config: SupernodeConfig,
    address_pool: Arc<std::sync::Mutex<RoomAddressPool>>,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub nat_type: NatType,
    pub external_addr: Option<SocketAddr>,
    pub public_key: [u8; 32],
    pub candidates: Vec<Candidate>,
    pub nickname: String,
    pub local_networks: Vec<Ipv4Net>,
    pub last_seen: std::time::Instant,
}

impl Supernode {
    pub async fn new(addr: &str) -> anyhow::Result<Self> {
        let config = SupernodeConfig::default();
        Self::new_with_config(addr, config).await
    }

    pub async fn new_with_config(addr: &str, config: SupernodeConfig) -> anyhow::Result<Self> {
        let transport = UdpTransport::bind(addr).await?;
        let slab = r2n_slab::PacketSlab::default_pool(4096);
        let address_pool = RoomAddressPool::new(&config.address_pool, config.room_prefix_len)?;
        Ok(Self {
            transport: Arc::new(transport),
            nodes: DashMap::new(),
            addr_to_node: DashMap::new(),
            rooms: DashMap::new(),
            invite_signing_key: SigningKey::from_bytes(&rand::random::<[u8; 32]>()),
            slab,
            config,
            address_pool: Arc::new(std::sync::Mutex::new(address_pool)),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let nodes_clone = self.nodes.clone();
        let addr_to_node_clone = self.addr_to_node.clone();
        let rooms_clone = self.rooms.clone();
        let transport_clone = self.transport.clone();
        self.spawn_management_api().await?;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                let mut dead_nodes = Vec::new();
                for entry in nodes_clone.iter() {
                    // 120 seconds timeout for zombies
                    if now.duration_since(entry.last_seen).as_secs() > 120 {
                        dead_nodes.push(*entry.key());
                    }
                }

                for dead_node in dead_nodes {
                    log::info!(
                        "Node {} timed out (120s), removing from supernode",
                        dead_node
                    );
                    if let Some((_, info)) = nodes_clone.remove(&dead_node) {
                        addr_to_node_clone.remove(&info.addr);
                        let mut empty_rooms = Vec::new();
                        for mut room_entry in rooms_clone.iter_mut() {
                            let room = room_entry.value_mut();
                            if room.members.remove(&dead_node).is_some() {
                                let notify = ControlFrame::PeerUpdate {
                                    peer: PeerInfo {
                                        node_id: dead_node,
                                        public_key: info.public_key,
                                        virtual_ip: VirtualIp([0, 0, 0, 0]),
                                        nickname: info.nickname.clone(),
                                    },
                                    action: PeerAction::Remove,
                                };
                                for member in room.members.values() {
                                    if let Some(target) = nodes_clone.get(&member.node_id) {
                                        let _ = transport_clone
                                            .send_control(&notify, target.addr)
                                            .await;
                                    }
                                }
                            }
                            if room.members.is_empty() {
                                empty_rooms.push(*room_entry.key());
                            }
                        }
                        for r in empty_rooms {
                            rooms_clone.remove(&r);
                        }
                    }
                }
            }
        });

        #[cfg(not(test))]
        {
            let rooms = self.rooms.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut reader = tokio::io::BufReader::new(tokio::io::stdin()).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    let line = line.trim();
                    if line == "rooms" || line == "list" {
                        println!("--- Active Rooms ---");
                        if rooms.is_empty() {
                            println!("No active rooms.");
                        } else {
                            for entry in rooms.iter() {
                                let room = entry.value();
                                println!(
                                    "ID: {}, Name: {}, Members: {}",
                                    room.room_id,
                                    room.name,
                                    room.members.len()
                                );
                            }
                        }
                        println!("--------------------");
                    }
                }
            });
        }

        log::info!("Supernode running on {}", self.transport.local_addr()?);
        let slab = self.slab.clone();
        let mut recv_buf = [0u8; 65535];

        loop {
            match self.transport.recv_packet(&mut recv_buf).await {
                Ok((TransportPacket::Control(packet), addr)) => {
                    if let Some(node_id) = self.addr_to_node.get(&addr).map(|entry| *entry.value())
                        && let Some(mut node) = self.nodes.get_mut(&node_id)
                    {
                        node.last_seen = std::time::Instant::now();
                    }
                    if let Err(err) = self.handle_control(packet, addr).await {
                        log::error!("handle control error: {err:#}");
                    }
                }
                Ok((TransportPacket::Data(frame), addr)) => {
                    if let Some(node_id) = self.addr_to_node.get(&addr).map(|entry| *entry.value())
                        && let Some(mut node) = self.nodes.get_mut(&node_id)
                    {
                        node.last_seen = std::time::Instant::now();
                    }
                    let frame_len = frame.header.frame_len();
                    let dst_node = frame.header.dst_node;

                    if let Some(target_info) = self.nodes.get(&dst_node) {
                        let Some(desc) = slab.acquire() else {
                            log::warn!("Supernode slab pool exhausted; dropping relay frame");
                            continue;
                        };
                        if frame_len > r2n_slab::DEFAULT_FRAME_CAP {
                            log::warn!(
                                "relay frame length {} exceeds slab frame capacity {}",
                                frame_len,
                                r2n_slab::DEFAULT_FRAME_CAP
                            );
                            slab.release(desc);
                            continue;
                        }
                        slab.with_slot_mut(desc, |slot| {
                            slot[..frame_len].copy_from_slice(&recv_buf[..frame_len]);
                        });

                        let target_addr = target_info.addr;
                        let transport = self.transport.clone();
                        let slab_clone = slab.clone();
                        tokio::spawn(async move {
                            let frame_slice = slab_clone.get_slot_slice(&desc);
                            log::debug!("Relaying dataplane frame to {}", dst_node);
                            if let Err(err) = transport
                                .send_raw(&frame_slice[..frame_len], target_addr)
                                .await
                            {
                                log::error!("relay error: {err:#}");
                            }
                            slab_clone.release(desc);
                        });
                    } else {
                        log::warn!("relay target {} not found", dst_node);
                    }
                }
                Err(err) => {
                    log::error!("transport error: {}", err);
                }
            }
        }
    }

    async fn handle_control(&self, frame: ControlFrame, addr: SocketAddr) -> anyhow::Result<()> {
        match frame {
            ControlFrame::RegisterNode {
                node_id,
                nat_type,
                external_addr,
                public_key,
                candidates,
                nickname,
                local_networks,
            } => {
                log::info!(
                    "Registering node {} ({}) from {} with NAT {:?}",
                    node_id,
                    nickname,
                    addr,
                    nat_type
                );
                let parsed_local_networks = parse_local_networks(&local_networks);
                self.nodes.insert(
                    node_id,
                    NodeInfo {
                        node_id,
                        addr,
                        nat_type,
                        external_addr,
                        public_key,
                        candidates: candidates.clone(),
                        nickname,
                        local_networks: parsed_local_networks,
                        last_seen: std::time::Instant::now(),
                    },
                );
                self.addr_to_node.insert(addr, node_id);
                self.transport
                    .send_control(&ControlFrame::RegisterOk, addr)
                    .await?;

                let mut peers_to_update = Vec::new();
                for entry in self.rooms.iter() {
                    let room = entry.value();
                    if room.members.contains_key(&node_id) {
                        for member in room.members.values() {
                            if member.node_id != node_id
                                && let Some(existing_node) =
                                    self.nodes.get(&member.node_id).map(|e| e.value().clone())
                            {
                                peers_to_update.push(existing_node.addr);
                            }
                        }
                    }
                }

                for peer_addr in peers_to_update {
                    let _ = self
                        .transport
                        .send_control(
                            &ControlFrame::PunchRequest {
                                target: node_id,
                                candidates: candidates.clone(),
                            },
                            peer_addr,
                        )
                        .await;
                }
            }
            ControlFrame::CreateRoom { name } => {
                let Some(node_id) = self.addr_to_node.get(&addr).map(|entry| *entry.value()) else {
                    self.transport
                        .send_control(
                            &ControlFrame::Error {
                                code: 400,
                                message: "node not registered".to_string(),
                            },
                            addr,
                        )
                        .await?;
                    return Ok(());
                };

                let room_id = RoomId(rand::random::<[u8; 16]>());
                let join_token = hex::encode(rand::random::<[u8; 16]>());
                let owner_local_networks = self
                    .nodes
                    .get(&node_id)
                    .map(|entry| entry.local_networks.clone())
                    .unwrap_or_default();
                let virtual_cidr = self
                    .address_pool
                    .lock()
                    .expect("address pool lock")
                    .allocate_with_avoidance(room_id, &owner_local_networks)?
                    .to_string();
                let mut room = Room::new(
                    room_id,
                    name.clone(),
                    node_id,
                    virtual_cidr.clone(),
                    join_token.clone(),
                );
                let owner_nickname = self
                    .nodes
                    .get(&node_id)
                    .map(|entry| entry.nickname.clone())
                    .unwrap_or_else(|| "Owner".to_string());
                let assigned_ip =
                    room.add_or_reuse_member(node_id, owner_nickname, MemberRole::Owner)?;
                self.rooms.insert(room_id, room);

                let primary_supernode = self.public_supernode_addr()?;
                let mut invite = InviteData {
                    version: InviteData::VERSION,
                    primary_supernode: primary_supernode.clone(),
                    fallback_supernodes: self.config.peers.clone(),
                    supernode_addr: primary_supernode,
                    room_id,
                    room_pub_key: self
                        .nodes
                        .get(&node_id)
                        .map(|entry| entry.public_key)
                        .unwrap_or([0u8; 32]),
                    virtual_cidr: Some(virtual_cidr.clone()),
                    token: Some(join_token),
                    expires_at: None,
                    signature: None,
                };
                invite.sign(&self.invite_signing_key);

                log::info!("Created room {} ({}) for {}", room_id, name, node_id);
                self.transport
                    .send_control(
                        &ControlFrame::RoomCreated {
                            room_id,
                            assigned_ip,
                            virtual_cidr,
                            invite_code: invite.encode(),
                        },
                        addr,
                    )
                    .await?;
            }
            ControlFrame::JoinRoom {
                room_id,
                token,
                room_name,
            } => {
                let Some(node_id) = self.addr_to_node.get(&addr).map(|entry| *entry.value()) else {
                    self.transport
                        .send_control(
                            &ControlFrame::JoinReject {
                                reason: "node not registered".to_string(),
                            },
                            addr,
                        )
                        .await?;
                    return Ok(());
                };

                let mut room = self.rooms.entry(room_id).or_insert_with(|| {
                    let name = room_name
                        .clone()
                        .unwrap_or_else(|| format!("Restored-{}", room_id));
                    log::info!("Re-creating room {} ({}) on demand", room_id, name);
                    let virtual_cidr = self
                        .address_pool
                        .lock()
                        .expect("address pool lock")
                        .allocate(room_id)
                        .map(|cidr| cidr.to_string())
                        .unwrap_or_else(|err| {
                            log::warn!("failed to allocate restored room CIDR: {}", err);
                            "192.168.255.0/24".to_string()
                        });
                    Room::new(
                        room_id,
                        name,
                        node_id,
                        virtual_cidr,
                        token.clone().unwrap_or_default(),
                    )
                });

                if room.join_token != token.unwrap_or_default() {
                    self.transport
                        .send_control(
                            &ControlFrame::JoinReject {
                                reason: "invalid invite token".to_string(),
                            },
                            addr,
                        )
                        .await?;
                    return Ok(());
                }

                let joining_local_networks = self
                    .nodes
                    .get(&node_id)
                    .map(|entry| entry.local_networks.clone())
                    .unwrap_or_default();
                if room_subnet_conflicts(&room.virtual_cidr, &joining_local_networks) {
                    self.transport
                        .send_control(
                            &ControlFrame::JoinReject {
                                reason: "room subnet conflicts with a local network on this device"
                                    .to_string(),
                            },
                            addr,
                        )
                        .await?;
                    return Ok(());
                }

                let assigned_ip = if let Some(existing) = room.members.get(&node_id) {
                    existing.virtual_ip
                } else {
                    let guest_nickname = self
                        .nodes
                        .get(&node_id)
                        .map(|entry| entry.nickname.clone())
                        .unwrap_or_else(|| format!("Peer{}", room.members.len() + 1));
                    room.add_or_reuse_member(node_id, guest_nickname, MemberRole::Guest)?
                };
                let joined_member = room
                    .members
                    .get(&node_id)
                    .cloned()
                    .expect("member inserted");
                let joined_peer = self.peer_info_for_member(&joined_member);

                log::info!("Node {} joined room {}", node_id, room_id);
                self.transport
                    .send_control(
                        &ControlFrame::JoinAccept {
                            room_id,
                            assigned_ip,
                            virtual_cidr: room.virtual_cidr.clone(),
                            room_name: Some(room.name.clone()),
                        },
                        addr,
                    )
                    .await?;

                let peers: Vec<PeerInfo> = room
                    .members
                    .values()
                    .map(|member| self.peer_info_for_member(member))
                    .collect();

                self.transport
                    .send_control(
                        &ControlFrame::PeerList {
                            peers: peers.clone(),
                        },
                        addr,
                    )
                    .await?;

                for member in room.members.values() {
                    if member.node_id == node_id {
                        continue;
                    }
                    if let Some(existing_node) =
                        self.nodes.get(&member.node_id).map(|entry| entry.clone())
                    {
                        self.transport
                            .send_control(
                                &ControlFrame::PeerUpdate {
                                    peer: joined_peer.clone(),
                                    action: PeerAction::Add,
                                },
                                existing_node.addr,
                            )
                            .await?;
                    }
                }

                if let Some(new_node) = self.nodes.get(&node_id).map(|entry| entry.clone()) {
                    for peer_info in peers {
                        if peer_info.node_id == node_id {
                            continue;
                        }
                        if let Some(existing_node) = self
                            .nodes
                            .get(&peer_info.node_id)
                            .map(|entry| entry.clone())
                        {
                            self.transport
                                .send_control(
                                    &ControlFrame::PunchRequest {
                                        target: node_id,
                                        candidates: new_node.candidates.clone(),
                                    },
                                    existing_node.addr,
                                )
                                .await?;
                            self.transport
                                .send_control(
                                    &ControlFrame::PunchRequest {
                                        target: peer_info.node_id,
                                        candidates: existing_node.candidates.clone(),
                                    },
                                    addr,
                                )
                                .await?;
                        }
                    }
                }
            }
            ControlFrame::LeaveRoom { room_id } => {
                let Some(node_id) = self.addr_to_node.get(&addr).map(|entry| *entry.value()) else {
                    return Ok(());
                };
                let Some(mut room) = self.rooms.get_mut(&room_id) else {
                    return Ok(());
                };

                let removed_member = room.members.get(&node_id).cloned();
                room.remove_member(&node_id);
                log::info!("Node {} left room {}", node_id, room_id);

                if let Some(removed_member) = removed_member {
                    let removed_peer = self.peer_info_for_member(&removed_member);
                    for member in room.members.values() {
                        if let Some(existing_node) =
                            self.nodes.get(&member.node_id).map(|entry| entry.clone())
                        {
                            self.transport
                                .send_control(
                                    &ControlFrame::PeerUpdate {
                                        peer: removed_peer.clone(),
                                        action: PeerAction::Remove,
                                    },
                                    existing_node.addr,
                                )
                                .await?;
                        }
                    }
                }

                if room.members.is_empty() {
                    self.rooms.remove(&room_id);
                    self.address_pool
                        .lock()
                        .expect("address pool lock")
                        .release(&room_id);
                }
            }
            ControlFrame::Heartbeat => {
                let _ = self
                    .transport
                    .send_control(&ControlFrame::Heartbeat, addr)
                    .await;
            }
            ControlFrame::QueryRooms => {
                let rooms_list: Vec<r2n_proto::RoomDescription> = self
                    .rooms
                    .iter()
                    .map(|entry| {
                        let room = entry.value();
                        r2n_proto::RoomDescription {
                            room_id: room.room_id,
                            name: room.name.clone(),
                            member_count: room.members.len(),
                        }
                    })
                    .collect();
                let _ = self
                    .transport
                    .send_control(&ControlFrame::RoomsList { rooms: rooms_list }, addr)
                    .await;
            }
            other => {
                log::debug!("Unhandled control frame from {}: {:?}", addr, other);
            }
        }
        Ok(())
    }

    fn peer_info_for_member(&self, member: &Member) -> PeerInfo {
        PeerInfo {
            node_id: member.node_id,
            virtual_ip: member.virtual_ip,
            nickname: member.nickname.clone(),
            public_key: self
                .nodes
                .get(&member.node_id)
                .map(|entry| entry.public_key)
                .unwrap_or([0u8; 32]),
        }
    }

    fn public_supernode_addr(&self) -> std::io::Result<String> {
        if let Some(addr) = &self.config.public_addr
            && !addr.trim().is_empty()
        {
            return Ok(addr.clone());
        }
        Ok(self.transport.local_addr()?.to_string())
    }

    async fn spawn_management_api(&self) -> anyhow::Result<()> {
        let bind = self.config.management_bind.trim();
        if bind.is_empty() {
            return Ok(());
        }
        let addr: SocketAddr = bind.parse()?;
        let state = ManagementState {
            nodes: self.nodes.clone(),
            rooms: self.rooms.clone(),
            peers: self.config.peers.clone(),
            federation_id: self.config.federation_id.clone(),
            admin_token: self.config.admin_token.clone(),
        };
        let app = management_router(state);
        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => listener,
                Err(err) => {
                    log::warn!("failed to bind supernode management API {}: {}", addr, err);
                    return;
                }
            };
            log::info!("Supernode management API listening on {}", addr);
            if let Err(err) = axum::serve(listener, app).await {
                log::warn!("supernode management API stopped: {}", err);
            }
        });
        Ok(())
    }
}

fn parse_local_networks(networks: &[String]) -> Vec<Ipv4Net> {
    networks
        .iter()
        .filter_map(|cidr| match cidr.parse() {
            Ok(network) => Some(network),
            Err(err) => {
                log::warn!("ignoring invalid local network {cidr}: {err}");
                None
            }
        })
        .collect()
}

fn room_subnet_conflicts(room_virtual_cidr: &str, local_networks: &[Ipv4Net]) -> bool {
    let Ok(room_network) = room_virtual_cidr.parse::<Ipv4Net>() else {
        return false;
    };
    local_networks
        .iter()
        .copied()
        .any(|local| ipv4_nets_overlap(room_network, local))
}

fn ipv4_nets_overlap(a: Ipv4Net, b: Ipv4Net) -> bool {
    let a_start = u32::from(a.network());
    let a_end = u32::from(a.broadcast());
    let b_start = u32::from(b.network());
    let b_end = u32::from(b.broadcast());
    a_start <= b_end && b_start <= a_end
}

#[derive(Clone)]
struct ManagementState {
    nodes: DashMap<NodeId, NodeInfo>,
    rooms: DashMap<RoomId, Room>,
    peers: Vec<String>,
    federation_id: String,
    admin_token: String,
}

fn management_router(state: ManagementState) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/health", get(management_health))
        .route("/rooms", get(management_rooms))
        .route("/nodes", get(management_nodes))
        .route("/stats", get(management_stats))
        .route("/federation", get(management_federation))
        .route("/nodes/:node_id/kick", post(management_kick_node))
        .with_state(state)
}

fn authorized(headers: &axum::http::HeaderMap, token: &str) -> bool {
    if token.trim().is_empty() {
        return false;
    }
    let bearer = format!("Bearer {token}");
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == bearer)
        .unwrap_or(false)
        || headers
            .get("x-r2n-admin-token")
            .and_then(|value| value.to_str().ok())
            .map(|value| value == token)
            .unwrap_or(false)
}

async fn management_health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn management_rooms(
    axum::extract::State(state): axum::extract::State<ManagementState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    if !authorized(&headers, &state.admin_token) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let rooms = state
        .rooms
        .iter()
        .map(|entry| {
            let room = entry.value();
            serde_json::json!({
                "room_id": room.room_id.to_string(),
                "name": room.name,
                "virtual_cidr": room.virtual_cidr,
                "members": room.members.len(),
                "leases": room.ip_leases.len()
            })
        })
        .collect::<Vec<_>>();
    Ok(axum::Json(serde_json::json!({ "rooms": rooms })))
}

async fn management_nodes(
    axum::extract::State(state): axum::extract::State<ManagementState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    if !authorized(&headers, &state.admin_token) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let nodes = state
        .nodes
        .iter()
        .map(|entry| {
            let node = entry.value();
            serde_json::json!({
                "node_id": node.node_id.to_string(),
                "addr": node.addr.to_string(),
                "nat_type": node.nat_type.to_string(),
                "nickname": node.nickname,
                "candidates": node.candidates.len(),
                "last_seen_secs": node.last_seen.elapsed().as_secs()
            })
        })
        .collect::<Vec<_>>();
    Ok(axum::Json(serde_json::json!({ "nodes": nodes })))
}

async fn management_stats(
    axum::extract::State(state): axum::extract::State<ManagementState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    if !authorized(&headers, &state.admin_token) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    Ok(axum::Json(serde_json::json!({
        "rooms": state.rooms.len(),
        "nodes": state.nodes.len(),
        "relay_load": {
            "active_nodes": state.nodes.len()
        }
    })))
}

async fn management_federation(
    axum::extract::State(state): axum::extract::State<ManagementState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    if !authorized(&headers, &state.admin_token) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    Ok(axum::Json(serde_json::json!({
        "federation_id": state.federation_id,
        "peers": state.peers
    })))
}

async fn management_kick_node(
    axum::extract::State(state): axum::extract::State<ManagementState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(node_id): axum::extract::Path<String>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    if !authorized(&headers, &state.admin_token) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    let decoded = hex::decode(node_id).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    let removed = state.nodes.remove(&NodeId(bytes)).is_some();
    Ok(axum::Json(serde_json::json!({ "removed": removed })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2n_common::SessionId;
    use r2n_proto::{
        Candidate, CandidateKind, CandidateSource, DATA_HEADER_SIZE, DataHeader, DataPacketType,
        PROTOCOL_VERSION,
    };
    use r2n_transport::TransportPacket;
    use std::time::Duration;

    fn dummy_candidate(addr: SocketAddr) -> Candidate {
        Candidate {
            kind: CandidateKind::ServerReflexive,
            source: CandidateSource::StunPrimary,
            addr,
            priority: 100,
            rtt_hint_ms: None,
        }
    }

    async fn recv_control(transport: &UdpTransport) -> (ControlFrame, SocketAddr) {
        let mut buf = [0u8; 2048];
        loop {
            let (packet, addr) = transport.recv_packet(&mut buf).await.expect("recv packet");
            if let TransportPacket::Control(frame) = packet {
                return (frame, addr);
            }
        }
    }

    #[tokio::test]
    async fn create_and_join_room_roundtrip() {
        let supernode = Arc::new(Supernode::new("127.0.0.1:0").await.expect("supernode"));
        let supernode_addr = supernode.local_addr().expect("addr");
        let server = supernode.clone();
        let server_task = tokio::spawn(async move { server.run().await });

        let owner = UdpTransport::bind("127.0.0.1:0").await.expect("owner");
        let owner_addr = owner.local_addr().expect("owner addr");
        owner
            .send_control(
                &ControlFrame::RegisterNode {
                    node_id: NodeId([1u8; 32]),
                    nat_type: NatType::Cone,
                    external_addr: Some(owner_addr),
                    public_key: [9u8; 32],
                    candidates: vec![dummy_candidate(owner_addr)],
                    nickname: "Owner".to_string(),
                    local_networks: vec!["192.168.200.0/24".to_string()],
                },
                supernode_addr,
            )
            .await
            .expect("register owner");
        let (frame, _) = recv_control(&owner).await;
        assert!(matches!(frame, ControlFrame::RegisterOk));

        owner
            .send_control(
                &ControlFrame::CreateRoom {
                    name: "test-room".to_string(),
                },
                supernode_addr,
            )
            .await
            .expect("create room");
        let (frame, _) = recv_control(&owner).await;
        let (room_id, invite_code) = match frame {
            ControlFrame::RoomCreated {
                room_id,
                assigned_ip,
                invite_code,
                ..
            } => {
                assert_eq!(assigned_ip, VirtualIp([192, 168, 201, 1]));
                (room_id, invite_code)
            }
            other => panic!("unexpected frame: {other:?}"),
        };

        let invite = InviteData::decode(&invite_code).expect("decode invite");
        assert_eq!(invite.room_id, room_id);
        assert_eq!(invite.supernode_addr, supernode_addr.to_string());
        assert!(invite.token.is_some());

        let guest = UdpTransport::bind("127.0.0.1:0").await.expect("guest");
        let guest_addr = guest.local_addr().expect("guest addr");
        guest
            .send_control(
                &ControlFrame::RegisterNode {
                    node_id: NodeId([2u8; 32]),
                    nat_type: NatType::Cone,
                    external_addr: Some(guest_addr),
                    public_key: [8u8; 32],
                    candidates: vec![dummy_candidate(guest_addr)],
                    nickname: "Guest".to_string(),
                    local_networks: vec![],
                },
                supernode_addr,
            )
            .await
            .expect("register guest");
        let (frame, _) = recv_control(&guest).await;
        assert!(matches!(frame, ControlFrame::RegisterOk));

        guest
            .send_control(
                &ControlFrame::JoinRoom {
                    room_id,
                    token: invite.token.clone(),
                    room_name: None,
                },
                supernode_addr,
            )
            .await
            .expect("join room");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut saw_join_accept = false;
        let mut saw_peer_list = false;
        while tokio::time::Instant::now() < deadline && !(saw_join_accept && saw_peer_list) {
            let (frame, _) = recv_control(&guest).await;
            match frame {
                ControlFrame::JoinAccept {
                    assigned_ip,
                    virtual_cidr,
                    ..
                } => {
                    saw_join_accept = true;
                    assert_eq!(assigned_ip, VirtualIp([192, 168, 201, 2]));
                    assert_eq!(virtual_cidr, "192.168.201.0/24");
                }
                ControlFrame::PeerList { peers } => {
                    saw_peer_list = true;
                    assert_eq!(peers.len(), 2);
                }
                _ => {}
            }
        }

        assert!(saw_join_accept);
        assert!(saw_peer_list);
        server_task.abort();
    }

    #[tokio::test]
    async fn relay_forwards_raw_frames() {
        let supernode = Arc::new(Supernode::new("127.0.0.1:0").await.expect("supernode"));
        let supernode_addr = supernode.local_addr().expect("addr");
        let server = supernode.clone();
        let server_task = tokio::spawn(async move { server.run().await });

        let sender = UdpTransport::bind("127.0.0.1:0").await.expect("sender");
        let receiver = UdpTransport::bind("127.0.0.1:0").await.expect("receiver");
        let sender_addr = sender.local_addr().expect("sender addr");
        let receiver_addr = receiver.local_addr().expect("receiver addr");

        for (node_id, public_key, addr, transport) in [
            (NodeId([3u8; 32]), [3u8; 32], sender_addr, &sender),
            (NodeId([4u8; 32]), [4u8; 32], receiver_addr, &receiver),
        ] {
            transport
                .send_control(
                    &ControlFrame::RegisterNode {
                        node_id,
                        nat_type: NatType::Cone,
                        external_addr: Some(addr),
                        public_key,
                        candidates: vec![dummy_candidate(addr)],
                        nickname: "Relay".to_string(),
                        local_networks: vec![],
                    },
                    supernode_addr,
                )
                .await
                .expect("register");
            let (frame, _) = recv_control(transport).await;
            assert!(matches!(frame, ControlFrame::RegisterOk));
        }

        let payload = b"relay-test";
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type: DataPacketType::IPv4,
            reserved: 0,
            ttl: 0,
            room_id: RoomId([1u8; 16]),
            src_node: NodeId([3u8; 32]),
            dst_node: NodeId([4u8; 32]),
            origin_node: NodeId([3u8; 32]),
            session_id: SessionId(1),
            nonce: 1,
            packet_id: r2n_common::PacketId(0),
            payload_len: payload.len() as u16,
        };
        let mut frame = vec![0u8; DATA_HEADER_SIZE + payload.len()];
        header
            .encode_into(&mut frame[..DATA_HEADER_SIZE])
            .expect("encode header");
        frame[DATA_HEADER_SIZE..].copy_from_slice(payload);

        sender
            .send_raw(&frame, supernode_addr)
            .await
            .expect("send raw frame");

        let mut buf = [0u8; 2048];
        let (packet, _) = receiver.recv_packet(&mut buf).await.expect("recv data");
        match packet {
            TransportPacket::Data(view) => {
                assert_eq!(view.header.src_node, NodeId([3u8; 32]));
                assert_eq!(view.header.dst_node, NodeId([4u8; 32]));
                assert_eq!(&buf[view.payload_range], payload);
            }
            other => panic!("unexpected packet: {other:?}"),
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn join_rejects_conflicting_local_network() {
        let supernode = Arc::new(Supernode::new("127.0.0.1:0").await.expect("supernode"));
        let supernode_addr = supernode.local_addr().expect("addr");
        let server = supernode.clone();
        let server_task = tokio::spawn(async move { server.run().await });

        let owner = UdpTransport::bind("127.0.0.1:0").await.expect("owner");
        let owner_addr = owner.local_addr().expect("owner addr");
        owner
            .send_control(
                &ControlFrame::RegisterNode {
                    node_id: NodeId([5u8; 32]),
                    nat_type: NatType::Cone,
                    external_addr: Some(owner_addr),
                    public_key: [5u8; 32],
                    candidates: vec![dummy_candidate(owner_addr)],
                    nickname: "Owner".to_string(),
                    local_networks: vec![],
                },
                supernode_addr,
            )
            .await
            .expect("register owner");
        let (frame, _) = recv_control(&owner).await;
        assert!(matches!(frame, ControlFrame::RegisterOk));

        owner
            .send_control(
                &ControlFrame::CreateRoom {
                    name: "conflict-room".to_string(),
                },
                supernode_addr,
            )
            .await
            .expect("create room");
        let (frame, _) = recv_control(&owner).await;
        let (room_id, token) = match frame {
            ControlFrame::RoomCreated {
                room_id,
                invite_code,
                ..
            } => {
                let invite = InviteData::decode(&invite_code).expect("decode invite");
                assert_eq!(invite.virtual_cidr.as_deref(), Some("192.168.200.0/24"));
                (room_id, invite.token)
            }
            other => panic!("unexpected frame: {other:?}"),
        };

        let guest = UdpTransport::bind("127.0.0.1:0").await.expect("guest");
        let guest_addr = guest.local_addr().expect("guest addr");
        guest
            .send_control(
                &ControlFrame::RegisterNode {
                    node_id: NodeId([6u8; 32]),
                    nat_type: NatType::Cone,
                    external_addr: Some(guest_addr),
                    public_key: [6u8; 32],
                    candidates: vec![dummy_candidate(guest_addr)],
                    nickname: "Guest".to_string(),
                    local_networks: vec!["192.168.200.0/24".to_string()],
                },
                supernode_addr,
            )
            .await
            .expect("register guest");
        let (frame, _) = recv_control(&guest).await;
        assert!(matches!(frame, ControlFrame::RegisterOk));

        guest
            .send_control(
                &ControlFrame::JoinRoom {
                    room_id,
                    token,
                    room_name: None,
                },
                supernode_addr,
            )
            .await
            .expect("join room");

        let (frame, _) = recv_control(&guest).await;
        match frame {
            ControlFrame::JoinReject { reason } => {
                assert!(reason.contains("conflicts with a local network"));
            }
            other => panic!("unexpected frame: {other:?}"),
        }

        server_task.abort();
    }
}
