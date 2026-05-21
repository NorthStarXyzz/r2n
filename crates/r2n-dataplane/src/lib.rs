pub mod defense;
pub mod path;

use crate::defense::{build_icmp_frag_needed, clamp_mss};

use crate::path::PathManager;
use anyhow::{Context, anyhow};
use dashmap::DashMap;
use r2n_common::{NodeId, PacketId, RoomId, SessionId};
use r2n_crypto::Cipher;
use r2n_discovery::DiscoveryManager;
use r2n_observability::{MetricsRegistry, PathKind};
use r2n_policy::{TrafficDirection, TrafficPolicy};
use r2n_proto::{DATA_HEADER_SIZE, DataHeader, DataPacketType, PROTOCOL_VERSION, PeerInfo};
use r2n_qos::{QosScheduler, TrafficClass, classify_packet};
use r2n_slab::{DEFAULT_FRAME_CAP, PacketDesc, PacketSlab};
use r2n_transport::UdpTransport;
use r2n_tun::{TunDevice, TunDeviceMode, TunInterface};
use std::collections::{HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const FLOOD_TTL: u8 = 1;
const SEEN_FLOOD_WINDOW: Duration = Duration::from_secs(30);
const SEEN_FLOOD_CAPACITY: usize = 4096;
const AEAD_TAG_LEN: usize = 16;
const MAX_DATAPLANE_PAYLOAD: usize = DEFAULT_FRAME_CAP - DATA_HEADER_SIZE - AEAD_TAG_LEN;
const MAC_TABLE_MAX_ENTRIES: usize = 4096;
const MAC_TABLE_MAX_AGE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameMode {
    L3,
    L2,
}

struct PacketTarget {
    peer: Arc<DataPeer>,
    flood: bool,
}

#[derive(Debug, Clone)]
struct MacTableEntry {
    node_id: NodeId,
    learned_at: Instant,
    last_seen: Instant,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct L2TableEntry {
    pub mac: String,
    pub node_id: NodeId,
    pub learned_for_secs: u64,
    pub idle_for_secs: u64,
}

struct SeenFloodPackets {
    order: VecDeque<(NodeId, PacketId, Instant)>,
    set: HashSet<(NodeId, PacketId)>,
}

impl SeenFloodPackets {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    fn insert_if_new(&mut self, origin: NodeId, packet_id: PacketId) -> bool {
        let now = Instant::now();
        self.prune(now);
        let key = (origin, packet_id);
        if self.set.contains(&key) {
            return false;
        }
        self.set.insert(key);
        self.order.push_back((origin, packet_id, now));
        self.prune(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        while self.order.len() > SEEN_FLOOD_CAPACITY {
            if let Some((origin, packet_id, _)) = self.order.pop_front() {
                self.set.remove(&(origin, packet_id));
            }
        }
        while let Some((origin, packet_id, seen_at)) = self.order.front().copied() {
            if now.duration_since(seen_at) <= SEEN_FLOOD_WINDOW {
                break;
            }
            self.order.pop_front();
            self.set.remove(&(origin, packet_id));
        }
    }
}

pub struct DataPeer {
    pub info: parking_lot::RwLock<PeerInfo>,
    pub path_manager: parking_lot::RwLock<PathManager>,
    pub cipher: parking_lot::RwLock<Option<Arc<Cipher>>>,
    pub session_id: SessionId,
    pub next_nonce: std::sync::atomic::AtomicU64,
}

impl DataPeer {
    pub fn new(
        info: PeerInfo,
        path_manager: PathManager,
        cipher: Option<Arc<Cipher>>,
        session_id: SessionId,
        next_nonce: u64,
    ) -> Self {
        Self {
            info: parking_lot::RwLock::new(info),
            path_manager: parking_lot::RwLock::new(path_manager),
            cipher: parking_lot::RwLock::new(cipher),
            session_id,
            next_nonce: std::sync::atomic::AtomicU64::new(next_nonce),
        }
    }
}

pub struct DataPlane {
    local_node_id: NodeId,
    transport: Arc<UdpTransport>,
    tun: Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
    room_id: Arc<parking_lot::RwLock<Option<RoomId>>>,
    peers: Arc<DashMap<NodeId, Arc<DataPeer>>>,
    discovery: Arc<DiscoveryManager>,
    metrics: Arc<MetricsRegistry>,
    slab: Arc<PacketSlab>,
    scheduler: Arc<tokio::sync::Mutex<QosScheduler<PacketDesc>>>,
    next_packet_id: std::sync::atomic::AtomicU64,
    seen_flood: parking_lot::Mutex<SeenFloodPackets>,
    mac_table: DashMap<[u8; 6], MacTableEntry>,
    traffic_policy: parking_lot::RwLock<TrafficPolicy>,
    started: AtomicBool,
    tun_mtu: u16,
}

impl DataPlane {
    pub fn new(
        local_node_id: NodeId,
        transport: Arc<UdpTransport>,
        tun: Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
        discovery: Arc<DiscoveryManager>,
        metrics: Arc<MetricsRegistry>,
        tun_mtu: u16,
    ) -> Arc<Self> {
        Arc::new(Self {
            local_node_id,
            transport,
            tun,
            room_id: Arc::new(parking_lot::RwLock::new(None)),
            peers: Arc::new(DashMap::new()),
            discovery,
            metrics,
            slab: PacketSlab::default_pool(4096),
            scheduler: Arc::new(tokio::sync::Mutex::new(QosScheduler::new(2048))),
            next_packet_id: std::sync::atomic::AtomicU64::new(1),
            seen_flood: parking_lot::Mutex::new(SeenFloodPackets::new()),
            mac_table: DashMap::new(),
            traffic_policy: parking_lot::RwLock::new(TrafficPolicy::default()),
            started: AtomicBool::new(false),
            tun_mtu,
        })
    }

    pub fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        let dataplane = self.clone();
        tokio::spawn(async move {
            dataplane.run_tun_loop().await;
        });

        let dataplane_ping = self.clone();
        tokio::spawn(async move {
            dataplane_ping.run_ping_loop().await;
        });
    }

    pub fn set_room_id(&self, room_id: Option<RoomId>) {
        *self.room_id.write() = room_id;
    }

    pub fn set_traffic_policy(&self, policy: TrafficPolicy) {
        *self.traffic_policy.write() = policy;
    }

    pub fn traffic_policy(&self) -> TrafficPolicy {
        self.traffic_policy.read().clone()
    }

    pub fn l2_table_snapshot(&self) -> Vec<L2TableEntry> {
        self.prune_mac_table();
        let now = Instant::now();
        self.mac_table
            .iter()
            .map(|entry| {
                let value = entry.value();
                L2TableEntry {
                    mac: format_mac(*entry.key()),
                    node_id: value.node_id,
                    learned_for_secs: now.saturating_duration_since(value.learned_at).as_secs(),
                    idle_for_secs: now.saturating_duration_since(value.last_seen).as_secs(),
                }
            })
            .collect()
    }

    pub fn upsert_peer(&self, peer: DataPeer) {
        let node_id = peer.info.read().node_id;
        if let Some(existing) = self.peers.get(&node_id) {
            // Preserve existing path_manager, cipher, session_id, and nonce state
            // Only update peer info (IP, public key, nickname, etc.)
            *existing.info.write() = peer.info.into_inner();
        } else {
            self.peers.insert(node_id, Arc::new(peer));
        }
    }

    pub fn remove_peer(&self, node_id: &NodeId) {
        self.peers.remove(node_id);
        self.mac_table.retain(|_, entry| &entry.node_id != node_id);
    }

    pub fn clear_peers(&self) {
        self.peers.clear();
        self.mac_table.clear();
    }

    pub fn set_direct_path(&self, node_id: NodeId, addr: SocketAddr, cipher: Option<Arc<Cipher>>) {
        if let Some(peer) = self.peers.get(&node_id) {
            peer.path_manager.write().add_or_update_path(addr, false);
            peer.path_manager.write().record_success(addr, 10.0);
            if let Some(cipher) = cipher {
                *peer.cipher.write() = Some(cipher);
            }
        }
    }

    pub fn add_peer_candidate(&self, node_id: NodeId, addr: SocketAddr) {
        if let Some(peer) = self.peers.get(&node_id) {
            peer.path_manager.write().add_or_update_path(addr, false);
        }
    }

    async fn run_tun_loop(self: Arc<Self>) {
        let mut buffer = [0u8; 2048];
        loop {
            let tun_opt = {
                let guard = self.tun.read();
                guard.clone()
            };
            let tun = match tun_opt {
                Some(tun) => tun,
                None => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            let len = match tun.recv(&mut buffer).await {
                Ok(len) => len,
                Err(err) => {
                    log::error!("dataplane tun recv failed: {}", err);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            let payload = &mut buffer[..len];
            let (mode, packet_type) = match tun.mode() {
                TunDeviceMode::Tun => {
                    let safe_payload_mtu = self.tun_mtu as usize;
                    if payload.len() > safe_payload_mtu
                        && payload.len() >= 20
                        && (payload[0] >> 4) == 4
                    {
                        let flags_frag = u16::from_be_bytes([payload[6], payload[7]]);
                        let df = (flags_frag & 0x4000) != 0;
                        if df {
                            if let Some(icmp_pkt) =
                                build_icmp_frag_needed(payload, safe_payload_mtu as u16)
                            {
                                log::debug!(
                                    "Dropping large packet ({} bytes) and sending ICMP Frag Needed with MTU {}",
                                    payload.len(),
                                    safe_payload_mtu
                                );
                                let _ = tun.send(&icmp_pkt).await;
                            }
                            continue;
                        }
                    }

                    clamp_mss(payload, safe_payload_mtu);
                    let packet_type = self
                        .discovery
                        .classify_managed_packet(payload)
                        .unwrap_or(DataPacketType::IPv4);
                    (FrameMode::L3, packet_type)
                }
                TunDeviceMode::Tap => (FrameMode::L2, DataPacketType::Ethernet),
            };

            if !self.policy_allows(mode, TrafficDirection::Outbound, payload) {
                self.metrics.mark_packet_drop(None);
                continue;
            }

            let targets = self.select_targets(mode, packet_type, payload);
            let has_flood_target = targets.iter().any(|target| target.flood);
            if has_flood_target && !self.discovery.allow_broadcast().await {
                continue;
            }

            if has_flood_target {
                self.metrics.mark_discovery_packet(packet_type);
            }
            for target in targets {
                if let Err(err) = self
                    .send_to_peer(target.peer, packet_type, payload, None, target.flood)
                    .await
                {
                    log::error!("dataplane send failed: {err:#}");
                    self.metrics.mark_packet_drop(None);
                }
            }
        }
    }

    async fn run_ping_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut next_ping_seq = 0u32;
        loop {
            interval.tick().await;

            if self.room_id.read().is_none() {
                continue;
            }

            // Check pending pings for timeouts (older than 2 seconds) and record failures
            let timed_out = self
                .metrics
                .check_ping_timeouts(std::time::Duration::from_secs(2));
            for (peer_id, addr) in timed_out {
                if let Some(peer) = self.peers.get(&peer_id) {
                    peer.path_manager.write().record_failure(addr);
                }
            }

            // Send ping to all active peers
            let active_peers: Vec<Arc<DataPeer>> = self
                .peers
                .iter()
                .map(|entry| Arc::clone(entry.value()))
                .collect();
            for peer in active_peers {
                let (active_addr, paths) = {
                    let pm = peer.path_manager.read();
                    (pm.active_addr(), pm.paths.clone())
                };
                for path in paths {
                    let seq = next_ping_seq;
                    next_ping_seq = next_ping_seq.wrapping_add(1);

                    let is_active = path.addr == active_addr;
                    self.metrics.record_ping_sent(
                        peer.info.read().node_id,
                        seq,
                        path.addr,
                        is_active,
                    );

                    let payload = seq.to_be_bytes();
                    if let Err(err) = self
                        .send_to_peer(
                            Arc::clone(&peer),
                            DataPacketType::Ping,
                            &payload,
                            Some(path.addr),
                            false,
                        )
                        .await
                    {
                        log::error!("failed to send dataplane ping: {err:#}");
                    }
                }
            }
        }
    }

    fn select_targets(
        &self,
        mode: FrameMode,
        packet_type: DataPacketType,
        payload: &[u8],
    ) -> Vec<PacketTarget> {
        match mode {
            FrameMode::L3 => self.select_l3_targets(packet_type, payload),
            FrameMode::L2 => self.select_l2_targets(payload),
        }
    }

    fn select_l3_targets(&self, packet_type: DataPacketType, payload: &[u8]) -> Vec<PacketTarget> {
        if matches!(
            packet_type,
            DataPacketType::Broadcast | DataPacketType::Multicast
        ) {
            return self
                .peers
                .iter()
                .map(|entry| PacketTarget {
                    peer: Arc::clone(entry.value()),
                    flood: true,
                })
                .collect();
        }

        let dest_ip = match etherparse::IpHeader::from_slice(payload) {
            Ok((etherparse::IpHeader::Version4(ipv4, _), _, _)) => Some(ipv4.destination),
            _ => None,
        };

        dest_ip
            .and_then(|dest| {
                self.peers
                    .iter()
                    .find(|entry| entry.value().info.read().virtual_ip.0 == dest)
                    .map(|entry| PacketTarget {
                        peer: Arc::clone(entry.value()),
                        flood: false,
                    })
            })
            .into_iter()
            .collect()
    }

    fn select_l2_targets(&self, frame: &[u8]) -> Vec<PacketTarget> {
        self.prune_mac_table();
        let Some((dst_mac, _src_mac)) = ethernet_macs(frame) else {
            return Vec::new();
        };

        let flood = is_broadcast_mac(dst_mac) || is_multicast_mac(dst_mac);
        if !flood
            && let Some(peer_id) = self
                .mac_table
                .get(&dst_mac)
                .map(|entry| entry.value().node_id)
            && let Some(peer) = self.peers.get(&peer_id)
        {
            return vec![PacketTarget {
                peer: Arc::clone(peer.value()),
                flood: false,
            }];
        }

        self.peers
            .iter()
            .map(|entry| PacketTarget {
                peer: Arc::clone(entry.value()),
                flood: true,
            })
            .collect()
    }

    async fn send_to_peer(
        &self,
        peer: Arc<DataPeer>,
        packet_type: DataPacketType,
        payload: &[u8],
        target_override: Option<SocketAddr>,
        flood: bool,
    ) -> anyhow::Result<()> {
        if payload.len() > MAX_DATAPLANE_PAYLOAD {
            anyhow::bail!(
                "payload {} exceeds dataplane capacity {}",
                payload.len(),
                MAX_DATAPLANE_PAYLOAD
            );
        }
        let room_id = {
            let guard = self.room_id.read();
            guard.ok_or_else(|| anyhow!("room not assigned yet"))?
        };
        let mut desc = self.slab.acquire().context("packet slab exhausted")?;
        let class = classify_packet(packet_type, payload);
        desc.class = map_class(class);
        desc.data_offset = 0;
        desc.payload_offset = DATA_HEADER_SIZE;

        let nonce = peer.next_nonce.fetch_add(1, Ordering::SeqCst);
        let packet_id = if flood {
            PacketId(self.next_packet_id.fetch_add(1, Ordering::SeqCst))
        } else {
            PacketId(0)
        };
        let ttl = if flood { FLOOD_TTL } else { 0 };
        let dst_node = peer.info.read().node_id;

        let cipher_opt = peer.cipher.read().clone();
        let payload_len = self.slab.with_slot_mut(desc, |slot| {
            slot[DATA_HEADER_SIZE..DATA_HEADER_SIZE + payload.len()].copy_from_slice(payload);

            let payload_len = if let Some(cipher) = cipher_opt {
                let mut header_buf = [0u8; DATA_HEADER_SIZE];
                let header = DataHeader {
                    version: PROTOCOL_VERSION,
                    flags: 0,
                    packet_type,
                    reserved: 0,
                    ttl,
                    room_id,
                    src_node: self.local_node_id,
                    dst_node,
                    origin_node: self.local_node_id,
                    session_id: peer.session_id,
                    nonce,
                    packet_id,
                    payload_len: (payload.len() + 16) as u16,
                };
                header
                    .encode_into(&mut header_buf)
                    .expect("encode data header");
                cipher
                    .encrypt_in_place(
                        nonce,
                        &header_buf,
                        &mut slot[DATA_HEADER_SIZE..],
                        payload.len(),
                    )
                    .context("encrypt payload")?
            } else {
                payload.len()
            };

            let header = DataHeader {
                version: PROTOCOL_VERSION,
                flags: 0,
                packet_type,
                reserved: 0,
                ttl,
                room_id,
                src_node: self.local_node_id,
                dst_node,
                origin_node: self.local_node_id,
                session_id: peer.session_id,
                nonce,
                packet_id,
                payload_len: payload_len as u16,
            };
            header
                .encode_into(&mut slot[..DATA_HEADER_SIZE])
                .expect("encode data header");

            anyhow::Ok(payload_len)
        })?;

        desc.len = DATA_HEADER_SIZE + payload_len;

        self.scheduler.lock().await.push(class, desc);
        let target = target_override.unwrap_or_else(|| peer.path_manager.read().active_addr());
        self.metrics.mark_path_hit(
            peer.info.read().node_id,
            if peer
                .path_manager
                .read()
                .paths
                .iter()
                .find(|p| p.addr == target)
                .map(|p| p.is_relay)
                .unwrap_or(false)
            {
                PathKind::Relay
            } else {
                PathKind::Direct
            },
        );
        let frame_bytes = self.slab.get_slot_slice(&desc);
        self.transport
            .send_raw(&frame_bytes[..desc.len], target)
            .await
            .context("send raw dataplane frame")?;
        let _ = self.scheduler.lock().await.pop();
        self.slab.release(desc);
        Ok(())
    }

    pub async fn handle_incoming_frame(
        &self,
        header: DataHeader,
        payload: &mut [u8],
        addr: SocketAddr,
    ) -> anyhow::Result<()> {
        if !self.validate_incoming_header(&header) {
            return Ok(());
        }

        let Some(peer) = self
            .peers
            .get(&header.src_node)
            .map(|entry| Arc::clone(entry.value()))
        else {
            return Ok(());
        };

        let cipher_opt = peer.cipher.read().clone();
        let decrypted_len = if let Some(cipher) = cipher_opt {
            let mut header_buf = [0u8; DATA_HEADER_SIZE];
            header
                .encode_into(&mut header_buf)
                .expect("re-encode header");
            cipher
                .decrypt_in_place(header.nonce, &header_buf, payload)
                .context("decrypt incoming dataplane frame")?
        } else {
            payload.len()
        };

        let packet = &mut payload[..decrypted_len];

        self.metrics.mark_path_hit(
            header.src_node,
            if peer
                .path_manager
                .read()
                .paths
                .iter()
                .find(|p| p.addr == addr)
                .map(|p| p.is_relay)
                .unwrap_or(false)
            {
                PathKind::Relay
            } else {
                PathKind::Direct
            },
        );

        let is_known = peer
            .path_manager
            .read()
            .paths
            .iter()
            .any(|p| p.addr == addr);
        if !is_known {
            log::info!(
                "Learned peer-reflexive candidate from peer {}: {}",
                header.src_node,
                addr
            );
            peer.path_manager.write().add_or_update_path(addr, false);
        }

        if header.packet_type == DataPacketType::Ping {
            if let Err(err) = self
                .send_to_peer(peer, DataPacketType::Pong, packet, Some(addr), false)
                .await
            {
                log::error!("failed to send pong response: {err:#}");
            }
            return Ok(());
        }

        if header.packet_type == DataPacketType::Pong {
            if packet.len() >= 4 {
                let seq = u32::from_be_bytes(packet[..4].try_into().unwrap());
                if let Some((ping_addr, rtt)) =
                    self.metrics.record_pong_received(header.src_node, seq)
                {
                    peer.path_manager
                        .write()
                        .record_success(ping_addr, rtt as f32);
                    log::debug!(
                        "Pong from {}, rtt: {}ms, active path is_relay: {}",
                        addr,
                        rtt,
                        peer.path_manager.read().is_active_relay()
                    );
                }
            }
            return Ok(());
        }

        let is_relay = peer
            .path_manager
            .read()
            .paths
            .iter()
            .find(|p| p.addr == addr)
            .map(|p| p.is_relay)
            .unwrap_or(false);
        if !is_relay {
            self.set_direct_path(header.src_node, addr, None);
        }
        if header.packet_type == DataPacketType::Ethernet
            && let Some((_dst_mac, src_mac)) = ethernet_macs(packet)
        {
            self.learn_mac(src_mac, header.src_node);
        }
        if !self.policy_allows_packet_type(header.packet_type, TrafficDirection::Inbound, packet) {
            self.metrics.mark_packet_drop(Some(header.src_node));
            return Ok(());
        }
        let tun_opt = self.tun.read().clone();
        if let Some(tun) = tun_opt {
            prepare_packet_for_local_tun(packet, header.packet_type, tun.ipv4_addr());
            tun.send(packet).await.context("write packet to tun")?;
        }
        Ok(())
    }

    fn validate_incoming_header(&self, header: &DataHeader) -> bool {
        let Some(room_id) = *self.room_id.read() else {
            return false;
        };
        if header.version != PROTOCOL_VERSION || header.room_id != room_id {
            self.metrics.mark_packet_drop(Some(header.src_node));
            return false;
        }
        if header.src_node == self.local_node_id || header.origin_node == self.local_node_id {
            self.metrics.mark_packet_drop(Some(header.src_node));
            return false;
        }

        let flood = header_is_flood(header);
        if !flood && header.dst_node != self.local_node_id {
            self.metrics.mark_packet_drop(Some(header.src_node));
            return false;
        }
        if flood {
            if header.ttl == 0 || header.packet_id.0 == 0 {
                self.metrics.mark_packet_drop(Some(header.src_node));
                return false;
            }
            if !self
                .seen_flood
                .lock()
                .insert_if_new(header.origin_node, header.packet_id)
            {
                self.metrics.mark_packet_drop(Some(header.src_node));
                return false;
            }
        }
        true
    }

    fn policy_allows(&self, mode: FrameMode, direction: TrafficDirection, packet: &[u8]) -> bool {
        match mode {
            FrameMode::L3 => self.traffic_policy.read().allows(direction, packet),
            FrameMode::L2 => ethernet_ip_payload(packet)
                .map(|ip| self.traffic_policy.read().allows(direction, ip))
                .unwrap_or(true),
        }
    }

    fn policy_allows_packet_type(
        &self,
        packet_type: DataPacketType,
        direction: TrafficDirection,
        packet: &[u8],
    ) -> bool {
        match packet_type {
            DataPacketType::IPv4
            | DataPacketType::IPv6
            | DataPacketType::Broadcast
            | DataPacketType::Multicast
            | DataPacketType::Discovery => self.traffic_policy.read().allows(direction, packet),
            DataPacketType::Ethernet => ethernet_ip_payload(packet)
                .map(|ip| self.traffic_policy.read().allows(direction, ip))
                .unwrap_or(true),
            _ => true,
        }
    }

    fn learn_mac(&self, mac: [u8; 6], node_id: NodeId) {
        let now = Instant::now();
        self.prune_mac_table();
        self.mac_table
            .entry(mac)
            .and_modify(|entry| {
                entry.node_id = node_id;
                entry.last_seen = now;
            })
            .or_insert(MacTableEntry {
                node_id,
                learned_at: now,
                last_seen: now,
            });
        if self.mac_table.len() > MAC_TABLE_MAX_ENTRIES {
            self.evict_oldest_mac();
        }
    }

    fn prune_mac_table(&self) {
        let now = Instant::now();
        self.mac_table
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= MAC_TABLE_MAX_AGE);
    }

    fn evict_oldest_mac(&self) {
        if let Some(oldest) = self
            .mac_table
            .iter()
            .min_by_key(|entry| entry.value().last_seen)
            .map(|entry| *entry.key())
        {
            self.mac_table.remove(&oldest);
        }
    }
}

fn header_is_flood(header: &DataHeader) -> bool {
    match header.packet_type {
        DataPacketType::Broadcast | DataPacketType::Multicast => true,
        DataPacketType::Ethernet => header.ttl > 0,
        _ => false,
    }
}

fn ethernet_macs(frame: &[u8]) -> Option<([u8; 6], [u8; 6])> {
    if frame.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    Some((dst, src))
}

fn ethernet_ip_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    match ether_type {
        0x0800 | 0x86dd => Some(&frame[14..]),
        _ => None,
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn is_broadcast_mac(mac: [u8; 6]) -> bool {
    mac == [0xff; 6]
}

fn is_multicast_mac(mac: [u8; 6]) -> bool {
    (mac[0] & 1) == 1
}

fn prepare_packet_for_local_tun(
    packet: &mut [u8],
    packet_type: DataPacketType,
    local_ipv4: Option<Ipv4Addr>,
) {
    #[cfg(target_os = "macos")]
    {
        if packet_type == DataPacketType::Broadcast
            && let Some(local_ipv4) = local_ipv4
        {
            let _ = rewrite_ipv4_destination(packet, local_ipv4);
        }
    }

    #[cfg(not(target_os = "macos"))]
    let _ = (packet, packet_type, local_ipv4);
}

#[allow(dead_code)]
fn rewrite_ipv4_destination(packet: &mut [u8], local_ipv4: Ipv4Addr) -> Option<()> {
    let ipv4_slice = etherparse::Ipv4HeaderSlice::from_slice(packet).ok()?;
    let header_len = ipv4_slice.slice().len();
    let source = ipv4_slice.source();
    let destination = ipv4_slice.destination();
    let protocol = ipv4_slice.protocol();
    let mut ipv4_header = ipv4_slice.to_header();
    if packet.len() < header_len {
        return None;
    }

    let new_dest = local_ipv4.octets();
    if destination == new_dest {
        return Some(());
    }

    packet[16..20].copy_from_slice(&new_dest);

    let transport = &mut packet[header_len..];
    match protocol {
        etherparse::ip_number::UDP => {
            let udp = etherparse::UdpHeaderSlice::from_slice(transport).ok()?;
            let payload = &transport[8..];
            let checksum = udp
                .to_header()
                .calc_checksum_ipv4_raw(source, new_dest, payload)
                .ok()?;
            transport[6..8].copy_from_slice(&checksum.to_be_bytes());
        }
        etherparse::ip_number::TCP => {
            let tcp = etherparse::TcpHeaderSlice::from_slice(transport).ok()?;
            let tcp_header_len = tcp.slice().len();
            let payload = &transport[tcp_header_len..];
            let checksum = tcp.calc_checksum_ipv4_raw(source, new_dest, payload).ok()?;
            transport[16..18].copy_from_slice(&checksum.to_be_bytes());
        }
        _ => {}
    }

    ipv4_header.destination = new_dest;
    let header_checksum = ipv4_header.calc_header_checksum().ok()?;
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Some(())
}

fn map_class(class: TrafficClass) -> r2n_slab::TrafficClass {
    match class {
        TrafficClass::Control => r2n_slab::TrafficClass::Control,
        TrafficClass::Realtime => r2n_slab::TrafficClass::Realtime,
        TrafficClass::Interactive => r2n_slab::TrafficClass::Interactive,
        TrafficClass::Bulk => r2n_slab::TrafficClass::Bulk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2n_common::{RoomId, SessionId, VirtualIp};

    async fn test_dataplane(local_id: NodeId, room_id: RoomId) -> Arc<DataPlane> {
        let transport = Arc::new(UdpTransport::bind("127.0.0.1:0").await.unwrap());
        let tun = Arc::new(parking_lot::RwLock::new(None));
        let discovery = Arc::new(DiscoveryManager::new());
        let metrics = Arc::new(MetricsRegistry::new());
        let dataplane = DataPlane::new(local_id, transport, tun, discovery, metrics, 1280);
        *dataplane.room_id.write() = Some(room_id);
        dataplane
    }

    fn add_test_peer(dataplane: &DataPlane, node_id: NodeId, virtual_ip: [u8; 4]) {
        let peer_info = PeerInfo {
            node_id,
            public_key: [0; 32],
            virtual_ip: VirtualIp(virtual_ip),
            nickname: "test_peer".to_string(),
        };
        let path_manager = PathManager::new("127.0.0.1:9999".parse().unwrap());
        let data_peer = DataPeer::new(peer_info, path_manager, None, SessionId(0), 0);
        dataplane.peers.insert(node_id, Arc::new(data_peer));
    }

    fn test_header(
        packet_type: DataPacketType,
        room_id: RoomId,
        src_node: NodeId,
        dst_node: NodeId,
    ) -> DataHeader {
        DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type,
            reserved: 0,
            ttl: 0,
            room_id,
            src_node,
            dst_node,
            origin_node: src_node,
            session_id: SessionId(0),
            nonce: 0,
            packet_id: PacketId(0),
            payload_len: 0,
        }
    }

    fn ethernet_frame(dst: [u8; 6], src: [u8; 6]) -> [u8; 14] {
        let mut frame = [0u8; 14];
        frame[0..6].copy_from_slice(&dst);
        frame[6..12].copy_from_slice(&src);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame
    }

    fn build_ipv4_udp_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let udp =
            etherparse::UdpHeader::without_ipv4_checksum(39082, 39082, payload.len()).unwrap();
        let mut ipv4 = etherparse::Ipv4Header::new(
            (8 + payload.len()) as u16,
            64,
            etherparse::ip_number::UDP,
            src,
            dst,
        );
        ipv4.header_checksum = ipv4.calc_header_checksum().unwrap();

        let mut udp = udp;
        udp.checksum = udp.calc_checksum_ipv4(&ipv4, payload).unwrap();

        let mut bytes = Vec::new();
        ipv4.write_raw(&mut bytes).unwrap();
        bytes.extend_from_slice(&udp.to_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn rewrite_ipv4_destination_updates_ip_and_udp_checksum() {
        let mut packet = build_ipv4_udp_packet(
            [10, 77, 0, 2],
            [10, 77, 0, 255],
            br#"{"kind":"r2n-discovery"}"#,
        );

        rewrite_ipv4_destination(&mut packet, Ipv4Addr::new(10, 77, 0, 1)).unwrap();

        let ipv4 = etherparse::Ipv4HeaderSlice::from_slice(&packet).unwrap();
        assert_eq!(ipv4.destination(), [10, 77, 0, 1]);

        let udp_offset = ipv4.slice().len();
        let udp = etherparse::UdpHeaderSlice::from_slice(&packet[udp_offset..]).unwrap();
        let payload = &packet[udp_offset + 8..];
        let expected_udp_checksum = udp
            .to_header()
            .calc_checksum_ipv4_raw(ipv4.source(), ipv4.destination(), payload)
            .unwrap();
        assert_eq!(udp.checksum(), expected_udp_checksum);

        let expected_ip_checksum = ipv4.to_header().calc_header_checksum().unwrap();
        assert_eq!(ipv4.header_checksum(), expected_ip_checksum);
    }

    #[tokio::test]
    async fn test_peer_reflexive_candidate_learning() {
        let local_id = NodeId([1; 32]);
        let remote_id = NodeId([2; 32]);
        let transport = Arc::new(UdpTransport::bind("127.0.0.1:0").await.unwrap());
        let tun = Arc::new(parking_lot::RwLock::new(None));
        let discovery = Arc::new(DiscoveryManager::new());
        let metrics = Arc::new(MetricsRegistry::new());

        let dataplane = DataPlane::new(local_id, transport, tun, discovery, metrics, 1400);
        let room_id = RoomId([1; 16]);
        *dataplane.room_id.write() = Some(room_id);

        let relay_addr = "127.0.0.1:9999".parse::<SocketAddr>().unwrap();
        let path_manager = PathManager::new(relay_addr);
        let peer_info = PeerInfo {
            node_id: remote_id,
            public_key: [0; 32],
            virtual_ip: VirtualIp([10, 77, 0, 2]),
            nickname: "test_peer".to_string(),
        };

        let data_peer = DataPeer::new(peer_info, path_manager, None, SessionId(0), 0);
        dataplane.peers.insert(remote_id, Arc::new(data_peer));

        let reflexive_addr = "127.0.0.1:12345".parse::<SocketAddr>().unwrap();
        let header = DataHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            packet_type: DataPacketType::Ping,
            reserved: 0,
            ttl: 0,
            room_id,
            src_node: remote_id,
            dst_node: local_id,
            origin_node: remote_id,
            session_id: SessionId(0),
            nonce: 0,
            packet_id: PacketId(0),
            payload_len: 0,
        };

        let mut payload = [];
        dataplane
            .handle_incoming_frame(header, &mut payload, reflexive_addr)
            .await
            .unwrap();

        let updated_peer = dataplane.peers.get(&remote_id).unwrap();
        let learned = updated_peer
            .path_manager
            .read()
            .paths
            .iter()
            .any(|p| p.addr == reflexive_addr);
        assert!(learned, "Should have learned reflexive candidate");
    }

    #[tokio::test]
    async fn incoming_header_validation_drops_wrong_room_dst_origin_and_duplicates() {
        let local_id = NodeId([1; 32]);
        let remote_id = NodeId([2; 32]);
        let other_id = NodeId([3; 32]);
        let room_id = RoomId([9; 16]);
        let dataplane = test_dataplane(local_id, room_id).await;

        let mut wrong_room =
            test_header(DataPacketType::IPv4, RoomId([8; 16]), remote_id, local_id);
        assert!(!dataplane.validate_incoming_header(&wrong_room));

        let wrong_dst = test_header(DataPacketType::IPv4, room_id, remote_id, other_id);
        assert!(!dataplane.validate_incoming_header(&wrong_dst));

        let mut origin_self = test_header(DataPacketType::IPv4, room_id, remote_id, local_id);
        origin_self.origin_node = local_id;
        assert!(!dataplane.validate_incoming_header(&origin_self));

        let mut flood = test_header(DataPacketType::Broadcast, room_id, remote_id, local_id);
        flood.ttl = FLOOD_TTL;
        flood.packet_id = PacketId(77);
        assert!(dataplane.validate_incoming_header(&flood));
        assert!(!dataplane.validate_incoming_header(&flood));

        wrong_room.version = PROTOCOL_VERSION.wrapping_sub(1);
        wrong_room.room_id = room_id;
        assert!(!dataplane.validate_incoming_header(&wrong_room));
    }

    #[tokio::test]
    async fn flood_packet_types_require_ttl_and_packet_id() {
        let local_id = NodeId([1; 32]);
        let remote_id = NodeId([2; 32]);
        let room_id = RoomId([9; 16]);
        let dataplane = test_dataplane(local_id, room_id).await;

        let mut no_ttl = test_header(DataPacketType::Multicast, room_id, remote_id, local_id);
        no_ttl.packet_id = PacketId(88);
        assert!(!dataplane.validate_incoming_header(&no_ttl));

        let mut no_packet_id = test_header(DataPacketType::Broadcast, room_id, remote_id, local_id);
        no_packet_id.ttl = FLOOD_TTL;
        assert!(!dataplane.validate_incoming_header(&no_packet_id));

        let ethernet_unicast = test_header(DataPacketType::Ethernet, room_id, remote_id, local_id);
        assert!(dataplane.validate_incoming_header(&ethernet_unicast));
    }

    #[tokio::test]
    async fn l2_switching_selects_flood_and_known_unicast_targets() {
        let local_id = NodeId([1; 32]);
        let peer_a = NodeId([2; 32]);
        let peer_b = NodeId([3; 32]);
        let room_id = RoomId([9; 16]);
        let dataplane = test_dataplane(local_id, room_id).await;
        add_test_peer(&dataplane, peer_a, [10, 77, 0, 2]);
        add_test_peer(&dataplane, peer_b, [10, 77, 0, 3]);

        let src_mac = [0x02, 0, 0, 0, 0, 1];
        let known_mac = [0x02, 0, 0, 0, 0, 2];
        let unknown_mac = [0x02, 0, 0, 0, 0, 99];

        let broadcast = ethernet_frame([0xff; 6], src_mac);
        let broadcast_targets = dataplane.select_l2_targets(&broadcast);
        assert_eq!(broadcast_targets.len(), 2);
        assert!(broadcast_targets.iter().all(|target| target.flood));

        let multicast = ethernet_frame([0x01, 0x00, 0x5e, 0, 0, 1], src_mac);
        let multicast_targets = dataplane.select_l2_targets(&multicast);
        assert_eq!(multicast_targets.len(), 2);
        assert!(multicast_targets.iter().all(|target| target.flood));

        let unknown = ethernet_frame(unknown_mac, src_mac);
        let unknown_targets = dataplane.select_l2_targets(&unknown);
        assert_eq!(unknown_targets.len(), 2);
        assert!(unknown_targets.iter().all(|target| target.flood));

        dataplane.learn_mac(known_mac, peer_a);
        let known = ethernet_frame(known_mac, src_mac);
        let known_targets = dataplane.select_l2_targets(&known);
        assert_eq!(known_targets.len(), 1);
        assert!(!known_targets[0].flood);
        assert_eq!(known_targets[0].peer.info.read().node_id, peer_a);

        dataplane.remove_peer(&peer_a);
        assert!(dataplane.mac_table.get(&known_mac).is_none());
    }
}
