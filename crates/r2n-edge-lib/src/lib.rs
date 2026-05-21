use dashmap::DashMap;
use ipnet::Ipv4Net;
use r2n_common::{InviteData, NodeId, RoomId, SessionId};
use r2n_config::{BackendConfig, BackendMode, VirtualLanConfig};
use r2n_crypto::{Cipher, NoiseSession, derive_public_key};
use r2n_dataplane::{DataPeer, DataPlane};
use r2n_discovery::{DiscoveryConfig, DiscoveryManager};
use r2n_nat::{
    NatProbe, PortMappingManager, PortMappingSnapshot, merge_mapped_candidate,
    preferred_external_addr,
};
use r2n_observability::MetricsRegistry;
use r2n_policy::TrafficPolicy;
use r2n_proto::{Candidate, ControlFrame, PeerAction, PeerInfo};
use r2n_rendezvous::build_candidate_pairs;
use r2n_route::RouteManager;
use r2n_transport::{TransportPacket, UdpTransport};
use r2n_tun::{MIN_TUN_MTU, TunDevice, TunDeviceMode, TunInterface};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;

pub mod ipc;

pub struct Edge {
    node_id: NodeId,
    private_key: [u8; 32],
    nickname: String,
    transport: Arc<UdpTransport>,
    tun: Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
    tun_name: String,
    supernode_addr: SocketAddr,
    supernodes: Vec<SocketAddr>,
    peers: Arc<DashMap<NodeId, PeerState>>,
    room_id: Arc<tokio::sync::Mutex<Option<RoomId>>>,
    discovery: Arc<DiscoveryManager>,
    stun_servers: Vec<String>,
    tun_mtu: u16,
    backend: BackendConfig,
    virtual_lan: VirtualLanConfig,
    traffic_policy: TrafficPolicy,
}

#[derive(Debug)]
pub enum EdgeCommand {
    CreateRoom {
        name: String,
        reply: oneshot::Sender<anyhow::Result<serde_json::Value>>,
    },
    JoinRoom {
        invite: String,
        reply: oneshot::Sender<anyhow::Result<serde_json::Value>>,
    },
    LeaveRoom {
        reply: oneshot::Sender<anyhow::Result<serde_json::Value>>,
    },
    Stop {
        reply: oneshot::Sender<anyhow::Result<serde_json::Value>>,
    },
    QueryRooms {
        reply: oneshot::Sender<anyhow::Result<serde_json::Value>>,
    },
    SwitchSupernode {
        addr: SocketAddr,
        reply: oneshot::Sender<anyhow::Result<serde_json::Value>>,
    },
}

#[derive(Clone)]
pub struct PeerState {
    pub info: PeerInfo,
    pub candidates: Vec<Candidate>,
    pub direct_addr: Option<SocketAddr>,
    pub cipher: Option<Arc<Cipher>>,
    pub session_id: SessionId,
    pub handshake: Arc<tokio::sync::Mutex<Option<NoiseSession>>>,
    pub pending_session_key: Arc<tokio::sync::Mutex<Option<[u8; 32]>>>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeState {
    pub supernode_addr: String,
    pub nat_type: String,
    pub tun_name: Option<String>,
    pub virtual_ip: Option<String>,
    pub route_cidr: Option<String>,
    pub route_installed: bool,
    pub discovery_routes_installed: bool,
    pub discovery_route_errors: Vec<String>,
    pub supernode_reachable: bool,
    pub backend_requested: String,
    pub backend_active: String,
    pub backend_degraded: bool,
    pub effective_mtu: u16,
    pub supernodes: Vec<String>,
    pub virtual_interface_preference_requested: bool,
    pub virtual_interface_preference_supported: bool,
    pub virtual_interface_preference_applied: bool,
    pub virtual_interface_preference_error: Option<String>,
    pub last_supernode_activity_at: Option<std::time::Instant>,
    pub port_mapping_acquired: bool,
    pub port_mapping_protocol: Option<String>,
    pub port_mapping_external_addr: Option<String>,
    pub port_mapping_lease_expires_at: Option<std::time::Instant>,
    pub last_error: Option<String>,
}

fn collect_local_networks(tun_name: &str) -> Vec<String> {
    let mut networks = Vec::new();
    for iface in netdev::get_interfaces() {
        if !iface.is_up() || iface.is_loopback() || iface.name == tun_name || iface.is_tun() {
            continue;
        }
        for network in iface.ipv4 {
            let addr = network.addr();
            if addr.is_loopback() || addr.is_link_local() || addr.is_unspecified() {
                continue;
            }
            let cidr = network.to_string();
            if !networks.contains(&cidr) {
                networks.push(cidr);
            }
        }
    }
    networks.sort();
    networks
}

// Room activation wires route, interface, runtime, and dataplane state atomically.
#[allow(clippy::too_many_arguments)]
async fn activate_room(
    room_id_state: &Arc<tokio::sync::Mutex<Option<RoomId>>>,
    tun: &Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
    tun_name: &str,
    route_manager: &Arc<RouteManager>,
    discovery: &Arc<DiscoveryManager>,
    runtime_state: &Arc<tokio::sync::RwLock<RuntimeState>>,
    dataplane: &Arc<DataPlane>,
    joined_room: RoomId,
    assigned_ip: r2n_common::VirtualIp,
    virtual_cidr: &str,
    tun_mtu: u16,
    backend: &BackendConfig,
    virtual_lan: &VirtualLanConfig,
) -> anyhow::Result<()> {
    let current_room = *room_id_state.lock().await;
    if let Some(active_room) = current_room {
        if active_room == joined_room {
            log::info!(
                "Room {} is already active, refreshing local state",
                joined_room
            );
        } else {
            anyhow::bail!(
                "already in room {}, leave it before joining or creating another room",
                active_room
            );
        }
    }

    #[allow(unused_mut)]
    let mut created_tun = false;
    #[cfg(target_os = "android")]
    let _ = tun_mtu;
    #[cfg(target_os = "android")]
    let _ = backend;
    let tun_device = if let Some(device) = tun.read().clone() {
        Some(device)
    } else {
        #[cfg(target_os = "android")]
        {
            // On Android, we tolerate empty tun device during join.
            // It will be registered dynamically later via register_tun_fd.
            log::info!(
                "No preconfigured TUN device on Android yet. Waiting for register_tun_fd..."
            );
            None
        }
        #[cfg(not(target_os = "android"))]
        {
            let (device, degraded, warning) = create_tun_device_with_backend(
                tun_name,
                &assigned_ip.to_string(),
                24,
                tun_mtu,
                backend,
            )?;
            *tun.write() = Some(device.clone());
            created_tun = true;
            {
                let mut runtime = runtime_state.write().await;
                runtime.backend_active = device_mode_label(device.mode()).to_string();
                runtime.backend_degraded = degraded;
                runtime.effective_mtu = device.effective_mtu();
                runtime.last_error = warning;
            }
            Some(device)
        }
    };

    let (interface_name, active_mode, effective_mtu) = if let Some(ref device) = tun_device {
        (device.name()?, device.mode(), device.effective_mtu())
    } else {
        (tun_name.to_string(), TunDeviceMode::Tun, tun_mtu)
    };

    let preference_requested = virtual_lan.prefer_virtual_interface;
    let preference_supported = virtual_interface_preference_supported();
    let mut preference_applied = false;
    let mut preference_error = None;
    if preference_requested && preference_supported && tun_device.is_some() {
        match TunDevice::prefer_virtual_interface(&interface_name) {
            Ok(applied) => {
                preference_applied = applied;
                if applied {
                    log::info!("Preferred virtual LAN interface {}", interface_name);
                }
            }
            Err(err) => {
                let message = format!(
                    "failed to prefer virtual LAN interface {}: {}",
                    interface_name, err
                );
                log::warn!("{}", message);
                preference_error = Some(message);
            }
        }
    }

    let network: Ipv4Net = virtual_cidr.parse()?;
    let mut discovery_route_errors = Vec::new();
    if tun_device.is_some() {
        if let Err(err) = route_manager.add_route(network, &interface_name).await {
            if created_tun {
                *tun.write() = None;
            }
            return Err(err.into());
        }

        discovery_route_errors =
            add_lan_discovery_routes(route_manager, discovery, &interface_name).await;
    }

    *room_id_state.lock().await = Some(joined_room);
    dataplane.set_room_id(Some(joined_room));

    let mut runtime = runtime_state.write().await;
    runtime.virtual_ip = Some(assigned_ip.to_string());
    runtime.tun_name = Some(interface_name);
    runtime.route_cidr = Some(virtual_cidr.to_string());
    runtime.route_installed = true;
    runtime.discovery_routes_installed = discovery_route_errors.is_empty();
    runtime.discovery_route_errors = discovery_route_errors;
    runtime.backend_requested = backend_request_label(backend).to_string();
    runtime.backend_active = device_mode_label(active_mode).to_string();
    runtime.effective_mtu = effective_mtu;
    runtime.virtual_interface_preference_requested = preference_requested;
    runtime.virtual_interface_preference_supported = preference_supported;
    runtime.virtual_interface_preference_applied = preference_applied;
    runtime.virtual_interface_preference_error = preference_error.clone();
    if runtime.backend_degraded {
        if runtime.last_error.is_none() {
            runtime.last_error = Some("requested TAP/L2 backend degraded to TUN".to_string());
        }
    } else if let Some(error) = preference_error {
        runtime.last_error = Some(error);
    } else if runtime.discovery_routes_installed {
        runtime.last_error = None;
    }
    Ok(())
}

async fn deactivate_room(
    room_id_state: &Arc<tokio::sync::Mutex<Option<RoomId>>>,
    tun: &Arc<parking_lot::RwLock<Option<Arc<TunDevice>>>>,
    route_manager: &Arc<RouteManager>,
    discovery: &Arc<DiscoveryManager>,
    runtime_state: &Arc<tokio::sync::RwLock<RuntimeState>>,
    dataplane: &Arc<DataPlane>,
) {
    let (route_cidr, tun_name) = {
        let runtime = runtime_state.read().await;
        (runtime.route_cidr.clone(), runtime.tun_name.clone())
    };

    if let (Some(route_cidr), Some(tun_name)) = (route_cidr, tun_name) {
        if let Ok(network) = route_cidr.parse::<Ipv4Net>()
            && let Err(err) = route_manager.remove_route(network, &tun_name).await
        {
            log::warn!(
                "failed to remove route {} via {}: {}",
                route_cidr,
                tun_name,
                err
            );
        }
        remove_lan_discovery_routes(route_manager, discovery, &tun_name).await;
    }

    *room_id_state.lock().await = None;
    *tun.write() = None;
    dataplane.clear_peers();
    dataplane.set_room_id(None);

    let mut runtime = runtime_state.write().await;
    runtime.virtual_ip = None;
    runtime.tun_name = None;
    runtime.route_cidr = None;
    runtime.route_installed = false;
    runtime.discovery_routes_installed = false;
    runtime.discovery_route_errors.clear();
    runtime.virtual_interface_preference_applied = false;
    runtime.virtual_interface_preference_error = None;
    runtime.last_error = None;
}

async fn add_lan_discovery_routes(
    route_manager: &Arc<RouteManager>,
    discovery: &Arc<DiscoveryManager>,
    interface_name: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    for cidr in discovery.route_cidrs() {
        let Ok(route) = cidr.parse::<Ipv4Net>() else {
            let message = format!("invalid LAN discovery route CIDR: {}", cidr);
            log::warn!("{}", message);
            errors.push(message);
            continue;
        };
        if let Err(err) = route_manager.add_route(route, interface_name).await {
            let message = format!(
                "failed to add LAN discovery route {} via {}: {}",
                cidr, interface_name, err
            );
            log::warn!("{}", message);
            errors.push(message);
        }
    }
    errors
}

async fn remove_lan_discovery_routes(
    route_manager: &Arc<RouteManager>,
    discovery: &Arc<DiscoveryManager>,
    interface_name: &str,
) {
    for cidr in discovery.route_cidrs() {
        let Ok(route) = cidr.parse::<Ipv4Net>() else {
            continue;
        };
        if let Err(err) = route_manager.remove_route(route, interface_name).await {
            log::warn!(
                "failed to remove LAN discovery route {} via {}: {}",
                cidr,
                interface_name,
                err
            );
        }
    }
}

async fn apply_port_mapping_snapshot(
    runtime_state: &Arc<tokio::sync::RwLock<RuntimeState>>,
    metrics: &Arc<MetricsRegistry>,
    snapshot: &PortMappingSnapshot,
) {
    let protocol = snapshot
        .protocol
        .map(|protocol| protocol.label().to_string());
    let external_addr = snapshot.external_addr.map(|addr| addr.to_string());
    let lease_expires_at = snapshot
        .lease_remaining
        .map(|lease| std::time::Instant::now() + lease);
    {
        let mut runtime = runtime_state.write().await;
        runtime.port_mapping_acquired = snapshot.acquired;
        runtime.port_mapping_protocol = protocol.clone();
        runtime.port_mapping_external_addr = external_addr.clone();
        runtime.port_mapping_lease_expires_at = lease_expires_at;
    }

    metrics.set_port_mapping_status(snapshot.acquired, protocol, external_addr, lease_expires_at);
}

async fn send_pending_reply(
    pending: &Arc<tokio::sync::Mutex<Option<oneshot::Sender<anyhow::Result<serde_json::Value>>>>>,
    result: anyhow::Result<serde_json::Value>,
) {
    if let Some(reply) = pending.lock().await.take() {
        let _ = reply.send(result);
    }
}

fn resolve_supernode_addr(invite_addr: &str, fallback: SocketAddr) -> anyhow::Result<SocketAddr> {
    let parsed = invite_addr.parse::<SocketAddr>()?;
    if parsed.ip().is_unspecified() {
        let port = if parsed.port() == 0 {
            fallback.port()
        } else {
            parsed.port()
        };
        Ok(SocketAddr::new(fallback.ip(), port))
    } else {
        Ok(parsed)
    }
}

fn normalize_invite_code(invite_code: &str, fallback: SocketAddr) -> String {
    let Some(mut invite) = InviteData::decode(invite_code) else {
        return invite_code.to_string();
    };

    if let Ok(addr) = resolve_supernode_addr(invite.primary_supernode_addr(), fallback) {
        invite.primary_supernode = addr.to_string();
        invite.supernode_addr = addr.to_string();
        invite.encode()
    } else {
        invite_code.to_string()
    }
}

fn build_peer_state(peer: PeerInfo) -> PeerState {
    PeerState {
        info: peer,
        candidates: Vec::new(),
        direct_addr: None,
        cipher: None,
        session_id: SessionId(0),
        handshake: Arc::new(tokio::sync::Mutex::new(None)),
        pending_session_key: Arc::new(tokio::sync::Mutex::new(None)),
    }
}

fn normalize_tun_mtu(mtu: u16) -> u16 {
    if mtu < MIN_TUN_MTU {
        log::warn!(
            "Configured TUN MTU {} is below the minimum {}; using {}",
            mtu,
            MIN_TUN_MTU,
            MIN_TUN_MTU
        );
        MIN_TUN_MTU
    } else {
        mtu
    }
}

fn normalize_supernodes(primary: SocketAddr, mut supernodes: Vec<SocketAddr>) -> Vec<SocketAddr> {
    supernodes.retain(|addr| *addr != primary);
    supernodes.insert(0, primary);
    supernodes.dedup();
    supernodes
}

fn next_supernode_after(current: SocketAddr, supernodes: &[SocketAddr]) -> SocketAddr {
    if supernodes.len() <= 1 {
        return current;
    }
    let index = supernodes
        .iter()
        .position(|addr| *addr == current)
        .map(|idx| (idx + 1) % supernodes.len())
        .unwrap_or(0);
    supernodes[index]
}

fn requested_tun_mode(backend: &BackendConfig) -> TunDeviceMode {
    if backend.mode == BackendMode::Tap || backend.desktop_l2_enhanced {
        TunDeviceMode::Tap
    } else {
        TunDeviceMode::Tun
    }
}

fn device_mode_label(mode: TunDeviceMode) -> &'static str {
    match mode {
        TunDeviceMode::Tun => "tun",
        TunDeviceMode::Tap => "tap",
    }
}

fn backend_request_label(backend: &BackendConfig) -> &'static str {
    device_mode_label(requested_tun_mode(backend))
}

fn virtual_interface_preference_supported() -> bool {
    cfg!(target_os = "windows")
}

#[cfg(target_os = "android")]
fn create_tun_device_with_backend(
    _tun_name: &str,
    _assigned_ip: &str,
    _prefix_len: u8,
    _tun_mtu: u16,
    _backend: &BackendConfig,
) -> anyhow::Result<(Arc<TunDevice>, bool, Option<String>)> {
    anyhow::bail!("Android TUN devices must be registered through register_tun_fd")
}

#[cfg(not(target_os = "android"))]
fn create_tun_device_with_backend(
    tun_name: &str,
    assigned_ip: &str,
    prefix_len: u8,
    tun_mtu: u16,
    backend: &BackendConfig,
) -> anyhow::Result<(Arc<TunDevice>, bool, Option<String>)> {
    match requested_tun_mode(backend) {
        TunDeviceMode::Tun => Ok((
            Arc::new(TunDevice::new_with_mode(
                tun_name,
                assigned_ip,
                prefix_len,
                tun_mtu,
                TunDeviceMode::Tun,
            )?),
            false,
            None,
        )),
        TunDeviceMode::Tap => match TunDevice::new_with_mode(
            tun_name,
            assigned_ip,
            prefix_len,
            tun_mtu,
            TunDeviceMode::Tap,
        ) {
            Ok(device) => Ok((Arc::new(device), false, None)),
            Err(err) => {
                let warning =
                    format!("requested TAP/L2 backend is unavailable: {err}; falling back to TUN");
                log::warn!("{}", warning);
                let device = TunDevice::new_with_mode(
                    tun_name,
                    assigned_ip,
                    prefix_len,
                    tun_mtu,
                    TunDeviceMode::Tun,
                )?;
                Ok((Arc::new(device), true, Some(warning)))
            }
        },
    }
}

impl Edge {
    // Constructor mirrors CLI/config surface; a builder would be a larger public API change.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        node_id: NodeId,
        private_key: [u8; 32],
        nickname: String,
        local_addr: &str,
        supernode_addr: SocketAddr,
        supernodes: Vec<SocketAddr>,
        tun_name: &str,
        stun_servers: Vec<String>,
        tun_mtu: u16,
        discovery_config: DiscoveryConfig,
        backend: BackendConfig,
        virtual_lan: VirtualLanConfig,
        traffic_policy: TrafficPolicy,
    ) -> anyhow::Result<Self> {
        Self::new_with_tun(
            node_id,
            private_key,
            nickname,
            local_addr,
            supernode_addr,
            supernodes,
            None,
            tun_name,
            stun_servers,
            tun_mtu,
            discovery_config,
            backend,
            virtual_lan,
            traffic_policy,
        )
        .await
    }

    // Test and Android call sites need explicit TUN injection while preserving constructor parity.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_tun(
        node_id: NodeId,
        private_key: [u8; 32],
        nickname: String,
        local_addr: &str,
        supernode_addr: SocketAddr,
        supernodes: Vec<SocketAddr>,
        preconfigured_tun: Option<Arc<TunDevice>>,
        tun_name: &str,
        stun_servers: Vec<String>,
        tun_mtu: u16,
        discovery_config: DiscoveryConfig,
        backend: BackendConfig,
        virtual_lan: VirtualLanConfig,
        traffic_policy: TrafficPolicy,
    ) -> anyhow::Result<Self> {
        let transport = UdpTransport::bind(local_addr).await?;
        let discovery = Arc::new(DiscoveryManager::with_config(discovery_config));

        Ok(Self {
            node_id,
            private_key,
            nickname,
            transport: Arc::new(transport),
            tun: Arc::new(parking_lot::RwLock::new(preconfigured_tun)),
            tun_name: tun_name.to_string(),
            supernode_addr,
            supernodes: normalize_supernodes(supernode_addr, supernodes),
            peers: Arc::new(DashMap::new()),
            room_id: Arc::new(tokio::sync::Mutex::new(None)),
            discovery,
            stun_servers,
            tun_mtu: normalize_tun_mtu(tun_mtu),
            backend,
            virtual_lan,
            traffic_policy,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<EdgeCommand>(32);
        let metrics = Arc::new(MetricsRegistry::new());
        let backend = self.backend.clone();
        let virtual_lan = self.virtual_lan.clone();
        let traffic_policy = self.traffic_policy.clone();
        let initial_device = self.tun.read().clone();
        let runtime_state = Arc::new(tokio::sync::RwLock::new(RuntimeState {
            supernode_addr: self.supernode_addr.to_string(),
            supernodes: self.supernodes.iter().map(ToString::to_string).collect(),
            nat_type: "Unknown".to_string(),
            backend_requested: backend_request_label(&backend).to_string(),
            backend_active: initial_device
                .as_ref()
                .map(|device| device_mode_label(device.mode()).to_string())
                .unwrap_or_default(),
            effective_mtu: initial_device
                .as_ref()
                .map(|device| device.effective_mtu())
                .unwrap_or(self.tun_mtu),
            virtual_interface_preference_requested: virtual_lan.prefer_virtual_interface,
            virtual_interface_preference_supported: virtual_interface_preference_supported(),
            ..RuntimeState::default()
        }));
        let dataplane = DataPlane::new(
            self.node_id,
            self.transport.clone(),
            self.tun.clone(),
            self.discovery.clone(),
            metrics.clone(),
            self.tun_mtu,
        );
        dataplane.set_traffic_policy(traffic_policy);
        dataplane.start();
        ipc::spawn_ipc_server(ipc::IpcServerContext {
            tx: tx.clone(),
            peers: self.peers.clone(),
            room_id: self.room_id.clone(),
            tun: self.tun.clone(),
            metrics: metrics.clone(),
            runtime_state: runtime_state.clone(),
            dataplane: dataplane.clone(),
            node_id: self.node_id,
        })
        .await?;

        let last_supernode_activity = Arc::new(tokio::sync::RwLock::new(std::time::Instant::now()));
        let active_invite_code = Arc::new(tokio::sync::Mutex::new(None::<String>));

        log::info!("Edge {} starting...", self.node_id);
        let stun_servers_ref: Vec<&str> = self.stun_servers.iter().map(|s| s.as_str()).collect();
        let nat_probe = NatProbe::new(self.transport.as_ref());
        let local_udp_port = self.transport.local_addr()?.port();
        let port_mapping_manager = PortMappingManager::discover(local_udp_port)?;
        let initial_port_mapping = if let Some(manager) = port_mapping_manager.as_ref() {
            let snapshot = manager.refresh().await;
            apply_port_mapping_snapshot(&runtime_state, &metrics, &snapshot).await;
            manager.start();
            snapshot
        } else {
            let snapshot = r2n_nat::PortMappingSnapshot::default();
            apply_port_mapping_snapshot(&runtime_state, &metrics, &snapshot).await;
            snapshot
        };
        log::info!(
            "Collecting NAT candidates before registering with supernode using STUN: {:?}",
            stun_servers_ref
        );
        let collect_res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            nat_probe.collect_candidates(&stun_servers_ref),
        )
        .await;

        let (nat_fingerprint, base_candidates) = match collect_res {
            Ok(Ok(res)) => res,
            Ok(Err(err)) => {
                log::warn!(
                    "NAT probe failed, continuing with degraded registration: {}",
                    err
                );
                (
                    r2n_nat::NatFingerprint {
                        nat_type: r2n_common::NatType::Unknown,
                        public_addrs: Vec::new(),
                        endpoint_independent_mapping: false,
                        port_preserving: false,
                        port_delta_pattern: None,
                        binding_lifetime: std::time::Duration::from_secs(30),
                        hairpin_supported: false,
                        udp_restricted: false,
                    },
                    Vec::new(),
                )
            }
            Err(_) => {
                log::warn!(
                    "NAT probe timed out after 5 seconds, continuing with degraded registration"
                );
                (
                    r2n_nat::NatFingerprint {
                        nat_type: r2n_common::NatType::Unknown,
                        public_addrs: Vec::new(),
                        endpoint_independent_mapping: false,
                        port_preserving: false,
                        port_delta_pattern: None,
                        binding_lifetime: std::time::Duration::from_secs(30),
                        hairpin_supported: false,
                        udp_restricted: false,
                    },
                    Vec::new(),
                )
            }
        };
        {
            let mut runtime = runtime_state.write().await;
            runtime.nat_type = format!("{:?}", nat_fingerprint.nat_type);
        }
        let local_candidates = merge_mapped_candidate(&base_candidates, &initial_port_mapping);
        log::info!(
            "Registering with supernode using NAT {:?} and {} candidates",
            nat_fingerprint.nat_type,
            local_candidates.len()
        );

        let public_key = derive_public_key(&self.private_key);
        self.transport
            .send_control(
                &ControlFrame::RegisterNode {
                    node_id: self.node_id,
                    nat_type: nat_fingerprint.nat_type,
                    external_addr: preferred_external_addr(&nat_fingerprint, &local_candidates),
                    public_key,
                    candidates: local_candidates.clone(),
                    nickname: self.nickname.clone(),
                    local_networks: collect_local_networks(&self.tun_name),
                },
                self.supernode_addr,
            )
            .await?;

        let transport = self.transport.clone();
        let peers = self.peers.clone();
        let room_id = self.room_id.clone();
        let tun = self.tun.clone();
        let tun_name = self.tun_name.clone();
        let tun_mtu = self.tun_mtu;
        let backend_udp = backend.clone();
        let virtual_lan_udp = virtual_lan.clone();
        let discovery = self.discovery.clone();
        let node_id = self.node_id;
        let private_key = self.private_key;
        let supernode_addr_shared = Arc::new(parking_lot::RwLock::new(self.supernode_addr));
        let dataplane_udp = dataplane.clone();
        let route_manager = Arc::new(RouteManager::new()?);
        let route_manager_udp = route_manager.clone();
        let discovery_udp = discovery.clone();
        let advertised_candidates = Arc::new(tokio::sync::RwLock::new(local_candidates.clone()));
        let base_candidates = Arc::new(base_candidates);
        let advertised_candidates_udp = advertised_candidates.clone();
        let metrics_udp = metrics.clone();
        let runtime_udp = runtime_state.clone();
        let pending_create = Arc::new(tokio::sync::Mutex::new(None));
        let pending_join = Arc::new(tokio::sync::Mutex::new(None));
        let pending_rooms_query = Arc::new(tokio::sync::Mutex::new(None));
        let pending_room_name = Arc::new(tokio::sync::Mutex::new(None));
        let pending_create_udp = pending_create.clone();
        let pending_join_udp = pending_join.clone();
        let pending_rooms_query_udp = pending_rooms_query.clone();
        let pending_room_name_udp = pending_room_name.clone();

        let last_supernode_activity_udp = last_supernode_activity.clone();
        let active_invite_code_udp = active_invite_code.clone();
        if let Some(manager) = port_mapping_manager.clone() {
            let mut updates = manager.subscribe();
            let runtime_mapping = runtime_state.clone();
            let metrics_mapping = metrics.clone();
            let transport_mapping = self.transport.clone();
            let advertised_candidates_mapping = advertised_candidates.clone();
            let base_candidates_mapping = base_candidates.clone();
            let nickname_mapping = self.nickname.clone();
            let public_key_mapping = public_key;
            let nat_type_mapping = nat_fingerprint.nat_type;
            let nat_public_addrs_mapping = nat_fingerprint.public_addrs.clone();
            let supernode_addr_mapping = supernode_addr_shared.clone();
            let tun_name_mapping = tun_name.clone();
            tokio::spawn(async move {
                loop {
                    if updates.changed().await.is_err() {
                        break;
                    }
                    let snapshot = updates.borrow().clone();
                    apply_port_mapping_snapshot(&runtime_mapping, &metrics_mapping, &snapshot)
                        .await;

                    let merged =
                        merge_mapped_candidate(base_candidates_mapping.as_ref(), &snapshot);
                    {
                        let mut current = advertised_candidates_mapping.write().await;
                        if *current == merged {
                            continue;
                        }
                        *current = merged.clone();
                    }

                    let current_supernode = *supernode_addr_mapping.read();
                    if let Err(err) = transport_mapping
                        .send_control(
                            &ControlFrame::RegisterNode {
                                node_id,
                                nat_type: nat_type_mapping,
                                external_addr: merged
                                    .iter()
                                    .find(|candidate| {
                                        candidate.source == r2n_proto::CandidateSource::PortMapping
                                    })
                                    .map(|candidate| candidate.addr)
                                    .or_else(|| nat_public_addrs_mapping.first().copied()),
                                public_key: public_key_mapping,
                                candidates: merged,
                                nickname: nickname_mapping.clone(),
                                local_networks: collect_local_networks(&tun_name_mapping),
                            },
                            current_supernode,
                        )
                        .await
                    {
                        log::warn!("failed to re-register updated mapping candidates: {}", err);
                    }
                }
            });
        }

        let supernode_addr_shared_udp = supernode_addr_shared.clone();
        let tun_name_udp = tun_name.clone();
        let udp_loop = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let (packet, addr) = match transport.recv_packet(&mut buf).await {
                    Ok(packet) => packet,
                    Err(err) => {
                        if let r2n_transport::TransportError::Io(io_err) = &err
                            && let Some(code) = io_err.raw_os_error()
                        {
                            // WSAECONNRESET (10054) & WSAENETRESET (10052)
                            if code == 10054 || code == 10052 || code == 10051 {
                                continue;
                            }
                        }
                        log::error!("transport recv failed: {}", err);
                        continue;
                    }
                };

                let supernode_addr_curr = *supernode_addr_shared_udp.read();
                if addr == supernode_addr_curr {
                    let now = std::time::Instant::now();
                    *last_supernode_activity_udp.write().await = now;
                    let mut runtime = runtime_udp.write().await;
                    runtime.supernode_reachable = true;
                    runtime.last_supernode_activity_at = Some(now);
                }

                match packet {
                    TransportPacket::Control(frame) => match frame {
                        ControlFrame::RoomCreated {
                            room_id: created_room,
                            assigned_ip,
                            virtual_cidr,
                            invite_code,
                        } => {
                            log::info!(
                                "Created room {} with IP {} and network {}",
                                created_room,
                                assigned_ip,
                                virtual_cidr
                            );
                            if let Err(err) = activate_room(
                                &room_id,
                                &tun,
                                &tun_name_udp,
                                &route_manager_udp,
                                &discovery_udp,
                                &runtime_udp,
                                &dataplane_udp,
                                created_room,
                                assigned_ip,
                                &virtual_cidr,
                                tun_mtu,
                                &backend_udp,
                                &virtual_lan_udp,
                            )
                            .await
                            {
                                runtime_udp.write().await.last_error = Some(err.to_string());
                                send_pending_reply(
                                    &pending_create_udp,
                                    Err(anyhow::anyhow!("failed to activate created room: {err}")),
                                )
                                .await;
                                continue;
                            }

                            let invite_code =
                                normalize_invite_code(&invite_code, supernode_addr_curr);
                            *active_invite_code_udp.lock().await = Some(invite_code.clone());

                            let room_name = pending_room_name_udp
                                .lock()
                                .await
                                .take()
                                .unwrap_or_else(|| format!("Room-{}", created_room));
                            add_to_history(
                                created_room.to_string(),
                                room_name,
                                invite_code.clone(),
                            );

                            send_pending_reply(
                                &pending_create_udp,
                                Ok(json!({
                                    "status": "ok",
                                    "room_id": created_room.to_string(),
                                    "assigned_ip": assigned_ip.to_string(),
                                    "virtual_cidr": virtual_cidr,
                                    "invite_code": invite_code
                                })),
                            )
                            .await;
                        }
                        ControlFrame::JoinAccept {
                            room_id: joined_room,
                            assigned_ip,
                            virtual_cidr,
                            room_name,
                        } => {
                            log::info!(
                                "Joined room {} with IP {} and network {}",
                                joined_room,
                                assigned_ip,
                                virtual_cidr
                            );
                            if let Err(err) = activate_room(
                                &room_id,
                                &tun,
                                &tun_name_udp,
                                &route_manager_udp,
                                &discovery_udp,
                                &runtime_udp,
                                &dataplane_udp,
                                joined_room,
                                assigned_ip,
                                &virtual_cidr,
                                tun_mtu,
                                &backend_udp,
                                &virtual_lan_udp,
                            )
                            .await
                            {
                                runtime_udp.write().await.last_error = Some(err.to_string());
                                send_pending_reply(
                                    &pending_join_udp,
                                    Err(anyhow::anyhow!("failed to activate joined room: {err}")),
                                )
                                .await;
                                continue;
                            }

                            let r_name =
                                room_name.unwrap_or_else(|| format!("Room-{}", joined_room));
                            if let Some(invite) = active_invite_code_udp.lock().await.as_ref() {
                                add_to_history(joined_room.to_string(), r_name, invite.clone());
                            }

                            send_pending_reply(
                                &pending_join_udp,
                                Ok(json!({
                                    "status": "ok",
                                    "room_id": joined_room.to_string(),
                                    "assigned_ip": assigned_ip.to_string(),
                                    "virtual_cidr": virtual_cidr
                                })),
                            )
                            .await;
                        }
                        ControlFrame::JoinReject { reason } => {
                            *active_invite_code_udp.lock().await = None;
                            runtime_udp.write().await.last_error = Some(reason.clone());
                            send_pending_reply(&pending_join_udp, Err(anyhow::anyhow!(reason)))
                                .await;
                        }
                        ControlFrame::PeerList { peers: room_peers } => {
                            let mut active_nodes = std::collections::HashSet::new();
                            for peer in room_peers {
                                if peer.node_id == node_id {
                                    continue;
                                }
                                active_nodes.insert(peer.node_id);
                                peers
                                    .entry(peer.node_id)
                                    .and_modify(|state| state.info = peer.clone())
                                    .or_insert_with(|| build_peer_state(peer.clone()));
                                dataplane_udp.upsert_peer(DataPeer::new(
                                    peer,
                                    r2n_dataplane::path::PathManager::new(supernode_addr_curr),
                                    None,
                                    SessionId(0),
                                    1,
                                ));
                            }

                            // Remove any peers that are no longer in the room
                            let to_remove: Vec<NodeId> = peers
                                .iter()
                                .map(|entry| *entry.key())
                                .filter(|id| !active_nodes.contains(id))
                                .collect();
                            for id in to_remove {
                                peers.remove(&id);
                                dataplane_udp.remove_peer(&id);
                            }
                        }
                        ControlFrame::PeerUpdate { peer, action } => match action {
                            PeerAction::Add | PeerAction::Update => {
                                if peer.node_id == node_id {
                                    continue;
                                }
                                peers
                                    .entry(peer.node_id)
                                    .and_modify(|state| state.info = peer.clone())
                                    .or_insert_with(|| build_peer_state(peer.clone()));
                                dataplane_udp.upsert_peer(DataPeer::new(
                                    peer,
                                    r2n_dataplane::path::PathManager::new(supernode_addr_curr),
                                    None,
                                    SessionId(0),
                                    1,
                                ));
                            }
                            PeerAction::Remove => {
                                peers.remove(&peer.node_id);
                                dataplane_udp.remove_peer(&peer.node_id);
                            }
                        },
                        ControlFrame::PunchRequest { target, candidates } => {
                            if let Some(mut peer) = peers.get_mut(&target) {
                                peer.candidates = candidates.clone();
                                for candidate in &candidates {
                                    dataplane_udp.add_peer_candidate(target, candidate.addr);
                                }
                                let local_candidates =
                                    advertised_candidates_udp.read().await.clone();
                                let pairs = build_candidate_pairs(&local_candidates, &candidates);
                                let mut session = match NoiseSession::initiator(
                                    &private_key,
                                    &peer.info.public_key,
                                ) {
                                    Ok(session) => session,
                                    Err(err) => {
                                        log::error!("failed to create initiator session: {}", err);
                                        metrics_udp.mark_handshake(target, false);
                                        continue;
                                    }
                                };
                                let session_key = rand::random::<[u8; 32]>();
                                let mut message = vec![0u8; 128];
                                let used = match session.write_message(&session_key, &mut message) {
                                    Ok(used) => used,
                                    Err(err) => {
                                        log::error!("failed to encode handshake: {}", err);
                                        metrics_udp.mark_handshake(target, false);
                                        continue;
                                    }
                                };
                                let handshake_payload = message[..used].to_vec();
                                *peer.handshake.lock().await = Some(session);
                                *peer.pending_session_key.lock().await = Some(session_key);

                                let selected_pairs: Vec<_> =
                                    pairs.into_iter().filter(|p| p.score > 0).take(16).collect();
                                let transport = transport.clone();
                                let payload = handshake_payload.clone();
                                tokio::spawn(async move {
                                    // Burst profile: 0ms, 20ms, 50ms, 100ms, 200ms, 400ms, 800ms
                                    let delays = [0, 20, 30, 50, 100, 200, 400];
                                    for delay in delays {
                                        if delay > 0 {
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                delay,
                                            ))
                                            .await;
                                        }
                                        for pair in &selected_pairs {
                                            let _ = transport
                                                .send_control(
                                                    &ControlFrame::Handshake {
                                                        from: node_id,
                                                        payload: payload.clone(),
                                                    },
                                                    pair.remote.addr,
                                                )
                                                .await;
                                        }
                                    }
                                });
                            }
                        }
                        ControlFrame::Handshake { from, payload } => {
                            let mut response = None;
                            let mut negotiated_key = None;
                            let mut completed_addr = None;

                            if let Some(peer) = peers.get(&from) {
                                let mut hs_lock = peer.handshake.lock().await;
                                if let Some(mut session) = hs_lock.take() {
                                    let mut output = vec![0u8; 128];
                                    if session.read_message(&payload, &mut output).is_ok() {
                                        if session.is_handshake_finished() {
                                            let _ = session.into_transport_mode();
                                            negotiated_key = *peer.pending_session_key.lock().await;
                                            completed_addr = Some(addr);
                                        } else {
                                            *hs_lock = Some(session);
                                        }
                                    }
                                } else {
                                    let mut session = match NoiseSession::responder(&private_key) {
                                        Ok(session) => session,
                                        Err(err) => {
                                            log::error!(
                                                "failed to create responder session: {}",
                                                err
                                            );
                                            metrics_udp.mark_handshake(from, false);
                                            continue;
                                        }
                                    };
                                    let mut output = vec![0u8; 128];
                                    if let Ok(size) = session.read_message(&payload, &mut output) {
                                        if size >= 32 {
                                            let mut key = [0u8; 32];
                                            key.copy_from_slice(&output[..32]);
                                            negotiated_key = Some(key);
                                        }
                                        let mut reply = vec![0u8; 128];
                                        if let Ok(used) = session.write_message(&[], &mut reply) {
                                            response = Some(reply[..used].to_vec());
                                        }
                                        if session.is_handshake_finished() {
                                            let _ = session.into_transport_mode();
                                            completed_addr = Some(addr);
                                        } else {
                                            *hs_lock = Some(session);
                                        }
                                    }
                                }
                            }

                            if let Some(payload) = response {
                                let _ = transport
                                    .send_control(
                                        &ControlFrame::Handshake {
                                            from: node_id,
                                            payload,
                                        },
                                        addr,
                                    )
                                    .await;
                            }

                            if let (Some(key), Some(completed_addr)) =
                                (negotiated_key, completed_addr)
                                && let Some(mut peer) = peers.get_mut(&from)
                            {
                                // Only install cipher if not already installed.
                                // This prevents replay window reset from burst retransmissions.
                                if peer.cipher.is_none() {
                                    let cipher = Arc::new(Cipher::new(&key));
                                    peer.cipher = Some(cipher.clone());
                                    peer.direct_addr = Some(completed_addr);
                                    dataplane_udp.set_direct_path(
                                        from,
                                        completed_addr,
                                        Some(cipher),
                                    );
                                    metrics_udp.mark_handshake(from, true);
                                    log::info!(
                                        "P2P handshake completed with peer {}, direct address: {}",
                                        from,
                                        completed_addr
                                    );
                                }
                            }
                        }
                        ControlFrame::Heartbeat | ControlFrame::RegisterOk => {}
                        ControlFrame::Error { message, .. } => {
                            runtime_udp.write().await.last_error = Some(message.clone());
                            send_pending_reply(
                                &pending_create_udp,
                                Err(anyhow::anyhow!(message.clone())),
                            )
                            .await;
                            send_pending_reply(&pending_join_udp, Err(anyhow::anyhow!(message)))
                                .await;
                        }
                        ControlFrame::RoomsList { rooms } => {
                            let list = rooms
                                .into_iter()
                                .map(|r| {
                                    json!({
                                        "room_id": r.room_id.to_string(),
                                        "name": r.name,
                                        "member_count": r.member_count,
                                    })
                                })
                                .collect::<Vec<_>>();
                            send_pending_reply(
                                &pending_rooms_query_udp,
                                Ok(json!({
                                    "status": "ok",
                                    "rooms": list
                                })),
                            )
                            .await;
                        }
                        other => {
                            log::debug!("Unhandled control frame: {:?}", other);
                        }
                    },
                    TransportPacket::Data(frame) => {
                        let payload = &mut buf[frame.payload_range];
                        if let Err(err) = dataplane_udp
                            .handle_incoming_frame(frame.header, payload, addr)
                            .await
                        {
                            log::error!("failed to process dataplane frame: {err:#}");
                        }
                    }
                }
            }
        });

        let transport_cmd = self.transport.clone();
        let room_id_cmd = self.room_id.clone();
        let tun_cmd = self.tun.clone();
        let peers_cmd = self.peers.clone();
        let dataplane_cmd = dataplane.clone();
        let route_manager_cmd = route_manager.clone();
        let discovery_cmd = discovery.clone();
        let runtime_cmd = runtime_state.clone();
        let pending_create_cmd = pending_create.clone();
        let pending_join_cmd = pending_join.clone();
        let pending_rooms_query_cmd = pending_rooms_query.clone();
        let pending_room_name_cmd = pending_room_name.clone();
        let active_invite_code_cmd = active_invite_code.clone();

        let supernode_addr_shared_cmd = supernode_addr_shared.clone();
        let nickname_cmd = self.nickname.clone();
        let advertised_candidates_cmd = advertised_candidates.clone();
        let nat_fingerprint_cmd = nat_fingerprint.clone();
        let tun_name_cmd = tun_name.clone();
        let cmd_loop = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    EdgeCommand::CreateRoom { name, reply } => {
                        if let Some(active_room) = *room_id_cmd.lock().await {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "already in room {}, leave it before creating a new room",
                                active_room
                            )));
                            continue;
                        }
                        if pending_create_cmd.lock().await.is_some() {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "another room creation is already in progress"
                            )));
                            continue;
                        }
                        *pending_create_cmd.lock().await = Some(reply);
                        *pending_room_name_cmd.lock().await = Some(name.clone());
                        let current_supernode = *supernode_addr_shared_cmd.read();
                        if let Err(err) = transport_cmd
                            .send_control(&ControlFrame::CreateRoom { name }, current_supernode)
                            .await
                        {
                            *pending_room_name_cmd.lock().await = None;
                            send_pending_reply(
                                &pending_create_cmd,
                                Err(anyhow::anyhow!("failed to send create request: {err}")),
                            )
                            .await;
                        }
                    }
                    EdgeCommand::JoinRoom { invite, reply } => {
                        if let Some(active_room) = *room_id_cmd.lock().await {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "already in room {}, leave it before joining another room",
                                active_room
                            )));
                            continue;
                        }
                        if pending_join_cmd.lock().await.is_some() {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "another join operation is already in progress"
                            )));
                            continue;
                        }
                        if let Some(invite_data) = r2n_common::InviteData::decode(&invite) {
                            let current_supernode = *supernode_addr_shared_cmd.read();
                            if let Ok(target_supernode) = resolve_supernode_addr(
                                invite_data.primary_supernode_addr(),
                                current_supernode,
                            ) {
                                *pending_join_cmd.lock().await = Some(reply);
                                *active_invite_code_cmd.lock().await = Some(invite.clone());
                                let mut room_name = None;
                                if let Some(history_item) = load_history()
                                    .into_iter()
                                    .find(|item| item.invite_code == invite)
                                {
                                    room_name = Some(history_item.name);
                                }
                                if let Err(err) = transport_cmd
                                    .send_control(
                                        &ControlFrame::JoinRoom {
                                            room_id: invite_data.room_id,
                                            token: invite_data.token,
                                            room_name,
                                        },
                                        target_supernode,
                                    )
                                    .await
                                {
                                    *active_invite_code_cmd.lock().await = None;
                                    send_pending_reply(
                                        &pending_join_cmd,
                                        Err(anyhow::anyhow!("failed to send join request: {err}")),
                                    )
                                    .await;
                                }
                            } else {
                                let _ = reply.send(Err(anyhow::anyhow!(
                                    "invite contains an invalid supernode address"
                                )));
                            }
                        } else {
                            let _ = reply.send(Err(anyhow::anyhow!("invalid invite code")));
                        }
                    }
                    EdgeCommand::LeaveRoom { reply } => {
                        let room = room_id_cmd.lock().await.unwrap_or(RoomId([0u8; 16]));
                        *active_invite_code_cmd.lock().await = None;
                        let current_supernode = *supernode_addr_shared_cmd.read();
                        let _ = transport_cmd
                            .send_control(
                                &ControlFrame::LeaveRoom { room_id: room },
                                current_supernode,
                            )
                            .await;
                        peers_cmd.clear();
                        deactivate_room(
                            &room_id_cmd,
                            &tun_cmd,
                            &route_manager_cmd,
                            &discovery_cmd,
                            &runtime_cmd,
                            &dataplane_cmd,
                        )
                        .await;
                        let _ = reply.send(Ok(json!({
                            "status": "ok",
                            "message": "left room"
                        })));
                    }
                    EdgeCommand::Stop { reply } => {
                        let room = room_id_cmd.lock().await.unwrap_or(RoomId([0u8; 16]));
                        *active_invite_code_cmd.lock().await = None;
                        let current_supernode = *supernode_addr_shared_cmd.read();
                        if room != RoomId([0u8; 16]) {
                            let _ = transport_cmd
                                .send_control(
                                    &ControlFrame::LeaveRoom { room_id: room },
                                    current_supernode,
                                )
                                .await;
                        }
                        peers_cmd.clear();
                        deactivate_room(
                            &room_id_cmd,
                            &tun_cmd,
                            &route_manager_cmd,
                            &discovery_cmd,
                            &runtime_cmd,
                            &dataplane_cmd,
                        )
                        .await;
                        let _ = reply.send(Ok(json!({
                            "status": "ok",
                            "message": "Daemon shutting down..."
                        })));
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        std::process::exit(0);
                    }
                    EdgeCommand::QueryRooms { reply } => {
                        if pending_rooms_query_cmd.lock().await.is_some() {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "another rooms query is already in progress"
                            )));
                            continue;
                        }
                        *pending_rooms_query_cmd.lock().await = Some(reply);
                        let current_supernode = *supernode_addr_shared_cmd.read();
                        if let Err(err) = transport_cmd
                            .send_control(&ControlFrame::QueryRooms, current_supernode)
                            .await
                        {
                            send_pending_reply(
                                &pending_rooms_query_cmd,
                                Err(anyhow::anyhow!("failed to send query request: {err}")),
                            )
                            .await;
                        }
                    }
                    EdgeCommand::SwitchSupernode { addr, reply } => {
                        let room = room_id_cmd.lock().await.unwrap_or(RoomId([0u8; 16]));
                        *active_invite_code_cmd.lock().await = None;
                        if room != RoomId([0u8; 16]) {
                            let old_supernode = *supernode_addr_shared_cmd.read();
                            let _ = transport_cmd
                                .send_control(
                                    &ControlFrame::LeaveRoom { room_id: room },
                                    old_supernode,
                                )
                                .await;
                        }
                        peers_cmd.clear();
                        deactivate_room(
                            &room_id_cmd,
                            &tun_cmd,
                            &route_manager_cmd,
                            &discovery_cmd,
                            &runtime_cmd,
                            &dataplane_cmd,
                        )
                        .await;

                        *supernode_addr_shared_cmd.write() = addr;

                        {
                            let mut runtime = runtime_cmd.write().await;
                            runtime.supernode_addr = addr.to_string();
                            runtime.last_error = None;
                        }

                        if let Some(config_path) = r2n_config::EdgeConfig::get_config_path() {
                            match r2n_config::EdgeConfig::load_or_create() {
                                Ok((mut config, _)) => {
                                    if config.default_supernode != addr.to_string() {
                                        config.default_supernode = addr.to_string();
                                        if let Err(err) = config.save(&config_path) {
                                            log::warn!(
                                                "failed to persist switched supernode to {:?}: {}",
                                                config_path,
                                                err
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    log::warn!(
                                        "failed to load config for supernode persistence: {}",
                                        err
                                    );
                                }
                            }
                        }

                        let public_key = derive_public_key(&private_key);
                        let current_candidates = advertised_candidates_cmd.read().await.clone();
                        if let Err(err) = transport_cmd
                            .send_control(
                                &ControlFrame::RegisterNode {
                                    node_id,
                                    nat_type: nat_fingerprint_cmd.nat_type,
                                    external_addr: preferred_external_addr(
                                        &nat_fingerprint_cmd,
                                        &current_candidates,
                                    ),
                                    public_key,
                                    candidates: current_candidates,
                                    nickname: nickname_cmd.clone(),
                                    local_networks: collect_local_networks(&tun_name_cmd),
                                },
                                addr,
                            )
                            .await
                        {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "failed to register on new supernode: {err}"
                            )));
                            continue;
                        }

                        let _ = reply.send(Ok(json!({
                            "status": "ok",
                            "message": format!("Successfully switched supernode to {}", addr)
                        })));
                    }
                }
            }
        });

        let heartbeat_transport = self.transport.clone();
        let supernode_addr_shared_hb = supernode_addr_shared.clone();
        let heartbeat_loop = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let current_supernode = *supernode_addr_shared_hb.read();
                let _ = heartbeat_transport
                    .send_control(&ControlFrame::Heartbeat, current_supernode)
                    .await;
            }
        });

        let p2p_transport = self.transport.clone();
        let peers_heartbeat = self.peers.clone();
        let p2p_heartbeat_loop = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                for peer in peers_heartbeat.iter() {
                    if let Some(addr) = peer.value().direct_addr {
                        let _ = p2p_transport
                            .send_control(&ControlFrame::Heartbeat, addr)
                            .await;
                    }
                }
            }
        });

        let watchdog_transport = self.transport.clone();
        let watchdog_room_id = self.room_id.clone();
        let watchdog_invite = active_invite_code.clone();
        let watchdog_activity = last_supernode_activity.clone();
        let watchdog_runtime = runtime_state.clone();
        let watchdog_node_id = self.node_id;
        let watchdog_private_key = self.private_key;
        let watchdog_nickname = self.nickname.clone();
        let watchdog_candidates = advertised_candidates.clone();
        let watchdog_nat_type = nat_fingerprint.nat_type;
        let watchdog_tun_name = tun_name.clone();
        let supernode_addr_shared_wd = supernode_addr_shared.clone();
        let watchdog_supernodes = self.supernodes.clone();

        let watchdog_loop = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            let mut is_reconnecting = false;
            loop {
                interval.tick().await;
                let room_active = watchdog_room_id.lock().await.is_some();
                let last_activity = *watchdog_activity.read().await;
                let elapsed = last_activity.elapsed();
                let current_supernode = *supernode_addr_shared_wd.read();
                let reachable = elapsed <= std::time::Duration::from_secs(25);

                {
                    let mut runtime = watchdog_runtime.write().await;
                    runtime.supernode_reachable = reachable;
                    if !reachable && runtime.last_error.is_none() && room_active {
                        runtime.last_error =
                            Some("Supernode heartbeat timed out; trying to reconnect".to_string());
                    } else if reachable
                        && matches!(
                            runtime.last_error.as_deref(),
                            Some("Supernode heartbeat timed out; trying to reconnect")
                        )
                    {
                        runtime.last_error = None;
                    }
                }

                if !room_active {
                    is_reconnecting = false;
                    continue;
                }

                if !reachable {
                    if !is_reconnecting {
                        log::warn!(
                            "Connection to supernode lost (no activity for {}s). Reconnecting...",
                            elapsed.as_secs()
                        );
                        is_reconnecting = true;
                    }
                    let target_supernode =
                        next_supernode_after(current_supernode, &watchdog_supernodes);
                    if target_supernode != current_supernode {
                        *supernode_addr_shared_wd.write() = target_supernode;
                        let mut runtime = watchdog_runtime.write().await;
                        runtime.supernode_addr = target_supernode.to_string();
                        runtime.last_error = Some(format!(
                            "Supernode heartbeat timed out; trying fallback {}",
                            target_supernode
                        ));
                    }

                    // Send RegisterNode to try to re-establish registration
                    let public_key = derive_public_key(&watchdog_private_key);
                    let current_candidates = watchdog_candidates.read().await.clone();
                    let reg_frame = ControlFrame::RegisterNode {
                        node_id: watchdog_node_id,
                        nat_type: watchdog_nat_type,
                        external_addr: current_candidates
                            .iter()
                            .find(|candidate| {
                                candidate.source == r2n_proto::CandidateSource::PortMapping
                                    || matches!(
                                        candidate.kind,
                                        r2n_proto::CandidateKind::ServerReflexive
                                    )
                            })
                            .map(|candidate| candidate.addr),
                        public_key,
                        candidates: current_candidates,
                        nickname: watchdog_nickname.clone(),
                        local_networks: collect_local_networks(&watchdog_tun_name),
                    };

                    let _ = watchdog_transport
                        .send_control(&reg_frame, target_supernode)
                        .await;

                    // If we have an active invite code, also send a JoinRoom to restore membership
                    if let Some(invite) = watchdog_invite.lock().await.as_ref()
                        && let Some(invite_data) = r2n_common::InviteData::decode(invite)
                    {
                        let mut room_name = None;
                        if let Some(history_item) = load_history()
                            .into_iter()
                            .find(|item| item.invite_code == *invite)
                        {
                            room_name = Some(history_item.name);
                        }
                        let join_frame = ControlFrame::JoinRoom {
                            room_id: invite_data.room_id,
                            token: invite_data.token,
                            room_name,
                        };
                        let _ = watchdog_transport
                            .send_control(&join_frame, target_supernode)
                            .await;
                    }
                } else if is_reconnecting {
                    log::info!("Successfully reconnected to supernode.");
                    is_reconnecting = false;
                }
            }
        });

        tokio::select! {
            _ = udp_loop => log::error!("udp loop exited"),
            _ = cmd_loop => log::error!("command loop exited"),
            _ = heartbeat_loop => log::error!("supernode heartbeat loop exited"),
            _ = p2p_heartbeat_loop => log::error!("peer heartbeat loop exited"),
            _ = watchdog_loop => log::error!("watchdog loop exited"),
        }

        Ok(())
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub room_id: String,
    pub name: String,
    pub invite_code: String,
    pub last_joined: u64,
}

pub fn get_history_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|dir| dir.join("r2n").join("history.json"))
}

pub fn load_history() -> Vec<HistoryItem> {
    let Some(path) = get_history_path() else {
        return Vec::new();
    };
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

pub fn save_history(mut history: Vec<HistoryItem>) {
    history.sort_by(|a, b| b.last_joined.cmp(&a.last_joined));
    history.truncate(20);
    let Some(path) = get_history_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(content) = serde_json::to_string_pretty(&history) {
        let _ = std::fs::write(path, content);
    }
}

pub fn add_to_history(room_id: String, name: String, invite_code: String) {
    let mut history = load_history();
    history.retain(|item| item.room_id != room_id);
    history.push(HistoryItem {
        room_id,
        name,
        invite_code,
        last_joined: std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });
    save_history(history);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn resolve_supernode_addr_rewrites_unspecified_ip() {
        let fallback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(139, 196, 85, 193)), 7777);
        let resolved = resolve_supernode_addr("0.0.0.0:7777", fallback).expect("resolve");
        assert_eq!(resolved, fallback);
    }

    #[test]
    fn normalize_invite_code_rewrites_unspecified_supernode() {
        let fallback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(139, 196, 85, 193)), 7777);
        let invite = InviteData {
            version: InviteData::VERSION,
            primary_supernode: "0.0.0.0:7777".to_string(),
            fallback_supernodes: Vec::new(),
            supernode_addr: "0.0.0.0:7777".to_string(),
            room_id: RoomId([5u8; 16]),
            room_pub_key: [9u8; 32],
            virtual_cidr: Some("10.66.1.0/24".to_string()),
            token: Some("token-1".to_string()),
            expires_at: None,
            signature: None,
        };
        let normalized = normalize_invite_code(&invite.encode(), fallback);
        let decoded = InviteData::decode(&normalized).expect("decode");
        assert_eq!(decoded.supernode_addr, fallback.to_string());
        assert_eq!(decoded.primary_supernode, fallback.to_string());
    }

    #[test]
    fn normalize_tun_mtu_enforces_floor_without_lowering_higher_values() {
        assert_eq!(normalize_tun_mtu(MIN_TUN_MTU - 80), MIN_TUN_MTU);
        assert_eq!(normalize_tun_mtu(MIN_TUN_MTU), MIN_TUN_MTU);
        assert_eq!(normalize_tun_mtu(1400), 1400);
    }

    #[test]
    fn backend_request_label_reflects_tap_and_l2_enhanced_modes() {
        let tun = BackendConfig::default();
        assert_eq!(backend_request_label(&tun), "tun");

        let tap = BackendConfig {
            mode: BackendMode::Tap,
            desktop_l2_enhanced: false,
        };
        assert_eq!(backend_request_label(&tap), "tap");

        let enhanced = BackendConfig {
            mode: BackendMode::Tun,
            desktop_l2_enhanced: true,
        };
        assert_eq!(backend_request_label(&enhanced), "tap");
    }

    #[test]
    fn test_history_serialization_and_deserialization() {
        // Create a temp directory for history.json
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let history_path = temp_dir.path().join("history.json");

        // Save a test item
        let history = vec![HistoryItem {
            room_id: "test_room_id".to_string(),
            name: "Test Room".to_string(),
            invite_code: "test_invite_code".to_string(),
            last_joined: 123456789,
        }];

        let content = serde_json::to_string_pretty(&history).expect("serialize history");
        std::fs::write(&history_path, content).expect("write history");

        // Load the saved item
        let loaded_content = std::fs::read_to_string(&history_path).expect("read history");
        let loaded: Vec<HistoryItem> =
            serde_json::from_str(&loaded_content).expect("deserialize history");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].room_id, "test_room_id");
        assert_eq!(loaded[0].name, "Test Room");
        assert_eq!(loaded[0].invite_code, "test_invite_code");
    }
}
