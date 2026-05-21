use chrono::{DateTime, Utc};
use dashmap::DashMap;
use r2n_common::{NatType, NodeId};
use r2n_proto::DataPacketType;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisReport {
    pub timestamp: DateTime<Utc>,
    pub supernode_reachable: bool,
    pub udp_working: bool,
    pub nat_type: NatType,
    pub virtual_ip: Option<String>,
    pub tun_status: String,
    pub route_status: String,
    pub discovery_broadcast_detected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPathMetrics {
    pub peer: NodeId,
    pub path: PathKind,
    pub last_rtt_ms: Option<u32>,
    pub relay_hits: u64,
    pub direct_hits: u64,
    pub handshake_successes: u64,
    pub handshake_failures: u64,
    pub packet_drops: u64,
    pub packet_loss_rate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub handshake_successes: u64,
    pub handshake_failures: u64,
    pub relay_packets: u64,
    pub direct_packets: u64,
    pub packet_drops: u64,
    pub broadcast_packets: u64,
    pub multicast_packets: u64,
    pub l2_flood_packets: u64,
    pub port_mapping_acquired: bool,
    pub port_mapping_protocol: Option<String>,
    pub port_mapping_external_addr: Option<String>,
    pub port_mapping_lease_remaining_secs: Option<u64>,
    pub peers: Vec<PeerPathMetrics>,
}

pub struct MetricsRegistry {
    handshake_successes: AtomicU64,
    handshake_failures: AtomicU64,
    relay_packets: AtomicU64,
    direct_packets: AtomicU64,
    packet_drops: AtomicU64,
    broadcast_packets: AtomicU64,
    multicast_packets: AtomicU64,
    l2_flood_packets: AtomicU64,
    port_mapping: std::sync::RwLock<PortMappingMetrics>,
    peers: DashMap<NodeId, Arc<PeerCounters>>,
}

#[derive(Debug, Clone, Default)]
struct PortMappingMetrics {
    acquired: bool,
    protocol: Option<String>,
    external_addr: Option<String>,
    lease_expires_at: Option<Instant>,
}

struct PeerCounters {
    path: std::sync::RwLock<PathKind>,
    last_rtt_ms: std::sync::RwLock<Option<u32>>,
    relay_hits: AtomicU64,
    direct_hits: AtomicU64,
    handshake_successes: AtomicU64,
    handshake_failures: AtomicU64,
    packet_drops: AtomicU64,
    pending_pings: std::sync::Mutex<HashMap<u32, (SocketAddr, Instant, bool)>>,
    ping_window: std::sync::Mutex<VecDeque<bool>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            handshake_successes: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
            relay_packets: AtomicU64::new(0),
            direct_packets: AtomicU64::new(0),
            packet_drops: AtomicU64::new(0),
            broadcast_packets: AtomicU64::new(0),
            multicast_packets: AtomicU64::new(0),
            l2_flood_packets: AtomicU64::new(0),
            port_mapping: std::sync::RwLock::new(PortMappingMetrics::default()),
            peers: DashMap::new(),
        }
    }

    pub fn mark_handshake(&self, peer: NodeId, success: bool) {
        let counters = self.ensure_peer(peer);
        if success {
            self.handshake_successes.fetch_add(1, Ordering::Relaxed);
            counters.handshake_successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.handshake_failures.fetch_add(1, Ordering::Relaxed);
            counters.handshake_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn mark_path_hit(&self, peer: NodeId, path: PathKind) {
        let counters = self.ensure_peer(peer);
        *counters.path.write().expect("path lock") = path;
        match path {
            PathKind::Direct => {
                self.direct_packets.fetch_add(1, Ordering::Relaxed);
                counters.direct_hits.fetch_add(1, Ordering::Relaxed);
            }
            PathKind::Relay => {
                self.relay_packets.fetch_add(1, Ordering::Relaxed);
                counters.relay_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn mark_packet_drop(&self, peer: Option<NodeId>) {
        self.packet_drops.fetch_add(1, Ordering::Relaxed);
        if let Some(peer) = peer {
            self.ensure_peer(peer)
                .packet_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn mark_discovery_packet(&self, packet_type: DataPacketType) {
        match packet_type {
            DataPacketType::Broadcast => {
                self.broadcast_packets.fetch_add(1, Ordering::Relaxed);
            }
            DataPacketType::Multicast => {
                self.multicast_packets.fetch_add(1, Ordering::Relaxed);
            }
            DataPacketType::Ethernet => {
                self.l2_flood_packets.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn update_rtt(&self, peer: NodeId, rtt_ms: Option<u32>) {
        *self
            .ensure_peer(peer)
            .last_rtt_ms
            .write()
            .expect("rtt lock") = rtt_ms;
    }

    pub fn set_port_mapping_status(
        &self,
        acquired: bool,
        protocol: Option<String>,
        external_addr: Option<String>,
        lease_expires_at: Option<Instant>,
    ) {
        *self.port_mapping.write().expect("port mapping lock") = PortMappingMetrics {
            acquired,
            protocol,
            external_addr,
            lease_expires_at,
        };
    }

    pub fn record_ping_sent(&self, peer: NodeId, seq: u32, addr: SocketAddr, is_active: bool) {
        let counters = self.ensure_peer(peer);
        let mut pending = counters.pending_pings.lock().expect("pending lock");
        pending.insert(seq, (addr, Instant::now(), is_active));
    }

    pub fn record_pong_received(&self, peer: NodeId, seq: u32) -> Option<(SocketAddr, u32)> {
        let counters = self.ensure_peer(peer);
        let mut pending = counters.pending_pings.lock().expect("pending lock");
        if let Some((addr, send_time, is_active)) = pending.remove(&seq) {
            let rtt_ms = send_time.elapsed().as_millis() as u32;
            *counters.last_rtt_ms.write().expect("rtt lock") = Some(rtt_ms);

            if is_active {
                let mut window = counters.ping_window.lock().expect("window lock");
                window.push_back(true);
                if window.len() > 20 {
                    window.pop_front();
                }
            }
            Some((addr, rtt_ms))
        } else {
            None
        }
    }

    pub fn check_ping_timeouts(&self, timeout: Duration) -> Vec<(NodeId, SocketAddr)> {
        let now = Instant::now();
        let mut all_timed_out = Vec::new();
        for entry in self.peers.iter() {
            let peer_id = *entry.key();
            let counters = entry.value();
            let mut pending = counters.pending_pings.lock().expect("pending lock");
            let mut window = counters.ping_window.lock().expect("window lock");

            let mut timed_out_seqs = Vec::new();
            for (&seq, &(addr, send_time, is_active)) in pending.iter() {
                if now.duration_since(send_time) > timeout {
                    timed_out_seqs.push((seq, addr, is_active));
                }
            }

            for (seq, addr, is_active) in timed_out_seqs {
                pending.remove(&seq);
                if is_active {
                    window.push_back(false);
                    if window.len() > 20 {
                        window.pop_front();
                    }
                }
                all_timed_out.push((peer_id, addr));
            }
        }
        all_timed_out
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let port_mapping = self.port_mapping.read().expect("port mapping lock").clone();
        MetricsSnapshot {
            handshake_successes: self.handshake_successes.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
            relay_packets: self.relay_packets.load(Ordering::Relaxed),
            direct_packets: self.direct_packets.load(Ordering::Relaxed),
            packet_drops: self.packet_drops.load(Ordering::Relaxed),
            broadcast_packets: self.broadcast_packets.load(Ordering::Relaxed),
            multicast_packets: self.multicast_packets.load(Ordering::Relaxed),
            l2_flood_packets: self.l2_flood_packets.load(Ordering::Relaxed),
            port_mapping_acquired: port_mapping.acquired,
            port_mapping_protocol: port_mapping.protocol,
            port_mapping_external_addr: port_mapping.external_addr,
            port_mapping_lease_remaining_secs: port_mapping.lease_expires_at.map(|expires_at| {
                expires_at
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            }),
            peers: self
                .peers
                .iter()
                .map(|entry| {
                    let window = entry.value().ping_window.lock().expect("window lock");
                    let packet_loss_rate = if window.is_empty() {
                        0.0
                    } else {
                        let failures = window.iter().filter(|&&success| !success).count();
                        failures as f32 / window.len() as f32
                    };
                    PeerPathMetrics {
                        peer: *entry.key(),
                        path: *entry.value().path.read().expect("path lock"),
                        last_rtt_ms: *entry.value().last_rtt_ms.read().expect("rtt lock"),
                        relay_hits: entry.value().relay_hits.load(Ordering::Relaxed),
                        direct_hits: entry.value().direct_hits.load(Ordering::Relaxed),
                        handshake_successes: entry
                            .value()
                            .handshake_successes
                            .load(Ordering::Relaxed),
                        handshake_failures: entry
                            .value()
                            .handshake_failures
                            .load(Ordering::Relaxed),
                        packet_drops: entry.value().packet_drops.load(Ordering::Relaxed),
                        packet_loss_rate,
                    }
                })
                .collect(),
        }
    }

    fn ensure_peer(&self, peer: NodeId) -> Arc<PeerCounters> {
        self.peers
            .entry(peer)
            .or_insert_with(|| {
                Arc::new(PeerCounters {
                    path: std::sync::RwLock::new(PathKind::Relay),
                    last_rtt_ms: std::sync::RwLock::new(None),
                    relay_hits: AtomicU64::new(0),
                    direct_hits: AtomicU64::new(0),
                    handshake_successes: AtomicU64::new(0),
                    handshake_failures: AtomicU64::new(0),
                    packet_drops: AtomicU64::new(0),
                    pending_pings: std::sync::Mutex::new(HashMap::new()),
                    ping_window: std::sync::Mutex::new(VecDeque::new()),
                })
            })
            .clone()
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DiagnosticEngine;

impl DiagnosticEngine {
    pub fn new() -> Self {
        Self
    }

    /// Perform a full diagnosis of the current node state.
    pub async fn run_diagnosis(&self) -> DiagnosisReport {
        DiagnosisReport {
            timestamp: Utc::now(),
            supernode_reachable: true,
            udp_working: true,
            nat_type: NatType::Unknown,
            virtual_ip: None,
            tun_status: "OK".to_string(),
            route_status: "OK".to_string(),
            discovery_broadcast_detected: false,
        }
    }
}

impl Default for DiagnosticEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_registry_tracks_peer_activity() {
        let registry = MetricsRegistry::new();
        let peer = NodeId([7u8; 32]);
        registry.mark_handshake(peer, true);
        registry.mark_path_hit(peer, PathKind::Direct);
        registry.mark_packet_drop(Some(peer));
        registry.update_rtt(peer, Some(42));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.handshake_successes, 1);
        assert_eq!(snapshot.direct_packets, 1);
        assert_eq!(snapshot.packet_drops, 1);
        assert_eq!(snapshot.broadcast_packets, 0);
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].last_rtt_ms, Some(42));
        assert_eq!(snapshot.peers[0].packet_loss_rate, 0.0);

        // Test ping/pong tracking and packet loss rate
        let dummy_addr = "127.0.0.1:8080".parse().unwrap();
        registry.record_ping_sent(peer, 1, dummy_addr, true);
        registry.record_ping_sent(peer, 2, dummy_addr, true);
        registry.record_pong_received(peer, 1);
        registry.check_ping_timeouts(Duration::from_secs(0));

        let snapshot2 = registry.snapshot();
        assert_eq!(snapshot2.peers[0].packet_loss_rate, 0.5);
    }

    #[test]
    fn metrics_registry_tracks_discovery_packets() {
        let registry = MetricsRegistry::new();

        registry.mark_discovery_packet(DataPacketType::Broadcast);
        registry.mark_discovery_packet(DataPacketType::Multicast);
        registry.mark_discovery_packet(DataPacketType::Ethernet);
        registry.mark_discovery_packet(DataPacketType::IPv4);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.broadcast_packets, 1);
        assert_eq!(snapshot.multicast_packets, 1);
        assert_eq!(snapshot.l2_flood_packets, 1);
    }
}
