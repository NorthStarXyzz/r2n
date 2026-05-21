mod port_mapping;

#[cfg(not(target_os = "android"))]
use if_addrs::get_if_addrs;
use r2n_common::NatType;
use r2n_proto::{Candidate, CandidateKind, CandidateSource};
use r2n_transport::UdpTransport;
use std::cmp::Reverse;
use std::net::SocketAddr;
use std::time::Duration;

pub use port_mapping::{
    PortMappingManager, PortMappingProtocol, PortMappingSnapshot, PortMappingSnapshotView,
};

#[derive(Debug, Clone)]
pub struct NatFingerprint {
    pub nat_type: NatType,
    pub public_addrs: Vec<SocketAddr>,
    pub endpoint_independent_mapping: bool,
    pub port_preserving: bool,
    pub port_delta_pattern: Option<i32>,
    pub binding_lifetime: Duration,
    pub hairpin_supported: bool,
    pub udp_restricted: bool,
}

pub struct NatProbe<'a> {
    transport: &'a UdpTransport,
}

impl<'a> NatProbe<'a> {
    pub fn new(transport: &'a UdpTransport) -> Self {
        Self { transport }
    }

    pub async fn fingerprint(&self, servers: &[&str]) -> r2n_transport::Result<NatFingerprint> {
        let mut unique_servers: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
        unique_servers.sort();
        unique_servers.dedup();

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(15));
        let mut futures = Vec::new();
        for server in unique_servers {
            let sem_clone = sem.clone();
            futures.push(tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.ok();
                match tokio::time::timeout(Duration::from_secs(2), probe_stun_server(server)).await
                {
                    Ok(Some((addr, rtt))) => Some((addr, rtt)),
                    _ => None,
                }
            }));
        }

        let results = futures_util::future::join_all(futures).await;
        let mut active_servers: Vec<(SocketAddr, Duration)> = results
            .into_iter()
            .filter_map(|res| res.ok().flatten())
            .collect();

        // Sort by latency (RTT) ascending
        active_servers.sort_by_key(|&(_, rtt)| rtt);

        // Take the top 5 fastest STUN servers to avoid creating excessive candidates
        let mut public_addrs = Vec::new();
        for (addr, rtt) in active_servers.into_iter().take(5) {
            log::info!("STUN server probe succeeded (RTT: {:?}): {}", rtt, addr);
            public_addrs.push(addr);
        }

        let nat_type = infer_nat_type(&public_addrs);
        let local_port = self.transport.local_addr()?.port();
        let first = public_addrs.first().copied();
        let endpoint_independent_mapping = public_addrs.iter().all(|addr| Some(*addr) == first);
        let port_preserving = first.map(|addr| addr.port() == local_port).unwrap_or(false);

        let port_delta_pattern = infer_port_delta_pattern(&public_addrs);

        Ok(NatFingerprint {
            nat_type,
            public_addrs,
            endpoint_independent_mapping,
            port_preserving,
            port_delta_pattern,
            binding_lifetime: Duration::from_secs(30),
            hairpin_supported: false,
            udp_restricted: false,
        })
    }

    pub async fn collect_candidates(
        &self,
        servers: &[&str],
    ) -> r2n_transport::Result<(NatFingerprint, Vec<Candidate>)> {
        let fingerprint = self.fingerprint(servers).await?;
        let mut candidates = Vec::new();
        let local_port = self.transport.local_addr()?.port();

        #[cfg(not(target_os = "android"))]
        if let Ok(ifaces) = get_if_addrs() {
            for iface in ifaces {
                let ip = iface.ip();
                if ip.is_loopback() {
                    continue;
                }
                candidates.push(Candidate {
                    kind: if ip.is_ipv6() {
                        CandidateKind::HostIpv6
                    } else {
                        CandidateKind::HostLan
                    },
                    source: CandidateSource::LocalInterface,
                    addr: SocketAddr::new(ip, local_port),
                    priority: 100,
                    rtt_hint_ms: None,
                });
            }
        }

        #[cfg(target_os = "android")]
        {
            // Android sandboxed apps typically have one active network interface.
            // LAN candidates are less useful on mobile; rely on STUN fingerprinting instead.
        }

        for addr in &fingerprint.public_addrs {
            candidates.push(Candidate {
                kind: CandidateKind::ServerReflexive,
                source: CandidateSource::StunPrimary,
                addr: *addr,
                priority: 80,
                rtt_hint_ms: None,
            });
        }

        if let Some(predicted) = predict_from_fingerprint(&fingerprint) {
            for addr in predicted {
                candidates.push(Candidate {
                    kind: CandidateKind::PortPredicted,
                    source: CandidateSource::PortPrediction,
                    addr,
                    priority: 50,
                    rtt_hint_ms: None,
                });
            }
        }

        candidates.sort_by_key(|candidate| Reverse(candidate.priority));
        candidates.dedup_by(|left, right| left.addr == right.addr && left.kind == right.kind);
        Ok((fingerprint, candidates))
    }
}

pub fn merge_mapped_candidate(
    base_candidates: &[Candidate],
    snapshot: &PortMappingSnapshot,
) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = base_candidates
        .iter()
        .filter(|candidate| candidate.source != CandidateSource::PortMapping)
        .cloned()
        .collect();

    if let Some(candidate) = snapshot.as_candidate() {
        candidates.push(candidate);
    }

    candidates.sort_by_key(|candidate| Reverse(candidate.priority));
    candidates.dedup_by(|left, right| left.addr == right.addr && left.kind == right.kind);
    candidates
}

pub fn preferred_external_addr(
    fingerprint: &NatFingerprint,
    candidates: &[Candidate],
) -> Option<SocketAddr> {
    candidates
        .iter()
        .find(|candidate| candidate.source == CandidateSource::PortMapping)
        .map(|candidate| candidate.addr)
        .or_else(|| fingerprint.public_addrs.first().copied())
}

fn infer_port_delta_pattern(public_addrs: &[SocketAddr]) -> Option<i32> {
    if public_addrs.len() < 2 {
        return None;
    }

    let mut ports: Vec<u16> = public_addrs.iter().map(|addr| addr.port()).collect();
    ports.sort_unstable();

    let mut deltas = Vec::new();
    for window in ports.windows(2) {
        let p1 = window[0] as i32;
        let p2 = window[1] as i32;
        deltas.push(p2 - p1);
    }

    let first_delta = deltas[0];
    if (1..=16).contains(&first_delta) && deltas.iter().all(|&d| d == first_delta) {
        Some(first_delta)
    } else {
        None
    }
}

pub fn predict_from_fingerprint(fp: &NatFingerprint) -> Option<Vec<SocketAddr>> {
    if !matches!(fp.nat_type, NatType::Symmetric) {
        return None;
    }

    let last_addr = fp.public_addrs.iter().max_by_key(|a| a.port())?;
    let ip = last_addr.ip();
    let max_port = last_addr.port() as i32;

    let mut predicted = Vec::new();
    let delta = fp.port_delta_pattern.unwrap_or(1);

    // Predict forward (e.g. next 8 ports based on delta)
    for i in 1..=8 {
        let p = max_port + delta * i;
        if p > 0 && p <= 65535 {
            predicted.push(SocketAddr::new(ip, p as u16));
        }
    }

    // Add a small window around the last port just in case
    for d in -8..=8 {
        if d == 0 {
            continue;
        }
        let p = max_port + d;
        if p > 0 && p <= 65535 {
            let addr = SocketAddr::new(ip, p as u16);
            if !predicted.contains(&addr) {
                predicted.push(addr);
            }
        }
    }

    Some(predicted)
}

fn infer_nat_type(public_addrs: &[SocketAddr]) -> NatType {
    if public_addrs.len() < 2 {
        return NatType::Unknown;
    }

    if public_addrs.windows(2).all(|window| window[0] == window[1]) {
        NatType::Cone
    } else {
        NatType::Symmetric
    }
}

async fn probe_stun_server(server: String) -> Option<(SocketAddr, Duration)> {
    use std::time::Instant;
    use stun_rs::attributes::stun::XorMappedAddress;
    use stun_rs::methods::BINDING;
    use stun_rs::{
        MessageClass, MessageDecoderBuilder, MessageEncoderBuilder, StunAttribute,
        StunMessageBuilder,
    };
    use tokio::net::UdpSocket;

    let start = Instant::now();
    let addrs = tokio::net::lookup_host(&server).await.ok()?;
    let target = addrs.into_iter().find(|addr| addr.is_ipv4())?;

    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let msg = StunMessageBuilder::new(BINDING, MessageClass::Request).build();
    let mut buffer = [0u8; 512];
    let encoder = MessageEncoderBuilder::default().build();
    let size = encoder.encode(&mut buffer, &msg).ok()?;

    socket.send_to(&buffer[..size], target).await.ok()?;

    let mut recv_buffer = [0u8; 512];
    let (n, _) = tokio::time::timeout(
        Duration::from_millis(1500),
        socket.recv_from(&mut recv_buffer),
    )
    .await
    .ok()?
    .ok()?;

    let decoder = MessageDecoderBuilder::default().build();
    let (decoded_msg, _) = decoder.decode(&recv_buffer[..n]).ok()?;

    if let Some(StunAttribute::XorMappedAddress(attr)) = decoded_msg.get::<XorMappedAddress>() {
        let elapsed = start.elapsed();
        Some((*attr.socket_address(), elapsed))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn infer_nat_type_requires_two_observations() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345);
        assert!(matches!(infer_nat_type(&[]), NatType::Unknown));
        assert!(matches!(infer_nat_type(&[addr]), NatType::Unknown));
    }

    #[test]
    fn infer_nat_type_distinguishes_cone_and_symmetric() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 23456);
        assert!(matches!(infer_nat_type(&[addr1, addr2]), NatType::Cone));
        assert!(matches!(
            infer_nat_type(&[addr1, addr3]),
            NatType::Symmetric
        ));
    }

    #[test]
    fn merge_mapped_candidate_replaces_previous_mapping_entry() {
        let base = vec![
            Candidate {
                kind: CandidateKind::HostLan,
                source: CandidateSource::LocalInterface,
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), 4000),
                priority: 100,
                rtt_hint_ms: None,
            },
            Candidate {
                kind: CandidateKind::ServerReflexive,
                source: CandidateSource::PortMapping,
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5000),
                priority: 90,
                rtt_hint_ms: None,
            },
        ];
        let snapshot = PortMappingSnapshot {
            acquired: true,
            protocol: Some(PortMappingProtocol::UpnpIgd),
            external_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 6000)),
            lease_remaining: Some(Duration::from_secs(120)),
        };

        let merged = merge_mapped_candidate(&base, &snapshot);
        let mapped: Vec<_> = merged
            .iter()
            .filter(|candidate| candidate.source == CandidateSource::PortMapping)
            .collect();

        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].addr, snapshot.external_addr.unwrap());
    }

    #[test]
    fn test_infer_port_delta_pattern_success() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let addrs = vec![
            SocketAddr::new(ip, 50000),
            SocketAddr::new(ip, 50002),
            SocketAddr::new(ip, 50004),
        ];
        let pattern = infer_port_delta_pattern(&addrs);
        assert_eq!(pattern, Some(2));
    }

    #[test]
    fn test_infer_port_delta_pattern_unsorted_success() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let addrs = vec![
            SocketAddr::new(ip, 50004),
            SocketAddr::new(ip, 50000),
            SocketAddr::new(ip, 50002),
        ];
        let pattern = infer_port_delta_pattern(&addrs);
        assert_eq!(pattern, Some(2));
    }

    #[test]
    fn test_infer_port_delta_pattern_too_large() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let addrs = vec![SocketAddr::new(ip, 50000), SocketAddr::new(ip, 50100)];
        let pattern = infer_port_delta_pattern(&addrs);
        assert_eq!(pattern, None);
    }

    #[test]
    fn test_predict_from_fingerprint_fallback() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let fp = NatFingerprint {
            nat_type: NatType::Symmetric,
            public_addrs: vec![SocketAddr::new(ip, 50000), SocketAddr::new(ip, 50005)],
            endpoint_independent_mapping: false,
            port_preserving: false,
            port_delta_pattern: None,
            binding_lifetime: Duration::from_secs(30),
            hairpin_supported: false,
            udp_restricted: false,
        };

        let predicted = predict_from_fingerprint(&fp).unwrap();
        assert!(predicted.contains(&SocketAddr::new(ip, 50006)));
        assert!(predicted.contains(&SocketAddr::new(ip, 50007)));
        assert!(predicted.contains(&SocketAddr::new(ip, 49997)));
    }
}
