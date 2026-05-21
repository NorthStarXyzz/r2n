use r2n_common::NodeId;
use r2n_proto::{Candidate, CandidateKind};
use std::cmp::Reverse;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub score: u32,
}

#[derive(Debug, Clone)]
pub struct PathScore {
    pub addr: SocketAddr,
    pub rtt: Option<Duration>,
    pub loss_basis_points: u16,
    pub relay: bool,
}

#[derive(Debug, Clone)]
pub struct PathUpgrade {
    pub peer: NodeId,
    pub preferred: SocketAddr,
    pub relay_fallback: Option<SocketAddr>,
}

pub fn build_candidate_pairs(local: &[Candidate], remote: &[Candidate]) -> Vec<CandidatePair> {
    let mut pairs = Vec::new();
    for left in local {
        for right in remote {
            let score = left.priority + right.priority + locality_bonus(left, right);
            pairs.push(CandidatePair {
                local: left.clone(),
                remote: right.clone(),
                score,
            });
        }
    }

    pairs.sort_by_key(|pair| Reverse(pair.score));
    pairs
}

pub fn choose_upgrade(
    peer: NodeId,
    relay_fallback: Option<SocketAddr>,
    scored_paths: &[PathScore],
) -> Option<PathUpgrade> {
    let best = scored_paths
        .iter()
        .min_by_key(|path| (path.relay, path.rtt.unwrap_or(Duration::from_millis(999))));
    best.map(|path| PathUpgrade {
        peer,
        preferred: path.addr,
        relay_fallback,
    })
}

fn locality_bonus(left: &Candidate, right: &Candidate) -> u32 {
    match (left.kind, right.kind) {
        (CandidateKind::HostLan, CandidateKind::HostLan) => 40,
        (CandidateKind::HostIpv6, CandidateKind::HostIpv6) => 30,
        (CandidateKind::ServerReflexive, CandidateKind::ServerReflexive) => 20,
        (CandidateKind::Relay, CandidateKind::Relay) => 0,
        _ => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2n_proto::{CandidateKind, CandidateSource};

    #[test]
    fn prefer_lan_pairs() {
        let local = vec![r2n_proto::Candidate {
            kind: CandidateKind::HostLan,
            source: CandidateSource::LocalInterface,
            addr: "10.0.0.2:4000".parse().expect("addr"),
            priority: 100,
            rtt_hint_ms: None,
        }];
        let remote = vec![r2n_proto::Candidate {
            kind: CandidateKind::HostLan,
            source: CandidateSource::LocalInterface,
            addr: "10.0.0.3:4001".parse().expect("addr"),
            priority: 100,
            rtt_hint_ms: None,
        }];

        let pairs = build_candidate_pairs(&local, &remote);
        assert_eq!(pairs.first().expect("pair").score, 240);
    }
}
