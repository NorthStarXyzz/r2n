use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

impl TrafficDirection {
    pub fn matches(self, actual: TrafficDirection) -> bool {
        self == TrafficDirection::Both || self == actual
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficRule {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub action: TrafficAction,
    pub direction: TrafficDirection,
    #[serde(default)]
    pub src_cidr: Option<IpNet>,
    #[serde(default)]
    pub dst_cidr: Option<IpNet>,
    #[serde(default = "default_protocol")]
    pub protocol: TrafficProtocol,
    #[serde(default)]
    pub src_ports: Vec<PortRange>,
    #[serde(default)]
    pub dst_ports: Vec<PortRange>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficPolicy {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub default_action: TrafficAction,
    #[serde(default)]
    pub rules: Vec<TrafficRule>,
}

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: TrafficAction::Allow,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: TrafficProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("unsupported or malformed packet")]
    UnsupportedPacket,
}

impl TrafficPolicy {
    pub fn decision(&self, direction: TrafficDirection, packet: &[u8]) -> TrafficAction {
        if !self.enabled {
            return TrafficAction::Allow;
        }
        let Ok(meta) = packet_meta(packet) else {
            return self.default_action;
        };
        self.decision_for_meta(direction, &meta)
    }

    pub fn decision_for_meta(
        &self,
        direction: TrafficDirection,
        meta: &PacketMeta,
    ) -> TrafficAction {
        if !self.enabled {
            return TrafficAction::Allow;
        }
        self.rules
            .iter()
            .find(|rule| rule.matches(direction, meta))
            .map(|rule| rule.action)
            .unwrap_or(self.default_action)
    }

    pub fn allows(&self, direction: TrafficDirection, packet: &[u8]) -> bool {
        self.decision(direction, packet) == TrafficAction::Allow
    }
}

impl TrafficRule {
    pub fn matches(&self, direction: TrafficDirection, meta: &PacketMeta) -> bool {
        if !self.enabled || !self.direction.matches(direction) {
            return false;
        }
        if self.protocol != TrafficProtocol::Any && self.protocol != meta.protocol {
            return false;
        }
        if let Some(cidr) = self.src_cidr
            && !cidr.contains(&meta.src)
        {
            return false;
        }
        if let Some(cidr) = self.dst_cidr
            && !cidr.contains(&meta.dst)
        {
            return false;
        }
        if !self.src_ports.is_empty() {
            let Some(port) = meta.src_port else {
                return false;
            };
            if !self.src_ports.iter().any(|range| range.contains(port)) {
                return false;
            }
        }
        if !self.dst_ports.is_empty() {
            let Some(port) = meta.dst_port else {
                return false;
            };
            if !self.dst_ports.iter().any(|range| range.contains(port)) {
                return false;
            }
        }
        true
    }
}

pub fn packet_meta(packet: &[u8]) -> Result<PacketMeta, PolicyError> {
    let sliced =
        etherparse::SlicedPacket::from_ip(packet).map_err(|_| PolicyError::UnsupportedPacket)?;
    match sliced.ip {
        Some(etherparse::InternetSlice::Ipv4(header, _)) => {
            let src = IpAddr::V4(header.source_addr());
            let dst = IpAddr::V4(header.destination_addr());
            let (protocol, src_port, dst_port) = transport_meta(sliced.transport);
            Ok(PacketMeta {
                src,
                dst,
                protocol,
                src_port,
                dst_port,
            })
        }
        Some(etherparse::InternetSlice::Ipv6(header, _)) => {
            let src = IpAddr::V6(header.source_addr());
            let dst = IpAddr::V6(header.destination_addr());
            let (protocol, src_port, dst_port) = transport_meta(sliced.transport);
            Ok(PacketMeta {
                src,
                dst,
                protocol,
                src_port,
                dst_port,
            })
        }
        None => Err(PolicyError::UnsupportedPacket),
    }
}

fn transport_meta(
    transport: Option<etherparse::TransportSlice<'_>>,
) -> (TrafficProtocol, Option<u16>, Option<u16>) {
    match transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => (
            TrafficProtocol::Tcp,
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
        ),
        Some(etherparse::TransportSlice::Udp(udp)) => (
            TrafficProtocol::Udp,
            Some(udp.source_port()),
            Some(udp.destination_port()),
        ),
        Some(etherparse::TransportSlice::Icmpv4(_))
        | Some(etherparse::TransportSlice::Icmpv6(_)) => (TrafficProtocol::Icmp, None, None),
        _ => (TrafficProtocol::Any, None, None),
    }
}

fn default_enabled() -> bool {
    true
}

fn default_protocol() -> TrafficProtocol {
    TrafficProtocol::Any
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let payload = b"policy";
        let mut ipv4 = etherparse::Ipv4Header::new(
            (8 + payload.len()) as u16,
            64,
            etherparse::ip_number::UDP,
            src,
            dst,
        );
        ipv4.header_checksum = ipv4.calc_header_checksum().unwrap();
        let mut udp =
            etherparse::UdpHeader::without_ipv4_checksum(src_port, dst_port, payload.len())
                .unwrap();
        udp.checksum = udp.calc_checksum_ipv4(&ipv4, payload).unwrap();

        let mut bytes = Vec::new();
        ipv4.write_raw(&mut bytes).unwrap();
        bytes.extend_from_slice(&udp.to_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn default_policy_allows() {
        let policy = TrafficPolicy::default();
        let packet = udp_packet([10, 66, 1, 2], [10, 66, 1, 3], 4000, 5000);
        assert!(policy.allows(TrafficDirection::Outbound, &packet));
    }

    #[test]
    fn deny_rule_matches_cidr_protocol_and_port() {
        let policy = TrafficPolicy {
            rules: vec![TrafficRule {
                id: "deny-discovery-port".to_string(),
                enabled: true,
                action: TrafficAction::Deny,
                direction: TrafficDirection::Outbound,
                src_cidr: Some("10.66.0.0/16".parse().unwrap()),
                dst_cidr: Some("10.66.1.0/24".parse().unwrap()),
                protocol: TrafficProtocol::Udp,
                src_ports: Vec::new(),
                dst_ports: vec![PortRange {
                    start: 5000,
                    end: 5001,
                }],
                description: None,
            }],
            ..TrafficPolicy::default()
        };
        let packet = udp_packet([10, 66, 1, 2], [10, 66, 1, 3], 4000, 5000);
        assert_eq!(
            policy.decision(TrafficDirection::Outbound, &packet),
            TrafficAction::Deny
        );
    }

    #[test]
    fn disabled_policy_ignores_deny_rules() {
        let mut policy = TrafficPolicy {
            rules: vec![TrafficRule {
                id: "deny-all".to_string(),
                enabled: true,
                action: TrafficAction::Deny,
                direction: TrafficDirection::Both,
                src_cidr: None,
                dst_cidr: None,
                protocol: TrafficProtocol::Any,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                description: None,
            }],
            ..TrafficPolicy::default()
        };
        policy.enabled = false;
        let packet = udp_packet([10, 66, 1, 2], [10, 66, 1, 3], 4000, 5000);
        assert!(policy.allows(TrafficDirection::Inbound, &packet));
    }
}
