use etherparse::IpHeader;
use r2n_proto::DataPacketType;
use ratelimit::Ratelimiter;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_true")]
    pub broadcast: bool,
    #[serde(default = "default_true")]
    pub subnet_broadcast: bool,
    #[serde(default = "default_true")]
    pub multicast: bool,
    #[serde(default = "default_true")]
    pub mdns: bool,
    #[serde(default = "default_true")]
    pub ssdp: bool,
    #[serde(default)]
    pub netbios: bool,
    #[serde(default = "default_rate_limit_pps")]
    pub rate_limit_pps: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            broadcast: default_true(),
            subnet_broadcast: default_true(),
            multicast: default_true(),
            mdns: default_true(),
            ssdp: default_true(),
            netbios: false,
            rate_limit_pps: default_rate_limit_pps(),
        }
    }
}

pub struct DiscoveryManager {
    config: DiscoveryConfig,
    limiter: Arc<Mutex<Ratelimiter>>,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        Self::with_config(DiscoveryConfig::default())
    }

    pub fn with_config(config: DiscoveryConfig) -> Self {
        let rate_limit_pps = config.rate_limit_pps.max(1);
        let limiter = Ratelimiter::builder(rate_limit_pps as u64, Duration::from_secs(1))
            .max_tokens(rate_limit_pps as u64)
            .initial_available(rate_limit_pps as u64)
            .build()
            .unwrap();
        Self {
            config,
            limiter: Arc::new(Mutex::new(limiter)),
        }
    }

    /// Check if we should allow a broadcast packet based on rate limit
    pub async fn allow_broadcast(&self) -> bool {
        self.limiter.lock().await.try_wait().is_ok()
    }

    /// Classify an IP packet to determine if it's a discovery/broadcast packet
    pub fn classify_packet(data: &[u8]) -> Option<DataPacketType> {
        Self::classify_packet_with_config(data, &DiscoveryConfig::default())
    }

    pub fn classify_managed_packet(&self, data: &[u8]) -> Option<DataPacketType> {
        Self::classify_packet_with_config(data, &self.config)
    }

    pub fn route_cidrs(&self) -> Vec<&'static str> {
        let mut routes = Vec::with_capacity(2);
        if self.config.multicast || self.config.mdns || self.config.ssdp {
            routes.push("224.0.0.0/4");
        }
        if self.config.broadcast || self.config.netbios {
            routes.push("255.255.255.255/32");
        }
        routes
    }

    /// Classify an IP packet according to the configured virtual LAN discovery policy.
    pub fn classify_packet_with_config(
        data: &[u8],
        config: &DiscoveryConfig,
    ) -> Option<DataPacketType> {
        match IpHeader::from_slice(data) {
            Ok((IpHeader::Version4(ipv4, _), _, _)) => {
                let dest = ipv4.destination;
                let src = ipv4.source;
                let udp_dst_port = udp_destination_port(data);

                let is_limited_broadcast = dest == [255, 255, 255, 255];
                let is_subnet_broadcast = (dest[3] == 255 && dest[0..3] == src[0..3])
                    || (dest[2] == 255 && dest[3] == 255 && dest[0..2] == src[0..2]);

                if config.mdns && dest == [224, 0, 0, 251] && udp_dst_port == Some(5353) {
                    return Some(DataPacketType::Multicast);
                }
                if config.ssdp && dest == [239, 255, 255, 250] && udp_dst_port == Some(1900) {
                    return Some(DataPacketType::Multicast);
                }
                if config.netbios
                    && (is_limited_broadcast || is_subnet_broadcast)
                    && matches!(udp_dst_port, Some(137 | 138))
                {
                    return Some(DataPacketType::Broadcast);
                }
                // Standard limited broadcast
                if config.broadcast && is_limited_broadcast {
                    return Some(DataPacketType::Broadcast);
                }
                // Check for /24 subnet broadcast (e.g. 10.77.0.255)
                if config.subnet_broadcast && is_subnet_broadcast {
                    return Some(DataPacketType::Broadcast);
                }
                // IPv4 Multicast range
                if config.multicast && dest[0] >= 224 && dest[0] <= 239 {
                    return Some(DataPacketType::Multicast);
                }
                None
            }
            _ => None,
        }
    }
}

impl Default for DiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

fn default_true() -> bool {
    true
}

fn default_rate_limit_pps() -> u32 {
    100
}

fn udp_destination_port(data: &[u8]) -> Option<u16> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(data[0] & 0x0f) * 4;
    if header_len < 20 || data.len() < header_len + 4 || data[9] != 17 {
        return None;
    }
    Some(u16::from_be_bytes([
        data[header_len + 2],
        data[header_len + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mock_ipv4(src: [u8; 4], dest: [u8; 4], udp_dst_port: Option<u16>) -> Vec<u8> {
        let len = if udp_dst_port.is_some() { 28 } else { 20 };
        let mut pkt = vec![0u8; len];
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[2] = 0x00;
        pkt[3] = len as u8;
        pkt[8] = 64; // TTL
        pkt[9] = 17; // Protocol UDP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dest);
        if let Some(port) = udp_dst_port {
            pkt[22..24].copy_from_slice(&port.to_be_bytes());
        }
        pkt
    }

    #[test]
    fn test_classify_packet() {
        // Standard broadcast
        let pkt = make_mock_ipv4([10, 77, 0, 5], [255, 255, 255, 255], None);
        assert_eq!(
            DiscoveryManager::classify_packet(&pkt),
            Some(DataPacketType::Broadcast)
        );

        // Subnet broadcast /24
        let pkt = make_mock_ipv4([10, 77, 0, 5], [10, 77, 0, 255], None);
        assert_eq!(
            DiscoveryManager::classify_packet(&pkt),
            Some(DataPacketType::Broadcast)
        );

        // Subnet broadcast /16
        let pkt = make_mock_ipv4([10, 77, 0, 5], [10, 77, 255, 255], None);
        assert_eq!(
            DiscoveryManager::classify_packet(&pkt),
            Some(DataPacketType::Broadcast)
        );

        // Multicast
        let pkt = make_mock_ipv4([10, 77, 0, 5], [224, 0, 0, 251], None);
        assert_eq!(
            DiscoveryManager::classify_packet(&pkt),
            Some(DataPacketType::Multicast)
        );

        // Regular unicast
        let pkt = make_mock_ipv4([10, 77, 0, 5], [10, 77, 0, 6], None);
        assert_eq!(DiscoveryManager::classify_packet(&pkt), None);
    }

    #[test]
    fn test_specific_discovery_protocols_can_be_enabled_without_generic_multicast() {
        let config = DiscoveryConfig {
            multicast: false,
            ..DiscoveryConfig::default()
        };

        let mdns = make_mock_ipv4([10, 77, 0, 5], [224, 0, 0, 251], Some(5353));
        assert_eq!(
            DiscoveryManager::classify_packet_with_config(&mdns, &config),
            Some(DataPacketType::Multicast)
        );

        let ssdp = make_mock_ipv4([10, 77, 0, 5], [239, 255, 255, 250], Some(1900));
        assert_eq!(
            DiscoveryManager::classify_packet_with_config(&ssdp, &config),
            Some(DataPacketType::Multicast)
        );

        let unknown_multicast = make_mock_ipv4([10, 77, 0, 5], [239, 1, 2, 3], Some(9999));
        assert_eq!(
            DiscoveryManager::classify_packet_with_config(&unknown_multicast, &config),
            None
        );
    }

    #[test]
    fn test_netbios_can_be_enabled_without_generic_broadcast() {
        let config = DiscoveryConfig {
            broadcast: false,
            subnet_broadcast: false,
            netbios: true,
            ..DiscoveryConfig::default()
        };

        let netbios = make_mock_ipv4([10, 77, 0, 5], [255, 255, 255, 255], Some(137));
        assert_eq!(
            DiscoveryManager::classify_packet_with_config(&netbios, &config),
            Some(DataPacketType::Broadcast)
        );

        let other_broadcast = make_mock_ipv4([10, 77, 0, 5], [255, 255, 255, 255], Some(9999));
        assert_eq!(
            DiscoveryManager::classify_packet_with_config(&other_broadcast, &config),
            None
        );
    }
}
