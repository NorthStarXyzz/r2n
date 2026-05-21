use anyhow::{Context, anyhow};
use default_net::{get_default_gateway, get_default_interface};
use igd_next::PortMappingProtocol as IgdPortMappingProtocol;
use igd_next::SearchOptions;
use natpmp::{Protocol as NatPmpProtocol, Response as NatPmpResponse, new_tokio_natpmp_with};
use r2n_proto::{Candidate, CandidateKind, CandidateSource};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;

const REQUESTED_LEASE_SECS: u32 = 3600;
const RETRY_INTERVAL: Duration = Duration::from_secs(60);
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortMappingProtocol {
    UpnpIgd,
    NatPmp,
    Pcp,
}

impl PortMappingProtocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::UpnpIgd => "UPnP IGD",
            Self::NatPmp => "NAT-PMP",
            Self::Pcp => "PCP",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortMappingSnapshot {
    pub acquired: bool,
    pub protocol: Option<PortMappingProtocol>,
    pub external_addr: Option<SocketAddr>,
    pub lease_remaining: Option<Duration>,
}

impl PortMappingSnapshot {
    pub fn as_candidate(&self) -> Option<Candidate> {
        if !self.acquired {
            return None;
        }

        Some(Candidate {
            kind: CandidateKind::ServerReflexive,
            source: CandidateSource::PortMapping,
            addr: self.external_addr?,
            priority: 90,
            rtt_hint_ms: None,
        })
    }

    pub fn view(&self) -> PortMappingSnapshotView {
        PortMappingSnapshotView {
            acquired: self.acquired,
            protocol: self.protocol.map(|protocol| protocol.label().to_string()),
            external_addr: self.external_addr.map(|addr| addr.to_string()),
            lease_remaining_secs: self.lease_remaining.map(|lease| lease.as_secs()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortMappingSnapshotView {
    pub acquired: bool,
    pub protocol: Option<String>,
    pub external_addr: Option<String>,
    pub lease_remaining_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct ActiveMapping {
    protocol: PortMappingProtocol,
    external_addr: SocketAddr,
    expires_at: Instant,
}

impl ActiveMapping {
    fn snapshot(&self) -> PortMappingSnapshot {
        PortMappingSnapshot {
            acquired: true,
            protocol: Some(self.protocol),
            external_addr: Some(self.external_addr),
            lease_remaining: Some(self.expires_at.saturating_duration_since(Instant::now())),
        }
    }

    fn renewal_delay(&self) -> Duration {
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        let half = remaining / 2;
        if half < MIN_RENEW_INTERVAL {
            MIN_RENEW_INTERVAL.min(remaining.max(Duration::from_secs(1)))
        } else {
            half
        }
    }
}

#[derive(Debug, Default)]
struct PortMappingState {
    active: Option<ActiveMapping>,
    first_refresh_done: bool,
}

pub struct PortMappingManager {
    local_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    local_port: NonZeroU16,
    state: Arc<RwLock<PortMappingState>>,
    updates_tx: watch::Sender<PortMappingSnapshot>,
}

impl PortMappingManager {
    pub fn discover(local_port: u16) -> anyhow::Result<Option<Arc<Self>>> {
        let local_port = NonZeroU16::new(local_port)
            .ok_or_else(|| anyhow!("local UDP port must not be zero"))?;
        let interface = match get_default_interface() {
            Ok(interface) => interface,
            Err(err) => {
                log::warn!(
                    "Default interface lookup failed, skipping port mapping: {}",
                    err
                );
                return Ok(None);
            }
        };
        let Some(local_ip) = interface
            .ipv4
            .iter()
            .find(|net| !net.addr.is_loopback())
            .map(|net| net.addr)
        else {
            log::warn!(
                "Default interface does not have a usable IPv4 address, skipping port mapping"
            );
            return Ok(None);
        };
        let gateway =
            get_default_gateway().map_err(|err| anyhow!("default gateway lookup failed: {}", err));
        let gateway = match gateway {
            Ok(gateway) => gateway.ip_addr,
            Err(err) => {
                log::warn!("{}, skipping port mapping", err);
                return Ok(None);
            }
        };
        let gateway = match gateway {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => {
                log::warn!("Default gateway is IPv6-only, skipping IPv4 port mapping");
                return Ok(None);
            }
        };

        let (updates_tx, _updates_rx) = watch::channel(PortMappingSnapshot::default());
        Ok(Some(Arc::new(Self {
            local_ip,
            gateway,
            local_port,
            state: Arc::new(RwLock::new(PortMappingState::default())),
            updates_tx,
        })))
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.local_ip, self.local_port.get())
    }

    pub fn subscribe(&self) -> watch::Receiver<PortMappingSnapshot> {
        self.updates_tx.subscribe()
    }

    pub fn snapshot(&self) -> PortMappingSnapshot {
        self.state
            .read()
            .expect("port mapping state lock")
            .active
            .as_ref()
            .map(ActiveMapping::snapshot)
            .unwrap_or_default()
    }

    pub async fn refresh(&self) -> PortMappingSnapshot {
        let (previous, first_refresh_done) = {
            let state = self.state.read().expect("port mapping state lock");
            (state.active.clone(), state.first_refresh_done)
        };
        let upnp_res =
            tokio::time::timeout(Duration::from_secs(3), self.try_upnp_igd(previous.as_ref()))
                .await;

        let next = match upnp_res {
            Ok(Ok(mapping)) => {
                log::info!(
                    "Port mapping acquired via {} at {}",
                    mapping.protocol.label(),
                    mapping.external_addr
                );
                Some(mapping)
            }
            other_upnp => {
                let upnp_err = match &other_upnp {
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => "UPnP search timed out".to_string(),
                    Ok(Ok(_)) => unreachable!(),
                };

                let nat_pmp_res = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.try_nat_pmp(previous.as_ref()),
                )
                .await;

                match nat_pmp_res {
                    Ok(Ok(mapping)) => {
                        log::info!(
                            "Port mapping acquired via {} at {}",
                            mapping.protocol.label(),
                            mapping.external_addr
                        );
                        Some(mapping)
                    }
                    other_nat => {
                        let nat_pmp_err = match &other_nat {
                            Ok(Err(e)) => e.to_string(),
                            Err(_) => "NAT-PMP timed out".to_string(),
                            Ok(Ok(_)) => unreachable!(),
                        };

                        let pcp_res = tokio::time::timeout(
                            Duration::from_secs(2),
                            self.try_pcp(previous.as_ref()),
                        )
                        .await;

                        match pcp_res {
                            Ok(Ok(mapping)) => {
                                log::info!(
                                    "Port mapping acquired via {} at {}",
                                    mapping.protocol.label(),
                                    mapping.external_addr
                                );
                                Some(mapping)
                            }
                            other_pcp => {
                                let pcp_err = match &other_pcp {
                                    Ok(Err(e)) => e.to_string(),
                                    Err(_) => "PCP timed out".to_string(),
                                    Ok(Ok(_)) => unreachable!(),
                                };
                                if !first_refresh_done || previous.is_some() {
                                    log::warn!(
                                        "Port mapping failed across all protocols: UPnP IGD: {}; NAT-PMP: {}; PCP: {}",
                                        upnp_err,
                                        nat_pmp_err,
                                        pcp_err
                                    );
                                } else {
                                    log::debug!(
                                        "Port mapping failed across all protocols: UPnP IGD: {}; NAT-PMP: {}; PCP: {}",
                                        upnp_err,
                                        nat_pmp_err,
                                        pcp_err
                                    );
                                }
                                previous.filter(|mapping| mapping.expires_at > Instant::now())
                            }
                        }
                    }
                }
            }
        };

        {
            let mut state = self.state.write().expect("port mapping state lock");
            state.active = next;
            state.first_refresh_done = true;
        }
        self.publish_snapshot()
    }

    pub fn start(self: &Arc<Self>) {
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                let wait_for = manager
                    .state
                    .read()
                    .expect("port mapping state lock")
                    .active
                    .as_ref()
                    .map(ActiveMapping::renewal_delay)
                    .unwrap_or(RETRY_INTERVAL);
                tokio::time::sleep(wait_for).await;
                let _ = manager.refresh().await;
            }
        });
    }

    fn publish_snapshot(&self) -> PortMappingSnapshot {
        let snapshot = self.snapshot();
        let _ = self.updates_tx.send(snapshot.clone());
        snapshot
    }

    async fn try_upnp_igd(
        &self,
        previous: Option<&ActiveMapping>,
    ) -> anyhow::Result<ActiveMapping> {
        let options = SearchOptions {
            timeout: Some(Duration::from_secs(3)),
            single_search_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        let gateway = igd_next::aio::tokio::search_gateway(options)
            .await
            .context("gateway discovery failed")?;
        let external_ip = gateway
            .get_external_ip()
            .await
            .context("external address query failed")?;
        let external_ip = match external_ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => anyhow::bail!("gateway returned an IPv6 external address"),
        };
        let local_addr = SocketAddr::V4(self.local_addr());
        let preferred_port = previous
            .filter(|mapping| mapping.protocol == PortMappingProtocol::UpnpIgd)
            .map(|mapping| mapping.external_addr.port())
            .unwrap_or(self.local_port.get());
        let external_port = match gateway
            .add_port(
                IgdPortMappingProtocol::UDP,
                preferred_port,
                local_addr,
                REQUESTED_LEASE_SECS,
                "R2N UDP",
            )
            .await
        {
            Ok(()) => preferred_port,
            Err(_) => gateway
                .add_any_port(
                    IgdPortMappingProtocol::UDP,
                    local_addr,
                    REQUESTED_LEASE_SECS,
                    "R2N UDP",
                )
                .await
                .context("port mapping request failed")?,
        };

        Ok(ActiveMapping {
            protocol: PortMappingProtocol::UpnpIgd,
            external_addr: SocketAddr::V4(SocketAddrV4::new(external_ip, external_port)),
            expires_at: Instant::now() + Duration::from_secs(REQUESTED_LEASE_SECS.into()),
        })
    }

    async fn try_nat_pmp(&self, previous: Option<&ActiveMapping>) -> anyhow::Result<ActiveMapping> {
        let mut client = new_tokio_natpmp_with(self.gateway).await?;
        client.send_public_address_request().await?;
        let external_ip = match client.read_response_or_retry().await? {
            NatPmpResponse::Gateway(response) => *response.public_address(),
            other => anyhow::bail!(
                "unexpected NAT-PMP response for public address: {:?}",
                other
            ),
        };

        let requested_public_port = previous
            .filter(|mapping| mapping.protocol == PortMappingProtocol::NatPmp)
            .map(|mapping| mapping.external_addr.port())
            .unwrap_or(self.local_port.get());

        client
            .send_port_mapping_request(
                NatPmpProtocol::UDP,
                self.local_port.get(),
                requested_public_port,
                REQUESTED_LEASE_SECS,
            )
            .await?;
        let mapping = match client.read_response_or_retry().await? {
            NatPmpResponse::UDP(response) => response,
            other => anyhow::bail!("unexpected NAT-PMP mapping response: {:?}", other),
        };

        Ok(ActiveMapping {
            protocol: PortMappingProtocol::NatPmp,
            external_addr: SocketAddr::V4(SocketAddrV4::new(external_ip, mapping.public_port())),
            expires_at: Instant::now() + *mapping.lifetime(),
        })
    }

    async fn try_pcp(&self, previous: Option<&ActiveMapping>) -> anyhow::Result<ActiveMapping> {
        if !pcp_client::probe_available(self.local_ip, self.gateway).await {
            anyhow::bail!("gateway did not answer PCP announce probe");
        }

        let preferred = previous
            .filter(|mapping| mapping.protocol == PortMappingProtocol::Pcp)
            .and_then(|mapping| match mapping.external_addr {
                SocketAddr::V4(addr) => Some((*addr.ip(), NonZeroU16::new(addr.port())?)),
                SocketAddr::V6(_) => None,
            });

        let mapping =
            pcp_client::Mapping::new(self.local_ip, self.local_port, self.gateway, preferred)
                .await?;

        Ok(ActiveMapping {
            protocol: PortMappingProtocol::Pcp,
            external_addr: SocketAddr::V4(SocketAddrV4::new(
                mapping.external_address,
                mapping.external_port.get(),
            )),
            expires_at: Instant::now() + Duration::from_secs(mapping.lifetime_seconds.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_view_exposes_expected_fields() {
        let snapshot = PortMappingSnapshot {
            acquired: true,
            protocol: Some(PortMappingProtocol::NatPmp),
            external_addr: Some(SocketAddr::from(([203, 0, 113, 10], 45678))),
            lease_remaining: Some(Duration::from_secs(321)),
        };

        let view = snapshot.view();
        assert!(view.acquired);
        assert_eq!(view.protocol.as_deref(), Some("NAT-PMP"));
        assert_eq!(view.external_addr.as_deref(), Some("203.0.113.10:45678"));
        assert_eq!(view.lease_remaining_secs, Some(321));
    }
}
