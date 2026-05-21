use r2n_common::{NodeId, RoomId, VirtualIp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub room_id: RoomId,
    pub name: String,
    pub owner: NodeId,
    pub virtual_cidr: String,
    pub join_token: String,
    pub members: HashMap<NodeId, Member>,
    #[serde(default)]
    pub ip_leases: HashMap<NodeId, VirtualIp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub node_id: NodeId,
    pub virtual_ip: VirtualIp,
    pub nickname: String,
    pub role: MemberRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberRole {
    Owner,
    Admin,
    Guest,
}

#[derive(Debug, Error)]
pub enum RoomError {
    #[error("invalid virtual CIDR: {0}")]
    InvalidCidr(String),
    #[error("room address pool is exhausted")]
    AddressPoolExhausted,
    #[error("invalid address pool: {0}")]
    InvalidAddressPool(String),
}

impl Room {
    pub fn new(
        room_id: RoomId,
        name: String,
        owner: NodeId,
        virtual_cidr: String,
        join_token: String,
    ) -> Self {
        Self {
            room_id,
            name,
            owner,
            virtual_cidr,
            join_token,
            members: HashMap::new(),
            ip_leases: HashMap::new(),
        }
    }

    pub fn add_member(&mut self, member: Member) {
        self.ip_leases.insert(member.node_id, member.virtual_ip);
        self.members.insert(member.node_id, member);
    }

    pub fn add_or_reuse_member(
        &mut self,
        node_id: NodeId,
        nickname: String,
        role: MemberRole,
    ) -> Result<VirtualIp, RoomError> {
        let virtual_ip = self.allocate_ip(node_id, role)?;
        self.add_member(Member {
            node_id,
            virtual_ip,
            nickname,
            role,
        });
        Ok(virtual_ip)
    }

    pub fn remove_member(&mut self, node_id: &NodeId) {
        self.members.remove(node_id);
    }

    fn allocate_ip(&mut self, node_id: NodeId, role: MemberRole) -> Result<VirtualIp, RoomError> {
        if let Some(ip) = self.ip_leases.get(&node_id).copied()
            && !self
                .members
                .values()
                .any(|member| member.node_id != node_id && member.virtual_ip == ip)
        {
            return Ok(ip);
        }

        let network: ipnet::Ipv4Net = self
            .virtual_cidr
            .parse()
            .map_err(|_| RoomError::InvalidCidr(self.virtual_cidr.clone()))?;
        let network_u32 = u32::from(network.network());
        let broadcast_u32 = u32::from(network.broadcast());
        let preferred_host = if role == MemberRole::Owner { 1 } else { 2 };
        let mut used: std::collections::HashSet<VirtualIp> = self
            .members
            .values()
            .map(|member| member.virtual_ip)
            .collect();
        used.extend(self.ip_leases.values().copied());

        for host in preferred_host.. {
            let candidate_u32 = network_u32.saturating_add(host);
            if candidate_u32 >= broadcast_u32 {
                break;
            }
            let candidate = VirtualIp(Ipv4Addr::from(candidate_u32).octets());
            if !used.contains(&candidate) {
                self.ip_leases.insert(node_id, candidate);
                return Ok(candidate);
            }
        }

        Err(RoomError::AddressPoolExhausted)
    }
}

#[derive(Debug, Clone)]
pub struct RoomAddressPool {
    pool: ipnet::Ipv4Net,
    room_prefix_len: u8,
    allocations: HashMap<RoomId, ipnet::Ipv4Net>,
}

impl RoomAddressPool {
    pub fn new(pool: &str, room_prefix_len: u8) -> Result<Self, RoomError> {
        let pool: ipnet::Ipv4Net = pool
            .parse()
            .map_err(|_| RoomError::InvalidAddressPool(pool.to_string()))?;
        if room_prefix_len < pool.prefix_len() || room_prefix_len > 30 {
            return Err(RoomError::InvalidAddressPool(format!(
                "{} with room prefix {}",
                pool, room_prefix_len
            )));
        }
        Ok(Self {
            pool,
            room_prefix_len,
            allocations: HashMap::new(),
        })
    }

    pub fn allocate(&mut self, room_id: RoomId) -> Result<ipnet::Ipv4Net, RoomError> {
        self.allocate_with_avoidance(room_id, &[])
    }

    pub fn allocate_with_avoidance(
        &mut self,
        room_id: RoomId,
        avoid: &[ipnet::Ipv4Net],
    ) -> Result<ipnet::Ipv4Net, RoomError> {
        if let Some(existing) = self.allocations.get(&room_id).copied() {
            return Ok(existing);
        }
        let pool_prefix = self.pool.prefix_len();
        let room_count = 1u32
            .checked_shl((self.room_prefix_len - pool_prefix) as u32)
            .unwrap_or(0);
        let subnet_size = 1u32
            .checked_shl((32 - self.room_prefix_len) as u32)
            .unwrap_or(0);
        let pool_base = u32::from(self.pool.network());
        for index in candidate_indices(self.pool, self.room_prefix_len, room_count) {
            let network = Ipv4Addr::from(pool_base + index * subnet_size);
            let candidate = ipnet::Ipv4Net::new(network, self.room_prefix_len)
                .map_err(|_| RoomError::InvalidAddressPool(self.pool.to_string()))?;
            if !self.allocations.values().any(|used| *used == candidate)
                && !avoid
                    .iter()
                    .any(|blocked| ipv4_nets_overlap(*blocked, candidate))
            {
                self.allocations.insert(room_id, candidate);
                return Ok(candidate);
            }
        }
        Err(RoomError::AddressPoolExhausted)
    }

    pub fn release(&mut self, room_id: &RoomId) {
        self.allocations.remove(room_id);
    }
}

impl Default for RoomAddressPool {
    fn default() -> Self {
        Self::new("192.168.0.0/16", 24).expect("default room address pool is valid")
    }
}

fn candidate_indices(pool: ipnet::Ipv4Net, room_prefix_len: u8, room_count: u32) -> Vec<u32> {
    if pool.network() == Ipv4Addr::new(192, 168, 0, 0)
        && pool.prefix_len() == 16
        && room_prefix_len == 24
        && room_count == 256
    {
        let mut preferred = Vec::with_capacity(256);
        preferred.extend(200..=255);
        preferred.extend(4..=30);
        preferred.extend(32..=199);
        preferred.extend([0, 1, 2, 3, 31]);
        preferred
    } else {
        (0..room_count).collect()
    }
}

fn ipv4_nets_overlap(a: ipnet::Ipv4Net, b: ipnet::Ipv4Net) -> bool {
    let a_start = u32::from(a.network());
    let a_end = u32::from(a.broadcast());
    let b_start = u32::from(b.network());
    let b_end = u32::from(b.broadcast());
    a_start <= b_end && b_start <= a_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_reuses_lease_after_member_leaves() {
        let mut room = Room::new(
            RoomId([1; 16]),
            "room".to_string(),
            NodeId([1; 32]),
            "192.168.7.0/24".to_string(),
            "token".to_string(),
        );
        let peer = NodeId([2; 32]);
        let ip = room
            .add_or_reuse_member(peer, "peer".to_string(), MemberRole::Guest)
            .unwrap();
        assert_eq!(ip, VirtualIp([192, 168, 7, 2]));
        room.remove_member(&peer);
        let reused = room
            .add_or_reuse_member(peer, "peer".to_string(), MemberRole::Guest)
            .unwrap();
        assert_eq!(reused, ip);
    }

    #[test]
    fn address_pool_allocates_distinct_room_subnets_and_releases() {
        let mut pool = RoomAddressPool::new("192.168.0.0/16", 24).unwrap();
        let a = RoomId([1; 16]);
        let b = RoomId([2; 16]);
        assert_eq!(pool.allocate(a).unwrap().to_string(), "192.168.200.0/24");
        assert_eq!(pool.allocate(b).unwrap().to_string(), "192.168.201.0/24");
        pool.release(&a);
        let c = RoomId([3; 16]);
        assert_eq!(pool.allocate(c).unwrap().to_string(), "192.168.200.0/24");
    }

    #[test]
    fn address_pool_avoids_conflicting_local_networks() {
        let mut pool = RoomAddressPool::new("192.168.0.0/16", 24).unwrap();
        let room_id = RoomId([9; 16]);
        let avoid = [
            "192.168.200.0/24".parse().unwrap(),
            "192.168.201.0/24".parse().unwrap(),
        ];
        assert_eq!(
            pool.allocate_with_avoidance(room_id, &avoid)
                .unwrap()
                .to_string(),
            "192.168.202.0/24"
        );
    }
}
