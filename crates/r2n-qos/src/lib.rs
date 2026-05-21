use r2n_proto::DataPacketType;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Control,
    Realtime,
    Interactive,
    Bulk,
}

pub fn classify_packet(packet_type: DataPacketType, payload: &[u8]) -> TrafficClass {
    match packet_type {
        DataPacketType::Keepalive | DataPacketType::Ping | DataPacketType::Pong => {
            TrafficClass::Control
        }
        DataPacketType::Broadcast
        | DataPacketType::Multicast
        | DataPacketType::Discovery
        | DataPacketType::Ethernet => TrafficClass::Realtime,
        DataPacketType::IPv4 | DataPacketType::IPv6 => classify_ip_packet(payload),
    }
}

fn classify_ip_packet(payload: &[u8]) -> TrafficClass {
    match etherparse::IpHeader::from_slice(payload) {
        Ok((ip, _, remainder)) => {
            let protocol = match ip {
                etherparse::IpHeader::Version4(ipv4, _) => ipv4.protocol,
                etherparse::IpHeader::Version6(ipv6, _) => ipv6.next_header,
            };

            if protocol == 1 || protocol == 58 {
                return TrafficClass::Control;
            }
            if protocol == 17 && payload.len() <= 512 {
                return TrafficClass::Realtime;
            }
            if protocol == 6 {
                if remainder.len() >= 14 && remainder[13] & 0x02 != 0 {
                    return TrafficClass::Interactive;
                }
                return TrafficClass::Bulk;
            }
            TrafficClass::Interactive
        }
        Err(_) => TrafficClass::Realtime,
    }
}

pub struct QosScheduler<T> {
    control: VecDeque<T>,
    realtime: VecDeque<T>,
    interactive: VecDeque<T>,
    bulk: VecDeque<T>,
    bulk_capacity: usize,
}

impl<T> QosScheduler<T> {
    pub fn new(bulk_capacity: usize) -> Self {
        Self {
            control: VecDeque::new(),
            realtime: VecDeque::new(),
            interactive: VecDeque::new(),
            bulk: VecDeque::new(),
            bulk_capacity,
        }
    }

    pub fn push(&mut self, class: TrafficClass, item: T) {
        match class {
            TrafficClass::Control => self.control.push_back(item),
            TrafficClass::Realtime => self.realtime.push_back(item),
            TrafficClass::Interactive => self.interactive.push_back(item),
            TrafficClass::Bulk => {
                if self.bulk.len() >= self.bulk_capacity {
                    let _ = self.bulk.pop_front();
                }
                self.bulk.push_back(item);
            }
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        self.control
            .pop_front()
            .or_else(|| self.realtime.pop_front())
            .or_else(|| self.interactive.pop_front())
            .or_else(|| self.bulk.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_order_respects_classes() {
        let mut scheduler = QosScheduler::new(8);
        scheduler.push(TrafficClass::Bulk, 1);
        scheduler.push(TrafficClass::Realtime, 2);
        scheduler.push(TrafficClass::Control, 3);
        assert_eq!(scheduler.pop(), Some(3));
        assert_eq!(scheduler.pop(), Some(2));
        assert_eq!(scheduler.pop(), Some(1));
    }
}
