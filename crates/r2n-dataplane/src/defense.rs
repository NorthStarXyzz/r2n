pub fn clamp_mss(packet: &mut [u8], safe_payload_mtu: usize) -> bool {
    let mut clamped = false;
    let packet_len = packet.len();

    // Check if it's an IPv4 packet
    if packet_len < 40 {
        return false;
    }

    let ip_ver = packet[0] >> 4;
    if ip_ver == 4 {
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        if packet_len < ihl + 20 {
            return false;
        }

        let protocol = packet[9];
        if protocol == 6 {
            // TCP
            let tcp_start = ihl;
            let tcp_len = packet_len - tcp_start;
            if tcp_len < 20 {
                return false;
            }

            let data_offset = ((packet[tcp_start + 12] >> 4) as usize) * 4;
            if data_offset > 20 {
                let syn_flag = (packet[tcp_start + 13] & 0x02) != 0;
                if syn_flag {
                    let mut i = 20;
                    while i < data_offset && i + 1 < tcp_len {
                        let kind = packet[tcp_start + i];
                        if kind == 0 {
                            break; // EOL
                        } else if kind == 1 {
                            i += 1; // NOP
                        } else {
                            let opt_len = packet[tcp_start + i + 1] as usize;
                            if opt_len < 2 || i + opt_len > data_offset {
                                break;
                            }
                            if kind == 2 && opt_len == 4 {
                                // MSS
                                let mss = u16::from_be_bytes([
                                    packet[tcp_start + i + 2],
                                    packet[tcp_start + i + 3],
                                ]);

                                let max_mss = (safe_payload_mtu.saturating_sub(ihl + 20)) as u16;
                                if mss > max_mss {
                                    packet[tcp_start + i + 2..tcp_start + i + 4]
                                        .copy_from_slice(&max_mss.to_be_bytes());
                                    clamped = true;
                                }
                            }
                            i += opt_len;
                        }
                    }
                }
            }

            if clamped {
                let (ipv4_hdr, tcp_segment) = packet.split_at_mut(ihl);
                recompute_tcp_checksum(ipv4_hdr, tcp_segment);
            }
        }
    }

    clamped
}

fn recompute_tcp_checksum(ipv4_hdr: &[u8], tcp_segment: &mut [u8]) {
    tcp_segment[16] = 0;
    tcp_segment[17] = 0;

    let mut sum = 0u32;
    let src_ip = &ipv4_hdr[12..16];
    let dst_ip = &ipv4_hdr[16..20];

    sum += u32::from(u16::from_be_bytes([src_ip[0], src_ip[1]]));
    sum += u32::from(u16::from_be_bytes([src_ip[2], src_ip[3]]));
    sum += u32::from(u16::from_be_bytes([dst_ip[0], dst_ip[1]]));
    sum += u32::from(u16::from_be_bytes([dst_ip[2], dst_ip[3]]));
    sum += 6u32;
    sum += tcp_segment.len() as u32;

    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += u32::from(u16::from_be_bytes([tcp_segment[i], 0]));
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    tcp_segment[16..18].copy_from_slice(&checksum.to_be_bytes());
}

pub fn build_icmp_frag_needed(original_ipv4: &[u8], next_hop_mtu: u16) -> Option<Vec<u8>> {
    let orig_ihl = ((original_ipv4[0] & 0x0F) as usize) * 4;
    let icmp_data_len = orig_ihl + 8;
    if original_ipv4.len() < icmp_data_len {
        return None;
    }

    let total_len = 20 + 8 + icmp_data_len;
    let mut pkt = vec![0u8; total_len];

    let src_ip = &original_ipv4[12..16];
    let dst_ip = &original_ipv4[16..20];

    let ip_hdr = &mut pkt[0..20];
    ip_hdr[0] = 0x45;
    ip_hdr[1] = 0;
    ip_hdr[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip_hdr[6..8].copy_from_slice(&0u16.to_be_bytes());
    ip_hdr[8] = 64;
    ip_hdr[9] = 1;
    // Swap src and dst for reply
    ip_hdr[12..16].copy_from_slice(dst_ip);
    ip_hdr[16..20].copy_from_slice(src_ip);

    let ip_cksum = ip_checksum(ip_hdr);
    ip_hdr[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let icmp_hdr = &mut pkt[20..28];
    icmp_hdr[0] = 3;
    icmp_hdr[1] = 4;
    icmp_hdr[6..8].copy_from_slice(&next_hop_mtu.to_be_bytes());

    pkt[28..28 + icmp_data_len].copy_from_slice(&original_ipv4[0..icmp_data_len]);

    let icmp_cksum = ip_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

    Some(pkt)
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to compute IPv4 header checksum
    fn calculate_ipv4_checksum(hdr: &mut [u8]) {
        hdr[10] = 0;
        hdr[11] = 0;
        let cksum = ip_checksum(hdr);
        hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    #[test]
    fn test_clamp_mss_ipv4_tcp_syn() {
        // Construct a valid IPv4 TCP SYN packet with an MSS option (1460)
        // IPv4 Header (20 bytes) + TCP Header with Options (24 bytes) = 44 bytes
        let mut pkt = vec![0u8; 44];

        // IPv4 Header
        pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes()); // Total Length
        pkt[9] = 6; // TCP Protocol
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // Source IP
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // Dest IP
        calculate_ipv4_checksum(&mut pkt[0..20]);

        {
            let (ip, tcp) = pkt.split_at_mut(20);
            tcp[12] = 0x60; // Data Offset = 6 (24 bytes)
            tcp[13] = 0x02; // SYN Flag

            // TCP Options: Kind=2 (MSS), Length=4, Value=1460 (0x05B4)
            tcp[20] = 2;
            tcp[21] = 4;
            tcp[22..24].copy_from_slice(&1460u16.to_be_bytes());

            // Recalculate original TCP checksum
            recompute_tcp_checksum(ip, tcp);
        }

        // Clamp MSS to 1280 (minimum effective MTU) -> max MSS = 1280 - 40 = 1240
        let clamped = clamp_mss(&mut pkt, 1280);
        assert!(clamped);

        // Verify MSS is clamped to 1240
        let clamped_mss = u16::from_be_bytes([pkt[42], pkt[43]]);
        assert_eq!(clamped_mss, 1240);

        // Verify TCP checksum matches recomputed checksum
        let original_cksum = u16::from_be_bytes([pkt[36], pkt[37]]);
        {
            let (ip, tcp) = pkt.split_at_mut(20);
            recompute_tcp_checksum(ip, tcp);
        }
        let recomputed_cksum = u16::from_be_bytes([pkt[36], pkt[37]]);
        assert_eq!(original_cksum, recomputed_cksum);
    }

    #[test]
    fn test_clamp_mss_ipv4_tcp_syn_smaller() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        calculate_ipv4_checksum(&mut pkt[0..20]);

        {
            let (ip, tcp) = pkt.split_at_mut(20);
            tcp[12] = 0x60;
            tcp[13] = 0x02;
            tcp[20] = 2;
            tcp[21] = 4;
            tcp[22..24].copy_from_slice(&1000u16.to_be_bytes()); // Already smaller than 1240
            recompute_tcp_checksum(ip, tcp);
        }

        let clamped = clamp_mss(&mut pkt, 1280);
        assert!(!clamped);

        let current_mss = u16::from_be_bytes([pkt[42], pkt[43]]);
        assert_eq!(current_mss, 1000);
    }

    #[test]
    fn test_clamp_mss_non_syn() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&44u16.to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        calculate_ipv4_checksum(&mut pkt[0..20]);

        {
            let (ip, tcp) = pkt.split_at_mut(20);
            tcp[12] = 0x60;
            tcp[13] = 0x10; // ACK flag only (no SYN)
            tcp[20] = 2;
            tcp[21] = 4;
            tcp[22..24].copy_from_slice(&1460u16.to_be_bytes());
            recompute_tcp_checksum(ip, tcp);
        }

        let clamped = clamp_mss(&mut pkt, 1280);
        assert!(!clamped);
    }

    #[test]
    fn test_build_icmp_frag_needed() {
        // Construct original IPv4 packet with DF set
        let mut original = vec![0u8; 100];
        original[0] = 0x45;
        original[2..4].copy_from_slice(&100u16.to_be_bytes());
        original[6] = 0x40; // Don't Fragment flag (0x4000)
        original[9] = 17; // UDP Protocol
        original[12..16].copy_from_slice(&[10, 0, 0, 1]); // Source IP
        original[16..20].copy_from_slice(&[10, 0, 0, 2]); // Dest IP
        calculate_ipv4_checksum(&mut original[0..20]);
        // Dummy payload
        original[20..28].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let next_hop_mtu = 1280u16;
        let icmp_opt = build_icmp_frag_needed(&original, next_hop_mtu);
        assert!(icmp_opt.is_some());
        let icmp_pkt = icmp_opt.unwrap();

        // ICMP packet total length: 20 (IP) + 8 (ICMP Header) + 28 (original IP + 8 payload bytes) = 56 bytes
        assert_eq!(icmp_pkt.len(), 56);

        // Verify Outer IP header of ICMP response
        assert_eq!(icmp_pkt[0], 0x45);
        assert_eq!(icmp_pkt[9], 1); // Protocol = 1 (ICMP)
        assert_eq!(&icmp_pkt[12..16], &[10, 0, 0, 2]); // Source IP is now original Dest
        assert_eq!(&icmp_pkt[16..20], &[10, 0, 0, 1]); // Dest IP is now original Source

        // Verify ICMP Header fields
        assert_eq!(icmp_pkt[20], 3); // Type = 3 (Destination Unreachable)
        assert_eq!(icmp_pkt[21], 4); // Code = 4 (Fragmentation Needed and DF set)

        // Verify Next-Hop MTU is correct
        let mtu = u16::from_be_bytes([icmp_pkt[26], icmp_pkt[27]]);
        assert_eq!(mtu, next_hop_mtu);

        // Verify original IP header is nested starting at offset 28
        assert_eq!(icmp_pkt[28], 0x45);
        assert_eq!(&icmp_pkt[40..44], &[10, 0, 0, 1]); // Nested original source IP
    }
}
