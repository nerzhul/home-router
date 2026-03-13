use std::net::Ipv4Addr;

/// Returns true if two subnets overlap (one contains or is contained by the other).
pub fn subnets_overlap(
    net_a: Ipv4Addr,
    prefix_a: u8,
    net_b: Ipv4Addr,
    prefix_b: u8,
) -> bool {
    let mask_a = if prefix_a == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_a)
    };
    let mask_b = if prefix_b == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_b)
    };
    let start_a = u32::from(net_a) & mask_a;
    let end_a = start_a | !mask_a;
    let start_b = u32::from(net_b) & mask_b;
    let end_b = start_b | !mask_b;
    start_a <= end_b && start_b <= end_a
}

/// Returns the Ethernet MAC address of `iface`, or `None` on failure.
///
/// * Linux   – `ioctl(SIOCGIFHWADDR)`
/// * FreeBSD – `getifaddrs(3)` scanning for an `AF_LINK` entry
#[cfg(target_os = "linux")]
pub fn get_iface_mac(iface: &str) -> Option<[u8; 6]> {
    let iface_cstr = std::ffi::CString::new(iface).ok()?;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return None;
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = iface_cstr.as_bytes_with_nul();
    let copy_len = name.len().min(libc::IFNAMSIZ);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            copy_len,
        );
    }
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR, &ifr) };
    unsafe { libc::close(sock) };
    if ret != 0 {
        return None;
    }
    let d = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Some([d[0] as u8, d[1] as u8, d[2] as u8, d[3] as u8, d[4] as u8, d[5] as u8])
}

#[cfg(target_os = "freebsd")]
pub fn get_iface_mac(iface: &str) -> Option<[u8; 6]> {
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return None;
        }
        let mut result = None;
        let mut cur = ifaddrs;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family as i32 == libc::AF_LINK as i32
            {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                if name == iface {
                    let sdl = ifa.ifa_addr as *const libc::sockaddr_dl;
                    let nlen = (*sdl).sdl_nlen as usize;
                    let alen = (*sdl).sdl_alen as usize;
                    if alen >= 6 {
                        // sdl_data layout: [name (sdl_nlen)] [mac (sdl_alen)] ...
                        let mac_ptr = (*sdl).sdl_data.as_ptr().add(nlen) as *const u8;
                        result = Some([
                            *mac_ptr,
                            *mac_ptr.add(1),
                            *mac_ptr.add(2),
                            *mac_ptr.add(3),
                            *mac_ptr.add(4),
                            *mac_ptr.add(5),
                        ]);
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
        result
    }
}

/// Standard one's-complement IP header checksum.
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a raw Ethernet frame containing an IPv4/UDP datagram.
///
/// The caller supplies pre-computed MAC addresses, IP endpoints and the UDP
/// payload.  The IP and UDP headers are filled in here; the UDP checksum is
/// left as zero (legal for IPv4, RFC 768).
pub fn build_l2_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    const ETH_P_IP: u16 = 0x0800;
    let udp_len = 8u16 + payload.len() as u16;
    let ip_total_len = 20u16 + udp_len;

    let mut frame = Vec::with_capacity(14 + ip_total_len as usize);

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETH_P_IP.to_be_bytes());

    // IPv4 header (20 bytes)
    let ip_start = frame.len();
    frame.push(0x45);                                    // version=4, IHL=5
    frame.push(0x00);                                    // DSCP/ECN
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());        // identification
    frame.extend_from_slice(&0x4000u16.to_be_bytes());   // DF, no fragment
    frame.push(128);                                     // TTL
    frame.push(17);                                      // protocol: UDP
    frame.extend_from_slice(&0u16.to_be_bytes());        // checksum placeholder
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());

    let cksum = ip_checksum(&frame[ip_start..ip_start + 20]).to_be_bytes();
    frame[ip_start + 10] = cksum[0];
    frame[ip_start + 11] = cksum[1];

    // UDP header (8 bytes)
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum = 0 (optional, IPv4)

    frame.extend_from_slice(payload);
    frame
}

/// Returns the interface index for `iface`, or `None` on failure.
///
/// Wraps `if_nametoindex(3)` which is available on both Linux and FreeBSD.
pub fn get_ifindex(iface: &str) -> Option<u32> {
    let cstr = std::ffi::CString::new(iface).ok()?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Returns the first link-local (`fe80::/10`) IPv6 address of `iface`.
///
/// Uses `getifaddrs(3)` which is portable across Linux and FreeBSD.
pub fn get_link_local_addr(iface: &str) -> Option<std::net::Ipv6Addr> {
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return None;
        }
        let mut result = None;
        let mut cur = ifaddrs;
        while !cur.is_null() {
            let ifa = &*cur;
            if ifa.ifa_addr.is_null() {
                cur = ifa.ifa_next;
                continue;
            }
            let family = (*ifa.ifa_addr).sa_family as i32;
            if family == libc::AF_INET6 {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
                if name == iface {
                    let sin6 = ifa.ifa_addr as *const libc::sockaddr_in6;
                    let addr_bytes = (*sin6).sin6_addr.s6_addr;
                    // fe80::/10 → first byte 0xfe, second byte high two bits = 10 (0x80)
                    if addr_bytes[0] == 0xfe && (addr_bytes[1] & 0xc0) == 0x80 {
                        result = Some(std::net::Ipv6Addr::from(addr_bytes));
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn test_identical_subnets_overlap() {
        assert!(subnets_overlap(ip("192.168.1.0"), 24, ip("192.168.1.0"), 24));
    }

    #[test]
    fn test_disjoint_subnets_no_overlap() {
        assert!(!subnets_overlap(ip("192.168.1.0"), 24, ip("192.168.2.0"), 24));
    }

    #[test]
    fn test_adjacent_subnets_no_overlap() {
        // 192.168.0.0/24 ends at .255, 192.168.1.0/24 starts at .1.0 — no overlap
        assert!(!subnets_overlap(ip("192.168.0.0"), 24, ip("192.168.1.0"), 24));
    }

    #[test]
    fn test_subnet_contained_in_larger() {
        // 192.168.1.0/24 is fully inside 192.168.0.0/16
        assert!(subnets_overlap(ip("192.168.1.0"), 24, ip("192.168.0.0"), 16));
    }

    #[test]
    fn test_larger_contains_smaller() {
        // 192.168.0.0/16 encompasses 192.168.1.0/24
        assert!(subnets_overlap(ip("192.168.0.0"), 16, ip("192.168.1.0"), 24));
    }

    #[test]
    fn test_partial_overlap() {
        // 10.0.0.0/8 and 10.128.0.0/9 overlap (10.128–255 is inside 10.0.0.0/8)
        assert!(subnets_overlap(ip("10.0.0.0"), 8, ip("10.128.0.0"), 9));
    }

    #[test]
    fn test_completely_different_ranges_no_overlap() {
        assert!(!subnets_overlap(ip("10.0.0.0"), 8, ip("172.16.0.0"), 12));
    }

    #[test]
    fn test_prefix_zero_matches_everything() {
        // /0 covers all addresses and overlaps with anything
        assert!(subnets_overlap(ip("0.0.0.0"), 0, ip("192.168.1.0"), 24));
        assert!(subnets_overlap(ip("192.168.1.0"), 24, ip("0.0.0.0"), 0));
    }

    #[test]
    fn test_prefix_32_single_host() {
        // /32 overlaps only with ranges that contain that exact address
        assert!(subnets_overlap(ip("192.168.1.1"), 32, ip("192.168.1.0"), 24));
        assert!(!subnets_overlap(ip("192.168.1.1"), 32, ip("192.168.2.0"), 24));
    }

    // --- ip_checksum tests ---

    #[test]
    fn test_ip_checksum_all_zeros() {
        // All-zero 20-byte header: sum of all 16-bit words = 0, complement = 0xffff
        let data = [0u8; 20];
        assert_eq!(ip_checksum(&data), 0xffff);
    }

    #[test]
    fn test_ip_checksum_known_header() {
        // A known IPv4 header with checksum field zeroed; the result must validate.
        // Header: version=4, IHL=5, TOS=0, total_len=40, id=0, flags/frag=0x4000,
        //         TTL=64, proto=17 (UDP), src=192.168.1.1, dst=192.168.1.2
        let mut hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x28, // version/IHL, DSCP, total length = 40
            0x00, 0x00, 0x40, 0x00, // id=0, DF set
            0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP, checksum placeholder
            192, 168, 1, 1,          // src
            192, 168, 1, 2,          // dst
        ];
        let cksum = ip_checksum(&hdr);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = cksum as u8;
        // Re-computing over the completed header must yield 0x0000 (valid in one's complement)
        assert_eq!(ip_checksum(&hdr), 0x0000);
    }

    #[test]
    fn test_ip_checksum_odd_length() {
        // Odd-length input: last byte is left-padded to a 16-bit word.
        // [0x01, 0x00] = 0x0100 sum, complement = 0xfeff
        assert_eq!(ip_checksum(&[0x01]), 0xfeff);
    }

    // --- build_l2_udp_frame tests ---

    #[test]
    fn test_build_l2_udp_frame_length() {
        use std::net::Ipv4Addr;
        let payload = b"hello";
        let frame = build_l2_udp_frame(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xff; 6],
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            67,
            68,
            payload,
        );
        // 14 (eth) + 20 (ip) + 8 (udp) + 5 (payload) = 47
        assert_eq!(frame.len(), 47);
        // verify checksum is correct
        let ip = &frame[14..34];
        let cksum = u16::from_be_bytes([ip[10], ip[11]]);
        assert_ne!(cksum, 0);
        assert_eq!(ip_checksum(ip), 0x0000);
    }

    #[test]
    fn test_build_l2_udp_frame_ethernet_header() {
        use std::net::Ipv4Addr;
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let dst_mac = [0xFF; 6];
        let frame = build_l2_udp_frame(
            src_mac,
            dst_mac,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1234,
            5678,
            &[],
        );
        // Ethernet dst is first 6 bytes
        assert_eq!(&frame[0..6], &dst_mac);
        // Ethernet src is next 6 bytes
        assert_eq!(&frame[6..12], &src_mac);
        // EtherType = 0x0800
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn test_build_l2_udp_frame_ip_header() {
        use std::net::Ipv4Addr;
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 255);
        let frame = build_l2_udp_frame(
            [0; 6],
            [0xFF; 6],
            src_ip,
            dst_ip,
            67,
            68,
            b"test",
        );
        let ip = &frame[14..34];
        assert_eq!(ip[0], 0x45);          // version=4, IHL=5
        assert_eq!(ip[9], 17);            // protocol UDP
        assert_eq!(&ip[12..16], &src_ip.octets());
        assert_eq!(&ip[16..20], &dst_ip.octets());
        // Checksum must be non-zero and must validate
        let cksum = u16::from_be_bytes([ip[10], ip[11]]);
        assert_ne!(cksum, 0);
        // Re-computing over the embedded checksum must yield 0x0000 (valid one's complement)
        assert_eq!(ip_checksum(ip), 0x0000);
    }

    #[test]
    fn test_build_l2_udp_frame_udp_header() {
        use std::net::Ipv4Addr;
        let frame = build_l2_udp_frame(
            [0; 6],
            [0xFF; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            67,
            68,
            b"payload",
        );
        let udp = &frame[34..42];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 67);   // src port
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 68);   // dst port
        // UDP length = 8 (header) + 7 (payload) = 15
        assert_eq!(u16::from_be_bytes([udp[4], udp[5]]), 15);
        // checksum = 0 (optional in IPv4)
        assert_eq!(u16::from_be_bytes([udp[6], udp[7]]), 0);
    }

    #[test]
    fn test_build_l2_udp_frame_payload() {
        use std::net::Ipv4Addr;
        let payload = b"dhcpdata";
        let frame = build_l2_udp_frame(
            [0; 6],
            [0xFF; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            67,
            68,
            payload,
        );
        // Payload starts at offset 42 (14+20+8)
        assert_eq!(&frame[42..], payload);

        // Verify IP checksum is correct for the whole frame
        let ip = &frame[14..34];
        let cksum = u16::from_be_bytes([ip[10], ip[11]]);
        assert_ne!(cksum, 0);
        assert_eq!(ip_checksum(ip), 0x0000);
    }
}
