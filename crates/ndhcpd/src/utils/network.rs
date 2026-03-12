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
}
