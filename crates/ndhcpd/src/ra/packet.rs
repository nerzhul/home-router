use crate::models::IAPrefix;
use std::{collections::HashSet, net::Ipv6Addr};

/// ICMPv6 type numbers
pub const ICMPV6_TYPE_RS: u8 = 133; // Router Solicitation
pub const ICMPV6_TYPE_RA: u8 = 134; // Router Advertisement

/// Build an ICMPv6 Router Advertisement payload (without IPv6 header).
///
/// The kernel automatically fills the ICMPv6 checksum when the packet is sent
/// through a raw `IPPROTO_ICMPV6` socket (RFC 3542).
///
/// # Options included
/// * **Prefix Information** (type 3, RFC 4861 §4.6.2) – one per prefix entry with L=1, A=1.
/// * **RDNSS** (type 25, RFC 6106) – one option with all deduplicated DNS servers.
pub fn build_router_advertisement(
    prefixes: &[IAPrefix],
    cur_hop_limit: u8,
    router_lifetime_secs: u16,
    managed: bool,
    other: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // ── ICMPv6 header (4 bytes) ──────────────────────────────────────────────
    buf.push(ICMPV6_TYPE_RA); // Type 134
    buf.push(0u8); // Code 0
    buf.extend_from_slice(&[0u8, 0u8]); // Checksum – kernel fills this

    // ── RA body (12 bytes) ──────────────────────────────────────────────────
    buf.push(cur_hop_limit);
    let flags: u8 = (if managed { 0x80 } else { 0 }) | (if other { 0x40 } else { 0 });
    buf.push(flags);
    buf.extend_from_slice(&router_lifetime_secs.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time
    buf.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer

    // ── Prefix Information options (type 3) ─────────────────────────────────
    for prefix in prefixes {
        // Length = 4 units of 8 bytes = 32 bytes total
        buf.push(3u8);
        buf.push(4u8);
        buf.push(prefix.prefix_len);
        // L=1 (on-link), A=1 (SLAAC autoconf), reserved bits = 0
        buf.push(0b1100_0000u8);
        buf.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());
        buf.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // Reserved2
        buf.extend_from_slice(&prefix.prefix.octets());
    }

    // ── RDNSS option (type 25, RFC 6106) ────────────────────────────────────
    // Deduplicate DNS servers across all prefixes and emit a single option.
    let dns_servers: Vec<Ipv6Addr> = prefixes
        .iter()
        .flat_map(|p| p.dns_servers.iter().copied())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    if !dns_servers.is_empty() {
        let n = dns_servers.len();
        // Option length in units of 8 bytes: 1 (type+len+reserved+lifetime) + 2*n (addresses)
        let length = (1 + 2 * n) as u8;
        let dns_lifetime = prefixes.iter().map(|p| p.dns_lifetime).max().unwrap_or(3600);

        buf.push(25u8); // Type: RDNSS
        buf.push(length);
        buf.extend_from_slice(&[0u8, 0u8]); // Reserved
        buf.extend_from_slice(&dns_lifetime.to_be_bytes());
        for addr in &dns_servers {
            buf.extend_from_slice(&addr.octets());
        }
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prefix(prefix: &str, prefix_len: u8, dns: Vec<&str>) -> IAPrefix {
        IAPrefix {
            id: None,
            interface: "eth0".to_string(),
            prefix: prefix.parse().unwrap(),
            prefix_len,
            preferred_lifetime: 14400,
            valid_lifetime: 86400,
            dns_servers: dns.iter().map(|s| s.parse().unwrap()).collect(),
            dns_lifetime: 3600,
        }
    }

    #[test]
    fn test_ra_minimal_no_prefixes() {
        let buf = build_router_advertisement(&[], 64, 1800, false, false);
        // 4 (ICMPv6 header) + 12 (RA body) = 16
        assert_eq!(buf.len(), 16);
        assert_eq!(buf[0], ICMPV6_TYPE_RA);
        assert_eq!(buf[1], 0);
        assert_eq!(buf[2], 0); // checksum high (kernel fills later)
        assert_eq!(buf[3], 0); // checksum low
        assert_eq!(buf[4], 64); // cur hop limit
        assert_eq!(buf[5], 0); // no M/O flags
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1800); // router lifetime
    }

    #[test]
    fn test_ra_managed_other_flags() {
        let buf = build_router_advertisement(&[], 64, 1800, true, true);
        assert_eq!(buf[5] & 0x80, 0x80); // M=1
        assert_eq!(buf[5] & 0x40, 0x40); // O=1
    }

    #[test]
    fn test_ra_prefix_option_layout() {
        let prefix = make_prefix("2001:db8::", 64, vec![]);
        let buf = build_router_advertisement(&[prefix], 64, 1800, false, false);
        // 16 (base) + 32 (prefix option: 4 * 8 bytes)
        assert_eq!(buf.len(), 48);
        assert_eq!(buf[16], 3); // option type: Prefix Information
        assert_eq!(buf[17], 4); // option length: 4 * 8 bytes
        assert_eq!(buf[18], 64); // prefix length
        assert_eq!(buf[19], 0b1100_0000); // L=1, A=1
        // valid lifetime at offset 20
        assert_eq!(u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]), 86400);
        // preferred lifetime at offset 24
        assert_eq!(u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]), 14400);
        // prefix address at offset 32
        let prefix_addr = Ipv6Addr::from({
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&buf[32..48]);
            arr
        });
        assert_eq!(prefix_addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_ra_rdnss_option() {
        let prefix = make_prefix("2001:db8::", 64, vec!["2001:db8::1"]);
        let buf = build_router_advertisement(&[prefix], 64, 1800, false, false);
        // 16 (base) + 32 (prefix) + 24 (RDNSS: (1 + 2*1) * 8 = 24)
        assert_eq!(buf.len(), 72);
        assert_eq!(buf[48], 25); // RDNSS type
        assert_eq!(buf[49], 3); // length: (1 + 2*1) units
        assert_eq!(u32::from_be_bytes([buf[52], buf[53], buf[54], buf[55]]), 3600); // lifetime
        let dns = Ipv6Addr::from({
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&buf[56..72]);
            arr
        });
        assert_eq!(dns, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_ra_rdnss_deduplicated() {
        // Two prefixes sharing the same DNS server – must appear only once.
        let p1 = make_prefix("2001:db8::", 64, vec!["2001:db8::1"]);
        let p2 = make_prefix("2001:db8:1::", 64, vec!["2001:db8::1"]);
        let buf = build_router_advertisement(&[p1, p2], 64, 1800, false, false);
        // 16 + 32 + 32 + 24 = 104
        assert_eq!(buf.len(), 16 + 32 + 32 + 24);
        // RDNSS option length field should still be 3 (= 1 + 2*1 DNS entry)
        let rdnss_offset = 16 + 32 + 32;
        assert_eq!(buf[rdnss_offset], 25);
        assert_eq!(buf[rdnss_offset + 1], 3);
    }

    #[test]
    fn test_ra_no_rdnss_when_no_dns() {
        let prefix = make_prefix("2001:db8::", 64, vec![]);
        let buf = build_router_advertisement(&[prefix], 64, 1800, false, false);
        // 16 (base) + 32 (prefix) – no RDNSS option
        assert_eq!(buf.len(), 48);
    }

    #[test]
    fn test_ra_multiple_prefixes() {
        let p1 = make_prefix("2001:db8::", 64, vec![]);
        let p2 = make_prefix("2001:db8:1::", 48, vec![]);
        let buf = build_router_advertisement(&[p1, p2], 64, 1800, false, false);
        assert_eq!(buf.len(), 16 + 32 + 32);
        // Second prefix at offset 48
        assert_eq!(buf[48], 3);
        assert_eq!(buf[50], 48); // prefix_len for second prefix
    }
}
