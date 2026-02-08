use crate::MessageType;
use std::net::Ipv4Addr;

/// DHCP options as defined in RFC 2132
#[derive(Debug, Clone, PartialEq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServer(Vec<Ipv4Addr>),
    DomainName(String),
    RequestedIpAddress(Ipv4Addr),
    LeaseTime(u32),
    MessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    RenewalTime(u32),
    RebindingTime(u32),
    Hostname(String),
    End,
    Unknown(u8, Vec<u8>),
}

impl DhcpOption {
    /// Parse a DHCP option from code and data bytes
    pub fn parse(code: u8, data: &[u8]) -> Self {
        match code {
            1 if data.len() == 4 => {
                Self::SubnetMask(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            3 => {
                let mut routers = Vec::new();
                for chunk in data.chunks_exact(4) {
                    routers.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
                Self::Router(routers)
            }
            6 => {
                let mut dns_servers = Vec::new();
                for chunk in data.chunks_exact(4) {
                    dns_servers.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
                Self::DnsServer(dns_servers)
            }
            15 => Self::DomainName(String::from_utf8_lossy(data).to_string()),
            50 if data.len() == 4 => {
                Self::RequestedIpAddress(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            51 if data.len() == 4 => {
                Self::LeaseTime(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            53 if data.len() == 1 => {
                if let Some(mt) = MessageType::from_u8(data[0]) {
                    Self::MessageType(mt)
                } else {
                    Self::Unknown(code, data.to_vec())
                }
            }
            54 if data.len() == 4 => {
                Self::ServerIdentifier(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
            }
            58 if data.len() == 4 => {
                Self::RenewalTime(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            59 if data.len() == 4 => {
                Self::RebindingTime(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            12 => Self::Hostname(String::from_utf8_lossy(data).to_string()),
            _ => Self::Unknown(code, data.to_vec()),
        }
    }

    /// Serialize the option to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::SubnetMask(addr) => {
                bytes.push(1);
                bytes.push(4);
                bytes.extend_from_slice(&addr.octets());
            }
            Self::Router(addrs) => {
                bytes.push(3);
                bytes.push((addrs.len() * 4) as u8);
                for addr in addrs {
                    bytes.extend_from_slice(&addr.octets());
                }
            }
            Self::DnsServer(addrs) => {
                bytes.push(6);
                bytes.push((addrs.len() * 4) as u8);
                for addr in addrs {
                    bytes.extend_from_slice(&addr.octets());
                }
            }
            Self::DomainName(name) => {
                bytes.push(15);
                bytes.push(name.len() as u8);
                bytes.extend_from_slice(name.as_bytes());
            }
            Self::RequestedIpAddress(addr) => {
                bytes.push(50);
                bytes.push(4);
                bytes.extend_from_slice(&addr.octets());
            }
            Self::LeaseTime(time) => {
                bytes.push(51);
                bytes.push(4);
                bytes.extend_from_slice(&time.to_be_bytes());
            }
            Self::MessageType(mt) => {
                bytes.push(53);
                bytes.push(1);
                bytes.push(mt.to_u8());
            }
            Self::ServerIdentifier(addr) => {
                bytes.push(54);
                bytes.push(4);
                bytes.extend_from_slice(&addr.octets());
            }
            Self::RenewalTime(time) => {
                bytes.push(58);
                bytes.push(4);
                bytes.extend_from_slice(&time.to_be_bytes());
            }
            Self::RebindingTime(time) => {
                bytes.push(59);
                bytes.push(4);
                bytes.extend_from_slice(&time.to_be_bytes());
            }
            Self::Hostname(name) => {
                bytes.push(12);
                bytes.push(name.len() as u8);
                bytes.extend_from_slice(name.as_bytes());
            }
            Self::End => {}
            Self::Unknown(code, data) => {
                bytes.push(*code);
                bytes.push(data.len() as u8);
                bytes.extend_from_slice(data);
            }
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_mask_parse() {
        let data = [255, 255, 255, 0];
        let opt = DhcpOption::parse(1, &data);
        assert_eq!(opt, DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn test_message_type_parse() {
        let data = [1];
        let opt = DhcpOption::parse(53, &data);
        assert_eq!(opt, DhcpOption::MessageType(MessageType::Discover));
    }

    #[test]
    fn test_lease_time_parse() {
        let data = [0, 0, 0x0E, 0x10]; // 3600 seconds
        let opt = DhcpOption::parse(51, &data);
        assert_eq!(opt, DhcpOption::LeaseTime(3600));
    }

    #[test]
    fn test_option_round_trip() {
        let original = DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0));
        let bytes = original.to_bytes();
        // bytes should be [1, 4, 255, 255, 255, 0]
        assert_eq!(bytes[0], 1); // code
        assert_eq!(bytes[1], 4); // length
        let parsed = DhcpOption::parse(bytes[0], &bytes[2..]);
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_hostname_parse() {
        let data = b"test-host";
        let opt = DhcpOption::parse(12, data);
        assert_eq!(opt, DhcpOption::Hostname("test-host".to_string()));
    }
}
