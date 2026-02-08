use crate::{DhcpOption, MacAddress, MessageType};
use std::net::Ipv4Addr;

/// DHCP packet structure as defined in RFC 2131
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op: u8,             // Message op code / message type
    pub htype: u8,          // Hardware address type
    pub hlen: u8,           // Hardware address length
    pub hops: u8,           // Client sets to zero
    pub xid: u32,           // Transaction ID
    pub secs: u16,          // Seconds elapsed
    pub flags: u16,         // Flags
    pub ciaddr: Ipv4Addr,   // Client IP address
    pub yiaddr: Ipv4Addr,   // 'Your' (client) IP address
    pub siaddr: Ipv4Addr,   // Server IP address
    pub giaddr: Ipv4Addr,   // Gateway IP address
    pub chaddr: MacAddress, // Client hardware address
    pub options: Vec<DhcpOption>,
}

/// DHCP magic cookie (RFC 2131)
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

impl DhcpPacket {
    /// Create a new empty DHCP packet
    pub fn new() -> Self {
        Self {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::new(0, 0, 0, 0),
            yiaddr: Ipv4Addr::new(0, 0, 0, 0),
            siaddr: Ipv4Addr::new(0, 0, 0, 0),
            giaddr: Ipv4Addr::new(0, 0, 0, 0),
            chaddr: MacAddress::new([0; 6]),
            options: Vec::new(),
        }
    }

    /// Parse a DHCP packet from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 240 {
            return Err("Packet too small".to_string());
        }

        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);

        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        let chaddr = MacAddress::from_slice(&data[28..34]).ok_or("Invalid MAC address")?;

        // Parse options (starting at byte 236 after magic cookie)
        let mut options = Vec::new();
        if data.len() > 240 && &data[236..240] == DHCP_MAGIC_COOKIE {
            let mut i = 240;
            while i < data.len() {
                let option_code = data[i];
                if option_code == 255 {
                    options.push(DhcpOption::End);
                    break;
                }
                if option_code == 0 {
                    i += 1;
                    continue;
                }

                if i + 1 >= data.len() {
                    break;
                }

                let option_len = data[i + 1] as usize;
                if i + 2 + option_len > data.len() {
                    break;
                }

                let option_data = &data[i + 2..i + 2 + option_len];
                options.push(DhcpOption::parse(option_code, option_data));

                i += 2 + option_len;
            }
        }

        Ok(Self {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            options,
        })
    }

    /// Serialize the packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 240];

        bytes[0] = self.op;
        bytes[1] = self.htype;
        bytes[2] = self.hlen;
        bytes[3] = self.hops;

        bytes[4..8].copy_from_slice(&self.xid.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.secs.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.flags.to_be_bytes());

        bytes[12..16].copy_from_slice(&self.ciaddr.octets());
        bytes[16..20].copy_from_slice(&self.yiaddr.octets());
        bytes[20..24].copy_from_slice(&self.siaddr.octets());
        bytes[24..28].copy_from_slice(&self.giaddr.octets());

        bytes[28..34].copy_from_slice(self.chaddr.as_bytes());

        // Magic cookie
        bytes[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        // Add options
        for option in &self.options {
            bytes.extend_from_slice(&option.to_bytes());
        }

        // End option
        bytes.push(255);

        bytes
    }

    /// Get the message type from the options
    pub fn get_message_type(&self) -> Option<MessageType> {
        for option in &self.options {
            if let DhcpOption::MessageType(mt) = option {
                return Some(*mt);
            }
        }
        None
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_creation() {
        let packet = DhcpPacket::new();
        assert_eq!(packet.op, 1);
        assert_eq!(packet.htype, 1);
        assert_eq!(packet.hlen, 6);
    }

    #[test]
    fn test_packet_too_small() {
        let data = vec![0u8; 100];
        assert!(DhcpPacket::parse(&data).is_err());
    }

    #[test]
    fn test_packet_round_trip() {
        let mut packet = DhcpPacket::new();
        packet.xid = 0x12345678;
        packet.chaddr = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        packet
            .options
            .push(DhcpOption::MessageType(MessageType::Discover));

        let bytes = packet.to_bytes();
        let parsed = DhcpPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.xid, 0x12345678);
        assert_eq!(
            parsed.chaddr.as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        assert_eq!(parsed.get_message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn test_get_message_type() {
        let mut packet = DhcpPacket::new();
        assert_eq!(packet.get_message_type(), None);

        packet
            .options
            .push(DhcpOption::MessageType(MessageType::Request));
        assert_eq!(packet.get_message_type(), Some(MessageType::Request));
    }
}
