/// DHCP message types as defined in RFC 2132
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    /// Convert to u8 representation
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse from u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_to_u8() {
        assert_eq!(MessageType::Discover.to_u8(), 1);
        assert_eq!(MessageType::Offer.to_u8(), 2);
        assert_eq!(MessageType::Request.to_u8(), 3);
        assert_eq!(MessageType::Ack.to_u8(), 5);
    }

    #[test]
    fn test_message_type_from_u8() {
        assert_eq!(MessageType::from_u8(1), Some(MessageType::Discover));
        assert_eq!(MessageType::from_u8(2), Some(MessageType::Offer));
        assert_eq!(MessageType::from_u8(5), Some(MessageType::Ack));
        assert_eq!(MessageType::from_u8(99), None);
    }
}
