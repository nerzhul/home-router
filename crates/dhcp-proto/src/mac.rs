/// MAC address representation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Create a new MAC address from a byte array
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Create a MAC address from a slice (must be at least 6 bytes)
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() >= 6 {
            let mut bytes = [0u8; 6];
            bytes.copy_from_slice(&slice[..6]);
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Get the underlying byte array
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Convert to a formatted string (XX:XX:XX:XX:XX:XX)
    pub fn to_string(&self) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    /// Parse a MAC address from a string (XX:XX:XX:XX:XX:XX)
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).ok()?;
        }

        Some(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_from_bytes() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(mac.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_from_slice() {
        let slice = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mac = MacAddress::from_slice(&slice).unwrap();
        assert_eq!(mac.as_bytes(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn test_mac_from_slice_too_short() {
        let slice = [0x11, 0x22, 0x33];
        assert!(MacAddress::from_slice(&slice).is_none());
    }

    #[test]
    fn test_mac_to_string() {
        let mac = MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(mac.to_string(), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_mac_from_string() {
        let mac = MacAddress::from_string("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_from_string_lowercase() {
        let mac = MacAddress::from_string("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.as_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_mac_from_string_invalid() {
        assert!(MacAddress::from_string("AA:BB:CC:DD:EE").is_none());
        assert!(MacAddress::from_string("AA:BB:CC:DD:EE:GG").is_none());
        assert!(MacAddress::from_string("AABBCCDDEEFF").is_none());
    }
}
