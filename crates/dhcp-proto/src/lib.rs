//! Generic DHCP packet parsing and serialization library
//!
//! This library provides low-level DHCP packet manipulation without any
//! business logic dependencies. It can be used in any DHCP server or client
//! implementation.

pub mod mac;
pub mod message_type;
pub mod option;
pub mod packet;

pub use mac::MacAddress;
pub use message_type::MessageType;
pub use option::DhcpOption;
pub use packet::DhcpPacket;
