use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use utoipa::ToSchema;

/// A subnet configuration
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Subnet {
    pub id: Option<i64>,
    
    /// Network address (e.g., 192.168.1.0)
    #[schema(value_type = String)]
    pub network: Ipv4Addr,
    
    /// Subnet mask (e.g., 24 for /24)
    pub netmask: u8,
    
    /// Gateway/router address
    #[schema(value_type = String)]
    pub gateway: Ipv4Addr,
    
    /// DNS servers (comma-separated in DB)
    #[schema(value_type = Vec<String>)]
    pub dns_servers: Vec<Ipv4Addr>,
    
    /// Domain name
    pub domain_name: Option<String>,
    
    /// Whether this subnet is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// A dynamic IP range within a subnet
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DynamicRange {
    pub id: Option<i64>,
    
    /// Foreign key to subnet
    pub subnet_id: i64,
    
    /// Start of the range (e.g., 192.168.1.100)
    #[schema(value_type = String)]
    pub range_start: Ipv4Addr,
    
    /// End of the range (e.g., 192.168.1.200)
    #[schema(value_type = String)]
    pub range_end: Ipv4Addr,
    
    /// Whether this range is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// A static IP assignment
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StaticIP {
    pub id: Option<i64>,
    
    /// Foreign key to subnet
    pub subnet_id: i64,
    
    /// MAC address (format: XX:XX:XX:XX:XX:XX)
    pub mac_address: String,
    
    /// Assigned IP address
    #[schema(value_type = String)]
    pub ip_address: Ipv4Addr,
    
    /// Optional hostname
    pub hostname: Option<String>,
    
    /// Whether this assignment is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// A DHCP lease
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Lease {
    pub id: Option<i64>,
    
    /// Foreign key to subnet
    pub subnet_id: i64,
    
    /// MAC address of the client
    pub mac_address: String,
    
    /// Leased IP address
    #[schema(value_type = String)]
    pub ip_address: Ipv4Addr,
    
    /// Lease start time (Unix timestamp)
    pub lease_start: i64,
    
    /// Lease end time (Unix timestamp)
    pub lease_end: i64,
    
    /// Optional hostname
    pub hostname: Option<String>,
    
    /// Whether this is an active lease
    #[serde(default = "default_true")]
    pub active: bool,
}

// Helper functions for converting between String and Ipv4Addr for sqlx
impl Subnet {
    pub fn dns_servers_to_string(&self) -> String {
        self.dns_servers
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    
    pub fn dns_servers_from_string(s: &str) -> Vec<Ipv4Addr> {
        s.split(',')
            .filter_map(|ip| ip.trim().parse().ok())
            .collect()
    }
}
