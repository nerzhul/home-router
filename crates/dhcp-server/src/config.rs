use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Configuration structure loaded from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listening addresses for the DHCP server
    pub listen_addresses: Vec<Ipv4Addr>,
    
    /// Database file path
    #[serde(default = "default_db_path")]
    pub database_path: String,
    
    /// API server configuration
    pub api: ApiConfig,
    
    /// DHCP server configuration
    pub dhcp: DhcpConfig,
}

fn default_db_path() -> String {
    "/var/lib/dhcp-server/dhcp.db".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// API listening address
    #[serde(default = "default_api_address")]
    pub listen_address: String,
    
    /// API listening port
    #[serde(default = "default_api_port")]
    pub port: u16,
}

fn default_api_address() -> String {
    "127.0.0.1".to_string()
}

fn default_api_port() -> u16 {
    8080
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    /// Default lease time in seconds
    #[serde(default = "default_lease_time")]
    pub default_lease_time: u32,
    
    /// Maximum lease time in seconds
    #[serde(default = "default_max_lease_time")]
    pub max_lease_time: u32,
}

fn default_lease_time() -> u32 {
    86400 // 24 hours
}

fn default_max_lease_time() -> u32 {
    604800 // 7 days
}

impl Config {
    /// Load configuration from a YAML file
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
    
    /// Save configuration to a YAML file
    pub fn to_file(&self, path: &str) -> anyhow::Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addresses: vec![Ipv4Addr::new(0, 0, 0, 0)],
            database_path: default_db_path(),
            api: ApiConfig {
                listen_address: default_api_address(),
                port: default_api_port(),
            },
            dhcp: DhcpConfig {
                default_lease_time: default_lease_time(),
                max_lease_time: default_max_lease_time(),
            },
        }
    }
}
