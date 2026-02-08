use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, Row};
use std::str::FromStr;
use crate::models::{Subnet, DynamicRange, StaticIP, Lease};

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true);
        
        let pool = SqlitePool::connect_with(options).await?;
        
        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;
        
        Ok(Self { pool })
    }
    
    /// Get the underlying connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
    
    // Subnet operations
    pub async fn create_subnet(&self, subnet: &Subnet) -> anyhow::Result<i64> {
        let dns_servers = subnet.dns_servers_to_string();
        let result = sqlx::query(
            "INSERT INTO subnets (network, netmask, gateway, dns_servers, domain_name, enabled) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(subnet.network.to_string())
        .bind(subnet.netmask as i64)
        .bind(subnet.gateway.to_string())
        .bind(dns_servers)
        .bind(&subnet.domain_name)
        .bind(subnet.enabled as i64)
        .execute(&self.pool)
        .await?;
        
        Ok(result.last_insert_rowid())
    }
    
    pub async fn get_subnet(&self, id: i64) -> anyhow::Result<Option<Subnet>> {
        let row = sqlx::query(
            "SELECT id, network, netmask, gateway, dns_servers, domain_name, enabled FROM subnets WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| Subnet {
            id: r.get("id"),
            network: r.get::<String, _>("network").parse().unwrap(),
            netmask: r.get::<i64, _>("netmask") as u8,
            gateway: r.get::<String, _>("gateway").parse().unwrap(),
            dns_servers: Subnet::dns_servers_from_string(&r.get::<String, _>("dns_servers")),
            domain_name: r.get("domain_name"),
            enabled: r.get::<i64, _>("enabled") != 0,
        }))
    }
    
    pub async fn list_subnets(&self) -> anyhow::Result<Vec<Subnet>> {
        let rows = sqlx::query(
            "SELECT id, network, netmask, gateway, dns_servers, domain_name, enabled FROM subnets"
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|r| Subnet {
            id: r.get("id"),
            network: r.get::<String, _>("network").parse().unwrap(),
            netmask: r.get::<i64, _>("netmask") as u8,
            gateway: r.get::<String, _>("gateway").parse().unwrap(),
            dns_servers: Subnet::dns_servers_from_string(&r.get::<String, _>("dns_servers")),
            domain_name: r.get("domain_name"),
            enabled: r.get::<i64, _>("enabled") != 0,
        }).collect())
    }
    
    pub async fn update_subnet(&self, id: i64, subnet: &Subnet) -> anyhow::Result<()> {
        let dns_servers = subnet.dns_servers_to_string();
        sqlx::query(
            "UPDATE subnets SET network = ?, netmask = ?, gateway = ?, dns_servers = ?, domain_name = ?, enabled = ? WHERE id = ?"
        )
        .bind(subnet.network.to_string())
        .bind(subnet.netmask as i64)
        .bind(subnet.gateway.to_string())
        .bind(dns_servers)
        .bind(&subnet.domain_name)
        .bind(subnet.enabled as i64)
        .bind(id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    pub async fn delete_subnet(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM subnets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    
    // Dynamic Range operations
    pub async fn create_range(&self, range: &DynamicRange) -> anyhow::Result<i64> {
        let result = sqlx::query(
            "INSERT INTO dynamic_ranges (subnet_id, range_start, range_end, enabled) VALUES (?, ?, ?, ?)"
        )
        .bind(range.subnet_id)
        .bind(range.range_start.to_string())
        .bind(range.range_end.to_string())
        .bind(range.enabled as i64)
        .execute(&self.pool)
        .await?;
        
        Ok(result.last_insert_rowid())
    }
    
    pub async fn list_ranges(&self, subnet_id: Option<i64>) -> anyhow::Result<Vec<DynamicRange>> {
        let rows = if let Some(subnet_id) = subnet_id {
            sqlx::query(
                "SELECT id, subnet_id, range_start, range_end, enabled FROM dynamic_ranges WHERE subnet_id = ?"
            )
            .bind(subnet_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, subnet_id, range_start, range_end, enabled FROM dynamic_ranges"
            )
            .fetch_all(&self.pool)
            .await?
        };
        
        Ok(rows.into_iter().map(|r| DynamicRange {
            id: r.get("id"),
            subnet_id: r.get("subnet_id"),
            range_start: r.get::<String, _>("range_start").parse().unwrap(),
            range_end: r.get::<String, _>("range_end").parse().unwrap(),
            enabled: r.get::<i64, _>("enabled") != 0,
        }).collect())
    }
    
    pub async fn delete_range(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM dynamic_ranges WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    
    // Static IP operations
    pub async fn create_static_ip(&self, static_ip: &StaticIP) -> anyhow::Result<i64> {
        let result = sqlx::query(
            "INSERT INTO static_ips (subnet_id, mac_address, ip_address, hostname, enabled) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(static_ip.subnet_id)
        .bind(&static_ip.mac_address)
        .bind(static_ip.ip_address.to_string())
        .bind(&static_ip.hostname)
        .bind(static_ip.enabled as i64)
        .execute(&self.pool)
        .await?;
        
        Ok(result.last_insert_rowid())
    }
    
    pub async fn list_static_ips(&self, subnet_id: Option<i64>) -> anyhow::Result<Vec<StaticIP>> {
        let rows = if let Some(subnet_id) = subnet_id {
            sqlx::query(
                "SELECT id, subnet_id, mac_address, ip_address, hostname, enabled FROM static_ips WHERE subnet_id = ?"
            )
            .bind(subnet_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, subnet_id, mac_address, ip_address, hostname, enabled FROM static_ips"
            )
            .fetch_all(&self.pool)
            .await?
        };
        
        Ok(rows.into_iter().map(|r| StaticIP {
            id: r.get("id"),
            subnet_id: r.get("subnet_id"),
            mac_address: r.get("mac_address"),
            ip_address: r.get::<String, _>("ip_address").parse().unwrap(),
            hostname: r.get("hostname"),
            enabled: r.get::<i64, _>("enabled") != 0,
        }).collect())
    }
    
    pub async fn get_static_ip_by_mac(&self, mac: &str) -> anyhow::Result<Option<StaticIP>> {
        let row = sqlx::query(
            "SELECT id, subnet_id, mac_address, ip_address, hostname, enabled FROM static_ips WHERE mac_address = ? AND enabled = 1"
        )
        .bind(mac)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| StaticIP {
            id: r.get("id"),
            subnet_id: r.get("subnet_id"),
            mac_address: r.get("mac_address"),
            ip_address: r.get::<String, _>("ip_address").parse().unwrap(),
            hostname: r.get("hostname"),
            enabled: r.get::<i64, _>("enabled") != 0,
        }))
    }
    
    pub async fn delete_static_ip(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM static_ips WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    
    // Lease operations
    pub async fn create_lease(&self, lease: &Lease) -> anyhow::Result<i64> {
        let result = sqlx::query(
            "INSERT INTO leases (subnet_id, mac_address, ip_address, lease_start, lease_end, hostname, active) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(lease.subnet_id)
        .bind(&lease.mac_address)
        .bind(lease.ip_address.to_string())
        .bind(lease.lease_start)
        .bind(lease.lease_end)
        .bind(&lease.hostname)
        .bind(lease.active as i64)
        .execute(&self.pool)
        .await?;
        
        Ok(result.last_insert_rowid())
    }
    
    pub async fn get_active_lease(&self, mac: &str) -> anyhow::Result<Option<Lease>> {
        let now = chrono::Utc::now().timestamp();
        let row = sqlx::query(
            "SELECT id, subnet_id, mac_address, ip_address, lease_start, lease_end, hostname, active FROM leases WHERE mac_address = ? AND active = 1 AND lease_end > ? ORDER BY lease_end DESC LIMIT 1"
        )
        .bind(mac)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|r| Lease {
            id: r.get("id"),
            subnet_id: r.get("subnet_id"),
            mac_address: r.get("mac_address"),
            ip_address: r.get::<String, _>("ip_address").parse().unwrap(),
            lease_start: r.get("lease_start"),
            lease_end: r.get("lease_end"),
            hostname: r.get("hostname"),
            active: r.get::<i64, _>("active") != 0,
        }))
    }
    
    pub async fn list_active_leases(&self) -> anyhow::Result<Vec<Lease>> {
        let now = chrono::Utc::now().timestamp();
        let rows = sqlx::query(
            "SELECT id, subnet_id, mac_address, ip_address, lease_start, lease_end, hostname, active FROM leases WHERE active = 1 AND lease_end > ?"
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|r| Lease {
            id: r.get("id"),
            subnet_id: r.get("subnet_id"),
            mac_address: r.get("mac_address"),
            ip_address: r.get::<String, _>("ip_address").parse().unwrap(),
            lease_start: r.get("lease_start"),
            lease_end: r.get("lease_end"),
            hostname: r.get("hostname"),
            active: r.get::<i64, _>("active") != 0,
        }).collect())
    }
    
    pub async fn expire_lease(&self, id: i64) -> anyhow::Result<()> {
        sqlx::query("UPDATE leases SET active = 0 WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
