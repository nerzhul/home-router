use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use super::packet::{DhcpOption, DhcpPacket, MessageType};
use crate::config::Config;
use crate::db::Database;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

pub struct DhcpServer {
    config: Arc<Config>,
    db: Arc<Database>,
}

impl DhcpServer {
    pub fn new(config: Arc<Config>, db: Arc<Database>) -> Self {
        Self { config, db }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Starting DHCP server");

        for listen_addr in &self.config.listen_addresses {
            let addr = SocketAddr::new((*listen_addr).into(), DHCP_SERVER_PORT);
            info!("Binding to {}", addr);

            // Clone Arc references for the spawned task
            let config = Arc::clone(&self.config);
            let db = Arc::clone(&self.db);

            tokio::spawn(async move {
                if let Err(e) = Self::listen_loop(addr, config, db).await {
                    error!("DHCP listener error on {}: {}", addr, e);
                }
            });
        }

        // Keep running
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    async fn listen_loop(
        addr: SocketAddr,
        config: Arc<Config>,
        db: Arc<Database>,
    ) -> anyhow::Result<()> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_broadcast(true)?;

        info!("DHCP server listening on {}", addr);

        let mut buf = vec![0u8; 1024];

        loop {
            let (len, src) = socket.recv_from(&mut buf)?;
            debug!("Received {} bytes from {}", len, src);

            let packet_data = &buf[..len];

            // Parse packet
            let packet = match DhcpPacket::parse(packet_data) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to parse DHCP packet: {}", e);
                    continue;
                }
            };

            // Handle packet
            let response = Self::handle_packet(&packet, &config, &db).await;

            if let Some(response_packet) = response {
                let response_bytes = response_packet.to_bytes();
                let broadcast_addr =
                    SocketAddr::new(Ipv4Addr::new(255, 255, 255, 255).into(), DHCP_CLIENT_PORT);

                if let Err(e) = socket.send_to(&response_bytes, broadcast_addr) {
                    warn!("Failed to send DHCP response: {}", e);
                }
            }
        }
    }

    async fn handle_packet(
        packet: &DhcpPacket,
        config: &Config,
        db: &Database,
    ) -> Option<DhcpPacket> {
        let msg_type = packet.get_message_type()?;
        let mac = packet.chaddr.to_string();

        match msg_type {
            MessageType::Discover => {
                info!("DHCP DISCOVER from {}", mac);
                Self::handle_discover(packet, config, db).await
            }
            MessageType::Request => {
                info!("DHCP REQUEST from {}", mac);
                Self::handle_request(packet, config, db).await
            }
            MessageType::Release => {
                info!("DHCP RELEASE from {}", mac);
                Self::handle_release(packet, db).await;
                None
            }
            MessageType::Inform => {
                info!("DHCP INFORM from {}", mac);
                None // Not implemented yet
            }
            _ => {
                debug!("Unhandled DHCP message type: {:?}", msg_type);
                None
            }
        }
    }

    async fn handle_discover(
        packet: &DhcpPacket,
        config: &Config,
        db: &Database,
    ) -> Option<DhcpPacket> {
        let mac = packet.chaddr.to_string();

        // Check for static IP assignment
        if let Ok(Some(static_ip)) = db.get_static_ip_by_mac(&mac).await {
            let subnet = db.get_subnet(static_ip.subnet_id).await.ok()??;

            return Some(Self::create_offer(
                packet,
                static_ip.ip_address,
                &subnet,
                config,
            ));
        }

        // Check for existing lease
        if let Ok(Some(lease)) = db.get_active_lease(&mac).await {
            let subnet = db.get_subnet(lease.subnet_id).await.ok()??;

            return Some(Self::create_offer(
                packet,
                lease.ip_address,
                &subnet,
                config,
            ));
        }

        // TODO: Allocate new IP from dynamic range
        // For now, just return None
        None
    }

    async fn handle_request(
        packet: &DhcpPacket,
        config: &Config,
        db: &Database,
    ) -> Option<DhcpPacket> {
        let mac = packet.chaddr.to_string();

        // Extract requested IP
        let requested_ip = packet.options.iter().find_map(|opt| {
            if let DhcpOption::RequestedIpAddress(ip) = opt {
                Some(*ip)
            } else {
                None
            }
        })?;

        // Check for static IP assignment
        if let Ok(Some(static_ip)) = db.get_static_ip_by_mac(&mac).await {
            if static_ip.ip_address == requested_ip {
                let subnet = db.get_subnet(static_ip.subnet_id).await.ok()??;

                return Some(Self::create_ack(packet, requested_ip, &subnet, config));
            }
        }

        // TODO: Validate and create lease
        None
    }

    async fn handle_release(packet: &DhcpPacket, db: &Database) {
        let mac = packet.chaddr.to_string();

        if let Ok(Some(lease)) = db.get_active_lease(&mac).await {
            if let Some(id) = lease.id {
                let _ = db.expire_lease(id).await;
            }
        }
    }

    fn create_offer(
        request: &DhcpPacket,
        offered_ip: Ipv4Addr,
        subnet: &crate::models::Subnet,
        config: &Config,
    ) -> DhcpPacket {
        let mut packet = DhcpPacket::new();
        packet.op = 2; // BOOTREPLY
        packet.xid = request.xid;
        packet.yiaddr = offered_ip;
        packet.chaddr = request.chaddr.clone();
        packet.siaddr = subnet.gateway;

        packet
            .options
            .push(DhcpOption::MessageType(MessageType::Offer));
        packet
            .options
            .push(DhcpOption::ServerIdentifier(subnet.gateway));
        packet
            .options
            .push(DhcpOption::LeaseTime(config.dhcp.default_lease_time));
        packet
            .options
            .push(DhcpOption::SubnetMask(Self::netmask_from_prefix(
                subnet.netmask,
            )));
        packet
            .options
            .push(DhcpOption::Router(vec![subnet.gateway]));
        packet
            .options
            .push(DhcpOption::DnsServer(subnet.dns_servers.clone()));

        if let Some(domain) = &subnet.domain_name {
            packet.options.push(DhcpOption::DomainName(domain.clone()));
        }

        packet
    }

    fn create_ack(
        request: &DhcpPacket,
        assigned_ip: Ipv4Addr,
        subnet: &crate::models::Subnet,
        config: &Config,
    ) -> DhcpPacket {
        let mut packet = DhcpPacket::new();
        packet.op = 2; // BOOTREPLY
        packet.xid = request.xid;
        packet.yiaddr = assigned_ip;
        packet.chaddr = request.chaddr.clone();
        packet.siaddr = subnet.gateway;

        packet
            .options
            .push(DhcpOption::MessageType(MessageType::Ack));
        packet
            .options
            .push(DhcpOption::ServerIdentifier(subnet.gateway));
        packet
            .options
            .push(DhcpOption::LeaseTime(config.dhcp.default_lease_time));
        packet
            .options
            .push(DhcpOption::RenewalTime(config.dhcp.default_lease_time / 2));
        packet.options.push(DhcpOption::RebindingTime(
            config.dhcp.default_lease_time * 7 / 8,
        ));
        packet
            .options
            .push(DhcpOption::SubnetMask(Self::netmask_from_prefix(
                subnet.netmask,
            )));
        packet
            .options
            .push(DhcpOption::Router(vec![subnet.gateway]));
        packet
            .options
            .push(DhcpOption::DnsServer(subnet.dns_servers.clone()));

        if let Some(domain) = &subnet.domain_name {
            packet.options.push(DhcpOption::DomainName(domain.clone()));
        }

        packet
    }

    fn netmask_from_prefix(prefix: u8) -> Ipv4Addr {
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        Ipv4Addr::from(mask)
    }
}
