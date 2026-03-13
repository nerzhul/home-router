use crate::client::ApiClient;
use crate::Ip6SubnetCommands;
use anyhow::Result;
use ndhcpd::models::IAPrefix;
use std::net::Ipv6Addr;

pub async fn handle(client: ApiClient, action: Ip6SubnetCommands) -> Result<()> {
    match action {
        Ip6SubnetCommands::List { interface } => list(client, interface).await,
        Ip6SubnetCommands::Create {
            interface,
            prefix,
            prefix_len,
            preferred_lifetime,
            valid_lifetime,
            dns_servers,
            dns_lifetime,
        } => {
            create(
                client,
                interface,
                prefix,
                prefix_len,
                preferred_lifetime,
                valid_lifetime,
                dns_servers,
                dns_lifetime,
            )
            .await
        }
        Ip6SubnetCommands::Get { id } => get(client, id).await,
        Ip6SubnetCommands::Delete { id } => delete(client, id).await,
    }
}

async fn list(client: ApiClient, interface: Option<String>) -> Result<()> {
    let path = if let Some(iface) = interface {
        format!("/api/ia-prefixes?interface={}", iface)
    } else {
        "/api/ia-prefixes".to_string()
    };

    let prefixes: Vec<IAPrefix> = client.get(&path).await?;

    if prefixes.is_empty() {
        println!("No IPv6 subnets configured");
    } else {
        println!(
            "{:<5} {:<10} {:<40} {:<6} {:<12} {:<12} {:<40}",
            "ID", "Interface", "Prefix", "Len", "Pref.Life", "Valid.Life", "DNS Servers"
        );
        println!("{}", "-".repeat(126));

        for p in prefixes {
            let dns = if p.dns_servers.is_empty() {
                "-".to_string()
            } else {
                p.dns_servers
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };

            println!(
                "{:<5} {:<10} {:<40} /{:<5} {:<12} {:<12} {:<40}",
                p.id.unwrap_or(0),
                p.interface,
                p.prefix,
                p.prefix_len,
                p.preferred_lifetime,
                p.valid_lifetime,
                dns,
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create(
    client: ApiClient,
    interface: String,
    prefix: String,
    prefix_len: u8,
    preferred_lifetime: Option<u32>,
    valid_lifetime: Option<u32>,
    dns_servers: Option<String>,
    dns_lifetime: Option<u32>,
) -> Result<()> {
    let prefix_addr: Ipv6Addr = prefix.parse()?;

    let dns: Vec<Ipv6Addr> = dns_servers
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse())
        .collect::<Result<Vec<_>, _>>()?;

    let ia_prefix = IAPrefix {
        id: None,
        interface,
        prefix: prefix_addr,
        prefix_len,
        // 0 means "use server default"
        preferred_lifetime: preferred_lifetime.unwrap_or(0),
        valid_lifetime: valid_lifetime.unwrap_or(0),
        dns_servers: dns,
        dns_lifetime: dns_lifetime.unwrap_or(0),
    };

    let id: i64 = client.post("/api/ia-prefixes", &ia_prefix).await?;
    println!("Created IPv6 subnet with ID: {}", id);

    Ok(())
}

async fn get(client: ApiClient, id: i64) -> Result<()> {
    let p: IAPrefix = client.get(&format!("/api/ia-prefixes/{}", id)).await?;

    println!("ID:                  {}", p.id.unwrap_or(0));
    println!("Interface:           {}", p.interface);
    println!("Prefix:              {}/{}", p.prefix, p.prefix_len);
    println!("Preferred lifetime:  {}s", p.preferred_lifetime);
    println!("Valid lifetime:      {}s", p.valid_lifetime);
    if !p.dns_servers.is_empty() {
        println!(
            "DNS servers:         {}",
            p.dns_servers
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("DNS lifetime:        {}s", p.dns_lifetime);
    }

    Ok(())
}

async fn delete(client: ApiClient, id: i64) -> Result<()> {
    client.delete(&format!("/api/ia-prefixes/{}", id)).await?;
    println!("Deleted IPv6 subnet {}", id);
    Ok(())
}
