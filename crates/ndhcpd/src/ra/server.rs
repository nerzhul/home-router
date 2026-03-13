use std::{
    net::Ipv6Addr,
    os::fd::{FromRawFd, OwnedFd},
    sync::Arc,
};
use tokio::io::unix::AsyncFd;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::{
    config::{Config, RaConfig},
    db::DynDatabase,
    utils::network::{get_ifindex, get_link_local_addr},
};

use super::packet::{build_router_advertisement, ICMPV6_TYPE_RA, ICMPV6_TYPE_RS};

/// Default Router Advertisement interval (RFC 4861 §6.2.1 MaxRtrAdvInterval default = 600 s).
/// We use 200 s as a common default for faster SLAAC convergence.
const MAX_RTR_ADV_INTERVAL_SECS: u64 = 200;

/// Platform-correct sockopt to join an IPv6 multicast group.
/// Linux calls it `IPV6_ADD_MEMBERSHIP`; FreeBSD uses `IPV6_JOIN_GROUP` (12).
#[cfg(target_os = "linux")]
const IPV6_JOIN_GROUP_OPT: libc::c_int = libc::IPV6_ADD_MEMBERSHIP;
#[cfg(target_os = "freebsd")]
const IPV6_JOIN_GROUP_OPT: libc::c_int = 12; // IPV6_JOIN_GROUP
#[cfg(target_os = "linux")]
const ICMP6_FILTER_SOCKOPT: libc::c_int = 1;
#[cfg(target_os = "freebsd")]
const ICMP6_FILTER_SOCKOPT: libc::c_int = 18;

/// Raw `icmp6_filter` structure: 256-bit bitmap, one bit per ICMPv6 type.
/// All-ones = all types blocked; clearing bit N passes type N.
#[repr(C)]
struct Icmp6Filter {
    icmp6_filt: [u32; 8],
}

impl Icmp6Filter {
    /// Block all ICMPv6 types.
    fn block_all() -> Self {
        Self {
            icmp6_filt: [0xffff_ffff; 8],
        }
    }

    /// Clear the bit for `icmpv6_type` so that type passes through.
    fn pass(&mut self, icmpv6_type: u8) {
        let t = icmpv6_type as usize;
        self.icmp6_filt[t >> 5] &= !(1u32 << (t & 31));
    }
}

/// Router Advertisement server.
///
/// When `config.ra.enabled` is true, spawns one async task per interface listed
/// in `config.ra.ip6_listen_interfaces`.  Each task:
/// 1. Creates a raw `IPPROTO_ICMPV6` socket.
/// 2. Joins the `ff02::2` (all-routers) multicast group to receive RS messages.
/// 3. Sends periodic RA packets to `ff02::1` at [`MAX_RTR_ADV_INTERVAL_SECS`].
/// 4. Responds immediately to Router Solicitations (ICMPv6 type 133).
///
/// Prefix information and RDNSS entries are read from the database on every send
/// so that changes take effect at the next RA without a restart.
pub struct RaServer {
    config: Arc<Config>,
    db: DynDatabase,
}

impl RaServer {
    pub fn new(config: Arc<Config>, db: DynDatabase) -> Self {
        Self { config, db }
    }

    /// Start the RA server.  Returns immediately if RA is disabled or no
    /// interfaces are configured.  Otherwise spawns one task per interface
    /// and awaits them all.
    pub async fn run(&self) -> anyhow::Result<()> {
        let ra_config = match &self.config.ra {
            Some(cfg) if cfg.enabled => cfg.clone(),
            _ => {
                debug!("Router Advertisement is disabled – skipping RA server");
                return Ok(());
            }
        };

        if ra_config.ip6_listen_interfaces.is_empty() {
            warn!("RA enabled but ip6_listen_interfaces is empty – nothing to do");
            return Ok(());
        }

        info!(
            "Starting Router Advertisement server on interfaces: {:?}",
            ra_config.ip6_listen_interfaces
        );

        let handles: Vec<_> = ra_config
            .ip6_listen_interfaces
            .iter()
            .map(|iface| {
                let iface = iface.clone();
                let db = Arc::clone(&self.db);
                let cfg = ra_config.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_on_interface(iface.clone(), db, cfg).await {
                        error!("RA server error on {}: {}", iface, e);
                    }
                })
            })
            .collect();

        futures::future::join_all(handles).await;
        Ok(())
    }
}

/// Inline helper: convert `Ipv6Addr` to `libc::in6_addr`.
#[inline]
fn to_in6_addr(addr: Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: addr.octets(),
    }
}

/// Create and configure the raw ICMPv6 socket for one interface.
///
/// Returns the raw file descriptor.  The caller is responsible for closing it.
fn create_ra_socket(
    iface: &str,
    ifindex: u32,
    link_local: Ipv6Addr,
) -> anyhow::Result<libc::c_int> {
    let sock_fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        )
    };
    if sock_fd < 0 {
        anyhow::bail!(
            "socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // ── Non-blocking ────────────────────────────────────────────────────────
    let flags = unsafe { libc::fcntl(sock_fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(sock_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        unsafe { libc::close(sock_fd) };
        anyhow::bail!(
            "fcntl(O_NONBLOCK) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // ── Hop limit = 255 (required by RFC 4861 for NDP) ──────────────────────
    let hops: libc::c_int = 255;
    for optname in [libc::IPV6_MULTICAST_HOPS, libc::IPV6_UNICAST_HOPS] {
        let ret = unsafe {
            libc::setsockopt(
                sock_fd,
                libc::IPPROTO_IPV6,
                optname,
                &hops as *const _ as *const libc::c_void,
                std::mem::size_of_val(&hops) as libc::socklen_t,
            )
        };
        if ret != 0 {
            unsafe { libc::close(sock_fd) };
            anyhow::bail!(
                "setsockopt IPV6_*_HOPS=255 failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // ── Multicast outgoing interface ─────────────────────────────────────────
    let ifidx_int: libc::c_int = ifindex as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            sock_fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &ifidx_int as *const _ as *const libc::c_void,
            std::mem::size_of_val(&ifidx_int) as libc::socklen_t,
        )
    };
    if ret != 0 {
        unsafe { libc::close(sock_fd) };
        anyhow::bail!(
            "setsockopt IPV6_MULTICAST_IF failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // ── Disable multicast loopback ───────────────────────────────────────────
    let no_loop: libc::c_int = 0;
    unsafe {
        libc::setsockopt(
            sock_fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_LOOP,
            &no_loop as *const _ as *const libc::c_void,
            std::mem::size_of_val(&no_loop) as libc::socklen_t,
        )
    };

    // ── Join ff02::2 (all-routers) to receive Router Solicitations ───────────
    let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: to_in6_addr(all_routers),
        ipv6mr_interface: ifindex,
    };
    let ret = unsafe {
        libc::setsockopt(
            sock_fd,
            libc::IPPROTO_IPV6,
            IPV6_JOIN_GROUP_OPT,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of_val(&mreq) as libc::socklen_t,
        )
    };
    if ret != 0 {
        unsafe { libc::close(sock_fd) };
        anyhow::bail!(
            "setsockopt IPV6_JOIN_GROUP ff02::2 on {} failed: {}",
            iface,
            std::io::Error::last_os_error()
        );
    }

    // ── ICMPv6 filter: receive only Router Solicitations (type 133) ──────────
    let mut filter = Icmp6Filter::block_all();
    filter.pass(ICMPV6_TYPE_RS);
    unsafe {
        libc::setsockopt(
            sock_fd,
            libc::IPPROTO_ICMPV6,
            ICMP6_FILTER_SOCKOPT,
            &filter as *const _ as *const libc::c_void,
            std::mem::size_of_val(&filter) as libc::socklen_t,
        )
    };

    // ── Bind to the interface's link-local address ───────────────────────────
    // This ensures RA packets are sourced from the correct link-local address.
    let mut bind_addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    bind_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    bind_addr.sin6_port = 0;
    bind_addr.sin6_addr = to_in6_addr(link_local);
    bind_addr.sin6_scope_id = ifindex;

    let ret = unsafe {
        libc::bind(
            sock_fd,
            &bind_addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        unsafe { libc::close(sock_fd) };
        anyhow::bail!(
            "bind to {}%{} failed: {}",
            link_local,
            iface,
            std::io::Error::last_os_error()
        );
    }

    Ok(sock_fd)
}

/// Send a Router Advertisement to `ff02::1` on the given interface.
fn do_send_ra(
    sock_fd: libc::c_int,
    payload: &[u8],
    ifindex: u32,
) -> anyhow::Result<()> {
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    let mut dst: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    dst.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    dst.sin6_port = 0;
    dst.sin6_addr = to_in6_addr(all_nodes);
    dst.sin6_scope_id = ifindex;

    let ret = unsafe {
        libc::sendto(
            sock_fd,
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            0,
            &dst as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "sendto ff02::1 failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Try a non-blocking receive. Returns `(bytes, src_addr)` or an `io::Error`.
fn try_recv(
    sock_fd: libc::c_int,
    buf: &mut [u8],
) -> std::io::Result<(usize, Ipv6Addr)> {
    let mut src: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut src_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let n = unsafe {
        libc::recvfrom(
            sock_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut src as *mut libc::sockaddr_in6 as *mut libc::sockaddr,
            &mut src_len,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let addr = Ipv6Addr::from(src.sin6_addr.s6_addr);
    Ok((n as usize, addr))
}

/// Fetch IA prefixes from DB and send an RA on `iface`.  Logs errors, does
/// not propagate them so a single send failure doesn't stop the server loop.
async fn send_ra(
    iface: &str,
    ifindex: u32,
    sock_fd: libc::c_int,
    db: &DynDatabase,
    ra_config: &RaConfig,
) {
    let prefixes = match db.list_ia_prefixes(Some(iface)).await {
        Ok(p) => p,
        Err(e) => {
            error!("RA: failed to list IA prefixes for {}: {}", iface, e);
            return;
        }
    };

    if prefixes.is_empty() {
        debug!("RA: no IA prefixes configured for {} – skipping RA", iface);
        return;
    }

    let payload = build_router_advertisement(
        &prefixes,
        64,
        ra_config
            .default_preferred_lifetime
            .min(u16::MAX as u32) as u16,
        false,
        false,
    );

    match do_send_ra(sock_fd, &payload, ifindex) {
        Ok(()) => debug!(
            "RA: sent Router Advertisement on {} ({} prefix(es))",
            iface,
            prefixes.len()
        ),
        Err(e) => error!("RA: send failed on {}: {}", iface, e),
    }
}

/// Main per-interface RA server loop.
async fn run_on_interface(
    iface: String,
    db: DynDatabase,
    ra_config: RaConfig,
) -> anyhow::Result<()> {
    let ifindex = get_ifindex(&iface).ok_or_else(|| {
        anyhow::anyhow!("RA: cannot resolve interface index for '{}'", iface)
    })?;

    let link_local = get_link_local_addr(&iface).ok_or_else(|| {
        anyhow::anyhow!(
            "RA: no link-local IPv6 address on '{}' – interface up and IPv6 enabled?",
            iface
        )
    })?;

    info!(
        "RA: interface {} (index {}) link-local {}",
        iface, ifindex, link_local
    );

    let sock_fd = create_ra_socket(&iface, ifindex, link_local)?;
    // Safety: we own this fd from this point; no other code will close it.
    let owned = unsafe { OwnedFd::from_raw_fd(sock_fd) };
    let async_fd = AsyncFd::new(owned)?;

    // Send an initial RA so hosts don't have to wait for the first interval.
    send_ra(&iface, ifindex, sock_fd, &db, &ra_config).await;

    let mut ra_timer = interval(Duration::from_secs(MAX_RTR_ADV_INTERVAL_SECS));
    ra_timer.tick().await; // consume the first immediate tick

    loop {
        let mut recv_buf = [0u8; 1500];

        tokio::select! {
            // ── Periodic RA ─────────────────────────────────────────────────
            _ = ra_timer.tick() => {
                send_ra(&iface, ifindex, sock_fd, &db, &ra_config).await;
            }

            // ── Receive Router Solicitation ──────────────────────────────────
            result = async_fd.readable() => {
                let mut guard = match result {
                    Ok(g) => g,
                    Err(e) => {
                        error!("RA: AsyncFd error on {}: {}", iface, e);
                        break;
                    }
                };

                // Drain all pending datagrams before yielding back.
                loop {
                    match try_recv(sock_fd, &mut recv_buf) {
                        Ok((n, src)) => {
                            // Sanity check: only act on RS (ICMP6_FILTER may not be
                            // available on all platforms, so double-check the type).
                            if n >= 1 && recv_buf[0] == ICMPV6_TYPE_RS {
                                debug!("RA: received RS from {} on {}", src, iface);
                                send_ra(&iface, ifindex, sock_fd, &db, &ra_config).await;
                            } else if n >= 1 && recv_buf[0] == ICMPV6_TYPE_RA {
                                // Our own RA looped back (shouldn't happen with
                                // IPV6_MULTICAST_LOOP=0) – silently ignore.
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            // No more pending datagrams.
                            break;
                        }
                        Err(e) => {
                            warn!("RA: recvfrom error on {}: {}", iface, e);
                            break;
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
