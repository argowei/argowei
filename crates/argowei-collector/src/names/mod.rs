//! Finding out what devices call themselves.
//!
//! Each source (DHCP leases, mDNS, NetBIOS, reverse DNS) is a
//! [`HostnameResolver`]. They are asked per device, with a per-query timeout,
//! and the whole batch runs on a bounded number of threads, in the same spirit
//! as the ARP scan: paced, bounded and never more traffic than needed. A
//! resolver that fails, times out or even panics only loses its own answer.

mod dhcp;
mod dns;
mod mdns;
mod netbios;
mod rdns;

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use argowei_core::names::NameSource;
pub use dhcp::{parse_leases, DhcpLeaseResolver, Lease};
pub use dns::DnsError;
pub use mdns::{MdnsResolver, MDNS_PORT};
pub use netbios::{NetbiosResolver, NETBIOS_PORT};
pub use rdns::{local_nameservers, search_domains, RdnsResolver, DNS_PORT};

/// Largest DNS or NetBIOS datagram worth reading; replies are far smaller.
const MAX_DATAGRAM: usize = 1500;

/// A device to find a name for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    /// Lower case, colon separated; empty when not known (see
    /// [`Target::without_mac`]).
    pub mac: String,
}

impl Target {
    /// A device known only by its address, e.g. one named on the command
    /// line without a scan. Sources keyed by MAC (the DHCP leases) then
    /// match by IP alone.
    pub fn without_mac(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            mac: String::new(),
        }
    }
}

#[derive(Debug)]
pub enum ResolveError {
    Io(io::Error),
    Dns(DnsError),
    Malformed(&'static str),
    /// Queries only go to the local network.
    NotLocal(Ipv4Addr),
    /// The resolver panicked; the batch carried on without it.
    Crashed,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Dns(error) => write!(f, "{error}"),
            Self::Malformed(what) => write!(f, "malformed answer: {what}"),
            Self::NotLocal(ip) => write!(f, "{ip} is not on the local network"),
            Self::Crashed => write!(f, "resolver crashed"),
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            // `Dns` displays its inner error as is; reporting it as the
            // source too would print the message twice.
            _ => None,
        }
    }
}

impl From<io::Error> for ResolveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DnsError> for ResolveError {
    fn from(error: DnsError) -> Self {
        Self::Dns(error)
    }
}

/// One way of learning a device's name.
pub trait HostnameResolver: Send + Sync {
    fn source(&self) -> NameSource;

    /// `Ok(None)` means the source has no (usable) name for this device,
    /// including "the device did not answer" and "the answer was a
    /// placeholder". `Err` means the lookup itself went wrong.
    fn resolve(&self, target: &Target, timeout: Duration) -> Result<Option<String>, ResolveError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    pub source: NameSource,
    pub name: String,
}

/// Everything learned about one target.
#[derive(Debug)]
pub struct TargetNames {
    pub target: Target,
    pub names: Vec<ResolvedName>,
    /// Resolvers whose lookup failed; informational, never fatal.
    pub errors: Vec<(NameSource, String)>,
}

/// Asks every resolver about every target, on at most `max_concurrency`
/// threads, each query limited by `timeout`. The result is in target order.
pub fn resolve_all(
    resolvers: &[Arc<dyn HostnameResolver>],
    targets: &[Target],
    timeout: Duration,
    max_concurrency: usize,
) -> Vec<TargetNames> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<TargetNames>>> =
        Mutex::new((0..targets.len()).map(|_| None).collect());
    let workers = max_concurrency.clamp(1, targets.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(target) = targets.get(index) else {
                    break;
                };
                let outcome = resolve_one(resolvers, target, timeout);
                results.lock().expect("results poisoned")[index] = Some(outcome);
            });
        }
    });

    results
        .into_inner()
        .expect("results poisoned")
        .into_iter()
        .flatten()
        .collect()
}

fn resolve_one(
    resolvers: &[Arc<dyn HostnameResolver>],
    target: &Target,
    timeout: Duration,
) -> TargetNames {
    let mut names = Vec::new();
    let mut errors = Vec::new();

    for resolver in resolvers {
        let source = resolver.source();
        // A resolver bug must not take the thread, and with it the batch, down.
        let outcome = catch_unwind(AssertUnwindSafe(|| resolver.resolve(target, timeout)))
            .unwrap_or(Err(ResolveError::Crashed));
        match outcome {
            Ok(Some(name)) => names.push(ResolvedName { source, name }),
            Ok(None) => {}
            Err(error) => errors.push((source, error.to_string())),
        }
    }

    TargetNames {
        target: target.clone(),
        names,
        errors,
    }
}

// --- shared plumbing ------------------------------------------------------

/// Private, link-local or loopback: the only places a name query may go.
pub fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || ip.is_loopback()
}

fn ensure_local(ip: Ipv4Addr) -> Result<(), ResolveError> {
    if is_local(ip) {
        Ok(())
    } else {
        Err(ResolveError::NotLocal(ip))
    }
}

/// A query id that differs between devices and over time. It only has to
/// match a reply to its query (replies must come from the address we asked,
/// as the socket is connected), not to be secret.
fn query_id(ip: Ipv4Addr) -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    (nanos ^ (nanos >> 16) ^ u32::from(ip)) as u16
}

/// Sends one datagram and waits up to `timeout` for a reply that passes
/// `accept`. The socket is connected, so only the asked address can answer,
/// and a closed port is reported at once instead of after the timeout.
///
/// `Ok(None)` covers silence, a refused port, and replies that were not for
/// this query; none of those is an error.
fn udp_exchange(
    destination: SocketAddr,
    request: &[u8],
    timeout: Duration,
    accept: impl Fn(&[u8]) -> bool,
) -> Result<Option<Vec<u8>>, ResolveError> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.connect(destination)?;
    socket.send(request)?;

    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; MAX_DATAGRAM];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        socket.set_read_timeout(Some(remaining))?;

        match socket.recv(&mut buffer) {
            Ok(length) if accept(&buffer[..length]) => return Ok(Some(buffer[..length].to_vec())),
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod fixtures;

#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests;
