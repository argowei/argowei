//! Names from a DHCP server's lease file. The lease records the hostname a
//! device sent when it asked for its address, which makes it the most
//! reliable name there is, but only if the file is readable from here: it
//! lives on the router or a Pi-hole/dnsmasq host, so this needs the file
//! mounted or copied to the machine Argowei runs on.
//!
//! Format (dnsmasq, `dhcp.leases`), one lease per line:
//!
//! ```text
//! 1735689600 aa:bb:cc:dd:ee:ff 192.168.1.5 annas-iphone 01:aa:bb:cc:dd:ee:ff
//! <expiry>   <mac>             <ip>        <hostname>   <client id>
//! ```
//!
//! A hostname of `*` means the device did not send one. Lines of another
//! shape (DHCPv6 leases, the `duid` header) are skipped.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use argowei_core::names::{sanitize_name, NameSource};

use super::{HostnameResolver, ResolveError, Target};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Lower case, colon separated.
    pub mac: String,
    pub ip: std::net::Ipv4Addr,
    pub hostname: Option<String>,
}

pub fn parse_leases(text: &str) -> Vec<Lease> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _expiry = fields.next()?;
            let mac = fields.next()?.to_lowercase();
            let ip = fields.next()?.parse().ok()?;
            let hostname = fields.next().filter(|name| *name != "*").map(str::to_owned);

            // DHCPv6 lines carry an IAID there instead of a MAC address.
            let is_mac = mac.split(':').count() == 6
                && mac
                    .split(':')
                    .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()));
            is_mac.then_some(Lease { mac, ip, hostname })
        })
        .collect()
}

struct Cached {
    modified: SystemTime,
    leases: Arc<Vec<Lease>>,
}

pub struct DhcpLeaseResolver {
    path: PathBuf,
    cache: Mutex<Option<Cached>>,
}

impl DhcpLeaseResolver {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache: Mutex::new(None),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The leases, re-read only when the file has changed.
    fn leases(&self) -> Result<Arc<Vec<Lease>>, ResolveError> {
        let modified = std::fs::metadata(&self.path)?.modified()?;
        let mut cache = self.cache.lock().expect("lease cache poisoned");

        if let Some(cached) = cache.as_ref().filter(|c| c.modified == modified) {
            return Ok(Arc::clone(&cached.leases));
        }
        let leases = Arc::new(parse_leases(&std::fs::read_to_string(&self.path)?));
        *cache = Some(Cached {
            modified,
            leases: Arc::clone(&leases),
        });
        Ok(leases)
    }
}

impl HostnameResolver for DhcpLeaseResolver {
    fn source(&self) -> NameSource {
        NameSource::Dhcp
    }

    /// Looks the device up by MAC address, which survives an address change,
    /// and falls back to its IP address.
    fn resolve(&self, target: &Target, _timeout: Duration) -> Result<Option<String>, ResolveError> {
        let leases = self.leases()?;
        let mac = target.mac.to_lowercase();

        let lease = leases
            .iter()
            .find(|lease| lease.mac == mac)
            .or_else(|| leases.iter().find(|lease| lease.ip == target.ip));

        Ok(lease
            .and_then(|lease| lease.hostname.as_deref())
            .and_then(|name| sanitize_name(name, Some(target.ip))))
    }
}

#[cfg(test)]
mod tests;
