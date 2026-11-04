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
mod tests {
    use super::*;
    use crate::names::testing::target_with_mac;

    /// A dnsmasq lease file as the daemon writes it, including a DHCPv6 lease
    /// and the `duid` header that must be skipped.
    const LEASES: &str = "\
1735689600 aa:bb:cc:dd:ee:01 192.168.1.5 annas-iphone 01:aa:bb:cc:dd:ee:01
1735689700 AA:BB:CC:DD:EE:02 192.168.1.6 * 01:aa:bb:cc:dd:ee:02
1735689800 aa:bb:cc:dd:ee:03 192.168.1.7 192-168-1-7 *
0 aa:bb:cc:dd:ee:04 192.168.1.8 media-server *
duid 00:01:00:01:2a:3b:4c:5d:aa:bb:cc:dd:ee:ff
1735689900 1234567 fd00::5 laptop 00:02:00:00:ab:11:cc:dd
not a lease line
";

    #[test]
    fn leases_are_parsed_and_foreign_lines_skipped() {
        let leases = parse_leases(LEASES);

        assert_eq!(leases.len(), 4);
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(
            leases[0].ip,
            "192.168.1.5".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(leases[0].hostname.as_deref(), Some("annas-iphone"));
        assert_eq!(
            leases[1].mac, "aa:bb:cc:dd:ee:02",
            "MACs are normalized to lower case"
        );
        assert_eq!(leases[1].hostname, None, "a star means no hostname");
        assert_eq!(
            leases[3].hostname.as_deref(),
            Some("media-server"),
            "an expiry of 0 is a static lease"
        );
    }

    #[test]
    fn an_empty_file_has_no_leases() {
        assert!(parse_leases("").is_empty());
        assert!(parse_leases("\n\n").is_empty());
    }

    fn resolver_with(contents: &str) -> (DhcpLeaseResolver, tempdir::Dir) {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("dhcp.leases");
        std::fs::write(&path, contents).unwrap();
        (DhcpLeaseResolver::new(path), dir)
    }

    fn name_of(resolver: &DhcpLeaseResolver, ip: &str, mac: &str) -> Option<String> {
        resolver
            .resolve(&target_with_mac(ip, mac), Duration::from_secs(1))
            .unwrap()
    }

    #[test]
    fn a_device_is_found_by_its_mac_address() {
        let (resolver, _dir) = resolver_with(LEASES);

        assert_eq!(
            name_of(&resolver, "192.168.1.5", "AA:BB:CC:DD:EE:01").as_deref(),
            Some("annas-iphone")
        );
    }

    #[test]
    fn the_mac_wins_over_a_stale_ip_when_the_address_changed() {
        let (resolver, _dir) = resolver_with(LEASES);

        // The device got a new address; the lease for its MAC is still its own.
        assert_eq!(
            name_of(&resolver, "192.168.1.99", "aa:bb:cc:dd:ee:01").as_deref(),
            Some("annas-iphone")
        );
    }

    #[test]
    fn the_address_is_the_fallback_when_the_mac_is_unknown() {
        let (resolver, _dir) = resolver_with(LEASES);

        assert_eq!(
            name_of(&resolver, "192.168.1.8", "00:00:00:00:00:00").as_deref(),
            Some("media-server")
        );
    }

    #[test]
    fn a_lease_without_hostname_or_with_a_generated_one_gives_no_name() {
        let (resolver, _dir) = resolver_with(LEASES);

        assert_eq!(name_of(&resolver, "192.168.1.6", "aa:bb:cc:dd:ee:02"), None);
        assert_eq!(name_of(&resolver, "192.168.1.7", "aa:bb:cc:dd:ee:03"), None);
    }

    #[test]
    fn an_unknown_device_has_no_name() {
        let (resolver, _dir) = resolver_with(LEASES);

        assert_eq!(
            name_of(&resolver, "192.168.1.200", "aa:bb:cc:dd:ee:ff"),
            None
        );
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_crash() {
        let resolver = DhcpLeaseResolver::new("/nonexistent/dhcp.leases");

        let result = resolver.resolve(
            &target_with_mac("192.168.1.5", "aa:bb:cc:dd:ee:01"),
            Duration::from_secs(1),
        );

        assert!(matches!(result, Err(ResolveError::Io(_))));
    }

    #[test]
    fn changes_to_the_file_are_picked_up() {
        let (resolver, dir) = resolver_with("0 aa:bb:cc:dd:ee:01 192.168.1.5 old-name *\n");
        assert_eq!(
            name_of(&resolver, "192.168.1.5", "aa:bb:cc:dd:ee:01").as_deref(),
            Some("old-name")
        );

        let path = dir.path().join("dhcp.leases");
        std::fs::write(&path, "0 aa:bb:cc:dd:ee:01 192.168.1.5 new-name *\n").unwrap();
        // Make sure the modification time differs even on coarse file systems.
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(SystemTime::now() + Duration::from_secs(5))
            .unwrap();

        assert_eq!(
            name_of(&resolver, "192.168.1.5", "aa:bb:cc:dd:ee:01").as_deref(),
            Some("new-name")
        );
    }

    /// A throwaway directory removed when dropped (no extra dependency).
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                static COUNTER: AtomicUsize = AtomicUsize::new(0);
                let path = std::env::temp_dir().join(format!(
                    "argowei-dhcp-test-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
