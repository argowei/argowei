//! Reverse DNS: a PTR query to a DNS server, normally the router, which knows
//! the names of the devices it gave addresses to (a FRITZ!Box answers for
//! `fritz.box` clients, dnsmasq and OpenWrt for their leases).
//!
//! A reverse lookup of a private address tells whichever server receives it
//! which devices exist on the network. That is fine for the router, but not
//! for a public resolver, so servers taken from the system configuration are
//! only used if they are on the local network; an explicitly configured
//! server is used as given.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use argowei_core::names::{sanitize_name, NameSource};

use super::dns::{self, TYPE_PTR};
use super::{
    ensure_local, is_local, query_id, udp_exchange, HostnameResolver, ResolveError, Target,
};

pub const DNS_PORT: u16 = 53;
/// Servers tried per lookup; a long list would only multiply the wait.
const MAX_SERVERS: usize = 2;

/// Domains a home router appends to its clients' names. Stripped from the
/// answer because `iPhone.fritz.box` is just `iPhone` to its owner.
const COMMON_LOCAL_DOMAINS: &[&str] = &[
    "fritz.box",
    "lan",
    "local",
    "localdomain",
    "home",
    "home.arpa",
    "internal",
];

pub struct RdnsResolver {
    servers: Vec<SocketAddr>,
    /// Longest first, lower case.
    local_domains: Vec<String>,
}

impl RdnsResolver {
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self::with_domains(servers, Vec::new())
    }

    /// `extra_domains` are search domains of the local network, on top of
    /// the common ones.
    pub fn with_domains(servers: Vec<SocketAddr>, extra_domains: Vec<String>) -> Self {
        let mut local_domains: Vec<String> = COMMON_LOCAL_DOMAINS
            .iter()
            .map(|d| (*d).to_owned())
            .chain(extra_domains.into_iter().map(|d| d.to_lowercase()))
            .collect();
        local_domains.sort_by_key(|d| std::cmp::Reverse(d.len()));
        local_domains.dedup();
        Self {
            servers,
            local_domains,
        }
    }

    /// The local nameservers and search domains from `/etc/resolv.conf`.
    pub fn from_system() -> Self {
        let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        Self::with_domains(local_nameservers(&text), search_domains(&text))
    }

    /// `iPhone.fritz.box` is called `iPhone`; a name that is the domain itself
    /// (`fritz.box`, the router) is kept whole.
    fn strip_local_domain<'a>(&self, name: &'a str) -> &'a str {
        let name = name.trim_end_matches('.');
        self.local_domains
            .iter()
            .find_map(|domain| {
                let cut = name.len().checked_sub(domain.len() + 1)?;
                let (host, tail) = name.split_at_checked(cut)?;
                let matches = tail.starts_with('.') && tail[1..].eq_ignore_ascii_case(domain);
                (matches && !host.is_empty()).then_some(host)
            })
            .unwrap_or(name)
    }

    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }
}

/// The domains named by `search` and `domain` lines of a resolv.conf.
pub fn search_domains(resolv_conf: &str) -> Vec<String> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            matches!(words.next()?, "search" | "domain").then_some(words)
        })
        .flatten()
        .map(|d| d.trim_end_matches('.').to_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

/// `nameserver` lines of a resolv.conf that point at the local network.
/// Public resolvers are skipped (see the module documentation), and so are
/// IPv6 servers, which this resolver does not speak to.
pub fn local_nameservers(resolv_conf: &str) -> Vec<SocketAddr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver").then(|| words.next())?
        })
        .filter_map(|address| address.parse::<Ipv4Addr>().ok())
        .filter(|ip| is_local(*ip))
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), DNS_PORT))
        .take(MAX_SERVERS)
        .collect()
}

impl HostnameResolver for RdnsResolver {
    fn source(&self) -> NameSource {
        NameSource::Rdns
    }

    fn resolve(&self, target: &Target, timeout: Duration) -> Result<Option<String>, ResolveError> {
        ensure_local(target.ip)?;
        let id = query_id(target.ip);
        let query = dns::build_query(id, &dns::reverse_name(target.ip), TYPE_PTR, true)?;
        let deadline = Instant::now() + timeout;

        let mut last_error = None;
        for (index, server) in self.servers.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            // A silent server must not use up the time meant for the next one.
            let servers_left = u32::try_from(self.servers.len() - index).unwrap_or(1);
            let attempt = udp_exchange(*server, &query, remaining / servers_left, |packet| {
                dns::is_response_to(packet, id)
            })
            .and_then(|reply| match reply {
                None => Ok(None),
                Some(packet) => Ok(dns::parse_ptr_response(&packet, id)?
                    .iter()
                    .filter_map(|name| {
                        sanitize_name(self.strip_local_domain(name), Some(target.ip))
                    })
                    .next()),
            });

            match attempt {
                Ok(Some(name)) => return Ok(Some(name)),
                Ok(None) => {}
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) if self.servers.len() == 1 => Err(error),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::testing::{answer_once, ptr_response, target};

    #[test]
    fn only_local_nameservers_are_taken_from_resolv_conf() {
        let text = "\
# generated by NetworkManager
search fritz.box
nameserver 192.168.178.1
nameserver 8.8.8.8
nameserver 10.0.0.53
nameserver 2001:4860:4860::8888
nameserver 127.0.0.53
";

        let servers = local_nameservers(text);

        // The public and IPv6 servers are skipped; two local ones are used at most.
        assert_eq!(
            servers,
            [
                "192.168.178.1:53".parse().unwrap(),
                "10.0.0.53:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn a_resolv_conf_with_no_usable_server_yields_none() {
        assert!(local_nameservers("").is_empty());
        assert!(local_nameservers("nameserver 1.1.1.1\nnameserver ::1\n").is_empty());
        assert!(local_nameservers("options edns0\nnameserver\n").is_empty());
    }

    fn resolver() -> RdnsResolver {
        RdnsResolver::with_domains(Vec::new(), vec!["Example.Org".into()])
    }

    #[test]
    fn the_local_domain_is_stripped_from_a_hostname() {
        let r = resolver();

        assert_eq!(r.strip_local_domain("iPhone.fritz.box"), "iPhone");
        assert_eq!(r.strip_local_domain("printer.lan"), "printer");
        assert_eq!(r.strip_local_domain("NAS.FRITZ.BOX"), "NAS");
        assert_eq!(r.strip_local_domain("tv.home.arpa"), "tv");
        assert_eq!(
            r.strip_local_domain("host.example.org."),
            "host",
            "search domains count, case-insensitively"
        );
        assert_eq!(r.strip_local_domain("a.b.fritz.box"), "a.b");
    }

    #[test]
    fn a_name_that_is_the_domain_itself_is_kept() {
        let r = resolver();

        assert_eq!(r.strip_local_domain("fritz.box"), "fritz.box");
        assert_eq!(r.strip_local_domain("lan"), "lan");
        assert_eq!(r.strip_local_domain(".lan"), ".lan");
    }

    #[test]
    fn other_domains_and_lookalikes_are_left_alone() {
        let r = resolver();

        assert_eq!(r.strip_local_domain("host.example.com"), "host.example.com");
        assert_eq!(r.strip_local_domain("notfritz.box"), "notfritz.box");
        assert_eq!(r.strip_local_domain("hostlan"), "hostlan");
        assert_eq!(
            r.strip_local_domain("ünï.lan"),
            "ünï",
            "multi-byte names are handled"
        );
    }

    #[test]
    fn search_domains_are_read_from_resolv_conf() {
        let text = "# generated\nsearch fritz.box Example.org.\ndomain corp.example\nnameserver 192.168.1.1\noptions edns0\n";

        assert_eq!(
            search_domains(text),
            ["fritz.box", "example.org", "corp.example"]
        );
        assert!(search_domains("nameserver 1.1.1.1").is_empty());
        assert!(search_domains("search\n").is_empty());
    }

    #[test]
    fn the_server_is_asked_and_the_name_is_returned() {
        let port =
            answer_once(|request| Some(ptr_response(request, b"\x0cannas-iphone\x03lan\x00")));
        let resolver = RdnsResolver::new(vec![format!("127.0.0.1:{port}").parse().unwrap()]);

        let name = resolver
            .resolve(&target("127.0.0.1"), Duration::from_secs(2))
            .unwrap();

        assert_eq!(name.as_deref(), Some("annas-iphone"));
    }

    #[test]
    fn the_query_asks_for_recursion() {
        let (seen, received) = std::sync::mpsc::channel();
        let port = answer_once(move |request| {
            seen.send(request.to_vec()).unwrap();
            Some(ptr_response(request, b"\x04host\x00"))
        });
        let resolver = RdnsResolver::new(vec![format!("127.0.0.1:{port}").parse().unwrap()]);

        assert!(resolver
            .resolve(&target("127.0.0.1"), Duration::from_secs(2))
            .unwrap()
            .is_some());
        assert_eq!(
            received.recv().unwrap()[2] & 0x01,
            1,
            "recursion desired must be set"
        );
    }

    #[test]
    fn a_second_server_is_tried_when_the_first_stays_silent() {
        let silent = answer_once(|_| None);
        let helpful = answer_once(|request| Some(ptr_response(request, b"\x07printer\x03lan\x00")));
        let resolver = RdnsResolver::new(vec![
            format!("127.0.0.1:{silent}").parse().unwrap(),
            format!("127.0.0.1:{helpful}").parse().unwrap(),
        ]);

        let name = resolver
            .resolve(&target("127.0.0.1"), Duration::from_secs(3))
            .unwrap();

        assert_eq!(name.as_deref(), Some("printer"));
    }

    #[test]
    fn no_record_means_no_name() {
        let port = answer_once(|request| {
            let mut response = ptr_response(request, b"\x04host\x00");
            response[3] = 0x83; // NXDOMAIN
            response[7] = 0;
            Some(response)
        });
        let resolver = RdnsResolver::new(vec![format!("127.0.0.1:{port}").parse().unwrap()]);

        assert_eq!(
            resolver
                .resolve(&target("127.0.0.1"), Duration::from_secs(2))
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_generated_name_that_only_spells_out_the_address_is_dropped() {
        let port = answer_once(|request| Some(ptr_response(request, b"\x09127-0-0-1\x03lan\x00")));
        let resolver = RdnsResolver::new(vec![format!("127.0.0.1:{port}").parse().unwrap()]);

        assert_eq!(
            resolver
                .resolve(&target("127.0.0.1"), Duration::from_secs(2))
                .unwrap(),
            None
        );
    }

    #[test]
    fn without_any_server_there_is_nothing_to_ask() {
        let resolver = RdnsResolver::new(Vec::new());

        assert_eq!(
            resolver
                .resolve(&target("127.0.0.1"), Duration::from_secs(1))
                .unwrap(),
            None
        );
    }

    #[test]
    fn a_server_that_never_answers_runs_into_the_timeout_not_forever() {
        let port = answer_once(|_| None);
        let resolver = RdnsResolver::new(vec![format!("127.0.0.1:{port}").parse().unwrap()]);
        let started = Instant::now();

        let name = resolver
            .resolve(&target("127.0.0.1"), Duration::from_millis(200))
            .unwrap();

        assert_eq!(name, None);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
