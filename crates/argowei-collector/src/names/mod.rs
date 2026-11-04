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
pub use mdns::MdnsResolver;
pub use netbios::NetbiosResolver;
pub use rdns::{local_nameservers, search_domains, RdnsResolver};

/// Largest DNS or NetBIOS datagram worth reading; replies are far smaller.
const MAX_DATAGRAM: usize = 1500;

/// A device to find a name for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ip: Ipv4Addr,
    /// Lower case, colon separated.
    pub mac: String,
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

impl std::error::Error for ResolveError {}

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
pub(crate) mod testing {
    use std::net::UdpSocket;
    use std::time::Duration;

    use super::{dns, Target};

    pub fn target(ip: &str) -> Target {
        target_with_mac(ip, "aa:bb:cc:dd:ee:01")
    }

    pub fn target_with_mac(ip: &str, mac: &str) -> Target {
        Target {
            ip: ip.parse().unwrap(),
            mac: mac.to_owned(),
        }
    }

    /// A UDP "device" on loopback that reads one request and answers it with
    /// whatever `handler` returns (`None` = stay silent). Returns its port.
    pub fn answer_once(handler: impl FnOnce(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let mut buffer = [0u8; 1500];
            if let Ok((length, from)) = socket.recv_from(&mut buffer) {
                if let Some(reply) = handler(&buffer[..length]) {
                    let _ = socket.send_to(&reply, from);
                }
            }
        });
        port
    }

    /// A PTR response to `request`: it repeats the question, and the answer
    /// points back at it, as DNS servers compress. `target_labels` is the
    /// answer's target in label form.
    pub fn ptr_response(request: &[u8], target_labels: &[u8]) -> Vec<u8> {
        let mut packet = request[..2].to_vec(); // same id
        packet.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(&request[12..]); // the question
        packet.extend_from_slice(&[0xc0, 0x0c, 0, dns::TYPE_PTR as u8, 0, 1, 0, 0, 0, 120]);
        packet.extend_from_slice(&(target_labels.len() as u16).to_be_bytes());
        packet.extend_from_slice(target_labels);
        packet
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::testing::target;
    use super::*;

    /// Answers with a fixed result and records how it was used.
    struct Fake {
        source: NameSource,
        result: fn(&Target) -> Result<Option<String>, ResolveError>,
        delay: Duration,
        running: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl Fake {
        fn new(
            source: NameSource,
            result: fn(&Target) -> Result<Option<String>, ResolveError>,
        ) -> Self {
            Self {
                source,
                result,
                delay: Duration::ZERO,
                running: Arc::default(),
                peak: Arc::default(),
            }
        }
    }

    impl HostnameResolver for Fake {
        fn source(&self) -> NameSource {
            self.source
        }

        fn resolve(
            &self,
            target: &Target,
            _timeout: Duration,
        ) -> Result<Option<String>, ResolveError> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            self.running.fetch_sub(1, Ordering::SeqCst);
            (self.result)(target)
        }
    }

    fn named(target: &Target) -> Result<Option<String>, ResolveError> {
        Ok(Some(format!("host-{}", target.ip.octets()[3])))
    }

    fn failing(_: &Target) -> Result<Option<String>, ResolveError> {
        Err(ResolveError::Malformed("boom"))
    }

    fn silent(_: &Target) -> Result<Option<String>, ResolveError> {
        Ok(None)
    }

    fn crashing(_: &Target) -> Result<Option<String>, ResolveError> {
        panic!("resolver bug")
    }

    fn targets(count: u8) -> Vec<Target> {
        (1..=count)
            .map(|n| target(&format!("192.168.1.{n}")))
            .collect()
    }

    fn arc(fake: Fake) -> Arc<dyn HostnameResolver> {
        Arc::new(fake)
    }

    #[test]
    fn every_answer_keeps_the_source_it_came_from() {
        let resolvers = [
            arc(Fake::new(NameSource::Mdns, named)),
            arc(Fake::new(NameSource::Rdns, named)),
        ];

        let result = resolve_all(&resolvers, &targets(1), Duration::from_secs(1), 4);

        assert_eq!(
            result[0].names,
            [
                ResolvedName {
                    source: NameSource::Mdns,
                    name: "host-1".into()
                },
                ResolvedName {
                    source: NameSource::Rdns,
                    name: "host-1".into()
                },
            ]
        );
        assert!(result[0].errors.is_empty());
    }

    #[test]
    fn results_come_back_in_target_order() {
        let resolvers = [arc(Fake::new(NameSource::Mdns, named))];

        let result = resolve_all(&resolvers, &targets(20), Duration::from_secs(1), 8);

        let order: Vec<_> = result.iter().map(|r| r.target.ip.octets()[3]).collect();
        assert_eq!(order, (1..=20).collect::<Vec<_>>());
    }

    #[test]
    fn a_failing_resolver_does_not_cost_the_others_their_answers() {
        let resolvers = [
            arc(Fake::new(NameSource::Dhcp, failing)),
            arc(Fake::new(NameSource::Mdns, named)),
            arc(Fake::new(NameSource::Netbios, silent)),
        ];

        let result = resolve_all(&resolvers, &targets(2), Duration::from_secs(1), 2);

        assert_eq!(result.len(), 2);
        for outcome in &result {
            assert_eq!(outcome.names.len(), 1);
            assert_eq!(outcome.names[0].source, NameSource::Mdns);
            assert_eq!(outcome.errors.len(), 1);
            assert_eq!(outcome.errors[0].0, NameSource::Dhcp);
            assert!(outcome.errors[0].1.contains("boom"));
        }
    }

    #[test]
    fn a_resolver_that_panics_only_loses_its_own_answer() {
        let resolvers = [
            arc(Fake::new(NameSource::Mdns, crashing)),
            arc(Fake::new(NameSource::Rdns, named)),
        ];

        let result = resolve_all(&resolvers, &targets(3), Duration::from_secs(1), 3);

        assert_eq!(result.len(), 3, "every target still has a result");
        assert!(result
            .iter()
            .all(|r| r.names.len() == 1 && r.names[0].source == NameSource::Rdns));
        assert!(result.iter().all(|r| r.errors[0].1.contains("crashed")));
    }

    #[test]
    fn no_more_queries_run_at_once_than_the_limit_allows() {
        let mut slow = Fake::new(NameSource::Mdns, named);
        slow.delay = Duration::from_millis(30);
        let peak = Arc::clone(&slow.peak);
        let resolvers = [arc(slow)];

        let result = resolve_all(&resolvers, &targets(24), Duration::from_secs(1), 3);

        assert_eq!(result.len(), 24);
        assert!(
            peak.load(Ordering::SeqCst) <= 3,
            "peak {}",
            peak.load(Ordering::SeqCst)
        );
        assert!(
            peak.load(Ordering::SeqCst) >= 2,
            "the limit should actually be used"
        );
    }

    #[test]
    fn a_limit_of_zero_still_makes_progress() {
        let resolvers = [arc(Fake::new(NameSource::Mdns, named))];

        assert_eq!(
            resolve_all(&resolvers, &targets(3), Duration::from_secs(1), 0).len(),
            3
        );
    }

    #[test]
    fn nothing_to_resolve_yields_nothing() {
        let resolvers = [arc(Fake::new(NameSource::Mdns, named))];

        assert!(resolve_all(&resolvers, &[], Duration::from_secs(1), 4).is_empty());
        assert_eq!(
            resolve_all(&[], &targets(2), Duration::from_secs(1), 4).len(),
            2
        );
    }

    #[test]
    fn only_the_local_network_is_asked() {
        for local in [
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.1.1",
            "127.0.0.1",
        ] {
            assert!(is_local(local.parse().unwrap()), "{local}");
        }
        for public in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.64.0.1"] {
            assert!(!is_local(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn a_real_resolver_refuses_a_public_address() {
        let resolver = MdnsResolver::default();

        let result = resolver.resolve(&target("8.8.8.8"), Duration::from_millis(100));

        assert!(matches!(result, Err(ResolveError::NotLocal(_))));
    }
}
