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

    fn resolve(&self, target: &Target, _timeout: Duration) -> Result<Option<String>, ResolveError> {
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
