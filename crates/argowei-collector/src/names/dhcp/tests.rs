use super::*;
use crate::names::testing::{target_with_mac, TempDir};

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

fn resolver_with(contents: &str) -> (DhcpLeaseResolver, TempDir) {
    let dir = TempDir::new();
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
