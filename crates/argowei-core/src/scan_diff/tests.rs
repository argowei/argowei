use super::*;

fn port(spec: &str) -> PortObservation {
    // "22/tcp open ssh OpenSSH 9.6", fields after the state are optional.
    let mut parts = spec.split_whitespace();
    let (number, protocol) = parts.next().unwrap().split_once('/').unwrap();
    PortObservation {
        protocol: protocol.to_owned(),
        port: number.parse().unwrap(),
        state: parts.next().unwrap().to_owned(),
        service: parts.next().map(str::to_owned),
        product: parts.next().map(str::to_owned),
        version: parts.next().map(str::to_owned),
    }
}

fn ports(specs: &[&str]) -> Vec<PortObservation> {
    specs.iter().map(|s| port(s)).collect()
}

fn coverage(services: &str) -> PortCoverage {
    let mut c = PortCoverage::default();
    c.add_services("tcp", services).unwrap();
    c
}

struct Case {
    name: &'static str,
    before: Vec<&'static str>,
    after: Vec<&'static str>,
    opened: Vec<u16>,
    closed: Vec<u16>,
    changed: Vec<u16>,
    unchanged: usize,
}

/// Every state transition of a port both scans covered.
#[test]
fn transitions_between_two_full_coverage_scans() {
    let cases = [
        Case {
            name: "nothing open either time",
            before: vec![],
            after: vec![],
            opened: vec![],
            closed: vec![],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "a port opens",
            before: vec![],
            after: vec!["22/tcp open ssh"],
            opened: vec![22],
            closed: vec![],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "a port closes",
            before: vec!["22/tcp open ssh"],
            after: vec![],
            opened: vec![],
            closed: vec![22],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "open to explicitly closed",
            before: vec!["22/tcp open ssh"],
            after: vec!["22/tcp closed"],
            opened: vec![],
            closed: vec![22],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "filtered to open",
            before: vec!["22/tcp filtered"],
            after: vec!["22/tcp open ssh"],
            opened: vec![22],
            closed: vec![],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "open to filtered",
            before: vec!["22/tcp open ssh"],
            after: vec!["22/tcp filtered"],
            opened: vec![],
            closed: vec![22],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "closed to filtered is not news",
            before: vec!["22/tcp closed"],
            after: vec!["22/tcp filtered"],
            opened: vec![],
            closed: vec![],
            changed: vec![],
            unchanged: 0,
        },
        Case {
            name: "stays open",
            before: vec!["22/tcp open ssh"],
            after: vec!["22/tcp open ssh"],
            opened: vec![],
            closed: vec![],
            changed: vec![],
            unchanged: 1,
        },
        Case {
            name: "several at once, sorted",
            before: vec!["80/tcp open http", "22/tcp open ssh", "443/tcp open https"],
            after: vec![
                "443/tcp open https",
                "8080/tcp open http-proxy",
                "21/tcp open ftp",
            ],
            opened: vec![21, 8080],
            closed: vec![22, 80],
            changed: vec![],
            unchanged: 1,
        },
    ];

    let all = PortCoverage::all("tcp");
    for case in cases {
        let (before, after) = (ports(&case.before), ports(&case.after));
        let d = diff(
            &ScanSide {
                profile: ScanProfile::Full,
                target: "192.168.1.5",
                coverage: &all,
                ports: &before,
            },
            &ScanSide {
                profile: ScanProfile::Full,
                target: "192.168.1.5",
                coverage: &all,
                ports: &after,
            },
        );
        let numbers = |v: &[PortChange]| v.iter().map(|c| c.port).collect::<Vec<_>>();
        assert_eq!(numbers(&d.opened), case.opened, "{}: opened", case.name);
        assert_eq!(numbers(&d.closed), case.closed, "{}: closed", case.name);
        assert_eq!(
            d.changed.iter().map(|c| c.port).collect::<Vec<_>>(),
            case.changed,
            "{}",
            case.name
        );
        assert_eq!(d.unchanged, case.unchanged, "{}: unchanged", case.name);
        assert!(d.not_comparable.is_empty() && !d.profile_mismatch && d.address_changed.is_none());
        assert_eq!(
            d.is_empty(),
            case.opened.is_empty() && case.closed.is_empty(),
            "{}",
            case.name
        );
    }
}

#[test]
fn service_changes_need_evidence_on_both_sides() {
    let all = PortCoverage::all("tcp");
    let check = |before: &str, after: &str, expected: bool| {
        let (b, a) = (ports(&[before]), ports(&[after]));
        let d = diff(
            &ScanSide {
                profile: ScanProfile::Service,
                target: "10.0.0.1",
                coverage: &all,
                ports: &b,
            },
            &ScanSide {
                profile: ScanProfile::Service,
                target: "10.0.0.1",
                coverage: &all,
                ports: &a,
            },
        );
        assert_eq!(!d.changed.is_empty(), expected, "{before} -> {after}");
        assert_eq!(d.unchanged, usize::from(!expected), "{before} -> {after}");
    };

    check(
        "22/tcp open ssh OpenSSH 9.6",
        "22/tcp open ssh OpenSSH 9.7",
        true,
    );
    check(
        "22/tcp open ssh OpenSSH 9.6",
        "22/tcp open ssh Dropbear 2024.85",
        true,
    );
    check("80/tcp open http", "80/tcp open ssh", true);
    check(
        "22/tcp open ssh OpenSSH 9.6",
        "22/tcp open ssh OpenSSH 9.6",
        false,
    );
    // One side only guessed the name from the port number: no evidence.
    check("80/tcp open http", "80/tcp open http nginx 1.27", false);
    check("80/tcp open http nginx 1.27", "80/tcp open http", false);
    check("80/tcp open", "80/tcp open http", false);

    let (b, a) = (
        ports(&["22/tcp open ssh OpenSSH 9.6"]),
        ports(&["22/tcp open ssh OpenSSH 9.7"]),
    );
    let d = diff(
        &ScanSide {
            profile: ScanProfile::Service,
            target: "10.0.0.1",
            coverage: &all,
            ports: &b,
        },
        &ScanSide {
            profile: ScanProfile::Service,
            target: "10.0.0.1",
            coverage: &all,
            ports: &a,
        },
    );
    assert_eq!(d.changed[0].before.version.as_deref(), Some("9.6"));
    assert_eq!(d.changed[0].after.version.as_deref(), Some("9.7"));
}

#[test]
fn ports_outside_the_other_scans_coverage_are_not_comparable() {
    // A quick scan looked at 22 and 80 only; the full scan at everything.
    let quick = coverage("22,80");
    let full = PortCoverage::all("tcp");
    let quick_ports = ports(&["22/tcp open ssh"]);
    let full_ports = ports(&[
        "22/tcp open ssh",
        "8443/tcp open https-alt",
        "80/tcp open http",
    ]);

    let d = diff(
        &ScanSide {
            profile: ScanProfile::Quick,
            target: "10.0.0.1",
            coverage: &quick,
            ports: &quick_ports,
        },
        &ScanSide {
            profile: ScanProfile::Full,
            target: "10.0.0.1",
            coverage: &full,
            ports: &full_ports,
        },
    );
    assert!(d.profile_mismatch);
    assert_eq!(
        d.opened.iter().map(|c| c.port).collect::<Vec<_>>(),
        [80],
        "80 was covered"
    );
    assert_eq!(
        d.not_comparable.iter().map(|c| c.port).collect::<Vec<_>>(),
        [8443]
    );
    assert_eq!(d.unchanged, 1);

    // The other way round: the full scan's 8443 is not "closed" in the quick one.
    let d = diff(
        &ScanSide {
            profile: ScanProfile::Full,
            target: "10.0.0.1",
            coverage: &full,
            ports: &full_ports,
        },
        &ScanSide {
            profile: ScanProfile::Quick,
            target: "10.0.0.1",
            coverage: &quick,
            ports: &quick_ports,
        },
    );
    assert_eq!(d.closed.iter().map(|c| c.port).collect::<Vec<_>>(), [80]);
    assert_eq!(
        d.not_comparable.iter().map(|c| c.port).collect::<Vec<_>>(),
        [8443]
    );
}

#[test]
fn a_scan_compared_with_itself_has_no_changes() {
    let all = PortCoverage::all("tcp");
    let p = ports(&[
        "22/tcp open ssh OpenSSH 9.6",
        "80/tcp open http nginx 1.27",
        "443/tcp closed",
    ]);
    let side = ScanSide {
        profile: ScanProfile::Service,
        target: "10.0.0.1",
        coverage: &all,
        ports: &p,
    };
    let d = diff(&side, &side);
    assert!(d.is_empty() && d.not_comparable.is_empty());
    assert_eq!(d.unchanged, 2);
}

#[test]
fn a_new_address_and_other_protocols_are_reported() {
    let mut both = PortCoverage::all("tcp");
    both.add_services("udp", "53").unwrap();
    let before = ports(&["53/udp open domain"]);
    let after = ports(&["53/tcp open domain", "53/udp open domain"]);
    let d = diff(
        &ScanSide {
            profile: ScanProfile::Full,
            target: "192.168.1.5",
            coverage: &both,
            ports: &before,
        },
        &ScanSide {
            profile: ScanProfile::Full,
            target: "192.168.1.9",
            coverage: &both,
            ports: &after,
        },
    );
    assert_eq!(
        d.address_changed,
        Some(("192.168.1.5".into(), "192.168.1.9".into()))
    );
    assert_eq!(d.opened.len(), 1);
    assert_eq!(
        (d.opened[0].protocol.as_str(), d.opened[0].port),
        ("tcp", 53)
    );
    assert_eq!(d.unchanged, 1, "53/udp is a different port from 53/tcp");
}

#[test]
fn coverage_lists_are_parsed_like_nmap_writes_them() {
    let c = coverage("1,3-4,6-7,9,13,8080");
    for open in [1, 3, 4, 6, 7, 9, 13, 8080] {
        assert!(c.contains("tcp", open), "{open}");
    }
    for out in [0, 2, 5, 8, 14, 8081] {
        assert!(!c.contains("tcp", out), "{out}");
    }
    assert!(!c.contains("udp", 1), "per protocol");
    assert!(PortCoverage::all("tcp").contains("tcp", 65535));
    assert!(PortCoverage::default().is_empty());

    let mut bad = PortCoverage::default();
    for list in ["1-", "a", "5-3", "70000", "1,,2-x"] {
        assert_eq!(bad.add_services("tcp", list), None, "{list}");
    }
}
