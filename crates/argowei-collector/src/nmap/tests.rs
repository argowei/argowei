//! The parser against output recorded from nmap 7.99 (a Python HTTP server on
//! loopback port 18080, port 18081 unused; `-oX` path replaced by `-`), plus
//! hand-made edge cases.

use super::*;

/// `-sT -p 18080,18081` without version detection.
const PORTS: &str = include_str!("fixtures/ports.xml");
/// The same with `-sV --version-light`.
const SERVICE: &str = include_str!("fixtures/service.xml");

#[test]
fn a_recorded_port_scan_is_read() {
    let run = parse_xml(PORTS).unwrap();

    assert_eq!(run.version.as_deref(), Some("7.993"));
    assert!(run.succeeded && run.error.is_none());
    assert!(run.args.unwrap().contains("--unprivileged"));
    assert!(run.elapsed_secs.unwrap() >= 0.0);
    assert_eq!(run.hosts.len(), 1);
    assert!(run.coverage.contains("tcp", 18080) && run.coverage.contains("tcp", 18081));
    assert!(!run.coverage.contains("tcp", 22), "only what nmap probed");

    let host = &run.hosts[0];
    assert_eq!(host.state, "up");
    assert_eq!(host.addresses, ["127.0.0.1"]);
    let ports: Vec<_> = host
        .ports
        .iter()
        .map(|p| (p.port, p.state.as_str(), p.is_open()))
        .collect();
    assert_eq!(ports, [(18080, "open", true), (18081, "closed", false)]);
    assert_eq!(host.ports[0].protocol, "tcp");
    assert_eq!(host.ports[1].reason.as_deref(), Some("conn-refused"));
}

#[test]
fn a_recorded_service_scan_names_product_and_version() {
    let run = parse_xml(SERVICE).unwrap();
    let open = &run.hosts[0].ports[0];
    let service = open.service.as_ref().unwrap();

    assert_eq!(service.name.as_deref(), Some("http"));
    assert_eq!(service.product.as_deref(), Some("SimpleHTTPServer"));
    assert_eq!(service.version.as_deref(), Some("0.6"));
    assert!(service.extra_info.as_deref().unwrap().starts_with("Python"));
    assert!(service.probed);
    assert!(
        run.hosts[0].ports[1].service.is_none(),
        "a closed port has no service"
    );
}

#[test]
fn every_prefix_of_a_recorded_run_is_an_error_not_a_panic() {
    // Cutting only trailing whitespace leaves a complete document.
    let complete = SERVICE.trim_end().len();
    for cut in 0..complete {
        if !SERVICE.is_char_boundary(cut) {
            continue;
        }
        // Prefixes up to the root's start tag are malformed; any cut after
        // it leaves the root unclosed. None may panic or pass.
        assert!(parse_xml(&SERVICE[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn a_down_host_and_an_error_exit_are_reported() {
    let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.993">
  <host><status state="down" reason="no-response"/><address addr="192.168.1.9" addrtype="ipv4"/></host>
  <runstats><finished exit="error" errormsg="Failed to resolve given hostname"/></runstats>
</nmaprun>"#;
    let run = parse_xml(xml).unwrap();
    assert!(!run.succeeded);
    assert_eq!(
        run.error.as_deref(),
        Some("Failed to resolve given hostname")
    );
    assert_eq!(run.hosts[0].state, "down");
    assert!(run.hosts[0].ports.is_empty());
}

#[test]
fn bad_documents_are_rejected_with_a_reason() {
    assert!(matches!(parse_xml(""), Err(NmapError::Malformed(_))));
    assert!(matches!(
        parse_xml("Starting Nmap 7.99"),
        Err(NmapError::Malformed(_))
    ));
    assert_eq!(parse_xml("<html></html>"), Err(NmapError::NotNmap));

    let no_state =
        r#"<nmaprun><host><ports><port protocol="tcp" portid="22"/></ports></host></nmaprun>"#;
    assert_eq!(parse_xml(no_state), Err(NmapError::Invalid("port state")));
    let bad_port = r#"<nmaprun><host><ports><port protocol="tcp" portid="70000"><state state="open"/></port></ports></host></nmaprun>"#;
    assert_eq!(parse_xml(bad_port), Err(NmapError::Invalid("port number")));
}

#[test]
fn entity_bombs_do_not_expand() {
    let bomb = r#"<?xml version="1.0"?>
<!DOCTYPE nmaprun [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
]>
<nmaprun version="&e;"></nmaprun>"#;
    // roxmltree refuses runaway expansion; either way nothing explodes.
    if let Ok(run) = parse_xml(bomb) {
        assert!(run.version.map_or(0, |v| v.len()) < 10_000_000);
    }
}

#[test]
fn external_entities_are_never_resolved() {
    let xxe = r#"<?xml version="1.0"?>
<!DOCTYPE nmaprun [ <!ENTITY secret SYSTEM "file:///etc/passwd"> ]>
<nmaprun version="&secret;"></nmaprun>"#;
    if let Ok(run) = parse_xml(xxe) {
        assert!(!run.version.unwrap_or_default().contains("root:"));
    }
}
