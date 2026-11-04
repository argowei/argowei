use super::*;
use crate::names::testing::{answer_once, target};

/// One 18-byte name-table entry.
fn entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
    let mut bytes = format!("{name:<15}").into_bytes();
    bytes.push(suffix);
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes
}

/// A node status response as Windows and Samba send it: no question, one
/// answer whose name is the encoded `*`, then the name table and the
/// 46 bytes of adapter statistics.
fn response(id: u16, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut packet = id.to_be_bytes().to_vec();
    packet.extend_from_slice(&[0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
    packet.push(32);
    packet.extend_from_slice(b"CK");
    packet.extend_from_slice(&[b'A'; 30]);
    packet.push(0);
    packet.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]); // NBSTAT, IN, ttl 0
    let rdata_len = 1 + entries.len() * NAME_ENTRY_LEN + 46;
    packet.extend_from_slice(&(rdata_len as u16).to_be_bytes());
    packet.push(entries.len() as u8);
    entries.iter().for_each(|e| packet.extend_from_slice(e));
    packet.extend_from_slice(&[0; 46]);
    packet
}

const UNIQUE: u16 = 0x0400;
const GROUP: u16 = 0x8400;

#[test]
fn the_status_request_has_the_exact_wire_layout() {
    let query = build_nbstat_query(0xabcd);

    let mut expected = vec![0xab, 0xcd, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32];
    expected.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expected.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    assert_eq!(query, expected);
    assert_eq!(query.len(), 50);
}

#[test]
fn the_computer_name_is_the_unique_workstation_entry() {
    let packet = response(
        1,
        &[
            entry("WORKGROUP", 0x00, GROUP),
            entry("ANNA-PC", 0x00, UNIQUE),
            entry("ANNA-PC", 0x20, UNIQUE),
            entry("WORKGROUP", 0x1e, GROUP),
        ],
    );

    assert_eq!(
        parse_nbstat_response(&packet).unwrap().as_deref(),
        Some("ANNA-PC")
    );
}

#[test]
fn padding_is_trimmed_from_the_name() {
    let packet = response(1, &[entry("NAS", 0x00, UNIQUE)]);

    assert_eq!(
        parse_nbstat_response(&packet).unwrap().as_deref(),
        Some("NAS")
    );
}

#[test]
fn the_file_server_entry_is_the_fallback() {
    let packet = response(
        1,
        &[
            entry("WORKGROUP", 0x00, GROUP),
            entry("FILESRV", 0x20, UNIQUE),
        ],
    );

    assert_eq!(
        parse_nbstat_response(&packet).unwrap().as_deref(),
        Some("FILESRV")
    );
}

#[test]
fn a_table_with_only_group_names_names_nothing() {
    let packet = response(
        1,
        &[
            entry("WORKGROUP", 0x00, GROUP),
            entry("WORKGROUP", 0x1e, GROUP),
        ],
    );

    assert_eq!(parse_nbstat_response(&packet).unwrap(), None);
}

#[test]
fn an_error_code_or_no_answer_is_no_name() {
    let mut refused = response(1, &[entry("X", 0, UNIQUE)]);
    refused[3] = 0x05;
    assert_eq!(parse_nbstat_response(&refused).unwrap(), None);

    let mut empty = response(1, &[]);
    empty[7] = 0;
    assert_eq!(parse_nbstat_response(&empty).unwrap(), None);
}

#[test]
fn something_that_is_not_a_response_is_malformed() {
    assert!(matches!(
        parse_nbstat_response(&build_nbstat_query(1)),
        Err(ResolveError::Malformed(_))
    ));
    assert!(matches!(
        parse_nbstat_response(&[1, 2, 3]),
        Err(ResolveError::Malformed(_))
    ));
}

#[test]
fn truncated_responses_never_panic() {
    let packet = response(
        1,
        &[
            entry("ANNA-PC", 0x00, UNIQUE),
            entry("WORKGROUP", 0x00, GROUP),
        ],
    );
    for cut in 0..packet.len() {
        let _ = parse_nbstat_response(&packet[..cut]);
    }
}

#[test]
fn a_count_larger_than_the_table_does_not_overrun() {
    let mut packet = response(1, &[entry("ANNA-PC", 0x00, UNIQUE)]);
    let count_at = packet.len() - 46 - NAME_ENTRY_LEN - 1;
    packet[count_at] = 200;

    assert_eq!(
        parse_nbstat_response(&packet).unwrap().as_deref(),
        Some("ANNA-PC")
    );
}

#[test]
fn the_resolver_asks_a_host_and_returns_its_name() {
    let port = answer_once(|request| {
        let id = u16::from_be_bytes([request[0], request[1]]);
        Some(response(id, &[entry("ANNA-PC", 0x00, UNIQUE)]))
    });

    let name = NetbiosResolver::with_port(port)
        .resolve(&target("127.0.0.1"), Duration::from_secs(2))
        .unwrap();

    assert_eq!(name.as_deref(), Some("ANNA-PC"));
}

#[test]
fn a_host_that_does_not_answer_has_no_name_and_no_error() {
    let port = answer_once(|_| None);

    let name = NetbiosResolver::with_port(port)
        .resolve(&target("127.0.0.1"), Duration::from_millis(150))
        .unwrap();

    assert_eq!(name, None);
}

#[test]
fn an_answer_to_another_query_is_ignored() {
    let port = answer_once(|request| {
        let wrong = u16::from_be_bytes([request[0], request[1]]).wrapping_add(1);
        Some(response(wrong, &[entry("INTRUDER", 0x00, UNIQUE)]))
    });

    let name = NetbiosResolver::with_port(port)
        .resolve(&target("127.0.0.1"), Duration::from_millis(200))
        .unwrap();

    assert_eq!(name, None);
}

#[test]
fn a_name_that_only_spells_out_the_address_is_dropped() {
    let port = answer_once(|request| {
        let id = u16::from_be_bytes([request[0], request[1]]);
        Some(response(id, &[entry("127-0-0-1", 0x00, UNIQUE)]))
    });

    let name = NetbiosResolver::with_port(port)
        .resolve(&target("127.0.0.1"), Duration::from_secs(2))
        .unwrap();

    assert_eq!(name, None);
}
