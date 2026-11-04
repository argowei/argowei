//! NetBIOS name service (RFC 1002): ask a host for its name table with a node
//! status request ("NBSTAT") on UDP 137. Windows machines and Samba answer
//! with their computer name; most other devices do not answer at all.

use std::net::SocketAddr;
use std::time::Duration;

use argowei_core::names::{sanitize_name, NameSource};

use super::dns::read_name;
use super::{ensure_local, query_id, udp_exchange, HostnameResolver, ResolveError, Target};

pub const DEFAULT_PORT: u16 = 137;

const TYPE_NBSTAT: u16 = 0x0021;
const CLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;
const NAME_ENTRY_LEN: usize = 18;

/// Name suffix for "workstation service": the machine's own name.
const SUFFIX_WORKSTATION: u8 = 0x00;
/// Name suffix for "file server service".
const SUFFIX_FILE_SERVER: u8 = 0x20;
const FLAG_GROUP: u16 = 0x8000;

pub struct NetbiosResolver {
    port: u16,
}

impl Default for NetbiosResolver {
    fn default() -> Self {
        Self { port: DEFAULT_PORT }
    }
}

impl NetbiosResolver {
    /// Uses a non-standard port; for tests that answer on loopback.
    pub fn with_port(port: u16) -> Self {
        Self { port }
    }
}

impl HostnameResolver for NetbiosResolver {
    fn source(&self) -> NameSource {
        NameSource::Netbios
    }

    fn resolve(&self, target: &Target, timeout: Duration) -> Result<Option<String>, ResolveError> {
        ensure_local(target.ip)?;
        let id = query_id(target.ip);

        let response = udp_exchange(
            SocketAddr::new(target.ip.into(), self.port),
            &build_nbstat_query(id),
            timeout,
            |packet| packet.len() >= HEADER_LEN && u16::from_be_bytes([packet[0], packet[1]]) == id,
        )?;

        Ok(response
            .map(|packet| parse_nbstat_response(&packet))
            .transpose()?
            .flatten()
            .and_then(|name| sanitize_name(&name, Some(target.ip))))
    }
}

/// The node status request: ask for the name `*`, which every host answers
/// with its whole name table. NetBIOS "first level encoding" turns each byte
/// of the 16-byte name into two letters (`*` becomes `CK`, a NUL becomes `AA`).
pub fn build_nbstat_query(id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // flags 0, one question
    packet.push(32);
    packet.extend_from_slice(b"CK");
    packet.extend_from_slice(&[b'A'; 30]);
    packet.push(0);
    packet.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    packet
}

/// The machine's own name from a node status response, if it reports one.
///
/// Group names (a workgroup or domain) are not the device's name and are
/// skipped; the workstation entry is preferred over the file server entry.
pub fn parse_nbstat_response(packet: &[u8]) -> Result<Option<String>, ResolveError> {
    let malformed = |what| ResolveError::Malformed(what);

    if packet.len() < HEADER_LEN || packet[2] & 0x80 == 0 {
        return Err(malformed("not a NetBIOS response"));
    }
    if packet[3] & 0x0f != 0 {
        return Ok(None);
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    if answers == 0 {
        return Ok(None);
    }

    let mut offset = HEADER_LEN;
    for _ in 0..questions {
        let (_, next) = read_name(packet, offset).map_err(|_| malformed("bad NetBIOS question"))?;
        offset = next + 4;
    }

    let (_, next) = read_name(packet, offset).map_err(|_| malformed("bad NetBIOS answer name"))?;
    let fixed = packet
        .get(next..next + 10)
        .ok_or_else(|| malformed("truncated NetBIOS answer"))?;
    if u16::from_be_bytes([fixed[0], fixed[1]]) != TYPE_NBSTAT {
        return Ok(None);
    }
    let rdata = packet
        .get(next + 10..)
        .ok_or_else(|| malformed("truncated NetBIOS answer"))?;

    let count = usize::from(*rdata.first().ok_or_else(|| malformed("empty name table"))?);
    let entries = rdata[1..]
        .chunks_exact(NAME_ENTRY_LEN)
        .take(count)
        .map(|entry| {
            let name = String::from_utf8_lossy(&entry[..15]).trim_end().to_owned();
            let suffix = entry[15];
            let flags = u16::from_be_bytes([entry[16], entry[17]]);
            (name, suffix, flags & FLAG_GROUP != 0)
        })
        .collect::<Vec<_>>();

    for wanted in [SUFFIX_WORKSTATION, SUFFIX_FILE_SERVER] {
        if let Some((name, _, _)) = entries
            .iter()
            .find(|(_, suffix, group)| *suffix == wanted && !group)
        {
            return Ok(Some(name.clone()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
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
}
