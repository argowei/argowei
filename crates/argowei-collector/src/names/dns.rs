//! Just enough of the DNS wire format (RFC 1035) to ask for a PTR record and
//! read the answer. Used for reverse DNS and, because multicast DNS speaks the
//! same format, for mDNS as well.
//!
//! Responses come from the network and are not trusted: every length and
//! compression pointer is bounds-checked and pointer loops are cut off.

use std::fmt;
use std::net::Ipv4Addr;

pub const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;

const HEADER_LEN: usize = 12;
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;
/// A legitimate name never needs more jumps than it has labels.
const MAX_POINTER_JUMPS: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum DnsError {
    /// A label is empty or longer than 63 bytes.
    InvalidLabel,
    Truncated,
    /// A compression pointer points outside the packet or loops.
    BadPointer,
    NameTooLong,
    NotAResponse,
    IdMismatch,
    /// The server answered with an error other than "no such name".
    ServerFailure(u8),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLabel => write!(f, "invalid DNS label"),
            Self::Truncated => write!(f, "truncated DNS packet"),
            Self::BadPointer => write!(f, "invalid DNS compression pointer"),
            Self::NameTooLong => write!(f, "DNS name too long"),
            Self::NotAResponse => write!(f, "not a DNS response"),
            Self::IdMismatch => write!(f, "DNS response id does not match the query"),
            Self::ServerFailure(code) => write!(f, "DNS server failure (rcode {code})"),
        }
    }
}

impl std::error::Error for DnsError {}

/// `5.1.168.192.in-addr.arpa` for 192.168.1.5.
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// A query for one name and type.
pub fn build_query(
    id: u16,
    name: &str,
    qtype: u16,
    recursion_desired: bool,
) -> Result<Vec<u8>, DnsError> {
    let mut packet = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&(u16::from(recursion_desired) << 8).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // one question
    packet.extend_from_slice(&[0; 6]); // no answer, authority or additional records

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > MAX_LABEL {
            return Err(DnsError::InvalidLabel);
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

/// Whether `packet` is a response carrying `id`; cheap check before parsing.
pub fn is_response_to(packet: &[u8], id: u16) -> bool {
    packet.len() >= HEADER_LEN
        && u16::from_be_bytes([packet[0], packet[1]]) == id
        && packet[2] & 0x80 != 0
}

/// The names in the PTR records of a response. An empty list means the server
/// has no such record ("no such name" is an answer, not a failure).
pub fn parse_ptr_response(packet: &[u8], expected_id: u16) -> Result<Vec<String>, DnsError> {
    if packet.len() < HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    if packet[2] & 0x80 == 0 {
        return Err(DnsError::NotAResponse);
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != expected_id {
        return Err(DnsError::IdMismatch);
    }
    match packet[3] & 0x0f {
        0 => {}
        3 => return Ok(Vec::new()),
        code => return Err(DnsError::ServerFailure(code)),
    }

    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);

    let mut offset = HEADER_LEN;
    for _ in 0..questions {
        let (_, next) = read_name(packet, offset)?;
        offset = next.checked_add(4).ok_or(DnsError::Truncated)?; // type and class
    }

    let mut names = Vec::new();
    for _ in 0..answers {
        let (_, next) = read_name(packet, offset)?;
        let fixed = packet.get(next..next + 10).ok_or(DnsError::Truncated)?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdata_len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_start = next + 10;
        let rdata_end = rdata_start
            .checked_add(rdata_len)
            .filter(|end| *end <= packet.len())
            .ok_or(DnsError::Truncated)?;

        if record_type == TYPE_PTR {
            // The target may use pointers into the rest of the packet.
            names.push(read_name(packet, rdata_start)?.0);
        }
        offset = rdata_end;
    }
    Ok(names)
}

/// Reads a possibly compressed name starting at `start`; returns the dotted
/// name and the offset just after it in the original position.
pub(super) fn read_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut offset = start;
    let mut resume: Option<usize> = None;
    let mut jumps = 0;

    loop {
        let length = *packet.get(offset).ok_or(DnsError::Truncated)?;
        match length {
            0 => {
                offset += 1;
                break;
            }
            l if l & 0xc0 == 0xc0 => {
                let low = *packet.get(offset + 1).ok_or(DnsError::Truncated)?;
                let target = (usize::from(l & 0x3f) << 8) | usize::from(low);
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || target >= packet.len() {
                    return Err(DnsError::BadPointer);
                }
                resume.get_or_insert(offset + 2);
                offset = target;
            }
            l if l & 0xc0 != 0 => return Err(DnsError::InvalidLabel),
            l => {
                let label = packet
                    .get(offset + 1..offset + 1 + usize::from(l))
                    .ok_or(DnsError::Truncated)?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(label));
                if name.len() > MAX_NAME {
                    return Err(DnsError::NameTooLong);
                }
                offset += 1 + usize::from(l);
            }
        }
    }
    Ok((name, resume.unwrap_or(offset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);

    /// Builds a response the way a DNS server lays it out: the question is
    /// repeated and the answer's owner name is a pointer back to it.
    fn response(id: u16, rcode: u8, target: Option<&[u8]>) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&[0x81, 0x80 | rcode]); // response, recursion available
        packet.extend_from_slice(&[0, 1, 0, u8::from(target.is_some()), 0, 0, 0, 0]);
        packet.extend_from_slice(
            &build_query(id, &reverse_name(IP), TYPE_PTR, true).unwrap()[HEADER_LEN..],
        );
        if let Some(target) = target {
            packet.extend_from_slice(&[0xc0, 0x0c]); // owner name: pointer to the question
            packet.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x0e, 0x10]); // PTR, IN, ttl 3600
            packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
            packet.extend_from_slice(target);
        }
        packet
    }

    /// `annas-iphone.local` as labels.
    const LABELS: &[u8] = b"\x0cannas-iphone\x05local\x00";

    #[test]
    fn reverse_names_list_the_octets_backwards() {
        assert_eq!(reverse_name(IP), "5.1.168.192.in-addr.arpa");
    }

    #[test]
    fn a_ptr_query_has_the_exact_wire_layout() {
        let query = build_query(0x1234, "5.1.168.192.in-addr.arpa", TYPE_PTR, true).unwrap();

        let expected: Vec<u8> = [
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..], // header, RD set, one question
            b"\x015\x011\x03168\x03192\x07in-addr\x04arpa\x00",
            &[0, 12, 0, 1], // PTR, IN
        ]
        .concat();
        assert_eq!(query, expected);
    }

    #[test]
    fn multicast_style_queries_do_not_ask_for_recursion() {
        let query = build_query(7, "x.local", TYPE_PTR, false).unwrap();

        assert_eq!(&query[2..4], &[0, 0]);
    }

    #[test]
    fn invalid_labels_are_refused() {
        assert_eq!(
            build_query(1, "a..b", TYPE_PTR, true),
            Err(DnsError::InvalidLabel)
        );
        assert_eq!(
            build_query(1, &"x".repeat(64), TYPE_PTR, true),
            Err(DnsError::InvalidLabel)
        );
    }

    #[test]
    fn a_ptr_answer_is_read() {
        let names = parse_ptr_response(&response(9, 0, Some(LABELS)), 9).unwrap();

        assert_eq!(names, ["annas-iphone.local"]);
    }

    #[test]
    fn a_target_that_points_back_into_the_packet_is_followed() {
        // The answer's target is "host" plus a pointer to the question's
        // "in-addr.arpa" tail, as real servers compress.
        let mut packet = response(3, 0, None);
        packet[7] = 1; // one answer
        let tail = packet.windows(8).position(|w| w == b"\x07in-addr").unwrap();
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]);
        let target = [b"\x04host".as_slice(), &[0xc0, tail as u8]].concat();
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(&target);

        assert_eq!(
            parse_ptr_response(&packet, 3).unwrap(),
            ["host.in-addr.arpa"]
        );
    }

    #[test]
    fn no_such_name_is_an_empty_answer_not_an_error() {
        assert_eq!(parse_ptr_response(&response(4, 3, None), 4), Ok(Vec::new()));
    }

    #[test]
    fn a_response_without_answers_yields_nothing() {
        assert_eq!(parse_ptr_response(&response(4, 0, None), 4), Ok(Vec::new()));
    }

    #[test]
    fn server_failures_are_reported() {
        assert_eq!(
            parse_ptr_response(&response(4, 2, None), 4),
            Err(DnsError::ServerFailure(2))
        );
        assert_eq!(
            parse_ptr_response(&response(4, 5, None), 4),
            Err(DnsError::ServerFailure(5))
        );
    }

    #[test]
    fn answers_to_a_different_query_are_rejected() {
        let packet = response(9, 0, Some(LABELS));

        assert_eq!(parse_ptr_response(&packet, 10), Err(DnsError::IdMismatch));
        assert!(is_response_to(&packet, 9));
        assert!(!is_response_to(&packet, 10));
    }

    #[test]
    fn a_query_is_not_mistaken_for_a_response() {
        let query = build_query(9, "x.local", TYPE_PTR, true).unwrap();

        assert_eq!(parse_ptr_response(&query, 9), Err(DnsError::NotAResponse));
        assert!(!is_response_to(&query, 9));
    }

    #[test]
    fn truncated_packets_never_panic() {
        let packet = response(9, 0, Some(LABELS));
        for cut in 0..packet.len() {
            let _ = parse_ptr_response(&packet[..cut], 9);
        }
        assert_eq!(parse_ptr_response(&[], 1), Err(DnsError::Truncated));
    }

    #[test]
    fn a_pointer_loop_is_cut_off() {
        let mut packet = response(9, 0, None);
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]);
        let loop_at = packet.len() + 2;
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, loop_at as u8]); // points at itself

        assert_eq!(parse_ptr_response(&packet, 9), Err(DnsError::BadPointer));
    }

    #[test]
    fn a_pointer_outside_the_packet_is_refused() {
        let mut packet = response(9, 0, None);
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0xff]);

        assert_eq!(parse_ptr_response(&packet, 9), Err(DnsError::BadPointer));
    }

    #[test]
    fn an_over_long_name_is_refused() {
        let label = [&[63u8][..], &[b'a'; 63]].concat();
        let target = [label.repeat(5), vec![0]].concat();

        assert_eq!(
            parse_ptr_response(&response(9, 0, Some(&target)), 9),
            Err(DnsError::NameTooLong)
        );
    }

    #[test]
    fn a_record_length_that_runs_past_the_packet_is_refused() {
        let mut packet = response(9, 0, Some(LABELS));
        let len_at = packet.len() - LABELS.len() - 2;
        packet[len_at] = 0xff;

        assert_eq!(parse_ptr_response(&packet, 9), Err(DnsError::Truncated));
    }
}
