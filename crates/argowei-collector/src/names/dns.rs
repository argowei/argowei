//! Just enough of the DNS wire format (RFC 1035) to ask for a PTR record and
//! read the answer. Used for reverse DNS and, because multicast DNS speaks the
//! same format, for mDNS as well.
//!
//! Responses come from the network and are not trusted: every length and
//! compression pointer is bounds-checked and pointer loops are cut off.

use std::fmt;
use std::net::Ipv4Addr;

pub(crate) const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;

/// Fixed DNS header (id, flags, four section counts).
pub(super) const HEADER_LEN: usize = 12;
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;
/// A legitimate name never needs more jumps than it has labels.
const MAX_POINTER_JUMPS: usize = 64;

/// What is wrong with a DNS packet or answer.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsError {
    /// A label is empty or longer than 63 bytes.
    InvalidLabel,
    /// The packet ends before a length it announced.
    Truncated,
    /// A compression pointer points outside the packet or loops.
    BadPointer,
    /// A name is longer than 255 bytes.
    NameTooLong,
    /// The packet is a query, not a response.
    NotAResponse,
    /// The response answers a different query.
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
pub(crate) fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// A query for one name and type.
pub(crate) fn build_query(
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
pub(crate) fn is_response_to(packet: &[u8], id: u16) -> bool {
    packet.len() >= HEADER_LEN
        && u16::from_be_bytes([packet[0], packet[1]]) == id
        && packet[2] & 0x80 != 0
}

/// The names in the PTR records of a response. An empty list means the server
/// has no such record ("no such name" is an answer, not a failure).
pub(crate) fn parse_ptr_response(packet: &[u8], expected_id: u16) -> Result<Vec<String>, DnsError> {
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
mod tests;
