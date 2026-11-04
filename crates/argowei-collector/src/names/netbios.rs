//! NetBIOS name service (RFC 1002): ask a host for its name table with a node
//! status request ("NBSTAT") on UDP 137. Windows machines and Samba answer
//! with their computer name; most other devices do not answer at all.

use std::net::SocketAddr;
use std::time::Duration;

use argowei_core::names::{sanitize_name, NameSource};

// NetBIOS name service packets share the DNS header and name encoding.
use super::dns::{read_name, HEADER_LEN};
use super::{ensure_local, query_id, udp_exchange, HostnameResolver, ResolveError, Target};

/// The NetBIOS name service port.
pub const NETBIOS_PORT: u16 = 137;

const TYPE_NBSTAT: u16 = 0x0021;
const CLASS_IN: u16 = 1;
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
        Self { port: NETBIOS_PORT }
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
pub(crate) fn build_nbstat_query(id: u16) -> Vec<u8> {
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
pub(crate) fn parse_nbstat_response(packet: &[u8]) -> Result<Option<String>, ResolveError> {
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
    // Whole entries only: a count larger than the table, or a trailing
    // partial entry, must not read past the data.
    let entries = rdata[1..]
        .as_chunks::<NAME_ENTRY_LEN>()
        .0
        .iter()
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
mod tests;
