//! Multicast DNS, asked directly: a unicast PTR query for the device's own
//! reverse name sent to the device's mDNS port (5353). Responders answer such
//! "legacy unicast" queries straight back (RFC 6762 section 6.7), so no
//! multicast group has to be joined, only the one device is asked, and a
//! device without mDNS refuses at once (ICMP port unreachable).
//!
//! Apple, Avahi and many printers and TVs answer; plain servers and many
//! phones in power saving do not.

use std::net::SocketAddr;
use std::time::Duration;

use argowei_core::names::{sanitize_name, NameSource};

use super::dns::{self, TYPE_PTR};
use super::{ensure_local, query_id, udp_exchange, HostnameResolver, ResolveError, Target};

/// The port mDNS responders listen on, also for unicast queries.
pub const MDNS_PORT: u16 = 5353;

pub struct MdnsResolver {
    port: u16,
}

impl Default for MdnsResolver {
    fn default() -> Self {
        Self { port: MDNS_PORT }
    }
}

impl MdnsResolver {
    /// Uses a non-standard port; for tests that answer on loopback.
    pub fn with_port(port: u16) -> Self {
        Self { port }
    }
}

impl HostnameResolver for MdnsResolver {
    fn source(&self) -> NameSource {
        NameSource::Mdns
    }

    fn resolve(&self, target: &Target, timeout: Duration) -> Result<Option<String>, ResolveError> {
        ensure_local(target.ip)?;
        let id = query_id(target.ip);
        let query = dns::build_query(id, &dns::reverse_name(target.ip), TYPE_PTR, false)?;

        let Some(packet) = udp_exchange(
            SocketAddr::new(target.ip.into(), self.port),
            &query,
            timeout,
            |packet| dns::is_response_to(packet, id),
        )?
        else {
            return Ok(None);
        };

        Ok(dns::parse_ptr_response(&packet, id)?
            .iter()
            .filter_map(|name| clean(name, target))
            .next())
    }
}

/// `annas-iphone.local` is called `annas-iphone`.
fn clean(name: &str, target: &Target) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    let host = trimmed
        .strip_suffix(".local")
        .or_else(|| trimmed.strip_suffix(".LOCAL"))
        .unwrap_or(trimmed);
    sanitize_name(host, Some(target.ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::testing::{answer_once, ptr_response, target};

    #[test]
    fn the_local_suffix_is_dropped() {
        let t = target("192.168.1.5");

        assert_eq!(
            clean("Annas-iPhone.local", &t).as_deref(),
            Some("Annas-iPhone")
        );
        assert_eq!(
            clean("annas-iphone.local.", &t).as_deref(),
            Some("annas-iphone")
        );
        assert_eq!(
            clean("printer.example.lan", &t).as_deref(),
            Some("printer.example.lan")
        );
    }

    #[test]
    fn placeholder_and_address_names_are_dropped() {
        let t = target("192.168.1.5");

        assert_eq!(clean("localhost.local", &t), None);
        assert_eq!(clean("192-168-1-5.local", &t), None);
        assert_eq!(clean(".local", &t), None);
    }

    #[test]
    fn the_query_goes_to_the_device_and_asks_for_its_reverse_name() {
        let (seen, received) = std::sync::mpsc::channel();
        let port = answer_once(move |request| {
            seen.send(request.to_vec()).unwrap();
            Some(ptr_response(request, b"\x0cannas-iphone\x05local\x00"))
        });

        let name = MdnsResolver::with_port(port)
            .resolve(&target("127.0.0.1"), Duration::from_secs(2))
            .unwrap();

        assert_eq!(name.as_deref(), Some("annas-iphone"));
        // It asked for exactly the device's own PTR, without recursion.
        let request = received.recv().unwrap();
        let expected = dns::build_query(
            u16::from_be_bytes([request[0], request[1]]),
            "1.0.0.127.in-addr.arpa",
            TYPE_PTR,
            false,
        )
        .unwrap();
        assert_eq!(request, expected);
    }

    #[test]
    fn a_device_that_does_not_speak_mdns_has_no_name_and_no_error() {
        let port = answer_once(|_| None);

        let name = MdnsResolver::with_port(port)
            .resolve(&target("127.0.0.1"), Duration::from_millis(150))
            .unwrap();

        assert_eq!(name, None);
    }

    #[test]
    fn an_unused_port_is_refused_immediately_rather_than_waiting() {
        // Nothing listens on this port: the OS answers with "port unreachable".
        let port = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        let started = std::time::Instant::now();

        let name = MdnsResolver::with_port(port)
            .resolve(&target("127.0.0.1"), Duration::from_secs(5))
            .unwrap();

        assert_eq!(name, None);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "should not wait for the full timeout"
        );
    }

    #[test]
    fn a_response_with_the_wrong_id_is_not_believed() {
        let port = answer_once(|request| {
            let mut response = ptr_response(request, b"\x08intruder\x05local\x00");
            response[1] = response[1].wrapping_add(1);
            Some(response)
        });

        let name = MdnsResolver::with_port(port)
            .resolve(&target("127.0.0.1"), Duration::from_millis(200))
            .unwrap();

        assert_eq!(name, None);
    }

    #[test]
    fn a_garbled_answer_is_an_error_not_a_name() {
        let port = answer_once(|request| {
            let mut response = ptr_response(request, b"\x0cannas-iphone\x05local\x00");
            response.truncate(20);
            Some(response)
        });

        let result =
            MdnsResolver::with_port(port).resolve(&target("127.0.0.1"), Duration::from_secs(2));

        assert!(result.is_err());
    }
}
