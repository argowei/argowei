//! Packets recorded from a real home network: a FRITZ!Box answering reverse
//! lookups (UDP 53) and a Raspberry Pi running Avahi answering a unicast mDNS
//! query (UDP 5353). They were captured with a plain UDP client using the
//! queries these resolvers send (id 0x1234), and are replayed here so the
//! parsers are tested against what real devices put on the wire, including
//! the quirks a hand-built packet would never have: compressed names, an
//! authority and additional section, thirteen aliases for the router itself.
//!
//! Only default hostnames and private addresses appear in them.

use std::time::Duration;

use super::dns::{parse_ptr_response, DnsError};
use super::testing::{answer_once, rdns_on, target};
use super::{HostnameResolver, MdnsResolver};

/// The id of the recorded queries.
const ID: u16 = 0x1234;

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// `PTR 62.178.168.192.in-addr.arpa` asked of the router: one PTR answer, plus
/// an NS record and the router's A and AAAA records in the other sections.
const ROUTER_FOR_IPHONE: &str = "12348580000100010001000302363203313738033136380331393207696e2d61646472046172706100000c0001c00c000c0001000000090012066950686f6e6505667269747a03626f7800c00c00020001000000090002c040c04000010001000000090004c0a8b201c040001c0001000000090010fdac5244fd20000036e1a9fffe091443c040001c0001000000090010200300f4071f540036e1a9fffe091443";

/// `PTR 37.178.168.192.in-addr.arpa`: a Raspberry Pi the router knows from DHCP.
const ROUTER_FOR_PI: &str = "12348580000100010001000302333703313738033136380331393207696e2d61646472046172706100000c0001c00c000c00010000000900170b726173706265727279706905667269747a03626f7800c00c00020001000000090002c045c04500010001000000090004c0a8b201c045001c0001000000090010fdac5244fd20000036e1a9fffe091443c045001c0001000000090010200300f4071f540036e1a9fffe091443";

/// `PTR 1.178.168.192.in-addr.arpa`: the router itself, under thirteen names.
const ROUTER_FOR_ROUTER: &str = "123485800001000d00010003013103313738033136380331393207696e2d61646472046172706100000c0001c00c000c000100000009000b05667269747a03626f7800c00c000c000100000009000603777777c038c00c000c000100000009001308667269747a626f7808696e7465726e616c00c00c000c000100000009001008667269747a626f7804686f6d65c022c00c000c000100000009000a076d79667269747ac03ec00c000c000100000009000603777777c09cc00c000c000100000009000b05667269747a036e617300c00c000c000100000009000603777777c0c4c00c000c000100000009000c09667269747a2d6e6173c038c00c000c000100000009000c09667269747a2d6e6173c03ec00c000c00010000000900070477706164c03ec00c000c00010000000900070477706164c038c00c000c00010000000900100d3139322d3136382d3137382d31c038c00c00020001000000090002c038c03800010001000000090004c0a8b201c038001c0001000000090010fdac5244fd20000036e1a9fffe091443c038001c0001000000090010200300f4071f540036e1a9fffe091443";

/// `PTR 200.178.168.192.in-addr.arpa`: no such name (NXDOMAIN, with the SOA).
const ROUTER_NXDOMAIN: &str = "1234858300010000000100000332303003313738033136380331393207696e2d61646472046172706100000c0001c0100006000100000009002705667269747a03626f78000561646d696ec03a6aeb090a00005460000007080000a8c00000000a";

/// `PTR 39.178.168.192.in-addr.arpa` sent unicast to the Pi's port 5353: Avahi
/// answers with its `.local` name.
const AVAHI_PI: &str = "12348400000100010000000002333903313738033136380331393207696e2d61646472046172706100000c0001c00c000c00010000000a00130b7261737062657272797069056c6f63616c00";

#[test]
fn the_router_names_a_client_in_a_recorded_answer() {
    let names = parse_ptr_response(&unhex(ROUTER_FOR_IPHONE), ID).unwrap();

    assert_eq!(names, ["iPhone.fritz.box"]);
}

#[test]
fn a_recorded_answer_with_authority_and_additional_sections_is_parsed() {
    let names = parse_ptr_response(&unhex(ROUTER_FOR_PI), ID).unwrap();

    assert_eq!(names, ["raspberrypi.fritz.box"]);
}

#[test]
fn the_router_lists_all_its_aliases_with_the_main_name_first() {
    let names = parse_ptr_response(&unhex(ROUTER_FOR_ROUTER), ID).unwrap();

    assert_eq!(names.len(), 13);
    assert_eq!(names[0], "fritz.box");
    assert!(names.contains(&"fritzbox.internal".to_owned()));
    assert!(names.contains(&"www.fritz.box".to_owned()));
    // A generated name that says nothing is in there too.
    assert!(names.contains(&"192-168-178-1.fritz.box".to_owned()));
}

#[test]
fn a_recorded_no_such_name_answer_is_empty() {
    assert_eq!(
        parse_ptr_response(&unhex(ROUTER_NXDOMAIN), ID),
        Ok(Vec::new())
    );
}

#[test]
fn a_recorded_avahi_answer_gives_the_local_name() {
    let names = parse_ptr_response(&unhex(AVAHI_PI), ID).unwrap();

    assert_eq!(names, ["raspberrypi.local"]);
}

#[test]
fn every_recorded_packet_is_rejected_for_a_different_query_id() {
    for packet in [
        ROUTER_FOR_IPHONE,
        ROUTER_FOR_PI,
        ROUTER_FOR_ROUTER,
        ROUTER_NXDOMAIN,
        AVAHI_PI,
    ] {
        assert_eq!(
            parse_ptr_response(&unhex(packet), ID + 1),
            Err(DnsError::IdMismatch)
        );
    }
}

#[test]
fn no_prefix_of_a_recorded_packet_makes_the_parser_panic() {
    for packet in [ROUTER_FOR_IPHONE, ROUTER_FOR_ROUTER, AVAHI_PI] {
        let bytes = unhex(packet);
        for cut in 0..bytes.len() {
            let _ = parse_ptr_response(&bytes[..cut], ID);
        }
    }
}

/// Replays a recorded packet from a loopback "device", with the id of the
/// query it receives so the resolver accepts it.
fn replay(recorded: &'static str) -> u16 {
    answer_once(move |request| {
        let mut packet = unhex(recorded);
        packet[..2].copy_from_slice(&request[..2]);
        Some(packet)
    })
}

#[test]
fn the_reverse_dns_resolver_turns_a_recorded_answer_into_a_plain_hostname() {
    let port = replay(ROUTER_FOR_IPHONE);
    let resolver = rdns_on(port);

    let name = resolver
        .resolve(&target("127.0.0.1"), Duration::from_secs(2))
        .unwrap();

    assert_eq!(
        name.as_deref(),
        Some("iPhone"),
        "the router's domain is dropped"
    );
}

#[test]
fn the_router_keeps_its_own_name_whole() {
    let port = replay(ROUTER_FOR_ROUTER);
    let resolver = rdns_on(port);

    let name = resolver
        .resolve(&target("127.0.0.1"), Duration::from_secs(2))
        .unwrap();

    assert_eq!(name.as_deref(), Some("fritz.box"));
}

#[test]
fn a_recorded_no_such_name_gives_no_name() {
    let port = replay(ROUTER_NXDOMAIN);
    let resolver = rdns_on(port);

    assert_eq!(
        resolver
            .resolve(&target("127.0.0.1"), Duration::from_secs(2))
            .unwrap(),
        None
    );
}

#[test]
fn the_mdns_resolver_turns_a_recorded_avahi_answer_into_a_plain_hostname() {
    let port = replay(AVAHI_PI);

    let name = MdnsResolver::with_port(port)
        .resolve(&target("127.0.0.1"), Duration::from_secs(2))
        .unwrap();

    assert_eq!(name.as_deref(), Some("raspberrypi"));
}
