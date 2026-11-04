//! Names a device announces about itself or that the network knows it by.
//!
//! Several sources may name the same device, and they can disagree. Each
//! source's answer is kept (so the user can see who said what); one of them is
//! chosen for display by a fixed priority. A name typed in by the user is a
//! different thing (the device's *label*) and always wins; it is never stored
//! here.
//!
//! Everything in this module is untrusted input from the local network: any
//! device can answer an mDNS or NetBIOS query with whatever it likes, so names
//! are sanitized before they are stored or shown.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Longest name kept, in characters. Hostnames are at most 253 bytes; a
/// friendly mDNS name ("Anna's iPhone") is far shorter.
pub const MAX_NAME_CHARS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NameSource {
    /// Hostname the device sent when it asked for an address, as recorded in a
    /// DHCP server's lease file.
    Dhcp,
    /// Multicast DNS: the device's own answer.
    Mdns,
    /// NetBIOS name service: the computer name a Windows or Samba host reports.
    Netbios,
    /// A PTR record from a DNS server (usually the router).
    Rdns,
}

impl NameSource {
    pub const ALL: [NameSource; 4] = [Self::Dhcp, Self::Mdns, Self::Netbios, Self::Rdns];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dhcp => "dhcp",
            Self::Mdns => "mdns",
            Self::Netbios => "netbios",
            Self::Rdns => "rdns",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }

    /// Lower is preferred when sources disagree.
    ///
    /// DHCP first: the lease records what the device asked to be called, and
    /// it comes from the network's own server rather than from the device on
    /// the wire. mDNS next: friendly and device-reported, but any host on the
    /// segment can claim anything. NetBIOS is older and flatter. Reverse DNS
    /// is last because it often just echoes one of the others, or an
    /// auto-generated name.
    pub fn priority(self) -> u8 {
        match self {
            Self::Dhcp => 0,
            Self::Mdns => 1,
            Self::Netbios => 2,
            Self::Rdns => 3,
        }
    }
}

/// The name to display: the answer of the highest-priority source.
pub fn choose_name(names: &[(NameSource, String)]) -> Option<(NameSource, &str)> {
    names
        .iter()
        .min_by_key(|(source, _)| source.priority())
        .map(|(source, name)| (*source, name.as_str()))
}

/// Names that say nothing about the device.
const PLACEHOLDERS: &[&str] = &[
    "localhost",
    "localdomain",
    "unknown",
    "none",
    "(none)",
    "*",
    "-",
];

/// Cleans a name received from the network, or rejects it.
///
/// Rejected: empty names, names with control characters, over-long names,
/// placeholders such as `localhost`, and names that are just the device's own
/// IP address spelled out (`192-168-1-5.example.lan`), which routers generate
/// when they know nothing better.
pub fn sanitize_name(raw: &str, ip: Option<Ipv4Addr>) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').trim();

    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
        || PLACEHOLDERS.contains(&name.to_lowercase().as_str())
    {
        return None;
    }
    if ip.is_some_and(|ip| spells_out_address(name, ip)) {
        return None;
    }
    Some(name.to_owned())
}

/// Words routers put in front of an address when they invent a name.
const GENERIC_PREFIXES: &[&str] = &[
    "ip", "host", "dhcp", "client", "node", "lease", "static", "dynamic", "addr", "address",
];

/// `192-168-1-5.lan`, `ip-192-168-1-5`, `192.168.1.5`: the address itself,
/// possibly behind a generic word and in front of a domain. A name that says
/// more (`printer-192-168-1-5`) is kept.
fn spells_out_address(name: &str, ip: Ipv4Addr) -> bool {
    let lower = name.to_lowercase();
    let dotted = ip.to_string();
    let dashed = dotted.replace('.', "-");

    [dotted, dashed].iter().any(|needle| {
        lower.match_indices(needle.as_str()).any(|(start, _)| {
            let before = &lower[..start];
            let after = &lower[start + needle.len()..];

            let bounded = !before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_digit())
                && !after.chars().next().is_some_and(|c| c.is_ascii_digit());
            let only_generic_before = before
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty())
                .all(|word| GENERIC_PREFIXES.contains(&word));
            let nothing_or_domain_after = after.is_empty() || after.starts_with('.');

            bounded && only_generic_before && nothing_or_domain_after
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);

    #[test]
    fn sources_round_trip_through_text_and_json() {
        for source in NameSource::ALL {
            assert_eq!(NameSource::parse(source.as_str()), Some(source));
            assert_eq!(
                serde_json::to_string(&source).unwrap(),
                format!("\"{}\"", source.as_str())
            );
        }
        assert_eq!(NameSource::parse("DHCP"), None);
        assert_eq!(NameSource::parse("wins"), None);
    }

    #[test]
    fn the_priority_is_dhcp_mdns_netbios_then_reverse_dns() {
        let mut sources = NameSource::ALL;
        sources.sort_by_key(|s| s.priority());

        assert_eq!(
            sources,
            [
                NameSource::Dhcp,
                NameSource::Mdns,
                NameSource::Netbios,
                NameSource::Rdns
            ]
        );
    }

    #[test]
    fn the_highest_priority_source_wins_when_sources_disagree() {
        let names = vec![
            (NameSource::Rdns, "host-5.lan".to_owned()),
            (NameSource::Mdns, "Annas-iPhone".to_owned()),
            (NameSource::Netbios, "ANNA-PC".to_owned()),
        ];

        assert_eq!(
            choose_name(&names),
            Some((NameSource::Mdns, "Annas-iPhone"))
        );
    }

    #[test]
    fn the_choice_does_not_depend_on_the_order_of_the_answers() {
        let mut names = vec![
            (NameSource::Netbios, "ANNA-PC".to_owned()),
            (NameSource::Dhcp, "anna".to_owned()),
            (NameSource::Rdns, "anna.lan".to_owned()),
        ];
        let forward = choose_name(&names).map(|(s, n)| (s, n.to_owned()));
        names.reverse();

        assert_eq!(choose_name(&names).map(|(s, n)| (s, n.to_owned())), forward);
        assert_eq!(forward, Some((NameSource::Dhcp, "anna".to_owned())));
    }

    #[test]
    fn nothing_known_chooses_nothing() {
        assert_eq!(choose_name(&[]), None);
    }

    #[test]
    fn names_are_trimmed_and_lose_a_trailing_dot() {
        assert_eq!(
            sanitize_name("  fritz.box.  ", None).as_deref(),
            Some("fritz.box")
        );
        assert_eq!(
            sanitize_name("Anna's iPhone", None).as_deref(),
            Some("Anna's iPhone")
        );
        assert_eq!(
            sanitize_name("Wohnzimmer-Büro", None).as_deref(),
            Some("Wohnzimmer-Büro")
        );
    }

    #[test]
    fn empty_placeholder_and_hostile_names_are_rejected() {
        let long = "x".repeat(MAX_NAME_CHARS + 1);
        for raw in [
            "",
            "   ",
            ".",
            "localhost",
            "LOCALHOST",
            "unknown",
            "(none)",
            "*",
            "-",
            "two\nlines",
            "bell\u{7}",
            "nul\0byte",
            "tab\there",
            long.as_str(),
        ] {
            assert_eq!(sanitize_name(raw, None), None, "{raw:?}");
        }
        assert!(sanitize_name(&"x".repeat(MAX_NAME_CHARS), None).is_some());
    }

    #[test]
    fn a_name_that_only_spells_out_the_address_says_nothing() {
        for raw in [
            "192-168-1-5.example.lan",
            "192.168.1.5",
            "ip-192-168-1-5",
            "host-192-168-1-5.fritz.box",
        ] {
            assert_eq!(sanitize_name(raw, Some(IP)), None, "{raw}");
        }
    }

    #[test]
    fn a_name_that_merely_contains_similar_digits_is_kept() {
        // .50 is not .5, and another device's address is not this device's.
        for raw in [
            "192-168-1-50.lan",
            "printer-192-168-1-5x",
            "192-168-2-5.lan",
        ] {
            assert_eq!(sanitize_name(raw, Some(IP)).as_deref(), Some(raw), "{raw}");
        }
        // Without an address to compare against, nothing is filtered this way.
        assert!(sanitize_name("192-168-1-5.lan", None).is_some());
    }
}
