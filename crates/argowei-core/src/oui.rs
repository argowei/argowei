//! Manufacturer lookup from a MAC address's OUI (the IEEE-assigned 24-bit
//! prefix), using the IEEE MA-L registry embedded at build time.
//!
//! Only globally unique (universally administered) addresses carry a
//! meaningful OUI. A locally administered address (second-lowest bit of the
//! first octet set) was not assigned by a manufacturer: phones and laptops
//! use such addresses for MAC randomization, and virtual interfaces use them
//! too. For those the OUI says nothing, so no vendor is reported.

use std::sync::OnceLock;

/// `prefix<TAB>organization` per line; `#` starts a comment. Regenerate with
/// `scripts/update-oui.sh`.
const EMBEDDED: &str = include_str!("../data/oui.tsv");

const LOCALLY_ADMINISTERED_BIT: u8 = 0b0000_0010;

/// A table of OUI prefixes, sorted for binary search. Borrows names from the
/// text it was parsed from, so the embedded table copies nothing.
pub struct OuiTable<'a> {
    entries: Vec<(u32, &'a str)>,
}

impl<'a> OuiTable<'a> {
    /// Parses `XXXXXX<TAB>Organization` lines. Malformed lines are skipped
    /// so one bad row cannot disable the whole table.
    pub fn parse(text: &'a str) -> Self {
        let mut entries: Vec<(u32, &str)> = text
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let (prefix, name) = line.split_once('\t')?;
                let name = name.trim();
                if prefix.len() != 6 || name.is_empty() {
                    return None;
                }
                Some((u32::from_str_radix(prefix, 16).ok()?, name))
            })
            .collect();
        entries.sort_by_key(|(prefix, _)| *prefix);
        entries.dedup_by_key(|(prefix, _)| *prefix);
        Self { entries }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Organization registered for a 24-bit OUI prefix.
    pub fn vendor_for_prefix(&self, prefix: u32) -> Option<&'a str> {
        self.entries
            .binary_search_by_key(&prefix, |(p, _)| *p)
            .ok()
            .map(|index| self.entries[index].1)
    }

    pub fn lookup(&self, mac: &str) -> MacInfo<'a> {
        let Some(octets) = parse_mac(mac) else {
            return MacInfo::default();
        };

        if octets[0] & LOCALLY_ADMINISTERED_BIT != 0 {
            return MacInfo {
                vendor: None,
                locally_administered: true,
            };
        }

        let prefix = u32::from_be_bytes([0, octets[0], octets[1], octets[2]]);
        MacInfo {
            vendor: self.vendor_for_prefix(prefix),
            locally_administered: false,
        }
    }
}

/// What a MAC address reveals about its origin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacInfo<'a> {
    /// Registered manufacturer; `None` when unknown, unregistered, or the
    /// address is locally administered.
    pub vendor: Option<&'a str>,
    /// The address was not assigned by a manufacturer. Typically MAC
    /// randomization by a phone or laptop, but virtual interfaces (VMs,
    /// containers, VPNs) use such addresses as well.
    pub locally_administered: bool,
}

/// Looks up a MAC address in the embedded IEEE registry. Accepts the usual
/// notations (`aa:bb:cc:dd:ee:ff`, `AA-BB-...`, `aabb.ccdd.eeff`, bare hex).
/// Unparseable input yields no vendor and no flags.
pub fn lookup(mac: &str) -> MacInfo<'static> {
    static TABLE: OnceLock<OuiTable<'static>> = OnceLock::new();
    TABLE.get_or_init(|| OuiTable::parse(EMBEDDED)).lookup(mac)
}

fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let hex: Vec<u8> = mac
        .bytes()
        .filter(|b| !matches!(b, b':' | b'-' | b'.'))
        .collect();
    if hex.len() != 12 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }

    let mut octets = [0u8; 6];
    for (octet, pair) in octets.iter_mut().zip(hex.chunks(2)) {
        *octet = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
# comment line
B827EB\tTest Pi Maker
00163E\tXen Test Corp
not-a-prefix\tBroken
ABCDEF\t
12345\tToo Short
";

    #[test]
    fn parses_fixture_and_skips_malformed_lines() {
        let table = OuiTable::parse(FIXTURE);

        assert_eq!(table.len(), 2);
        assert_eq!(table.vendor_for_prefix(0xB827EB), Some("Test Pi Maker"));
        assert_eq!(table.vendor_for_prefix(0x00163E), Some("Xen Test Corp"));
        assert_eq!(table.vendor_for_prefix(0xABCDEF), None);
    }

    #[test]
    fn known_oui_resolves_in_every_notation() {
        let table = OuiTable::parse(FIXTURE);

        for mac in [
            "b8:27:eb:12:34:56",
            "B8:27:EB:12:34:56",
            "b8-27-eb-12-34-56",
            "b827.eb12.3456",
            "b827eb123456",
        ] {
            assert_eq!(table.lookup(mac).vendor, Some("Test Pi Maker"), "{mac}");
        }
    }

    #[test]
    fn unknown_oui_has_no_vendor_and_is_not_flagged() {
        let info = OuiTable::parse(FIXTURE).lookup("00:11:22:33:44:55");

        assert_eq!(info, MacInfo::default());
    }

    #[test]
    fn locally_administered_addresses_report_no_vendor() {
        // 0x1a has the locally administered bit set. Even if its prefix were
        // registered, the OUI would not identify a manufacturer.
        let table = OuiTable::parse("1A56CE\tShould Not Appear\n");

        let info = table.lookup("1a:56:ce:30:fa:6c");

        assert_eq!(info.vendor, None);
        assert!(info.locally_administered);
    }

    #[test]
    fn universally_administered_addresses_are_not_flagged() {
        let info = OuiTable::parse(FIXTURE).lookup("b8:27:eb:00:00:01");

        assert!(!info.locally_administered);
    }

    #[test]
    fn invalid_input_is_neither_vendor_nor_randomized() {
        let table = OuiTable::parse(FIXTURE);

        for mac in ["", "b8:27:eb", "zz:27:eb:12:34:56", "b8:27:eb:12:34:56:78"] {
            assert_eq!(table.lookup(mac), MacInfo::default(), "{mac:?}");
        }
    }

    #[test]
    fn embedded_registry_is_loaded_and_resolves_well_known_vendors() {
        // Names change when IEEE renames an organization, so assert on a
        // stable substring and on table size rather than exact strings.
        assert!(OuiTable::parse(EMBEDDED).len() > 30_000);

        let pi = lookup("b8:27:eb:00:00:01")
            .vendor
            .expect("Raspberry Pi OUI");
        assert!(pi.contains("Raspberry"), "{pi}");
        let avm = lookup("bc:05:43:00:00:01").vendor.expect("AVM OUI");
        assert!(avm.contains("AVM"), "{avm}");
    }
}
