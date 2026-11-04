//! Rule-based device type inference.
//!
//! The classifier is a pure function of the signals it is given, so the same
//! input always yields the same answer, and every answer carries the evidence
//! behind it. Nothing is a black box: each rule that fired is returned with
//! its weight, so a user can see why a device was called a printer and
//! correct it.
//!
//! Weights are percentages of confidence a single signal gives to one type.
//! Evidence for the same type combines like independent witnesses
//! (`1 - Π(1 - w)`), so weak signals add up without ever reaching certainty;
//! the result is capped at [`MAX_CONFIDENCE`]. A signal kind contributes at
//! most once per type (many open printer ports are still one kind of
//! evidence), which keeps noisy kinds from drowning out the rest.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Inference is never certain, however much evidence agrees.
pub const MAX_CONFIDENCE: u8 = 95;
/// Below this the evidence is too thin to name a type.
pub const MIN_CONFIDENCE: u8 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Smartphone,
    Laptop,
    Server,
    Iot,
    Printer,
    Router,
    Unknown,
}

impl DeviceType {
    pub const ALL: [DeviceType; 7] = [
        Self::Smartphone,
        Self::Laptop,
        Self::Server,
        Self::Iot,
        Self::Printer,
        Self::Router,
        Self::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smartphone => "smartphone",
            Self::Laptop => "laptop",
            Self::Server => "server",
            Self::Iot => "iot",
            Self::Printer => "printer",
            Self::Router => "router",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == value)
    }

    /// Order used to break exact ties, most specific kind first, so the
    /// outcome never depends on iteration order.
    fn priority(self) -> u8 {
        match self {
            Self::Router => 0,
            Self::Printer => 1,
            Self::Server => 2,
            Self::Iot => 3,
            Self::Laptop => 4,
            Self::Smartphone => 5,
            Self::Unknown => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Vendor,
    PrivateMac,
    Hostname,
    Port,
    Mdns,
}

/// One rule that fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    /// What was observed (the vendor name, the port, the service type, ...).
    pub detail: String,
    #[serde(rename = "type")]
    pub device_type: DeviceType,
    /// Confidence in percent this one signal gives to `device_type`.
    pub weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub device_type: DeviceType,
    /// 0-100; 0 when the type is `Unknown`.
    pub confidence: u8,
    /// Every rule that fired, strongest first (also when the result is
    /// `Unknown`, to show what little there was).
    pub evidence: Vec<Evidence>,
}

impl Default for Classification {
    fn default() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            confidence: 0,
            evidence: Vec::new(),
        }
    }
}

/// Everything the classifier may look at. Sources that do not exist yet
/// (open ports, mDNS) are simply empty.
#[derive(Debug, Default, Clone, Copy)]
pub struct Signals<'a> {
    pub vendor: Option<&'a str>,
    /// The MAC is locally administered (typically MAC randomization).
    pub locally_administered_mac: bool,
    pub hostname: Option<&'a str>,
    pub open_ports: &'a [u16],
    /// mDNS service types such as `_ipp._tcp.local`.
    pub mdns_services: &'a [&'a str],
}

// --- rule tables ----------------------------------------------------------
//
// Order matters only within a table: for vendor and hostname the first
// matching rule wins, so list the more specific pattern first.

use DeviceType::{Iot, Laptop, Printer, Router, Server, Smartphone};

/// (case-insensitive substring of the registered organization, type, weight)
const VENDORS: &[(&str, DeviceType, u8)] = &[
    ("brother", Printer, 70),
    ("canon", Printer, 65),
    ("epson", Printer, 70),
    ("lexmark", Printer, 75),
    ("xerox", Printer, 65),
    ("kyocera", Printer, 70),
    ("ricoh", Printer, 65),
    ("konica", Printer, 70),
    ("hewlett packard", Printer, 30),
    ("avm", Router, 70),
    ("mikrotik", Router, 75),
    ("routerboard", Router, 75),
    ("ubiquiti", Router, 60),
    ("netgear", Router, 60),
    ("d-link", Router, 60),
    ("tp-link", Router, 55),
    ("zyxel", Router, 65),
    ("linksys", Router, 65),
    ("technicolor", Router, 65),
    ("sagemcom", Router, 65),
    ("synology", Server, 80),
    ("qnap", Server, 80),
    ("supermicro", Server, 70),
    ("proxmox", Server, 80),
    ("vmware", Server, 65),
    ("xensource", Server, 65),
    ("raspberry pi", Server, 40),
    ("espressif", Iot, 75),
    ("tuya", Iot, 70),
    ("allterco", Iot, 80),
    ("shelly", Iot, 80),
    ("sonos", Iot, 75),
    ("signify", Iot, 75),
    ("philips lighting", Iot, 75),
    ("roku", Iot, 75),
    ("ecobee", Iot, 75),
    ("wyze", Iot, 75),
    ("itead", Iot, 75),
    ("ring llc", Iot, 70),
    ("nest labs", Iot, 70),
    ("amazon technologies", Iot, 55),
    ("google", Iot, 30),
    ("oneplus", Smartphone, 70),
    ("fairphone", Smartphone, 70),
    ("realme", Smartphone, 65),
    ("vivo mobile", Smartphone, 65),
    ("motorola mobility", Smartphone, 65),
    ("oppo", Smartphone, 60),
    ("xiaomi", Smartphone, 45),
    ("huawei", Smartphone, 30),
    ("samsung", Smartphone, 25),
    ("apple", Smartphone, 30),
    ("lenovo", Laptop, 55),
    ("acer", Laptop, 55),
    ("liteon", Laptop, 45),
    ("azurewave", Laptop, 40),
    ("dell", Laptop, 35),
    ("microsoft", Laptop, 35),
    ("intel corporate", Laptop, 35),
    ("asustek", Laptop, 35),
];

/// (hostname token, type, weight); a trailing `*` matches a token prefix,
/// anything else must equal a whole token (so "nas" does not match "kenas").
const HOSTNAMES: &[(&str, DeviceType, u8)] = &[
    ("iphone*", Smartphone, 80),
    ("ipad*", Smartphone, 75),
    ("android*", Smartphone, 75),
    ("galaxy*", Smartphone, 70),
    ("pixel*", Smartphone, 70),
    ("oneplus*", Smartphone, 80),
    ("redmi*", Smartphone, 70),
    ("macbook*", Laptop, 85),
    ("thinkpad*", Laptop, 85),
    ("laptop*", Laptop, 80),
    ("notebook*", Laptop, 75),
    ("imac*", Laptop, 70),
    ("surface*", Laptop, 60),
    ("desktop*", Laptop, 60),
    ("printer*", Printer, 90),
    ("laserjet*", Printer, 90),
    ("officejet*", Printer, 90),
    ("deskjet*", Printer, 90),
    ("mfc*", Printer, 85),
    ("dcp*", Printer, 85),
    ("brn*", Printer, 60),
    ("epson*", Printer, 80),
    ("fritz*", Router, 85),
    ("router*", Router, 85),
    ("speedport*", Router, 85),
    ("openwrt*", Router, 90),
    ("edgerouter*", Router, 90),
    ("mikrotik*", Router, 85),
    ("ubnt*", Router, 70),
    ("gateway", Router, 60),
    ("server*", Server, 80),
    ("nas", Server, 55),
    ("pve*", Server, 70),
    ("proxmox*", Server, 80),
    ("docker*", Server, 70),
    ("raspberrypi", Server, 60),
    ("synology*", Server, 80),
    ("truenas*", Server, 80),
    ("unraid*", Server, 80),
    ("homeassistant", Server, 70),
    ("esp*", Iot, 85),
    ("tasmota*", Iot, 90),
    ("shelly*", Iot, 90),
    ("chromecast*", Iot, 85),
    ("sonos*", Iot, 85),
    ("roku*", Iot, 85),
    ("echo", Iot, 60),
    ("hue", Iot, 70),
    ("tv", Iot, 55),
    ("cam", Iot, 70),
    ("camera*", Iot, 70),
    ("thermostat*", Iot, 75),
    ("plug", Iot, 60),
    ("bulb", Iot, 60),
];

/// (TCP/UDP port, type, weight)
const PORTS: &[(u16, DeviceType, u8)] = &[
    (9100, Printer, 80),
    (631, Printer, 75),
    (515, Printer, 60),
    (62078, Smartphone, 80),
    (8008, Iot, 70),
    (8009, Iot, 70),
    (8291, Router, 80),
    (8728, Router, 70),
    (7547, Router, 70),
    (53, Router, 50),
    (5060, Router, 30),
    (8123, Server, 60),
    (5000, Server, 45),
    (5001, Server, 45),
    (2049, Server, 50),
    (1883, Server, 40),
    (22, Server, 30),
    (3389, Laptop, 55),
    (548, Laptop, 40),
    (445, Laptop, 25),
];

/// (service name without `._tcp`/`._udp`, type, weight)
const MDNS: &[(&str, DeviceType, u8)] = &[
    ("_ipp", Printer, 90),
    ("_ipps", Printer, 90),
    ("_printer", Printer, 90),
    ("_pdl-datastream", Printer, 90),
    ("_scanner", Printer, 70),
    ("_apple-mobdev2", Smartphone, 85),
    ("_companion-link", Smartphone, 50),
    ("_googlecast", Iot, 80),
    ("_hap", Iot, 80),
    ("_matter", Iot, 80),
    ("_esphomelib", Iot, 90),
    ("_sonos", Iot, 85),
    ("_hue", Iot, 80),
    ("_airplay", Iot, 50),
    ("_raop", Iot, 45),
    ("_spotify-connect", Iot, 50),
    ("_homeassistant", Server, 80),
    ("_nfs", Server, 55),
    ("_afpovertcp", Server, 40),
    ("_smb", Server, 40),
    ("_ssh", Server, 35),
    ("_sftp-ssh", Server, 35),
    ("_workstation", Laptop, 30),
];

/// Weak hint: phones and laptops randomize their MAC by default.
const PRIVATE_MAC: &[(DeviceType, u8)] = &[(Smartphone, 25), (Laptop, 15)];

// --- classifier -----------------------------------------------------------

/// Infers a device type from the given signals. Deterministic: the same
/// signals (in any order) always produce the same classification.
pub fn classify(signals: &Signals) -> Classification {
    let mut evidence: Vec<Evidence> = Vec::new();

    if let Some(vendor) = signals.vendor {
        let lower = vendor.to_lowercase();
        if let Some(&(_, device_type, weight)) =
            VENDORS.iter().find(|(needle, _, _)| lower.contains(needle))
        {
            evidence.push(Evidence {
                kind: EvidenceKind::Vendor,
                detail: vendor.to_owned(),
                device_type,
                weight,
            });
        }
    }

    if signals.locally_administered_mac {
        for &(device_type, weight) in PRIVATE_MAC {
            evidence.push(Evidence {
                kind: EvidenceKind::PrivateMac,
                detail: "locally administered (private) MAC address".to_owned(),
                device_type,
                weight,
            });
        }
    }

    if let Some(hostname) = signals.hostname {
        let lower = hostname.to_lowercase();
        let tokens: Vec<&str> = lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .collect();
        if let Some(&(_, device_type, weight)) = HOSTNAMES
            .iter()
            .find(|(pattern, _, _)| tokens.iter().any(|token| token_matches(pattern, token)))
        {
            evidence.push(Evidence {
                kind: EvidenceKind::Hostname,
                detail: hostname.to_owned(),
                device_type,
                weight,
            });
        }
    }

    for &port in signals.open_ports {
        if let Some(&(_, device_type, weight)) = PORTS.iter().find(|(p, _, _)| *p == port) {
            evidence.push(Evidence {
                kind: EvidenceKind::Port,
                detail: format!("port {port} open"),
                device_type,
                weight,
            });
        }
    }

    for service in signals.mdns_services {
        let name = service.to_lowercase();
        let name = name.split('.').next().unwrap_or_default();
        if let Some(&(_, device_type, weight)) = MDNS.iter().find(|(n, _, _)| *n == name) {
            evidence.push(Evidence {
                kind: EvidenceKind::Mdns,
                detail: (*service).to_owned(),
                device_type,
                weight,
            });
        }
    }

    // A signal kind counts at most once per type: keep its strongest piece.
    let mut strongest: BTreeMap<(DeviceType, EvidenceKind), u8> = BTreeMap::new();
    for item in &evidence {
        let slot = strongest.entry((item.device_type, item.kind)).or_insert(0);
        *slot = (*slot).max(item.weight);
    }

    // Independent witnesses: P = 1 - Π(1 - w), computed in integer percent.
    let mut per_type: BTreeMap<DeviceType, f64> = BTreeMap::new();
    for ((device_type, _), weight) in &strongest {
        let miss = per_type.entry(*device_type).or_insert(1.0);
        *miss *= 1.0 - f64::from(*weight) / 100.0;
    }

    let best = per_type
        .iter()
        .map(|(device_type, miss)| (*device_type, ((1.0 - miss) * 100.0).round() as u8))
        .max_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.0.priority().cmp(&a.0.priority()))
        });

    // Strongest first; ties by kind, type, then detail so the list is stable.
    evidence.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then(a.kind.cmp(&b.kind))
            .then(a.device_type.priority().cmp(&b.device_type.priority()))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    evidence.dedup();

    match best {
        Some((device_type, confidence)) if confidence >= MIN_CONFIDENCE => Classification {
            device_type,
            confidence: confidence.min(MAX_CONFIDENCE),
            evidence,
        },
        _ => Classification {
            device_type: DeviceType::Unknown,
            confidence: 0,
            evidence,
        },
    }
}

fn token_matches(pattern: &str, token: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => token.starts_with(prefix),
        None => token == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_vendor(vendor: &str) -> Classification {
        classify(&Signals {
            vendor: Some(vendor),
            ..Signals::default()
        })
    }

    fn classify_hostname(hostname: &str) -> Classification {
        classify(&Signals {
            hostname: Some(hostname),
            ..Signals::default()
        })
    }

    /// (input, expected type, expected confidence)
    #[test]
    fn vendors_name_a_type_in_proportion_to_how_telling_they_are() {
        let cases = [
            ("Brother industries, LTD.", DeviceType::Printer, 70),
            (
                "AVM Audiovisuelles Marketing und Computersysteme GmbH",
                DeviceType::Router,
                70,
            ),
            ("Synology Incorporated", DeviceType::Server, 80),
            ("Espressif Inc.", DeviceType::Iot, 75),
            ("Raspberry Pi Foundation", DeviceType::Server, 40),
            ("Lenovo Mobile Communication", DeviceType::Laptop, 55),
            // Weak, ambiguous vendors still count when they reach the threshold ...
            ("Apple, Inc.", DeviceType::Smartphone, 30),
            ("Hewlett Packard", DeviceType::Printer, 30),
            // ... and fall to Unknown when they do not.
            ("Samsung Electronics Co.,Ltd", DeviceType::Unknown, 0),
            ("Some Unlisted Vendor Ltd", DeviceType::Unknown, 0),
        ];

        for (vendor, expected_type, expected_confidence) in cases {
            let result = classify_vendor(vendor);
            assert_eq!(
                (result.device_type, result.confidence),
                (expected_type, expected_confidence),
                "{vendor}"
            );
        }
    }

    #[test]
    fn vendor_matching_ignores_case() {
        assert_eq!(
            classify_vendor("BROTHER INDUSTRIES").device_type,
            DeviceType::Printer
        );
    }

    #[test]
    fn hostnames_match_whole_tokens_or_prefixes() {
        let cases = [
            ("iPhone-von-Anna", DeviceType::Smartphone, 80),
            ("DESKTOP-AB12CD", DeviceType::Laptop, 60),
            ("Brother-MFC-L2750DW", DeviceType::Printer, 85),
            ("fritz.box", DeviceType::Router, 85),
            ("esp32-living-room", DeviceType::Iot, 85),
            ("living-room-tv", DeviceType::Iot, 55),
            ("backup-nas", DeviceType::Server, 55),
            ("raspberrypi", DeviceType::Server, 60),
            // "nas" must be a whole token: this is just a name.
            ("kenas", DeviceType::Unknown, 0),
            ("annas-room", DeviceType::Unknown, 0),
            ("", DeviceType::Unknown, 0),
        ];

        for (hostname, expected_type, expected_confidence) in cases {
            let result = classify_hostname(hostname);
            assert_eq!(
                (result.device_type, result.confidence),
                (expected_type, expected_confidence),
                "{hostname:?}"
            );
        }
    }

    #[test]
    fn open_ports_hint_at_a_type() {
        let cases: [(&[u16], DeviceType, u8); 6] = [
            (&[9100], DeviceType::Printer, 80),
            (&[62078], DeviceType::Smartphone, 80),
            (&[8291], DeviceType::Router, 80),
            (&[22], DeviceType::Server, 30),
            // Everyone has a web server; that says nothing.
            (&[80, 443], DeviceType::Unknown, 0),
            // Several printer ports are one kind of evidence, not three.
            (&[631, 9100, 515], DeviceType::Printer, 80),
        ];

        for (ports, expected_type, expected_confidence) in cases {
            let result = classify(&Signals {
                open_ports: ports,
                ..Signals::default()
            });
            assert_eq!(
                (result.device_type, result.confidence),
                (expected_type, expected_confidence),
                "{ports:?}"
            );
        }
    }

    #[test]
    fn mdns_service_types_are_normalized_and_matched() {
        let result = classify(&Signals {
            mdns_services: &["_IPP._tcp.local", "_unknown-thing._tcp.local"],
            ..Signals::default()
        });

        assert_eq!(
            (result.device_type, result.confidence),
            (DeviceType::Printer, 90)
        );
        assert_eq!(
            result.evidence.len(),
            1,
            "an unknown service is not evidence"
        );

        let casts = classify(&Signals {
            mdns_services: &["_googlecast._tcp.local", "_airplay._tcp.local"],
            ..Signals::default()
        });
        // Same kind of evidence for the same type: the strongest counts once.
        assert_eq!((casts.device_type, casts.confidence), (DeviceType::Iot, 80));
    }

    #[test]
    fn agreeing_evidence_combines_but_never_reaches_certainty() {
        let printer = classify(&Signals {
            vendor: Some("Brother industries, LTD."),
            mdns_services: &["_ipp._tcp.local"],
            ..Signals::default()
        });
        // 1 - 0.30 * 0.10 = 97, capped.
        assert_eq!(
            (printer.device_type, printer.confidence),
            (DeviceType::Printer, MAX_CONFIDENCE)
        );

        let phone = classify(&Signals {
            vendor: Some("Apple, Inc."),
            hostname: Some("iPhone-von-Anna"),
            ..Signals::default()
        });
        // 1 - 0.70 * 0.20 = 86.
        assert_eq!(
            (phone.device_type, phone.confidence),
            (DeviceType::Smartphone, 86)
        );
    }

    #[test]
    fn a_private_mac_alone_is_too_weak_to_name_a_type() {
        let result = classify(&Signals {
            locally_administered_mac: true,
            ..Signals::default()
        });

        assert_eq!(
            (result.device_type, result.confidence),
            (DeviceType::Unknown, 0)
        );
        // The evidence is still reported, so the UI can say what little there was.
        assert!(result
            .evidence
            .iter()
            .all(|e| e.kind == EvidenceKind::PrivateMac));
        assert_eq!(result.evidence.len(), 2);
    }

    #[test]
    fn a_private_mac_tips_weak_evidence_over_the_threshold() {
        let result = classify(&Signals {
            vendor: Some("Apple, Inc."),
            locally_administered_mac: true,
            ..Signals::default()
        });

        // Smartphone: 1 - 0.70 * 0.75 = 48.
        assert_eq!(
            (result.device_type, result.confidence),
            (DeviceType::Smartphone, 48)
        );
    }

    #[test]
    fn the_better_supported_type_wins_a_conflict() {
        let result = classify(&Signals {
            vendor: Some("Dell Inc."),
            open_ports: &[22],
            ..Signals::default()
        });

        assert_eq!(
            (result.device_type, result.confidence),
            (DeviceType::Laptop, 35)
        );
        assert_eq!(result.evidence.len(), 2, "both signals are reported");
    }

    #[test]
    fn exact_ties_resolve_by_a_fixed_priority_not_by_input_order() {
        // Port 53 (router, 50) and port 2049 (server, 50) tie.
        for ports in [[53u16, 2049], [2049, 53]] {
            let result = classify(&Signals {
                open_ports: &ports,
                ..Signals::default()
            });
            assert_eq!(
                (result.device_type, result.confidence),
                (DeviceType::Router, 50),
                "{ports:?}"
            );
        }
    }

    #[test]
    fn the_result_does_not_depend_on_input_order() {
        let a = classify(&Signals {
            vendor: Some("Brother industries, LTD."),
            hostname: Some("BRN001122"),
            open_ports: &[9100, 631, 80, 22],
            mdns_services: &["_ipp._tcp.local", "_printer._tcp.local"],
            ..Signals::default()
        });
        let b = classify(&Signals {
            vendor: Some("Brother industries, LTD."),
            hostname: Some("BRN001122"),
            open_ports: &[22, 80, 631, 9100],
            mdns_services: &["_printer._tcp.local", "_ipp._tcp.local"],
            ..Signals::default()
        });

        assert_eq!(a, b);
        assert_eq!(
            a,
            classify(&Signals {
                vendor: Some("Brother industries, LTD."),
                hostname: Some("BRN001122"),
                open_ports: &[9100, 631, 80, 22],
                mdns_services: &["_ipp._tcp.local", "_printer._tcp.local"],
                ..Signals::default()
            })
        );
    }

    #[test]
    fn evidence_lists_only_fired_rules_strongest_first() {
        let result = classify(&Signals {
            vendor: Some("Dell Inc."),
            hostname: Some("thinkpad-x1"),
            open_ports: &[22, 80],
            ..Signals::default()
        });

        let weights: Vec<u8> = result.evidence.iter().map(|e| e.weight).collect();
        assert_eq!(weights, vec![85, 35, 30]);
        assert_eq!(result.evidence[0].kind, EvidenceKind::Hostname);
        assert_eq!(result.evidence[2].detail, "port 22 open");
    }

    #[test]
    fn nothing_known_means_unknown_with_no_confidence() {
        assert_eq!(classify(&Signals::default()), Classification::default());
    }

    #[test]
    fn confidence_is_zero_exactly_when_the_type_is_unknown() {
        let samples = [
            Signals::default(),
            Signals {
                vendor: Some("Samsung"),
                ..Signals::default()
            },
            Signals {
                vendor: Some("Brother"),
                ..Signals::default()
            },
            Signals {
                open_ports: &[22],
                ..Signals::default()
            },
        ];
        for signals in samples {
            let result = classify(&signals);
            assert_eq!(
                result.device_type == DeviceType::Unknown,
                result.confidence == 0,
                "{signals:?}"
            );
            assert!(result.confidence <= MAX_CONFIDENCE);
        }
    }

    #[test]
    fn device_types_round_trip_through_text_and_json() {
        for device_type in DeviceType::ALL {
            assert_eq!(DeviceType::parse(device_type.as_str()), Some(device_type));
            assert_eq!(
                serde_json::to_string(&device_type).unwrap(),
                format!("\"{}\"", device_type.as_str())
            );
        }
        assert_eq!(DeviceType::parse("Printer"), None);
        assert_eq!(DeviceType::parse("toaster"), None);
    }

    #[test]
    fn a_classification_survives_a_json_round_trip() {
        let original = classify(&Signals {
            vendor: Some("Brother industries, LTD."),
            open_ports: &[9100],
            ..Signals::default()
        });

        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["evidence"][0]["kind"], "port");
        assert_eq!(json["evidence"][0]["type"], "printer");
        assert_eq!(
            serde_json::from_value::<Classification>(json).unwrap(),
            original
        );
    }

    /// The tables must not contain two rules that can never be told apart,
    /// or a typo that would silently shadow a rule.
    #[test]
    fn rule_tables_have_no_duplicates_and_sane_weights() {
        fn unique<T: Ord + Copy + std::fmt::Debug>(items: Vec<T>) {
            let mut sorted = items.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), items.len(), "duplicate rule in {items:?}");
        }

        unique(VENDORS.iter().map(|r| r.0).collect());
        unique(HOSTNAMES.iter().map(|r| r.0).collect());
        unique(PORTS.iter().map(|r| r.0).collect());
        unique(MDNS.iter().map(|r| r.0).collect());

        let weights = VENDORS
            .iter()
            .map(|r| r.2)
            .chain(HOSTNAMES.iter().map(|r| r.2))
            .chain(PORTS.iter().map(|r| r.2))
            .chain(MDNS.iter().map(|r| r.2));
        for weight in weights {
            assert!((1..=95).contains(&weight), "weight {weight} out of range");
        }
        assert!(VENDORS.iter().all(|r| r.1 != DeviceType::Unknown));
    }
}
