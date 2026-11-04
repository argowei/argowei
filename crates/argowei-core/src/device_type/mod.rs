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

/// What kind of device something is. Stored and serialized in lower case
/// (`"smartphone"`, ...).
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

/// The kind of signal a piece of [`Evidence`] comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// The organization the MAC prefix is registered to.
    Vendor,
    /// The MAC is locally administered (randomized).
    PrivateMac,
    Hostname,
    /// An open TCP or UDP port.
    Port,
    /// An advertised mDNS service.
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

impl Evidence {
    fn from_rule<P>(kind: EvidenceKind, detail: &str, rule: &Rule<P>) -> Self {
        Self {
            kind,
            detail: detail.to_owned(),
            device_type: rule.device_type,
            weight: rule.weight,
        }
    }
}

/// The classifier's answer for one device.
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

mod rules;

use rules::{Rule, HOSTNAMES, MDNS, PORTS, PRIVATE_MAC, VENDORS};

// --- classifier -----------------------------------------------------------

/// Infers a device type from the given signals. Deterministic: the same
/// signals (in any order) always produce the same classification.
pub fn classify(signals: &Signals) -> Classification {
    let mut evidence: Vec<Evidence> = Vec::new();

    if let Some(vendor) = signals.vendor {
        let lower = vendor.to_lowercase();
        if let Some(rule) = VENDORS.iter().find(|rule| lower.contains(rule.pattern)) {
            evidence.push(Evidence::from_rule(EvidenceKind::Vendor, vendor, rule));
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
        if let Some(rule) = HOSTNAMES.iter().find(|rule| {
            tokens
                .iter()
                .any(|token| token_matches(rule.pattern, token))
        }) {
            evidence.push(Evidence::from_rule(EvidenceKind::Hostname, hostname, rule));
        }
    }

    for &port in signals.open_ports {
        if let Some(rule) = PORTS.iter().find(|rule| rule.pattern == port) {
            let detail = format!("port {port} open");
            evidence.push(Evidence::from_rule(EvidenceKind::Port, &detail, rule));
        }
    }

    for service in signals.mdns_services {
        let name = service.to_lowercase();
        let name = name.split('.').next().unwrap_or_default();
        if let Some(rule) = MDNS.iter().find(|rule| rule.pattern == name) {
            evidence.push(Evidence::from_rule(EvidenceKind::Mdns, service, rule));
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
mod tests;
