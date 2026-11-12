//! Comparing two port scans of the same device: which ports opened or
//! closed, and which services changed.
//!
//! A comparison is only meaningful where *both* scans looked. A quick scan
//! covers 100 ports, a full scan all of them; a port found open by the full
//! scan but outside the quick scan's coverage did not "open", it was simply
//! not looked at before. Each scan therefore carries its [`PortCoverage`]
//! (nmap reports exactly which ports it probed), and such ports are reported
//! as [`ScanDiff::not_comparable`] instead of opened or closed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::scan_profile::ScanProfile;

/// The ports a scan probed, per protocol, as nmap reports them in
/// `<scaninfo protocol="tcp" services="1,3-4,6-7,...">`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortCoverage {
    /// `(protocol, first, last)`, inclusive.
    ranges: Vec<(String, u16, u16)>,
}

impl PortCoverage {
    /// Every port of `protocol`.
    pub fn all(protocol: &str) -> Self {
        Self {
            ranges: vec![(protocol.to_owned(), 0, u16::MAX)],
        }
    }

    /// Adds nmap's `services` list for one protocol, e.g. `1,3-4,8080`.
    /// Returns `None` for a malformed list.
    pub fn add_services(&mut self, protocol: &str, services: &str) -> Option<()> {
        for part in services.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (first, last) = match part.split_once('-') {
                Some((a, b)) => (a.parse().ok()?, b.parse().ok()?),
                None => {
                    let port = part.parse().ok()?;
                    (port, port)
                }
            };
            if first > last {
                return None;
            }
            self.ranges.push((protocol.to_owned(), first, last));
        }
        Some(())
    }

    pub fn contains(&self, protocol: &str, port: u16) -> bool {
        self.ranges
            .iter()
            .any(|(p, first, last)| p == protocol && (*first..=*last).contains(&port))
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// One port as a scan saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortObservation {
    pub protocol: String,
    pub port: u16,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

impl PortObservation {
    fn is_open(&self) -> bool {
        self.state == "open"
    }
}

/// One side of a comparison.
#[derive(Debug, Clone)]
pub struct ScanSide<'a> {
    pub profile: ScanProfile,
    pub target: &'a str,
    pub coverage: &'a PortCoverage,
    pub ports: &'a [PortObservation],
}

/// What runs on a port, as far as a scan could tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

impl ServiceInfo {
    fn of(port: &PortObservation) -> Self {
        Self {
            service: port.service.clone(),
            product: port.product.clone(),
            version: port.version.clone(),
        }
    }

    /// Whether the scan identified the software, not just guessed a name
    /// from the port number.
    fn identified(&self) -> bool {
        self.product.is_some() || self.version.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortChange {
    pub protocol: String,
    pub port: u16,
    /// The service the side that saw the port open reported.
    pub service: ServiceInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceChange {
    pub protocol: String,
    pub port: u16,
    pub before: ServiceInfo,
    pub after: ServiceInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanDiff {
    /// Open now, not open before, and the earlier scan did look at it.
    pub opened: Vec<PortChange>,
    /// Open before, not open now, and the later scan did look at it.
    pub closed: Vec<PortChange>,
    /// Open in both, with a different service, product or version.
    pub changed: Vec<ServiceChange>,
    /// Open in both, nothing changed.
    pub unchanged: usize,
    /// Open in one scan, outside the other scan's coverage.
    pub not_comparable: Vec<PortChange>,
    /// The scans used different profiles: coverage differs, see
    /// `not_comparable`; versions are only compared when both identified them.
    pub profile_mismatch: bool,
    /// `(older, newer)` when the device was scanned at different addresses.
    pub address_changed: Option<(String, String)>,
}

impl ScanDiff {
    pub fn is_empty(&self) -> bool {
        self.opened.is_empty() && self.closed.is_empty() && self.changed.is_empty()
    }
}

type Key = (String, u16);

fn open_ports(ports: &[PortObservation]) -> BTreeMap<Key, &PortObservation> {
    ports
        .iter()
        .filter(|p| p.is_open())
        .map(|p| ((p.protocol.clone(), p.port), p))
        .collect()
}

/// Compares `older` with `newer`. Pure: the same scans always give the same
/// diff, ordered by protocol and port.
pub fn diff(older: &ScanSide, newer: &ScanSide) -> ScanDiff {
    let before = open_ports(older.ports);
    let after = open_ports(newer.ports);

    let mut result = ScanDiff {
        opened: Vec::new(),
        closed: Vec::new(),
        changed: Vec::new(),
        unchanged: 0,
        not_comparable: Vec::new(),
        profile_mismatch: older.profile != newer.profile,
        address_changed: (older.target != newer.target)
            .then(|| (older.target.to_owned(), newer.target.to_owned())),
    };

    for ((protocol, port), now) in &after {
        let change = || PortChange {
            protocol: protocol.clone(),
            port: *port,
            service: ServiceInfo::of(now),
        };
        match before.get(&(protocol.clone(), *port)) {
            Some(then) => {
                let (was, is) = (ServiceInfo::of(then), ServiceInfo::of(now));
                if service_changed(&was, &is) {
                    result.changed.push(ServiceChange {
                        protocol: protocol.clone(),
                        port: *port,
                        before: was,
                        after: is,
                    });
                } else {
                    result.unchanged += 1;
                }
            }
            None if older.coverage.contains(protocol, *port) => result.opened.push(change()),
            None => result.not_comparable.push(change()),
        }
    }

    for ((protocol, port), then) in &before {
        if after.contains_key(&(protocol.clone(), *port)) {
            continue;
        }
        let change = PortChange {
            protocol: protocol.clone(),
            port: *port,
            service: ServiceInfo::of(then),
        };
        if newer.coverage.contains(protocol, *port) {
            result.closed.push(change);
        } else {
            result.not_comparable.push(change);
        }
    }
    result
        .not_comparable
        .sort_by(|a, b| (&a.protocol, a.port).cmp(&(&b.protocol, b.port)));
    result
}

/// A service counts as changed when both scans name it differently, or when
/// both identified the software and product or version differ. A scan
/// without version detection only guesses the name from the port number, so
/// "SimpleHTTPServer 0.6" versus "unknown" is not a change.
fn service_changed(was: &ServiceInfo, is: &ServiceInfo) -> bool {
    let names_differ = matches!((&was.service, &is.service), (Some(a), Some(b)) if a != b);
    let versions_differ = was.identified()
        && is.identified()
        && (was.product != is.product || was.version != is.version);
    names_differ || versions_differ
}

#[cfg(test)]
mod tests;
