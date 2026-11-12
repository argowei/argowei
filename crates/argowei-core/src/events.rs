//! The event vocabulary: what can appear on the timeline, at which severity,
//! and the exact shape of each event's payload.
//!
//! Every event is one variant of [`Event`], which wraps a payload struct of
//! its own. Recording goes through `Event`, so an event type can never be
//! stored with another type's payload, and the payload structs below are the
//! documented schema (`docs/EVENTS.md` lists them for readers of the API).
//!
//! # Versioning
//!
//! [`EventKind::schema_version`] is stored with every event. Adding an
//! optional field keeps the version; renaming or removing a field, or
//! changing what a field means, bumps it, so stored history stays readable:
//! a consumer checks `(type, schema_version)` before interpreting a payload.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::names::NameSource;
use crate::scan_profile::ScanProfile;

/// How much attention an event deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 3] = [Self::Info, Self::Warning, Self::Critical];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }
}

/// The type of an event, stored as its `as_str` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "device.discovered")]
    DeviceDiscovered,
    #[serde(rename = "device.online")]
    DeviceOnline,
    #[serde(rename = "device.offline")]
    DeviceOffline,
    #[serde(rename = "device.named")]
    DeviceNamed,
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    #[serde(rename = "scan.failed")]
    ScanFailed,
}

impl EventKind {
    pub const ALL: [EventKind; 6] = [
        Self::DeviceDiscovered,
        Self::DeviceOnline,
        Self::DeviceOffline,
        Self::DeviceNamed,
        Self::ScanCompleted,
        Self::ScanFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceDiscovered => "device.discovered",
            Self::DeviceOnline => "device.online",
            Self::DeviceOffline => "device.offline",
            Self::DeviceNamed => "device.named",
            Self::ScanCompleted => "scan.completed",
            Self::ScanFailed => "scan.failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == value)
    }

    /// Version of this type's payload schema; see the module docs.
    pub fn schema_version(self) -> i16 {
        match self {
            Self::DeviceDiscovered
            | Self::DeviceOnline
            | Self::DeviceOffline
            | Self::DeviceNamed
            | Self::ScanCompleted
            | Self::ScanFailed => 1,
        }
    }

    /// The severity every event of this type is recorded with.
    pub fn severity(self) -> Severity {
        match self {
            Self::DeviceDiscovered
            | Self::DeviceOnline
            | Self::DeviceOffline
            | Self::DeviceNamed
            | Self::ScanCompleted
            | Self::ScanFailed => Severity::Info,
        }
    }
}

/// An event ready to be recorded: its type and its payload, which always
/// belong together. Serializes as the bare payload object.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Event {
    DeviceDiscovered(DeviceDiscovered),
    DeviceOnline(DeviceOnline),
    DeviceOffline(DeviceOffline),
    DeviceNamed(DeviceNamed),
    ScanCompleted(ScanCompleted),
    ScanFailed(ScanFailed),
}

impl Event {
    pub fn kind(&self) -> EventKind {
        match self {
            Self::DeviceDiscovered(_) => EventKind::DeviceDiscovered,
            Self::DeviceOnline(_) => EventKind::DeviceOnline,
            Self::DeviceOffline(_) => EventKind::DeviceOffline,
            Self::DeviceNamed(_) => EventKind::DeviceNamed,
            Self::ScanCompleted(_) => EventKind::ScanCompleted,
            Self::ScanFailed(_) => EventKind::ScanFailed,
        }
    }
}

/// `device.discovered` (v1): the first sighting of a MAC address, which also
/// starts the device's first online period.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceDiscovered {
    /// Interface the scan ran on.
    pub interface: String,
    /// The ARP scan (`discovery_scans.id`) that saw the device.
    pub scan_id: i64,
    /// The IPv4 address it answered from.
    pub ip: String,
    /// Learned silently during the interface's baseline: analyses of how a
    /// network grew can tell baseline devices from new ones.
    pub baseline: bool,
}

/// `device.online` (v1): a known device answered again after having been
/// marked offline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceOnline {
    pub interface: String,
    pub scan_id: i64,
    pub ip: String,
    /// When it was last seen before it went offline.
    pub last_seen_before: DateTime<Utc>,
}

/// `device.offline` (v1): a device missed enough scans, for long enough, to
/// be considered gone. Carries the evidence and the policy that decided it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceOffline {
    pub interface: String,
    pub last_seen: DateTime<Utc>,
    /// Scans of the interface that ran since `last_seen`.
    pub missed_scans: i64,
    pub silent_for_secs: i64,
    pub policy: OfflinePolicy,
}

/// The presence policy in force when a device was marked offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflinePolicy {
    pub offline_after_missed_scans: u32,
    pub offline_after_secs: u64,
}

/// `device.named` (v1): the name shown for a device changed because a source
/// named it (or a better-ranked source did).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceNamed {
    pub from: String,
    pub to: String,
    /// The source the new name comes from.
    pub source: NameSource,
    /// Every source's current answer, the chosen one included.
    pub answers: Vec<NameAnswer>,
}

/// One source's answer in a [`DeviceNamed`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameAnswer {
    pub source: NameSource,
    pub name: String,
}

/// `scan.completed` (v1): a port scan finished and its results are stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanCompleted {
    /// `scans.id`; the full result is at `GET /api/scans/{scan_id}`.
    pub scan_id: i64,
    pub profile: ScanProfile,
    /// The address that was scanned.
    pub target: String,
    /// Open TCP ports found, ascending.
    pub open_ports: Vec<u16>,
    /// Wall-clock run time of nmap in seconds.
    pub duration_secs: f64,
}

/// `scan.failed` (v1): a port scan ended without a result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanFailed {
    pub scan_id: i64,
    pub profile: ScanProfile,
    pub target: String,
    /// `failed`, `timed_out` or `cancelled`.
    pub outcome: String,
    /// What went wrong, in words.
    pub error: String,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[test]
    fn kinds_and_severities_round_trip_through_their_text() {
        for kind in EventKind::ALL {
            assert_eq!(EventKind::parse(kind.as_str()), Some(kind));
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(kind.as_str()));
            assert!(kind.schema_version() >= 1);
        }
        for severity in Severity::ALL {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
            assert_eq!(
                serde_json::to_value(severity).unwrap(),
                json!(severity.as_str())
            );
        }
        assert_eq!(EventKind::parse("device.new"), None);
        assert_eq!(Severity::parse("Info"), None);
    }

    /// The payloads are what discovery stored before they had types: the
    /// stored history and the typed structs must agree field for field.
    #[test]
    fn payloads_serialize_to_the_documented_shape() {
        let at = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        let cases = [
            (
                Event::DeviceDiscovered(DeviceDiscovered {
                    interface: "eth0".into(),
                    scan_id: 7,
                    ip: "192.168.1.5".into(),
                    baseline: true,
                }),
                json!({ "interface": "eth0", "scan_id": 7, "ip": "192.168.1.5", "baseline": true }),
            ),
            (
                Event::DeviceOnline(DeviceOnline {
                    interface: "eth0".into(),
                    scan_id: 8,
                    ip: "192.168.1.5".into(),
                    last_seen_before: at,
                }),
                json!({ "interface": "eth0", "scan_id": 8, "ip": "192.168.1.5",
                        "last_seen_before": "2026-01-01T12:00:00Z" }),
            ),
            (
                Event::DeviceOffline(DeviceOffline {
                    interface: "eth0".into(),
                    last_seen: at,
                    missed_scans: 3,
                    silent_for_secs: 900,
                    policy: OfflinePolicy {
                        offline_after_missed_scans: 3,
                        offline_after_secs: 900,
                    },
                }),
                json!({ "interface": "eth0", "last_seen": "2026-01-01T12:00:00Z",
                        "missed_scans": 3, "silent_for_secs": 900,
                        "policy": { "offline_after_missed_scans": 3, "offline_after_secs": 900 } }),
            ),
            (
                Event::DeviceNamed(DeviceNamed {
                    from: "aa:bb:cc:00:00:01".into(),
                    to: "iPhone".into(),
                    source: NameSource::Rdns,
                    answers: vec![NameAnswer {
                        source: NameSource::Rdns,
                        name: "iPhone".into(),
                    }],
                }),
                json!({ "from": "aa:bb:cc:00:00:01", "to": "iPhone", "source": "rdns",
                        "answers": [{ "source": "rdns", "name": "iPhone" }] }),
            ),
        ];

        for (event, expected) in cases {
            assert_eq!(
                serde_json::to_value(&event).unwrap(),
                expected,
                "{:?}",
                event.kind()
            );
        }
    }

    #[test]
    fn every_kind_has_an_event_variant() {
        // Adding a kind without a payload struct would leave it unrecordable.
        let kinds: Vec<_> = [
            Event::DeviceDiscovered(DeviceDiscovered {
                interface: String::new(),
                scan_id: 0,
                ip: String::new(),
                baseline: false,
            }),
            Event::DeviceOnline(DeviceOnline {
                interface: String::new(),
                scan_id: 0,
                ip: String::new(),
                last_seen_before: Utc::now(),
            }),
            Event::DeviceOffline(DeviceOffline {
                interface: String::new(),
                last_seen: Utc::now(),
                missed_scans: 0,
                silent_for_secs: 0,
                policy: OfflinePolicy {
                    offline_after_missed_scans: 1,
                    offline_after_secs: 0,
                },
            }),
            Event::DeviceNamed(DeviceNamed {
                from: String::new(),
                to: String::new(),
                source: NameSource::Dhcp,
                answers: Vec::new(),
            }),
            Event::ScanCompleted(ScanCompleted {
                scan_id: 0,
                profile: ScanProfile::Quick,
                target: String::new(),
                open_ports: Vec::new(),
                duration_secs: 0.0,
            }),
            Event::ScanFailed(ScanFailed {
                scan_id: 0,
                profile: ScanProfile::Quick,
                target: String::new(),
                outcome: String::new(),
                error: String::new(),
            }),
        ]
        .iter()
        .map(Event::kind)
        .collect();
        assert_eq!(kinds, EventKind::ALL);
    }
}
