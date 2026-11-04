//! Scheduled ARP discovery: scan the configured interfaces, store what
//! answered, and keep presence, device types, baselines and alerts up to date.
//!
//! The pipeline, per interface and tick:
//!
//! 1. [`schedule`]: a timer per interface calls [`run_scan`], which takes the
//!    interface's lock (scans never overlap) and runs the blocking ARP scan on
//!    the blocking thread pool.
//! 2. [`persist`]: [`record_scan`] stores the result in one transaction:
//!    the scan row, each device and address, the sighting (the evidence that a
//!    device answered), the device type inference, `device.*` events, a
//!    `device.new` alert outside the baseline, and offline marking for devices
//!    that stayed silent long enough.
//! 3. Name lookups ([`crate::names`]) run afterwards in a step of their own,
//!    so nothing they do can fail or delay the stored scan.
//! 4. [`status`]: the outcome of each attempt, including failures that store
//!    nothing, is kept in memory for `GET /api/discovery/status`.
//!
//! Scanning goes through the [`Scanner`] trait so all of the above can be
//! tested without root or a network.

mod persist;
mod schedule;
mod status;

use std::net::Ipv4Addr;
use std::time::Duration;

use serde::Serialize;

pub use persist::record_scan;
pub use schedule::{run_scan, spawn, DiscoveryConfig, DiscoveryError, InterfaceLocks, ScanOutcome};
pub use status::{router, DiscoveryStatus, InterfaceStatus};

/// A host that answered an ARP request. The MAC is lower-case, colon-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHost {
    pub ip: Ipv4Addr,
    pub mac: String,
}

/// Why a scan produced no result; scanners report anything from a missing
/// interface to missing privileges, so the type is open.
pub type ScanError = Box<dyn std::error::Error + Send + Sync>;

/// Finds the hosts on an interface's network. Blocking: called on the blocking
/// thread pool.
pub trait Scanner: Send + Sync + 'static {
    fn scan(&self, interface: &str, timeout: Duration) -> Result<Vec<ObservedHost>, ScanError>;
}

/// Real scanner backed by `argowei-collector`; needs root or CAP_NET_RAW.
pub struct ArpScanner;

impl Scanner for ArpScanner {
    fn scan(&self, interface: &str, timeout: Duration) -> Result<Vec<ObservedHost>, ScanError> {
        Ok(argowei_collector::scan_arp(interface, timeout)?
            .into_iter()
            .map(|host| ObservedHost {
                ip: host.ip,
                mac: host.mac.to_string().to_ascii_lowercase(),
            })
            .collect())
    }
}

/// What one stored scan changed, for logs and the discovery status.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    pub hosts_seen: usize,
    pub new_devices: usize,
    pub new_addresses: usize,
    /// New (device, address) pairs whose IP was already known on another device.
    pub reassigned_addresses: usize,
    /// Alerts raised for devices never seen before (none during the baseline).
    pub new_alerts: usize,
    /// Known devices that answered again after having been marked offline.
    pub came_online: usize,
    /// Devices that missed enough scans, for long enough, to be marked offline.
    pub went_offline: usize,
}
