//! Scheduled ARP discovery: scans configured interfaces on an interval and
//! records what answered in `devices` / `device_addresses`.
//!
//! Scanning is blocking and may take many seconds, so it runs on the blocking
//! pool. The scanner is a trait so the persistence and scheduling logic can
//! be tested without root or a network.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

use crate::config::Settings;

/// A host that answered an ARP request. The MAC is lower-case, colon-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHost {
    pub ip: Ipv4Addr,
    pub mac: String,
}

pub type ScanError = Box<dyn std::error::Error + Send + Sync>;

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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanSummary {
    pub hosts_seen: usize,
    pub new_devices: usize,
    pub new_addresses: usize,
    /// New (device, address) pairs whose IP was already known on another device.
    pub reassigned_addresses: usize,
}

/// Stores one scan. Everything happens in a single transaction so a failure
/// leaves no half-recorded scan behind.
///
/// Devices are upserted by MAC and addresses by (device, IP), so re-scanning
/// only moves `last_seen` forward. When an IP shows up on a different device,
/// the previous holder's row is kept (history); the newest `last_seen` marks
/// the current holder. Devices that did not answer are left untouched: one
/// missed reply is not proof of absence (online/offline tracking is separate).
pub async fn record_scan(
    db: &PgPool,
    hosts: &[ObservedHost],
    seen_at: DateTime<Utc>,
) -> sqlx::Result<ScanSummary> {
    let mut summary = ScanSummary {
        hosts_seen: hosts.len(),
        ..ScanSummary::default()
    };
    let mut tx = db.begin().await?;

    for host in hosts {
        // `xmax = 0` is true only for a freshly inserted row.
        let (device_id, device_inserted): (i32, bool) = sqlx::query_as(
            "INSERT INTO devices (name, mac_address, is_online, first_seen, last_seen) \
             VALUES ($1, $1, true, $2, $2) \
             ON CONFLICT (mac_address) DO UPDATE SET \
                 is_online = true, \
                 last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen) \
             RETURNING id, (xmax = 0)",
        )
        .bind(&host.mac)
        .bind(seen_at)
        .fetch_one(&mut *tx)
        .await?;

        let (address_inserted, held_by_other): (bool, bool) = sqlx::query_as(
            "INSERT INTO device_addresses \
                 (device_id, ip_address, protocol, source, first_seen, last_seen) \
             VALUES ($1, $2, 'ipv4', 'arp', $3, $3) \
             ON CONFLICT (device_id, ip_address) DO UPDATE SET \
                 last_seen = GREATEST(device_addresses.last_seen, EXCLUDED.last_seen) \
             RETURNING (xmax = 0), \
                 EXISTS (SELECT 1 FROM device_addresses other \
                         WHERE other.ip_address = $2 AND other.device_id <> $1)",
        )
        .bind(device_id)
        .bind(host.ip.to_string())
        .bind(seen_at)
        .fetch_one(&mut *tx)
        .await?;

        summary.new_devices += usize::from(device_inserted);
        summary.new_addresses += usize::from(address_inserted);
        summary.reassigned_addresses += usize::from(address_inserted && held_by_other);
    }

    tx.commit().await?;
    Ok(summary)
}

/// One lock per interface so a scan can never overlap another on the same
/// interface, whether it comes from the scheduler or a later manual trigger.
#[derive(Clone, Default)]
pub struct InterfaceLocks(Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>);

impl InterfaceLocks {
    fn lock_for(&self, interface: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self.0.lock().expect("interface lock map poisoned");
        locks.entry(interface.to_owned()).or_default().clone()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    Completed(ScanSummary),
    /// Another scan of this interface was still running.
    Skipped,
}

#[derive(Debug)]
pub enum DiscoveryError {
    Scan(ScanError),
    Task(tokio::task::JoinError),
    Database(sqlx::Error),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(err) => write!(f, "scan failed: {err}"),
            Self::Task(err) => write!(f, "scan task failed: {err}"),
            Self::Database(err) => write!(f, "could not store scan results: {err}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Scans one interface and stores the result, unless a scan of that
/// interface is already running.
pub async fn run_scan(
    db: &PgPool,
    scanner: &Arc<dyn Scanner>,
    locks: &InterfaceLocks,
    interface: &str,
    timeout: Duration,
) -> Result<ScanOutcome, DiscoveryError> {
    let Ok(_guard) = locks.lock_for(interface).try_lock_owned() else {
        return Ok(ScanOutcome::Skipped);
    };

    let hosts = {
        let scanner = Arc::clone(scanner);
        let interface = interface.to_owned();
        tokio::task::spawn_blocking(move || scanner.scan(&interface, timeout))
            .await
            .map_err(DiscoveryError::Task)?
            .map_err(DiscoveryError::Scan)?
    };

    let summary = record_scan(db, &hosts, Utc::now())
        .await
        .map_err(DiscoveryError::Database)?;
    Ok(ScanOutcome::Completed(summary))
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub interfaces: Vec<String>,
    pub interval: Duration,
    pub timeout: Duration,
}

impl From<&Settings> for DiscoveryConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            interfaces: settings.discovery_interfaces.clone(),
            interval: Duration::from_secs(settings.discovery_interval_secs),
            timeout: Duration::from_secs(settings.discovery_timeout_secs),
        }
    }
}

/// Starts one scan loop per configured interface; returns no tasks when
/// discovery is not configured. A failed scan is logged and retried on the
/// next tick, so a transient error (or missing privileges, which the log
/// message explains) never stops the loop or the API.
pub fn spawn(
    db: PgPool,
    scanner: Arc<dyn Scanner>,
    locks: InterfaceLocks,
    config: DiscoveryConfig,
) -> Vec<JoinHandle<()>> {
    if config.interfaces.is_empty() {
        tracing::info!("scheduled discovery disabled (ARGOWEI_DISCOVERY_INTERFACES is empty)");
    }

    config
        .interfaces
        .iter()
        .cloned()
        .map(|interface| {
            let (db, scanner, locks) = (db.clone(), Arc::clone(&scanner), locks.clone());
            let (period, timeout) = (config.interval, config.timeout);

            tokio::spawn(async move {
                tracing::info!(%interface, ?period, "scheduled discovery started");
                let mut ticker = interval(period);
                // A slow scan delays the next one instead of triggering a burst.
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    ticker.tick().await;
                    match run_scan(&db, &scanner, &locks, &interface, timeout).await {
                        Ok(ScanOutcome::Completed(summary)) => {
                            tracing::info!(%interface, ?summary, "discovery scan complete");
                        }
                        Ok(ScanOutcome::Skipped) => {
                            tracing::warn!(%interface, "previous scan still running; skipping");
                        }
                        Err(error) => {
                            tracing::error!(%interface, %error, "discovery scan failed");
                        }
                    }
                }
            })
        })
        .collect()
}
