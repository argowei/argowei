//! Scheduled ARP discovery: scans configured interfaces on an interval and
//! records what answered in `devices` / `device_addresses`.
//!
//! Scanning is blocking and may take many seconds, so it runs on the blocking
//! pool. The scanner is a trait so the persistence and scheduling logic can
//! be tested without root or a network.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

use argowei_core::device_type::{classify, Signals};
use argowei_core::oui;

use crate::config::Settings;
use crate::events::{self, Severity};
use crate::presence::PresencePolicy;
use crate::state::AppState;
use serde_json::json;

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

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    pub hosts_seen: usize,
    pub new_devices: usize,
    pub new_addresses: usize,
    /// New (device, address) pairs whose IP was already known on another device.
    pub reassigned_addresses: usize,
    /// Known devices that answered again after having been marked offline.
    pub came_online: usize,
    /// Devices that missed enough scans, for long enough, to be marked offline.
    pub went_offline: usize,
}

/// Stores one scan and updates presence. Everything happens in a single
/// transaction so a failure leaves no half-recorded scan behind.
///
/// The scan itself and each sighting are kept as evidence, so presence can be
/// analyzed later and "missed scans" is a query over what actually ran.
/// Devices are upserted by MAC and addresses by (device, IP): re-scanning only
/// moves `last_seen` forward. When an IP shows up on a different device, the
/// previous holder's row is kept (history); the newest `last_seen` marks the
/// current holder.
///
/// A device that did not answer is *not* marked offline for that alone: see
/// [`PresencePolicy`]. State changes are recorded as events
/// (`device.discovered`, `device.online`, `device.offline`), each exactly once
/// per transition, in the same transaction as the change.
pub async fn record_scan(
    db: &PgPool,
    interface: &str,
    hosts: &[ObservedHost],
    seen_at: DateTime<Utc>,
    policy: &PresencePolicy,
) -> sqlx::Result<ScanSummary> {
    let mut summary = ScanSummary {
        hosts_seen: hosts.len(),
        ..ScanSummary::default()
    };
    let mut tx = db.begin().await?;

    let scan_id: i64 = sqlx::query_scalar(
        "INSERT INTO discovery_scans (interface, method, scanned_at, hosts_seen) \
         VALUES ($1, 'arp', $2, $3) RETURNING id",
    )
    .bind(interface)
    .bind(seen_at)
    .bind(hosts.len() as i32)
    .fetch_one(&mut *tx)
    .await?;

    for host in hosts {
        // Lock the row so concurrent scans of different interfaces cannot
        // both report the same transition.
        let previous: Option<(bool, DateTime<Utc>)> = sqlx::query_as(
            "SELECT is_online, last_seen FROM devices WHERE mac_address = $1 FOR UPDATE",
        )
        .bind(&host.mac)
        .fetch_optional(&mut *tx)
        .await?;

        // `xmax = 0` is true only for a freshly inserted row.
        let (device_id, device_inserted): (i32, bool) = sqlx::query_as(
            "INSERT INTO devices \
                 (name, mac_address, is_online, first_seen, last_seen, last_seen_interface) \
             VALUES ($1, $1, true, $2, $2, $3) \
             ON CONFLICT (mac_address) DO UPDATE SET \
                 is_online = true, \
                 last_seen_interface = CASE \
                     WHEN EXCLUDED.last_seen >= devices.last_seen \
                     THEN EXCLUDED.last_seen_interface \
                     ELSE devices.last_seen_interface END, \
                 last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen) \
             RETURNING id, (xmax = 0)",
        )
        .bind(&host.mac)
        .bind(seen_at)
        .bind(interface)
        .fetch_one(&mut *tx)
        .await?;

        classify_device(&mut tx, device_id, &host.mac).await?;

        let ip = host.ip.to_string();
        let evidence = json!({ "interface": interface, "scan_id": scan_id, "ip": ip });

        if device_inserted {
            events::record(
                &mut *tx,
                seen_at,
                events::DEVICE_DISCOVERED,
                Severity::Info,
                Some(device_id),
                evidence,
            )
            .await?;
        } else if let Some((false, offline_since)) = previous {
            summary.came_online += 1;
            events::record(
                &mut *tx,
                seen_at,
                events::DEVICE_ONLINE,
                Severity::Info,
                Some(device_id),
                json!({
                    "interface": interface,
                    "scan_id": scan_id,
                    "ip": ip,
                    "last_seen_before": offline_since,
                }),
            )
            .await?;
        }

        sqlx::query(
            "INSERT INTO device_sightings (scan_id, device_id, ip_address) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(scan_id)
        .bind(device_id)
        .bind(&ip)
        .execute(&mut *tx)
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
        .bind(&ip)
        .bind(seen_at)
        .fetch_one(&mut *tx)
        .await?;

        summary.new_devices += usize::from(device_inserted);
        summary.new_addresses += usize::from(address_inserted);
        summary.reassigned_addresses += usize::from(address_inserted && held_by_other);
    }

    summary.went_offline =
        mark_missing_devices_offline(&mut tx, interface, seen_at, policy).await?;

    tx.commit().await?;
    Ok(summary)
}

/// Re-infers a device's type from what is known about it and stores the
/// result. This only ever writes the *inferred* columns: a user's manual
/// override lives in its own column and is never touched here. Skips the
/// write when nothing changed, so a scan does not rewrite every row.
///
/// Only the vendor and the MAC kind are known so far; open ports, mDNS
/// services and hostnames feed in as those sources arrive.
async fn classify_device(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: i32,
    mac: &str,
) -> sqlx::Result<()> {
    let mac_info = oui::lookup(mac);
    let classification = classify(&Signals {
        vendor: mac_info.vendor,
        locally_administered_mac: mac_info.locally_administered,
        ..Signals::default()
    });
    let evidence = serde_json::to_value(&classification.evidence)
        .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;

    sqlx::query(
        "UPDATE devices SET inferred_type = $2, inferred_confidence = $3, \
             inferred_evidence = $4 \
         WHERE id = $1 \
           AND (inferred_type, inferred_confidence, inferred_evidence) \
               IS DISTINCT FROM ($2, $3::smallint, $4::jsonb)",
    )
    .bind(device_id)
    .bind(classification.device_type.as_str())
    .bind(i16::from(classification.confidence))
    .bind(evidence)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Online devices last seen on this interface, but not in the scan just
/// recorded, are checked against the policy. Missed scans are counted from
/// the scans that actually ran since the device was last seen.
async fn mark_missing_devices_offline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    interface: &str,
    now: DateTime<Utc>,
    policy: &PresencePolicy,
) -> sqlx::Result<usize> {
    let candidates: Vec<(i32, DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT d.id, d.last_seen, \
                (SELECT count(*) FROM discovery_scans s \
                 WHERE s.interface = d.last_seen_interface AND s.scanned_at > d.last_seen) \
         FROM devices d \
         WHERE d.is_online AND d.last_seen_interface = $1 AND d.last_seen < $2 \
         ORDER BY d.id",
    )
    .bind(interface)
    .bind(now)
    .fetch_all(&mut **tx)
    .await?;

    let mut went_offline = 0;
    for (device_id, last_seen, missed_scans) in candidates {
        if !policy.is_offline(missed_scans, last_seen, now) {
            continue;
        }

        sqlx::query("UPDATE devices SET is_online = false WHERE id = $1")
            .bind(device_id)
            .execute(&mut **tx)
            .await?;
        events::record(
            &mut **tx,
            now,
            events::DEVICE_OFFLINE,
            Severity::Info,
            Some(device_id),
            json!({
                "interface": interface,
                "last_seen": last_seen,
                "missed_scans": missed_scans,
                "silent_for_secs": now.signed_duration_since(last_seen).num_seconds(),
                "policy": {
                    "offline_after_missed_scans": policy.offline_after_missed_scans,
                    "offline_after_secs": policy.offline_after.as_secs(),
                },
            }),
        )
        .await?;
        went_offline += 1;
    }

    Ok(went_offline)
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
    policy: &PresencePolicy,
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

    let summary = record_scan(db, interface, &hosts, Utc::now(), policy)
        .await
        .map_err(DiscoveryError::Database)?;
    Ok(ScanOutcome::Completed(summary))
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub interfaces: Vec<String>,
    pub interval: Duration,
    pub timeout: Duration,
    pub presence: PresencePolicy,
}

impl From<&Settings> for DiscoveryConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            interfaces: settings.discovery_interfaces.clone(),
            interval: Duration::from_secs(settings.discovery_interval_secs),
            timeout: Duration::from_secs(settings.discovery_timeout_secs),
            presence: PresencePolicy {
                offline_after_missed_scans: settings.offline_after_missed_scans,
                offline_after: Duration::from_secs(settings.offline_after_secs),
            },
        }
    }
}

/// How the latest scans of one interface went. Lives in memory only: a
/// failed scan is not a scan (it writes no row and never counts as a missed
/// scan for presence), but it should be visible, so it is reported here and
/// forgotten on restart.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceStatus {
    pub interface: String,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_summary: Option<ScanSummary>,
    /// Message of the most recent failure; cleared by the next success.
    pub last_error: Option<String>,
    pub last_failure_at: Option<DateTime<Utc>>,
    /// Failed attempts in a row since the last success.
    pub consecutive_failures: u32,
}

impl InterfaceStatus {
    fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            last_attempt_at: None,
            last_success_at: None,
            last_summary: None,
            last_error: None,
            last_failure_at: None,
            consecutive_failures: 0,
        }
    }
}

#[derive(Clone, Default)]
pub struct DiscoveryStatus(Arc<Mutex<BTreeMap<String, InterfaceStatus>>>);

impl DiscoveryStatus {
    /// Lists an interface before its first scan has run.
    pub fn register(&self, interface: &str) {
        self.lock()
            .entry(interface.to_owned())
            .or_insert_with(|| InterfaceStatus::new(interface));
    }

    /// Records the outcome of one attempt. A skipped attempt (another scan was
    /// still running) is not an attempt and changes nothing.
    pub fn record(
        &self,
        interface: &str,
        outcome: &Result<ScanOutcome, DiscoveryError>,
        now: DateTime<Utc>,
    ) {
        let mut interfaces = self.lock();
        let status = interfaces
            .entry(interface.to_owned())
            .or_insert_with(|| InterfaceStatus::new(interface));

        match outcome {
            Ok(ScanOutcome::Skipped) => {}
            Ok(ScanOutcome::Completed(summary)) => {
                status.last_attempt_at = Some(now);
                status.last_success_at = Some(now);
                status.last_summary = Some(summary.clone());
                status.last_error = None;
                status.consecutive_failures = 0;
            }
            Err(error) => {
                status.last_attempt_at = Some(now);
                status.last_failure_at = Some(now);
                status.last_error = Some(error.to_string());
                status.consecutive_failures = status.consecutive_failures.saturating_add(1);
            }
        }
    }

    /// Interfaces in name order.
    pub fn snapshot(&self) -> Vec<InterfaceStatus> {
        self.lock().values().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, InterfaceStatus>> {
        self.0.lock().expect("discovery status lock poisoned")
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/discovery/status", get(status_handler))
}

async fn status_handler(State(state): State<AppState>) -> Json<Vec<InterfaceStatus>> {
    Json(state.discovery.snapshot())
}

/// Starts one scan loop per configured interface; returns no tasks when
/// discovery is not configured. A failed scan is logged and retried on the
/// next tick, so a transient error (or missing privileges, which the log
/// message explains) never stops the loop or the API.
pub fn spawn(
    db: PgPool,
    scanner: Arc<dyn Scanner>,
    locks: InterfaceLocks,
    status: DiscoveryStatus,
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
            status.register(&interface);
            let (db, scanner, locks) = (db.clone(), Arc::clone(&scanner), locks.clone());
            let status = status.clone();
            let (period, timeout, policy) = (config.interval, config.timeout, config.presence);

            tokio::spawn(async move {
                tracing::info!(%interface, ?period, "scheduled discovery started");
                let mut ticker = interval(period);
                // A slow scan delays the next one instead of triggering a burst.
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    ticker.tick().await;
                    let outcome =
                        run_scan(&db, &scanner, &locks, &interface, timeout, &policy).await;
                    status.record(&interface, &outcome, Utc::now());
                    match outcome {
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, minute, 0).unwrap()
    }

    fn failure(message: &str) -> Result<ScanOutcome, DiscoveryError> {
        Err(DiscoveryError::Scan(message.into()))
    }

    fn ok() -> Result<ScanOutcome, DiscoveryError> {
        Ok(ScanOutcome::Completed(ScanSummary {
            hosts_seen: 4,
            ..ScanSummary::default()
        }))
    }

    fn only(status: &DiscoveryStatus) -> InterfaceStatus {
        let mut all = status.snapshot();
        assert_eq!(all.len(), 1);
        all.remove(0)
    }

    #[test]
    fn a_registered_interface_is_listed_before_its_first_scan() {
        let status = DiscoveryStatus::default();
        status.register("eth0");

        let entry = only(&status);
        assert_eq!(entry.interface, "eth0");
        assert!(entry.last_attempt_at.is_none() && entry.last_error.is_none());
        assert_eq!(entry.consecutive_failures, 0);
    }

    #[test]
    fn failures_are_visible_and_counted() {
        let status = DiscoveryStatus::default();
        status.record("eth0", &ok(), at(0));
        status.record("eth0", &failure("not permitted: CAP_NET_RAW"), at(5));
        status.record("eth0", &failure("not permitted: CAP_NET_RAW"), at(10));

        let entry = only(&status);
        assert_eq!(entry.consecutive_failures, 2);
        assert_eq!(entry.last_failure_at, Some(at(10)));
        assert_eq!(entry.last_success_at, Some(at(0)));
        assert!(entry.last_error.unwrap().contains("CAP_NET_RAW"));
    }

    #[test]
    fn a_success_resets_the_failure_streak_and_error() {
        let status = DiscoveryStatus::default();
        status.record("eth0", &failure("boom"), at(0));
        status.record("eth0", &ok(), at(5));

        let entry = only(&status);
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.last_error.is_none());
        assert_eq!(entry.last_summary.unwrap().hosts_seen, 4);
        // The fact that it failed once stays visible.
        assert_eq!(entry.last_failure_at, Some(at(0)));
    }

    #[test]
    fn a_skipped_attempt_changes_nothing() {
        let status = DiscoveryStatus::default();
        status.record("eth0", &failure("boom"), at(0));
        status.record("eth0", &Ok(ScanOutcome::Skipped), at(5));

        let entry = only(&status);
        assert_eq!(entry.consecutive_failures, 1);
        assert_eq!(entry.last_attempt_at, Some(at(0)));
    }

    #[test]
    fn interfaces_are_independent_and_sorted() {
        let status = DiscoveryStatus::default();
        status.record("wlan0", &failure("boom"), at(0));
        status.record("eth0", &ok(), at(0));

        let names: Vec<_> = status.snapshot().into_iter().map(|s| s.interface).collect();
        assert_eq!(names, vec!["eth0", "wlan0"]);
        assert_eq!(status.snapshot()[0].consecutive_failures, 0);
        assert_eq!(status.snapshot()[1].consecutive_failures, 1);
    }
}
