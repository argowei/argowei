//! Running scans: one timer per interface, one lock per interface, and the
//! blocking scan moved off the async runtime.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

use super::{record_scan, DiscoveryStatus, ScanError, ScanSummary, Scanner};
use crate::config::Settings;
use crate::names::{self, NamePipeline};
use crate::presence::PresencePolicy;

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
    /// The scan ran and was stored.
    Completed(ScanSummary),
    /// Another scan of this interface was still running.
    Skipped,
}

/// Why a scan attempt stored nothing.
#[derive(Debug)]
pub enum DiscoveryError {
    /// The scanner failed (no such interface, missing privileges, ...).
    Scan(ScanError),
    /// The blocking scan task panicked or was cancelled.
    Task(tokio::task::JoinError),
    /// The scan ran but could not be stored; the transaction was rolled back.
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

/// The scheduler's settings, taken from [`Settings`].
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Interfaces to scan; empty disables scheduled discovery.
    pub interfaces: Vec<String>,
    /// Time between the starts of two scans of the same interface.
    pub interval: Duration,
    /// How long one scan waits for replies.
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
    names: Option<NamePipeline>,
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
            let names = names.clone();
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
                            // After the scan is stored, in a step of its own: nothing
                            // a name lookup does can fail or delay the scan result.
                            if let Some(pipeline) = &names {
                                names::after_scan(&db, pipeline, &interface).await;
                            }
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
