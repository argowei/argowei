//! The in-memory record of how scans went, served at
//! `GET /api/discovery/status`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{DiscoveryError, ScanOutcome, ScanSummary};
use crate::state::AppState;

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

/// Status of every interface, shared between the scan loops and the API.
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

    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, InterfaceStatus>> {
        self.0.lock().expect("discovery status lock poisoned")
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/discovery/status", get(status_handler))
}

async fn status_handler(State(state): State<AppState>) -> Json<Vec<InterfaceStatus>> {
    Json(state.discovery.snapshot())
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
