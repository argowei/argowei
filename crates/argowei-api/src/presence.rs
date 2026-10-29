//! When does a device count as offline?
//!
//! ARP replies are unauthenticated and sleeping Wi-Fi devices often miss
//! requests, so one missing reply proves nothing. A device is marked offline
//! only when it has missed enough consecutive scans *and* enough time has
//! passed since it was last seen. Requiring both matters: a long gap in
//! scanning (the API was down for an hour) would otherwise satisfy a pure
//! time rule after a single missed scan and mark the whole network offline.

use std::time::Duration;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresencePolicy {
    /// Consecutive completed scans (of the interface that last saw the
    /// device) without a reply.
    pub offline_after_missed_scans: u32,
    /// Minimum time since the device was last seen.
    pub offline_after: Duration,
}

impl Default for PresencePolicy {
    fn default() -> Self {
        Self {
            offline_after_missed_scans: 3,
            offline_after: Duration::from_secs(15 * 60),
        }
    }
}

impl PresencePolicy {
    /// Pure decision: `now` is passed in so the rule is testable without a clock.
    pub fn is_offline(
        &self,
        missed_scans: i64,
        last_seen: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> bool {
        let elapsed = now.signed_duration_since(last_seen);
        let required =
            chrono::Duration::from_std(self.offline_after).unwrap_or(chrono::Duration::MAX);

        missed_scans >= i64::from(self.offline_after_missed_scans) && elapsed >= required
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn t(minutes: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap() + chrono::Duration::minutes(minutes)
    }

    fn policy() -> PresencePolicy {
        PresencePolicy {
            offline_after_missed_scans: 3,
            offline_after: Duration::from_secs(15 * 60),
        }
    }

    #[test]
    fn a_single_missed_scan_never_marks_offline() {
        assert!(!policy().is_offline(1, t(0), t(5)));
        // Not even after a long gap: the miss count still has to be reached.
        assert!(!policy().is_offline(1, t(0), t(600)));
    }

    #[test]
    fn enough_misses_without_enough_time_stays_online() {
        assert!(!policy().is_offline(3, t(0), t(14)));
        assert!(!policy().is_offline(10, t(0), t(14)));
    }

    #[test]
    fn both_thresholds_met_marks_offline_at_the_boundary() {
        assert!(policy().is_offline(3, t(0), t(15)));
        assert!(policy().is_offline(7, t(0), t(120)));
    }

    #[test]
    fn a_last_seen_in_the_future_is_not_offline() {
        // Clock skew or an out-of-order scan must not produce an offline.
        assert!(!policy().is_offline(5, t(30), t(0)));
    }

    #[test]
    fn zero_time_requirement_leaves_only_the_miss_count() {
        let policy = PresencePolicy {
            offline_after_missed_scans: 2,
            offline_after: Duration::ZERO,
        };

        assert!(!policy.is_offline(1, t(0), t(1)));
        assert!(policy.is_offline(2, t(0), t(1)));
    }
}
