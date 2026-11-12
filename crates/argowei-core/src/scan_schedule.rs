//! When scheduled scans run: classic five-field cron expressions, at most
//! every 15 minutes, never catching up on missed runs, with a little jitter so
//! that schedules sharing a time do not all hit the network at once.
//!
//! Times are evaluated in the server's local time zone (`TZ`), so "0 3 * * *"
//! means 03:00 where the server runs.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, NaiveDate, TimeZone};
use croner::parser::{CronParser, Seconds, Year};
use croner::Cron;
use serde::{Deserialize, Serialize};

/// The shortest gap allowed between two runs of a schedule: port scans are
/// not a monitoring loop.
pub const MIN_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// A run that is overdue by more than this (the server was down or asleep)
/// is skipped, not started late.
pub const GRACE: Duration = Duration::from_secs(2 * 60);
/// Upper bound on the random delay before a run.
pub const MAX_JITTER: Duration = Duration::from_secs(60);
/// Occurrences checked when enforcing [`MIN_INTERVAL`].
const INTERVAL_SAMPLES: usize = 96;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    /// Not a valid five-field cron expression; the parser's reason.
    Invalid(String),
    /// Runs more often than [`MIN_INTERVAL`].
    TooFrequent,
    /// Never runs (e.g. February 30th).
    NeverRuns,
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(
                f,
                "not a valid cron expression (minute hour day month weekday): {reason}"
            ),
            Self::TooFrequent => write!(
                f,
                "a schedule may run at most every {} minutes",
                MIN_INTERVAL.as_secs() / 60
            ),
            Self::NeverRuns => write!(f, "the cron expression never matches a date"),
        }
    }
}

impl std::error::Error for ScheduleError {}

/// A parsed, validated cron expression.
#[derive(Debug, Clone)]
pub struct CronSchedule {
    cron: Cron,
}

impl CronSchedule {
    /// Parses `minute hour day-of-month month day-of-week`, e.g. `0 3 * * *`.
    /// Seconds and years are refused, and so is anything that would run
    /// more often than every 15 minutes.
    pub fn parse(expression: &str) -> Result<Self, ScheduleError> {
        let fields = expression.split_whitespace().count();
        if fields != 5 {
            return Err(ScheduleError::Invalid(format!(
                "expected 5 fields, got {fields}"
            )));
        }
        let cron = CronParser::builder()
            .seconds(Seconds::Disallowed)
            .year(Year::Disallowed)
            .build()
            .parse(expression)
            .map_err(|error| ScheduleError::Invalid(error.to_string()))?;
        let schedule = Self { cron };

        // A fixed reference keeps validation deterministic. Ninety-six runs
        // cover a day of a 15-minute schedule and reveal irregular patterns
        // such as "0,5 * * * *".
        let reference = NaiveDate::from_ymd_opt(2026, 1, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|t| chrono::Utc.from_utc_datetime(&t))
            .expect("valid reference date");
        let runs = schedule.upcoming(&reference, INTERVAL_SAMPLES);
        if runs.is_empty() {
            return Err(ScheduleError::NeverRuns);
        }
        let too_close = runs
            .windows(2)
            .any(|pair| (pair[1] - pair[0]).to_std().unwrap_or_default() < MIN_INTERVAL);
        if too_close {
            return Err(ScheduleError::TooFrequent);
        }
        Ok(schedule)
    }

    /// The first run strictly after `after`.
    pub fn next_after<Tz: TimeZone>(&self, after: &DateTime<Tz>) -> Option<DateTime<Tz>> {
        self.cron.find_next_occurrence(after, false).ok()
    }

    /// The next `count` runs after `after`.
    pub fn upcoming<Tz: TimeZone>(&self, after: &DateTime<Tz>, count: usize) -> Vec<DateTime<Tz>> {
        let mut runs = Vec::with_capacity(count);
        let mut from = after.clone();
        while runs.len() < count {
            let Some(next) = self.next_after(&from) else {
                break;
            };
            from = next.clone();
            runs.push(next);
        }
        runs
    }

    /// A human-readable description, e.g. "At 03:00".
    pub fn describe(&self) -> String {
        self.cron.describe()
    }
}

/// Whether a run due at `due` is too late to start at `now` (see [`GRACE`]).
pub fn is_missed<Tz: TimeZone>(due: &DateTime<Tz>, now: &DateTime<Tz>) -> bool {
    now.clone()
        .signed_duration_since(due.clone())
        .to_std()
        .unwrap_or_default()
        > GRACE
}

/// The largest random delay for a run at `this` whose next run is `next`:
/// a tenth of the interval, at most [`MAX_JITTER`].
pub fn jitter_limit<Tz: TimeZone>(this: &DateTime<Tz>, next: &DateTime<Tz>) -> Duration {
    let interval = next
        .clone()
        .signed_duration_since(this.clone())
        .to_std()
        .unwrap_or_default();
    (interval / 10).min(MAX_JITTER)
}

/// What a schedule scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
pub enum ScheduleTarget {
    /// One device.
    Device(i32),
    /// Every device in a group, as it is when the schedule runs.
    Group(i32),
    /// Every device with a scannable address.
    All,
}

impl ScheduleTarget {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Device(_) => "device",
            Self::Group(_) => "group",
            Self::All => "all",
        }
    }

    pub fn id(self) -> Option<i32> {
        match self {
            Self::Device(id) | Self::Group(id) => Some(id),
            Self::All => None,
        }
    }

    /// From the stored `(target_kind, target_id)` columns.
    pub fn from_columns(kind: &str, id: Option<i32>) -> Option<Self> {
        match (kind, id) {
            ("device", Some(id)) => Some(Self::Device(id)),
            ("group", Some(id)) => Some(Self::Group(id)),
            ("all", None) => Some(Self::All),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn common_schedules_are_accepted() {
        for expression in [
            "0 3 * * *",
            "*/15 * * * *",
            "30 2 * * 1-5",
            "0 */6 * * *",
            "0 0 1 * *",
            "0 4 * * SUN",
        ] {
            assert!(CronSchedule::parse(expression).is_ok(), "{expression}");
        }
    }

    #[test]
    fn invalid_or_too_frequent_schedules_are_refused() {
        for (expression, expected) in [
            ("* * * * *", ScheduleError::TooFrequent),
            ("*/5 * * * *", ScheduleError::TooFrequent),
            ("0,5 * * * *", ScheduleError::TooFrequent),
            ("*/14 * * * *", ScheduleError::TooFrequent),
        ] {
            assert_eq!(
                CronSchedule::parse(expression).unwrap_err(),
                expected,
                "{expression}"
            );
        }
        for invalid in [
            "",
            "0 3 * *",
            "0 0 3 * * *",
            "0 3 * * * 2027",
            "61 * * * *",
            "0 25 * * *",
            "every day",
            "0 3 * * ; rm -rf /",
        ] {
            assert!(
                matches!(CronSchedule::parse(invalid), Err(ScheduleError::Invalid(_))),
                "{invalid}"
            );
        }
        assert_eq!(
            CronSchedule::parse("0 0 30 2 *").unwrap_err(),
            ScheduleError::NeverRuns
        );
    }

    #[test]
    fn the_next_run_is_strictly_in_the_future() {
        let daily = CronSchedule::parse("0 3 * * *").unwrap();
        assert_eq!(
            daily.next_after(&at("2026-03-10T02:59:00Z")),
            Some(at("2026-03-10T03:00:00Z"))
        );
        assert_eq!(
            daily.next_after(&at("2026-03-10T03:00:00Z")),
            Some(at("2026-03-11T03:00:00Z"))
        );
        assert_eq!(
            daily.upcoming(&at("2026-03-10T12:00:00Z"), 3),
            [
                at("2026-03-11T03:00:00Z"),
                at("2026-03-12T03:00:00Z"),
                at("2026-03-13T03:00:00Z")
            ]
        );
    }

    #[test]
    fn runs_follow_the_given_time_zone() {
        let daily = CronSchedule::parse("0 3 * * *").unwrap();
        let berlin = chrono::FixedOffset::east_opt(3600).unwrap();
        let next = daily
            .next_after(&at("2026-03-10T00:00:00Z").with_timezone(&berlin))
            .unwrap();
        assert_eq!(
            next.with_timezone(&Utc),
            at("2026-03-10T02:00:00Z"),
            "03:00 at UTC+1"
        );
    }

    #[test]
    fn overdue_runs_are_skipped_after_the_grace_period() {
        let due = at("2026-03-10T03:00:00Z");
        assert!(!is_missed(&due, &at("2026-03-10T03:00:30Z")));
        assert!(!is_missed(&due, &at("2026-03-10T03:02:00Z")));
        assert!(is_missed(&due, &at("2026-03-10T03:02:01Z")));
        assert!(
            is_missed(&due, &at("2026-03-12T09:00:00Z")),
            "after a long downtime"
        );
        assert!(!is_missed(&due, &at("2026-03-10T02:00:00Z")), "not yet due");
    }

    #[test]
    fn jitter_is_a_tenth_of_the_interval_at_most_a_minute() {
        let t = at("2026-03-10T03:00:00Z");
        assert_eq!(
            jitter_limit(&t, &at("2026-03-10T03:15:00Z")),
            Duration::from_secs(60)
        );
        assert_eq!(
            jitter_limit(&t, &at("2026-03-10T03:05:00Z")),
            Duration::from_secs(30)
        );
        assert_eq!(
            jitter_limit(&t, &at("2026-03-11T03:00:00Z")),
            Duration::from_secs(60)
        );
        assert_eq!(jitter_limit(&t, &t), Duration::ZERO);
    }

    #[test]
    fn targets_round_trip_through_their_columns_and_json() {
        for target in [
            ScheduleTarget::Device(4),
            ScheduleTarget::Group(2),
            ScheduleTarget::All,
        ] {
            assert_eq!(
                ScheduleTarget::from_columns(target.kind(), target.id()),
                Some(target)
            );
        }
        assert_eq!(ScheduleTarget::from_columns("device", None), None);
        assert_eq!(ScheduleTarget::from_columns("all", Some(1)), None);
        assert_eq!(ScheduleTarget::from_columns("planet", Some(1)), None);
        assert_eq!(
            serde_json::to_value(ScheduleTarget::Group(2)).unwrap(),
            serde_json::json!({ "kind": "group", "id": 2 })
        );
        assert_eq!(
            serde_json::to_value(ScheduleTarget::All).unwrap(),
            serde_json::json!({ "kind": "all" })
        );
        assert_eq!(
            serde_json::from_value::<ScheduleTarget>(
                serde_json::json!({ "kind": "device", "id": 7 })
            )
            .unwrap(),
            ScheduleTarget::Device(7)
        );
    }
}
