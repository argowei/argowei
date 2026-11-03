//! Deterministic synthetic evaluation of the production PresencePolicy.
//! No sockets, database, wall clock, or random seed are used.

use std::time::Duration;

use argowei_api::presence::PresencePolicy;
use chrono::{TimeZone, Utc};
use serde::Serialize;

#[derive(Clone, Copy)]
struct Step {
    minute: i64,
    completed: bool,
    replied: bool,
    truly_online: bool,
}

const fn scan(minute: i64, replied: bool, truly_online: bool) -> Step {
    Step {
        minute,
        completed: true,
        replied,
        truly_online,
    }
}

const fn failed(minute: i64, truly_online: bool) -> Step {
    Step {
        minute,
        completed: false,
        replied: false,
        truly_online,
    }
}

const INTERMITTENT: &[Step] = &[
    scan(0, true, true),
    scan(5, false, true),
    scan(10, false, true),
    scan(15, true, true),
    scan(20, false, true),
    scan(25, true, true),
];
const DEPARTURE: &[Step] = &[
    scan(0, true, true),
    scan(5, true, true),
    scan(10, true, true),
    scan(15, false, false),
    scan(20, false, false),
    scan(25, false, false),
    scan(30, false, false),
];
const SCANNER_GAP: &[Step] = &[
    scan(0, true, true),
    failed(5, true),
    failed(10, true),
    scan(65, false, true),
    scan(70, true, true),
];
const SLEEP: &[Step] = &[
    scan(0, true, true),
    scan(5, false, true),
    scan(10, false, true),
    scan(15, false, true),
    scan(20, false, true),
    scan(25, true, true),
];
const RAPID_MISSES: &[Step] = &[
    scan(0, true, true),
    scan(1, false, true),
    scan(2, false, true),
    scan(3, false, true),
    scan(5, true, true),
];

const SCENARIOS: &[(&str, &[Step])] = &[
    ("intermittent_replies", INTERMITTENT),
    ("actual_departure", DEPARTURE),
    ("scanner_gap", SCANNER_GAP),
    ("sleeping_device", SLEEP),
    ("rapid_misses", RAPID_MISSES),
];

#[derive(Clone, Copy)]
enum Rule {
    Production,
    TimeOnly,
    MissesOnly,
    OneMiss,
}

const RULES: &[(Rule, &str)] = &[
    (Rule::Production, "production_and"),
    (Rule::TimeOnly, "time_only_15m"),
    (Rule::MissesOnly, "misses_only_3"),
    (Rule::OneMiss, "one_miss"),
];

#[derive(Serialize)]
struct ResultRow {
    scenario: &'static str,
    rule: &'static str,
    completed_scans: u32,
    false_offline: u32,
    missed_offline: u32,
    first_detection_minute: Option<i64>,
}

fn evaluate(name: &'static str, steps: &[Step], rule: Rule, rule_name: &'static str) -> ResultRow {
    let policy = PresencePolicy {
        offline_after_missed_scans: 3,
        offline_after: Duration::from_secs(15 * 60),
    };
    let origin = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let mut last_seen = origin;
    let mut misses = 0_i64;
    let mut online = true;
    let mut row = ResultRow {
        scenario: name,
        rule: rule_name,
        completed_scans: 0,
        false_offline: 0,
        missed_offline: 0,
        first_detection_minute: None,
    };
    for step in steps {
        if !step.completed {
            continue; // A failed scan supplies no evidence about the device.
        }
        row.completed_scans += 1;
        let now = origin + chrono::Duration::minutes(step.minute);
        if step.replied {
            last_seen = now;
            misses = 0;
            online = true;
        } else {
            misses += 1;
            let offline = match rule {
                Rule::Production => policy.is_offline(misses, last_seen, now),
                Rule::TimeOnly => now.signed_duration_since(last_seen).num_minutes() >= 15,
                Rule::MissesOnly => misses >= 3,
                Rule::OneMiss => misses >= 1,
            };
            if offline {
                online = false;
            }
        }
        if step.truly_online && !online {
            row.false_offline += 1;
        } else if !step.truly_online && online {
            row.missed_offline += 1;
        }
        if !step.truly_online && !online && row.first_detection_minute.is_none() {
            row.first_detection_minute = Some(step.minute);
        }
    }
    row
}

fn main() {
    let results: Vec<_> = SCENARIOS
        .iter()
        .flat_map(|(name, steps)| {
            RULES
                .iter()
                .map(move |(rule, rule_name)| evaluate(name, steps, *rule, rule_name))
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_and_sleep_expose_distinct_failure_modes() {
        let gap = evaluate(
            "scanner_gap",
            SCANNER_GAP,
            Rule::Production,
            "production_and",
        );
        let time = evaluate("scanner_gap", SCANNER_GAP, Rule::TimeOnly, "time_only_15m");
        let sleep = evaluate("sleeping_device", SLEEP, Rule::Production, "production_and");
        assert_eq!(gap.false_offline, 0);
        assert_eq!(time.false_offline, 1);
        assert_eq!(sleep.false_offline, 2);
        let rapid = evaluate(
            "rapid_misses",
            RAPID_MISSES,
            Rule::Production,
            "production_and",
        );
        let misses = evaluate(
            "rapid_misses",
            RAPID_MISSES,
            Rule::MissesOnly,
            "misses_only_3",
        );
        assert_eq!(rapid.false_offline, 0);
        assert_eq!(misses.false_offline, 1);
    }
}
