//! Export one device's persisted scan attempts to the presence replay schema.
//! Labels and a pseudonym come from a separate, operator-written JSON file.

use std::path::Path;
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[cfg(test)]
#[path = "presence_replay/mod.rs"]
mod presence_replay;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Study {
    schema_version: u8,
    dataset: Dataset,
    policy: Policy,
    traces: Vec<Window>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    offline_after_missed_scans: u32,
    offline_after_secs: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Dataset {
    id: String,
    kind: String,
    description: String,
    ground_truth_source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    device_id: String,
    mac_address: String,
    interface: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    ground_truth: Vec<ReferenceLabel>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceLabel {
    at: DateTime<Utc>,
    state: LabelState,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum LabelState {
    Online,
    Offline,
    Unknown,
}

#[derive(Serialize)]
struct ReplayInput {
    schema_version: u8,
    dataset: Dataset,
    policy: Policy,
    traces: Vec<ReplayTrace>,
}

#[derive(Serialize)]
struct ReplayTrace {
    device_id: String,
    interface: String,
    duration_ms: u64,
    observations: Vec<Observation>,
    ground_truth: Vec<Label>,
}

#[derive(Serialize)]
struct Observation {
    at_ms: u64,
    outcome: &'static str,
}

#[derive(Serialize)]
struct Label {
    at_ms: u64,
    state: LabelState,
}

#[derive(sqlx::FromRow)]
struct Attempt {
    attempted_at: DateTime<Utc>,
    outcome: String,
    replied: bool,
    scan_interface: Option<String>,
    scanned_at: Option<DateTime<Utc>>,
    offline_after_missed_scans: Option<i64>,
    offline_after_secs: Option<i64>,
}

fn offset(at: DateTime<Utc>, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<u64, String> {
    if at < start || at >= end {
        return Err("event timestamp is outside its half-open trace window".into());
    }
    u64::try_from((at - start).num_milliseconds()).map_err(|_| "invalid event offset".into())
}

fn labels(window: &Window) -> Result<Vec<Label>, String> {
    let mut result = Vec::with_capacity(window.ground_truth.len());
    let mut previous = None;
    for item in &window.ground_truth {
        let at_ms = offset(item.at, window.start, window.end)?;
        if previous.is_some_and(|at| at >= at_ms) {
            return Err(format!(
                "ground-truth labels must strictly increase for {}",
                window.device_id
            ));
        }
        result.push(Label {
            at_ms,
            state: item.state,
        });
        previous = Some(at_ms);
    }
    if result.is_empty() {
        return Err(format!(
            "ground-truth labels are required for {}",
            window.device_id
        ));
    }
    Ok(result)
}

async fn export(pool: &PgPool, study: Study) -> Result<ReplayInput, String> {
    if study.schema_version != 1 || study.dataset.kind != "lab" || study.traces.is_empty() {
        return Err("expected schema_version 1, dataset.kind lab and nonempty traces".into());
    }
    if study.policy.offline_after_missed_scans == 0 {
        return Err("offline_after_missed_scans must be positive".into());
    }
    chrono::Duration::from_std(std::time::Duration::from_secs(
        study.policy.offline_after_secs,
    ))
    .map_err(|_| "offline_after_secs exceeds the supported time range")?;
    for value in [
        &study.dataset.id,
        &study.dataset.description,
        &study.dataset.ground_truth_source,
    ] {
        if value.trim().is_empty() {
            return Err("dataset provenance fields must not be blank".into());
        }
    }
    // A single read-only snapshot keeps the inventory lookup, completeness
    // check, attempts and sightings consistent while discovery is running.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("cannot start export snapshot: {e}"))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("cannot configure export snapshot: {e}"))?;
    let mut traces = Vec::with_capacity(study.traces.len());
    let mut ids = std::collections::HashSet::new();
    for window in study.traces {
        if window.device_id.trim().is_empty()
            || window.interface.trim().is_empty()
            || window.mac_address.trim().is_empty()
            || !ids.insert(window.device_id.clone())
        {
            return Err(
                "trace identifiers, interface and MAC must be nonempty; device IDs must be unique"
                    .into(),
            );
        }
        let duration_ms = u64::try_from((window.end - window.start).num_milliseconds())
            .map_err(|_| "trace end must be after start".to_string())?;
        if duration_ms == 0 {
            return Err("trace duration must be positive".into());
        }
        let ground_truth = labels(&window)?;
        let mac = window.mac_address.to_ascii_lowercase();
        let known: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE mac_address = $1)")
                .bind(&mac)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| format!("cannot look up device: {e}"))?;
        if !known {
            return Err(format!(
                "device {} has no inventory record",
                window.device_id
            ));
        }
        let unjournaled: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM discovery_scans s \
             LEFT JOIN scan_attempts a ON a.scan_id = s.id \
                 AND a.interface = s.interface AND a.attempted_at = s.scanned_at \
             WHERE s.interface = $1 AND s.scanned_at >= $2 AND s.scanned_at < $3 \
             AND a.id IS NULL)",
        )
        .bind(&window.interface)
        .bind(window.start)
        .bind(window.end)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("cannot check scan history: {e}"))?;
        if unjournaled {
            return Err(format!(
                "window for {} contains completed scans without attempt records",
                window.device_id
            ));
        }
        let rows: Vec<Attempt> = sqlx::query_as(
            "SELECT a.attempted_at, a.outcome, s.interface AS scan_interface, \
                    s.scanned_at, a.offline_after_missed_scans, a.offline_after_secs, \
                    EXISTS (SELECT 1 FROM device_sightings s \
                            JOIN devices d ON d.id = s.device_id \
                            WHERE s.scan_id = a.scan_id AND d.mac_address = $4) AS replied \
             FROM scan_attempts a \
             LEFT JOIN discovery_scans s ON s.id = a.scan_id \
             WHERE a.interface = $1 AND a.attempted_at >= $2 AND a.attempted_at < $3 \
             ORDER BY a.attempted_at, a.id",
        )
        .bind(&window.interface)
        .bind(window.start)
        .bind(window.end)
        .bind(&mac)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("cannot read scan attempts: {e}"))?;
        let mut observations = Vec::new();
        let mut previous = None;
        let mut has_non_skipped = false;
        for row in rows {
            if row.outcome == "completed"
                && (row.scan_interface.as_deref() != Some(window.interface.as_str())
                    || row.scanned_at != Some(row.attempted_at))
            {
                return Err(format!(
                    "completed attempt has mismatched scan interface or timestamp for {}",
                    window.device_id
                ));
            }
            if row.outcome == "completed" {
                let recorded = (row.offline_after_missed_scans, row.offline_after_secs);
                if recorded.0.is_none() || recorded.1.is_none() {
                    return Err(format!(
                        "completed attempt has no recorded presence policy for {}; use a window after migration 0012",
                        window.device_id
                    ));
                }
                let expected = (
                    i64::from(study.policy.offline_after_missed_scans),
                    i64::try_from(study.policy.offline_after_secs)
                        .map_err(|_| "study policy exceeds BIGINT seconds")?,
                );
                if recorded != (Some(expected.0), Some(expected.1)) {
                    return Err(format!(
                        "recorded presence policy differs from study policy for {}; use a separate study for each policy or correct the study",
                        window.device_id
                    ));
                }
            }
            let at_ms = offset(row.attempted_at, window.start, window.end)?;
            if previous.is_some_and(|at| at >= at_ms) {
                return Err(format!(
                    "scan attempts share one millisecond for {}; narrow or repair the window",
                    window.device_id
                ));
            }
            let outcome = match row.outcome.as_str() {
                "completed" if row.replied => "reply",
                "completed" => "miss",
                "failed" => "failed",
                "skipped" => "skipped",
                _ => return Err("unsupported attempt outcome".into()),
            };
            has_non_skipped |= outcome != "skipped";
            observations.push(Observation { at_ms, outcome });
            previous = Some(at_ms);
        }
        if !has_non_skipped {
            return Err(format!("no non-skipped attempts for {}", window.device_id));
        }
        traces.push(ReplayTrace {
            device_id: window.device_id,
            interface: window.interface,
            duration_ms,
            observations,
            ground_truth,
        });
    }
    tx.commit()
        .await
        .map_err(|e| format!("cannot finish export snapshot: {e}"))?;
    Ok(ReplayInput {
        schema_version: 2,
        dataset: study.dataset,
        policy: study.policy,
        traces,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("presence_export: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: presence_export <study.json> (requires DATABASE_URL)".into());
    }
    let bytes =
        std::fs::read(Path::new(&args[0])).map_err(|e| format!("cannot read study: {e}"))?;
    let study: Study = serde_json::from_slice(&bytes).map_err(|e| format!("invalid study: {e}"))?;
    let url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let pool = PgPool::connect(&url)
        .await
        .map_err(|e| format!("cannot connect: {e}"))?;
    let result = export(&pool, study).await?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &result)
        .map_err(|e| format!("cannot write export: {e}"))?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argowei_api::discovery::{record_scan, ObservedHost};
    use argowei_api::presence::PresencePolicy;
    use chrono::{Duration, TimeZone};
    use std::net::Ipv4Addr;

    const MAC: &str = "aa:bb:cc:00:00:01";

    fn start() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    fn policy() -> PresencePolicy {
        PresencePolicy {
            offline_after_missed_scans: 4,
            offline_after: std::time::Duration::from_secs(1200),
        }
    }

    /// A reply, a miss, a failed and a skipped attempt in one ten-minute window,
    /// with a matching study. Each error test starts from this clean state and
    /// mutates one thing, so the tests do not depend on each other's order.
    async fn seed(db: &PgPool) -> serde_json::Value {
        let start = start();
        record_scan(
            db,
            "eth0",
            &[ObservedHost {
                ip: Ipv4Addr::new(192, 168, 1, 10),
                mac: MAC.into(),
            }],
            start,
            &policy(),
        )
        .await
        .unwrap();
        record_scan(db, "eth0", &[], start + Duration::minutes(5), &policy())
            .await
            .unwrap();
        for (minute, outcome, kind) in [(7, "failed", Some("scanner")), (8, "skipped", None)] {
            sqlx::query(
                "INSERT INTO scan_attempts (interface, attempted_at, outcome, failure_kind) \
                         VALUES ('eth0', $1, $2, $3)",
            )
            .bind(start + Duration::minutes(minute))
            .bind(outcome)
            .bind(kind)
            .execute(db)
            .await
            .unwrap();
        }
        serde_json::json!({
            "schema_version": 1,
            "dataset": { "id": "test", "kind": "lab", "description": "test window",
                "ground_truth_source": "independent test label" },
            "policy": { "offline_after_missed_scans": 4, "offline_after_secs": 1200 },
            "traces": [{ "device_id": "device-1", "mac_address": MAC,
                "interface": "eth0", "start": start,
                "end": start + Duration::minutes(10),
                "ground_truth": [{ "at": start, "state": "online" }] }]
        })
    }

    async fn export_error(db: &PgPool, study_json: serde_json::Value) -> String {
        export(db, serde_json::from_value(study_json).unwrap())
            .await
            .err()
            .expect("export should have failed")
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn exports_reply_miss_failure_and_skip(db: PgPool) {
        let study_json = seed(&db).await;
        let output = export(&db, serde_json::from_value(study_json).unwrap())
            .await
            .unwrap();
        presence_replay::replay_json(&serde_json::to_vec(&output).unwrap()).unwrap();
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["policy"]["offline_after_missed_scans"], 4);
        assert_eq!(value["policy"]["offline_after_secs"], 1200);
        assert_eq!(
            value["traces"][0]["observations"],
            serde_json::json!([
                { "at_ms": 0, "outcome": "reply" },
                { "at_ms": 300000, "outcome": "miss" },
                { "at_ms": 420000, "outcome": "failed" },
                { "at_ms": 480000, "outcome": "skipped" }
            ])
        );
        assert_eq!(
            value["traces"][0]["ground_truth"],
            serde_json::json!([{ "at_ms": 0, "state": "online" }])
        );
        // The pseudonym travels; the real MAC never does.
        assert!(value.to_string().contains("device-1"));
        assert!(!value.to_string().contains(MAC));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_study_policy_that_differs_from_the_recorded_one(db: PgPool) {
        let mut study_json = seed(&db).await;
        study_json["policy"]["offline_after_missed_scans"] = serde_json::json!(3);
        assert!(export_error(&db, study_json)
            .await
            .contains("recorded presence policy differs"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_completed_scan_without_a_policy_snapshot(db: PgPool) {
        let study_json = seed(&db).await;
        sqlx::query(
            "UPDATE scan_attempts SET offline_after_missed_scans = NULL, offline_after_secs = NULL \
             WHERE attempted_at = $1",
        )
        .bind(start())
        .execute(&db)
        .await
        .unwrap();
        assert!(export_error(&db, study_json)
            .await
            .contains("no recorded presence policy"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_completed_scan_without_an_attempt_record(db: PgPool) {
        let study_json = seed(&db).await;
        sqlx::query(
            "INSERT INTO discovery_scans (interface, scanned_at, hosts_seen) \
                     VALUES ('eth0', $1, 0)",
        )
        .bind(start() + Duration::minutes(9))
        .execute(&db)
        .await
        .unwrap();
        assert!(export_error(&db, study_json)
            .await
            .contains("without attempt records"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_completed_attempt_linked_to_a_different_interface(db: PgPool) {
        let study_json = seed(&db).await;
        sqlx::query("UPDATE discovery_scans SET interface = 'wlan0' WHERE scanned_at = $1")
            .bind(start())
            .execute(&db)
            .await
            .unwrap();
        assert!(export_error(&db, study_json)
            .await
            .contains("mismatched scan interface or timestamp"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_completed_attempt_linked_to_a_different_timestamp(db: PgPool) {
        let study_json = seed(&db).await;
        sqlx::query("UPDATE discovery_scans SET scanned_at = $1 WHERE scanned_at = $2")
            .bind(start() - Duration::seconds(1))
            .bind(start())
            .execute(&db)
            .await
            .unwrap();
        assert!(export_error(&db, study_json)
            .await
            .contains("mismatched scan interface or timestamp"));
    }

    /// A syntactically valid study whose input passes serde but can be mutated to
    /// trip one input validation. These checks run before any database read, so
    /// the error is about the study, not the inventory.
    fn minimal_study() -> serde_json::Value {
        let start = start();
        serde_json::json!({
            "schema_version": 1,
            "dataset": { "id": "test", "kind": "lab", "description": "test window",
                "ground_truth_source": "independent test label" },
            "policy": { "offline_after_missed_scans": 4, "offline_after_secs": 1200 },
            "traces": [{ "device_id": "device-1", "mac_address": MAC,
                "interface": "eth0", "start": start,
                "end": start + Duration::minutes(10),
                "ground_truth": [{ "at": start, "state": "online" }] }]
        })
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_study_that_is_not_a_lab_schema_1_window(db: PgPool) {
        let mut study = minimal_study();
        study["dataset"]["kind"] = serde_json::json!("synthetic");
        assert!(export_error(&db, study)
            .await
            .contains("schema_version 1, dataset.kind lab"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_non_positive_miss_threshold(db: PgPool) {
        let mut study = minimal_study();
        study["policy"]["offline_after_missed_scans"] = serde_json::json!(0);
        assert!(export_error(&db, study)
            .await
            .contains("offline_after_missed_scans must be positive"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_blank_dataset_provenance(db: PgPool) {
        let mut study = minimal_study();
        study["dataset"]["ground_truth_source"] = serde_json::json!("   ");
        assert!(export_error(&db, study)
            .await
            .contains("dataset provenance fields must not be blank"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_trace_whose_end_precedes_its_start(db: PgPool) {
        let mut study = minimal_study();
        // end < start: a negative duration, which is the "end after start" check.
        study["traces"][0]["end"] = serde_json::to_value(start() - Duration::minutes(1)).unwrap();
        assert!(export_error(&db, study)
            .await
            .contains("trace end must be after start"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_zero_length_trace(db: PgPool) {
        let mut study = minimal_study();
        // end == start: a zero duration, caught by the positive-duration check.
        study["traces"][0]["end"] = serde_json::to_value(start()).unwrap();
        assert!(export_error(&db, study)
            .await
            .contains("trace duration must be positive"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_duplicate_device_pseudonyms(db: PgPool) {
        // seed provides the inventory the first trace needs, so the export
        // reaches the second trace and rejects the repeated device_id.
        let study_json = seed(&db).await;
        let mut study = study_json.clone();
        let second = study["traces"][0].clone();
        study["traces"].as_array_mut().unwrap().push(second);
        assert!(export_error(&db, study)
            .await
            .contains("device IDs must be unique"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_non_increasing_ground_truth_labels(db: PgPool) {
        let mut study = minimal_study();
        let start = start();
        study["traces"][0]["ground_truth"] = serde_json::json!([
            { "at": start, "state": "online" },
            { "at": start, "state": "offline" }
        ]);
        assert!(export_error(&db, study)
            .await
            .contains("ground-truth labels must strictly increase"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_label_outside_the_trace_window(db: PgPool) {
        let mut study = minimal_study();
        let start = start();
        study["traces"][0]["ground_truth"] =
            serde_json::json!([{ "at": start - Duration::minutes(1), "state": "online" }]);
        assert!(export_error(&db, study)
            .await
            .contains("outside its half-open trace window"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_trace_without_ground_truth_labels(db: PgPool) {
        let mut study = minimal_study();
        study["traces"][0]["ground_truth"] = serde_json::json!([]);
        assert!(export_error(&db, study)
            .await
            .contains("ground-truth labels are required"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_a_window_with_only_skipped_attempts(db: PgPool) {
        // Seed a known device, then a window whose only attempt is skipped.
        let study_json = seed(&db).await;
        let late = start() + Duration::minutes(20);
        sqlx::query(
            "INSERT INTO scan_attempts (interface, attempted_at, outcome) \
                     VALUES ('eth0', $1, 'skipped')",
        )
        .bind(late)
        .execute(&db)
        .await
        .unwrap();
        let mut study = study_json;
        study["traces"][0]["start"] = serde_json::to_value(late).unwrap();
        study["traces"][0]["end"] = serde_json::to_value(late + Duration::minutes(5)).unwrap();
        study["traces"][0]["ground_truth"] = serde_json::json!([{ "at": late, "state": "online" }]);
        assert!(export_error(&db, study)
            .await
            .contains("no non-skipped attempts"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rejects_attempts_that_share_a_millisecond(db: PgPool) {
        // Seed a device, then two failed attempts at the same instant.
        let study_json = seed(&db).await;
        let late = start() + Duration::minutes(20);
        for _ in 0..2 {
            sqlx::query(
                "INSERT INTO scan_attempts (interface, attempted_at, outcome, failure_kind) \
                         VALUES ('eth0', $1, 'failed', 'scanner')",
            )
            .bind(late)
            .execute(&db)
            .await
            .unwrap();
        }
        let mut study = study_json;
        study["traces"][0]["start"] = serde_json::to_value(late).unwrap();
        study["traces"][0]["end"] = serde_json::to_value(late + Duration::minutes(5)).unwrap();
        study["traces"][0]["ground_truth"] = serde_json::json!([{ "at": late, "state": "online" }]);
        assert!(export_error(&db, study)
            .await
            .contains("share one millisecond"));
    }
}
