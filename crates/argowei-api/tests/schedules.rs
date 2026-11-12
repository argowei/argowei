//! Scan schedules: the API, and the scheduler's steps (claiming due runs,
//! skipping missed ones, queuing scans as `system`, never overlapping).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use argowei_api::scans::scheduler::{claim_due, execute_run, DueRun};
use argowei_api::scans::{ScanConfig, ScanRunner};
use argowei_core::scan_profile::ScanProfile;
use argowei_core::scan_schedule::ScheduleTarget;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

/// A stand-in nmap that never finishes, so scans stay `running`.
struct SleepingNmap {
    dir: PathBuf,
}

impl SleepingNmap {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "argowei-sched-nmap-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("nmap");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 600\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir }
    }

    fn runner(&self) -> ScanRunner {
        ScanRunner::new(ScanConfig {
            nmap_path: self.dir.join("nmap").to_str().unwrap().to_owned(),
            ..ScanConfig::default()
        })
    }
}

impl Drop for SleepingNmap {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn create(h: &Harness, cookie: &str, body: Value) -> Reply {
    send(
        &h.app,
        Method::POST,
        "/api/scan-schedules",
        Some(cookie),
        Some(body),
    )
    .await
}

async fn patch(h: &Harness, cookie: &str, id: i64, body: Value) -> Reply {
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/scan-schedules/{id}"),
        Some(cookie),
        Some(body),
    )
    .await
}

fn nightly(name: &str, target: Value) -> Value {
    json!({ "name": name, "cron": "0 3 * * *", "profile": "quick", "target": target })
}

fn time(value: &Value) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value.as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc)
}

async fn next_run(h: &Harness, id: i32) -> Option<DateTime<Utc>> {
    sqlx::query_scalar("SELECT next_run_at FROM scan_schedules WHERE id = $1")
        .bind(id)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

/// Makes a schedule due `ago` before now.
async fn due(h: &Harness, id: i32, ago: ChronoDuration) {
    sqlx::query("UPDATE scan_schedules SET next_run_at = $2 WHERE id = $1")
        .bind(id)
        .bind(Utc::now() - ago)
        .execute(&h.pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn schedules_are_created_listed_edited_and_deleted(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let device = insert_device(&h.pool, "aa:bb:cc:00:00:01").await;

    let reply = create(
        &h,
        &cookie,
        nightly("  Nightly  ", json!({ "kind": "device", "id": device })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let s = &reply.body;
    let id = s["id"].as_i64().unwrap();
    assert_eq!(s["name"], "Nightly");
    assert_eq!(s["enabled"], true);
    assert_eq!(s["target"], json!({ "kind": "device", "id": device }));
    assert_eq!(s["target_name"], "aa:bb:cc:00:00:01");
    assert_eq!(s["created_by"], "admin");
    assert!(s["description"].as_str().unwrap().contains("03:00"), "{s}");
    assert!(time(&s["next_run_at"]) > Utc::now());
    let upcoming = s["upcoming"].as_array().unwrap();
    assert_eq!(upcoming.len(), 3);
    assert_eq!(
        time(&upcoming[1]) - time(&upcoming[0]),
        ChronoDuration::days(1)
    );

    let all = create(&h, &cookie, json!({ "name": "Everything", "cron": "0 4 * * SUN", "profile": "full", "target": { "kind": "all" }, "enabled": false })).await;
    assert_eq!(all.status, StatusCode::CREATED);
    assert!(
        all.body["next_run_at"].is_null() && all.body["upcoming"].as_array().unwrap().is_empty()
    );

    let list = send(
        &h.app,
        Method::GET,
        "/api/scan-schedules",
        Some(&cookie),
        None,
    )
    .await;
    let names: Vec<&str> = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Everything", "Nightly"]);

    // Renaming keeps the planned run; disabling clears it; enabling plans anew.
    let before = s["next_run_at"].clone();
    let renamed = patch(&h, &cookie, id, json!({ "name": "Nightly scan" })).await;
    assert_eq!(renamed.status, StatusCode::OK);
    assert_eq!(renamed.body["next_run_at"], before);
    let off = patch(&h, &cookie, id, json!({ "enabled": false })).await;
    assert!(off.body["next_run_at"].is_null());
    let on = patch(
        &h,
        &cookie,
        id,
        json!({ "enabled": true, "cron": "30 2 * * *" }),
    )
    .await;
    assert_eq!(on.body["cron"], "30 2 * * *");
    assert!(time(&on.body["next_run_at"]) > Utc::now());

    let removed = send(
        &h.app,
        Method::DELETE,
        &format!("/api/scan-schedules/{id}"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert_eq!(
        patch(&h, &cookie, id, json!({ "enabled": false }))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    assert_eq!(audit_count(&h, "scan_schedule.create").await, 2);
    assert_eq!(audit_count(&h, "scan_schedule.update").await, 3);
    assert_eq!(audit_count(&h, "scan_schedule.delete").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn bad_schedules_are_refused_with_a_reason(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let all = json!({ "kind": "all" });

    for (body, status, message) in [
        (
            json!({ "name": "x", "cron": "*/5 * * * *", "profile": "quick", "target": all }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a schedule may run at most every 15 minutes",
        ),
        (
            json!({ "name": "x", "cron": "0 3 * *", "profile": "quick", "target": all }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "not a valid cron expression",
        ),
        (
            json!({ "name": "x", "cron": "0 0 30 2 *", "profile": "quick", "target": all }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "never matches",
        ),
        (
            json!({ "name": "x", "cron": "0 3 * * *", "profile": "-sS", "target": all }),
            StatusCode::BAD_REQUEST,
            "profile must be",
        ),
        (
            json!({ "name": "x", "cron": "0 3 * * *", "profile": "quick", "target": { "kind": "device", "id": 999 } }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "no such device to scan",
        ),
        (
            json!({ "name": "x", "cron": "0 3 * * *", "profile": "quick", "target": { "kind": "group", "id": 999 } }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "no such group to scan",
        ),
        (
            json!({ "name": " ", "cron": "0 3 * * *", "profile": "quick", "target": all }),
            StatusCode::BAD_REQUEST,
            "name must be",
        ),
    ] {
        let reply = create(&h, &cookie, body.clone()).await;
        assert_eq!(reply.status, status, "{body}: {}", reply.body);
        assert!(
            reply.body["error"].as_str().unwrap().contains(message),
            "{body}: {}",
            reply.body
        );
    }

    assert_eq!(
        create(&h, &cookie, nightly("Nightly", all.clone()))
            .await
            .status,
        StatusCode::CREATED
    );
    let twin = create(&h, &cookie, nightly("NIGHTLY", all.clone())).await;
    assert_eq!(twin.status, StatusCode::CONFLICT);

    let preview = send(
        &h.app,
        Method::GET,
        "/api/scan-schedules/preview?cron=0%203%20*%20*%20*",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(preview.body["upcoming"].as_array().unwrap().len(), 3);
    let bad = send(
        &h.app,
        Method::GET,
        "/api/scan-schedules/preview?cron=*%20*%20*%20*%20*",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);

    let anonymous = send(&h.app, Method::GET, "/api/scan-schedules", None, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_due_run_is_claimed_once_and_a_missed_one_is_skipped(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let a = create(&h, &cookie, nightly("Due", json!({ "kind": "all" })))
        .await
        .body["id"]
        .as_i64()
        .unwrap() as i32;
    let b = create(&h, &cookie, nightly("Missed", json!({ "kind": "all" })))
        .await
        .body["id"]
        .as_i64()
        .unwrap() as i32;
    let c = create(&h, &cookie, nightly("Later", json!({ "kind": "all" })))
        .await
        .body["id"]
        .as_i64()
        .unwrap() as i32;
    let off = create(&h, &cookie, json!({ "name": "Off", "cron": "0 3 * * *", "profile": "quick", "target": { "kind": "all" }, "enabled": false })).await;
    assert_eq!(off.status, StatusCode::CREATED);
    due(&h, a, ChronoDuration::seconds(30)).await;
    due(&h, b, ChronoDuration::days(2)).await; // the server was down
    let later = next_run(&h, c).await;

    let claimed = claim_due(&h.pool, Local::now()).await.unwrap();
    assert_eq!(
        claimed
            .runs
            .iter()
            .map(|r| r.schedule_id)
            .collect::<Vec<_>>(),
        [a]
    );
    assert_eq!(claimed.runs[0].profile, ScanProfile::Quick);
    assert_eq!(claimed.runs[0].target, ScheduleTarget::All);
    assert_eq!(claimed.skipped_missed, [b]);

    // Both moved to their next future occurrence. Claiming alone does not
    // count as a run: the scan may still be skipped or fail to queue.
    assert!(next_run(&h, a).await.unwrap() > Utc::now());
    assert!(next_run(&h, b).await.unwrap() > Utc::now());
    assert_eq!(next_run(&h, c).await, later);
    let last_runs: Vec<(String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT name, last_run_at FROM scan_schedules ORDER BY id")
            .fetch_all(&h.pool)
            .await
            .unwrap();
    assert!(last_runs[0].1.is_none(), "Due was only claimed");
    assert!(last_runs[1].1.is_none(), "Missed did not");

    // Claiming again at the same moment finds nothing: no double runs.
    let again = claim_due(&h.pool, Local::now()).await.unwrap();
    assert!(again.runs.is_empty() && again.skipped_missed.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_run_queues_its_targets_as_system_and_never_overlaps(pool: PgPool) {
    let nmap = SleepingNmap::new();
    let runner = nmap.runner();
    let h = harness(pool).await;
    let servers: i32 = sqlx::query_scalar("SELECT id FROM device_groups WHERE slug = 'servers'")
        .fetch_one(&h.pool)
        .await
        .unwrap();

    // Two devices in the group (one with a public address), one outside it.
    scan(
        &h,
        &[host(10, "aa:bb:cc:00:00:01"), host(11, "aa:bb:cc:00:00:03")],
        t0(),
    )
    .await;
    let public = insert_device(&h.pool, "aa:bb:cc:00:00:02").await;
    sqlx::query(
        "INSERT INTO device_addresses (device_id, ip_address, protocol, source, first_seen, last_seen) \
         VALUES ($1, '8.8.8.8', 'ipv4', 'arp', now(), now())",
    )
    .bind(public)
    .execute(&h.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET group_id = $1 WHERE mac_address IN ('aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02')")
        .bind(servers)
        .execute(&h.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO scan_schedules (name, cron, profile, target_kind, target_id, created_by, next_run_at) \
         VALUES ('Servers', '0 3 * * *', 'quick', 'group', $1, 'admin', now())",
    )
    .bind(servers)
    .execute(&h.pool)
    .await
    .unwrap();
    let schedule: i32 = sqlx::query_scalar("SELECT id FROM scan_schedules")
        .fetch_one(&h.pool)
        .await
        .unwrap();

    let run = DueRun {
        schedule_id: schedule,
        profile: ScanProfile::Quick,
        target: ScheduleTarget::Group(servers),
        jitter: std::time::Duration::ZERO,
    };
    let first = execute_run(&h.pool, &runner, &run).await.unwrap();
    assert_eq!(first.queued.len(), 1, "only the group's scannable device");
    assert_eq!(first.refused, 1, "the public address is refused");
    assert!(!first.skipped_overlap);
    let first_run_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_run_at FROM scan_schedules WHERE id = $1")
            .bind(schedule)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(first_run_at.is_some(), "a queued scan counts as a run");

    let (requested_by, schedule_id, target): (String, Option<i32>, String) =
        sqlx::query_as("SELECT requested_by, schedule_id, target_ip FROM scans")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        (requested_by.as_str(), schedule_id, target.as_str()),
        ("system", Some(schedule), "192.168.1.10")
    );
    let actors: Vec<(String, String, String)> = audit_actions(&h.pool).await;
    assert_eq!(
        actors,
        [("system".into(), "scan.start".into(), "success".into())]
    );

    // The scan is still running: the next run of the schedule is skipped.
    let second = execute_run(&h.pool, &runner, &run).await.unwrap();
    assert!(second.skipped_overlap);
    assert!(second.queued.is_empty());
    assert_eq!(count(&h.pool, "scans").await, 1);
    let after_overlap: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_run_at FROM scan_schedules WHERE id = $1")
            .bind(schedule)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(after_overlap, first_run_at, "overlap is not a run");

    sqlx::query("UPDATE scans SET status = 'cancelled', finished_at = now()")
        .execute(&h.pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn disabling_a_claimed_schedule_prevents_its_scan(pool: PgPool) {
    let nmap = SleepingNmap::new();
    let runner = nmap.runner();
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, "aa:bb:cc:00:00:01")], t0()).await;
    let schedule = create(&h, &cookie, nightly("Pending", json!({ "kind": "all" })))
        .await
        .body["id"]
        .as_i64()
        .unwrap() as i32;
    due(&h, schedule, ChronoDuration::seconds(30)).await;
    let claimed = claim_due(&h.pool, Local::now()).await.unwrap();
    assert_eq!(claimed.runs.len(), 1);

    let off = patch(
        &h,
        &cookie,
        i64::from(schedule),
        json!({ "enabled": false }),
    )
    .await;
    assert_eq!(off.status, StatusCode::OK);
    let outcome = execute_run(&h.pool, &runner, &claimed.runs[0])
        .await
        .unwrap();
    assert!(outcome.skipped_inactive);
    assert!(outcome.queued.is_empty());
    assert_eq!(count(&h.pool, "scans").await, 0);
    let last_run_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_run_at FROM scan_schedules WHERE id = $1")
            .bind(schedule)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert!(last_run_at.is_none());
}
