//! Port scans through the API, with small shell scripts standing in for
//! nmap: one replays recorded XML (and writes down the arguments it got),
//! one sleeps (for cancel and timeout), one fails.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use argowei_api::scans::{store, ScanConfig};
use argowei_core::scan_target::ScanTargets;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

const PRINTER: &str = "aa:bb:cc:00:00:01";
const NAS: &str = "aa:bb:cc:00:00:02";

/// A throwaway directory holding a stand-in nmap script and what it records.
struct FakeNmap {
    dir: PathBuf,
}

impl FakeNmap {
    fn new(body: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "argowei-fake-nmap-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("nmap");
        let body = body.replace("$DIR", dir.to_str().unwrap());
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir }
    }

    /// Replays recorded nmap output: 18080/tcp open (SimpleHTTPServer 0.6).
    fn answering() -> Self {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../argowei-collector/src/nmap/fixtures/service.xml");
        Self::new(&format!(
            "printf '%s\\n' \"$@\" > $DIR/args\nenv > $DIR/env\ncat '{}'",
            fixture.display()
        ))
    }

    /// Runs until killed; its PID is in `pid`.
    fn sleeping() -> Self {
        Self::new("echo $$ > $DIR/pid\nexec sleep 600")
    }

    fn failing() -> Self {
        Self::new("echo 'Failed to open device eth9' >&2\nexit 1")
    }

    fn path(&self) -> String {
        self.dir.join("nmap").to_str().unwrap().to_owned()
    }

    fn config(&self) -> ScanConfig {
        ScanConfig {
            nmap_path: self.path(),
            ..ScanConfig::default()
        }
    }

    fn recorded(&self, file: &str) -> String {
        std::fs::read_to_string(self.dir.join(file)).unwrap_or_default()
    }

    /// The PID of the sleeping script, once it has started.
    async fn pid(&self) -> u32 {
        let started = Instant::now();
        loop {
            if let Ok(pid) = self.recorded("pid").trim().parse() {
                return pid;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "fake nmap never started"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for FakeNmap {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

async fn gone(pid: u32) -> bool {
    let started = Instant::now();
    while alive(pid) {
        if started.elapsed() > Duration::from_secs(5) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

async fn setup(pool: PgPool, config: ScanConfig) -> (Harness, String) {
    let h = harness_with_scans(pool, config).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;
    (h, cookie)
}

async fn device_id(h: &Harness, mac: &str) -> i32 {
    sqlx::query_scalar("SELECT id FROM devices WHERE mac_address = $1")
        .bind(mac)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

/// A device that discovery saw at `ip` (any address, also public ones).
async fn device_at(h: &Harness, mac: &str, ip: &str) -> i32 {
    let id = insert_device(&h.pool, mac).await;
    sqlx::query(
        "INSERT INTO device_addresses (device_id, ip_address, protocol, source, first_seen, last_seen) \
         VALUES ($1, $2, 'ipv4', 'arp', now(), now())",
    )
    .bind(id)
    .bind(ip)
    .execute(&h.pool)
    .await
    .unwrap();
    id
}

async fn start(h: &Harness, cookie: &str, device: i32, profile: &str) -> Reply {
    send(
        &h.app,
        Method::POST,
        &format!("/api/devices/{device}/scans"),
        Some(cookie),
        Some(json!({ "profile": profile })),
    )
    .await
}

async fn get_scan(h: &Harness, cookie: &str, id: i64) -> Value {
    let reply = send(
        &h.app,
        Method::GET,
        &format!("/api/scans/{id}"),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    reply.body
}

/// Waits until the scan reaches `status`.
async fn wait_for(h: &Harness, cookie: &str, id: i64, status: &str) -> Value {
    let started = Instant::now();
    loop {
        let scan = get_scan(h, cookie, id).await;
        if scan["status"] == status {
            return scan;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "scan {id} stuck at {scan}, expected {status}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn scan_events(h: &Harness) -> Vec<(String, Value)> {
    sqlx::query_as("SELECT type, payload FROM events WHERE type LIKE 'scan.%' ORDER BY id")
        .fetch_all(&h.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_scan_runs_in_the_background_and_stores_its_ports(pool: PgPool) {
    let nmap = FakeNmap::answering();
    let (h, cookie) = setup(pool, nmap.config()).await;
    scan(&h, &[host(10, PRINTER)], t0()).await;
    let printer = device_id(&h, PRINTER).await;

    let reply = start(&h, &cookie, printer, "service").await;
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.body);
    assert!(["queued", "running"].contains(&reply.body["status"].as_str().unwrap()));
    assert_eq!(reply.body["target_ip"], "192.168.1.10");
    assert_eq!(reply.body["requested_by"], "admin");
    let id = reply.body["id"].as_i64().unwrap();

    let done = wait_for(&h, &cookie, id, "completed").await;
    assert_eq!(done["nmap_version"], "7.993");
    assert_eq!(done["open_ports"], 1);
    assert!(done["finished_at"].is_string() && done["error"].is_null());
    let ports = done["ports"].as_array().unwrap();
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0]["port"], 18080);
    assert_eq!(ports[0]["state"], "open");
    assert_eq!(ports[0]["service"], "http");
    assert_eq!(ports[0]["product"], "SimpleHTTPServer");
    assert_eq!(ports[1]["state"], "closed");

    // nmap got the fixed argument vector, the target last, and nothing else
    // from the API's environment.
    let args: Vec<String> = nmap.recorded("args").lines().map(str::to_owned).collect();
    assert_eq!(args.last().map(String::as_str), Some("192.168.1.10"));
    for expected in ["--unprivileged", "-sT", "-sV", "-oX", "--host-timeout"] {
        assert!(args.iter().any(|a| a == expected), "{expected} in {args:?}");
    }
    let env = nmap.recorded("env");
    assert!(
        !env.contains("DATABASE_URL") && !env.contains("POSTGRES"),
        "{env}"
    );

    let events = scan_events(&h).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "scan.completed");
    assert_eq!(events[0].1["open_ports"], json!([18080]));
    assert_eq!(events[0].1["profile"], "service");
    assert_eq!(audit_count(&h, "scan.start").await, 1);

    let history = send(
        &h.app,
        Method::GET,
        &format!("/api/devices/{printer}/scans"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(history.body.as_array().unwrap().len(), 1);
    assert_eq!(history.body[0]["id"], id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_local_addresses_are_ever_scanned(pool: PgPool) {
    let nmap = FakeNmap::answering();
    let (h, cookie) = setup(pool, nmap.config()).await;

    for (mac, ip, expected) in [
        (
            "aa:bb:cc:00:00:11",
            "8.8.8.8",
            "8.8.8.8 is not on the local network",
        ),
        (
            "aa:bb:cc:00:00:12",
            "127.0.0.1",
            "127.0.0.1 is not on the local network",
        ),
        (
            "aa:bb:cc:00:00:13",
            "100.64.1.1",
            "100.64.1.1 is not on the local network",
        ),
        ("aa:bb:cc:00:00:14", "not-an-ip", "is not an IP address"),
    ] {
        let device = device_at(&h, mac, ip).await;
        let reply = start(&h, &cookie, device, "quick").await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{ip}");
        assert!(
            reply.body["error"].as_str().unwrap().contains(expected),
            "{}",
            reply.body
        );
    }

    let silent = insert_device(&h.pool, "aa:bb:cc:00:00:15").await;
    let reply = start(&h, &cookie, silent, "quick").await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        reply.body["error"],
        "the device has no known IPv4 address to scan"
    );

    assert_eq!(count(&h.pool, "scans").await, 0, "nothing was queued");
    assert!(nmap.recorded("args").is_empty(), "nmap never ran");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_allowed_ranges_narrow_what_may_be_scanned(pool: PgPool) {
    let nmap = FakeNmap::answering();
    let config = ScanConfig {
        targets: ScanTargets::parse_list("10.0.0.0/8").unwrap(),
        ..nmap.config()
    };
    let (h, cookie) = setup(pool, config).await;
    let device = device_at(&h, PRINTER, "192.168.1.10").await;

    let reply = start(&h, &cookie, device, "quick").await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        reply.body["error"],
        "192.168.1.10 is outside the allowed scan ranges"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn bad_requests_are_refused(pool: PgPool) {
    let nmap = FakeNmap::answering();
    let (h, cookie) = setup(pool, nmap.config()).await;
    let device = device_at(&h, PRINTER, "192.168.1.10").await;

    let reply = start(&h, &cookie, device, "-sS -O --script vuln").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.body["error"],
        "profile must be quick, service or full"
    );

    assert_eq!(
        start(&h, &cookie, 9999, "quick").await.status,
        StatusCode::NOT_FOUND
    );
    let missing = send(&h.app, Method::GET, "/api/scans/9999", Some(&cookie), None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let anonymous = send(
        &h.app,
        Method::POST,
        &format!("/api/devices/{device}/scans"),
        None,
        Some(json!({ "profile": "quick" })),
    )
    .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(count(&h.pool, "scans").await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cancelled_scan_kills_nmap_and_frees_the_device(pool: PgPool) {
    let nmap = FakeNmap::sleeping();
    let (h, cookie) = setup(pool, nmap.config()).await;
    let device = device_at(&h, PRINTER, "192.168.1.10").await;

    let id = start(&h, &cookie, device, "full").await.body["id"]
        .as_i64()
        .unwrap();
    wait_for(&h, &cookie, id, "running").await;
    let pid = nmap.pid().await;
    assert!(alive(pid));

    let second = start(&h, &cookie, device, "quick").await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert_eq!(
        second.body["error"],
        "a scan of this device is already queued or running"
    );

    let cancelled = send(
        &h.app,
        Method::POST,
        &format!("/api/scans/{id}/cancel"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(cancelled.status, StatusCode::OK);
    assert_eq!(cancelled.body["status"], "cancelled");
    assert_eq!(cancelled.body["error"], "cancelled by admin");
    assert!(gone(pid).await, "nmap must be killed");

    let again = send(
        &h.app,
        Method::POST,
        &format!("/api/scans/{id}/cancel"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(audit_count(&h, "scan.cancel").await, 1);
    let events = scan_events(&h).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "scan.failed");
    assert_eq!(events[0].1["outcome"], "cancelled");

    // The device is free again.
    assert_eq!(
        start(&h, &cookie, device, "quick").await.status,
        StatusCode::ACCEPTED
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_scan_that_runs_too_long_is_killed(pool: PgPool) {
    let nmap = FakeNmap::sleeping();
    let config = ScanConfig {
        max_duration: Some(Duration::from_secs(1)),
        ..nmap.config()
    };
    let (h, cookie) = setup(pool, config).await;
    let device = device_at(&h, PRINTER, "192.168.1.10").await;

    let id = start(&h, &cookie, device, "quick").await.body["id"]
        .as_i64()
        .unwrap();
    let pid = nmap.pid().await;
    let done = wait_for(&h, &cookie, id, "timed_out").await;
    assert_eq!(done["error"], "the scan did not finish within 1 s");
    assert!(gone(pid).await, "nmap must be killed");
    assert_eq!(scan_events(&h).await[0].1["outcome"], "timed_out");
}

#[sqlx::test(migrations = "../../migrations")]
async fn nmap_failures_are_stored_with_their_reason(pool: PgPool) {
    let nmap = FakeNmap::failing();
    let (h, cookie) = setup(pool, nmap.config()).await;
    let device = device_at(&h, PRINTER, "192.168.1.10").await;
    let id = start(&h, &cookie, device, "quick").await.body["id"]
        .as_i64()
        .unwrap();
    let done = wait_for(&h, &cookie, id, "failed").await;
    assert_eq!(done["error"], "nmap failed: Failed to open device eth9");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_nmap_fails_the_scan_not_the_api(pool: PgPool) {
    let missing = ScanConfig {
        nmap_path: "/nonexistent/nmap".to_owned(),
        ..ScanConfig::default()
    };
    let (h, cookie) = setup(pool, missing).await;
    let device = device_at(&h, NAS, "192.168.1.11").await;
    let id = start(&h, &cookie, device, "quick").await.body["id"]
        .as_i64()
        .unwrap();
    let done = wait_for(&h, &cookie, id, "failed").await;
    assert!(
        done["error"]
            .as_str()
            .unwrap()
            .contains("nmap was not found"),
        "{done}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn scans_beyond_the_concurrency_limit_wait_their_turn(pool: PgPool) {
    let nmap = FakeNmap::sleeping();
    let config = ScanConfig {
        concurrency: 1,
        ..nmap.config()
    };
    let (h, cookie) = setup(pool, config).await;
    let first = device_at(&h, PRINTER, "192.168.1.10").await;
    let second = device_at(&h, NAS, "192.168.1.11").await;

    let a = start(&h, &cookie, first, "quick").await.body["id"]
        .as_i64()
        .unwrap();
    wait_for(&h, &cookie, a, "running").await;
    let b = start(&h, &cookie, second, "quick").await.body["id"]
        .as_i64()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(get_scan(&h, &cookie, b).await["status"], "queued");

    // A queued scan can be cancelled before it ever starts.
    let cancel_b = send(
        &h.app,
        Method::POST,
        &format!("/api/scans/{b}/cancel"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(cancel_b.body["status"], "cancelled");
    let c = start(&h, &cookie, second, "quick").await.body["id"]
        .as_i64()
        .unwrap();

    send(
        &h.app,
        Method::POST,
        &format!("/api/scans/{a}/cancel"),
        Some(&cookie),
        None,
    )
    .await;
    wait_for(&h, &cookie, c, "running").await;
    assert_eq!(
        get_scan(&h, &cookie, b).await["started_at"],
        Value::Null,
        "b never ran"
    );
    send(
        &h.app,
        Method::POST,
        &format!("/api/scans/{c}/cancel"),
        Some(&cookie),
        None,
    )
    .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn scans_cut_off_by_a_restart_are_marked_failed(pool: PgPool) {
    let h = harness(pool).await;
    let device = device_at(&h, PRINTER, "192.168.1.10").await;
    // One finished scan (left alone) and one cut off while running.
    sqlx::query(
        "INSERT INTO scans (device_id, target_ip, profile, status, requested_by, finished_at) \
         VALUES ($1, '192.168.1.10', 'full', 'completed', 'admin', now())",
    )
    .bind(device)
    .execute(&h.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO scans (device_id, target_ip, profile, status, requested_by) \
         VALUES ($1, '192.168.1.10', 'quick', 'running', 'admin')",
    )
    .bind(device)
    .execute(&h.pool)
    .await
    .unwrap();

    assert_eq!(store::fail_interrupted(&h.pool).await.unwrap(), 1);
    let statuses: Vec<String> = sqlx::query_scalar("SELECT status FROM scans ORDER BY id")
        .fetch_all(&h.pool)
        .await
        .unwrap();
    assert_eq!(statuses, ["completed", "failed"]);
    assert_eq!(scan_events(&h).await[0].1["outcome"], "failed");
}
