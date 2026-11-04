//! Persistence and scheduling of ARP discovery, driven by a fake scanner so
//! no root, raw socket or network is needed. Needs Postgres like the other
//! integration tests (`DATABASE_URL`).

mod common;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use argowei_api::discovery::{
    record_scan, run_scan, DiscoveryError, InterfaceLocks, ObservedHost, ScanError, ScanOutcome,
    ScanSummary, Scanner,
};
use argowei_api::presence::PresencePolicy;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use common::{count, host, minutes, t0, POLICY};
use sqlx::PgPool;

const MAC_A: &str = "aa:bb:cc:00:00:01";
const MAC_B: &str = "aa:bb:cc:00:00:02";

async fn rec(db: &PgPool, hosts: &[ObservedHost], at: DateTime<Utc>) -> sqlx::Result<ScanSummary> {
    record_scan(db, "eth0", hosts, at, &POLICY).await
}

async fn is_online(db: &PgPool, mac: &str) -> bool {
    sqlx::query_scalar("SELECT is_online FROM devices WHERE mac_address = $1")
        .bind(mac)
        .fetch_one(db)
        .await
        .unwrap()
}

/// Event types for a device, oldest first.
async fn event_types(db: &PgPool, mac: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT e.type FROM events e JOIN devices d ON d.id = e.device_id \
         WHERE d.mac_address = $1 ORDER BY e.id",
    )
    .bind(mac)
    .fetch_all(db)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_scan_creates_devices_and_addresses(db: PgPool) {
    let hosts = [host(10, MAC_A), host(11, MAC_B)];

    let summary = rec(&db, &hosts, t0()).await.unwrap();

    assert_eq!(
        summary,
        ScanSummary {
            hosts_seen: 2,
            new_devices: 2,
            new_addresses: 2,
            ..ScanSummary::default()
        }
    );
    assert_eq!(count(&db, "devices").await, 2);
    assert_eq!(count(&db, "device_addresses").await, 2);

    let (name, online, first_seen): (String, bool, DateTime<Utc>) =
        sqlx::query_as("SELECT name, is_online, first_seen FROM devices WHERE mac_address = $1")
            .bind(MAC_A)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        name, MAC_A,
        "unnamed devices are labelled by MAC until edited"
    );
    assert!(online);
    assert_eq!(first_seen, t0());
}

#[sqlx::test(migrations = "../../migrations")]
async fn rescanning_updates_last_seen_without_duplicates(db: PgPool) {
    let hosts = [host(10, MAC_A)];
    rec(&db, &hosts, t0()).await.unwrap();

    let later = t0() + ChronoDuration::minutes(5);
    let summary = rec(&db, &hosts, later).await.unwrap();

    assert_eq!(summary.new_devices, 0);
    assert_eq!(summary.new_addresses, 0);
    assert_eq!(count(&db, "devices").await, 1);
    assert_eq!(count(&db, "device_addresses").await, 1);

    let (first, last): (DateTime<Utc>, DateTime<Utc>) =
        sqlx::query_as("SELECT first_seen, last_seen FROM devices")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!((first, last), (t0(), later));

    let (first, last): (DateTime<Utc>, DateTime<Utc>) =
        sqlx::query_as("SELECT first_seen, last_seen FROM device_addresses")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!((first, last), (t0(), later));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_older_scan_never_moves_last_seen_backwards(db: PgPool) {
    let hosts = [host(10, MAC_A)];
    let later = t0() + ChronoDuration::minutes(5);
    rec(&db, &hosts, later).await.unwrap();

    rec(&db, &hosts, t0()).await.unwrap();

    let last: DateTime<Utc> = sqlx::query_scalar("SELECT last_seen FROM devices")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(last, later);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_that_changes_ip_keeps_both_addresses(db: PgPool) {
    rec(&db, &[host(10, MAC_A)], t0()).await.unwrap();

    let later = t0() + ChronoDuration::hours(1);
    let summary = rec(&db, &[host(50, MAC_A)], later).await.unwrap();

    assert_eq!(summary.new_devices, 0);
    assert_eq!(summary.new_addresses, 1);
    assert_eq!(summary.reassigned_addresses, 0);
    assert_eq!(count(&db, "devices").await, 1);
    assert_eq!(count(&db, "device_addresses").await, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_ip_moving_between_devices_preserves_history(db: PgPool) {
    rec(&db, &[host(10, MAC_A)], t0()).await.unwrap();

    let later = t0() + ChronoDuration::hours(2);
    let summary = rec(&db, &[host(10, MAC_B)], later).await.unwrap();

    assert_eq!(summary.new_devices, 1);
    assert_eq!(summary.new_addresses, 1);
    assert_eq!(summary.reassigned_addresses, 1);

    // Both devices keep a row for the IP; the newest last_seen is the holder.
    let rows: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT d.mac_address, a.last_seen FROM device_addresses a \
         JOIN devices d ON d.id = a.device_id \
         WHERE a.ip_address = '192.168.1.10' ORDER BY a.last_seen DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![(MAC_B.to_owned(), later), (MAC_A.to_owned(), t0())]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn silent_devices_are_left_untouched(db: PgPool) {
    rec(&db, &[host(10, MAC_A), host(11, MAC_B)], t0())
        .await
        .unwrap();

    let later = t0() + ChronoDuration::minutes(5);
    rec(&db, &[host(10, MAC_A)], later).await.unwrap();

    let (online, last): (bool, DateTime<Utc>) =
        sqlx::query_as("SELECT is_online, last_seen FROM devices WHERE mac_address = $1")
            .bind(MAC_B)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(online, "one missed reply must not flip a device offline");
    assert_eq!(last, t0());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_scan_changes_nothing(db: PgPool) {
    rec(&db, &[host(10, MAC_A)], t0()).await.unwrap();

    let summary = rec(&db, &[], t0() + ChronoDuration::minutes(5))
        .await
        .unwrap();

    assert_eq!(summary, ScanSummary::default());
    assert_eq!(count(&db, "devices").await, 1);
}

// --- run_scan: scanner integration, failure and overlap handling ---------

struct FakeScanner {
    results: Mutex<VecDeque<Result<Vec<ObservedHost>, String>>>,
}

impl FakeScanner {
    fn scripted(results: Vec<Result<Vec<ObservedHost>, String>>) -> Arc<dyn Scanner> {
        Arc::new(Self {
            results: Mutex::new(results.into()),
        })
    }
}

impl Scanner for FakeScanner {
    fn scan(&self, _interface: &str, _timeout: Duration) -> Result<Vec<ObservedHost>, ScanError> {
        self.results
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra scan")
            .map_err(Into::into)
    }
}

const TIMEOUT: Duration = Duration::from_secs(3);

#[sqlx::test(migrations = "../../migrations")]
async fn run_scan_stores_what_the_scanner_found(db: PgPool) {
    let scanner = FakeScanner::scripted(vec![Ok(vec![host(10, MAC_A)])]);

    let outcome = run_scan(
        &db,
        &scanner,
        &InterfaceLocks::default(),
        "eth0",
        TIMEOUT,
        &POLICY,
    )
    .await
    .unwrap();

    assert!(matches!(outcome, ScanOutcome::Completed(s) if s.new_devices == 1));
    assert_eq!(count(&db, "devices").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_scan_reports_the_error_and_stores_nothing(db: PgPool) {
    let scanner = FakeScanner::scripted(vec![Err("not permitted; grant CAP_NET_RAW".into())]);

    let error = run_scan(
        &db,
        &scanner,
        &InterfaceLocks::default(),
        "eth0",
        TIMEOUT,
        &POLICY,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, DiscoveryError::Scan(_)));
    assert!(error.to_string().contains("CAP_NET_RAW"));
    assert_eq!(count(&db, "devices").await, 0);
}

/// Blocks inside `scan` until released, to hold an interface lock open.
struct BlockingScanner {
    started: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Scanner for BlockingScanner {
    fn scan(&self, _interface: &str, _timeout: Duration) -> Result<Vec<ObservedHost>, ScanError> {
        self.started.lock().unwrap().send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        Ok(vec![host(10, MAC_A)])
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn scans_of_the_same_interface_never_overlap(db: PgPool) {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let slow: Arc<dyn Scanner> = Arc::new(BlockingScanner {
        started: Mutex::new(started_tx),
        release: Mutex::new(release_rx),
    });
    let locks = InterfaceLocks::default();

    let first = {
        let (db, locks) = (db.clone(), locks.clone());
        tokio::spawn(async move { run_scan(&db, &slow, &locks, "eth0", TIMEOUT, &POLICY).await })
    };
    tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("first scan should have started");

    // Same interface while the first is running: skipped, scanner untouched
    // (the fake would panic on an unexpected scan).
    let unused = FakeScanner::scripted(vec![]);
    let second = run_scan(&db, &unused, &locks, "eth0", TIMEOUT, &POLICY)
        .await
        .unwrap();
    assert_eq!(second, ScanOutcome::Skipped);

    // A different interface is independent.
    let other = FakeScanner::scripted(vec![Ok(vec![ObservedHost {
        ip: Ipv4Addr::new(10, 0, 0, 5),
        mac: MAC_B.to_owned(),
    }])]);
    let third = run_scan(&db, &other, &locks, "wlan0", TIMEOUT, &POLICY)
        .await
        .unwrap();
    assert!(matches!(third, ScanOutcome::Completed(_)));

    release_tx.send(()).unwrap();
    let first = first.await.unwrap().unwrap();
    assert!(matches!(first, ScanOutcome::Completed(_)));

    // The lock is released afterwards.
    let again = FakeScanner::scripted(vec![Ok(vec![])]);
    let fourth = run_scan(&db, &again, &locks, "eth0", TIMEOUT, &POLICY)
        .await
        .unwrap();
    assert!(matches!(fourth, ScanOutcome::Completed(_)));
}

// --- presence: offline detection, events and recorded evidence -----------

/// Scans at `t0`, then empty scans every 5 minutes up to `until_minutes`.
async fn seen_once_then_silent(db: &PgPool, until_minutes: i64) {
    rec(db, &[host(10, MAC_A)], t0()).await.unwrap();
    let mut at = 5;
    while at <= until_minutes {
        rec(db, &[], t0() + minutes(at)).await.unwrap();
        at += 5;
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_is_discovered_exactly_once(db: PgPool) {
    let hosts = [host(10, MAC_A)];
    rec(&db, &hosts, t0()).await.unwrap();
    rec(&db, &hosts, t0() + minutes(5)).await.unwrap();

    assert_eq!(event_types(&db, MAC_A).await, vec!["device.discovered"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_a_few_scans_does_not_change_state(db: PgPool) {
    // 10 minutes: two misses, and under the 15 minute requirement.
    seen_once_then_silent(&db, 10).await;

    assert!(is_online(&db, MAC_A).await);
    assert_eq!(event_types(&db, MAC_A).await, vec!["device.discovered"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn enough_missed_scans_and_time_mark_the_device_offline_once(db: PgPool) {
    // Third miss lands exactly on the 15 minute mark.
    seen_once_then_silent(&db, 15).await;
    assert!(!is_online(&db, MAC_A).await);

    // Further silent scans must not repeat the event.
    rec(&db, &[], t0() + minutes(20)).await.unwrap();
    rec(&db, &[], t0() + minutes(25)).await.unwrap();

    assert_eq!(
        event_types(&db, MAC_A).await,
        vec!["device.discovered", "device.offline"]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_offline_event_carries_its_evidence(db: PgPool) {
    seen_once_then_silent(&db, 15).await;

    let payload: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM events WHERE type = 'device.offline'")
            .fetch_one(&db)
            .await
            .unwrap();

    assert_eq!(payload["interface"], "eth0");
    assert_eq!(payload["missed_scans"], 3);
    assert_eq!(payload["silent_for_secs"], 15 * 60);
    assert_eq!(payload["policy"]["offline_after_missed_scans"], 3);
    assert_eq!(payload["policy"]["offline_after_secs"], 15 * 60);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_long_scanning_gap_does_not_mark_offline_after_a_single_miss(db: PgPool) {
    // The API was down for two hours; the first scan afterwards finds nothing.
    rec(&db, &[host(10, MAC_A)], t0()).await.unwrap();
    let summary = rec(&db, &[], t0() + minutes(120)).await.unwrap();

    assert_eq!(summary.went_offline, 0);
    assert!(is_online(&db, MAC_A).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn enough_misses_inside_the_grace_time_stay_online(db: PgPool) {
    let slow = PresencePolicy {
        offline_after_missed_scans: 3,
        offline_after: Duration::from_secs(60 * 60),
    };
    record_scan(&db, "eth0", &[host(10, MAC_A)], t0(), &slow)
        .await
        .unwrap();
    for at in [10, 20, 30, 40] {
        record_scan(&db, "eth0", &[], t0() + minutes(at), &slow)
            .await
            .unwrap();
    }
    assert!(is_online(&db, MAC_A).await, "4 misses but only 40 minutes");

    record_scan(&db, "eth0", &[], t0() + minutes(60), &slow)
        .await
        .unwrap();
    assert!(!is_online(&db, MAC_A).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_returning_device_comes_online_exactly_once(db: PgPool) {
    seen_once_then_silent(&db, 15).await;
    let back = [host(10, MAC_A)];

    let summary = rec(&db, &back, t0() + minutes(20)).await.unwrap();
    rec(&db, &back, t0() + minutes(25)).await.unwrap();

    assert_eq!(summary.came_online, 1);
    assert!(is_online(&db, MAC_A).await);
    assert_eq!(
        event_types(&db, MAC_A).await,
        vec!["device.discovered", "device.offline", "device.online"]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn scans_of_other_interfaces_do_not_count_as_misses(db: PgPool) {
    record_scan(&db, "eth0", &[host(10, MAC_A)], t0(), &POLICY)
        .await
        .unwrap();

    // Many empty scans, but on a different interface.
    for at in [5, 10, 15, 20, 25, 30] {
        record_scan(&db, "wlan0", &[], t0() + minutes(at), &POLICY)
            .await
            .unwrap();
    }

    assert!(is_online(&db, MAC_A).await);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_evidence_behind_presence_is_recorded(db: PgPool) {
    rec(&db, &[host(10, MAC_A), host(11, MAC_B)], t0())
        .await
        .unwrap();
    rec(&db, &[host(10, MAC_A)], t0() + minutes(5))
        .await
        .unwrap();
    rec(&db, &[], t0() + minutes(10)).await.unwrap();

    // Every completed scan is kept, including empty ones.
    let scans: Vec<(String, i32)> =
        sqlx::query_as("SELECT interface, hosts_seen FROM discovery_scans ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(
        scans,
        vec![("eth0".into(), 2), ("eth0".into(), 1), ("eth0".into(), 0)]
    );

    // Sightings per device reconstruct its presence timeline; absence is the
    // lack of a sighting for a scan that ran.
    let sightings: Vec<(String, i64)> = sqlx::query_as(
        "SELECT d.mac_address, count(*) FROM device_sightings s \
         JOIN devices d ON d.id = s.device_id GROUP BY d.mac_address ORDER BY 1",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(
        sightings,
        vec![(MAC_A.to_owned(), 2), (MAC_B.to_owned(), 1)]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_scan_leaves_presence_untouched(db: PgPool) {
    rec(&db, &[host(10, MAC_A)], t0()).await.unwrap();

    // run_scan only records after the scanner succeeds, so a failure is not
    // a scan: no scan row, hence no missed scan for anyone.
    let scanner = FakeScanner::scripted(vec![Err("interface down".into())]);
    for _ in 0..5 {
        let _ = run_scan(
            &db,
            &scanner_failing(),
            &InterfaceLocks::default(),
            "eth0",
            TIMEOUT,
            &POLICY,
        )
        .await;
    }
    drop(scanner);

    assert_eq!(count(&db, "discovery_scans").await, 1);
    assert!(is_online(&db, MAC_A).await);
}

fn scanner_failing() -> Arc<dyn Scanner> {
    struct Failing;
    impl Scanner for Failing {
        fn scan(&self, _: &str, _: Duration) -> Result<Vec<ObservedHost>, ScanError> {
            Err("interface down".into())
        }
    }
    Arc::new(Failing)
}
