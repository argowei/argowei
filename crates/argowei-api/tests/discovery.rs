//! Persistence and scheduling of ARP discovery, driven by a fake scanner so
//! no root, raw socket or network is needed. Needs Postgres like the other
//! integration tests (`DATABASE_URL`).

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use argowei_api::discovery::{
    record_scan, run_scan, DiscoveryError, InterfaceLocks, ObservedHost, ScanError, ScanOutcome,
    ScanSummary, Scanner,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use sqlx::PgPool;

const MAC_A: &str = "aa:bb:cc:00:00:01";
const MAC_B: &str = "aa:bb:cc:00:00:02";

fn host(ip: [u8; 4], mac: &str) -> ObservedHost {
    ObservedHost {
        ip: Ipv4Addr::from(ip),
        mac: mac.to_owned(),
    }
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
}

async fn count(db: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(db)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_scan_creates_devices_and_addresses(db: PgPool) {
    let hosts = [
        host([192, 168, 1, 10], MAC_A),
        host([192, 168, 1, 11], MAC_B),
    ];

    let summary = record_scan(&db, &hosts, t0()).await.unwrap();

    assert_eq!(
        summary,
        ScanSummary {
            hosts_seen: 2,
            new_devices: 2,
            new_addresses: 2,
            reassigned_addresses: 0
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
    let hosts = [host([192, 168, 1, 10], MAC_A)];
    record_scan(&db, &hosts, t0()).await.unwrap();

    let later = t0() + ChronoDuration::minutes(5);
    let summary = record_scan(&db, &hosts, later).await.unwrap();

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
    let hosts = [host([192, 168, 1, 10], MAC_A)];
    let later = t0() + ChronoDuration::minutes(5);
    record_scan(&db, &hosts, later).await.unwrap();

    record_scan(&db, &hosts, t0()).await.unwrap();

    let last: DateTime<Utc> = sqlx::query_scalar("SELECT last_seen FROM devices")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(last, later);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_that_changes_ip_keeps_both_addresses(db: PgPool) {
    record_scan(&db, &[host([192, 168, 1, 10], MAC_A)], t0())
        .await
        .unwrap();

    let later = t0() + ChronoDuration::hours(1);
    let summary = record_scan(&db, &[host([192, 168, 1, 50], MAC_A)], later)
        .await
        .unwrap();

    assert_eq!(summary.new_devices, 0);
    assert_eq!(summary.new_addresses, 1);
    assert_eq!(summary.reassigned_addresses, 0);
    assert_eq!(count(&db, "devices").await, 1);
    assert_eq!(count(&db, "device_addresses").await, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_ip_moving_between_devices_preserves_history(db: PgPool) {
    record_scan(&db, &[host([192, 168, 1, 10], MAC_A)], t0())
        .await
        .unwrap();

    let later = t0() + ChronoDuration::hours(2);
    let summary = record_scan(&db, &[host([192, 168, 1, 10], MAC_B)], later)
        .await
        .unwrap();

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
    record_scan(
        &db,
        &[
            host([192, 168, 1, 10], MAC_A),
            host([192, 168, 1, 11], MAC_B),
        ],
        t0(),
    )
    .await
    .unwrap();

    let later = t0() + ChronoDuration::minutes(5);
    record_scan(&db, &[host([192, 168, 1, 10], MAC_A)], later)
        .await
        .unwrap();

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
    record_scan(&db, &[host([192, 168, 1, 10], MAC_A)], t0())
        .await
        .unwrap();

    let summary = record_scan(&db, &[], t0() + ChronoDuration::minutes(5))
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
    let scanner = FakeScanner::scripted(vec![Ok(vec![host([192, 168, 1, 10], MAC_A)])]);

    let outcome = run_scan(&db, &scanner, &InterfaceLocks::default(), "eth0", TIMEOUT)
        .await
        .unwrap();

    assert!(matches!(outcome, ScanOutcome::Completed(s) if s.new_devices == 1));
    assert_eq!(count(&db, "devices").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_scan_reports_the_error_and_stores_nothing(db: PgPool) {
    let scanner = FakeScanner::scripted(vec![Err("not permitted; grant CAP_NET_RAW".into())]);

    let error = run_scan(&db, &scanner, &InterfaceLocks::default(), "eth0", TIMEOUT)
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
        Ok(vec![host([192, 168, 1, 10], MAC_A)])
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
        tokio::spawn(async move { run_scan(&db, &slow, &locks, "eth0", TIMEOUT).await })
    };
    tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("first scan should have started");

    // Same interface while the first is running: skipped, scanner untouched
    // (the fake would panic on an unexpected scan).
    let unused = FakeScanner::scripted(vec![]);
    let second = run_scan(&db, &unused, &locks, "eth0", TIMEOUT)
        .await
        .unwrap();
    assert_eq!(second, ScanOutcome::Skipped);

    // A different interface is independent.
    let other = FakeScanner::scripted(vec![Ok(vec![host([10, 0, 0, 5], MAC_B)])]);
    let third = run_scan(&db, &other, &locks, "wlan0", TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(third, ScanOutcome::Completed(_)));

    release_tx.send(()).unwrap();
    let first = first.await.unwrap().unwrap();
    assert!(matches!(first, ScanOutcome::Completed(_)));

    // The lock is released afterwards.
    let again = FakeScanner::scripted(vec![Ok(vec![])]);
    let fourth = run_scan(&db, &again, &locks, "eth0", TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(fourth, ScanOutcome::Completed(_)));
}
