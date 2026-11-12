//! Comparing scans: the diff endpoint and the port events recorded after
//! each completed scan. A stand-in nmap replays whatever XML the test put in
//! place for the next run.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use argowei_api::scans::ScanConfig;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

/// A stand-in nmap that prints `next.xml`.
struct Replay {
    dir: PathBuf,
}

impl Replay {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "argowei-replay-nmap-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("nmap");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ncat '{}/next.xml'\n", dir.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir }
    }

    fn config(&self) -> ScanConfig {
        ScanConfig {
            nmap_path: self.dir.join("nmap").to_str().unwrap().to_owned(),
            ..ScanConfig::default()
        }
    }

    /// Sets what the next scan finds: `services` is the coverage nmap
    /// reports, `ports` are `(port, state, service, product, version)`.
    fn next(&self, services: &str, ports: &[(u16, &str, &str, &str, &str)]) {
        let ports: String = ports
            .iter()
            .map(|(port, state, service, product, version)| {
                let attr = |name: &str, value: &str| {
                    if value.is_empty() {
                        String::new()
                    } else {
                        format!(" {name}=\"{value}\"")
                    }
                };
                format!(
                    "<port protocol=\"tcp\" portid=\"{port}\"><state state=\"{state}\"/>\
                     <service{}{}{}/></port>",
                    attr("name", service),
                    attr("product", product),
                    attr("version", version),
                )
            })
            .collect();
        let xml = format!(
            "<?xml version=\"1.0\"?><nmaprun scanner=\"nmap\" version=\"7.993\">\
             <scaninfo type=\"connect\" protocol=\"tcp\" services=\"{services}\"/>\
             <host><status state=\"up\"/><address addr=\"192.168.1.10\" addrtype=\"ipv4\"/>\
             <ports>{ports}</ports></host>\
             <runstats><finished elapsed=\"0.5\" exit=\"success\"/></runstats></nmaprun>"
        );
        std::fs::write(self.dir.join("next.xml"), xml).unwrap();
    }
}

impl Drop for Replay {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn setup(pool: PgPool, replay: &Replay) -> (Harness, String, i32) {
    let h = harness_with_scans(pool, replay.config()).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;
    scan(&h, &[host(10, "aa:bb:cc:00:00:01")], t0()).await;
    let device = sqlx::query_scalar("SELECT id FROM devices")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    (h, cookie, device)
}

/// Runs one scan to completion and returns its id.
async fn completed_scan(h: &Harness, cookie: &str, device: i32, profile: &str) -> i64 {
    let reply = send(
        &h.app,
        Method::POST,
        &format!("/api/devices/{device}/scans"),
        Some(cookie),
        Some(json!({ "profile": profile })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.body);
    let id = reply.body["id"].as_i64().unwrap();
    let started = Instant::now();
    loop {
        let scan = send(
            &h.app,
            Method::GET,
            &format!("/api/scans/{id}"),
            Some(cookie),
            None,
        )
        .await;
        match scan.body["status"].as_str().unwrap() {
            "completed" => return id,
            "queued" | "running" => {}
            other => panic!("scan {id} ended {other}: {}", scan.body),
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "scan {id} never finished"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn port_events(h: &Harness) -> Vec<(String, String, Value)> {
    sqlx::query_as(
        "SELECT type, severity, payload FROM events \
         WHERE type IN ('port.opened', 'port.closed', 'service.changed') ORDER BY id",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap()
}

async fn diff(h: &Harness, cookie: &str, query: &str) -> Reply {
    send(
        &h.app,
        Method::GET,
        &format!("/api/scans/{query}"),
        Some(cookie),
        None,
    )
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn changes_since_the_previous_scan_become_events(pool: PgPool) {
    let replay = Replay::new();
    let (h, cookie, device) = setup(pool, &replay).await;

    replay.next(
        "1-1000",
        &[
            (22, "open", "ssh", "OpenSSH", "9.6"),
            (631, "open", "ipp", "CUPS", "2.4"),
        ],
    );
    let first = completed_scan(&h, &cookie, device, "service").await;
    assert!(
        port_events(&h).await.is_empty(),
        "the first scan has nothing to compare with"
    );

    replay.next(
        "1-1000",
        &[
            (22, "open", "ssh", "OpenSSH", "9.7"),
            (80, "open", "http", "nginx", "1.27"),
            (631, "closed", "", "", ""),
        ],
    );
    let second = completed_scan(&h, &cookie, device, "service").await;

    let events = port_events(&h).await;
    let summary: Vec<(&str, &str, i64)> = events
        .iter()
        .map(|(t, s, p)| (t.as_str(), s.as_str(), p["port"].as_i64().unwrap()))
        .collect();
    assert_eq!(
        summary,
        [
            ("port.opened", "warning", 80),
            ("port.closed", "info", 631),
            ("service.changed", "info", 22)
        ]
    );
    let opened = &events[0].2;
    assert_eq!(opened["scan_id"], second);
    assert_eq!(opened["previous_scan_id"], first);
    assert_eq!(opened["service"]["product"], "nginx");
    assert_eq!(events[2].2["before"]["version"], "9.6");
    assert_eq!(events[2].2["after"]["version"], "9.7");

    // The endpoint shows the same, and defaults to the previous scan.
    let reply = diff(&h, &cookie, &format!("{second}/diff")).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["older"]["id"], first);
    assert_eq!(reply.body["newer"]["id"], second);
    let d = &reply.body["diff"];
    assert_eq!(d["opened"][0]["port"], 80);
    assert_eq!(d["closed"][0]["port"], 631);
    assert_eq!(d["changed"][0]["port"], 22);
    assert_eq!(d["unchanged"], 0);
    assert_eq!(d["profile_mismatch"], false);
    assert!(d["address_changed"].is_null());

    // Either order gives the same direction.
    let reversed = diff(&h, &cookie, &format!("{first}/diff?against={second}")).await;
    assert_eq!(reversed.body["diff"], reply.body["diff"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn scans_of_different_profiles_are_compared_only_where_both_looked(pool: PgPool) {
    let replay = Replay::new();
    let (h, cookie, device) = setup(pool, &replay).await;

    // A quick scan looked at 22 and 80; the full scan at everything.
    replay.next("22,80", &[(22, "open", "ssh", "", "")]);
    let quick = completed_scan(&h, &cookie, device, "quick").await;
    replay.next(
        "1-65535",
        &[
            (22, "open", "ssh", "", ""),
            (80, "open", "http", "", ""),
            (8443, "open", "https-alt", "", ""),
        ],
    );
    let full = completed_scan(&h, &cookie, device, "full").await;

    assert!(
        port_events(&h).await.is_empty(),
        "events only compare scans of the same profile"
    );

    let reply = diff(&h, &cookie, &format!("{full}/diff?against={quick}")).await;
    let d = &reply.body["diff"];
    assert_eq!(d["profile_mismatch"], true);
    assert_eq!(d["opened"].as_array().unwrap().len(), 1);
    assert_eq!(d["opened"][0]["port"], 80, "80 was covered by both");
    assert_eq!(
        d["not_comparable"][0]["port"], 8443,
        "8443 was never looked at before"
    );
    assert_eq!(d["unchanged"], 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_comparable_scans_can_be_diffed(pool: PgPool) {
    let replay = Replay::new();
    let (h, cookie, device) = setup(pool, &replay).await;

    replay.next("1-100", &[]);
    let only = completed_scan(&h, &cookie, device, "quick").await;
    let reply = diff(&h, &cookie, &format!("{only}/diff")).await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        reply.body["error"],
        "there is no earlier completed scan of this device to compare with"
    );

    // A scan of another device.
    scan(&h, &[host(11, "aa:bb:cc:00:00:02")], t0() + minutes(1)).await;
    let other_device: i32 =
        sqlx::query_scalar("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:00:00:02'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    let other = completed_scan(&h, &cookie, other_device, "quick").await;
    let reply = diff(&h, &cookie, &format!("{only}/diff?against={other}")).await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        reply.body["error"],
        "only scans of the same device can be compared"
    );

    // A scan that did not complete.
    sqlx::query(
        "INSERT INTO scans (device_id, target_ip, profile, status, requested_by, finished_at, error) \
         VALUES ($1, '192.168.1.10', 'quick', 'failed', 'admin', now(), 'boom')",
    )
    .bind(device)
    .execute(&h.pool)
    .await
    .unwrap();
    let failed: i64 = sqlx::query_scalar("SELECT max(id) FROM scans")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let reply = diff(&h, &cookie, &format!("{only}/diff?against={failed}")).await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reply.body["error"], "only completed scans can be compared");

    assert_eq!(
        diff(&h, &cookie, "9999/diff").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        diff(&h, &cookie, &format!("{only}/diff?against=9999"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}
