//! New-device alerts: the baseline that keeps a fresh install quiet, one alert
//! per new device, and the alert life cycle through the API.

mod common;

use std::time::Duration;

use argowei_api::alerts::apply_baseline_window;
use argowei_api::discovery::{record_scan, ObservedHost};
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

/// A real Brother prefix, so the alert can name a manufacturer.
const PRINTER: &str = "00:80:77:aa:bb:01";
const PHONE: &str = "1a:56:ce:aa:bb:02";
const LAPTOP: &str = "3c:22:fb:aa:bb:03";

fn hours(n: i64) -> ChronoDuration {
    ChronoDuration::hours(n)
}

async fn scan_on(h: &Harness, interface: &str, hosts: &[ObservedHost], at: DateTime<Utc>) {
    record_scan(&h.pool, interface, hosts, at, &POLICY)
        .await
        .unwrap();
}

async fn alerts(h: &Harness, cookie: &str, query: &str) -> Value {
    let reply = send(
        &h.app,
        Method::GET,
        &format!("/api/alerts{query}"),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{query}");
    reply.body
}

async fn alert_count(h: &Harness) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM alerts")
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

async fn status(h: &Harness, cookie: &str) -> Value {
    send(
        &h.app,
        Method::GET,
        "/api/alerts/status",
        Some(cookie),
        None,
    )
    .await
    .body
}

/// A network that was scanned once (the baseline) and then gained a printer.
async fn with_one_new_device(pool: PgPool) -> (Harness, String) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(1, LAPTOP)], t0()).await;
    scan(&h, &[host(1, LAPTOP), host(20, PRINTER)], t0() + hours(1)).await;
    (h, cookie)
}

// --- the baseline ---------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_first_scan_learns_the_network_without_alerts(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    scan(
        &h,
        &[host(1, LAPTOP), host(20, PRINTER), host(30, PHONE)],
        t0(),
    )
    .await;

    assert_eq!(alert_count(&h).await, 0);
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(devices, 3, "the devices are still recorded");
    assert_eq!(alerts(&h, &cookie, "").await["items"], json!([]));

    // The discovery event says it was learned silently.
    let baseline_flags: Vec<bool> = sqlx::query_scalar(
        "SELECT (payload->>'baseline')::boolean FROM events WHERE type = 'device.discovered'",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();
    assert_eq!(baseline_flags, [true, true, true]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_new_device_after_the_baseline_raises_exactly_one_alert(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;

    // The same device on later scans must not alert again.
    for n in 2..5 {
        scan(&h, &[host(1, LAPTOP), host(20, PRINTER)], t0() + hours(n)).await;
    }

    assert_eq!(alert_count(&h).await, 1);
    let list = alerts(&h, &cookie, "").await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);

    let alert = &list["items"][0];
    assert_eq!(alert["type"], "device.new");
    assert_eq!(alert["severity"], "warning");
    assert_eq!(alert["status"], "open");
    assert_eq!(alert["device"]["mac_address"], PRINTER);
    assert!(alert["device"]["vendor"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("brother"));
    assert_eq!(alert["payload"]["interface"], "eth0");
    assert_eq!(alert["payload"]["ip"], "192.168.1.20");
    assert_eq!(alert["payload"]["mac"], PRINTER);

    let baseline_flag: bool = sqlx::query_scalar(
        "SELECT (payload->>'baseline')::boolean FROM events \
         WHERE type = 'device.discovered' AND payload->>'ip' = '192.168.1.20'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert!(!baseline_flag);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_summary_counts_new_alerts(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(1, LAPTOP)], t0()).await;

    let summary = record_scan(
        &h.pool,
        "eth0",
        &[host(1, LAPTOP), host(20, PRINTER), host(30, PHONE)],
        t0() + hours(1),
        &POLICY,
    )
    .await
    .unwrap();

    assert_eq!((summary.new_devices, summary.new_alerts), (2, 2));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_alert_suggests_actions_and_disables_those_needing_enforcement(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;

    let list = alerts(&h, &cookie, "").await;
    let actions = list["items"][0]["payload"]["suggested_actions"]
        .as_array()
        .unwrap();

    let offered: Vec<(&str, bool)> = actions
        .iter()
        .map(|a| {
            (
                a["action"].as_str().unwrap(),
                a["available"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        offered,
        [
            ("trust", true),
            ("restrict", true),
            ("block", false),
            ("quarantine", false)
        ]
    );
    assert!(actions[2]["reason"]
        .as_str()
        .unwrap()
        .contains("gateway or router"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_already_known_never_alerts(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(1, LAPTOP)], t0()).await;
    // Present before the printer was ever scanned, e.g. added by hand.
    sqlx::query("INSERT INTO devices (name, mac_address, is_online) VALUES ($1, $1, false)")
        .bind(PRINTER)
        .execute(&h.pool)
        .await
        .unwrap();

    scan(&h, &[host(1, LAPTOP), host(20, PRINTER)], t0() + hours(1)).await;

    assert_eq!(alert_count(&h).await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_database_allows_one_new_device_alert_per_device(pool: PgPool) {
    let (h, _) = with_one_new_device(pool).await;

    let duplicate = sqlx::query(
        "INSERT INTO alerts (type, device_id, created_at) \
         SELECT 'device.new', device_id, now() FROM alerts",
    )
    .execute(&h.pool)
    .await;

    assert!(
        duplicate.is_err(),
        "a second device.new alert for one device must be rejected"
    );
    assert_eq!(alert_count(&h).await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_baseline_window_keeps_learning_silently_for_a_while(pool: PgPool) {
    let (h, _) = admin(pool).await;
    apply_baseline_window(&h.pool, Duration::from_secs(2 * 3600))
        .await
        .unwrap();

    scan(&h, &[host(1, LAPTOP)], t0()).await;
    // 90 minutes in: still inside the 2 h window.
    scan(
        &h,
        &[host(1, LAPTOP), host(20, PRINTER)],
        t0() + ChronoDuration::minutes(90),
    )
    .await;
    assert_eq!(
        alert_count(&h).await,
        0,
        "learned silently inside the window"
    );

    // 3 hours in: the window is over.
    scan(
        &h,
        &[host(1, LAPTOP), host(20, PRINTER), host(30, PHONE)],
        t0() + hours(3),
    )
    .await;
    assert_eq!(
        alert_count(&h).await,
        1,
        "only the phone, which appeared after the window"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_interface_has_its_own_baseline(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan_on(&h, "eth0", &[host(1, LAPTOP)], t0()).await;

    // Weeks later a second network is added. Its first scan is its baseline.
    scan_on(&h, "wlan0", &[host(20, PRINTER)], t0() + hours(24 * 30)).await;
    assert_eq!(alert_count(&h).await, 0);

    // But a new device on it afterwards does alert.
    scan_on(
        &h,
        "wlan0",
        &[host(20, PRINTER), host(30, PHONE)],
        t0() + hours(24 * 30 + 1),
    )
    .await;
    assert_eq!(alert_count(&h).await, 1);
}

// --- status ---------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_status_shows_pending_learning_and_done(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    apply_baseline_window(&h.pool, Duration::from_secs(2 * 3600))
        .await
        .unwrap();

    let pending = status(&h, &cookie).await;
    assert_eq!(pending["baseline"]["state"], "pending");
    assert_eq!(
        (pending["open"].as_i64(), pending["acknowledged"].as_i64()),
        (Some(0), Some(0))
    );

    // A scan that just happened starts the window.
    scan(&h, &[host(1, LAPTOP)], Utc::now()).await;
    let learning = status(&h, &cookie).await;
    assert_eq!(learning["baseline"]["state"], "learning");
    assert_eq!(learning["baseline"]["window_secs"], 7200);
    assert!(learning["baseline"]["ends_at"].is_string());

    // The same scan long ago means the window is over.
    sqlx::query("UPDATE baselines SET started_at = now() - interval '1 day'")
        .execute(&h.pool)
        .await
        .unwrap();
    let done = status(&h, &cookie).await;
    assert_eq!(done["baseline"]["state"], "done");
    assert!(done["baseline"]["ends_at"].is_null());
}

#[sqlx::test(migrations = "../../migrations")]
async fn without_a_window_the_baseline_is_done_after_the_first_scan(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(
        &h,
        &[host(1, LAPTOP)],
        Utc::now() - ChronoDuration::seconds(5),
    )
    .await;

    assert_eq!(status(&h, &cookie).await["baseline"]["state"], "done");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_status_counts_open_and_acknowledged_alerts(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(1, LAPTOP)], t0()).await;
    scan(
        &h,
        &[host(1, LAPTOP), host(20, PRINTER), host(30, PHONE)],
        t0() + hours(1),
    )
    .await;
    let first = alerts(&h, &cookie, "").await["items"][0]["id"]
        .as_i64()
        .unwrap();
    send(
        &h.app,
        Method::POST,
        &format!("/api/alerts/{first}/acknowledge"),
        Some(&cookie),
        None,
    )
    .await;

    let counts = status(&h, &cookie).await;

    assert_eq!(
        (counts["open"].as_i64(), counts["acknowledged"].as_i64()),
        (Some(1), Some(1))
    );
}

// --- life cycle -----------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn alerts_require_a_session(pool: PgPool) {
    let (h, _) = with_one_new_device(pool).await;

    for (method, uri) in [
        (Method::GET, "/api/alerts"),
        (Method::GET, "/api/alerts/status"),
        (Method::POST, "/api/alerts/1/acknowledge"),
        (Method::POST, "/api/alerts/1/resolve"),
    ] {
        assert_eq!(
            send(&h.app, method, uri, None, None).await.status,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_alert_goes_from_open_to_acknowledged_to_resolved(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;
    let id = alerts(&h, &cookie, "").await["items"][0]["id"]
        .as_i64()
        .unwrap();

    let ack = send(
        &h.app,
        Method::POST,
        &format!("/api/alerts/{id}/acknowledge"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(ack.status, StatusCode::OK);
    assert_eq!(ack.body["status"], "acknowledged");
    assert_eq!(ack.body["acknowledged_by"], "admin");
    assert!(ack.body["acknowledged_at"].is_string());

    let resolved = send(
        &h.app,
        Method::POST,
        &format!("/api/alerts/{id}/resolve"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resolved.body["status"], "resolved");
    assert_eq!(resolved.body["resolved_by"], "admin");

    assert_eq!(
        alerts(&h, &cookie, "").await["items"],
        json!([]),
        "resolved alerts leave the default list"
    );
    assert_eq!(
        alerts(&h, &cookie, "?status=resolved").await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_open_alert_can_be_resolved_directly(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;
    let id = alerts(&h, &cookie, "").await["items"][0]["id"]
        .as_i64()
        .unwrap();

    let resolved = send(
        &h.app,
        Method::POST,
        &format!("/api/alerts/{id}/resolve"),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(resolved.body["status"], "resolved");
}

#[sqlx::test(migrations = "../../migrations")]
async fn repeating_a_step_is_harmless_but_going_back_is_refused(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;
    let id = alerts(&h, &cookie, "").await["items"][0]["id"]
        .as_i64()
        .unwrap();
    let ack = format!("/api/alerts/{id}/acknowledge");
    let resolve = format!("/api/alerts/{id}/resolve");

    send(&h.app, Method::POST, &ack, Some(&cookie), None).await;
    let again = send(&h.app, Method::POST, &ack, Some(&cookie), None).await;
    assert_eq!(
        (again.status, again.body["status"].as_str()),
        (StatusCode::OK, Some("acknowledged"))
    );

    send(&h.app, Method::POST, &resolve, Some(&cookie), None).await;
    let resolve_again = send(&h.app, Method::POST, &resolve, Some(&cookie), None).await;
    assert_eq!(resolve_again.status, StatusCode::OK);

    let back = send(&h.app, Method::POST, &ack, Some(&cookie), None).await;
    assert_eq!(back.status, StatusCode::CONFLICT);
    assert_eq!(
        alerts(&h, &cookie, "?status=resolved").await["items"][0]["status"],
        "resolved"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn unknown_alerts_are_not_found(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    for step in ["acknowledge", "resolve"] {
        let reply = send(
            &h.app,
            Method::POST,
            &format!("/api/alerts/9999/{step}"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{step}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_real_step_is_audited_and_a_repeat_is_not(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;
    let id = alerts(&h, &cookie, "").await["items"][0]["id"]
        .as_i64()
        .unwrap();
    let ack = format!("/api/alerts/{id}/acknowledge");
    send(&h.app, Method::POST, &ack, Some(&cookie), None).await;
    send(&h.app, Method::POST, &ack, Some(&cookie), None).await;
    send(
        &h.app,
        Method::POST,
        &format!("/api/alerts/{id}/resolve"),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(audit_count(&h, "alert.acknowledge").await, 1);
    assert_eq!(audit_count(&h, "alert.resolve").await, 1);

    let payload: Value =
        sqlx::query_scalar("SELECT payload FROM audit_log WHERE action = 'alert.resolve'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(payload["from"], "acknowledged");
    assert_eq!(payload["type"], "device.new");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_list_filters_by_status_and_pages_with_a_cursor(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(1, LAPTOP)], t0()).await;
    scan(
        &h,
        &[host(1, LAPTOP), host(20, PRINTER), host(30, PHONE)],
        t0() + hours(1),
    )
    .await;

    let page1 = alerts(&h, &cookie, "?limit=1").await;
    assert_eq!(page1["items"].as_array().unwrap().len(), 1);
    let cursor = page1["next_before"].as_i64().unwrap();
    let page2 = alerts(&h, &cookie, &format!("?limit=1&before={cursor}")).await;
    assert_eq!(page2["items"].as_array().unwrap().len(), 1);
    assert!(page2["next_before"].is_null());
    assert_ne!(page1["items"][0]["id"], page2["items"][0]["id"]);

    assert_eq!(
        alerts(&h, &cookie, "?status=open").await["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        alerts(&h, &cookie, "?status=all").await["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        alerts(&h, &cookie, "?status=resolved").await["items"],
        json!([])
    );

    let bad = send(
        &h.app,
        Method::GET,
        "/api/alerts?status=bogus",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_alert_shows_the_devices_current_name(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;
    let device_id: i32 = sqlx::query_scalar("SELECT id FROM devices WHERE mac_address = $1")
        .bind(PRINTER)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{device_id}"),
        Some(&cookie),
        Some(json!({ "label": "Office printer" })),
    )
    .await;

    let list = alerts(&h, &cookie, "").await;

    assert_eq!(list["items"][0]["device"]["display_name"], "Office printer");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_alert_outlives_its_device(pool: PgPool) {
    let (h, cookie) = with_one_new_device(pool).await;

    sqlx::query("DELETE FROM devices WHERE mac_address = $1")
        .bind(PRINTER)
        .execute(&h.pool)
        .await
        .unwrap();

    let list = alerts(&h, &cookie, "").await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert!(list["items"][0]["device"].is_null());
    assert_eq!(
        list["items"][0]["payload"]["mac"], PRINTER,
        "what was observed is kept"
    );
}
