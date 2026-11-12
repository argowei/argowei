//! The event timeline API: filters, cursor paging, polling for news, and that
//! paging stays complete while other transactions are still writing events.

mod common;

use argowei_api::events::record;
use argowei_core::events::{DeviceDiscovered, Event};
use axum::http::{Method, StatusCode};
use chrono::Utc;
use common::*;
use serde_json::Value;
use sqlx::PgPool;

const PHONE: &str = "aa:bb:cc:00:00:01";
const PRINTER: &str = "aa:bb:cc:00:00:02";

async fn events(h: &Harness, cookie: &str, query: &str) -> Value {
    let reply = send(
        &h.app,
        Method::GET,
        &format!("/api/events{query}"),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{query}: {}", reply.body);
    reply.body
}

fn types_of(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap().to_owned())
        .collect()
}

fn ids_of(page: &Value) -> Vec<i64> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_i64().unwrap())
        .collect()
}

/// A standalone event, as another service would write it.
fn discovered(scan_id: i64) -> Event {
    Event::DeviceDiscovered(DeviceDiscovered {
        interface: "eth0".into(),
        scan_id,
        ip: "192.168.1.9".into(),
        baseline: false,
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_timeline_needs_a_session(pool: PgPool) {
    let h = harness(pool).await;
    let reply = send(&h.app, Method::GET, "/api/events", None, None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_events_appear_newest_first_with_their_device(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PHONE)], t0()).await;
    scan(&h, &[host(11, PRINTER)], t0() + minutes(5)).await;

    let page = events(&h, &cookie, "").await;
    assert_eq!(types_of(&page), ["device.discovered", "device.discovered"]);
    let newest = &page["items"][0];
    assert_eq!(newest["device"]["mac_address"], PRINTER);
    assert_eq!(newest["device"]["display_name"], PRINTER);
    assert_eq!(newest["severity"], "info");
    assert_eq!(newest["schema_version"], 1);
    assert_eq!(newest["payload"]["ip"], "192.168.1.11");
    // Only the first scan is the baseline (no window configured).
    assert_eq!(newest["payload"]["baseline"], false);
    assert_eq!(page["items"][1]["payload"]["baseline"], true);
    assert!(newest["cursor"].is_string());
    assert!(page["next_before"].is_null());
    assert_eq!(page["truncated"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn filters_narrow_the_timeline(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PHONE), host(11, PRINTER)], t0()).await;
    // The phone stays silent long enough to go offline.
    for n in 1..=4 {
        scan(&h, &[host(11, PRINTER)], t0() + minutes(10 * n)).await;
    }

    let phone: i64 = sqlx::query_scalar::<_, i32>("SELECT id FROM devices WHERE mac_address = $1")
        .bind(PHONE)
        .fetch_one(&h.pool)
        .await
        .map(i64::from)
        .unwrap();

    let offline = events(&h, &cookie, "?type=device.offline").await;
    assert_eq!(types_of(&offline), ["device.offline"]);
    assert_eq!(offline["items"][0]["device"]["id"], phone);

    let mine = events(&h, &cookie, &format!("?device={phone}")).await;
    assert_eq!(types_of(&mine), ["device.offline", "device.discovered"]);

    assert!(types_of(&events(&h, &cookie, "?severity=warning").await).is_empty());

    let late = events(&h, &cookie, "?from=2026-01-01T12:30:00Z").await;
    assert_eq!(types_of(&late), ["device.offline"]);
    let early = events(&h, &cookie, "?to=2026-01-01T12:00:00Z").await;
    assert_eq!(types_of(&early), ["device.discovered", "device.discovered"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn pages_follow_each_other_without_gaps_or_repeats(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    for n in 0..7 {
        record(&h.pool, Utc::now(), None, &discovered(n))
            .await
            .unwrap();
    }

    let mut seen = Vec::new();
    let mut query = "?limit=3".to_owned();
    loop {
        let page = events(&h, &cookie, &query).await;
        seen.extend(ids_of(&page));
        match page["next_before"].as_str() {
            Some(cursor) => query = format!("?limit=3&before={cursor}"),
            None => break,
        }
    }
    let mut expected = seen.clone();
    expected.sort_unstable_by(|a, b| b.cmp(a));
    expected.dedup();
    assert_eq!(seen, expected, "newest first, each once");
    assert_eq!(seen.len(), 7);
}

#[sqlx::test(migrations = "../../migrations")]
async fn polling_with_after_returns_only_newer_events(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    record(&h.pool, Utc::now(), None, &discovered(1))
        .await
        .unwrap();
    let first = events(&h, &cookie, "").await;
    let top = first["items"][0]["cursor"].as_str().unwrap().to_owned();

    assert!(ids_of(&events(&h, &cookie, &format!("?after={top}")).await).is_empty());

    for n in 2..=4 {
        record(&h.pool, Utc::now(), None, &discovered(n))
            .await
            .unwrap();
    }
    let newer = events(&h, &cookie, &format!("?after={top}")).await;
    assert_eq!(ids_of(&newer).len(), 3);
    assert_eq!(newer["truncated"], false);

    let capped = events(&h, &cookie, &format!("?after={top}&limit=2")).await;
    assert_eq!(ids_of(&capped).len(), 2);
    assert_eq!(
        capped["truncated"], true,
        "the client must reload, not prepend"
    );
}

/// The case the transaction-id cursor exists for: an event inserted first
/// but committed last must neither be skipped by paging nor by polling.
#[sqlx::test(migrations = "../../migrations")]
async fn an_event_committed_late_is_not_skipped(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    record(&h.pool, Utc::now(), None, &discovered(1))
        .await
        .unwrap();
    let before = events(&h, &cookie, "").await;
    let top = before["items"][0]["cursor"].as_str().unwrap().to_owned();

    // A slow writer inserts (and so takes the lower id) but has not committed...
    let mut slow = h.pool.begin().await.unwrap();
    record(&mut *slow, Utc::now(), None, &discovered(2))
        .await
        .unwrap();
    // ...while a fast writer inserts after it and commits at once.
    record(&h.pool, Utc::now(), None, &discovered(3))
        .await
        .unwrap();

    // While the slow transaction runs, nothing newer than it is served, so a
    // poll cannot move its cursor past the slow event.
    let during = events(&h, &cookie, &format!("?after={top}")).await;
    assert!(ids_of(&during).is_empty(), "{during}");

    slow.commit().await.unwrap();
    let after = events(&h, &cookie, &format!("?after={top}")).await;
    let scan_ids: Vec<i64> = after["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["payload"]["scan_id"].as_i64().unwrap())
        .collect();
    assert_eq!(scan_ids.len(), 2, "both events arrive: {after}");
    assert!(scan_ids.contains(&2) && scan_ids.contains(&3));

    // And the full list is still consistently ordered and complete.
    assert_eq!(ids_of(&events(&h, &cookie, "").await).len(), 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn bad_parameters_get_a_json_error(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    for (query, message) in [
        ("?type=nope", "unknown event type"),
        (
            "?severity=loud",
            "severity must be info, warning or critical",
        ),
        ("?from=yesterday", "from must be an RFC 3339 timestamp"),
        ("?before=garbage", "before is not a valid cursor"),
        ("?device=abc", "device must be a device id"),
    ] {
        let reply = send(
            &h.app,
            Method::GET,
            &format!("/api/events{query}"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(reply.body["error"], message, "{query}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_event_types_are_listed_with_version_and_severity(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let reply = send(
        &h.app,
        Method::GET,
        "/api/events/types",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let types: Vec<&str> = reply
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            "device.discovered",
            "device.online",
            "device.offline",
            "device.named"
        ]
    );
    assert_eq!(reply.body[0]["schema_version"], 1);
    assert_eq!(reply.body[0]["severity"], "info");
}
