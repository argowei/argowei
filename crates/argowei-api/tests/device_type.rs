//! Device type: inference during scans, the manual override, and that the two
//! never interfere.

mod common;

use std::time::Duration;

use argowei_api::discovery::{record_scan, ObservedHost};
use argowei_api::presence::PresencePolicy;
use axum::http::{Method, StatusCode};
use chrono::Utc;
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

/// Real registered prefixes: Brother (printer), Raspberry Pi (server), AVM (router).
const PRINTER_MAC: &str = "00:80:77:aa:bb:01";
const PI_MAC: &str = "b8:27:eb:aa:bb:02";
const ROUTER_MAC: &str = "bc:05:43:aa:bb:03";
/// Locally administered: a phone with a private address.
const PRIVATE_MAC: &str = "1a:56:ce:aa:bb:04";
/// Not in the registry.
const UNLISTED_MAC: &str = "0c:0d:0e:aa:bb:05";

const POLICY: PresencePolicy = PresencePolicy {
    offline_after_missed_scans: 3,
    offline_after: Duration::from_secs(900),
};

fn host(last_octet: u8, mac: &str) -> ObservedHost {
    ObservedHost {
        ip: format!("192.168.1.{last_octet}").parse().unwrap(),
        mac: mac.to_owned(),
    }
}

async fn scan(h: &Harness, hosts: &[ObservedHost]) {
    record_scan(&h.pool, "eth0", hosts, Utc::now(), &POLICY)
        .await
        .unwrap();
}

async fn admin(pool: PgPool) -> (Harness, String) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;
    (h, cookie)
}

async fn device_json(h: &Harness, cookie: &str, mac: &str) -> Value {
    let list = send(&h.app, Method::GET, "/api/devices", Some(cookie), None).await;
    list.body
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["mac_address"] == mac)
        .unwrap_or_else(|| panic!("{mac} not listed"))
        .clone()
}

async fn patch(h: &Harness, cookie: &str, id: i64, body: Value) -> Reply {
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{id}"),
        Some(cookie),
        Some(body),
    )
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn scans_infer_a_type_with_confidence_and_evidence(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(
        &h,
        &[
            host(10, PRINTER_MAC),
            host(11, PI_MAC),
            host(12, ROUTER_MAC),
        ],
    )
    .await;

    let printer = device_json(&h, &cookie, PRINTER_MAC).await;
    assert_eq!(printer["device_type"], "printer");
    assert_eq!(printer["type_source"], "inferred");
    assert_eq!(printer["type_override"], Value::Null);
    assert_eq!(printer["inferred"]["device_type"], "printer");
    assert_eq!(printer["inferred"]["confidence"], 70);
    let evidence = &printer["inferred"]["evidence"][0];
    assert_eq!(evidence["kind"], "vendor");
    assert_eq!(evidence["type"], "printer");
    assert_eq!(evidence["weight"], 70);
    assert!(evidence["detail"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("brother"));

    let pi = device_json(&h, &cookie, PI_MAC).await;
    assert_eq!(
        (
            pi["device_type"].as_str(),
            pi["inferred"]["confidence"].as_i64()
        ),
        (Some("server"), Some(40))
    );
    let router = device_json(&h, &cookie, ROUTER_MAC).await;
    assert_eq!(router["device_type"], "router");
}

#[sqlx::test(migrations = "../../migrations")]
async fn weak_or_missing_evidence_stays_unknown_but_is_explained(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(13, PRIVATE_MAC), host(14, UNLISTED_MAC)]).await;

    let private = device_json(&h, &cookie, PRIVATE_MAC).await;
    assert_eq!(private["device_type"], "unknown");
    assert_eq!(private["inferred"]["confidence"], 0);
    assert_eq!(private["inferred"]["evidence"][0]["kind"], "private_mac");
    assert_eq!(private["locally_administered_mac"], true);

    let unlisted = device_json(&h, &cookie, UNLISTED_MAC).await;
    assert_eq!(unlisted["device_type"], "unknown");
    assert_eq!(unlisted["inferred"]["evidence"], json!([]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn devices_recorded_before_classification_existed_get_classified_when_seen(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    sqlx::query("INSERT INTO devices (name, mac_address, is_online) VALUES ($1, $1, true)")
        .bind(PRINTER_MAC)
        .execute(&h.pool)
        .await
        .unwrap();
    assert_eq!(
        device_json(&h, &cookie, PRINTER_MAC).await["device_type"],
        "unknown"
    );

    scan(&h, &[host(10, PRINTER_MAC)]).await;

    assert_eq!(
        device_json(&h, &cookie, PRINTER_MAC).await["device_type"],
        "printer"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_manual_override_wins_and_leaves_the_inference_visible(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    let id = device_json(&h, &cookie, PRINTER_MAC).await["id"]
        .as_i64()
        .unwrap();

    let reply = patch(&h, &cookie, id, json!({ "type_override": "server" })).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["device_type"], "server");
    assert_eq!(reply.body["type_source"], "manual");
    assert_eq!(reply.body["type_override"], "server");
    assert_eq!(
        reply.body["inferred"]["device_type"], "printer",
        "the inference is kept"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn re_classification_never_overwrites_the_manual_override(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    let id = device_json(&h, &cookie, PRINTER_MAC).await["id"]
        .as_i64()
        .unwrap();
    patch(&h, &cookie, id, json!({ "type_override": "iot" })).await;

    // Make the stored inference stale so the next scan really changes it.
    sqlx::query("UPDATE devices SET inferred_type = 'router', inferred_confidence = 99")
        .execute(&h.pool)
        .await
        .unwrap();
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;

    let device = device_json(&h, &cookie, PRINTER_MAC).await;
    assert_eq!(
        device["inferred"]["device_type"], "printer",
        "the inference was refreshed"
    );
    assert_eq!(device["inferred"]["confidence"], 70);
    assert_eq!(device["type_override"], "iot", "the override survived");
    assert_eq!(device["device_type"], "iot");
    assert_eq!(device["type_source"], "manual");
}

#[sqlx::test(migrations = "../../migrations")]
async fn removing_the_override_brings_the_inference_back(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    let id = device_json(&h, &cookie, PRINTER_MAC).await["id"]
        .as_i64()
        .unwrap();
    patch(&h, &cookie, id, json!({ "type_override": "laptop" })).await;

    let cleared = patch(&h, &cookie, id, json!({ "type_override": null })).await;

    assert_eq!(cleared.status, StatusCode::OK);
    assert_eq!(cleared.body["device_type"], "printer");
    assert_eq!(cleared.body["type_source"], "inferred");
    assert_eq!(cleared.body["type_override"], Value::Null);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_unknown_is_a_decision_and_an_absent_field_changes_nothing(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    let id = device_json(&h, &cookie, PRINTER_MAC).await["id"]
        .as_i64()
        .unwrap();

    let unknown = patch(&h, &cookie, id, json!({ "type_override": "unknown" })).await;
    assert_eq!(
        (
            unknown.body["device_type"].as_str(),
            unknown.body["type_source"].as_str()
        ),
        (Some("unknown"), Some("manual"))
    );

    let other_field = patch(&h, &cookie, id, json!({ "notes": "hallway" })).await;
    assert_eq!(
        other_field.body["type_override"], "unknown",
        "untouched by an unrelated edit"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_types_are_rejected_and_change_nothing(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    let id = device_json(&h, &cookie, PRINTER_MAC).await["id"]
        .as_i64()
        .unwrap();

    for value in [json!("toaster"), json!("Printer"), json!(""), json!(7)] {
        let reply = patch(&h, &cookie, id, json!({ "type_override": value.clone() })).await;
        assert!(
            reply.status == StatusCode::BAD_REQUEST
                || reply.status == StatusCode::UNPROCESSABLE_ENTITY,
            "{value} -> {}",
            reply.status
        );
    }
    assert_eq!(
        device_json(&h, &cookie, PRINTER_MAC).await["type_source"],
        "inferred"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn override_changes_are_audited(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;
    let id = device_json(&h, &cookie, PRINTER_MAC).await["id"]
        .as_i64()
        .unwrap();
    patch(&h, &cookie, id, json!({ "type_override": "server" })).await;
    patch(&h, &cookie, id, json!({ "type_override": "server" })).await; // no change
    patch(&h, &cookie, id, json!({ "type_override": null })).await;

    let payloads: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM audit_log WHERE action = 'device.update' ORDER BY id",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();

    assert_eq!(payloads.len(), 2, "the repeated request is not a change");
    assert_eq!(
        payloads[0]["changes"]["type_override"],
        json!({ "from": null, "to": "server" })
    );
    assert_eq!(
        payloads[1]["changes"]["type_override"],
        json!({ "from": "server", "to": null })
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_database_rejects_a_type_it_does_not_know(pool: PgPool) {
    let (h, _) = admin(pool).await;
    scan(&h, &[host(10, PRINTER_MAC)]).await;

    let override_bad = sqlx::query("UPDATE devices SET type_override = 'toaster'")
        .execute(&h.pool)
        .await;
    let inferred_bad = sqlx::query("UPDATE devices SET inferred_type = 'toaster'")
        .execute(&h.pool)
        .await;
    let confidence_bad = sqlx::query("UPDATE devices SET inferred_confidence = 101")
        .execute(&h.pool)
        .await;

    assert!(override_bad.is_err() && inferred_bad.is_err() && confidence_bad.is_err());
}
