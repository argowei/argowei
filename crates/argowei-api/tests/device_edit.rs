//! Editing a device's label and notes through the API.

mod common;

use argowei_api::discovery::record_scan;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use sqlx::PgPool;

const MAC: &str = "aa:bb:cc:00:00:01";

/// An admin who is logged in and one device known to the system.
async fn setup(pool: PgPool) -> (Harness, String, i32) {
    let (h, cookie) = admin(pool).await;
    let id = insert_device(&h.pool, MAC).await;
    (h, cookie, id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn label_and_notes_round_trip(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;

    let reply = patch_device(
        &h,
        &cookie,
        id,
        json!({ "label": "Wohnzimmer TV", "notes": "Hinter dem Schrank\nSamsung" }),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["label"], "Wohnzimmer TV");
    assert_eq!(reply.body["display_name"], "Wohnzimmer TV");
    assert_eq!(reply.body["name"], MAC, "the discovered name is untouched");

    // The list endpoint returns what was stored.
    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;
    assert_eq!(list.body[0]["label"], "Wohnzimmer TV");
    assert_eq!(list.body[0]["notes"], "Hinter dem Schrank\nSamsung");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_without_a_label_shows_its_discovered_name(pool: PgPool) {
    let (h, cookie, _) = setup(pool).await;

    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;

    assert!(list.body[0]["label"].is_null());
    assert_eq!(list.body[0]["notes"], "");
    assert_eq!(list.body[0]["display_name"], MAC);
}

#[sqlx::test(migrations = "../../migrations")]
async fn values_are_trimmed_and_blank_or_null_clears(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;

    let trimmed = patch_device(
        &h,
        &cookie,
        id,
        json!({ "label": "  Drucker  ", "notes": "  hallo  " }),
    )
    .await;
    assert_eq!(trimmed.body["label"], "Drucker");
    assert_eq!(trimmed.body["notes"], "hallo");

    let blank = patch_device(&h, &cookie, id, json!({ "label": "   " })).await;
    assert!(blank.body["label"].is_null());
    assert_eq!(
        blank.body["notes"], "hallo",
        "an absent field is left alone"
    );

    patch_device(&h, &cookie, id, json!({ "label": "Wieder da" })).await;
    let null = patch_device(&h, &cookie, id, json!({ "label": null, "notes": "" })).await;
    assert!(null.body["label"].is_null());
    assert_eq!(null.body["notes"], "");
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_input_is_rejected_and_changes_nothing(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;
    patch_device(&h, &cookie, id, json!({ "label": "Behalten" })).await;

    for body in [
        json!({ "label": "x".repeat(65) }),
        json!({ "label": "two\nlines" }),
        json!({ "notes": "x".repeat(2001) }),
        json!({ "notes": "bell\u{7}" }),
        json!({ "name": "renamed" }),
        json!({ "is_online": false }),
    ] {
        let reply = patch_device(&h, &cookie, id, body.clone()).await;
        assert!(
            reply.status == StatusCode::BAD_REQUEST
                || reply.status == StatusCode::UNPROCESSABLE_ENTITY,
            "{body} -> {}",
            reply.status
        );
    }

    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;
    assert_eq!(list.body[0]["label"], "Behalten");
    assert_eq!(list.body[0]["name"], MAC);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_device_is_not_found(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;

    let reply = patch_device(&h, &cookie, id + 1000, json!({ "label": "x" })).await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn editing_requires_a_session(pool: PgPool) {
    let (h, _, id) = setup(pool).await;

    let reply = send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{id}"),
        None,
        Some(json!({ "label": "x" })),
    )
    .await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    let label: Option<String> = sqlx::query_scalar("SELECT label FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(label, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn changes_are_audited_with_a_diff(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;
    patch_device(&h, &cookie, id, json!({ "label": "Alt" })).await;
    patch_device(&h, &cookie, id, json!({ "label": "Neu", "notes": "Notiz" })).await;

    let rows: Vec<(String, String, Option<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT actor, action, target_id, payload FROM audit_log WHERE action = 'device.update' ORDER BY id",
    )
    .fetch_all(&h.pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 2, "one entry per change, no generic duplicate");
    assert_eq!(rows[1].0, "admin");
    assert_eq!(rows[1].2.as_deref(), Some(id.to_string().as_str()));
    assert_eq!(
        rows[1].3["changes"]["label"],
        json!({ "from": "Alt", "to": "Neu" })
    );
    assert_eq!(
        rows[1].3["changes"]["notes"],
        json!({ "from": "", "to": "Notiz" })
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_request_that_changes_nothing_writes_no_change_entry(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;
    patch_device(&h, &cookie, id, json!({ "label": "Gleich" })).await;

    let again = patch_device(&h, &cookie, id, json!({ "label": " Gleich " })).await;

    assert_eq!(again.status, StatusCode::OK);
    let updates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'device.update'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(updates, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_never_overwrites_user_input(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;
    patch_device(
        &h,
        &cookie,
        id,
        json!({ "label": "Mein Gerät", "notes": "wichtig" }),
    )
    .await;

    let host = host(10, MAC);
    for minutes in [0, 5, 10] {
        let at = chrono::Utc::now() + chrono::Duration::minutes(minutes);
        record_scan(&h.pool, "eth0", std::slice::from_ref(&host), at, &POLICY)
            .await
            .unwrap();
    }

    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;
    assert_eq!(list.body[0]["label"], "Mein Gerät");
    assert_eq!(list.body[0]["notes"], "wichtig");
    assert_eq!(list.body[0]["display_name"], "Mein Gerät");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_single_device_can_be_fetched_with_its_addresses(pool: PgPool) {
    let (h, cookie, id) = setup(pool).await;
    sqlx::query(
        "INSERT INTO device_addresses (device_id, ip_address, protocol, source) \
         VALUES ($1, '192.168.1.10', 'ipv4', 'arp')",
    )
    .bind(id)
    .execute(&h.pool)
    .await
    .unwrap();

    let reply = send(
        &h.app,
        Method::GET,
        &format!("/api/devices/{id}"),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["id"], id);
    assert_eq!(reply.body["addresses"][0]["ip_address"], "192.168.1.10");

    let missing = send(
        &h.app,
        Method::GET,
        &format!("/api/devices/{}", id + 1000),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let anonymous = send(
        &h.app,
        Method::GET,
        &format!("/api/devices/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}
