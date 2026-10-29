//! Device groups (CRUD, system groups) and per-device group and trust level.

mod common;

use std::time::Duration;

use argowei_api::discovery::{record_scan, ObservedHost};
use argowei_api::presence::PresencePolicy;
use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{json, Value};
use sqlx::PgPool;

const MAC: &str = "aa:bb:cc:00:00:01";

async fn admin(pool: PgPool) -> (Harness, String) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;
    (h, cookie)
}

async fn new_device(h: &Harness, mac: &str) -> i32 {
    sqlx::query_scalar(
        "INSERT INTO devices (name, mac_address, is_online) VALUES ($1, $1, true) RETURNING id",
    )
    .bind(mac)
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

async fn groups(h: &Harness, cookie: &str) -> Vec<Value> {
    let reply = send(&h.app, Method::GET, "/api/groups", Some(cookie), None).await;
    assert_eq!(reply.status, StatusCode::OK);
    reply.body.as_array().unwrap().clone()
}

fn group_id(groups: &[Value], name: &str) -> i64 {
    groups.iter().find(|g| g["name"] == name).unwrap()["id"]
        .as_i64()
        .unwrap()
}

async fn unassigned(h: &Harness, cookie: &str) -> i64 {
    group_id(&groups(h, cookie).await, "Unassigned")
}

async fn audit_count(h: &Harness, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1")
        .bind(action)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}

// --- system groups --------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_system_groups_are_seeded_with_their_default_behavior(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    let all = groups(&h, &cookie).await;

    let names: Vec<&str> = all.iter().map(|g| g["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "Unassigned",
            "Trusted",
            "Servers",
            "Guest",
            "IoT",
            "Kids",
            "Quarantine",
            "Blocked"
        ]
    );
    assert!(all
        .iter()
        .all(|g| g["is_system"] == true && g["device_count"] == 0));

    let by = |slug: &str| all.iter().find(|g| g["slug"] == slug).unwrap()["defaults"].clone();
    assert_eq!(by("unassigned"), json!({}));
    assert_eq!(by("guest")["lan"], "block");
    assert_eq!(by("guest")["dns_filter"], true);
    assert_eq!(by("quarantine")["manual_release"], true);
    assert_eq!(by("blocked")["internet"], "block");
}

#[sqlx::test(migrations = "../../migrations")]
async fn seeding_again_changes_nothing_and_keeps_edits(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let kids = group_id(&groups(&h, &cookie).await, "Kids");
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/groups/{kids}"),
        Some(&cookie),
        Some(json!({ "description": "Angepasst" })),
    )
    .await;

    sqlx::query("SELECT seed_system_groups()")
        .execute(&h.pool)
        .await
        .unwrap();

    let all = groups(&h, &cookie).await;
    assert_eq!(all.len(), 8);
    let kids = all.iter().find(|g| g["name"] == "Kids").unwrap();
    assert_eq!(kids["description"], "Angepasst");
}

#[sqlx::test(migrations = "../../migrations")]
async fn groups_require_a_session(pool: PgPool) {
    let (h, _) = admin(pool).await;

    for (method, uri) in [
        (Method::GET, "/api/groups"),
        (Method::POST, "/api/groups"),
        (Method::DELETE, "/api/groups/1"),
    ] {
        let reply = send(&h.app, method, uri, None, Some(json!({ "name": "x" }))).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_unassigned_group_cannot_be_renamed_or_deleted(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let uri = format!("/api/groups/{}", unassigned(&h, &cookie).await);

    let rename = send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "name": "Other" })),
    )
    .await;
    let delete = send(&h.app, Method::DELETE, &uri, Some(&cookie), None).await;

    assert_eq!(rename.status, StatusCode::CONFLICT);
    assert_eq!(delete.status, StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "../../migrations")]
async fn system_groups_cannot_be_renamed_or_deleted_but_can_be_tuned(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let iot = group_id(&groups(&h, &cookie).await, "IoT");
    let uri = format!("/api/groups/{iot}");

    let rename = send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "name": "Gadgets" })),
    )
    .await;
    assert_eq!(rename.status, StatusCode::CONFLICT);

    let delete = send(&h.app, Method::DELETE, &uri, Some(&cookie), None).await;
    assert_eq!(delete.status, StatusCode::CONFLICT);

    let tune = send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "name": "IoT", "defaults": { "internet": "block" } })),
    )
    .await;
    assert_eq!(tune.status, StatusCode::OK);
    assert_eq!(tune.body["defaults"], json!({ "internet": "block" }));
    assert_eq!(groups(&h, &cookie).await.len(), 8);
}

// --- custom groups --------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn custom_groups_can_be_created_renamed_and_deleted(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    let created = send(&h.app, Method::POST, "/api/groups", Some(&cookie), Some(json!({ "name": "  Labor  ", "description": "Testgeräte", "defaults": { "internet": "allow" } }))).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["name"], "Labor");
    assert_eq!(created.body["is_system"], false);
    assert!(created.body["slug"].is_null());
    let id = created.body["id"].as_i64().unwrap();

    let renamed = send(
        &h.app,
        Method::PATCH,
        &format!("/api/groups/{id}"),
        Some(&cookie),
        Some(json!({ "name": "Werkstatt" })),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK);
    assert_eq!(renamed.body["name"], "Werkstatt");

    let deleted = send(
        &h.app,
        Method::DELETE,
        &format!("/api/groups/{id}"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(groups(&h, &cookie).await.len(), 8);
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_names_are_unique_ignoring_case(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    for name in ["iot", "IOT", "Trusted"] {
        let reply = send(
            &h.app,
            Method::POST,
            "/api/groups",
            Some(&cookie),
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{name}");
    }
    send(
        &h.app,
        Method::POST,
        "/api/groups",
        Some(&cookie),
        Some(json!({ "name": "Labor" })),
    )
    .await;
    let rename_clash = send(
        &h.app,
        Method::PATCH,
        &format!(
            "/api/groups/{}",
            group_id(&groups(&h, &cookie).await, "Labor")
        ),
        Some(&cookie),
        Some(json!({ "name": "GUEST" })),
    )
    .await;
    assert_eq!(rename_clash.status, StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_group_input_is_rejected(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    for body in [
        json!({ "name": "" }),
        json!({ "name": "x".repeat(65) }),
        json!({ "name": "a\nb" }),
        json!({ "name": "ok", "defaults": "allow" }),
        json!({ "name": "ok", "defaults": [1] }),
        json!({ "name": "ok", "is_system": true }),
        json!({ "name": "ok", "slug": "trusted" }),
    ] {
        let reply = send(
            &h.app,
            Method::POST,
            "/api/groups",
            Some(&cookie),
            Some(body.clone()),
        )
        .await;
        assert!(
            reply.status == StatusCode::BAD_REQUEST
                || reply.status == StatusCode::UNPROCESSABLE_ENTITY,
            "{body} -> {}",
            reply.status
        );
    }
    assert_eq!(groups(&h, &cookie).await.len(), 8);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_with_devices_cannot_be_deleted(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let created = send(
        &h.app,
        Method::POST,
        "/api/groups",
        Some(&cookie),
        Some(json!({ "name": "Labor" })),
    )
    .await;
    let gid = created.body["id"].as_i64().unwrap();
    let device = new_device(&h, MAC).await;
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{device}"),
        Some(&cookie),
        Some(json!({ "group_id": gid })),
    )
    .await;

    let refused = send(
        &h.app,
        Method::DELETE,
        &format!("/api/groups/{gid}"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);

    let back = unassigned(&h, &cookie).await;
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{device}"),
        Some(&cookie),
        Some(json!({ "group_id": back })),
    )
    .await;
    let deleted = send(
        &h.app,
        Method::DELETE,
        &format!("/api/groups/{gid}"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
}

#[sqlx::test(migrations = "../../migrations")]
async fn unknown_groups_are_not_found(pool: PgPool) {
    let (h, cookie) = admin(pool).await;

    let patch = send(
        &h.app,
        Method::PATCH,
        "/api/groups/9999",
        Some(&cookie),
        Some(json!({ "name": "x" })),
    )
    .await;
    let delete = send(
        &h.app,
        Method::DELETE,
        "/api/groups/9999",
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(patch.status, StatusCode::NOT_FOUND);
    assert_eq!(delete.status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_changes_are_audited(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let created = send(
        &h.app,
        Method::POST,
        "/api/groups",
        Some(&cookie),
        Some(json!({ "name": "Labor" })),
    )
    .await;
    let uri = format!("/api/groups/{}", created.body["id"]);
    send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "description": "neu" })),
    )
    .await;
    send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "description": "neu" })),
    )
    .await; // no change
    send(&h.app, Method::DELETE, &uri, Some(&cookie), None).await;

    assert_eq!(audit_count(&h, "group.create").await, 1);
    assert_eq!(
        audit_count(&h, "group.update").await,
        1,
        "a no-op update is not a change"
    );
    assert_eq!(audit_count(&h, "group.delete").await, 1);
    let diff: Value =
        sqlx::query_scalar("SELECT payload FROM audit_log WHERE action = 'group.update'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(
        diff["changes"]["description"],
        json!({ "from": "", "to": "neu" })
    );
}

// --- group membership and trust level on devices ---------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn new_devices_start_unassigned_and_untrusted(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    new_device(&h, MAC).await;
    let unassigned = unassigned(&h, &cookie).await;

    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;

    assert_eq!(list.body[0]["trust_level"], "unknown");
    assert_eq!(
        list.body[0]["group"],
        json!({ "id": unassigned, "name": "Unassigned" })
    );
    assert_eq!(list.body[0]["group_id"], unassigned);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_device_has_one_group_and_moving_it_updates_both_counts(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let device = new_device(&h, MAC).await;
    let all = groups(&h, &cookie).await;
    let (iot, guest) = (group_id(&all, "IoT"), group_id(&all, "Guest"));
    let uri = format!("/api/devices/{device}");

    let first = send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "group_id": iot, "trust_level": "restricted" })),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["group"], json!({ "id": iot, "name": "IoT" }));
    assert_eq!(first.body["trust_level"], "restricted");

    let moved = send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "group_id": guest })),
    )
    .await;
    assert_eq!(moved.body["group"]["name"], "Guest");
    assert_eq!(
        moved.body["trust_level"], "restricted",
        "an absent field is left alone"
    );

    let counts: Vec<(String, i64)> = groups(&h, &cookie)
        .await
        .iter()
        .map(|g| {
            (
                g["name"].as_str().unwrap().to_owned(),
                g["device_count"].as_i64().unwrap(),
            )
        })
        .collect();
    assert!(counts.contains(&("Guest".into(), 1)) && counts.contains(&("IoT".into(), 0)));

    // Moving a device back is done by id; there is no "no group".
    let back = unassigned(&h, &cookie).await;
    let moved_back = send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "group_id": back })),
    )
    .await;
    assert_eq!(moved_back.status, StatusCode::OK);
    assert_eq!(moved_back.body["group"]["name"], "Unassigned");
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_group_or_trust_values_are_rejected_and_change_nothing(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let device = new_device(&h, MAC).await;
    let uri = format!("/api/devices/{device}");
    send(
        &h.app,
        Method::PATCH,
        &uri,
        Some(&cookie),
        Some(json!({ "trust_level": "normal" })),
    )
    .await;

    for body in [
        json!({ "group_id": 9999 }),
        json!({ "trust_level": "admin" }),
        json!({ "trust_level": "Trusted" }),
        json!({ "trust_level": null }),
    ] {
        let reply = send(
            &h.app,
            Method::PATCH,
            &uri,
            Some(&cookie),
            Some(body.clone()),
        )
        .await;
        assert!(
            reply.status == StatusCode::BAD_REQUEST
                || reply.status == StatusCode::UNPROCESSABLE_ENTITY,
            "{body} -> {}",
            reply.status
        );
    }

    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;
    assert_eq!(list.body[0]["trust_level"], "normal");
    assert_eq!(
        list.body[0]["group"]["name"], "Unassigned",
        "a rejected request changes nothing"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_and_trust_changes_are_audited_with_names(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let device = new_device(&h, MAC).await;
    let iot = group_id(&groups(&h, &cookie).await, "IoT");

    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{device}"),
        Some(&cookie),
        Some(json!({ "group_id": iot, "trust_level": "suspicious" })),
    )
    .await;

    let payload: Value =
        sqlx::query_scalar("SELECT payload FROM audit_log WHERE action = 'device.update'")
            .fetch_one(&h.pool)
            .await
            .unwrap();
    let from = unassigned(&h, &cookie).await;
    assert_eq!(
        payload["changes"]["group"],
        json!({ "from": { "id": from, "name": "Unassigned" }, "to": { "id": iot, "name": "IoT" } })
    );
    assert_eq!(
        payload["changes"]["trust_level"],
        json!({ "from": "unknown", "to": "suspicious" })
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_never_changes_group_or_trust(pool: PgPool) {
    let (h, cookie) = admin(pool).await;
    let policy = PresencePolicy {
        offline_after_missed_scans: 3,
        offline_after: Duration::from_secs(900),
    };
    let host = ObservedHost {
        ip: "192.168.1.10".parse().unwrap(),
        mac: MAC.to_owned(),
    };
    record_scan(
        &h.pool,
        "eth0",
        std::slice::from_ref(&host),
        chrono::Utc::now(),
        &policy,
    )
    .await
    .unwrap();

    // Discovery created the device unassigned and untrusted ...
    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;
    assert_eq!(list.body[0]["trust_level"], "unknown");
    assert_eq!(list.body[0]["group"]["name"], "Unassigned");

    // ... and later scans leave the user's classification alone.
    let id = list.body[0]["id"].as_i64().unwrap();
    let trusted = group_id(&groups(&h, &cookie).await, "Trusted");
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{id}"),
        Some(&cookie),
        Some(json!({ "group_id": trusted, "trust_level": "trusted" })),
    )
    .await;
    for minutes in [5, 10] {
        let at = chrono::Utc::now() + chrono::Duration::minutes(minutes);
        record_scan(&h.pool, "eth0", std::slice::from_ref(&host), at, &policy)
            .await
            .unwrap();
    }

    let list = send(&h.app, Method::GET, "/api/devices", Some(&cookie), None).await;
    assert_eq!(list.body[0]["trust_level"], "trusted");
    assert_eq!(list.body[0]["group"]["name"], "Trusted");
}
