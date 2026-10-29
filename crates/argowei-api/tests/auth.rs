//! End-to-end tests for authentication and the audit log.
//!
//! Needs Postgres: `DATABASE_URL` must point at a server where the test user
//! may create databases (`#[sqlx::test]` creates one per test).

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn protected_routes_reject_anonymous_requests(pool: PgPool) {
    let h = harness(pool).await;

    for uri in [
        "/api/devices",
        "/api/audit-log",
        "/api/auth/me",
        "/api/discovery/status",
    ] {
        let reply = send(&h.app, Method::GET, uri, None, None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{uri}");
    }

    let public = send(&h.app, Method::GET, "/api/auth/status", None, None).await;
    assert_eq!(public.status, StatusCode::OK);
    assert_eq!(public.body["setup_required"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn setup_works_once_and_needs_the_token(pool: PgPool) {
    let h = harness(pool).await;
    let attempt = |token: &str| {
        Some(json!({ "setup_token": token, "username": "admin", "password": PASSWORD }))
    };

    let wrong = send(
        &h.app,
        Method::POST,
        "/api/auth/setup",
        None,
        attempt("nope"),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);

    let weak = send(
        &h.app,
        Method::POST,
        "/api/auth/setup",
        None,
        Some(json!({ "setup_token": h.setup_token, "username": "admin", "password": "short" })),
    )
    .await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);

    let ok = send(
        &h.app,
        Method::POST,
        "/api/auth/setup",
        None,
        attempt(&h.setup_token),
    )
    .await;
    assert_eq!(ok.status, StatusCode::CREATED);

    let again = send(
        &h.app,
        Method::POST,
        "/api/auth/setup",
        None,
        attempt(&h.setup_token),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);

    let status = send(&h.app, Method::GET, "/api/auth/status", None, None).await;
    assert_eq!(status.body["setup_required"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn password_is_stored_as_argon2id_hash(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;

    let stored: String = sqlx::query_scalar("SELECT password_hash FROM admin_users")
        .fetch_one(&h.pool)
        .await
        .unwrap();

    assert!(stored.starts_with("$argon2id$"));
    assert!(!stored.contains(PASSWORD));
}

#[sqlx::test(migrations = "../../migrations")]
async fn login_session_and_logout_lifecycle(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;

    let bad = send(
        &h.app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "username": "admin", "password": "wrong password!" })),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(bad.set_cookie.is_none());

    let reply = send(
        &h.app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "username": "admin", "password": PASSWORD })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let set_cookie = reply.set_cookie.unwrap();
    for attribute in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=3600"] {
        assert!(
            set_cookie.contains(attribute),
            "{set_cookie} lacks {attribute}"
        );
    }
    let cookie = set_cookie.split(';').next().unwrap().to_owned();

    let me = send(&h.app, Method::GET, "/api/auth/me", Some(&cookie), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["username"], "admin");
    assert_eq!(
        send(&h.app, Method::GET, "/api/devices", Some(&cookie), None)
            .await
            .status,
        StatusCode::OK
    );

    let logout = send(
        &h.app,
        Method::POST,
        "/api/auth/logout",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);

    let after = send(&h.app, Method::GET, "/api/auth/me", Some(&cookie), None).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn expired_session_is_rejected(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;

    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
        .execute(&h.pool)
        .await
        .unwrap();

    let reply = send(&h.app, Method::GET, "/api/auth/me", Some(&cookie), None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn repeated_failures_are_throttled_even_for_the_right_password(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let attempt = |password: &str| Some(json!({ "username": "admin", "password": password }));

    let mut last = None;
    for _ in 0..4 {
        last = Some(
            send(
                &h.app,
                Method::POST,
                "/api/auth/login",
                None,
                attempt("wrong password!"),
            )
            .await,
        );
    }
    assert_eq!(last.unwrap().status, StatusCode::UNAUTHORIZED);

    let blocked = send(
        &h.app,
        Method::POST,
        "/api/auth/login",
        None,
        attempt(PASSWORD),
    )
    .await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.retry_after.unwrap().parse::<u64>().unwrap() >= 1);
    assert!(blocked.set_cookie.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn cross_origin_state_changes_are_rejected(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;

    let evil = send_with_origin(
        &h.app,
        Method::POST,
        "/api/auth/logout",
        Some(&cookie),
        None,
        Some("http://evil.example"),
    )
    .await;
    assert_eq!(evil.status, StatusCode::FORBIDDEN);

    let same = send_with_origin(
        &h.app,
        Method::POST,
        "/api/auth/logout",
        Some(&cookie),
        None,
        Some("http://argowei.test"),
    )
    .await;
    assert_eq!(same.status, StatusCode::NO_CONTENT);
}

#[sqlx::test(migrations = "../../migrations")]
async fn auth_events_are_audited_without_secrets(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    send(
        &h.app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "username": "admin", "password": "wrong password!" })),
    )
    .await;
    let cookie = login(&h).await;
    send(
        &h.app,
        Method::POST,
        "/api/auth/logout",
        Some(&cookie),
        None,
    )
    .await;

    let rows = audit_actions(&h.pool).await;
    let expected = [
        ("admin", "auth.setup", "success"),
        ("admin", "auth.login", "denied"),
        ("admin", "auth.login", "success"),
        ("admin", "auth.logout", "success"),
    ];
    assert_eq!(rows.len(), expected.len(), "{rows:?}");
    for (row, want) in rows.iter().zip(expected) {
        assert_eq!((row.0.as_str(), row.1.as_str(), row.2.as_str()), want);
    }

    let dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap();
    for secret in [
        PASSWORD,
        "wrong password!",
        h.setup_token.as_str(),
        cookie.split('=').nth(1).unwrap(),
    ] {
        assert!(!dump.contains(secret), "audit log leaks a secret");
    }
}

/// Mutating requests that a handler did not audit itself still leave a
/// trace, including ones rejected before reaching the handler.
#[sqlx::test(migrations = "../../migrations")]
async fn denied_mutations_are_audited_by_the_safety_net(pool: PgPool) {
    let h = harness(pool).await;

    let reply = send(&h.app, Method::POST, "/api/auth/logout", None, None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    assert_eq!(
        audit_actions(&h.pool).await,
        vec![(
            "anonymous".into(),
            "http.POST /api/auth/logout".into(),
            "denied".into()
        )]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn audit_log_is_append_only(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;

    for statement in [
        "UPDATE audit_log SET actor = 'mallory'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ] {
        assert!(
            sqlx::query(statement).execute(&h.pool).await.is_err(),
            "{statement}"
        );
    }
    assert_eq!(audit_actions(&h.pool).await.len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn audit_log_endpoint_filters_and_paginates(pool: PgPool) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;

    let all = send(&h.app, Method::GET, "/api/audit-log", Some(&cookie), None).await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(all.body["items"].as_array().unwrap().len(), 2);
    assert!(all.body["next_before"].is_null());
    assert_eq!(all.body["items"][0]["action"], "auth.login", "newest first");

    let page1 = send(
        &h.app,
        Method::GET,
        "/api/audit-log?limit=1",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(page1.body["items"].as_array().unwrap().len(), 1);
    let cursor = page1.body["next_before"].as_i64().unwrap();

    let page2 = send(
        &h.app,
        Method::GET,
        &format!("/api/audit-log?limit=1&before={cursor}"),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(page2.body["items"][0]["action"], "auth.setup");
    assert!(page2.body["next_before"].is_null());

    let filtered = send(
        &h.app,
        Method::GET,
        "/api/audit-log?action=auth.setup",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(filtered.body["items"].as_array().unwrap().len(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_status_shows_failed_scans_without_persisting_them(pool: PgPool) {
    use argowei_api::discovery::{DiscoveryError, ScanOutcome};

    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;

    h.discovery.register("eth0");
    let failed: Result<ScanOutcome, DiscoveryError> = Err(DiscoveryError::Scan(
        "not permitted; grant CAP_NET_RAW".into(),
    ));
    h.discovery.record("eth0", &failed, chrono::Utc::now());

    let reply = send(
        &h.app,
        Method::GET,
        "/api/discovery/status",
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    let entry = &reply.body[0];
    assert_eq!(entry["interface"], "eth0");
    assert_eq!(entry["consecutive_failures"], 1);
    assert!(entry["last_error"]
        .as_str()
        .unwrap()
        .contains("CAP_NET_RAW"));
    assert!(entry["last_success_at"].is_null());

    // Visible, but not stored: no scan row, so it cannot count as a miss.
    let scans: i64 = sqlx::query_scalar("SELECT count(*) FROM discovery_scans")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(scans, 0);
}
