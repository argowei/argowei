//! Shared setup for the API integration tests: builds the app around a test
//! database and drives it through the HTTP layer as an admin would.

#![allow(dead_code)]

use argowei_api::auth::AuthState;
use argowei_api::routes;
use argowei_api::state::AppState;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE};
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use argowei_api::discovery::{record_scan, ObservedHost};
use argowei_api::presence::PresencePolicy;

pub const PASSWORD: &str = "correct horse battery";

pub struct Harness {
    pub app: Router,
    pub discovery: argowei_api::discovery::DiscoveryStatus,
    pub setup_token: String,
    pub pool: PgPool,
}

pub async fn harness(pool: PgPool) -> Harness {
    harness_with_scans(pool, argowei_api::scans::ScanConfig::default()).await
}

/// A harness whose port scans run with `config` (e.g. a stand-in for nmap).
pub async fn harness_with_scans(pool: PgPool, config: argowei_api::scans::ScanConfig) -> Harness {
    let auth = AuthState::new(false, chrono::Duration::hours(1));
    let state = AppState::new(pool.clone(), auth).with_scan_config(config);
    let setup_token = state
        .auth
        .init_setup_token(&state.db)
        .await
        .expect("fresh database must issue a setup token");

    let discovery = state.discovery.clone();

    Harness {
        discovery,
        app: routes::router(state),
        setup_token,
        pool,
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub set_cookie: Option<String>,
    pub retry_after: Option<String>,
    pub body: Value,
}

pub async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> Reply {
    send_with_origin(app, method, uri, cookie, body, None).await
}

pub async fn send_with_origin(
    app: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
    origin: Option<&str>,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "argowei.test");
    if let Some(cookie) = cookie {
        builder = builder.header(COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(ORIGIN, origin);
    }
    let request = match body {
        Some(json) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(json.to_string())),
        None => builder.body(Body::empty()),
    }
    .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_owned());
    let retry_after = response
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    Reply {
        status,
        set_cookie,
        retry_after,
        body,
    }
}

pub async fn setup_admin(h: &Harness) {
    let reply = send(
        &h.app,
        Method::POST,
        "/api/auth/setup",
        None,
        Some(json!({ "setup_token": h.setup_token, "username": "admin", "password": PASSWORD })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED);
}

/// Logs in and returns the `name=value` pair to send back as a Cookie header.
pub async fn login(h: &Harness) -> String {
    let reply = send(
        &h.app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "username": "admin", "password": PASSWORD })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    reply
        .set_cookie
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

pub async fn audit_actions(pool: &PgPool) -> Vec<(String, String, String)> {
    sqlx::query_as("SELECT actor, action, outcome FROM audit_log ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// A fresh app with the admin set up and logged in; returns the session cookie.
pub async fn admin(pool: PgPool) -> (Harness, String) {
    let h = harness(pool).await;
    setup_admin(&h).await;
    let cookie = login(&h).await;
    (h, cookie)
}

// --- discovery ------------------------------------------------------------

/// The presence policy the tests scan with: offline after 3 missed scans
/// and 15 minutes.
pub const POLICY: PresencePolicy = PresencePolicy {
    offline_after_missed_scans: 3,
    offline_after: std::time::Duration::from_secs(900),
};

/// A fixed point in time, so tests can scan at `t0() + minutes(n)`.
pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
}

pub fn minutes(n: i64) -> ChronoDuration {
    ChronoDuration::minutes(n)
}

/// A host at `192.168.1.<last_octet>`.
pub fn host(last_octet: u8, mac: &str) -> ObservedHost {
    ObservedHost {
        ip: format!("192.168.1.{last_octet}").parse().unwrap(),
        mac: mac.to_owned(),
    }
}

/// Stores a scan of `eth0` that found `hosts`.
pub async fn scan(h: &Harness, hosts: &[ObservedHost], at: DateTime<Utc>) {
    record_scan(&h.pool, "eth0", hosts, at, &POLICY)
        .await
        .unwrap();
}

/// Inserts a device directly, without a scan; returns its id.
pub async fn insert_device(pool: &PgPool, mac: &str) -> i32 {
    sqlx::query_scalar(
        "INSERT INTO devices (name, mac_address, is_online) VALUES ($1, $1, true) RETURNING id",
    )
    .bind(mac)
    .fetch_one(pool)
    .await
    .unwrap()
}

// --- reading back -----------------------------------------------------------

/// The device with this MAC, as `GET /api/devices` lists it.
pub async fn device_json(h: &Harness, cookie: &str, mac: &str) -> Value {
    let list = send(&h.app, Method::GET, "/api/devices", Some(cookie), None).await;
    list.body
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["mac_address"] == mac)
        .unwrap_or_else(|| panic!("{mac} not listed"))
        .clone()
}

pub async fn patch_device(
    h: &Harness,
    cookie: &str,
    id: impl std::fmt::Display,
    body: Value,
) -> Reply {
    send(
        &h.app,
        Method::PATCH,
        &format!("/api/devices/{id}"),
        Some(cookie),
        Some(body),
    )
    .await
}

/// Rows in `table`.
pub async fn count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Audit entries with this action.
pub async fn audit_count(h: &Harness, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1")
        .bind(action)
        .fetch_one(&h.pool)
        .await
        .unwrap()
}
