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
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

pub const PASSWORD: &str = "correct horse battery";

pub struct Harness {
    pub app: Router,
    pub discovery: argowei_api::discovery::DiscoveryStatus,
    pub setup_token: String,
    pub pool: PgPool,
}

pub async fn harness(pool: PgPool) -> Harness {
    let auth = AuthState::new(false, chrono::Duration::hours(1));
    let redis = redis::Client::open("redis://127.0.0.1:6379/0").unwrap();
    let state = AppState::new(pool.clone(), redis, auth);
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
