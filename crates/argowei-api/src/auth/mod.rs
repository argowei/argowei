//! Single-admin authentication with server-side sessions.
//!
//! The session token is a random value held in an `HttpOnly`,
//! `SameSite=Strict` cookie; only its SHA-256 is stored in Postgres. State
//! changing requests additionally have their `Origin` header checked
//! against `Host` as a second CSRF layer.

mod password;
mod throttle;

use std::sync::Mutex;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::header::{HOST, ORIGIN, RETRY_AFTER};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use crate::audit::{self, AuditEntry, Audited, Outcome};
use crate::state::AppState;
use throttle::LoginThrottle;

pub const SESSION_COOKIE: &str = "argowei_session";

const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 64;
/// Throttle key shared by every username that is not the admin's.
const UNKNOWN_USER_KEY: &str = "*";
const SETUP_THROTTLE_KEY: &str = "setup";

/// The authenticated administrator, available to handlers via
/// `Extension<AuthUser>` on protected routes.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: i32,
    pub username: String,
}

pub struct AuthState {
    cookie_secure: bool,
    session_ttl: Duration,
    /// One-time secret printed to the server log on first start. Whoever can
    /// read the log may create the admin, so a stranger on the LAN cannot
    /// claim a fresh install first. `None` once setup is done.
    setup_token: Mutex<Option<String>>,
    throttle: LoginThrottle,
}

impl AuthState {
    pub fn new(cookie_secure: bool, session_ttl: Duration) -> Self {
        Self {
            cookie_secure,
            session_ttl,
            setup_token: Mutex::new(None),
            throttle: LoginThrottle::default(),
        }
    }

    /// Generates (and logs) the setup token if no admin exists yet.
    /// Returns it for tests; the server only needs the side effect.
    pub async fn init_setup_token(&self, db: &PgPool) -> Option<String> {
        match admin_exists(db).await {
            Ok(false) => {
                let token = random_token();
                tracing::warn!("no admin account yet; first-run setup token: {token}");
                *self.setup_token.lock().expect("setup token lock poisoned") = Some(token.clone());
                Some(token)
            }
            Ok(true) => None,
            Err(error) => {
                tracing::warn!(%error, "could not check for an admin account; setup is unavailable until restart");
                None
            }
        }
    }
}

// --- errors ---------------------------------------------------------------

enum ApiError {
    Unauthorized,
    Forbidden(&'static str),
    BadRequest(String),
    Conflict(&'static str),
    TooManyRequests {
        retry_after_secs: u64,
    },
    Unavailable,
    /// Wraps a failure the handler already wrote to the audit log, so the
    /// safety-net middleware does not add a second entry.
    Audited(Box<ApiError>),
}

impl ApiError {
    /// For failures already written to the audit log by the handler.
    fn audited(self) -> ApiError {
        ApiError::Audited(Box::new(self))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Audited(inner) = self {
            let mut response = inner.into_response();
            response.extensions_mut().insert(Audited);
            return response;
        }

        let (status, message) = match &self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication required".into()),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, (*msg).to_owned()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, (*msg).to_owned()),
            ApiError::TooManyRequests { .. } => {
                (StatusCode::TOO_MANY_REQUESTS, "too many attempts".into())
            }
            ApiError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service unavailable".into(),
            ),
            ApiError::Audited(_) => unreachable!("handled above"),
        };

        let mut response = (status, Json(json!({ "error": message }))).into_response();
        if let ApiError::TooManyRequests { retry_after_secs } = self {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(retry_after_secs));
        }
        response
    }
}

fn db_error(error: sqlx::Error) -> ApiError {
    tracing::error!(%error, "database error in auth handler");
    ApiError::Unavailable
}

// --- tokens ---------------------------------------------------------------

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

// --- middleware -----------------------------------------------------------

/// Rejects requests without a valid, unexpired session.
pub async fn require_auth(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(cookie) = jar.get(SESSION_COOKIE) else {
        return ApiError::Unauthorized.into_response();
    };

    let user = sqlx::query_as::<_, (i32, String)>(
        "SELECT u.id, u.username FROM sessions s \
         JOIN admin_users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(hash_token(cookie.value()))
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some((id, username))) => AuthUser { id, username },
        Ok(None) => return ApiError::Unauthorized.into_response(),
        Err(error) => return db_error(error).into_response(),
    };

    request.extensions_mut().insert(user.clone());
    let mut response = next.run(request).await;
    // Lets the audit layer, which sits outside this one, attribute the action.
    response.extensions_mut().insert(user);
    response
}

/// CSRF defense in depth on top of `SameSite=Strict`: browsers always send
/// `Origin` on cross-origin state-changing requests, so a mismatch with
/// `Host` is rejected. Requests without `Origin` (curl, native clients) pass.
pub async fn check_origin(request: Request, next: Next) -> Response {
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );

    if !safe {
        if let Some(origin) = request.headers().get(ORIGIN) {
            let host = request.headers().get(HOST).and_then(|h| h.to_str().ok());
            if !origin_matches_host(origin.to_str().unwrap_or(""), host) {
                return ApiError::Forbidden("cross-origin request rejected").into_response();
            }
        }
    }

    next.run(request).await
}

fn origin_matches_host(origin: &str, host: Option<&str>) -> bool {
    let authority = origin.split_once("://").map(|(_, rest)| rest);
    matches!((authority, host), (Some(a), Some(h)) if a.eq_ignore_ascii_case(h))
}

// --- routes ---------------------------------------------------------------

/// Endpoints reachable without a session.
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/status", get(status))
        .route("/api/auth/setup", post(setup))
        .route("/api/auth/login", post(login))
}

/// Endpoints that require a session.
pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/me", get(me))
        .route("/api/auth/logout", post(logout))
}

async fn admin_exists(db: &PgPool) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admin_users)")
        .fetch_one(db)
        .await
}

async fn status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let exists = admin_exists(&state.db).await.map_err(db_error)?;
    Ok(Json(json!({ "setup_required": !exists })))
}

async fn me(Extension(user): Extension<AuthUser>) -> Json<serde_json::Value> {
    Json(json!({ "username": user.username }))
}

#[derive(Deserialize)]
struct SetupRequest {
    setup_token: String,
    username: String,
    password: String,
}

async fn setup(
    State(state): State<AppState>,
    request_meta: RequestMeta,
    Json(body): Json<SetupRequest>,
) -> Result<Response, ApiError> {
    let auth = &state.auth;
    let remote = request_meta.remote_addr;

    if let Err(wait) = auth.throttle.check(SETUP_THROTTLE_KEY, Instant::now()) {
        return Err(ApiError::TooManyRequests {
            retry_after_secs: wait.as_secs().max(1),
        });
    }

    let token_ok = {
        let guard = auth.setup_token.lock().expect("setup token lock poisoned");
        match guard.as_deref() {
            None => return Err(ApiError::Conflict("setup already completed")),
            Some(expected) => bool::from(expected.as_bytes().ct_eq(body.setup_token.as_bytes())),
        }
    };

    if !token_ok {
        auth.throttle
            .record_failure(SETUP_THROTTLE_KEY, Instant::now());
        audit_best_effort(
            &state.db,
            AuditEntry::new(audit::ANONYMOUS, "auth.setup", Outcome::Denied)
                .remote_addr(remote)
                .payload(json!({ "reason": "invalid setup token" })),
        )
        .await;
        return Err(ApiError::Forbidden("invalid setup token").audited());
    }

    let username = body.username.trim().to_owned();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&username.chars().count()) {
        return Err(ApiError::BadRequest(format!(
            "username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters"
        )));
    }
    if !(password::MIN_PASSWORD_LEN..=password::MAX_PASSWORD_LEN).contains(&body.password.len()) {
        return Err(ApiError::BadRequest(format!(
            "password must be {}-{} bytes",
            password::MIN_PASSWORD_LEN,
            password::MAX_PASSWORD_LEN
        )));
    }

    let password_hash = hash_blocking(body.password)
        .await
        .ok_or(ApiError::Unavailable)?;

    let mut tx = state.db.begin().await.map_err(db_error)?;
    // The unique index on `(true)` makes this a no-op if an admin exists.
    let created: Option<i32> = sqlx::query_scalar(
        "INSERT INTO admin_users (username, password_hash) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&username)
    .bind(&password_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_error)?;

    let Some(id) = created else {
        return Err(ApiError::Conflict("setup already completed"));
    };

    audit::record(
        &mut *tx,
        AuditEntry::new(&username, "auth.setup", Outcome::Success)
            .target("admin_user", id)
            .remote_addr(remote),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;

    *auth.setup_token.lock().expect("setup token lock poisoned") = None;

    let mut response = (StatusCode::CREATED, Json(json!({ "username": username }))).into_response();
    response.extensions_mut().insert(Audited);
    Ok(response)
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    request_meta: RequestMeta,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Response), ApiError> {
    let auth = &state.auth;
    let remote = request_meta.remote_addr;

    let admin: Option<(i32, String, String)> =
        sqlx::query_as("SELECT id, username, password_hash FROM admin_users WHERE username = $1")
            .bind(&body.username)
            .fetch_optional(&state.db)
            .await
            .map_err(db_error)?;

    let key = admin
        .as_ref()
        .map_or(UNKNOWN_USER_KEY, |(_, username, _)| username.as_str())
        .to_owned();

    if let Err(wait) = auth.throttle.check(&key, Instant::now()) {
        audit_best_effort(
            &state.db,
            login_entry(&body.username, Outcome::Denied, remote.clone())
                .payload(json!({ "reason": "throttled" })),
        )
        .await;
        return Err(ApiError::TooManyRequests {
            retry_after_secs: wait.as_secs().max(1),
        }
        .audited());
    }

    // Verify against a dummy hash for unknown users to keep timing uniform.
    let stored_hash = admin
        .as_ref()
        .map_or_else(|| password::dummy_hash().to_owned(), |(_, _, h)| h.clone());
    let candidate = body.password;
    let verified = tokio::task::spawn_blocking(move || password::verify(&candidate, &stored_hash))
        .await
        .unwrap_or(false);

    let Some((user_id, username, _)) = admin.filter(|_| verified) else {
        auth.throttle.record_failure(&key, Instant::now());
        audit_best_effort(
            &state.db,
            login_entry(&body.username, Outcome::Denied, remote)
                .payload(json!({ "reason": "invalid credentials" })),
        )
        .await;
        return Err(ApiError::Unauthorized.audited());
    };

    auth.throttle.record_success(&key);

    let token = random_token();
    let expires_at = Utc::now() + auth.session_ttl;

    let mut tx = state.db.begin().await.map_err(db_error)?;
    sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_token(&token))
        .bind(user_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    audit::record(
        &mut *tx,
        login_entry(&username, Outcome::Success, remote).target("admin_user", user_id),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;

    let cookie = Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(auth.cookie_secure)
        .path("/")
        .max_age(time::Duration::seconds(auth.session_ttl.num_seconds()))
        .build();

    let mut response = Json(json!({ "username": username })).into_response();
    response.extensions_mut().insert(Audited);
    Ok((jar.add(cookie), response))
}

async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    jar: CookieJar,
    request_meta: RequestMeta,
) -> Result<(CookieJar, Response), ApiError> {
    let mut tx = state.db.begin().await.map_err(db_error)?;
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(hash_token(cookie.value()))
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    }
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "auth.logout", Outcome::Success)
            .target("admin_user", user.id)
            .remote_addr(request_meta.remote_addr),
    )
    .await
    .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    response.extensions_mut().insert(Audited);
    Ok((
        jar.remove(Cookie::build(SESSION_COOKIE).path("/")),
        response,
    ))
}

// --- helpers --------------------------------------------------------------

fn login_entry(username: &str, outcome: Outcome, remote: Option<String>) -> AuditEntry {
    // The attempted name is attacker-controlled; bound its size in the log.
    let actor: String = username.chars().take(MAX_USERNAME_LEN).collect();
    AuditEntry::new(actor, "auth.login", outcome).remote_addr(remote)
}

/// For failure paths that return an error response anyway: a broken audit
/// write must not mask the real outcome, but it must not be silent either.
async fn audit_best_effort(db: &PgPool, entry: AuditEntry) {
    if let Err(error) = audit::record(db, entry).await {
        tracing::error!(%error, "failed to write audit entry");
    }
}

async fn hash_blocking(password: String) -> Option<String> {
    tokio::task::spawn_blocking(move || password::hash(&password))
        .await
        .ok()
        .and_then(Result::ok)
}

/// Client details handlers want for the audit log.
struct RequestMeta {
    remote_addr: Option<String>,
}

#[axum::async_trait]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequestMeta {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let remote_addr = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(addr)| addr.ip().to_string());
        Ok(Self { remote_addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_must_match_host() {
        assert!(origin_matches_host(
            "http://localhost:4200",
            Some("localhost:4200")
        ));
        assert!(origin_matches_host(
            "https://Argowei.lan",
            Some("argowei.lan")
        ));
        assert!(!origin_matches_host(
            "http://evil.example",
            Some("localhost:4200")
        ));
        assert!(!origin_matches_host("http://localhost:4200", None));
        assert!(!origin_matches_host("null", Some("localhost:4200")));
    }

    #[test]
    fn session_tokens_are_random_and_hash_is_stable() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_ne!(hash_token(&a), hash_token(&b));
    }
}
