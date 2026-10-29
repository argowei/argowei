//! Append-only audit log of administrative actions.
//!
//! Handlers that change state call [`record`] with the same transaction as
//! the change, so the log entry and the change commit or roll back together.
//! As a safety net, [`audit_mutations`] writes a generic entry for every
//! mutating request whose handler did not record one itself, so a newly added
//! route cannot be forgotten.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, MatchedPath, Query, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgExecutor;

use crate::auth::AuthUser;
use crate::state::AppState;

/// Actor recorded when no authenticated user is involved.
pub const ANONYMOUS: &str = "anonymous";

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Failure,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Denied => "denied",
            Outcome::Failure => "failure",
        }
    }

    fn from_status(status: StatusCode) -> Self {
        match status {
            s if s.is_success() || s.is_redirection() => Outcome::Success,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
                Outcome::Denied
            }
            _ => Outcome::Failure,
        }
    }
}

pub struct AuditEntry {
    pub actor: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub outcome: Outcome,
    pub remote_addr: Option<String>,
    pub payload: Value,
}

impl AuditEntry {
    pub fn new(actor: impl Into<String>, action: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            target_type: None,
            target_id: None,
            outcome,
            remote_addr: None,
            payload: json!({}),
        }
    }

    pub fn target(mut self, target_type: impl Into<String>, id: impl ToString) -> Self {
        self.target_type = Some(target_type.into());
        self.target_id = Some(id.to_string());
        self
    }

    pub fn remote_addr(mut self, addr: Option<String>) -> Self {
        self.remote_addr = addr;
        self
    }

    pub fn payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }
}

/// Marker placed in a response's extensions by handlers that wrote their own
/// audit entry, telling [`audit_mutations`] not to add a generic one.
#[derive(Clone, Copy)]
pub struct Audited;

/// Inserts an audit entry. Pass a transaction to commit it with the change.
/// Secrets in the payload are redacted before insert.
pub async fn record<'e, E: PgExecutor<'e>>(executor: E, mut entry: AuditEntry) -> sqlx::Result<()> {
    redact(&mut entry.payload);

    sqlx::query(
        "INSERT INTO audit_log \
         (actor, action, target_type, target_id, outcome, remote_addr, payload) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&entry.actor)
    .bind(&entry.action)
    .bind(&entry.target_type)
    .bind(&entry.target_id)
    .bind(entry.outcome.as_str())
    .bind(&entry.remote_addr)
    .bind(&entry.payload)
    .execute(executor)
    .await?;

    Ok(())
}

const SENSITIVE_KEY_PARTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "hash",
    "authorization",
    "cookie",
    "api_key",
    "apikey",
];

/// Replaces values of secret-looking keys, recursively, so credentials can
/// never end up in the log even if a caller passes a raw request body.
pub fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                let key = key.to_ascii_lowercase();
                if SENSITIVE_KEY_PARTS.iter().any(|part| key.contains(part)) {
                    *val = Value::String("[redacted]".into());
                } else {
                    redact(val);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

pub fn remote_addr_of(request: &Request) -> Option<String> {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
}

/// Audits every mutating request that its handler did not audit itself.
/// Must wrap the authentication layer so denied (401/403) requests are
/// recorded too.
pub async fn audit_mutations(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| path.clone());
    let remote_addr = remote_addr_of(&request);

    let response = next.run(request).await;

    if response.extensions().get::<Audited>().is_none() {
        let actor = response
            .extensions()
            .get::<AuthUser>()
            .map_or_else(|| ANONYMOUS.to_owned(), |user| user.username.clone());

        let entry = AuditEntry::new(
            actor,
            format!("http.{method} {route}"),
            Outcome::from_status(response.status()),
        )
        .remote_addr(remote_addr)
        .payload(json!({ "path": path, "status": response.status().as_u16() }));

        if let Err(error) = record(&state.db, entry).await {
            tracing::error!(%error, "failed to write audit entry");
        }
    }

    response
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/audit-log", get(list))
}

#[derive(Deserialize)]
struct ListQuery {
    actor: Option<String>,
    action: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    /// Cursor: return entries with an id lower than this.
    before: Option<i64>,
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditRecord {
    id: i64,
    occurred_at: DateTime<Utc>,
    actor: String,
    action: String,
    target_type: Option<String>,
    target_id: Option<String>,
    outcome: String,
    remote_addr: Option<String>,
    payload: Value,
}

#[derive(Serialize)]
struct ListResponse {
    items: Vec<AuditRecord>,
    /// Pass as `before` to fetch the next (older) page; absent on the last page.
    next_before: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, StatusCode> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);

    let mut items = sqlx::query_as::<_, AuditRecord>(
        "SELECT id, occurred_at, actor, action, target_type, target_id, outcome, \
                remote_addr, payload \
         FROM audit_log \
         WHERE ($1::text IS NULL OR actor = $1) \
           AND ($2::text IS NULL OR action = $2) \
           AND ($3::timestamptz IS NULL OR occurred_at >= $3) \
           AND ($4::timestamptz IS NULL OR occurred_at <= $4) \
           AND ($5::bigint IS NULL OR id < $5) \
         ORDER BY id DESC \
         LIMIT $6",
    )
    .bind(&query.actor)
    .bind(&query.action)
    .bind(query.from)
    .bind(query.to)
    .bind(query.before)
    // One extra row tells us whether another page exists.
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await
    .map_err(|error| {
        tracing::error!(%error, "failed to list audit log");
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    let next_before = if items.len() as i64 > limit {
        items.truncate(limit as usize);
        items.last().map(|last| last.id)
    } else {
        None
    };

    Ok(Json(ListResponse { items, next_before }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_keys_recursively() {
        let mut value = json!({
            "username": "admin",
            "password": "hunter2",
            "nested": { "Api_Key": "k", "ok": 1, "list": [{ "session_token": "t" }] },
        });

        redact(&mut value);

        assert_eq!(value["username"], "admin");
        assert_eq!(value["password"], "[redacted]");
        assert_eq!(value["nested"]["Api_Key"], "[redacted]");
        assert_eq!(value["nested"]["ok"], 1);
        assert_eq!(value["nested"]["list"][0]["session_token"], "[redacted]");
    }

    #[test]
    fn maps_status_to_outcome() {
        assert_eq!(Outcome::from_status(StatusCode::OK), Outcome::Success);
        assert_eq!(
            Outcome::from_status(StatusCode::UNAUTHORIZED),
            Outcome::Denied
        );
        assert_eq!(Outcome::from_status(StatusCode::FORBIDDEN), Outcome::Denied);
        assert_eq!(
            Outcome::from_status(StatusCode::BAD_REQUEST),
            Outcome::Failure
        );
        assert_eq!(
            Outcome::from_status(StatusCode::INTERNAL_SERVER_ERROR),
            Outcome::Failure
        );
    }
}
