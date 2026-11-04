//! Alerts for things the user should look at, starting with "a device we have
//! never seen appeared".
//!
//! A fresh install would otherwise alert for every device already on the
//! network, so each interface has a *baseline*: devices found in its first
//! scan, and within an optional window after it, are learned silently. After
//! that every new device raises exactly one alert (the database enforces it).

use std::time::Duration;

use argowei_core::oui;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};

use crate::audit::{self, mark_audited, AuditEntry, Outcome, RequestMeta};
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

pub const NEW_DEVICE: &str = "device.new";
const BASELINE_WINDOW_KEY: &str = "baseline_window_secs";

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;

// --- baseline -------------------------------------------------------------

/// Stores how long after an interface's first scan new devices are still
/// learned silently. Called at startup; the value lives in the database, so a
/// later settings screen can change it without a restart.
pub async fn apply_baseline_window(db: &PgPool, window: Duration) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO system_settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(BASELINE_WINDOW_KEY)
    .bind(json!(window.as_secs()))
    .execute(db)
    .await?;
    Ok(())
}

async fn baseline_window<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
) -> sqlx::Result<chrono::Duration> {
    let secs: Option<Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(BASELINE_WINDOW_KEY)
            .fetch_optional(executor)
            .await?;
    let secs = secs.and_then(|v| v.as_i64()).unwrap_or(0);
    Ok(chrono::Duration::seconds(secs))
}

/// Whether a scan of `interface` at `seen_at` still counts as the baseline.
///
/// The first scan of an interface starts its baseline (and is part of it);
/// devices are then learned silently until `window` has passed. A newly added
/// interface gets its own baseline, so configuring a second network later
/// does not flood the user either.
pub async fn scan_in_baseline(
    tx: &mut Transaction<'_, Postgres>,
    interface: &str,
    seen_at: DateTime<Utc>,
) -> sqlx::Result<bool> {
    sqlx::query(
        "INSERT INTO baselines (interface, started_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(interface)
    .bind(seen_at)
    .execute(&mut **tx)
    .await?;
    let started_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT started_at FROM baselines WHERE interface = $1")
            .bind(interface)
            .fetch_one(&mut **tx)
            .await?;
    let window = baseline_window(&mut **tx).await?;

    Ok(seen_at <= started_at + window)
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BaselineState {
    /// No scan has completed yet: the first one will become the baseline.
    Pending,
    /// New devices are being learned silently until `ends_at`.
    Learning,
    /// Baseline over: new devices raise alerts.
    Done,
}

#[derive(Serialize)]
pub struct BaselineStatus {
    pub state: BaselineState,
    pub window_secs: i64,
    /// When silent learning ends; only set while `state` is `learning`.
    pub ends_at: Option<DateTime<Utc>>,
}

/// Pure, so the three states are easy to test with a clock.
pub fn baseline_status(
    started: &[DateTime<Utc>],
    window: chrono::Duration,
    now: DateTime<Utc>,
) -> BaselineStatus {
    let latest_end = started.iter().map(|at| *at + window).max();
    let (state, ends_at) = match latest_end {
        None => (BaselineState::Pending, None),
        Some(end) if end > now => (BaselineState::Learning, Some(end)),
        Some(_) => (BaselineState::Done, None),
    };
    BaselineStatus {
        state,
        window_secs: window.num_seconds(),
        ends_at,
    }
}

// --- raising alerts -------------------------------------------------------

/// Raises the one alert for a newly seen device. Safe to call again: the
/// unique index turns a repeat into a no-op. Returns whether one was created.
pub async fn raise_new_device(
    tx: &mut Transaction<'_, Postgres>,
    device_id: i32,
    seen_at: DateTime<Utc>,
    interface: &str,
    scan_id: i64,
    mac: &str,
    ip: &str,
) -> sqlx::Result<bool> {
    let payload = json!({
        "mac": mac,
        "vendor": oui::lookup(mac).vendor,
        "interface": interface,
        "ip": ip,
        "scan_id": scan_id,
    });

    let result = sqlx::query(
        "INSERT INTO alerts (type, severity, device_id, created_at, payload) \
         VALUES ($1, 'warning', $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(NEW_DEVICE)
    .bind(device_id)
    .bind(seen_at)
    .bind(payload)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected() == 1)
}

// --- API ------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/alerts", get(list))
        .route("/api/alerts/status", get(status))
        .route("/api/alerts/:id/acknowledge", post(acknowledge))
        .route("/api/alerts/:id/resolve", post(resolve))
}

#[derive(sqlx::FromRow)]
struct AlertRow {
    id: i64,
    r#type: String,
    severity: String,
    status: String,
    created_at: DateTime<Utc>,
    acknowledged_at: Option<DateTime<Utc>>,
    acknowledged_by: Option<String>,
    resolved_at: Option<DateTime<Utc>>,
    resolved_by: Option<String>,
    payload: Value,
    device_id: Option<i32>,
    device_name: Option<String>,
    device_label: Option<String>,
    device_mac: Option<String>,
}

#[derive(Serialize)]
struct DeviceSummary {
    id: i32,
    display_name: String,
    mac_address: String,
    vendor: Option<&'static str>,
}

#[derive(Serialize)]
struct Alert {
    id: i64,
    r#type: String,
    severity: String,
    status: String,
    created_at: DateTime<Utc>,
    acknowledged_at: Option<DateTime<Utc>>,
    acknowledged_by: Option<String>,
    resolved_at: Option<DateTime<Utc>>,
    resolved_by: Option<String>,
    /// `null` once the device itself is gone.
    device: Option<DeviceSummary>,
    /// What was observed, plus `suggested_actions`.
    payload: Value,
}

impl From<AlertRow> for Alert {
    fn from(row: AlertRow) -> Self {
        let device = match (row.device_id, row.device_mac) {
            (Some(id), Some(mac_address)) => Some(DeviceSummary {
                id,
                display_name: row
                    .device_label
                    .or(row.device_name)
                    .unwrap_or_else(|| mac_address.clone()),
                vendor: oui::lookup(&mac_address).vendor,
                mac_address,
            }),
            _ => None,
        };

        let mut payload = row.payload;
        if row.r#type == NEW_DEVICE {
            if let Some(object) = payload.as_object_mut() {
                object.insert("suggested_actions".into(), suggested_actions());
            }
        }

        Alert {
            id: row.id,
            r#type: row.r#type,
            severity: row.severity,
            status: row.status,
            created_at: row.created_at,
            acknowledged_at: row.acknowledged_at,
            acknowledged_by: row.acknowledged_by,
            resolved_at: row.resolved_at,
            resolved_by: row.resolved_by,
            device,
            payload,
        }
    }
}

/// What the user can do about a new device. Computed when read, not stored,
/// so an action becomes available as soon as the system can carry it out.
/// Trusting and restricting only classify the device; blocking and
/// quarantine need enforcement (gateway or router integration), which does
/// not exist yet.
fn suggested_actions() -> Value {
    const NEEDS_ENFORCEMENT: &str = "Needs gateway or router integration, which is not set up yet.";
    json!([
        { "action": "trust", "label": "Trust", "available": true,
          "effect": "Sets the trust level to trusted." },
        { "action": "restrict", "label": "Restrict", "available": true,
          "effect": "Sets the trust level to restricted." },
        { "action": "block", "label": "Block", "available": false,
          "reason": NEEDS_ENFORCEMENT },
        { "action": "quarantine", "label": "Quarantine", "available": false,
          "reason": NEEDS_ENFORCEMENT },
    ])
}

const SELECT_ALERTS: &str = "SELECT a.id, a.type, a.severity, a.status, a.created_at, \
        a.acknowledged_at, a.acknowledged_by, a.resolved_at, a.resolved_by, a.payload, \
        a.device_id, d.name AS device_name, d.label AS device_label, \
        d.mac_address AS device_mac \
    FROM alerts a LEFT JOIN devices d ON d.id = a.device_id";

#[derive(Deserialize)]
struct ListQuery {
    /// `active` (open and acknowledged, the default), `open`, `acknowledged`,
    /// `resolved` or `all`.
    status: Option<String>,
    /// Cursor: only alerts with a lower id.
    before: Option<i64>,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct ListResponse {
    items: Vec<Alert>,
    next_before: Option<i64>,
}

fn statuses(filter: Option<&str>) -> Result<Vec<&'static str>, ApiError> {
    Ok(match filter.unwrap_or("active") {
        "active" => vec!["open", "acknowledged"],
        "open" => vec!["open"],
        "acknowledged" => vec!["acknowledged"],
        "resolved" => vec!["resolved"],
        "all" => vec!["open", "acknowledged", "resolved"],
        _ => {
            return Err(ApiError::BadRequest(
                "status must be active, open, acknowledged, resolved or all".into(),
            ))
        }
    })
}

async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, ApiError> {
    let statuses = statuses(query.status.as_deref())?;
    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);

    let mut rows: Vec<AlertRow> = sqlx::query_as(&format!(
        "{SELECT_ALERTS} WHERE a.status = ANY($1) AND ($2::bigint IS NULL OR a.id < $2) \
         ORDER BY a.id DESC LIMIT $3"
    ))
    .bind(&statuses)
    .bind(query.before)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;

    let next_before = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        rows.last().map(|row| row.id)
    } else {
        None
    };

    Ok(Json(ListResponse {
        items: rows.into_iter().map(Alert::from).collect(),
        next_before,
    }))
}

#[derive(Serialize)]
struct StatusResponse {
    open: i64,
    acknowledged: i64,
    baseline: BaselineStatus,
}

async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, ApiError> {
    let (open, acknowledged): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status = 'open'), \
                count(*) FILTER (WHERE status = 'acknowledged') FROM alerts",
    )
    .fetch_one(&state.db)
    .await?;

    let started: Vec<DateTime<Utc>> = sqlx::query_scalar("SELECT started_at FROM baselines")
        .fetch_all(&state.db)
        .await?;
    let window = baseline_window(&state.db).await?;

    Ok(Json(StatusResponse {
        open,
        acknowledged,
        baseline: baseline_status(&started, window, Utc::now()),
    }))
}

#[derive(Clone, Copy)]
enum Transition {
    Acknowledge,
    Resolve,
}

async fn acknowledge(
    state: State<AppState>,
    user: Extension<AuthUser>,
    meta: RequestMeta,
    id: Path<i64>,
) -> Result<Response, ApiError> {
    transition(state, user, meta, id, Transition::Acknowledge).await
}

async fn resolve(
    state: State<AppState>,
    user: Extension<AuthUser>,
    meta: RequestMeta,
    id: Path<i64>,
) -> Result<Response, ApiError> {
    transition(state, user, meta, id, Transition::Resolve).await
}

/// open -> acknowledged -> resolved; an alert can also go straight from open
/// to resolved. Repeating a step is a harmless no-op; going back is refused.
async fn transition(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i64>,
    step: Transition,
) -> Result<Response, ApiError> {
    let mut tx = state.db.begin().await?;
    let (current, kind, device_id): (String, String, Option<i32>) =
        sqlx::query_as("SELECT status, type, device_id FROM alerts WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound("no such alert"))?;

    let (action, new_status) = match (step, current.as_str()) {
        (Transition::Acknowledge, "open") => ("alert.acknowledge", Some("acknowledged")),
        (Transition::Acknowledge, "acknowledged") => ("alert.acknowledge", None),
        (Transition::Acknowledge, _) => {
            return Err(ApiError::Conflict("the alert is already resolved"))
        }
        (Transition::Resolve, "resolved") => ("alert.resolve", None),
        (Transition::Resolve, _) => ("alert.resolve", Some("resolved")),
    };

    let changed = new_status.is_some();
    if let Some(new_status) = new_status {
        let sql = if new_status == "acknowledged" {
            "UPDATE alerts SET status = 'acknowledged', acknowledged_at = now(), \
                 acknowledged_by = $2 WHERE id = $1"
        } else {
            "UPDATE alerts SET status = 'resolved', resolved_at = now(), \
                 resolved_by = $2 WHERE id = $1"
        };
        sqlx::query(sql)
            .bind(id)
            .bind(&user.username)
            .execute(&mut *tx)
            .await?;
        audit::record(
            &mut *tx,
            AuditEntry::new(&user.username, action, Outcome::Success)
                .target("alert", id)
                .remote_addr(meta.remote_addr)
                .payload(json!({ "type": kind, "device_id": device_id, "from": current })),
        )
        .await?;
    }
    tx.commit().await?;

    let row: AlertRow = sqlx::query_as(&format!("{SELECT_ALERTS} WHERE a.id = $1"))
        .bind(id)
        .fetch_one(&state.db)
        .await?;

    let response = (StatusCode::OK, Json(Alert::from(row))).into_response();
    let response = if changed {
        // Audited above; a request that changed nothing is left to the
        // middleware's generic entry.
        mark_audited(response)
    } else {
        response
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, hour, 0, 0).unwrap()
    }

    #[test]
    fn without_any_scan_the_baseline_is_pending() {
        let status = baseline_status(&[], chrono::Duration::hours(24), at(12));

        assert_eq!(status.state, BaselineState::Pending);
        assert!(status.ends_at.is_none());
    }

    #[test]
    fn within_the_window_the_network_is_being_learned() {
        let status = baseline_status(&[at(10)], chrono::Duration::hours(24), at(12));

        assert_eq!(status.state, BaselineState::Learning);
        assert_eq!(status.ends_at, Some(at(10) + chrono::Duration::hours(24)));
        assert_eq!(status.window_secs, 24 * 3600);
    }

    #[test]
    fn after_the_window_the_baseline_is_done() {
        let status = baseline_status(&[at(1)], chrono::Duration::hours(1), at(12));

        assert_eq!(status.state, BaselineState::Done);
        assert!(status.ends_at.is_none());
    }

    #[test]
    fn with_no_window_only_the_first_scan_counts() {
        // The first scan has completed; nothing is left to learn afterwards.
        assert_eq!(
            baseline_status(&[at(10)], chrono::Duration::zero(), at(10)).state,
            BaselineState::Done
        );
    }

    #[test]
    fn the_latest_interface_decides_when_learning_ends() {
        let status = baseline_status(&[at(1), at(9)], chrono::Duration::hours(4), at(11));

        assert_eq!(status.state, BaselineState::Learning);
        assert_eq!(status.ends_at, Some(at(13)));
    }

    #[test]
    fn only_trust_and_restrict_are_offered_until_enforcement_exists() {
        let actions = suggested_actions();
        let available: Vec<(&str, bool)> = actions
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["action"].as_str().unwrap(),
                    a["available"].as_bool().unwrap(),
                )
            })
            .collect();

        assert_eq!(
            available,
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
            .contains("not set up"));
    }

    #[test]
    fn status_filters_map_to_alert_states() {
        assert_eq!(statuses(None).unwrap(), ["open", "acknowledged"]);
        assert_eq!(statuses(Some("resolved")).unwrap(), ["resolved"]);
        assert_eq!(statuses(Some("all")).unwrap().len(), 3);
        assert!(statuses(Some("bogus")).is_err());
    }
}
