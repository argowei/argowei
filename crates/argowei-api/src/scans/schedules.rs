//! Scan schedules: which devices to scan, with which profile, when.
//!
//! - `GET /api/scan-schedules` lists them with their next three runs.
//! - `POST /api/scan-schedules` creates one (201).
//! - `PATCH /api/scan-schedules/{id}` changes fields, e.g. `{ "enabled": false }`.
//! - `DELETE /api/scan-schedules/{id}` removes one (204); its past scans stay.
//! - `GET /api/scan-schedules/preview?cron=...` checks an expression and
//!   returns its next runs, for the form.
//!
//! Invalid or too frequent cron expressions and unknown targets are a 422.
//! Every change is audited with the user; the runs themselves are audited
//! as `system` (see [`super::scheduler`]).

use argowei_core::scan_profile::ScanProfile;
use argowei_core::scan_schedule::{CronSchedule, ScheduleTarget};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgExecutor, PgPool};

use crate::audit::{self, mark_audited, AuditEntry, Outcome, RequestMeta};
use crate::auth::AuthUser;
use crate::error::{is_unique_violation, ApiError};
use crate::state::AppState;
use crate::validate;

const MAX_NAME_CHARS: usize = 64;
/// Runs shown as a preview in lists and the form.
const PREVIEW_RUNS: usize = 3;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/scan-schedules", get(list).post(create))
        .route("/api/scan-schedules/preview", get(preview))
        .route(
            "/api/scan-schedules/:id",
            axum::routing::patch(update).delete(remove),
        )
}

/// A stored schedule.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduleRow {
    pub id: i32,
    pub name: String,
    pub cron: String,
    pub profile: String,
    pub target_kind: String,
    pub target_id: Option<i32>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
}

impl ScheduleRow {
    pub fn target(&self) -> Option<ScheduleTarget> {
        ScheduleTarget::from_columns(&self.target_kind, self.target_id)
    }

    pub fn profile(&self) -> Option<ScanProfile> {
        ScanProfile::parse(&self.profile)
    }
}

const SELECT_SCHEDULES: &str = "SELECT id, name, cron, profile, target_kind, target_id, enabled, \
        created_by, created_at, last_run_at, next_run_at FROM scan_schedules";

pub async fn get_schedule<'e, E: PgExecutor<'e>>(
    executor: E,
    id: i32,
) -> sqlx::Result<Option<ScheduleRow>> {
    sqlx::query_as(&format!("{SELECT_SCHEDULES} WHERE id = $1"))
        .bind(id)
        .fetch_optional(executor)
        .await
}

/// A schedule as the API returns it.
#[derive(Serialize)]
struct Schedule {
    id: i32,
    name: String,
    cron: String,
    /// What the expression means, e.g. "At 03:00".
    description: Option<String>,
    profile: String,
    target: Option<ScheduleTarget>,
    /// The target's name (device label or name, group name); `null` for
    /// "all" or a target that no longer exists.
    target_name: Option<String>,
    enabled: bool,
    created_by: String,
    created_at: DateTime<Utc>,
    last_run_at: Option<DateTime<Utc>>,
    next_run_at: Option<DateTime<Utc>>,
    /// The next runs after `next_run_at`, in the server's time zone.
    upcoming: Vec<DateTime<Utc>>,
}

async fn target_name(db: &PgPool, target: Option<ScheduleTarget>) -> sqlx::Result<Option<String>> {
    match target {
        Some(ScheduleTarget::Device(id)) => {
            sqlx::query_scalar("SELECT coalesce(label, name) FROM devices WHERE id = $1")
                .bind(id)
                .fetch_optional(db)
                .await
        }
        Some(ScheduleTarget::Group(id)) => {
            sqlx::query_scalar("SELECT name FROM device_groups WHERE id = $1")
                .bind(id)
                .fetch_optional(db)
                .await
        }
        _ => Ok(None),
    }
}

async fn to_api(db: &PgPool, row: ScheduleRow) -> sqlx::Result<Schedule> {
    let parsed = CronSchedule::parse(&row.cron).ok();
    let upcoming = match (&parsed, row.next_run_at, row.enabled) {
        (Some(cron), Some(next), true) => std::iter::once(next)
            .chain(
                cron.upcoming(&next.with_timezone(&Local), PREVIEW_RUNS - 1)
                    .into_iter()
                    .map(|t| t.with_timezone(&Utc)),
            )
            .collect(),
        _ => Vec::new(),
    };
    let target = row.target();
    Ok(Schedule {
        target_name: target_name(db, target).await?,
        id: row.id,
        description: parsed.map(|c| c.describe()),
        name: row.name,
        cron: row.cron,
        profile: row.profile,
        target,
        enabled: row.enabled,
        created_by: row.created_by,
        created_at: row.created_at,
        last_run_at: row.last_run_at,
        next_run_at: row.next_run_at,
        upcoming,
    })
}

// --- validation -------------------------------------------------------------

fn parse_cron(expression: &str) -> Result<CronSchedule, ApiError> {
    CronSchedule::parse(expression.trim()).map_err(|e| ApiError::Unprocessable(e.to_string()))
}

fn parse_profile(value: &str) -> Result<ScanProfile, ApiError> {
    ScanProfile::parse(value)
        .ok_or_else(|| ApiError::BadRequest("profile must be quick, service or full".into()))
}

/// The first run of a schedule saved now.
fn first_run(cron: &CronSchedule) -> Result<DateTime<Utc>, ApiError> {
    cron.next_after(&Local::now())
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| ApiError::Unprocessable("the cron expression never matches a date".into()))
}

async fn check_target(db: &PgPool, target: ScheduleTarget) -> Result<(), ApiError> {
    let exists: bool = match target {
        ScheduleTarget::Device(id) => {
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)")
                .bind(id)
                .fetch_one(db)
                .await?
        }
        ScheduleTarget::Group(id) => {
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM device_groups WHERE id = $1)")
                .bind(id)
                .fetch_one(db)
                .await?
        }
        ScheduleTarget::All => true,
    };
    if exists {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(format!(
            "no such {} to scan",
            target.kind()
        )))
    }
}

fn duplicate_name() -> ApiError {
    ApiError::Conflict("a schedule with this name already exists")
}

// --- handlers ---------------------------------------------------------------

async fn list(State(state): State<AppState>) -> Result<Json<Vec<Schedule>>, ApiError> {
    let rows: Vec<ScheduleRow> =
        sqlx::query_as(&format!("{SELECT_SCHEDULES} ORDER BY lower(name)"))
            .fetch_all(&state.db)
            .await?;
    let mut schedules = Vec::with_capacity(rows.len());
    for row in rows {
        schedules.push(to_api(&state.db, row).await?);
    }
    Ok(Json(schedules))
}

#[derive(Deserialize)]
struct PreviewQuery {
    cron: String,
}

#[derive(Serialize)]
struct Preview {
    description: String,
    upcoming: Vec<DateTime<Utc>>,
}

async fn preview(Query(query): Query<PreviewQuery>) -> Result<Json<Preview>, ApiError> {
    let cron = parse_cron(&query.cron)?;
    Ok(Json(Preview {
        description: cron.describe(),
        upcoming: cron
            .upcoming(&Local::now(), PREVIEW_RUNS)
            .into_iter()
            .map(|t| t.with_timezone(&Utc))
            .collect(),
    }))
}

#[derive(Deserialize)]
struct CreateSchedule {
    name: String,
    cron: String,
    profile: String,
    target: ScheduleTarget,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Json(body): Json<CreateSchedule>,
) -> Result<Response, ApiError> {
    let name = validate::single_line(&body.name, "name", 1..=MAX_NAME_CHARS)?;
    let profile = parse_profile(&body.profile)?;
    let cron = parse_cron(&body.cron)?;
    check_target(&state.db, body.target).await?;
    let next_run_at = body.enabled.then(|| first_run(&cron)).transpose()?;

    let mut tx = state.db.begin().await?;
    let id: i32 = match sqlx::query_scalar(
        "INSERT INTO scan_schedules \
             (name, cron, profile, target_kind, target_id, enabled, created_by, next_run_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(&name)
    .bind(body.cron.trim())
    .bind(profile.as_str())
    .bind(body.target.kind())
    .bind(body.target.id())
    .bind(body.enabled)
    .bind(&user.username)
    .bind(next_run_at)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(error) if is_unique_violation(&error) => return Err(duplicate_name()),
        Err(error) => return Err(error.into()),
    };
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "scan_schedule.create", Outcome::Success)
            .target("scan_schedule", id)
            .remote_addr(meta.remote_addr)
            .payload(json!({
                "name": name,
                "cron": body.cron.trim(),
                "profile": profile,
                "target": body.target,
                "enabled": body.enabled,
            })),
    )
    .await?;
    let row = get_schedule(&mut *tx, id)
        .await?
        .ok_or(ApiError::Unavailable)?;
    tx.commit().await?;
    state.schedule_changed.notify_one();

    let schedule = to_api(&state.db, row).await?;
    Ok(mark_audited(
        (StatusCode::CREATED, Json(schedule)).into_response(),
    ))
}

/// Fields to change; omitted fields stay as they are.
#[derive(Deserialize)]
struct UpdateSchedule {
    name: Option<String>,
    cron: Option<String>,
    profile: Option<String>,
    target: Option<ScheduleTarget>,
    enabled: Option<bool>,
}

async fn update(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i32>,
    Json(body): Json<UpdateSchedule>,
) -> Result<Response, ApiError> {
    let name = body
        .name
        .as_deref()
        .map(|n| validate::single_line(n, "name", 1..=MAX_NAME_CHARS))
        .transpose()?;
    let profile = body.profile.as_deref().map(parse_profile).transpose()?;
    if let Some(target) = body.target {
        check_target(&state.db, target).await?;
    }

    let mut tx = state.db.begin().await?;
    // Locked until commit: the audited "before" values are the ones replaced.
    let old: ScheduleRow = sqlx::query_as(&format!("{SELECT_SCHEDULES} WHERE id = $1 FOR UPDATE"))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound("no such schedule"))?;

    let cron_text = body
        .cron
        .as_deref()
        .map(str::trim)
        .unwrap_or(&old.cron)
        .to_owned();
    let cron = parse_cron(&cron_text)?;
    let enabled = body.enabled.unwrap_or(old.enabled);
    let target = body.target.or(old.target()).ok_or(ApiError::Unavailable)?;
    // A new expression or re-enabling starts counting from now; otherwise
    // the stored next run stays (editing the name must not skip a run).
    let new_name = name.unwrap_or_else(|| old.name.clone());
    let new_profile = profile.map_or_else(|| old.profile.clone(), |p| p.as_str().to_owned());
    let next_run_at = match (enabled, old.next_run_at) {
        (false, _) => None,
        (true, Some(next)) if body.cron.is_none() && old.enabled => Some(next),
        (true, _) => Some(first_run(&cron)?),
    };

    let updated = sqlx::query(
        "UPDATE scan_schedules SET name = $2, cron = $3, profile = $4, target_kind = $5, \
             target_id = $6, enabled = $7, next_run_at = $8 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(&new_name)
    .bind(&cron_text)
    .bind(&new_profile)
    .bind(target.kind())
    .bind(target.id())
    .bind(enabled)
    .bind(next_run_at)
    .execute(&mut *tx)
    .await;
    match updated {
        Err(error) if is_unique_violation(&error) => return Err(duplicate_name()),
        other => other?,
    };
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "scan_schedule.update", Outcome::Success)
            .target("scan_schedule", id)
            .remote_addr(meta.remote_addr)
            .payload(json!({
                "before": {
                    "name": old.name, "cron": old.cron, "profile": old.profile,
                    "target": old.target(), "enabled": old.enabled,
                },
                "after": {
                    "name": new_name, "cron": cron_text,
                    "profile": new_profile,
                    "target": target, "enabled": enabled,
                },
            })),
    )
    .await?;
    let row = get_schedule(&mut *tx, id)
        .await?
        .ok_or(ApiError::Unavailable)?;
    tx.commit().await?;
    state.schedule_changed.notify_one();

    let schedule = to_api(&state.db, row).await?;
    Ok(mark_audited(Json(schedule).into_response()))
}

async fn remove(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i32>,
) -> Result<Response, ApiError> {
    let mut tx = state.db.begin().await?;
    let removed: Option<String> =
        sqlx::query_scalar("DELETE FROM scan_schedules WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let name = removed.ok_or(ApiError::NotFound("no such schedule"))?;
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "scan_schedule.delete", Outcome::Success)
            .target("scan_schedule", id)
            .remote_addr(meta.remote_addr)
            .payload(json!({ "name": name })),
    )
    .await?;
    tx.commit().await?;
    state.schedule_changed.notify_one();
    Ok(mark_audited(StatusCode::NO_CONTENT.into_response()))
}
