//! Port scans with nmap, started from the dashboard.
//!
//! - `POST /api/devices/{id}/scans` `{ "profile": "quick" | "service" | "full" }`
//!   queues a scan of the device's current IPv4 address (202). Refused with
//!   422 when the device has no address or the address is not on the local
//!   network ([`argowei_core::scan_target`]), 409 while another scan of the
//!   device is queued or running.
//! - `GET /api/scans/{id}` returns a scan with its ports.
//! - `GET /api/devices/{id}/scans` lists a device's scans, newest first.
//! - `POST /api/scans/{id}/cancel` stops a queued or running scan.
//! - `GET /api/scans/{id}/diff?against={other}` compares two completed scans
//!   of the same device (default: the previous completed one), see
//!   [`argowei_core::scan_diff`].
//!
//! Starting and cancelling are audited; outcomes are recorded as
//! `scan.completed` / `scan.failed` events. The work itself happens in
//! [`runner`]; results may be incomplete (firewalls, rate limiting).

pub mod runner;
pub mod scheduler;
pub mod schedules;
pub mod store;

use std::net::IpAddr;

use argowei_core::scan_diff::{self, ScanDiff};
use argowei_core::scan_profile::ScanProfile;
use argowei_core::scan_target::ScanTargets;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::audit::{self, mark_audited, AuditEntry, Outcome, RequestMeta};
use crate::auth::AuthUser;
use crate::error::{is_unique_violation, ApiError};
use crate::state::AppState;

pub use runner::{ScanConfig, ScanJob, ScanRunner};
use store::{Failure, Finished, Scan, ScanPort};

/// Scans listed per device.
const HISTORY_LIMIT: i64 = 50;

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(schedules::router())
        .route("/api/devices/:id/scans", post(start).get(history))
        .route("/api/scans/:id", get(show))
        .route("/api/scans/:id/cancel", post(cancel))
        .route("/api/scans/:id/diff", get(compare))
}

#[derive(Deserialize)]
struct StartScan {
    profile: String,
}

#[derive(Serialize)]
struct ScanWithPorts {
    #[serde(flatten)]
    scan: Scan,
    ports: Vec<ScanPort>,
}

fn parse_profile(value: &str) -> Result<ScanProfile, ApiError> {
    ScanProfile::parse(value)
        .ok_or_else(|| ApiError::BadRequest("profile must be quick, service or full".into()))
}

/// The address a scan of the device should target: its most recently seen
/// IPv4 address, if it may be scanned at all.
async fn scan_target(
    db: &PgPool,
    targets: &ScanTargets,
    device_id: i32,
) -> Result<IpAddr, ApiError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)")
        .bind(device_id)
        .fetch_one(db)
        .await?;
    if !exists {
        return Err(ApiError::NotFound("no such device"));
    }

    let address: Option<String> = sqlx::query_scalar(
        "SELECT ip_address FROM device_addresses \
         WHERE device_id = $1 AND protocol = 'ipv4' ORDER BY last_seen DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;
    let address = address.ok_or_else(|| {
        ApiError::Unprocessable("the device has no known IPv4 address to scan".into())
    })?;
    let ip: IpAddr = address.parse().map_err(|_| {
        ApiError::Unprocessable(format!(
            "the stored address \"{address}\" is not an IP address"
        ))
    })?;
    targets
        .check(ip)
        .map_err(|rejected| ApiError::Unprocessable(rejected.to_string()))?;
    Ok(ip)
}

/// Who asked for a scan, for `scans.requested_by` and the audit log.
pub struct Requester<'a> {
    /// A user name, or [`audit::SYSTEM`] for scheduled scans.
    pub actor: &'a str,
    pub remote_addr: Option<String>,
    /// The schedule that queued the scan, if any.
    pub schedule_id: Option<i32>,
}

/// Queues a scan of a device and hands it to the runner: the one way scans
/// start, whether a user or a schedule asks. Checks the target (404, 422),
/// enforces one active scan per device (409) and audits the start.
pub async fn enqueue(
    db: &PgPool,
    runner: &ScanRunner,
    device_id: i32,
    profile: ScanProfile,
    requester: Requester<'_>,
) -> Result<Scan, ApiError> {
    let target = scan_target(db, runner.targets(), device_id).await?;
    let target_text = target.to_string();

    let mut tx = db.begin().await?;
    let scan_id = match store::insert_queued(
        &mut *tx,
        device_id,
        &target_text,
        profile,
        requester.actor,
        requester.schedule_id,
    )
    .await
    {
        Ok(id) => id,
        // The partial unique index allows one active scan per device, also
        // when two requests race.
        Err(error) if is_unique_violation(&error) => {
            return Err(ApiError::Conflict(
                "a scan of this device is already queued or running",
            ))
        }
        Err(error) => return Err(error.into()),
    };
    audit::record(
        &mut *tx,
        AuditEntry::new(requester.actor, "scan.start", Outcome::Success)
            .target("device", device_id)
            .remote_addr(requester.remote_addr)
            .payload(json!({
                "scan_id": scan_id,
                "profile": profile,
                "target": target_text,
                "schedule_id": requester.schedule_id,
            })),
    )
    .await?;
    let scan = store::get(&mut *tx, scan_id)
        .await?
        .ok_or(ApiError::Unavailable)?;
    tx.commit().await?;

    runner.submit(
        db.clone(),
        ScanJob {
            scan_id,
            device_id,
            target,
            profile,
        },
    );
    Ok(scan)
}

async fn start(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(device_id): Path<i32>,
    Json(body): Json<StartScan>,
) -> Result<Response, ApiError> {
    let profile = parse_profile(&body.profile)?;
    let scan = enqueue(
        &state.db,
        &state.scans,
        device_id,
        profile,
        Requester {
            actor: &user.username,
            remote_addr: meta.remote_addr,
            schedule_id: None,
        },
    )
    .await?;
    Ok(mark_audited(
        (StatusCode::ACCEPTED, Json(scan)).into_response(),
    ))
}

async fn show(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ScanWithPorts>, ApiError> {
    let scan = store::get(&state.db, id)
        .await?
        .ok_or(ApiError::NotFound("no such scan"))?;
    let ports = store::ports(&state.db, id).await?;
    Ok(Json(ScanWithPorts { scan, ports }))
}

async fn history(
    State(state): State<AppState>,
    Path(device_id): Path<i32>,
) -> Result<Json<Vec<Scan>>, ApiError> {
    Ok(Json(
        store::for_device(&state.db, device_id, HISTORY_LIMIT).await?,
    ))
}

#[derive(Deserialize)]
struct DiffQuery {
    against: Option<i64>,
}

#[derive(Serialize)]
struct DiffResponse {
    older: Scan,
    newer: Scan,
    diff: ScanDiff,
}

/// `GET /api/scans/{id}/diff`: what changed between two completed scans of
/// one device. The older scan is always `older`, whichever way round the
/// ids were given.
async fn compare(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<DiffResponse>, ApiError> {
    let mut tx = state.db.begin().await?;
    let scan = store::get(&mut *tx, id)
        .await?
        .ok_or(ApiError::NotFound("no such scan"))?;
    let other_id = match query.against {
        Some(other) => other,
        None => store::previous_completed(&mut tx, scan.device_id, id, None)
            .await?
            .ok_or_else(|| {
                ApiError::Unprocessable(
                    "there is no earlier completed scan of this device to compare with".into(),
                )
            })?,
    };
    let other = store::get(&mut *tx, other_id)
        .await?
        .ok_or(ApiError::NotFound("no such scan"))?;
    if other.device_id != scan.device_id {
        return Err(ApiError::Unprocessable(
            "only scans of the same device can be compared".into(),
        ));
    }

    let (older, newer) = if other.id < scan.id {
        (other, scan)
    } else {
        (scan, other)
    };
    let not_completed = || ApiError::Unprocessable("only completed scans can be compared".into());
    let before = store::snapshot(&mut tx, older.id)
        .await?
        .ok_or_else(not_completed)?;
    let after = store::snapshot(&mut tx, newer.id)
        .await?
        .ok_or_else(not_completed)?;
    tx.commit().await?;

    Ok(Json(DiffResponse {
        diff: scan_diff::diff(&before.side(), &after.side()),
        older,
        newer,
    }))
}

async fn cancel(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let mut tx = state.db.begin().await?;
    let scan = store::get(&mut *tx, id)
        .await?
        .ok_or(ApiError::NotFound("no such scan"))?;
    let profile = parse_profile(&scan.profile)?;
    let finished = Finished {
        scan_id: id,
        device_id: scan.device_id,
        profile,
        target: &scan.target_ip,
    };
    let stopped = store::store_failure(
        &mut tx,
        &finished,
        Failure::Cancelled,
        &format!("cancelled by {}", user.username),
        &["queued", "running"],
    )
    .await?;
    if !stopped {
        return Err(ApiError::Conflict(
            "the scan is no longer queued or running",
        ));
    }
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "scan.cancel", Outcome::Success)
            .target("scan", id.to_string())
            .remote_addr(meta.remote_addr)
            .payload(json!({ "device_id": scan.device_id, "previous_status": scan.status })),
    )
    .await?;
    let updated = store::get(&mut *tx, id)
        .await?
        .ok_or(ApiError::Unavailable)?;
    tx.commit().await?;

    // Stored first, then stopped: whatever nmap returns now is discarded.
    state.scans.cancel(id);
    Ok(mark_audited(Json(updated).into_response()))
}
