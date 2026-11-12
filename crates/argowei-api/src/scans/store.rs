//! Reading and writing `scans` and `scan_ports`.
//!
//! Status changes are conditional (`WHERE status = ...`), so the request
//! handlers and the runner can race (a cancel while nmap finishes, a restart
//! while a scan runs) and exactly one of them wins; the loser's update
//! simply matches no row.

use argowei_collector::nmap::NmapRun;
use argowei_core::events::{Event, ScanCompleted, ScanFailed};
use argowei_core::scan_profile::ScanProfile;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

use crate::events;

/// How a scan that produced no result ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Failed,
    TimedOut,
    Cancelled,
}

impl Failure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A scan as the API returns it.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Scan {
    pub id: i64,
    pub device_id: i32,
    pub target_ip: String,
    pub profile: String,
    /// `queued`, `running`, `completed`, `failed`, `cancelled` or `timed_out`.
    pub status: String,
    pub requested_by: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub nmap_version: Option<String>,
    /// Open ports found (0 until the scan completed).
    pub open_ports: i64,
}

/// One port of a scan's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct ScanPort {
    pub protocol: String,
    pub port: i32,
    pub state: String,
    pub reason: Option<String>,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
}

const SELECT_SCAN: &str = "SELECT s.id, s.device_id, s.target_ip, s.profile, s.status, \
        s.requested_by, s.created_at, s.started_at, s.finished_at, s.error, s.nmap_version, \
        (SELECT count(*) FROM scan_ports p WHERE p.scan_id = s.id AND p.state = 'open') \
            AS open_ports \
    FROM scans s";

pub async fn insert_queued<'e, E: PgExecutor<'e>>(
    executor: E,
    device_id: i32,
    target_ip: &str,
    profile: ScanProfile,
    requested_by: &str,
) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "INSERT INTO scans (device_id, target_ip, profile, requested_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(device_id)
    .bind(target_ip)
    .bind(profile.as_str())
    .bind(requested_by)
    .fetch_one(executor)
    .await
}

pub async fn get<'e, E: PgExecutor<'e>>(executor: E, id: i64) -> sqlx::Result<Option<Scan>> {
    sqlx::query_as(&format!("{SELECT_SCAN} WHERE s.id = $1"))
        .bind(id)
        .fetch_optional(executor)
        .await
}

/// The newest scans of a device, newest first.
pub async fn for_device(db: &PgPool, device_id: i32, limit: i64) -> sqlx::Result<Vec<Scan>> {
    sqlx::query_as(&format!(
        "{SELECT_SCAN} WHERE s.device_id = $1 ORDER BY s.id DESC LIMIT $2"
    ))
    .bind(device_id)
    .bind(limit)
    .fetch_all(db)
    .await
}

pub async fn ports(db: &PgPool, scan_id: i64) -> sqlx::Result<Vec<ScanPort>> {
    sqlx::query_as(
        "SELECT protocol, port, state, reason, service, product, version, extra_info \
         FROM scan_ports WHERE scan_id = $1 ORDER BY protocol, port",
    )
    .bind(scan_id)
    .fetch_all(db)
    .await
}

/// `queued` → `running`. False when the scan is no longer queued (it was
/// cancelled while waiting for a slot).
pub async fn mark_running(db: &PgPool, id: i64) -> sqlx::Result<bool> {
    let updated = sqlx::query(
        "UPDATE scans SET status = 'running', started_at = now() \
         WHERE id = $1 AND status = 'queued'",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(updated.rows_affected() == 1)
}

/// What a finished scan needs for its event and its row.
pub struct Finished<'a> {
    pub scan_id: i64,
    pub device_id: i32,
    pub profile: ScanProfile,
    pub target: &'a str,
}

/// Stores a completed scan: its ports, the raw XML, `completed`, and a
/// `scan.completed` event, all in one transaction. Does nothing when the
/// scan is no longer running (cancelled meanwhile); returns whether it
/// stored anything.
pub async fn store_result(
    db: &PgPool,
    scan: &Finished<'_>,
    run: &NmapRun,
    raw_xml: &str,
) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let updated = sqlx::query(
        "UPDATE scans SET status = 'completed', finished_at = now(), nmap_version = $2, \
             raw_xml = $3 \
         WHERE id = $1 AND status = 'running'",
    )
    .bind(scan.scan_id)
    .bind(&run.version)
    .bind(raw_xml)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(false);
    }

    let mut open_ports = Vec::new();
    for port in run.hosts.iter().flat_map(|host| &host.ports) {
        let service = port.service.as_ref();
        sqlx::query(
            "INSERT INTO scan_ports (scan_id, protocol, port, state, reason, service, product, \
                 version, extra_info) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT DO NOTHING",
        )
        .bind(scan.scan_id)
        .bind(&port.protocol)
        .bind(i32::from(port.port))
        .bind(&port.state)
        .bind(&port.reason)
        .bind(service.and_then(|s| s.name.as_ref()))
        .bind(service.and_then(|s| s.product.as_ref()))
        .bind(service.and_then(|s| s.version.as_ref()))
        .bind(service.and_then(|s| s.extra_info.as_ref()))
        .execute(&mut *tx)
        .await?;
        if port.is_open() && port.protocol == "tcp" {
            open_ports.push(port.port);
        }
    }
    open_ports.sort_unstable();
    open_ports.dedup();

    events::record(
        &mut *tx,
        Utc::now(),
        Some(scan.device_id),
        &Event::ScanCompleted(ScanCompleted {
            scan_id: scan.scan_id,
            profile: scan.profile,
            target: scan.target.to_owned(),
            open_ports,
            duration_secs: run.elapsed_secs.unwrap_or(0.0),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Ends a scan without a result and records `scan.failed`, if it is still
/// in one of `from` (the statuses this caller may end it from).
pub async fn store_failure(
    tx: &mut Transaction<'_, Postgres>,
    scan: &Finished<'_>,
    failure: Failure,
    error: &str,
    from: &[&str],
) -> sqlx::Result<bool> {
    let updated = sqlx::query(
        "UPDATE scans SET status = $2, finished_at = now(), error = $3 \
         WHERE id = $1 AND status = ANY($4)",
    )
    .bind(scan.scan_id)
    .bind(failure.as_str())
    .bind(error)
    .bind(from)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(false);
    }
    events::record(
        &mut **tx,
        Utc::now(),
        Some(scan.device_id),
        &Event::ScanFailed(ScanFailed {
            scan_id: scan.scan_id,
            profile: scan.profile,
            target: scan.target.to_owned(),
            outcome: failure.as_str().to_owned(),
            error: error.to_owned(),
        }),
    )
    .await?;
    Ok(true)
}

/// Scans that were queued or running when the API stopped can never finish:
/// their task died with the process. Marks them failed at startup.
pub async fn fail_interrupted(db: &PgPool) -> sqlx::Result<usize> {
    let stale: Vec<(i64, i32, String, String)> = sqlx::query_as(
        "SELECT id, device_id, profile, target_ip FROM scans \
         WHERE status IN ('queued', 'running') ORDER BY id",
    )
    .fetch_all(db)
    .await?;

    let mut failed = 0;
    for (scan_id, device_id, profile, target) in stale {
        let Some(profile) = ScanProfile::parse(&profile) else {
            continue; // the CHECK constraint makes this unreachable
        };
        let mut tx = db.begin().await?;
        let scan = Finished {
            scan_id,
            device_id,
            profile,
            target: &target,
        };
        if store_failure(
            &mut tx,
            &scan,
            Failure::Failed,
            "interrupted: the API restarted while the scan was queued or running",
            &["queued", "running"],
        )
        .await?
        {
            failed += 1;
        }
        tx.commit().await?;
    }
    Ok(failed)
}
