//! Reading and writing `scans` and `scan_ports`.
//!
//! Status changes are conditional (`WHERE status = ...`), so the request
//! handlers and the runner can race (a cancel while nmap finishes, a restart
//! while a scan runs) and exactly one of them wins; the loser's update
//! simply matches no row.

use argowei_collector::nmap::{self, NmapPort, NmapRun};
use argowei_core::events::{Event, PortEvent, ScanCompleted, ScanFailed, ServiceChanged};
use argowei_core::scan_diff::{self, PortCoverage, PortObservation, ScanSide};
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

    record_changes(&mut tx, scan, run).await?;

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

/// A completed scan as a side of a comparison: its ports from `scan_ports`
/// and its coverage from the stored XML.
pub struct Snapshot {
    pub id: i64,
    pub profile: ScanProfile,
    pub target: String,
    pub coverage: PortCoverage,
    pub ports: Vec<PortObservation>,
}

impl Snapshot {
    pub fn side(&self) -> ScanSide<'_> {
        ScanSide {
            profile: self.profile,
            target: &self.target,
            coverage: &self.coverage,
            ports: &self.ports,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ObservationRow {
    protocol: String,
    port: i32,
    state: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SnapshotRow {
    id: i64,
    profile: String,
    target_ip: String,
    raw_xml: Option<String>,
}

/// Loads a completed scan for comparison; `None` if it is not completed.
pub async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    scan_id: i64,
) -> sqlx::Result<Option<Snapshot>> {
    let row: Option<SnapshotRow> = sqlx::query_as(
        "SELECT id, profile, target_ip, raw_xml FROM scans WHERE id = $1 AND status = 'completed'",
    )
    .bind(scan_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let Some(profile) = ScanProfile::parse(&row.profile) else {
        return Ok(None);
    };
    let ports: Vec<ObservationRow> = sqlx::query_as(
        "SELECT protocol, port, state, service, product, version FROM scan_ports \
         WHERE scan_id = $1",
    )
    .bind(scan_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(Some(Snapshot {
        id: row.id,
        profile,
        target: row.target_ip,
        // Without readable XML nothing is known to be covered: every port
        // then counts as "not comparable" rather than opened or closed.
        coverage: row
            .raw_xml
            .and_then(|xml| nmap::parse_xml(&xml).ok())
            .map(|run| run.coverage)
            .unwrap_or_default(),
        ports: ports
            .into_iter()
            .filter_map(|row| {
                Some(PortObservation {
                    protocol: row.protocol,
                    port: u16::try_from(row.port).ok()?,
                    state: row.state,
                    service: row.service,
                    product: row.product,
                    version: row.version,
                })
            })
            .collect(),
    }))
}

/// The newest completed scan of a device older than `before`, optionally
/// of one profile only.
pub async fn previous_completed(
    tx: &mut Transaction<'_, Postgres>,
    device_id: i32,
    before: i64,
    profile: Option<ScanProfile>,
) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(
        "SELECT id FROM scans          WHERE device_id = $1 AND id < $2 AND status = 'completed'            AND ($3::text IS NULL OR profile = $3)          ORDER BY id DESC LIMIT 1",
    )
    .bind(device_id)
    .bind(before)
    .bind(profile.map(ScanProfile::as_str))
    .fetch_optional(&mut **tx)
    .await
}

fn observation(port: &NmapPort) -> PortObservation {
    let service = port.service.as_ref();
    PortObservation {
        protocol: port.protocol.clone(),
        port: port.port,
        state: port.state.clone(),
        service: service.and_then(|s| s.name.clone()),
        product: service.and_then(|s| s.product.clone()),
        version: service.and_then(|s| s.version.clone()),
    }
}

/// Compares a just-completed scan with the previous completed scan of the
/// same device *and profile* (so coverage matches) and records what changed
/// as `port.opened`, `port.closed` and `service.changed` events. The first
/// scan of a device has nothing to compare with and records nothing.
async fn record_changes(
    tx: &mut Transaction<'_, Postgres>,
    scan: &Finished<'_>,
    run: &NmapRun,
) -> sqlx::Result<()> {
    let Some(previous_id) =
        previous_completed(tx, scan.device_id, scan.scan_id, Some(scan.profile)).await?
    else {
        return Ok(());
    };
    let Some(previous) = snapshot(tx, previous_id).await? else {
        return Ok(());
    };
    let ports: Vec<PortObservation> = run
        .hosts
        .iter()
        .flat_map(|host| &host.ports)
        .map(observation)
        .collect();
    let current = ScanSide {
        profile: scan.profile,
        target: scan.target,
        coverage: &run.coverage,
        ports: &ports,
    };
    let changes = scan_diff::diff(&previous.side(), &current);

    let now = Utc::now();
    let port_event = |change: &scan_diff::PortChange| PortEvent {
        scan_id: scan.scan_id,
        previous_scan_id: previous.id,
        target: scan.target.to_owned(),
        protocol: change.protocol.clone(),
        port: change.port,
        service: change.service.clone(),
    };
    let mut events: Vec<Event> = Vec::new();
    events.extend(
        changes
            .opened
            .iter()
            .map(|c| Event::PortOpened(port_event(c))),
    );
    events.extend(
        changes
            .closed
            .iter()
            .map(|c| Event::PortClosed(port_event(c))),
    );
    events.extend(changes.changed.iter().map(|c| {
        Event::ServiceChanged(ServiceChanged {
            scan_id: scan.scan_id,
            previous_scan_id: previous.id,
            target: scan.target.to_owned(),
            protocol: c.protocol.clone(),
            port: c.port,
            before: c.before.clone(),
            after: c.after.clone(),
        })
    }));
    for event in &events {
        events::record(&mut **tx, now, Some(scan.device_id), event).await?;
    }
    Ok(())
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
