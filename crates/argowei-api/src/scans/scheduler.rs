//! Runs scan schedules.
//!
//! One loop wakes up when the earliest schedule is due (or a schedule
//! changed) and, per due schedule:
//!
//! 1. **Claims the run** by moving `next_run_at` to the next occurrence
//!    after *now*, conditional on the value it read, so a run starts once
//!    even if two API processes share the database. A run overdue by more
//!    than two minutes ([`argowei_core::scan_schedule::GRACE`]; the server
//!    was down or asleep) is skipped, not
//!    started late, and never replayed: missed runs do not stampede.
//! 2. **Waits a random jitter** (a tenth of the interval, at most a minute),
//!    so schedules sharing a time do not all hit the network at once.
//! 3. **Skips the run** if the schedule's previous scans are still queued or
//!    running. The check reads `scans.schedule_id`, so it also holds across
//!    a restart.
//! 4. **Queues one scan per device** of the target through the same path as
//!    the dashboard ([`super::enqueue`]): the same address guard, the same
//!    one-active-scan-per-device rule, the same global concurrency limit.
//!    Runs are audited with the actor [`audit::SYSTEM`].

use std::sync::Arc;
use std::time::Duration;

use argowei_core::scan_profile::ScanProfile;
use argowei_core::scan_schedule::{is_missed, jitter_limit, CronSchedule, ScheduleTarget};
use chrono::{DateTime, Local, Utc};
use rand::Rng;
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::schedules::ScheduleRow;
use super::{enqueue, Requester, ScanRunner};
use crate::audit;
use crate::error::ApiError;

/// The loop looks again at least this often, so a clock change or a missed
/// notification never delays a run for long.
const MAX_SLEEP: Duration = Duration::from_secs(30);

/// A run the scheduler has claimed; it may still be skipped if the schedule
/// is disabled or a previous run overlaps.
#[derive(Debug, Clone)]
pub struct DueRun {
    pub schedule_id: i32,
    pub profile: ScanProfile,
    pub target: ScheduleTarget,
    /// Upper bound of the random delay before starting.
    pub jitter: Duration,
}

/// What [`claim_due`] did.
#[derive(Debug, Default)]
pub struct Claimed {
    pub runs: Vec<DueRun>,
    /// Schedules whose run was overdue beyond the grace period and skipped.
    pub skipped_missed: Vec<i32>,
}

/// Claims every schedule due at `now`: advances its `next_run_at` to the
/// next occurrence after `now` and returns the runs to start.
pub async fn claim_due(db: &PgPool, now: DateTime<Local>) -> sqlx::Result<Claimed> {
    let due: Vec<ScheduleRow> = sqlx::query_as(
        "SELECT id, name, cron, profile, target_kind, target_id, enabled, created_by, \
                created_at, last_run_at, next_run_at \
         FROM scan_schedules WHERE enabled AND next_run_at <= $1 ORDER BY next_run_at, id",
    )
    .bind(now.with_timezone(&Utc))
    .fetch_all(db)
    .await?;

    let mut claimed = Claimed::default();
    for schedule in due {
        let (Some(due_at), Ok(cron), Some(profile), Some(target)) = (
            schedule.next_run_at,
            CronSchedule::parse(&schedule.cron),
            schedule.profile(),
            schedule.target(),
        ) else {
            tracing::error!(
                schedule_id = schedule.id,
                "unusable stored schedule; disabling it"
            );
            sqlx::query(
                "UPDATE scan_schedules SET enabled = false, next_run_at = NULL WHERE id = $1",
            )
            .bind(schedule.id)
            .execute(db)
            .await?;
            continue;
        };
        let Some(next) = cron.next_after(&now) else {
            continue;
        };
        let missed = is_missed(&due_at.with_timezone(&Local), &now);

        // Conditional on the value read: whoever moves it first owns the run.
        let won = sqlx::query(
            "UPDATE scan_schedules SET next_run_at = $3 \
             WHERE id = $1 AND enabled AND next_run_at = $2",
        )
        .bind(schedule.id)
        .bind(due_at)
        .bind(next.with_timezone(&Utc))
        .execute(db)
        .await?
        .rows_affected()
            == 1;
        if !won {
            continue;
        }
        if missed {
            tracing::info!(schedule_id = schedule.id, %due_at, "skipping a run missed while the server was away");
            claimed.skipped_missed.push(schedule.id);
        } else {
            claimed.runs.push(DueRun {
                schedule_id: schedule.id,
                profile,
                target,
                jitter: jitter_limit(&now, &next),
            });
        }
    }
    Ok(claimed)
}

/// What one run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunOutcome {
    /// Scans queued, by scan id.
    pub queued: Vec<i64>,
    /// The previous run's scans were still going: nothing was queued.
    pub skipped_overlap: bool,
    /// The schedule was disabled or deleted after this run was claimed.
    pub skipped_inactive: bool,
    /// Devices left out: no scannable address, or already being scanned.
    pub refused: usize,
}

/// Queues the scans of one claimed run (without waiting for jitter). Fails
/// only when the database does; per-device refusals are counted instead.
pub async fn execute_run(
    db: &PgPool,
    runner: &ScanRunner,
    run: &DueRun,
) -> Result<RunOutcome, ApiError> {
    // Keep the schedule locked until its scans have been queued. This makes
    // disabling or deleting it atomic with respect to the start of a run:
    // once an edit completes, no previously claimed run can still start.
    // NO KEY UPDATE permits the scan inserts' foreign-key KEY SHARE locks.
    let mut tx = db.begin().await?;
    let active: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM scan_schedules WHERE id = $1 FOR NO KEY UPDATE")
            .bind(run.schedule_id)
            .fetch_optional(&mut *tx)
            .await?;
    if active != Some(true) {
        tracing::info!(
            schedule_id = run.schedule_id,
            "claimed schedule is no longer active; skipping"
        );
        return Ok(RunOutcome {
            skipped_inactive: true,
            ..RunOutcome::default()
        });
    }

    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM scans \
                        WHERE schedule_id = $1 AND status IN ('queued', 'running'))",
    )
    .bind(run.schedule_id)
    .fetch_one(&mut *tx)
    .await?;
    if busy {
        tracing::info!(
            schedule_id = run.schedule_id,
            "previous run still going; skipping"
        );
        return Ok(RunOutcome {
            skipped_overlap: true,
            ..RunOutcome::default()
        });
    }

    let devices: Vec<i32> = match run.target {
        ScheduleTarget::Device(id) => {
            sqlx::query_scalar("SELECT id FROM devices WHERE id = $1")
                .bind(id)
                .fetch_all(db)
                .await?
        }
        ScheduleTarget::Group(id) => {
            sqlx::query_scalar("SELECT id FROM devices WHERE group_id = $1 ORDER BY id")
                .bind(id)
                .fetch_all(db)
                .await?
        }
        ScheduleTarget::All => {
            sqlx::query_scalar("SELECT id FROM devices ORDER BY id")
                .fetch_all(db)
                .await?
        }
    };

    let mut outcome = RunOutcome::default();
    for device_id in devices {
        let requester = Requester {
            actor: audit::SYSTEM,
            remote_addr: None,
            schedule_id: Some(run.schedule_id),
        };
        match enqueue(db, runner, device_id, run.profile, requester).await {
            Ok(scan) => outcome.queued.push(scan.id),
            // Expected for some devices of a group or "all": no address, an
            // address outside the allowed ranges, or a scan already running.
            Err(ApiError::Unprocessable(_) | ApiError::Conflict(_) | ApiError::NotFound(_)) => {
                outcome.refused += 1;
            }
            Err(error) => return Err(error),
        }
    }
    if !outcome.queued.is_empty() {
        sqlx::query("UPDATE scan_schedules SET last_run_at = now() WHERE id = $1")
            .bind(run.schedule_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(
        schedule_id = run.schedule_id,
        queued = outcome.queued.len(),
        refused = outcome.refused,
        "scheduled run started"
    );
    Ok(outcome)
}

/// Starts the scheduler loop. `changed` wakes it when a schedule is created,
/// edited or deleted.
pub fn spawn(db: PgPool, runner: ScanRunner, changed: Arc<Notify>) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("scan scheduler started");
        loop {
            match claim_due(&db, Local::now()).await {
                Ok(claimed) => {
                    for run in claimed.runs {
                        let (db, runner) = (db.clone(), runner.clone());
                        tokio::spawn(async move {
                            let jitter_ms = u64::try_from(run.jitter.as_millis()).unwrap_or(0);
                            let delay = rand::thread_rng().gen_range(0..=jitter_ms);
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            if let Err(error) = execute_run(&db, &runner, &run).await {
                                tracing::error!(
                                    schedule_id = run.schedule_id,
                                    ?error,
                                    "scheduled run failed"
                                );
                            }
                        });
                    }
                }
                Err(error) => tracing::error!(%error, "could not read scan schedules"),
            }

            let sleep = until_next(&db).await.unwrap_or(MAX_SLEEP).min(MAX_SLEEP);
            tokio::select! {
                _ = tokio::time::sleep(sleep) => {}
                _ = changed.notified() => {}
            }
        }
    })
}

/// Time until the earliest enabled schedule is due.
async fn until_next(db: &PgPool) -> Option<Duration> {
    let next: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT min(next_run_at) FROM scan_schedules WHERE enabled")
            .fetch_one(db)
            .await
            .ok()
            .flatten();
    next.map(|at| (at - Utc::now()).to_std().unwrap_or(Duration::ZERO))
}
