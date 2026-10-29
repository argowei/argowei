//! Event stream: timestamped, typed facts with structured evidence in the
//! payload (state transitions today, anomalies and alerts later).

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;

/// First sighting of a MAC address. Also marks the start of the device's
/// first online period.
pub const DEVICE_DISCOVERED: &str = "device.discovered";
/// A known device answered again after having been marked offline.
pub const DEVICE_ONLINE: &str = "device.online";
/// A device missed enough scans, for long enough, to be considered gone.
pub const DEVICE_OFFLINE: &str = "device.offline";

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Inserts an event. Pass a transaction to commit it together with the
/// change it describes, so an event exists exactly when its change does.
pub async fn record<'e, E: PgExecutor<'e>>(
    executor: E,
    occurred_at: DateTime<Utc>,
    kind: &str,
    severity: Severity,
    device_id: Option<i32>,
    payload: Value,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO events (occurred_at, type, severity, device_id, payload) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(occurred_at)
    .bind(kind)
    .bind(severity.as_str())
    .bind(device_id)
    .bind(payload)
    .execute(executor)
    .await?;

    Ok(())
}
