use argowei_core::device::Device;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Row};

use crate::state::AppState;

// argowei-core intentionally has no sqlx dependency (it stays usable from
// the CLI crate without pulling in a database driver), so the FromRow
// mapping for the shared Device type lives here instead of a derive on the
// struct itself.
struct DeviceRow(Device);

impl FromRow<'_, PgRow> for DeviceRow {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        Ok(DeviceRow(Device {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            ip_address: row.try_get("ip_address")?,
            mac_address: row.try_get("mac_address")?,
            is_online: row.try_get("is_online")?,
            first_seen: row.try_get("first_seen")?,
            last_seen: row.try_get("last_seen")?,
        }))
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/devices", get(list_devices))
        .with_state(state)
}

async fn list_devices(State(state): State<AppState>) -> Result<Json<Vec<Device>>, StatusCode> {
    list(&state.db)
        .await
        .map(|rows| Json(rows.into_iter().map(|r| r.0).collect()))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Returns all known devices, most recently seen first.
async fn list(db: &PgPool) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(
        "SELECT id, name, ip_address, mac_address, is_online, first_seen, last_seen \
         FROM devices ORDER BY last_seen DESC",
    )
    .fetch_all(db)
    .await
}
