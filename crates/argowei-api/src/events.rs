//! The event timeline: recording typed events ([`record`]) and reading them
//! back (`GET /api/events`).
//!
//! # Why the cursor is a transaction id, not the row id
//!
//! Row ids come from a sequence when the row is *inserted*, but a row only
//! becomes visible when its transaction *commits*. A scan transaction that
//! inserts event 10 and commits after the transaction holding event 11 would
//! make event 10 appear behind a reader that has already moved past 11 (paging
//! back) or past 10 (polling for news). Either way it is silently skipped.
//!
//! So every event also stores the id of the transaction that wrote it
//! (`tx_id`, assigned in the database), and the list only serves events whose
//! transaction is older than every transaction still running (`HORIZON`).
//! Whatever commits later has a transaction id at least that large, so it
//! sorts *after* everything already served, and ordering by `(tx_id, id)`
//! never changes for rows a client has seen. The price: while some
//! transaction runs, events written after it started wait until it ends
//! (scan transactions take milliseconds).

use argowei_core::events::{Event, EventKind, Severity};
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgExecutor;

use crate::device_summary::DeviceSummary;
use crate::error::ApiError;
use crate::state::AppState;

/// The oldest transaction that may still commit events: the lowest running
/// transaction id, ignoring transactions known to belong to *other*
/// databases on the same server (they cannot write our events, and must not
/// hold the timeline back, e.g. a backup or, in tests, the next test's
/// database). A transaction that cannot be attributed is kept, so the
/// horizon only ever errs towards waiting. With nothing running it is the
/// snapshot's `xmax`, so everything committed is served.
const HORIZON: &str = "(WITH snap AS (SELECT pg_current_snapshot() AS s) \
    SELECT coalesce( \
        (SELECT min(x) FROM snap, pg_snapshot_xip(snap.s) AS x \
         WHERE x::xid NOT IN (SELECT backend_xid FROM pg_stat_activity \
                              WHERE datname IS DISTINCT FROM current_database() \
                                AND backend_xid IS NOT NULL)), \
        (SELECT pg_snapshot_xmax(s) FROM snap)))";

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;

/// Inserts an event. Pass a transaction to commit it together with the
/// change it describes, so an event exists exactly when its change does.
/// Type, schema version and severity all come from the event itself.
pub async fn record<'e, E: PgExecutor<'e>>(
    executor: E,
    occurred_at: DateTime<Utc>,
    device_id: Option<i32>,
    event: &Event,
) -> sqlx::Result<()> {
    let kind = event.kind();
    let payload =
        serde_json::to_value(event).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;

    sqlx::query(
        "INSERT INTO events (occurred_at, type, schema_version, severity, device_id, payload) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(occurred_at)
    .bind(kind.as_str())
    .bind(kind.schema_version())
    .bind(kind.severity().as_str())
    .bind(device_id)
    .bind(payload)
    .execute(executor)
    .await?;

    Ok(())
}

pub fn router() -> axum::Router<AppState> {
    Router::new()
        .route("/api/events", get(list))
        .route("/api/events/types", get(types))
}

// --- cursor -----------------------------------------------------------------

/// A position in the timeline: `(tx_id, id)` of an event. Opaque to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    tx_id: u64,
    id: i64,
}

impl Cursor {
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!("{}.{}", self.tx_id, self.id))
    }

    pub fn decode(value: &str) -> Option<Self> {
        let text = String::from_utf8(URL_SAFE_NO_PAD.decode(value).ok()?).ok()?;
        let (tx_id, id) = text.split_once('.')?;
        Some(Self {
            tx_id: tx_id.parse().ok()?,
            id: id.parse().ok()?,
        })
    }
}

// --- list -------------------------------------------------------------------

/// Query parameters. Everything is read as text and validated here, so a bad
/// value gets the usual JSON error instead of the extractor's plain text.
#[derive(Deserialize)]
struct ListQuery {
    device: Option<String>,
    r#type: Option<String>,
    severity: Option<String>,
    /// RFC 3339; inclusive bounds on `occurred_at`.
    from: Option<String>,
    to: Option<String>,
    /// Older events than this cursor (paging back).
    before: Option<String>,
    /// Newer events than this cursor (polling for news).
    after: Option<String>,
    limit: Option<String>,
}

/// The validated form of [`ListQuery`].
#[derive(Debug, Default)]
struct Filter {
    device: Option<i32>,
    kind: Option<EventKind>,
    severity: Option<Severity>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    before: Option<Cursor>,
    after: Option<Cursor>,
    limit: i64,
}

fn bad(message: &str) -> ApiError {
    ApiError::BadRequest(message.to_owned())
}

fn parse_time(value: &str, field: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| ApiError::BadRequest(format!("{field} must be an RFC 3339 timestamp")))
}

impl TryFrom<ListQuery> for Filter {
    type Error = ApiError;

    fn try_from(query: ListQuery) -> Result<Self, ApiError> {
        let non_empty = |value: Option<String>| value.filter(|v| !v.is_empty());
        let filter = Filter {
            device: non_empty(query.device)
                .map(|v| v.parse().map_err(|_| bad("device must be a device id")))
                .transpose()?,
            kind: non_empty(query.r#type)
                .map(|v| EventKind::parse(&v).ok_or_else(|| bad("unknown event type")))
                .transpose()?,
            severity: non_empty(query.severity)
                .map(|v| {
                    Severity::parse(&v)
                        .ok_or_else(|| bad("severity must be info, warning or critical"))
                })
                .transpose()?,
            from: non_empty(query.from)
                .map(|v| parse_time(&v, "from"))
                .transpose()?,
            to: non_empty(query.to)
                .map(|v| parse_time(&v, "to"))
                .transpose()?,
            before: non_empty(query.before)
                .map(|v| Cursor::decode(&v).ok_or_else(|| bad("before is not a valid cursor")))
                .transpose()?,
            after: non_empty(query.after)
                .map(|v| Cursor::decode(&v).ok_or_else(|| bad("after is not a valid cursor")))
                .transpose()?,
            limit: match non_empty(query.limit) {
                None => DEFAULT_PAGE_SIZE,
                Some(v) => v
                    .parse::<i64>()
                    .map_err(|_| bad("limit must be a number"))?
                    .clamp(1, MAX_PAGE_SIZE),
            },
        };

        if let (Some(from), Some(to)) = (filter.from, filter.to) {
            if from > to {
                return Err(bad("from must not be after to"));
            }
        }
        if filter.before.is_some() && filter.after.is_some() {
            return Err(bad("use either before or after, not both"));
        }
        Ok(filter)
    }
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: i64,
    tx_id: String,
    occurred_at: DateTime<Utc>,
    r#type: String,
    schema_version: i16,
    severity: String,
    payload: Value,
    device_id: Option<i32>,
    device_name: Option<String>,
    device_label: Option<String>,
    device_mac: Option<String>,
}

#[derive(Serialize)]
struct EventItem {
    id: i64,
    /// This event's position; pass it as `before` or `after`.
    cursor: String,
    occurred_at: DateTime<Utc>,
    r#type: String,
    schema_version: i16,
    severity: String,
    /// `null` when the event concerns no device, or the device is gone.
    device: Option<DeviceSummary>,
    payload: Value,
}

impl TryFrom<EventRow> for EventItem {
    type Error = ApiError;

    fn try_from(row: EventRow) -> Result<Self, ApiError> {
        let tx_id = row.tx_id.parse().map_err(|_| {
            tracing::error!(tx_id = %row.tx_id, "event with an unreadable transaction id");
            ApiError::Unavailable
        })?;
        Ok(EventItem {
            id: row.id,
            cursor: Cursor { tx_id, id: row.id }.encode(),
            occurred_at: row.occurred_at,
            r#type: row.r#type,
            schema_version: row.schema_version,
            severity: row.severity,
            device: DeviceSummary::from_columns(
                row.device_id,
                row.device_mac,
                row.device_label,
                row.device_name,
            ),
            payload: row.payload,
        })
    }
}

#[derive(Serialize)]
struct ListResponse {
    /// Newest first.
    items: Vec<EventItem>,
    /// Cursor for the next older page; `null` when there is none.
    next_before: Option<String>,
    /// With `after`: more new events exist than `limit`; reload from the top.
    truncated: bool,
}

/// `GET /api/events`: newest first, filtered, paged by cursor (see the module
/// docs for why paging is stable).
async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, ApiError> {
    let filter = Filter::try_from(query)?;
    let (cursor_tx, cursor_id, newer) = match (&filter.before, &filter.after) {
        (Some(c), _) => (Some(c.tx_id.to_string()), Some(c.id), false),
        (_, Some(c)) => (Some(c.tx_id.to_string()), Some(c.id), true),
        _ => (None, None, false),
    };

    let mut rows: Vec<EventRow> = sqlx::query_as(&format!(
        "SELECT e.id, e.tx_id::text AS tx_id, e.occurred_at, e.type, e.schema_version, \
                e.severity, e.payload, e.device_id, d.name AS device_name, \
                d.label AS device_label, d.mac_address AS device_mac \
         FROM events e LEFT JOIN devices d ON d.id = e.device_id \
         WHERE e.tx_id < {HORIZON} \
           AND ($1::int IS NULL OR e.device_id = $1) \
           AND ($2::text IS NULL OR e.type = $2) \
           AND ($3::text IS NULL OR e.severity = $3) \
           AND ($4::timestamptz IS NULL OR e.occurred_at >= $4) \
           AND ($5::timestamptz IS NULL OR e.occurred_at <= $5) \
           AND ($6::text IS NULL OR CASE WHEN $8 \
                    THEN (e.tx_id, e.id) > ($6::xid8, $7::bigint) \
                    ELSE (e.tx_id, e.id) < ($6::xid8, $7::bigint) END) \
         ORDER BY e.tx_id DESC, e.id DESC \
         LIMIT $9"
    ))
    .bind(filter.device)
    .bind(filter.kind.map(EventKind::as_str))
    .bind(filter.severity.map(Severity::as_str))
    .bind(filter.from)
    .bind(filter.to)
    .bind(cursor_tx)
    .bind(cursor_id)
    .bind(newer)
    .bind(filter.limit + 1)
    .fetch_all(&state.db)
    .await?;

    let more = rows.len() as i64 > filter.limit;
    rows.truncate(filter.limit as usize);
    let items = rows
        .into_iter()
        .map(EventItem::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    // Newer-than queries return the newest `limit` events; if there were
    // more, the client has a gap and must reload instead of prepending.
    let next_before = if more && !newer {
        items.last().map(|item| item.cursor.clone())
    } else {
        None
    };
    Ok(Json(ListResponse {
        items,
        next_before,
        truncated: more && newer,
    }))
}

#[derive(Serialize)]
struct TypeInfo {
    r#type: &'static str,
    schema_version: i16,
    severity: Severity,
}

/// `GET /api/events/types`: every event type the server records.
async fn types() -> Json<Vec<TypeInfo>> {
    Json(
        EventKind::ALL
            .into_iter()
            .map(|kind| TypeInfo {
                r#type: kind.as_str(),
                schema_version: kind.schema_version(),
                severity: kind.severity(),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> ListQuery {
        let mut q = ListQuery {
            device: None,
            r#type: None,
            severity: None,
            from: None,
            to: None,
            before: None,
            after: None,
            limit: None,
        };
        for (key, value) in pairs {
            let value = Some((*value).to_owned());
            match *key {
                "device" => q.device = value,
                "type" => q.r#type = value,
                "severity" => q.severity = value,
                "from" => q.from = value,
                "to" => q.to = value,
                "before" => q.before = value,
                "after" => q.after = value,
                "limit" => q.limit = value,
                _ => unreachable!("unknown test key"),
            }
        }
        q
    }

    fn rejected(pairs: &[(&str, &str)]) -> String {
        match Filter::try_from(query(pairs)) {
            Err(ApiError::BadRequest(message)) => message,
            other => panic!("expected a bad request, got {other:?}"),
        }
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let cursor = Cursor {
            tx_id: 123_456,
            id: 42,
        };
        assert_eq!(Cursor::decode(&cursor.encode()), Some(cursor));
        for garbage in ["", "!!", "MTIz", "YS5i", "LTEuMg"] {
            assert_eq!(Cursor::decode(garbage), None, "{garbage}");
        }
    }

    #[test]
    fn a_full_query_is_parsed() {
        let cursor = Cursor { tx_id: 9, id: 3 }.encode();
        let filter = Filter::try_from(query(&[
            ("device", "7"),
            ("type", "device.offline"),
            ("severity", "warning"),
            ("from", "2026-01-01T00:00:00Z"),
            ("to", "2026-01-02T00:00:00+01:00"),
            ("before", &cursor),
            ("limit", "10"),
        ]))
        .unwrap();
        assert_eq!(filter.device, Some(7));
        assert_eq!(filter.kind, Some(EventKind::DeviceOffline));
        assert_eq!(filter.severity, Some(Severity::Warning));
        assert_eq!(filter.before, Some(Cursor { tx_id: 9, id: 3 }));
        assert_eq!(filter.limit, 10);
    }

    #[test]
    fn empty_values_mean_no_filter_and_limits_are_clamped() {
        let filter = Filter::try_from(query(&[("type", ""), ("device", "")])).unwrap();
        assert!(filter.kind.is_none() && filter.device.is_none());
        assert_eq!(filter.limit, DEFAULT_PAGE_SIZE);
        assert_eq!(Filter::try_from(query(&[("limit", "0")])).unwrap().limit, 1);
        assert_eq!(
            Filter::try_from(query(&[("limit", "100000")]))
                .unwrap()
                .limit,
            MAX_PAGE_SIZE
        );
    }

    #[test]
    fn bad_values_are_rejected_with_a_reason() {
        assert_eq!(
            rejected(&[("type", "device.exploded")]),
            "unknown event type"
        );
        assert!(rejected(&[("severity", "loud")]).starts_with("severity must be"));
        assert_eq!(rejected(&[("device", "x")]), "device must be a device id");
        assert!(rejected(&[("from", "yesterday")]).contains("RFC 3339"));
        assert_eq!(rejected(&[("limit", "many")]), "limit must be a number");
        assert_eq!(
            rejected(&[("before", "nope")]),
            "before is not a valid cursor"
        );
        assert_eq!(
            rejected(&[
                ("from", "2026-01-02T00:00:00Z"),
                ("to", "2026-01-01T00:00:00Z")
            ]),
            "from must not be after to"
        );
        let cursor = Cursor { tx_id: 1, id: 1 }.encode();
        assert_eq!(
            rejected(&[("before", &cursor), ("after", &cursor)]),
            "use either before or after, not both"
        );
    }
}
