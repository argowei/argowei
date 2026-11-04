//! Device groups: seeded system groups plus user-defined ones.
//!
//! A group's `defaults` describe its default behavior as data (internet and
//! LAN access, DNS filtering, ...) for the policy engine to consume later.
//! Nothing here enforces anything.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::audit::{self, mark_audited, AuditEntry, Outcome, RequestMeta};
use crate::auth::AuthUser;
use crate::error::{is_foreign_key_violation, is_unique_violation, ApiError};
use crate::state::AppState;
use crate::validate;

const MAX_NAME_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 500;
const MAX_DEFAULTS_BYTES: usize = 4096;

#[derive(Serialize, sqlx::FromRow)]
struct Group {
    id: i32,
    /// Stable key of a system group; `null` for custom groups.
    slug: Option<String>,
    name: String,
    description: String,
    is_system: bool,
    defaults: Value,
    device_count: i64,
    created_at: DateTime<Utc>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/:id", patch(update_group).delete(delete_group))
}

const SELECT_GROUPS: &str = "SELECT g.id, g.slug, g.name, g.description, g.is_system, \
         g.defaults, g.created_at, count(d.id) AS device_count \
     FROM device_groups g LEFT JOIN devices d ON d.group_id = g.id \
     WHERE ($1::int IS NULL OR g.id = $1) \
     GROUP BY g.id ORDER BY g.is_system DESC, g.id";

async fn fetch_groups(db: &PgPool, only: Option<i32>) -> sqlx::Result<Vec<Group>> {
    sqlx::query_as(SELECT_GROUPS).bind(only).fetch_all(db).await
}

async fn list_groups(State(state): State<AppState>) -> Result<Json<Vec<Group>>, ApiError> {
    Ok(Json(fetch_groups(&state.db, None).await?))
}

// --- validation -----------------------------------------------------------

fn normalize_name(raw: &str) -> Result<String, ApiError> {
    validate::single_line(raw, "name", 1..=MAX_NAME_CHARS)
}

fn normalize_description(raw: &str) -> Result<String, ApiError> {
    validate::multi_line(raw, "description", 0..=MAX_DESCRIPTION_CHARS)
}

fn validate_defaults(value: &Value) -> Result<(), ApiError> {
    if !value.is_object() {
        return Err(ApiError::BadRequest(
            "defaults must be a JSON object".into(),
        ));
    }
    if value.to_string().len() > MAX_DEFAULTS_BYTES {
        return Err(ApiError::BadRequest(format!(
            "defaults must be at most {MAX_DEFAULTS_BYTES} bytes"
        )));
    }
    Ok(())
}

// --- create ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGroup {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "empty_object")]
    defaults: Value,
}

fn empty_object() -> Value {
    json!({})
}

async fn create_group(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Json(body): Json<CreateGroup>,
) -> Result<Response, ApiError> {
    let name = normalize_name(&body.name)?;
    let description = normalize_description(&body.description)?;
    validate_defaults(&body.defaults)?;

    let mut tx = state.db.begin().await?;
    let id: i32 = sqlx::query_scalar(
        "INSERT INTO device_groups (name, description, defaults) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&name)
    .bind(&description)
    .bind(&body.defaults)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            ApiError::Conflict("a group with this name already exists")
        } else {
            ApiError::from(error)
        }
    })?;
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "group.create", Outcome::Success)
            .target("group", id)
            .remote_addr(meta.remote_addr)
            .payload(
                json!({ "name": name, "description": description, "defaults": body.defaults }),
            ),
    )
    .await?;
    tx.commit().await?;

    let group = fetch_groups(&state.db, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or(ApiError::Unavailable)?;
    Ok(mark_audited(
        (StatusCode::CREATED, Json(group)).into_response(),
    ))
}

// --- update ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateGroup {
    name: Option<String>,
    description: Option<String>,
    defaults: Option<Value>,
}

/// The columns an update compares against, read under a row lock.
#[derive(sqlx::FromRow)]
struct EditableGroup {
    name: String,
    description: String,
    defaults: Value,
    is_system: bool,
}

async fn update_group(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i32>,
    Json(body): Json<UpdateGroup>,
) -> Result<Response, ApiError> {
    let new_name = body.name.as_deref().map(normalize_name).transpose()?;
    let new_description = body
        .description
        .as_deref()
        .map(normalize_description)
        .transpose()?;
    if let Some(defaults) = &body.defaults {
        validate_defaults(defaults)?;
    }

    // Locked until commit, as for devices: the audited "before" values must be
    // the ones the update replaced.
    let mut tx = state.db.begin().await?;
    let EditableGroup {
        name: old_name,
        description: old_description,
        defaults: old_defaults,
        is_system,
    } = sqlx::query_as(
        "SELECT name, description, defaults, is_system FROM device_groups \
             WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound("no such group"))?;

    let name = new_name.unwrap_or_else(|| old_name.clone());
    if is_system && name != old_name {
        return Err(ApiError::Conflict("system groups cannot be renamed"));
    }
    let description = new_description.unwrap_or_else(|| old_description.clone());
    let defaults = body.defaults.unwrap_or_else(|| old_defaults.clone());

    let mut changes = serde_json::Map::new();
    if name != old_name {
        changes.insert("name".into(), json!({ "from": old_name, "to": name }));
    }
    if description != old_description {
        changes.insert(
            "description".into(),
            json!({ "from": old_description, "to": description }),
        );
    }
    if defaults != old_defaults {
        changes.insert(
            "defaults".into(),
            json!({ "from": old_defaults, "to": defaults }),
        );
    }

    let changed = !changes.is_empty();
    if changed {
        sqlx::query(
            "UPDATE device_groups SET name = $2, description = $3, defaults = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(&defaults)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::Conflict("a group with this name already exists")
            } else {
                ApiError::from(error)
            }
        })?;
        audit::record(
            &mut *tx,
            AuditEntry::new(&user.username, "group.update", Outcome::Success)
                .target("group", id)
                .remote_addr(meta.remote_addr)
                .payload(json!({ "changes": Value::Object(changes) })),
        )
        .await?;
    }
    tx.commit().await?;

    let group = fetch_groups(&state.db, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or(ApiError::NotFound("no such group"))?;
    let response = Json(group).into_response();
    let response = if changed {
        // Audited above; a request that changed nothing is left to the
        // middleware's generic entry.
        mark_audited(response)
    } else {
        response
    };
    Ok(response)
}

// --- delete ---------------------------------------------------------------

/// What deleting needs to know, read under a row lock so a device cannot be
/// moved into the group between the check and the delete without the foreign
/// key noticing (that race is still caught below).
#[derive(sqlx::FromRow)]
struct GroupToDelete {
    name: String,
    is_system: bool,
    device_count: i64,
}

async fn delete_group(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i32>,
) -> Result<Response, ApiError> {
    // Lock the group so a concurrent rename cannot change what the audit
    // entry names. A device moved into the group meanwhile is caught by the
    // foreign key, not by the count read here.
    let mut tx = state.db.begin().await?;
    let GroupToDelete {
        name,
        is_system,
        device_count,
    } = sqlx::query_as(
        "SELECT name, is_system, \
                (SELECT count(*) FROM devices WHERE group_id = $1) AS device_count \
         FROM device_groups WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound("no such group"))?;

    if is_system {
        return Err(ApiError::Conflict("system groups cannot be deleted"));
    }
    if device_count > 0 {
        return Err(ApiError::Conflict(
            "the group still has devices; move them to another group first",
        ));
    }

    sqlx::query("DELETE FROM device_groups WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            // A device was assigned between the check and the delete.
            if is_foreign_key_violation(&error) {
                ApiError::Conflict("the group still has devices; move them to another group first")
            } else {
                ApiError::from(error)
            }
        })?;
    audit::record(
        &mut *tx,
        AuditEntry::new(&user.username, "group.delete", Outcome::Success)
            .target("group", id)
            .remote_addr(meta.remote_addr)
            .payload(json!({ "name": name })),
    )
    .await?;
    tx.commit().await?;

    Ok(mark_audited(StatusCode::NO_CONTENT.into_response()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad<T: std::fmt::Debug>(result: Result<T, ApiError>) {
        crate::validate::bad_request(result);
    }

    #[test]
    fn names_are_trimmed_single_line_and_bounded() {
        assert_eq!(normalize_name("  Gäste  ").unwrap(), "Gäste");
        bad(normalize_name("   "));
        bad(normalize_name(&"x".repeat(MAX_NAME_CHARS + 1)));
        bad(normalize_name("two\nlines"));
        assert!(normalize_name(&"ä".repeat(MAX_NAME_CHARS)).is_ok());
    }

    #[test]
    fn descriptions_allow_lines_but_not_control_characters() {
        assert_eq!(normalize_description(" a\nb ").unwrap(), "a\nb");
        assert_eq!(normalize_description("").unwrap(), "");
        bad(normalize_description("bell\x07"));
        bad(normalize_description(
            &"x".repeat(MAX_DESCRIPTION_CHARS + 1),
        ));
    }

    #[test]
    fn defaults_must_be_a_bounded_object() {
        assert!(validate_defaults(&json!({"internet": "allow"})).is_ok());
        bad(validate_defaults(&json!("allow")));
        bad(validate_defaults(&json!([1, 2])));
        bad(validate_defaults(
            &json!({ "k": "x".repeat(MAX_DEFAULTS_BYTES) }),
        ));
    }
}
