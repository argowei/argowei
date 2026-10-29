use argowei_core::device::{AddressSource, Device, DeviceAddress, IpProtocol};
use argowei_core::oui;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Row};

use crate::audit::{self, AuditEntry, Audited, Outcome, RequestMeta};
use crate::auth::AuthUser;
use crate::error::{db_error, ApiError};
use crate::state::AppState;

const MAX_LABEL_CHARS: usize = 64;
const MAX_NOTES_CHARS: usize = 2000;
/// Longest stretch of a changed value copied into the audit log.
const AUDIT_EXCERPT_CHARS: usize = 200;

// argowei-core intentionally has no sqlx dependency (it stays usable from
// the CLI crate without pulling in a database driver), so FromRow mapping
// for the shared types lives here instead of a derive on the structs
// themselves.
struct DeviceRow(Device);

impl FromRow<'_, PgRow> for DeviceRow {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        Ok(DeviceRow(Device {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            label: row.try_get("label")?,
            notes: row.try_get("notes")?,
            mac_address: row.try_get("mac_address")?,
            is_online: row.try_get("is_online")?,
            first_seen: row.try_get("first_seen")?,
            last_seen: row.try_get("last_seen")?,
        }))
    }
}

struct DeviceAddressRow(DeviceAddress);

impl FromRow<'_, PgRow> for DeviceAddressRow {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        let protocol: String = row.try_get("protocol")?;
        let source: String = row.try_get("source")?;

        Ok(DeviceAddressRow(DeviceAddress {
            id: row.try_get("id")?,
            device_id: row.try_get("device_id")?,
            ip_address: row.try_get("ip_address")?,
            protocol: match protocol.as_str() {
                "ipv4" => IpProtocol::V4,
                "ipv6" => IpProtocol::V6,
                other => {
                    return Err(sqlx::Error::Decode(
                        format!("unknown ip_protocol value: {other}").into(),
                    ))
                }
            },
            source: match source.as_str() {
                "arp" => AddressSource::Arp,
                "ndp" => AddressSource::Ndp,
                other => {
                    return Err(sqlx::Error::Decode(
                        format!("unknown address source value: {other}").into(),
                    ))
                }
            },
            first_seen: row.try_get("first_seen")?,
            last_seen: row.try_get("last_seen")?,
        }))
    }
}

#[derive(Serialize)]
struct DeviceWithAddresses {
    #[serde(flatten)]
    device: Device,
    /// The user's label if set, otherwise the discovered name.
    display_name: String,
    /// Manufacturer from the IEEE OUI registry; `null` if unknown or the MAC
    /// is locally administered.
    vendor: Option<&'static str>,
    /// The MAC was not assigned by a manufacturer: typically randomization by
    /// a phone or laptop, but also used by virtual interfaces.
    locally_administered_mac: bool,
    addresses: Vec<DeviceAddress>,
}

impl DeviceWithAddresses {
    fn new(device: Device, addresses: Vec<DeviceAddress>) -> Self {
        let mac = oui::lookup(&device.mac_address);
        Self {
            display_name: device.display_name().to_owned(),
            device,
            vendor: mac.vendor,
            locally_administered_mac: mac.locally_administered,
            addresses,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/devices", get(list_devices))
        .route("/api/devices/:id", patch(update_device))
}

async fn list_devices(
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceWithAddresses>>, StatusCode> {
    list_with_addresses(&state.db, None)
        .await
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Returns known devices (all, or just `only`) with their addresses, most
/// recently seen first.
/// Two queries (devices, then addresses filtered to those device ids) rather
/// than a join: with the DEVICE:ADDRESS 1:N relationship, a join would repeat
/// every device column per address row for no benefit here.
async fn list_with_addresses(
    db: &PgPool,
    only: Option<i32>,
) -> Result<Vec<DeviceWithAddresses>, sqlx::Error> {
    let devices = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, name, label, notes, mac_address, is_online, first_seen, last_seen \
         FROM devices WHERE ($1::int IS NULL OR id = $1) ORDER BY last_seen DESC",
    )
    .bind(only)
    .fetch_all(db)
    .await?;

    let device_ids: Vec<i32> = devices.iter().map(|row| row.0.id).collect();

    let addresses = sqlx::query_as::<_, DeviceAddressRow>(
        "SELECT id, device_id, ip_address, protocol::text, source, first_seen, last_seen \
         FROM device_addresses WHERE device_id = ANY($1)",
    )
    .bind(&device_ids)
    .fetch_all(db)
    .await?;

    Ok(devices
        .into_iter()
        .map(|DeviceRow(device)| {
            let addresses = addresses
                .iter()
                .filter(|DeviceAddressRow(addr)| addr.device_id == device.id)
                .map(|DeviceAddressRow(addr)| addr.clone())
                .collect();

            DeviceWithAddresses::new(device, addresses)
        })
        .collect())
}

// --- editing --------------------------------------------------------------

/// Fields a user may change. Absent fields are left alone; unknown fields are
/// rejected so a typo cannot silently do nothing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDevice {
    /// Absent: unchanged. `null` or blank: clear the label.
    #[serde(default, deserialize_with = "present")]
    label: Option<Option<String>>,
    /// Absent: unchanged. Blank: clear the notes.
    notes: Option<String>,
}

/// Distinguishes "field absent" (None) from "field is null" (Some(None)).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// Trims; a blank label means "no label". Single line, no control characters.
fn normalize_label(raw: &str) -> Result<Option<String>, ApiError> {
    let label = raw.trim();
    if label.is_empty() {
        return Ok(None);
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(ApiError::BadRequest(format!(
            "label must be at most {MAX_LABEL_CHARS} characters"
        )));
    }
    if label.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "label must be a single line without control characters".into(),
        ));
    }
    Ok(Some(label.to_owned()))
}

/// Trims; may span several lines, but no other control characters.
fn normalize_notes(raw: &str) -> Result<String, ApiError> {
    let notes = raw.trim();
    if notes.chars().count() > MAX_NOTES_CHARS {
        return Err(ApiError::BadRequest(format!(
            "notes must be at most {MAX_NOTES_CHARS} characters"
        )));
    }
    if notes
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(ApiError::BadRequest(
            "notes must not contain control characters".into(),
        ));
    }
    Ok(notes.to_owned())
}

fn excerpt(text: &str) -> String {
    text.chars().take(AUDIT_EXCERPT_CHARS).collect()
}

async fn update_device(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    meta: RequestMeta,
    Path(id): Path<i32>,
    Json(body): Json<UpdateDevice>,
) -> Result<Response, ApiError> {
    let new_label = body
        .label
        .map(|l| normalize_label(&l.unwrap_or_default()))
        .transpose()?;
    let new_notes = body.notes.as_deref().map(normalize_notes).transpose()?;

    let mut tx = state.db.begin().await.map_err(db_error)?;
    let (old_label, old_notes): (Option<String>, String) =
        sqlx::query_as("SELECT label, notes FROM devices WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?
            .ok_or(ApiError::NotFound("no such device"))?;

    let label = new_label.unwrap_or_else(|| old_label.clone());
    let notes = new_notes.unwrap_or_else(|| old_notes.clone());

    let mut changes = serde_json::Map::new();
    if label != old_label {
        changes.insert("label".into(), json!({ "from": old_label, "to": label }));
    }
    if notes != old_notes {
        changes.insert(
            "notes".into(),
            json!({ "from": excerpt(&old_notes), "to": excerpt(&notes) }),
        );
    }

    let changed = !changes.is_empty();
    if changed {
        sqlx::query("UPDATE devices SET label = $2, notes = $3 WHERE id = $1")
            .bind(id)
            .bind(&label)
            .bind(&notes)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        audit::record(
            &mut *tx,
            AuditEntry::new(&user.username, "device.update", Outcome::Success)
                .target("device", id)
                .remote_addr(meta.remote_addr)
                .payload(json!({ "changes": Value::Object(changes) })),
        )
        .await
        .map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;

    let device = list_with_addresses(&state.db, Some(id))
        .await
        .map_err(db_error)?
        .into_iter()
        .next()
        .ok_or(ApiError::NotFound("no such device"))?;

    let mut response = Json(device).into_response();
    if changed {
        // Written to the audit log above; skip the generic fallback entry.
        response.extensions_mut().insert(Audited);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn device(mac: &str) -> Device {
        Device {
            id: 1,
            name: mac.to_owned(),
            label: None,
            notes: String::new(),
            mac_address: mac.to_owned(),
            is_online: true,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn bad_request(result: Result<impl std::fmt::Debug, ApiError>) -> String {
        match result {
            Err(ApiError::BadRequest(message)) => message,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn labels_are_trimmed_and_blank_clears() {
        assert_eq!(
            normalize_label("  Wohnzimmer TV  ").unwrap().as_deref(),
            Some("Wohnzimmer TV")
        );
        assert_eq!(normalize_label("   ").unwrap(), None);
        assert_eq!(normalize_label("").unwrap(), None);
    }

    #[test]
    fn labels_have_a_length_limit_counted_in_characters() {
        assert!(normalize_label(&"ä".repeat(MAX_LABEL_CHARS)).is_ok());
        assert!(bad_request(normalize_label(&"ä".repeat(MAX_LABEL_CHARS + 1))).contains("64"));
    }

    #[test]
    fn labels_are_single_line() {
        bad_request(normalize_label("two\nlines"));
        bad_request(normalize_label("tab\there"));
        bad_request(normalize_label("nul\0byte"));
    }

    #[test]
    fn notes_may_span_lines_but_are_trimmed_and_limited() {
        assert_eq!(
            normalize_notes("  first\nsecond\n\n").unwrap(),
            "first\nsecond"
        );
        assert_eq!(normalize_notes("   ").unwrap(), "");
        assert!(normalize_notes(&"x".repeat(MAX_NOTES_CHARS)).is_ok());
        assert!(bad_request(normalize_notes(&"x".repeat(MAX_NOTES_CHARS + 1))).contains("2000"));
        bad_request(normalize_notes("bell\x07"));
    }

    #[test]
    fn registered_mac_exposes_its_vendor() {
        let json = serde_json::to_value(DeviceWithAddresses::new(
            device("b8:27:eb:12:34:56"),
            vec![],
        ))
        .unwrap();

        assert!(json["vendor"].as_str().unwrap().contains("Raspberry"));
        assert_eq!(json["locally_administered_mac"], false);
        assert_eq!(json["mac_address"], "b8:27:eb:12:34:56");
    }

    #[test]
    fn unknown_mac_has_null_vendor() {
        let json = serde_json::to_value(DeviceWithAddresses::new(
            device("0c:0d:0e:33:44:55"),
            vec![],
        ))
        .unwrap();

        assert!(json["vendor"].is_null());
        assert_eq!(json["locally_administered_mac"], false);
    }

    #[test]
    fn randomized_mac_is_flagged_instead_of_given_a_vendor() {
        let json = serde_json::to_value(DeviceWithAddresses::new(
            device("1a:56:ce:30:fa:6c"),
            vec![],
        ))
        .unwrap();

        assert!(json["vendor"].is_null());
        assert_eq!(json["locally_administered_mac"], true);
    }
}
