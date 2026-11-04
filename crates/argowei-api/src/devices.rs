//! `GET /api/devices`, `GET /api/devices/{id}` and `PATCH /api/devices/{id}`:
//! the device inventory and the fields a user may edit (label, notes, group,
//! trust level, type override). Every edit is audited with the old and new
//! values.

use argowei_core::device::{
    AddressSource, Device, DeviceAddress, IpProtocol, TrustLevel, TypeSource,
};
use argowei_core::device_type::{Classification, DeviceType};
use argowei_core::names::NameSource;
use argowei_core::oui;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Row};

use crate::audit::{self, mark_audited, AuditEntry, Outcome, RequestMeta};
use crate::auth::AuthUser;
use crate::error::{is_foreign_key_violation, ApiError};
use crate::state::AppState;
use crate::validate;

const MAX_LABEL_CHARS: usize = 64;
const MAX_NOTES_CHARS: usize = 2000;
/// Longest stretch of a changed value copied into the audit log.
const AUDIT_EXCERPT_CHARS: usize = 200;

// argowei-core intentionally has no sqlx dependency (it stays usable from
// the CLI crate without pulling in a database driver), so FromRow mapping
// for the shared types lives here instead of a derive on the structs
// themselves.
fn parse_device_type(value: &str) -> sqlx::Result<DeviceType> {
    DeviceType::parse(value)
        .ok_or_else(|| sqlx::Error::Decode(format!("unknown device type: {value}").into()))
}

struct DeviceRow(Device, String);

impl FromRow<'_, PgRow> for DeviceRow {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        let trust_level: String = row.try_get("trust_level")?;
        let trust_level = TrustLevel::parse(&trust_level).ok_or_else(|| {
            sqlx::Error::Decode(format!("unknown trust level: {trust_level}").into())
        })?;

        let name_source = row
            .try_get::<Option<String>, _>("name_source")?
            .map(|value| {
                NameSource::parse(&value).ok_or_else(|| {
                    sqlx::Error::Decode(format!("unknown name source: {value}").into())
                })
            })
            .transpose()?;

        let type_override = row
            .try_get::<Option<String>, _>("type_override")?
            .map(|value| parse_device_type(&value))
            .transpose()?;
        let evidence: serde_json::Value = row.try_get("inferred_evidence")?;
        let confidence: i16 = row.try_get("inferred_confidence")?;
        let inferred_type: String = row.try_get("inferred_type")?;
        let inferred = Classification {
            device_type: parse_device_type(&inferred_type)?,
            confidence: u8::try_from(confidence).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            evidence: serde_json::from_value(evidence)
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        };

        Ok(DeviceRow(
            Device {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                name_source,
                label: row.try_get("label")?,
                notes: row.try_get("notes")?,
                group_id: row.try_get("group_id")?,
                trust_level,
                type_override,
                inferred,
                mac_address: row.try_get("mac_address")?,
                is_online: row.try_get("is_online")?,
                first_seen: row.try_get("first_seen")?,
                last_seen: row.try_get("last_seen")?,
            },
            row.try_get("group_name")?,
        ))
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
    /// The group the device is in (`group_id` carries just the id).
    group: GroupRef,
    /// The type to show: the user's override if set, otherwise the inference
    /// (`inferred` carries the inference with its evidence).
    device_type: DeviceType,
    /// Whether `device_type` was `manual` or `inferred`.
    type_source: TypeSource,
    /// Manufacturer from the IEEE OUI registry; `null` if unknown or the MAC
    /// is locally administered.
    vendor: Option<&'static str>,
    /// The MAC was not assigned by a manufacturer: typically randomization by
    /// a phone or laptop, but also used by virtual interfaces.
    locally_administered_mac: bool,
    addresses: Vec<DeviceAddress>,
    /// What each source last called the device, preferred source first. `name`
    /// is the one chosen for display; a label the user set wins over all of them.
    names: Vec<DeviceName>,
}

#[derive(Serialize)]
struct DeviceName {
    source: NameSource,
    name: String,
    last_seen: DateTime<Utc>,
}

#[derive(Serialize)]
struct GroupRef {
    id: i32,
    name: String,
}

impl DeviceWithAddresses {
    fn new(
        device: Device,
        group_name: String,
        addresses: Vec<DeviceAddress>,
        names: Vec<DeviceName>,
    ) -> Self {
        let mac = oui::lookup(&device.mac_address);
        let group = GroupRef {
            id: device.group_id,
            name: group_name,
        };
        Self {
            display_name: device.display_name().to_owned(),
            group,
            device_type: device.device_type(),
            type_source: device.type_source(),
            device,
            vendor: mac.vendor,
            locally_administered_mac: mac.locally_administered,
            addresses,
            names,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/devices", get(list_devices))
        .route("/api/devices/:id", get(get_device).patch(update_device))
}

async fn list_devices(
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceWithAddresses>>, ApiError> {
    Ok(Json(list_with_addresses(&state.db, None).await?))
}

async fn get_device(
    State(state): State<AppState>,
    Path(id): Path<i32>,
) -> Result<Json<DeviceWithAddresses>, ApiError> {
    list_with_addresses(&state.db, Some(id))
        .await?
        .into_iter()
        .next()
        .map(Json)
        .ok_or(ApiError::NotFound("no such device"))
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
        "SELECT d.id, d.name, d.name_source, d.label, d.notes, d.group_id, g.name AS group_name, \
                d.trust_level, d.type_override, d.inferred_type, d.inferred_confidence, \
                d.inferred_evidence, d.mac_address, d.is_online, d.first_seen, d.last_seen \
         FROM devices d JOIN device_groups g ON g.id = d.group_id \
         WHERE ($1::int IS NULL OR d.id = $1) ORDER BY d.last_seen DESC",
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

    let names: Vec<(i32, NameSource, String, DateTime<Utc>)> = {
        let rows: Vec<(i32, String, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT device_id, source, name, last_seen FROM device_names \
             WHERE device_id = ANY($1)",
        )
        .bind(&device_ids)
        .fetch_all(db)
        .await?;
        rows.into_iter()
            .filter_map(|(id, source, name, seen)| {
                NameSource::parse(&source).map(|source| (id, source, name, seen))
            })
            .collect()
    };

    Ok(devices
        .into_iter()
        .map(|DeviceRow(device, group_name)| {
            let addresses = addresses
                .iter()
                .filter(|DeviceAddressRow(addr)| addr.device_id == device.id)
                .map(|DeviceAddressRow(addr)| addr.clone())
                .collect();

            let mut names: Vec<DeviceName> = names
                .iter()
                .filter(|(id, ..)| *id == device.id)
                .map(|(_, source, name, last_seen)| DeviceName {
                    source: *source,
                    name: name.clone(),
                    last_seen: *last_seen,
                })
                .collect();
            names.sort_by_key(|n| n.source.priority());

            DeviceWithAddresses::new(device, group_name, addresses, names)
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
    /// Absent: unchanged. `null` is rejected: every device is in a group,
    /// and "Unassigned" is one (move a device back by its id).
    #[serde(default, deserialize_with = "required")]
    group_id: Option<i32>,
    /// Absent: unchanged. `null` is rejected: there is no "no trust level".
    #[serde(default, deserialize_with = "required")]
    trust_level: Option<TrustLevel>,
    /// Absent: unchanged. A type sets the manual override; `null` removes it,
    /// so the inferred type shows again.
    #[serde(default, deserialize_with = "present")]
    type_override: Option<Option<DeviceType>>,
}

/// For fields that may be omitted but, when present, must have a real value
/// (a plain `Option` would quietly treat `null` as omitted).
fn required<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// Distinguishes "field absent" (None) from "field is null" (Some(None)).
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// A blank label means "no label", so the discovered name shows again.
fn normalize_label(raw: &str) -> Result<Option<String>, ApiError> {
    let label = validate::single_line(raw, "label", 0..=MAX_LABEL_CHARS)?;
    Ok((!label.is_empty()).then_some(label))
}

fn normalize_notes(raw: &str) -> Result<String, ApiError> {
    validate::multi_line(raw, "notes", 0..=MAX_NOTES_CHARS)
}

fn excerpt(text: &str) -> String {
    text.chars().take(AUDIT_EXCERPT_CHARS).collect()
}

/// What a user can change about a device, read under a row lock: two edits at
/// once are applied one after the other, and each is audited against the values
/// it really replaced.
#[derive(sqlx::FromRow)]
struct EditableDevice {
    label: Option<String>,
    notes: String,
    group_id: i32,
    trust_level: String,
    type_override: Option<String>,
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

    // The row stays locked until commit: the values read here are what the
    // audit entry reports as "before", so no concurrent edit may land between
    // this read and the update.
    let mut tx = state.db.begin().await?;
    let EditableDevice {
        label: old_label,
        notes: old_notes,
        group_id: old_group,
        trust_level: old_trust,
        type_override: old_type,
    } = sqlx::query_as(
        "SELECT label, notes, group_id, trust_level, type_override \
         FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound("no such device"))?;
    let old_trust = TrustLevel::parse(&old_trust).ok_or(ApiError::Unavailable)?;
    let old_type = old_type
        .map(|value| DeviceType::parse(&value).ok_or(ApiError::Unavailable))
        .transpose()?;

    let label = new_label.unwrap_or_else(|| old_label.clone());
    let notes = new_notes.unwrap_or_else(|| old_notes.clone());
    let group = body.group_id.unwrap_or(old_group);
    let trust = body.trust_level.unwrap_or(old_trust);
    let type_override = body.type_override.unwrap_or(old_type);

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
    if trust != old_trust {
        changes.insert(
            "trust_level".into(),
            json!({ "from": old_trust, "to": trust }),
        );
    }

    if type_override != old_type {
        changes.insert(
            "type_override".into(),
            json!({ "from": old_type, "to": type_override }),
        );
    }

    let changed_group = group != old_group;
    let changed = !changes.is_empty() || changed_group;
    if changed {
        sqlx::query(
            "UPDATE devices SET label = $2, notes = $3, group_id = $4, trust_level = $5, \
                 type_override = $6 WHERE id = $1",
        )
        .bind(id)
        .bind(&label)
        .bind(&notes)
        .bind(group)
        .bind(trust.as_str())
        .bind(type_override.map(DeviceType::as_str))
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            if is_foreign_key_violation(&error) {
                ApiError::BadRequest("no such group".into())
            } else {
                ApiError::from(error)
            }
        })?;

        if changed_group {
            // Names make the audit entry readable after a group is renamed.
            let names: Vec<(i32, String)> =
                sqlx::query_as("SELECT id, name FROM device_groups WHERE id = ANY($1)")
                    .bind(vec![old_group, group])
                    .fetch_all(&mut *tx)
                    .await?;
            let describe = |group: i32| {
                let name = names
                    .iter()
                    .find(|(id, _)| *id == group)
                    .map(|(_, name)| name.as_str());
                json!({ "id": group, "name": name })
            };
            changes.insert(
                "group".into(),
                json!({ "from": describe(old_group), "to": describe(group) }),
            );
        }

        audit::record(
            &mut *tx,
            AuditEntry::new(&user.username, "device.update", Outcome::Success)
                .target("device", id)
                .remote_addr(meta.remote_addr)
                .payload(json!({ "changes": Value::Object(changes) })),
        )
        .await?;
    }
    tx.commit().await?;

    let device = list_with_addresses(&state.db, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or(ApiError::NotFound("no such device"))?;

    let response = Json(device).into_response();
    let response = if changed {
        // Audited above; a request that changed nothing is left to the
        // middleware's generic entry.
        mark_audited(response)
    } else {
        response
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use crate::validate::bad_request;
    use chrono::Utc;

    use super::*;

    fn device(mac: &str) -> Device {
        Device {
            id: 1,
            name: mac.to_owned(),
            name_source: None,
            label: None,
            notes: String::new(),
            group_id: 1,
            trust_level: TrustLevel::default(),
            type_override: None,
            inferred: Classification::default(),
            mac_address: mac.to_owned(),
            is_online: true,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
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
            "Unassigned".to_owned(),
            vec![],
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
            "Unassigned".to_owned(),
            vec![],
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
            "Unassigned".to_owned(),
            vec![],
            vec![],
        ))
        .unwrap();

        assert!(json["vendor"].is_null());
        assert_eq!(json["locally_administered_mac"], true);
    }
}
