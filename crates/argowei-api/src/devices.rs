use argowei_core::device::{AddressSource, Device, DeviceAddress, IpProtocol};
use argowei_core::oui;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgPool, Row};

use crate::state::AppState;

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
            device,
            vendor: mac.vendor,
            locally_administered_mac: mac.locally_administered,
            addresses,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/api/devices", get(list_devices))
}

async fn list_devices(
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceWithAddresses>>, StatusCode> {
    list_with_addresses(&state.db)
        .await
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Returns all known devices with their addresses, most recently seen first.
/// Two queries (devices, then addresses filtered to those device ids) rather
/// than a join: with the DEVICE:ADDRESS 1:N relationship, a join would repeat
/// every device column per address row for no benefit here.
async fn list_with_addresses(db: &PgPool) -> Result<Vec<DeviceWithAddresses>, sqlx::Error> {
    let devices = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, name, mac_address, is_online, first_seen, last_seen \
         FROM devices ORDER BY last_seen DESC",
    )
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn device(mac: &str) -> Device {
        Device {
            id: 1,
            name: mac.to_owned(),
            mac_address: mac.to_owned(),
            is_online: true,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
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
