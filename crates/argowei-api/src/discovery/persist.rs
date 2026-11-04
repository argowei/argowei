//! Storing one scan: devices, addresses, sightings, presence transitions,
//! device types and new-device alerts, all in a single transaction.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};

use argowei_core::device::AddressSource;
use argowei_core::device_type::{classify, Signals};
use argowei_core::oui;

use super::{ObservedHost, ScanSummary};
use crate::alerts;
use crate::events::{self, Severity};
use crate::presence::PresencePolicy;

type Tx<'a> = Transaction<'a, Postgres>;

/// Value of `discovery_scans.method` for the scans stored here.
const SCAN_METHOD: &str = "arp";

/// Stores one scan and updates presence. Everything happens in a single
/// transaction so a failure leaves no half-recorded scan behind.
///
/// The scan itself and each sighting are kept as evidence, so presence can be
/// analyzed later and "missed scans" is a query over what actually ran.
/// Devices are upserted by MAC and addresses by (device, IP): re-scanning only
/// moves `last_seen` forward. When an IP shows up on a different device, the
/// previous holder's row is kept (history); the newest `last_seen` marks the
/// current holder.
///
/// A device that did not answer is *not* marked offline for that alone: see
/// [`PresencePolicy`]. State changes are recorded as events
/// (`device.discovered`, `device.online`, `device.offline`), each exactly once
/// per transition, in the same transaction as the change.
pub async fn record_scan(
    db: &PgPool,
    interface: &str,
    hosts: &[ObservedHost],
    seen_at: DateTime<Utc>,
    policy: &PresencePolicy,
) -> sqlx::Result<ScanSummary> {
    let mut summary = ScanSummary {
        hosts_seen: hosts.len(),
        ..ScanSummary::default()
    };
    let mut tx = db.begin().await?;

    let scan = ScanContext {
        id: insert_scan(&mut tx, interface, hosts.len(), seen_at).await?,
        interface,
        seen_at,
        // Devices found while the interface is still being learned do not alert.
        baseline: alerts::scan_in_baseline(&mut tx, interface, seen_at).await?,
    };

    for host in hosts {
        let ip = host.ip.to_string();
        let device = upsert_device(&mut tx, &scan, &host.mac).await?;
        classify_device(&mut tx, device.id, &host.mac).await?;
        record_device_event(&mut tx, &scan, &device, host, &ip, &mut summary).await?;
        record_sighting(&mut tx, scan.id, device.id, &ip).await?;
        let address = upsert_address(&mut tx, device.id, &ip, seen_at).await?;

        summary.new_devices += usize::from(device.inserted);
        summary.new_addresses += usize::from(address.inserted);
        summary.reassigned_addresses += usize::from(address.inserted && address.held_by_other);
    }

    summary.went_offline =
        mark_missing_devices_offline(&mut tx, interface, seen_at, policy).await?;

    tx.commit().await?;
    Ok(summary)
}

/// What every step of one scan needs to know about it.
struct ScanContext<'a> {
    id: i64,
    interface: &'a str,
    seen_at: DateTime<Utc>,
    /// The interface is still inside its baseline window: new devices are
    /// learned silently.
    baseline: bool,
}

/// A device row after the upsert, with what it looked like before.
struct UpsertedDevice {
    id: i32,
    inserted: bool,
    /// `None` for a new device; otherwise whether it was online, and when it
    /// was last seen, before this scan.
    previous: Option<(bool, DateTime<Utc>)>,
}

struct UpsertedAddress {
    inserted: bool,
    /// Another device already had this IP: the address moved (DHCP reuse,
    /// a replaced device) or two devices claim it.
    held_by_other: bool,
}

async fn insert_scan(
    tx: &mut Tx<'_>,
    interface: &str,
    hosts_seen: usize,
    scanned_at: DateTime<Utc>,
) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "INSERT INTO discovery_scans (interface, method, scanned_at, hosts_seen) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(interface)
    .bind(SCAN_METHOD)
    .bind(scanned_at)
    .bind(hosts_seen as i32)
    .fetch_one(&mut **tx)
    .await
}

/// Inserts the device, or marks a known one online and moves `last_seen`
/// forward. A new device is named after its MAC; the name lookups
/// ([`crate::names`]) replace that with a real name once they find one.
async fn upsert_device(
    tx: &mut Tx<'_>,
    scan: &ScanContext<'_>,
    mac: &str,
) -> sqlx::Result<UpsertedDevice> {
    // Lock the row so concurrent scans of different interfaces cannot both
    // report the same transition.
    let previous: Option<(bool, DateTime<Utc>)> = sqlx::query_as(
        "SELECT is_online, last_seen FROM devices WHERE mac_address = $1 FOR UPDATE",
    )
    .bind(mac)
    .fetch_optional(&mut **tx)
    .await?;

    // `xmax = 0` is true only for a row this statement inserted: an upsert
    // that hit the conflict branch has the updating transaction's id there.
    let (id, inserted): (i32, bool) = sqlx::query_as(
        "INSERT INTO devices \
             (name, mac_address, is_online, first_seen, last_seen, last_seen_interface) \
         VALUES ($1, $1, true, $2, $2, $3) \
         ON CONFLICT (mac_address) DO UPDATE SET \
             is_online = true, \
             last_seen_interface = CASE \
                 WHEN EXCLUDED.last_seen >= devices.last_seen \
                 THEN EXCLUDED.last_seen_interface \
                 ELSE devices.last_seen_interface END, \
             last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen) \
         RETURNING id, (xmax = 0)",
    )
    .bind(mac)
    .bind(scan.seen_at)
    .bind(scan.interface)
    .fetch_one(&mut **tx)
    .await?;

    Ok(UpsertedDevice {
        id,
        inserted,
        previous,
    })
}

/// Records `device.discovered` for a new device (and raises the new-device
/// alert outside the baseline), or `device.online` for a known device that
/// was offline. A device that simply stayed online records nothing.
async fn record_device_event(
    tx: &mut Tx<'_>,
    scan: &ScanContext<'_>,
    device: &UpsertedDevice,
    host: &ObservedHost,
    ip: &str,
    summary: &mut ScanSummary,
) -> sqlx::Result<()> {
    if device.inserted {
        events::record(
            &mut **tx,
            scan.seen_at,
            events::DEVICE_DISCOVERED,
            Severity::Info,
            Some(device.id),
            // Whether the device was learned silently: analyses of how a
            // network grew should be able to tell baseline from new.
            json!({
                "interface": scan.interface,
                "scan_id": scan.id,
                "ip": ip,
                "baseline": scan.baseline,
            }),
        )
        .await?;

        if !scan.baseline
            && alerts::raise_new_device(
                tx,
                device.id,
                scan.seen_at,
                scan.interface,
                scan.id,
                &host.mac,
                ip,
            )
            .await?
        {
            summary.new_alerts += 1;
        }
    } else if let Some((false, offline_since)) = device.previous {
        summary.came_online += 1;
        events::record(
            &mut **tx,
            scan.seen_at,
            events::DEVICE_ONLINE,
            Severity::Info,
            Some(device.id),
            json!({
                "interface": scan.interface,
                "scan_id": scan.id,
                "ip": ip,
                "last_seen_before": offline_since,
            }),
        )
        .await?;
    }
    Ok(())
}

/// The evidence that this device answered this scan, at this address.
async fn record_sighting(
    tx: &mut Tx<'_>,
    scan_id: i64,
    device_id: i32,
    ip: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO device_sightings (scan_id, device_id, ip_address) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(scan_id)
    .bind(device_id)
    .bind(ip)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn upsert_address(
    tx: &mut Tx<'_>,
    device_id: i32,
    ip: &str,
    seen_at: DateTime<Utc>,
) -> sqlx::Result<UpsertedAddress> {
    let (inserted, held_by_other): (bool, bool) = sqlx::query_as(
        "INSERT INTO device_addresses \
             (device_id, ip_address, protocol, source, first_seen, last_seen) \
         VALUES ($1, $2, 'ipv4', $3, $4, $4) \
         ON CONFLICT (device_id, ip_address) DO UPDATE SET \
             last_seen = GREATEST(device_addresses.last_seen, EXCLUDED.last_seen) \
         RETURNING (xmax = 0), \
             EXISTS (SELECT 1 FROM device_addresses other \
                     WHERE other.ip_address = $2 AND other.device_id <> $1)",
    )
    .bind(device_id)
    .bind(ip)
    .bind(AddressSource::Arp.as_str())
    .bind(seen_at)
    .fetch_one(&mut **tx)
    .await?;

    Ok(UpsertedAddress {
        inserted,
        held_by_other,
    })
}

/// Re-infers a device's type from what is known about it and stores the
/// result. This only ever writes the *inferred* columns: a user's manual
/// override lives in its own column and is never touched here. Skips the
/// write when nothing changed, so a scan does not rewrite every row.
///
/// Discovery knows the vendor and the MAC kind; other signals
/// ([`Signals`]) are left empty here.
async fn classify_device(tx: &mut Tx<'_>, device_id: i32, mac: &str) -> sqlx::Result<()> {
    let mac_info = oui::lookup(mac);
    let classification = classify(&Signals {
        vendor: mac_info.vendor,
        locally_administered_mac: mac_info.locally_administered,
        ..Signals::default()
    });
    let evidence = serde_json::to_value(&classification.evidence)
        .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;

    sqlx::query(
        "UPDATE devices SET inferred_type = $2, inferred_confidence = $3, \
             inferred_evidence = $4 \
         WHERE id = $1 \
           AND (inferred_type, inferred_confidence, inferred_evidence) \
               IS DISTINCT FROM ($2, $3::smallint, $4::jsonb)",
    )
    .bind(device_id)
    .bind(classification.device_type.as_str())
    .bind(i16::from(classification.confidence))
    .bind(evidence)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Online devices last seen on this interface, but not in the scan just
/// recorded, are checked against the policy. Missed scans are counted from
/// the scans that actually ran since the device was last seen.
async fn mark_missing_devices_offline(
    tx: &mut Tx<'_>,
    interface: &str,
    now: DateTime<Utc>,
    policy: &PresencePolicy,
) -> sqlx::Result<usize> {
    let candidates: Vec<(i32, DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT d.id, d.last_seen, \
                (SELECT count(*) FROM discovery_scans s \
                 WHERE s.interface = d.last_seen_interface AND s.scanned_at > d.last_seen) \
         FROM devices d \
         WHERE d.is_online AND d.last_seen_interface = $1 AND d.last_seen < $2 \
         ORDER BY d.id",
    )
    .bind(interface)
    .bind(now)
    .fetch_all(&mut **tx)
    .await?;

    let mut went_offline = 0;
    for (device_id, last_seen, missed_scans) in candidates {
        if !policy.is_offline(missed_scans, last_seen, now) {
            continue;
        }

        sqlx::query("UPDATE devices SET is_online = false WHERE id = $1")
            .bind(device_id)
            .execute(&mut **tx)
            .await?;
        events::record(
            &mut **tx,
            now,
            events::DEVICE_OFFLINE,
            Severity::Info,
            Some(device_id),
            json!({
                "interface": interface,
                "last_seen": last_seen,
                "missed_scans": missed_scans,
                "silent_for_secs": now.signed_duration_since(last_seen).num_seconds(),
                "policy": {
                    "offline_after_missed_scans": policy.offline_after_missed_scans,
                    "offline_after_secs": policy.offline_after.as_secs(),
                },
            }),
        )
        .await?;
        went_offline += 1;
    }

    Ok(went_offline)
}
