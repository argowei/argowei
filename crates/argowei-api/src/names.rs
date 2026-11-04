//! Looking up what discovered devices call themselves, and storing it.
//!
//! After a scan, the devices that scan saw are looked up, but only when it is
//! worth it: a device is asked about once it is new, then again at a refresh
//! interval, and sooner while no name is known at all. That keeps the traffic
//! to a few small packets per device per hour instead of per scan.
//!
//! Lookups happen *after* the scan has been stored and run in a separate step,
//! so nothing a resolver does (time out, fail, even panic) can fail a
//! discovery run.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use argowei_collector::names::{
    resolve_all, DhcpLeaseResolver, HostnameResolver, MdnsResolver, NameSource, NetbiosResolver,
    RdnsResolver, Target, TargetNames,
};
use argowei_core::names::{choose_name, sanitize_name};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;

use crate::config::Settings;
use crate::events::{self, Severity};

/// A device without any name is looked up again after this fraction of the
/// refresh interval; it may simply have been asleep.
const UNNAMED_RETRY_DIVISOR: u32 = 6;

/// Where names come from. A trait so tests can supply canned answers.
pub trait NameLookup: Send + Sync + 'static {
    fn lookup(&self, targets: &[Target]) -> Vec<TargetNames>;
}

/// The real lookup, built on the collector's resolvers.
pub struct CollectorLookup {
    resolvers: Vec<Arc<dyn HostnameResolver>>,
    timeout: Duration,
    concurrency: usize,
}

impl CollectorLookup {
    pub fn new(
        resolvers: Vec<Arc<dyn HostnameResolver>>,
        timeout: Duration,
        concurrency: usize,
    ) -> Self {
        Self {
            resolvers,
            timeout,
            concurrency,
        }
    }
}

impl NameLookup for CollectorLookup {
    fn lookup(&self, targets: &[Target]) -> Vec<TargetNames> {
        resolve_all(&self.resolvers, targets, self.timeout, self.concurrency)
    }
}

/// How and how often names are looked up.
#[derive(Clone)]
pub struct NamePipeline {
    pub lookup: Arc<dyn NameLookup>,
    /// How long a known name is trusted before the device is asked again.
    pub refresh: Duration,
}

impl NamePipeline {
    /// Builds the pipeline from the settings; `None` when no source is enabled.
    pub fn from_settings(settings: &Settings) -> Option<Self> {
        let mut resolvers: Vec<Arc<dyn HostnameResolver>> = Vec::new();

        for source in &settings.hostname_sources {
            match source {
                NameSource::Dhcp => match &settings.dhcp_leases_file {
                    Some(path) => resolvers.push(Arc::new(DhcpLeaseResolver::new(path))),
                    None => tracing::info!(
                        "DHCP names enabled but ARGOWEI_DHCP_LEASES_FILE is not set; skipping that source"
                    ),
                },
                NameSource::Mdns => resolvers.push(Arc::new(MdnsResolver::default())),
                NameSource::Netbios => resolvers.push(Arc::new(NetbiosResolver::default())),
                NameSource::Rdns => {
                    let resolver = match settings.dns_server {
                        Some(server) => RdnsResolver::new(vec![server]),
                        None => RdnsResolver::from_system(),
                    };
                    if resolver.servers().is_empty() {
                        tracing::info!(
                            "no local DNS server found for reverse lookups; set ARGOWEI_DNS_SERVER to your router"
                        );
                    }
                    resolvers.push(Arc::new(resolver));
                }
            }
        }

        if resolvers.is_empty() {
            return None;
        }
        Some(Self {
            lookup: Arc::new(CollectorLookup::new(
                resolvers,
                Duration::from_millis(settings.hostname_timeout_ms),
                settings.hostname_concurrency,
            )),
            refresh: Duration::from_secs(settings.hostname_refresh_secs),
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct NamesSummary {
    /// Devices that were looked up.
    pub looked_up: usize,
    /// Devices whose displayed name changed as a result.
    pub renamed: usize,
    /// Resolver failures (not "no answer"): informational.
    pub resolver_errors: usize,
}

#[derive(Debug)]
pub enum NamesError {
    Task(tokio::task::JoinError),
    Database(sqlx::Error),
}

impl std::fmt::Display for NamesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Task(error) => write!(f, "name lookup task failed: {error}"),
            Self::Database(error) => write!(f, "could not store names: {error}"),
        }
    }
}

impl std::error::Error for NamesError {}

/// The step the scheduler runs after a scan: look names up and store them,
/// and never let a problem here reach the scan itself. Failures are logged.
pub async fn after_scan(db: &PgPool, pipeline: &NamePipeline, interface: &str) {
    match resolve_pending(db, pipeline, interface, Utc::now()).await {
        Ok(summary) if summary.looked_up > 0 => {
            tracing::info!(%interface, ?summary, "device names looked up");
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%interface, %error, "device name lookup failed"),
    }
}

/// Looks up the devices the latest scan of `interface` saw that are due for
/// it, and stores the answers.
pub async fn resolve_pending(
    db: &PgPool,
    pipeline: &NamePipeline,
    interface: &str,
    now: DateTime<Utc>,
) -> Result<NamesSummary, NamesError> {
    let refresh =
        chrono::Duration::from_std(pipeline.refresh).unwrap_or(chrono::Duration::hours(1));
    let named_before = now - refresh;
    let unnamed_before = now - refresh / UNNAMED_RETRY_DIVISOR as i32;

    let due: Vec<(i32, String, String)> = sqlx::query_as(
        "SELECT d.id, d.mac_address, a.ip_address \
         FROM devices d \
         JOIN LATERAL (SELECT ip_address FROM device_addresses \
                       WHERE device_id = d.id AND protocol = 'ipv4' \
                       ORDER BY last_seen DESC LIMIT 1) a ON true \
         WHERE d.last_seen_interface = $1 \
           AND d.last_seen = (SELECT max(scanned_at) FROM discovery_scans WHERE interface = $1) \
           AND (d.names_checked_at IS NULL \
                OR (d.name_source IS NULL AND d.names_checked_at <= $2) \
                OR (d.name_source IS NOT NULL AND d.names_checked_at <= $3)) \
         ORDER BY d.id",
    )
    .bind(interface)
    .bind(unnamed_before)
    .bind(named_before)
    .fetch_all(db)
    .await
    .map_err(NamesError::Database)?;

    let mut ids = Vec::new();
    let mut targets = Vec::new();
    for (id, mac, ip) in due {
        if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            ids.push(id);
            targets.push(Target { ip, mac });
        }
    }
    if targets.is_empty() {
        return Ok(NamesSummary::default());
    }

    let lookup = Arc::clone(&pipeline.lookup);
    let looked_up = tokio::task::spawn_blocking(move || {
        let results = lookup.lookup(&targets);
        (targets, results)
    })
    .await
    .map_err(NamesError::Task)?
    .1;

    store(db, &ids, &looked_up, now)
        .await
        .map_err(NamesError::Database)
}

/// Stores the answers for the looked-up devices in one transaction.
async fn store(
    db: &PgPool,
    ids: &[i32],
    results: &[TargetNames],
    now: DateTime<Utc>,
) -> sqlx::Result<NamesSummary> {
    let mut summary = NamesSummary {
        looked_up: ids.len(),
        ..NamesSummary::default()
    };
    let mut tx = db.begin().await?;

    // Results come back in target order; match them up by position, and skip
    // anything that does not line up rather than guess.
    for (device_id, result) in ids.iter().zip(results) {
        summary.resolver_errors += result.errors.len();

        for resolved in &result.names {
            // Answers come from the network; never store one unchecked.
            let Some(name) = sanitize_name(&resolved.name, Some(result.target.ip)) else {
                continue;
            };
            sqlx::query(
                "INSERT INTO device_names (device_id, source, name, first_seen, last_seen) \
                 VALUES ($1, $2, $3, $4, $4) \
                 ON CONFLICT (device_id, source) DO UPDATE SET \
                     name = EXCLUDED.name, last_seen = EXCLUDED.last_seen",
            )
            .bind(device_id)
            .bind(resolved.source.as_str())
            .bind(name)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query("UPDATE devices SET names_checked_at = $2 WHERE id = $1")
            .bind(device_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;

        if refresh_displayed_name(&mut tx, *device_id, now).await? {
            summary.renamed += 1;
        }
    }

    tx.commit().await?;
    Ok(summary)
}

/// Chooses the name to show from everything the sources said, and records an
/// event when it changes. The user's label is a separate column and is never
/// touched. Returns whether the displayed name changed.
async fn refresh_displayed_name(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: i32,
    now: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT source, name FROM device_names WHERE device_id = $1")
            .bind(device_id)
            .fetch_all(&mut **tx)
            .await?;
    let known: Vec<(NameSource, String)> = rows
        .into_iter()
        .filter_map(|(source, name)| NameSource::parse(&source).map(|source| (source, name)))
        .collect();

    let Some((source, name)) = choose_name(&known) else {
        return Ok(false);
    };

    // Locked so two lookups of the same device cannot both see the old name
    // and both record the rename.
    let (current_name, current_source): (String, Option<String>) =
        sqlx::query_as("SELECT name, name_source FROM devices WHERE id = $1 FOR UPDATE")
            .bind(device_id)
            .fetch_one(&mut **tx)
            .await?;
    if current_name == name && current_source.as_deref() == Some(source.as_str()) {
        return Ok(false);
    }

    sqlx::query("UPDATE devices SET name = $2, name_source = $3 WHERE id = $1")
        .bind(device_id)
        .bind(name)
        .bind(source.as_str())
        .execute(&mut **tx)
        .await?;

    let renamed = current_name != name;
    if renamed {
        events::record(
            &mut **tx,
            now,
            events::DEVICE_NAMED,
            Severity::Info,
            Some(device_id),
            json!({
                "from": current_name,
                "to": name,
                "source": source,
                "answers": known.iter().map(|(s, n)| json!({ "source": s, "name": n })).collect::<Vec<_>>(),
            }),
        )
        .await?;
    }
    Ok(renamed)
}
