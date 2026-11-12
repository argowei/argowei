//! State shared by all handlers.

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use crate::auth::AuthState;
use crate::config::Settings;
use crate::discovery::DiscoveryStatus;
use crate::scans::{ScanConfig, ScanRunner};

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub auth: Arc<AuthState>,
    /// In-memory outcome of the latest discovery scans (not persisted).
    pub discovery: DiscoveryStatus,
    /// Runs port scans in the background.
    pub scans: ScanRunner,
    /// Wakes the scan scheduler when a schedule changes.
    pub schedule_changed: Arc<tokio::sync::Notify>,
}

impl AppState {
    /// Builds a lazily-connecting pool. The server runs migrations before
    /// serving requests; tests can still construct a state without a database.
    pub fn connect(settings: &Settings) -> Self {
        let db = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(3))
            .connect_lazy(&settings.database_url())
            .expect("failed to build Postgres pool");

        let auth = AuthState::new(
            settings.cookie_secure,
            chrono::Duration::hours(settings.session_ttl_hours),
        );

        Self::new(db, auth).with_scan_config(ScanConfig::from(settings))
    }

    pub fn new(db: sqlx::PgPool, auth: AuthState) -> Self {
        Self {
            db,
            auth: Arc::new(auth),
            discovery: DiscoveryStatus::default(),
            scans: ScanRunner::new(ScanConfig::default()),
            schedule_changed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Replaces how port scans run (the nmap binary, limits, allowed ranges).
    pub fn with_scan_config(mut self, config: ScanConfig) -> Self {
        self.scans = ScanRunner::new(config);
        self
    }
}
