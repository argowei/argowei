//! State shared by all handlers.

use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use crate::auth::AuthState;
use crate::config::Settings;
use crate::discovery::DiscoveryStatus;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub auth: Arc<AuthState>,
    /// In-memory outcome of the latest discovery scans (not persisted).
    pub discovery: DiscoveryStatus,
}

impl AppState {
    /// Builds a lazily-connecting pool: no connection is made until the first
    /// query, so the app starts even before Postgres is up. The acquire timeout
    /// is kept short so `/api/health` fails fast instead of hanging on
    /// sqlx's default 30s connect-retry backoff when the database is down.
    pub fn connect(settings: &Settings) -> Self {
        let db = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(3))
            .connect_lazy(&settings.database_url())
            .expect("failed to build Postgres pool");

        let auth = AuthState::new(
            settings.cookie_secure,
            chrono::Duration::hours(settings.session_ttl_hours),
        );

        Self::new(db, auth)
    }

    pub fn new(db: sqlx::PgPool, auth: AuthState) -> Self {
        Self {
            db,
            auth: Arc::new(auth),
            discovery: DiscoveryStatus::default(),
        }
    }
}
