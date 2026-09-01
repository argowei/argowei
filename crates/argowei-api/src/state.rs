use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use crate::config::Settings;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: redis::Client,
}

impl AppState {
    /// Builds a lazily-connecting pool/client: no connection is made until
    /// the first query, mirroring the previous SQLAlchemy/redis-py setup so
    /// the app starts even before Postgres/Redis are up. The acquire timeout
    /// is kept short so `/api/health` fails fast instead of hanging on
    /// sqlx's default 30s connect-retry backoff when the database is down.
    pub fn connect(settings: &Settings) -> Self {
        let db = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(3))
            .connect_lazy(&settings.database_url())
            .expect("failed to build Postgres pool");

        let redis =
            redis::Client::open(settings.redis_url()).expect("failed to build Redis client");

        Self { db, redis }
    }
}
