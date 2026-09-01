/// Application settings.
///
/// Values are read from environment variables (see .env.example), falling
/// back to the defaults below for local development without Docker. The
/// defaults mirror docker-compose.yml so a plain `cargo run` against a
/// locally running Postgres/Redis works out of the box.
pub struct Settings {
    pub postgres_user: String,
    pub postgres_password: String,
    pub postgres_db: String,
    pub postgres_host: String,
    pub postgres_port: u16,

    pub redis_host: String,
    pub redis_port: u16,
    pub redis_db: u8,
}

impl Settings {
    pub fn from_env() -> Self {
        Self {
            postgres_user: env_or("POSTGRES_USER", "argowei"),
            postgres_password: env_or("POSTGRES_PASSWORD", "argowei"),
            postgres_db: env_or("POSTGRES_DB", "argowei"),
            postgres_host: env_or("POSTGRES_HOST", "localhost"),
            postgres_port: env_or("POSTGRES_PORT", "5432")
                .parse()
                .expect("POSTGRES_PORT must be a valid port number"),

            redis_host: env_or("REDIS_HOST", "localhost"),
            redis_port: env_or("REDIS_PORT", "6379")
                .parse()
                .expect("REDIS_PORT must be a valid port number"),
            redis_db: env_or("REDIS_DB", "0")
                .parse()
                .expect("REDIS_DB must be a valid database index"),
        }
    }

    /// Postgres DSN, assembled from the discrete settings above.
    pub fn database_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.postgres_user,
            self.postgres_password,
            self.postgres_host,
            self.postgres_port,
            self.postgres_db
        )
    }

    pub fn redis_url(&self) -> String {
        format!(
            "redis://{}:{}/{}",
            self.redis_host, self.redis_port, self.redis_db
        )
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
