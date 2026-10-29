/// Application settings.
///
/// Values are read from environment variables (see .env.example), falling
/// back to the defaults below for local development without Docker. The
/// defaults mirror docker-compose.yml so a plain `cargo run` against a
/// locally running Postgres/Redis works out of the box.
pub struct Settings {
    /// Address the API listens on.
    pub bind_address: std::net::SocketAddr,

    pub postgres_user: String,
    pub postgres_password: String,
    pub postgres_db: String,
    pub postgres_host: String,
    pub postgres_port: u16,

    pub redis_host: String,
    pub redis_port: u16,
    pub redis_db: u8,

    /// Mark the session cookie `Secure`. Leave off for plain-HTTP LAN
    /// deployments; enable when served over HTTPS (e.g. behind nginx).
    pub cookie_secure: bool,
    pub session_ttl_hours: i64,

    /// Interfaces to scan periodically. Empty disables scheduled discovery.
    pub discovery_interfaces: Vec<String>,
    pub discovery_interval_secs: u64,
    pub discovery_timeout_secs: u64,
    /// Consecutive missed scans before a device may be marked offline.
    pub offline_after_missed_scans: u32,
    /// Minimum time since last seen before a device may be marked offline.
    pub offline_after_secs: u64,
}

impl Settings {
    pub fn from_env() -> Self {
        Self {
            bind_address: env_or("ARGOWEI_BIND_ADDRESS", "0.0.0.0:8000")
                .parse()
                .expect("ARGOWEI_BIND_ADDRESS must be an address like 0.0.0.0:8000"),
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

            cookie_secure: matches!(
                env_or("ARGOWEI_COOKIE_SECURE", "false").as_str(),
                "1" | "true"
            ),
            session_ttl_hours: env_or("ARGOWEI_SESSION_TTL_HOURS", "24")
                .parse()
                .expect("ARGOWEI_SESSION_TTL_HOURS must be a number of hours"),

            discovery_interfaces: parse_interface_list(&env_or("ARGOWEI_DISCOVERY_INTERFACES", "")),
            discovery_interval_secs: bounded("ARGOWEI_DISCOVERY_INTERVAL_SECS", 300, 30, 86_400),
            discovery_timeout_secs: bounded("ARGOWEI_DISCOVERY_TIMEOUT_SECS", 3, 1, 60),
            offline_after_missed_scans: bounded("ARGOWEI_OFFLINE_AFTER_MISSED_SCANS", 3, 1, 1_000)
                as u32,
            offline_after_secs: bounded("ARGOWEI_OFFLINE_AFTER_SECS", 900, 0, 604_800),
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

/// Splits a comma-separated interface list, dropping blanks and duplicates
/// while keeping the configured order.
fn parse_interface_list(value: &str) -> Vec<String> {
    let mut interfaces: Vec<String> = Vec::new();
    for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if !interfaces.iter().any(|existing| existing == name) {
            interfaces.push(name.to_owned());
        }
    }
    interfaces
}

fn bounded(key: &str, default: u64, min: u64, max: u64) -> u64 {
    let value: u64 = env_or(key, &default.to_string())
        .parse()
        .unwrap_or_else(|_| panic!("{key} must be a whole number"));
    assert!(
        (min..=max).contains(&value),
        "{key} must be between {min} and {max}"
    );
    value
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_list_is_trimmed_and_deduplicated() {
        assert_eq!(
            parse_interface_list(" eth0, wlan0 ,,eth0 "),
            vec!["eth0", "wlan0"]
        );
        assert!(parse_interface_list("").is_empty());
        assert!(parse_interface_list(" , ").is_empty());
    }
}
