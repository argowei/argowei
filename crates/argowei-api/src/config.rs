//! Settings from environment variables. The defaults are in
//! [`Settings::from_env`]; `.env.example` shows the common ones.

/// Application settings.
///
/// Values are read from environment variables (see .env.example), falling
/// back to the defaults below for local development without Docker. The
/// defaults mirror docker-compose.yml so a plain `cargo run` against a
/// locally running Postgres works out of the box.
pub struct Settings {
    /// Address the API listens on.
    pub bind_address: std::net::SocketAddr,

    pub postgres_user: String,
    pub postgres_password: String,
    pub postgres_db: String,
    pub postgres_host: String,
    pub postgres_port: u16,

    /// Mark the session cookie `Secure`. Leave off for plain-HTTP LAN
    /// deployments; enable when served over HTTPS (e.g. behind nginx).
    pub cookie_secure: bool,
    pub session_ttl_hours: i64,

    /// Interfaces to scan periodically. Empty disables scheduled discovery.
    pub discovery_interfaces: Vec<String>,
    pub discovery_interval_secs: u64,
    pub discovery_timeout_secs: u64,

    /// Name sources to ask about discovered devices; empty disables lookups.
    pub hostname_sources: Vec<argowei_core::names::NameSource>,
    /// dnsmasq lease file for the DHCP source (optional).
    pub dhcp_leases_file: Option<String>,
    /// DNS server for reverse lookups; `None` uses the local servers listed in
    /// the system's resolv.conf.
    pub dns_server: Option<std::net::SocketAddr>,
    pub hostname_timeout_ms: u64,
    pub hostname_refresh_secs: u64,
    pub hostname_concurrency: usize,

    /// Consecutive missed scans before a device may be marked offline.
    pub offline_after_missed_scans: u32,
    /// Minimum time since last seen before a device may be marked offline.
    pub offline_after_secs: u64,
    /// How long after an interface's first scan new devices are still learned
    /// silently instead of raising an alert. 0 = only the first scan.
    pub baseline_window_secs: u64,

    /// The nmap binary for port scans (a name on `PATH` or a full path).
    pub nmap_path: String,
    /// Port scans running at once, across all devices and schedules.
    pub scan_concurrency: usize,
    /// Ranges port scans may target; always inside the local ranges.
    pub scan_targets: argowei_core::scan_target::ScanTargets,
    /// Upper bound on a scan's run time in seconds, on top of each profile's
    /// own limit; 0 keeps the profile limits.
    pub scan_max_secs: u64,
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

            hostname_sources: parse_name_sources(&env_or(
                "ARGOWEI_HOSTNAME_SOURCES",
                "dhcp,mdns,netbios,rdns",
            ))
            .unwrap_or_else(|error| panic!("ARGOWEI_HOSTNAME_SOURCES: {error}")),
            dhcp_leases_file: Some(env_or("ARGOWEI_DHCP_LEASES_FILE", ""))
                .filter(|path| !path.trim().is_empty()),
            dns_server: parse_dns_server(&env_or("ARGOWEI_DNS_SERVER", ""))
                .unwrap_or_else(|error| panic!("ARGOWEI_DNS_SERVER: {error}")),
            hostname_timeout_ms: bounded("ARGOWEI_HOSTNAME_TIMEOUT_MS", 1000, 100, 10_000),
            hostname_refresh_secs: bounded("ARGOWEI_HOSTNAME_REFRESH_SECS", 3600, 60, 604_800),
            hostname_concurrency: bounded("ARGOWEI_HOSTNAME_CONCURRENCY", 16, 1, 64) as usize,

            offline_after_missed_scans: bounded("ARGOWEI_OFFLINE_AFTER_MISSED_SCANS", 3, 1, 1_000)
                as u32,
            offline_after_secs: bounded("ARGOWEI_OFFLINE_AFTER_SECS", 900, 0, 604_800),
            baseline_window_secs: bounded("ARGOWEI_BASELINE_WINDOW_SECS", 0, 0, 2_592_000),

            nmap_path: Some(env_or("ARGOWEI_NMAP_PATH", "nmap"))
                .map(|path| path.trim().to_owned())
                .filter(|path| !path.is_empty())
                .unwrap_or_else(|| "nmap".to_owned()),
            scan_concurrency: bounded("ARGOWEI_SCAN_CONCURRENCY", 2, 1, 8) as usize,
            scan_targets: argowei_core::scan_target::ScanTargets::parse_list(&env_or(
                "ARGOWEI_SCAN_ALLOWED_RANGES",
                "",
            ))
            .unwrap_or_else(|error| panic!("ARGOWEI_SCAN_ALLOWED_RANGES: {error}")),
            scan_max_secs: bounded("ARGOWEI_SCAN_MAX_SECS", 0, 0, 7_200),
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

/// `dhcp,mdns,netbios,rdns` (any subset, in any order); empty means none.
fn parse_name_sources(value: &str) -> Result<Vec<argowei_core::names::NameSource>, String> {
    let mut sources = Vec::new();
    for name in value.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let source = argowei_core::names::NameSource::parse(name)
            .ok_or_else(|| format!("unknown source \"{name}\" (use dhcp, mdns, netbios, rdns)"))?;
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    Ok(sources)
}

/// `192.168.178.1` or `192.168.178.1:53`; empty means "use the system's".
fn parse_dns_server(value: &str) -> Result<Option<std::net::SocketAddr>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<std::net::SocketAddr>()
        .or_else(|_| {
            value
                .parse::<std::net::Ipv4Addr>()
                .map(|ip| std::net::SocketAddr::new(ip.into(), argowei_collector::names::DNS_PORT))
        })
        .map(Some)
        .map_err(|_| format!("\"{value}\" is not an IPv4 address (optionally with :port)"))
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
    fn name_sources_are_parsed_in_order_without_duplicates() {
        use argowei_core::names::NameSource::{Dhcp, Mdns, Rdns};

        assert_eq!(
            parse_name_sources("dhcp,mdns,netbios,rdns").unwrap().len(),
            4
        );
        assert_eq!(
            parse_name_sources(" rdns , mdns,rdns,dhcp ").unwrap(),
            [Rdns, Mdns, Dhcp]
        );
        assert!(parse_name_sources("").unwrap().is_empty());
    }

    #[test]
    fn an_unknown_name_source_is_refused_with_the_valid_ones() {
        let error = parse_name_sources("mdns,wins").unwrap_err();

        assert!(
            error.contains("wins") && error.contains("netbios"),
            "{error}"
        );
    }

    #[test]
    fn the_dns_server_may_omit_the_port() {
        assert_eq!(parse_dns_server("").unwrap(), None);
        assert_eq!(
            parse_dns_server("192.168.178.1").unwrap(),
            Some("192.168.178.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_dns_server(" 10.0.0.2:5353 ").unwrap(),
            Some("10.0.0.2:5353".parse().unwrap())
        );
        assert!(parse_dns_server("fritz.box").is_err());
    }

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
