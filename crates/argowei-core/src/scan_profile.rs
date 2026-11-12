//! Port-scan profiles. The client picks a profile by name; the nmap
//! arguments behind it are fixed here and never come from a request.
//!
//! Scans run unprivileged (TCP connect scans, `--unprivileged`): no raw
//! sockets and no capabilities for nmap, at the cost of OS detection, which
//! needs raw packets and is therefore not offered.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    /// The 100 most common TCP ports: a quick look.
    Quick,
    /// The 1000 most common TCP ports with service and version detection.
    Service,
    /// All 65535 TCP ports.
    Full,
}

/// Arguments every scan gets: XML on stdout, unprivileged TCP connect scan,
/// no DNS (names come from discovery), no ping (the device is known), no
/// interactive keys, and few retries.
const COMMON_ARGS: &[&str] = &[
    "-oX",
    "-",
    "--unprivileged",
    "-sT",
    "-n",
    "-Pn",
    "--noninteractive",
    "--max-retries",
    "2",
];

impl ScanProfile {
    pub const ALL: [ScanProfile; 3] = [Self::Quick, Self::Service, Self::Full];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Service => "service",
            Self::Full => "full",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == value)
    }

    /// How long a scan may run before it is killed.
    pub fn timeout(self) -> Duration {
        match self {
            Self::Quick => Duration::from_secs(2 * 60),
            Self::Service => Duration::from_secs(10 * 60),
            Self::Full => Duration::from_secs(30 * 60),
        }
    }

    fn profile_args(self) -> &'static [&'static str] {
        match self {
            Self::Quick => &["--top-ports", "100", "-T4"],
            Self::Service => &["--top-ports", "1000", "-sV", "--version-light", "-T4"],
            Self::Full => &["-p-", "-T4"],
        }
    }

    /// The complete argument vector (without the program name) for scanning
    /// `target`, stopping nmap itself a little before `limit` so it can still
    /// write its XML. The target is the last element, never interpolated.
    pub fn nmap_args(self, target: std::net::IpAddr, limit: Duration) -> Vec<String> {
        let host_timeout = limit
            .saturating_sub(Duration::from_secs(5))
            .max(Duration::from_secs(1));
        let mut args: Vec<String> = COMMON_ARGS
            .iter()
            .chain(self.profile_args())
            .map(|arg| (*arg).to_owned())
            .collect();
        args.extend([
            "--host-timeout".to_owned(),
            format!("{}s", host_timeout.as_secs()),
        ]);
        if target.is_ipv6() {
            args.push("-6".to_owned());
        }
        args.push(target.to_string());
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_round_trip_through_their_names() {
        for profile in ScanProfile::ALL {
            assert_eq!(ScanProfile::parse(profile.as_str()), Some(profile));
            assert_eq!(serde_json_name(profile), profile.as_str());
        }
        assert_eq!(ScanProfile::parse("-sS -O"), None);
        assert_eq!(ScanProfile::parse("Quick"), None);
    }

    fn serde_json_name(profile: ScanProfile) -> String {
        serde_json::to_value(profile)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn the_argument_vector_is_fixed_and_ends_with_the_target() {
        let args =
            ScanProfile::Quick.nmap_args("192.168.1.20".parse().unwrap(), Duration::from_secs(120));
        assert_eq!(
            args,
            [
                "-oX",
                "-",
                "--unprivileged",
                "-sT",
                "-n",
                "-Pn",
                "--noninteractive",
                "--max-retries",
                "2",
                "--top-ports",
                "100",
                "-T4",
                "--host-timeout",
                "115s",
                "192.168.1.20"
            ]
        );
    }

    #[test]
    fn every_profile_is_unprivileged_and_never_detects_the_os() {
        for profile in ScanProfile::ALL {
            let args = profile.nmap_args("10.0.0.1".parse().unwrap(), profile.timeout());
            assert!(args.contains(&"--unprivileged".to_owned()), "{profile:?}");
            assert!(args.contains(&"-sT".to_owned()), "{profile:?}");
            for privileged in ["-O", "-sS", "-sU", "--privileged", "--script", "-A"] {
                assert!(
                    !args.contains(&privileged.to_owned()),
                    "{profile:?} {privileged}"
                );
            }
        }
    }

    #[test]
    fn ipv6_targets_get_the_ipv6_flag_and_short_limits_stay_positive() {
        let args = ScanProfile::Full.nmap_args("fd00::5".parse().unwrap(), Duration::from_secs(2));
        assert_eq!(&args[args.len() - 2..], ["-6", "fd00::5"]);
        assert!(args.windows(2).any(|w| w == ["--host-timeout", "1s"]));
    }
}
