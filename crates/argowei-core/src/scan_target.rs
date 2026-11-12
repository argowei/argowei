//! Which addresses Argowei may port-scan: the local network only.
//!
//! A port scan of someone else's network is at best rude and at worst
//! illegal, and a scan request is user input. So the server checks every
//! target here, never trusting the client: an address must lie inside the
//! private and link-local ranges ([`LOCAL_RANGES`]) and inside the ranges
//! the operator allows (`ARGOWEI_SCAN_ALLOWED_RANGES`, which can only
//! narrow the local ranges, never widen them).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// RFC 1918, IPv4 link-local, IPv6 unique local (ULA) and IPv6 link-local.
pub const LOCAL_RANGES: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

/// An address range such as `192.168.178.0/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `address/prefix`; a bare address is a single-host range. Host
    /// bits must be zero (`192.168.1.5/24` is rejected as a likely typo).
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| format!("\"{text}\" is not an IP address or range"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("\"{text}\" has an invalid prefix length"))?,
        };
        let cidr = Cidr { network, prefix };
        if cidr.masked(network) != network {
            return Err(format!(
                "\"{text}\" has host bits set; did you mean {}?",
                Cidr {
                    network: cidr.masked(network),
                    prefix,
                }
            ));
        }
        Ok(cidr)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.network.is_ipv4() && self.masked(ip) == self.network
    }

    /// Whether every address of `other` is also in `self`.
    pub fn covers(&self, other: &Cidr) -> bool {
        other.prefix >= self.prefix && self.contains(other.network)
    }

    fn masked(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn local_ranges() -> impl Iterator<Item = Cidr> {
    LOCAL_RANGES
        .iter()
        .map(|range| Cidr::parse(range).expect("LOCAL_RANGES are valid"))
}

/// Why an address may not be scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetRejected {
    /// Not a private or link-local address (public, loopback, multicast, ...).
    NotLocal(IpAddr),
    /// Local, but outside `ARGOWEI_SCAN_ALLOWED_RANGES`.
    NotAllowed(IpAddr),
}

impl fmt::Display for TargetRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLocal(ip) => write!(f, "{ip} is not on the local network; only private and link-local addresses can be scanned"),
            Self::NotAllowed(ip) => write!(f, "{ip} is outside the allowed scan ranges"),
        }
    }
}

impl std::error::Error for TargetRejected {}

/// The ranges scans may target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTargets {
    allowed: Vec<Cidr>,
}

impl Default for ScanTargets {
    /// All of [`LOCAL_RANGES`].
    fn default() -> Self {
        Self {
            allowed: local_ranges().collect(),
        }
    }
}

impl ScanTargets {
    /// Narrows scanning to `allowed`. Every range must lie inside a local
    /// range: configuration can restrict scanning, never open it up to the
    /// internet. An empty list means the default (all local ranges).
    pub fn new(allowed: Vec<Cidr>) -> Result<Self, String> {
        if allowed.is_empty() {
            return Ok(Self::default());
        }
        if let Some(outside) = allowed
            .iter()
            .find(|range| !local_ranges().any(|local| local.covers(range)))
        {
            return Err(format!(
                "{outside} is not inside a private or link-local range ({})",
                LOCAL_RANGES.join(", ")
            ));
        }
        Ok(Self { allowed })
    }

    /// Parses a comma-separated list such as `192.168.178.0/24, 10.0.0.0/8`.
    pub fn parse_list(text: &str) -> Result<Self, String> {
        let ranges = text
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(Cidr::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(ranges)
    }

    pub fn ranges(&self) -> &[Cidr] {
        &self.allowed
    }

    /// Accepts `ip` only if it is local and allowed.
    pub fn check(&self, ip: IpAddr) -> Result<(), TargetRejected> {
        if !local_ranges().any(|range| range.contains(ip)) {
            return Err(TargetRejected::NotLocal(ip));
        }
        if !self.allowed.iter().any(|range| range.contains(ip)) {
            return Err(TargetRejected::NotAllowed(ip));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn private_and_link_local_addresses_are_scannable() {
        let targets = ScanTargets::default();
        for local in [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.178.37",
            "169.254.1.1",
            "fd12:3456:789a::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert_eq!(targets.check(ip(local)), Ok(()), "{local}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        let targets = ScanTargets::default();
        for other in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.169.0.1",
            "100.64.0.1", // carrier-grade NAT: not your network
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251",
            "::1",
            "::",
            "2001:4860:4860::8888",
            "ff02::1",
            "::ffff:192.168.1.1", // IPv4-mapped: not matched as IPv4 here
        ] {
            assert_eq!(
                targets.check(ip(other)),
                Err(TargetRejected::NotLocal(ip(other))),
                "{other}"
            );
        }
    }

    #[test]
    fn allowed_ranges_narrow_scanning() {
        let targets = ScanTargets::parse_list("192.168.178.0/24, 10.1.0.0/16").unwrap();
        assert_eq!(targets.check(ip("192.168.178.20")), Ok(()));
        assert_eq!(targets.check(ip("10.1.2.3")), Ok(()));
        assert_eq!(
            targets.check(ip("192.168.1.20")),
            Err(TargetRejected::NotAllowed(ip("192.168.1.20")))
        );
        assert_eq!(
            targets.check(ip("8.8.8.8")),
            Err(TargetRejected::NotLocal(ip("8.8.8.8"))),
            "public stays NotLocal"
        );
    }

    #[test]
    fn allowed_ranges_cannot_widen_scanning() {
        for wide in [
            "0.0.0.0/0",
            "8.8.8.0/24",
            "10.0.0.0/7",
            "192.168.0.0/15",
            "::/0",
            "100.64.0.0/10",
        ] {
            assert!(ScanTargets::parse_list(wide).is_err(), "{wide}");
        }
        assert_eq!(ScanTargets::parse_list("").unwrap(), ScanTargets::default());
        assert_eq!(
            ScanTargets::parse_list(" , ").unwrap(),
            ScanTargets::default()
        );
    }

    #[test]
    fn ranges_are_parsed_strictly() {
        assert_eq!(
            Cidr::parse("192.168.1.0/24").unwrap().to_string(),
            "192.168.1.0/24"
        );
        assert_eq!(
            Cidr::parse("192.168.1.7").unwrap().to_string(),
            "192.168.1.7/32"
        );
        assert_eq!(Cidr::parse("fd00::/8").unwrap().to_string(), "fd00::/8");
        assert!(Cidr::parse("192.168.1.5/24")
            .unwrap_err()
            .contains("192.168.1.0/24"));
        for bad in [
            "",
            "192.168.1.0/33",
            "192.168.1.0/-1",
            "fd00::/129",
            "example.org",
            "192.168.1/24",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        let any4 = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(any4.contains(ip("8.8.8.8")) && !any4.contains(ip("::1")));
    }
}
