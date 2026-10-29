use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A device is identified by its MAC address. Its IP addresses are tracked
/// separately in `DeviceAddress`, since a single device can hold several at
/// once (an IPv4 address via ARP, plus one or more IPv6 addresses via NDP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: i32,
    /// Name derived by discovery. Never set by the user; see `label`.
    pub name: String,
    /// Name chosen by the user. Wins over `name` for display.
    pub label: Option<String>,
    /// Free-text notes written by the user.
    pub notes: String,
    pub mac_address: String,
    pub is_online: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Device {
    /// What to show for this device: the user's label if there is one,
    /// otherwise the discovered name.
    pub fn display_name(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpProtocol {
    V4,
    V6,
}

/// How an address was learned. Kept as an open-ended string in storage (see
/// the migration) so a new source, e.g. observed DHCP leases, doesn't need
/// its own schema change — this enum covers what discovery can produce today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressSource {
    Arp,
    Ndp,
}

impl AddressSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Ndp => "ndp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAddress {
    pub id: i32,
    pub device_id: i32,
    pub ip_address: String,
    pub protocol: IpProtocol,
    pub source: AddressSource,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, label: Option<&str>) -> Device {
        Device {
            id: 1,
            name: name.to_owned(),
            label: label.map(str::to_owned),
            notes: String::new(),
            mac_address: "aa:bb:cc:00:00:01".to_owned(),
            is_online: true,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn a_label_wins_over_the_discovered_name() {
        assert_eq!(
            device("raspberrypi", Some("Printer")).display_name(),
            "Printer"
        );
    }

    #[test]
    fn without_a_label_the_discovered_name_is_shown() {
        assert_eq!(device("raspberrypi", None).display_name(), "raspberrypi");
    }
}
