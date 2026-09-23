use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A device is identified by its MAC address. Its IP addresses are tracked
/// separately in `DeviceAddress`, since a single device can hold several at
/// once (an IPv4 address via ARP, plus one or more IPv6 addresses via NDP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: i32,
    pub name: String,
    pub mac_address: String,
    pub is_online: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
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
