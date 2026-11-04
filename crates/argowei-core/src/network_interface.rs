//! Local network interfaces, as listed by `argowei interfaces`.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Kernel name, e.g. `eth0`.
    pub name: String,
    pub kind: NetworkInterfaceKind,
    /// From `/sys/class/net/<name>/address`; `None` when it is missing or empty.
    pub mac_address: Option<String>,
    /// The kernel's `operstate` (`up`, `down`, `unknown`, ...).
    pub oper_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkInterfaceKind {
    Loopback,
    Wireless,
    Ethernet,
    Virtual,
    Unknown,
}

impl fmt::Display for NetworkInterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Loopback => "loopback",
            Self::Wireless => "wireless",
            Self::Ethernet => "ethernet",
            Self::Virtual => "virtual",
            Self::Unknown => "unknown",
        };

        f.write_str(label)
    }
}
