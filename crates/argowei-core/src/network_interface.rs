use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub kind: NetworkInterfaceKind,
    pub mac_address: Option<String>,
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
