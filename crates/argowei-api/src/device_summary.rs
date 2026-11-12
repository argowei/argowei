//! The short form of a device that alerts, events and scans embed, so a list
//! can show "which device" without a second request.

use argowei_core::oui;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeviceSummary {
    pub id: i32,
    /// The user's label, else the discovered name, else the MAC.
    pub display_name: String,
    pub mac_address: String,
    pub vendor: Option<&'static str>,
}

impl DeviceSummary {
    /// Builds the summary from the columns of a `LEFT JOIN devices`; `None`
    /// when there is no device (the row outlived it, or never had one).
    pub fn from_columns(
        id: Option<i32>,
        mac_address: Option<String>,
        label: Option<String>,
        name: Option<String>,
    ) -> Option<Self> {
        let (id, mac_address) = (id?, mac_address?);
        Some(Self {
            id,
            display_name: label.or(name).unwrap_or_else(|| mac_address.clone()),
            vendor: oui::lookup(&mac_address).vendor,
            mac_address,
        })
    }
}
