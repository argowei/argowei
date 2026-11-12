//! The shared domain model of Argowei: devices and their addresses, device
//! types and the classifier, name sources, network interfaces and the MAC
//! vendor registry.
//!
//! Pure data and logic, no I/O and no database: the API, the collector and
//! the CLI all depend on it, so it must stay cheap to depend on.

pub mod device;
pub mod device_type;
pub mod events;
pub mod names;
pub mod network_interface;
pub mod oui;

pub const PROJECT_NAME: &str = "Argowei";
