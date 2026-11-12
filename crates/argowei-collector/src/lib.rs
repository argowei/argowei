//! Talking to the network: the active ARP scan, the hostname resolvers
//! (DHCP leases, mDNS, NetBIOS, reverse DNS) and reading nmap's output.
//!
//! Everything here is blocking and stateless; callers decide when to run it
//! (the API's scheduler on its blocking pool, the CLI directly). Traffic is
//! paced and bounded, and only the local network is ever asked.

pub mod arp;
pub mod names;
pub mod nmap;

pub use arp::{scan_arp, ArpScanError, DiscoveredHost};
