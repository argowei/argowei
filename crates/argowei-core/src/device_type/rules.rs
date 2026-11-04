//! The rule tables behind [`classify`](super::classify).
//!
//! # How to add or tune a rule
//!
//! - **Weight** is the confidence, in percent, that this one signal alone
//!   gives the type. Roughly: 80-90 when the signal practically names the
//!   type (`_ipp` is a printer), 50-75 for a strong hint (a printer vendor),
//!   25-45 for a vendor that makes many kinds of devices. Several signals for
//!   the same type combine (`1 - Π(1 - w)`), so do not inflate one weight to
//!   make up for missing signals. Keep weights within 1-95.
//! - **Order** matters only for vendors and hostnames, where the *first*
//!   matching rule wins: list the more specific pattern first (a
//!   "hewlett packard enterprise" server rule would have to come before
//!   the "hewlett packard" printer rule).
//! - **Duplicates** are rejected by the test
//!   `rule_tables_have_no_duplicates_and_sane_weights`; add a test in
//!   `tests.rs` for any rule whose effect is not obvious.
//!
//! Changing a table changes the stored type of existing devices on their next
//! scan, and that change is visible to users. Say so in the PR.

use super::DeviceType::{self, Iot, Laptop, Printer, Router, Server, Smartphone};

/// One rule: if `pattern` matches the device, it is `device_type` with
/// `weight` percent confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Rule<P> {
    pub pattern: P,
    pub device_type: DeviceType,
    pub weight: u8,
}

/// Keeps the tables to one line per rule.
pub(super) const fn rule<P>(pattern: P, device_type: DeviceType, weight: u8) -> Rule<P> {
    Rule {
        pattern,
        device_type,
        weight,
    }
}

/// Vendor rules: `pattern` is a case-insensitive substring of the
/// organization the MAC prefix is registered to. First match wins.
pub(super) const VENDORS: &[Rule<&str>] = &[
    rule("brother", Printer, 70),
    rule("canon", Printer, 65),
    rule("epson", Printer, 70),
    rule("lexmark", Printer, 75),
    rule("xerox", Printer, 65),
    rule("kyocera", Printer, 70),
    rule("ricoh", Printer, 65),
    rule("konica", Printer, 70),
    rule("hewlett packard", Printer, 30),
    rule("avm", Router, 70),
    rule("mikrotik", Router, 75),
    rule("routerboard", Router, 75),
    rule("ubiquiti", Router, 60),
    rule("netgear", Router, 60),
    rule("d-link", Router, 60),
    rule("tp-link", Router, 55),
    rule("zyxel", Router, 65),
    rule("linksys", Router, 65),
    rule("technicolor", Router, 65),
    rule("sagemcom", Router, 65),
    rule("synology", Server, 80),
    rule("qnap", Server, 80),
    rule("supermicro", Server, 70),
    rule("proxmox", Server, 80),
    rule("vmware", Server, 65),
    rule("xensource", Server, 65),
    rule("raspberry pi", Server, 40),
    rule("espressif", Iot, 75),
    rule("tuya", Iot, 70),
    rule("allterco", Iot, 80),
    rule("shelly", Iot, 80),
    rule("sonos", Iot, 75),
    rule("signify", Iot, 75),
    rule("philips lighting", Iot, 75),
    rule("roku", Iot, 75),
    rule("ecobee", Iot, 75),
    rule("wyze", Iot, 75),
    rule("itead", Iot, 75),
    rule("ring llc", Iot, 70),
    rule("nest labs", Iot, 70),
    rule("amazon technologies", Iot, 55),
    rule("google", Iot, 30),
    rule("oneplus", Smartphone, 70),
    rule("fairphone", Smartphone, 70),
    rule("realme", Smartphone, 65),
    rule("vivo mobile", Smartphone, 65),
    rule("motorola mobility", Smartphone, 65),
    rule("oppo", Smartphone, 60),
    rule("xiaomi", Smartphone, 45),
    rule("huawei", Smartphone, 30),
    rule("samsung", Smartphone, 25),
    rule("apple", Smartphone, 30),
    rule("lenovo", Laptop, 55),
    rule("acer", Laptop, 55),
    rule("liteon", Laptop, 45),
    rule("azurewave", Laptop, 40),
    rule("dell", Laptop, 35),
    rule("microsoft", Laptop, 35),
    rule("intel corporate", Laptop, 35),
    rule("asustek", Laptop, 35),
];

/// Hostname rules: `pattern` is a hostname token. A trailing `*` matches a
/// token prefix, anything else must equal a whole token (so "nas" does not
/// match "kenas"). Tokens are the alphanumeric runs of the lower-cased name.
/// First match wins.
pub(super) const HOSTNAMES: &[Rule<&str>] = &[
    rule("iphone*", Smartphone, 80),
    rule("ipad*", Smartphone, 75),
    rule("android*", Smartphone, 75),
    rule("galaxy*", Smartphone, 70),
    rule("pixel*", Smartphone, 70),
    rule("oneplus*", Smartphone, 80),
    rule("redmi*", Smartphone, 70),
    rule("macbook*", Laptop, 85),
    rule("thinkpad*", Laptop, 85),
    rule("laptop*", Laptop, 80),
    rule("notebook*", Laptop, 75),
    rule("imac*", Laptop, 70),
    rule("surface*", Laptop, 60),
    rule("desktop*", Laptop, 60),
    rule("printer*", Printer, 90),
    rule("laserjet*", Printer, 90),
    rule("officejet*", Printer, 90),
    rule("deskjet*", Printer, 90),
    rule("mfc*", Printer, 85),
    rule("dcp*", Printer, 85),
    rule("brn*", Printer, 60),
    rule("epson*", Printer, 80),
    rule("fritz*", Router, 85),
    rule("router*", Router, 85),
    rule("speedport*", Router, 85),
    rule("openwrt*", Router, 90),
    rule("edgerouter*", Router, 90),
    rule("mikrotik*", Router, 85),
    rule("ubnt*", Router, 70),
    rule("gateway", Router, 60),
    rule("server*", Server, 80),
    rule("nas", Server, 55),
    rule("pve*", Server, 70),
    rule("proxmox*", Server, 80),
    rule("docker*", Server, 70),
    rule("raspberrypi", Server, 60),
    rule("synology*", Server, 80),
    rule("truenas*", Server, 80),
    rule("unraid*", Server, 80),
    rule("homeassistant", Server, 70),
    rule("esp*", Iot, 85),
    rule("tasmota*", Iot, 90),
    rule("shelly*", Iot, 90),
    rule("chromecast*", Iot, 85),
    rule("sonos*", Iot, 85),
    rule("roku*", Iot, 85),
    rule("echo", Iot, 60),
    rule("hue", Iot, 70),
    rule("tv", Iot, 55),
    rule("cam", Iot, 70),
    rule("camera*", Iot, 70),
    rule("thermostat*", Iot, 75),
    rule("plug", Iot, 60),
    rule("bulb", Iot, 60),
];

/// Open-port rules: `pattern` is a TCP or UDP port. Every open port that has a
/// rule counts.
pub(super) const PORTS: &[Rule<u16>] = &[
    rule(9100, Printer, 80),
    rule(631, Printer, 75),
    rule(515, Printer, 60),
    rule(62078, Smartphone, 80),
    rule(8008, Iot, 70),
    rule(8009, Iot, 70),
    rule(8291, Router, 80),
    rule(8728, Router, 70),
    rule(7547, Router, 70),
    rule(53, Router, 50),
    rule(5060, Router, 30),
    rule(8123, Server, 60),
    rule(5000, Server, 45),
    rule(5001, Server, 45),
    rule(2049, Server, 50),
    rule(1883, Server, 40),
    rule(22, Server, 30),
    rule(3389, Laptop, 55),
    rule(548, Laptop, 40),
    rule(445, Laptop, 25),
];

/// mDNS rules: `pattern` is the service name without `._tcp`/`._udp` and the
/// domain. Every advertised service that has a rule counts.
pub(super) const MDNS: &[Rule<&str>] = &[
    rule("_ipp", Printer, 90),
    rule("_ipps", Printer, 90),
    rule("_printer", Printer, 90),
    rule("_pdl-datastream", Printer, 90),
    rule("_scanner", Printer, 70),
    rule("_apple-mobdev2", Smartphone, 85),
    rule("_companion-link", Smartphone, 50),
    rule("_googlecast", Iot, 80),
    rule("_hap", Iot, 80),
    rule("_matter", Iot, 80),
    rule("_esphomelib", Iot, 90),
    rule("_sonos", Iot, 85),
    rule("_hue", Iot, 80),
    rule("_airplay", Iot, 50),
    rule("_raop", Iot, 45),
    rule("_spotify-connect", Iot, 50),
    rule("_homeassistant", Server, 80),
    rule("_nfs", Server, 55),
    rule("_afpovertcp", Server, 40),
    rule("_smb", Server, 40),
    rule("_ssh", Server, 35),
    rule("_sftp-ssh", Server, 35),
    rule("_workstation", Laptop, 30),
];

/// Weak hint: phones and laptops randomize their MAC by default.
pub(super) const PRIVATE_MAC: &[(DeviceType, u8)] = &[(Smartphone, 25), (Laptop, 15)];
