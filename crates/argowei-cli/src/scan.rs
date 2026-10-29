use std::error::Error;
use std::time::Duration;

use argowei_collector::scan_arp;
use argowei_core::oui;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

pub fn run(interface: &str) -> Result<(), Box<dyn Error>> {
    println!(
        "Scanning on {interface} (response window {DEFAULT_TIMEOUT:?} after paced requests)..."
    );

    let hosts = scan_arp(interface, DEFAULT_TIMEOUT)?;

    if hosts.is_empty() {
        println!("No hosts responded.");
        return Ok(());
    }

    println!("{:<18} {:<19} VENDOR", "IP", "MAC");
    let mut sorted = hosts;
    sorted.sort_by_key(|host| host.ip);
    for host in &sorted {
        let mac = host.mac.to_string().to_ascii_lowercase();
        let info = oui::lookup(&mac);
        let vendor = match (info.vendor, info.locally_administered) {
            (Some(name), _) => name,
            (None, true) => "(locally administered / randomized)",
            (None, false) => "(unknown)",
        };
        println!("{:<18} {:<19} {vendor}", host.ip, mac);
    }

    Ok(())
}
