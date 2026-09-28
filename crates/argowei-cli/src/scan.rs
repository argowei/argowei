use std::error::Error;
use std::time::Duration;

use argowei_collector::scan_arp;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

pub fn run(interface: &str) -> Result<(), Box<dyn Error>> {
    println!("Scanning on {interface} (timeout {DEFAULT_TIMEOUT:?})...");

    let hosts = scan_arp(interface, DEFAULT_TIMEOUT)?;

    if hosts.is_empty() {
        println!("No hosts responded.");
        return Ok(());
    }

    println!("{:<18} MAC", "IP");
    let mut sorted = hosts;
    sorted.sort_by_key(|host| host.ip);
    for host in &sorted {
        println!("{:<18} {}", host.ip, host.mac);
    }

    Ok(())
}
