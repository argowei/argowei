//! Active ARP discovery: sends an ARP request for every host in a subnet on
//! a chosen network interface and collects the replies. This is IPv4-only —
//! `AddressSource::Arp` in argowei-core. NDP (IPv6 neighbor discovery) is a
//! separate, later collector module; the two protocols solve the same
//! problem (MAC-to-IP resolution) but are different packet formats and
//! don't share implementation.
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;

#[derive(Debug)]
pub enum ArpScanError {
    InterfaceNotFound(String),
    InterfaceHasNoIpv4(String),
    NoChannel(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ArpScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceNotFound(name) => write!(f, "no such network interface: {name}"),
            Self::InterfaceHasNoIpv4(name) => {
                write!(f, "interface {name} has no IPv4 address to scan from")
            }
            Self::NoChannel(reason) => write!(f, "could not open a datalink channel: {reason}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for ArpScanError {}

impl From<std::io::Error> for ArpScanError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

type SendRecvChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

/// Sends an ARP request to every host address in `interface`'s IPv4 /24
/// subnet and returns whoever replies within `timeout`.
///
/// Requires permission to open a raw datalink socket (root, or
/// `CAP_NET_RAW` on Linux).
pub fn scan_arp(interface_name: &str, timeout: Duration) -> Result<Vec<DiscoveredHost>, ArpScanError> {
    let interface = find_interface(interface_name)?;
    let (source_ip, prefix_len) = interface_ipv4(&interface)?;
    let source_mac = interface
        .mac
        .ok_or_else(|| ArpScanError::InterfaceHasNoIpv4(interface_name.to_string()))?;

    let (mut tx, mut rx) = open_channel(&interface)?;

    let targets = host_addresses(source_ip, prefix_len);
    for target_ip in &targets {
        send_arp_request(tx.as_mut(), source_mac, source_ip, *target_ip);
    }

    Ok(collect_replies(rx.as_mut(), source_ip, timeout))
}

fn find_interface(name: &str) -> Result<NetworkInterface, ArpScanError> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| ArpScanError::InterfaceNotFound(name.to_string()))
}

/// Returns the interface's IPv4 address and subnet prefix length (e.g. 24).
fn interface_ipv4(interface: &NetworkInterface) -> Result<(Ipv4Addr, u8), ArpScanError> {
    interface
        .ips
        .iter()
        .find_map(|ip_network| match ip_network.ip() {
            std::net::IpAddr::V4(addr) => Some((addr, ip_network.prefix())),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or_else(|| ArpScanError::InterfaceHasNoIpv4(interface.name.clone()))
}

/// All usable host addresses in the subnet, excluding the network/broadcast
/// addresses and the scanning interface's own address.
fn host_addresses(source_ip: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    let network = u32::from(source_ip) & mask;
    let broadcast = network | !mask;

    (network + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|&ip| ip != source_ip)
        .collect()
}

/// How long a single blocking read waits for a packet before `collect_replies`
/// re-checks its overall deadline. `pnet`'s default config has no read
/// timeout at all (blocks forever), which would let a quiet subnet make the
/// scan hang past the caller's requested timeout.
const READ_POLL_INTERVAL: Duration = Duration::from_millis(200);

fn open_channel(interface: &NetworkInterface) -> Result<SendRecvChannel, ArpScanError> {
    let config = datalink::Config {
        read_timeout: Some(READ_POLL_INTERVAL),
        ..Default::default()
    };

    match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(ArpScanError::NoChannel(
            "unsupported channel type for this interface".to_string(),
        )),
        Err(err) => Err(ArpScanError::NoChannel(err.to_string())),
    }
}

fn send_arp_request(
    tx: &mut dyn DataLinkSender,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    // Best-effort: a single unreachable host on the subnet shouldn't abort
    // the whole scan. Errors surface as that host simply not replying.
    let _ = tx.send_to(ethernet_packet.packet(), None);
}

fn collect_replies(
    rx: &mut dyn DataLinkReceiver,
    source_ip: Ipv4Addr,
    timeout: Duration,
) -> Vec<DiscoveredHost> {
    let mut found: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        // `rx.next()` blocks for up to READ_POLL_INTERVAL (set in
        // open_channel) and returns an error on timeout, which is expected
        // here — it's how this loop gets to re-check the deadline instead
        // of blocking past it on a quiet subnet.
        let Ok(packet) = rx.next() else {
            continue;
        };

        let Some(ethernet) = EthernetPacket::new(packet) else {
            continue;
        };
        if ethernet.get_ethertype() != EtherTypes::Arp {
            continue;
        }
        let Some(arp) = ArpPacket::new(ethernet.payload()) else {
            continue;
        };
        if arp.get_operation() != ArpOperations::Reply {
            continue;
        }

        let replier_ip = arp.get_sender_proto_addr();
        if replier_ip == source_ip {
            continue;
        }
        found.insert(replier_ip, arp.get_sender_hw_addr());
    }

    found
        .into_iter()
        .map(|(ip, mac)| DiscoveredHost { ip, mac })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_addresses_excludes_network_broadcast_and_self() {
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let hosts = host_addresses(source, 24);

        assert_eq!(hosts.len(), 253); // 256 - network - broadcast - self
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!hosts.contains(&source));
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn host_addresses_handles_a_slash_30() {
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let hosts = host_addresses(source, 30);

        // /30 has 4 addresses total: network, 2 hosts, broadcast.
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 2));
    }
}
