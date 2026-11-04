//! Active ARP discovery: sends an ARP request for every host in a subnet on
//! a chosen network interface and collects the replies. This is IPv4-only —
//! `AddressSource::Arp` in argowei-core. NDP (IPv6 neighbor discovery) is a
//! separate, later collector module; the two protocols solve the same
//! problem (MAC-to-IP resolution) but are different packet formats and
//! don't share implementation.
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;

/// Why a scan could not run. A host that does not answer is not an error.
#[derive(Debug)]
pub enum ArpScanError {
    InterfaceNotFound(String),
    InterfaceHasNoIpv4(String),
    InterfaceHasNoMac(String),
    /// The interface's prefix is outside /22../32 (too many hosts to ask).
    InvalidSubnet(u8),
    /// The response window is outside 1 ms..60 s.
    InvalidTimeout,
    ReceiverPanicked,
    /// The raw datalink channel could not be opened, for a reason other
    /// than missing privileges.
    NoChannel(String),
    /// Opening the raw socket was refused: the process lacks root or
    /// CAP_NET_RAW. Kept separate from `NoChannel` so callers can show an
    /// actionable message instead of a bare OS error.
    MissingPrivileges(String),
    /// Sending or receiving a frame failed.
    Io(std::io::Error),
}

impl std::fmt::Display for ArpScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceNotFound(name) => write!(f, "no such network interface: {name}"),
            Self::InterfaceHasNoIpv4(name) => {
                write!(f, "interface {name} has no IPv4 address to scan from")
            }
            Self::InterfaceHasNoMac(name) => write!(f, "interface {name} has no MAC address"),
            Self::InvalidSubnet(prefix) => write!(f, "unsupported /{prefix} subnet: choose an interface with an IPv4 prefix between /22 and /32 (at most 1021 peers)"),
            Self::InvalidTimeout => write!(f, "response timeout must be between 1 ms and 60 s"),
            Self::ReceiverPanicked => write!(f, "ARP receiver thread panicked"),
            Self::NoChannel(reason) => write!(f, "could not open a datalink channel: {reason}"),
            Self::MissingPrivileges(interface) => write!(f, "not permitted to open a raw socket on {interface}: run as root or grant CAP_NET_RAW (see docs/DEPLOYMENT.md)"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for ArpScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ArpScanError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// A host that answered: the IP it was asked for and the MAC it answered
/// with. The MAC is whatever the host claims (ARP is not authenticated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

type SendRecvChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

/// Discovers peers on the interface's first IPv4 network (prefix /22 through /32).
/// Requests are paced at no more than 100 per second while a receiver runs
/// concurrently. `timeout` is the response window after sending finishes;
/// allow up to one additional read-poll interval for shutdown.
///
/// Requires a raw datalink socket (root, or CAP_NET_RAW on Linux). A missing
/// response is not proof that a device is offline. ARP identity is untrusted.
pub fn scan_arp(
    interface_name: &str,
    timeout: Duration,
) -> Result<Vec<DiscoveredHost>, ArpScanError> {
    if timeout < Duration::from_millis(1) || timeout > Duration::from_secs(60) {
        return Err(ArpScanError::InvalidTimeout);
    }
    let interface = find_interface(interface_name)?;
    let (source_ip, prefix_len) = interface_ipv4(&interface)?;
    let source_mac = interface
        .mac
        .ok_or_else(|| ArpScanError::InterfaceHasNoMac(interface_name.to_string()))?;
    // Validate before allocating targets or opening a privileged socket.
    let targets = host_addresses(source_ip, prefix_len)?;
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let (mut tx, mut rx) = open_channel(&interface)?;
    scan_channel(
        tx.as_mut(),
        rx.as_mut(),
        source_ip,
        source_mac,
        &targets,
        timeout,
    )
}

const REQUEST_INTERVAL: Duration = Duration::from_millis(10);

fn scan_channel(
    tx: &mut dyn DataLinkSender,
    rx: &mut dyn DataLinkReceiver,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    targets: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<DiscoveredHost>, ArpScanError> {
    let stopped = AtomicBool::new(false);
    let (sending_done_tx, sending_done_rx) = mpsc::channel();
    let target_set = targets.iter().copied().collect();
    thread::scope(|scope| {
        let receiver = scope.spawn(|| {
            let result = collect_replies(
                rx,
                source_ip,
                source_mac,
                &target_set,
                timeout,
                sending_done_rx,
                &stopped,
            );
            stopped.store(true, Ordering::Release);
            result
        });
        let sent = (|| {
            for (index, target) in targets.iter().enumerate() {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                send_arp_request(tx, source_mac, source_ip, *target)?;
                if index + 1 < targets.len() {
                    thread::sleep(REQUEST_INTERVAL);
                }
            }
            Ok::<_, ArpScanError>(())
        })();
        let _ = sending_done_tx.send(Instant::now());
        if sent.is_err() {
            stopped.store(true, Ordering::Release);
        }
        let received = receiver
            .join()
            .map_err(|_| ArpScanError::ReceiverPanicked)?;
        sent?;
        received
    })
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

/// Bounded before allocation. /31 point-to-point links have no reserved
/// network/broadcast addresses; /32 has no peers. Use u64 for end arithmetic
/// so the final IPv4 subnet cannot overflow.
fn host_addresses(source_ip: Ipv4Addr, prefix_len: u8) -> Result<Vec<Ipv4Addr>, ArpScanError> {
    if !(22..=32).contains(&prefix_len) {
        return Err(ArpScanError::InvalidSubnet(prefix_len));
    }
    let mask = u32::MAX << (32 - prefix_len);
    let network = u64::from(u32::from(source_ip) & mask);
    let end = network + (1u64 << (32 - prefix_len));
    let range = if prefix_len < 31 {
        network + 1..end - 1
    } else {
        network..end
    };
    Ok(range
        .map(|ip| Ipv4Addr::from(ip as u32))
        .filter(|&ip| ip != source_ip)
        .collect())
}

/// How long a single blocking read waits for a packet before `collect_replies`
/// re-checks its overall deadline. `pnet`'s default config has no read
/// timeout at all (blocks forever), which would let a quiet subnet make the
/// scan hang past the caller's requested timeout.
const READ_POLL_INTERVAL: Duration = Duration::from_millis(200);

fn open_channel(interface: &NetworkInterface) -> Result<SendRecvChannel, ArpScanError> {
    let config = datalink::Config {
        read_timeout: Some(READ_POLL_INTERVAL),
        write_timeout: Some(READ_POLL_INTERVAL),
        ..Default::default()
    };

    match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(ArpScanError::NoChannel(
            "unsupported channel type for this interface".to_string(),
        )),
        Err(err) => Err(classify_channel_error(&interface.name, err)),
    }
}

fn classify_channel_error(interface_name: &str, err: std::io::Error) -> ArpScanError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        ArpScanError::MissingPrivileges(interface_name.to_string())
    } else {
        ArpScanError::NoChannel(err.to_string())
    }
}

fn send_arp_request(
    tx: &mut dyn DataLinkSender,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<(), ArpScanError> {
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

    tx.send_to(ethernet_packet.packet(), None).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "datalink sender has no capacity",
        )
    })??;
    Ok(())
}

fn parse_reply(
    packet: &[u8],
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    targets: &HashSet<Ipv4Addr>,
) -> Option<DiscoveredHost> {
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Arp || ethernet.get_destination() != source_mac {
        return None;
    }
    let arp = ArpPacket::new(ethernet.payload())?;
    let ip = arp.get_sender_proto_addr();
    let mac = arp.get_sender_hw_addr();
    if arp.get_hardware_type() != ArpHardwareTypes::Ethernet
        || arp.get_protocol_type() != EtherTypes::Ipv4
        || arp.get_hw_addr_len() != 6
        || arp.get_proto_addr_len() != 4
        || arp.get_operation() != ArpOperations::Reply
        || arp.get_target_proto_addr() != source_ip
        || arp.get_target_hw_addr() != source_mac
        || !targets.contains(&ip)
        || ip == source_ip
        || mac == MacAddr::zero()
        || mac.is_multicast()
        || ethernet.get_source() != mac
    {
        return None;
    }
    Some(DiscoveredHost { ip, mac })
}

fn collect_replies(
    rx: &mut dyn DataLinkReceiver,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    targets: &HashSet<Ipv4Addr>,
    timeout: Duration,
    sending_done: mpsc::Receiver<Instant>,
    stopped: &AtomicBool,
) -> Result<Vec<DiscoveredHost>, ArpScanError> {
    let mut found = HashMap::new();
    let mut deadline = None;
    loop {
        if stopped.load(Ordering::Acquire) {
            break;
        }
        if deadline.is_none() {
            if let Ok(finished) = sending_done.try_recv() {
                deadline = Some(finished + timeout);
            }
        }
        if deadline.is_some_and(|end| Instant::now() >= end) {
            break;
        }
        let packet = match rx.next() {
            Ok(packet) => packet,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(err) => return Err(err.into()),
        };
        if let Some(host) = parse_reply(packet, source_ip, source_mac, targets) {
            found.insert(host.ip, host.mac);
        }
    }
    let mut hosts: Vec<_> = found
        .into_iter()
        .map(|(ip, mac)| DiscoveredHost { ip, mac })
        .collect();
    hosts.sort_by_key(|host| host.ip);
    Ok(hosts)
}

#[cfg(test)]
mod tests;
