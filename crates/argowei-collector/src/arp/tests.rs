use super::*;

#[test]
fn host_addresses_excludes_network_broadcast_and_self() {
    let source = Ipv4Addr::new(192, 168, 1, 10);
    let hosts = host_addresses(source, 24).unwrap();

    assert_eq!(hosts.len(), 253); // 256 - network - broadcast - self
    assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 0)));
    assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 255)));
    assert!(!hosts.contains(&source));
    assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 1)));
    assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 254)));
}

#[test]
fn permission_errors_are_reported_as_missing_privileges() {
    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let message = classify_channel_error("eth0", denied).to_string();
    assert!(
        message.contains("CAP_NET_RAW") && message.contains("eth0"),
        "{message}"
    );

    let other = std::io::Error::other("boom");
    assert!(matches!(
        classify_channel_error("eth0", other),
        ArpScanError::NoChannel(reason) if reason.contains("boom")
    ));
}

#[test]
fn host_addresses_handles_a_slash_30() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let hosts = host_addresses(source, 30).unwrap();

    // /30 has 4 addresses total: network, 2 hosts, broadcast.
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 2));
}

#[test]
fn subnet_limits_and_point_to_point_edges_are_explicit() {
    let source = Ipv4Addr::new(255, 255, 255, 255);
    assert!(host_addresses(source, 32).unwrap().is_empty());
    assert_eq!(
        host_addresses(source, 31).unwrap(),
        vec![Ipv4Addr::new(255, 255, 255, 254)]
    );
    assert_eq!(
        host_addresses(Ipv4Addr::new(10, 0, 0, 1), 22)
            .unwrap()
            .len(),
        1021
    );
    for prefix in [0, 8, 16, 21, 33, 255] {
        assert!(matches!(
            host_addresses(source, prefix),
            Err(ArpScanError::InvalidSubnet(_))
        ));
    }
}

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
const LOCAL_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);
const PEER_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 2);

fn reply() -> Vec<u8> {
    let mut buffer = vec![0; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    let mut ethernet = MutableEthernetPacket::new(&mut buffer).unwrap();
    ethernet.set_destination(LOCAL_MAC);
    ethernet.set_source(PEER_MAC);
    ethernet.set_ethertype(EtherTypes::Arp);
    let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Reply);
    arp.set_sender_hw_addr(PEER_MAC);
    arp.set_sender_proto_addr(PEER_IP);
    arp.set_target_hw_addr(LOCAL_MAC);
    arp.set_target_proto_addr(LOCAL_IP);
    buffer
}

#[test]
fn accepts_only_replies_for_the_requested_scope() {
    let targets = HashSet::from([PEER_IP]);
    assert_eq!(
        parse_reply(&reply(), LOCAL_IP, LOCAL_MAC, &targets),
        Some(DiscoveredHost {
            ip: PEER_IP,
            mac: PEER_MAC
        })
    );
    assert!(parse_reply(&reply(), LOCAL_IP, LOCAL_MAC, &HashSet::new()).is_none());
    assert!(parse_reply(&reply(), PEER_IP, LOCAL_MAC, &targets).is_none());
    assert!(parse_reply(&reply(), LOCAL_IP, PEER_MAC, &targets).is_none());
    for length in 0..ETHERNET_HEADER_LEN + ARP_PACKET_LEN {
        assert!(parse_reply(&reply()[..length], LOCAL_IP, LOCAL_MAC, &targets).is_none());
    }
}

#[test]
fn rejects_wrong_protocol_fields_and_inconsistent_identity() {
    let mutations: &[fn(&mut MutableArpPacket<'_>)] = &[
        |arp| arp.set_operation(ArpOperations::Request),
        |arp| arp.set_protocol_type(EtherTypes::Ipv6),
        |arp| arp.set_hw_addr_len(5),
        |arp| arp.set_proto_addr_len(16),
        |arp| arp.set_target_proto_addr(PEER_IP),
        |arp| arp.set_target_hw_addr(PEER_MAC),
        |arp| arp.set_sender_hw_addr(MacAddr::broadcast()),
        |arp| arp.set_sender_hw_addr(MacAddr::zero()),
        |arp| arp.set_sender_hw_addr(LOCAL_MAC),
    ];
    for mutate in mutations {
        let mut buffer = reply();
        let mut ethernet = MutableEthernetPacket::new(&mut buffer).unwrap();
        mutate(&mut MutableArpPacket::new(ethernet.payload_mut()).unwrap());
        assert!(parse_reply(&buffer, LOCAL_IP, LOCAL_MAC, &HashSet::from([PEER_IP])).is_none());
    }
}

#[derive(Default)]
struct Sender {
    packets: Vec<Vec<u8>>,
    fail: bool,
    no_capacity: bool,
    wait_for_read: Option<mpsc::Receiver<()>>,
}

impl DataLinkSender for Sender {
    fn build_and_send(
        &mut self,
        _: usize,
        _: usize,
        _: &mut dyn FnMut(&mut [u8]),
    ) -> Option<std::io::Result<()>> {
        unreachable!("scan uses send_to")
    }

    fn send_to(
        &mut self,
        packet: &[u8],
        _: Option<NetworkInterface>,
    ) -> Option<std::io::Result<()>> {
        if let Some(ready) = self.wait_for_read.take() {
            ready
                .recv_timeout(Duration::from_secs(2))
                .expect("receiver never started reading");
        }
        if self.no_capacity {
            return None;
        }
        if self.fail {
            return Some(Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        self.packets.push(packet.to_vec());
        Some(Ok(()))
    }
}

#[test]
fn sends_a_well_formed_request_and_propagates_write_failures() {
    let mut sender = Sender::default();
    send_arp_request(&mut sender, LOCAL_MAC, LOCAL_IP, PEER_IP).unwrap();
    let ethernet = EthernetPacket::new(&sender.packets[0]).unwrap();
    let arp = ArpPacket::new(ethernet.payload()).unwrap();
    assert_eq!(ethernet.get_destination(), MacAddr::broadcast());
    assert_eq!(arp.get_operation(), ArpOperations::Request);
    assert_eq!(arp.get_sender_proto_addr(), LOCAL_IP);
    assert_eq!(arp.get_target_proto_addr(), PEER_IP);
    sender.fail = true;
    assert!(
        matches!(send_arp_request(&mut sender, LOCAL_MAC, LOCAL_IP, PEER_IP), Err(ArpScanError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied)
    );
    sender.no_capacity = true;
    assert!(
        matches!(send_arp_request(&mut sender, LOCAL_MAC, LOCAL_IP, PEER_IP), Err(ArpScanError::Io(err)) if err.kind() == std::io::ErrorKind::WriteZero)
    );
}

struct Receiver {
    pending: std::collections::VecDeque<Vec<u8>>,
    current: Vec<u8>,
    fail: bool,
    notify_read: Option<mpsc::Sender<()>>,
}

impl DataLinkReceiver for Receiver {
    fn next(&mut self) -> std::io::Result<&[u8]> {
        if let Some(ready) = self.notify_read.take() {
            ready.send(()).expect("sender stopped before read");
        }
        if self.fail {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        if let Some(packet) = self.pending.pop_front() {
            self.current = packet;
            return Ok(&self.current);
        }
        thread::sleep(Duration::from_millis(1));
        Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
    }
}

#[test]
fn scan_deduplicates_replies_and_finishes_on_a_quiet_channel() {
    let mut sender = Sender::default();
    let mut receiver = Receiver {
        pending: [reply(), reply()].into(),
        current: vec![],
        fail: false,
        notify_read: None,
    };
    let hosts = scan_channel(
        &mut sender,
        &mut receiver,
        LOCAL_IP,
        LOCAL_MAC,
        &[PEER_IP],
        Duration::from_millis(5),
    )
    .unwrap();
    assert_eq!(
        hosts,
        vec![DiscoveredHost {
            ip: PEER_IP,
            mac: PEER_MAC
        }]
    );
    assert_eq!(sender.packets.len(), 1);
    let hosts = scan_channel(
        &mut sender,
        &mut receiver,
        LOCAL_IP,
        LOCAL_MAC,
        &[PEER_IP],
        Duration::from_millis(5),
    )
    .unwrap();
    assert!(hosts.is_empty());
}

#[test]
fn scan_propagates_transport_failures_instead_of_reporting_an_empty_network() {
    let mut sender = Sender::default();
    let (ready_tx, ready_rx) = mpsc::channel();
    sender.wait_for_read = Some(ready_rx);
    let mut receiver = Receiver {
        pending: [].into(),
        current: vec![],
        fail: true,
        notify_read: Some(ready_tx),
    };
    assert!(
        matches!(scan_channel(&mut sender, &mut receiver, LOCAL_IP, LOCAL_MAC, &[PEER_IP], Duration::from_millis(5)), Err(ArpScanError::Io(err)) if err.kind() == std::io::ErrorKind::BrokenPipe)
    );
    sender.fail = true;
    sender.wait_for_read = None;
    receiver.fail = false;
    assert!(
        matches!(scan_channel(&mut sender, &mut receiver, LOCAL_IP, LOCAL_MAC, &[PEER_IP], Duration::from_millis(5)), Err(ArpScanError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn validates_response_window_before_accessing_the_interface() {
    for timeout in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_secs(61),
    ] {
        assert!(matches!(
            scan_arp("nonexistent", timeout),
            Err(ArpScanError::InvalidTimeout)
        ));
    }
}

#[test]
fn receives_while_requests_are_still_being_sent() {
    // The sender cannot finish its first write until a read starts. This
    // would time out if discovery ever reverted to send-all-then-receive.
    struct CoordinatedSender(mpsc::Receiver<()>, Sender);
    impl DataLinkSender for CoordinatedSender {
        fn build_and_send(
            &mut self,
            _: usize,
            _: usize,
            _: &mut dyn FnMut(&mut [u8]),
        ) -> Option<std::io::Result<()>> {
            unreachable!("scan uses send_to")
        }
        fn send_to(
            &mut self,
            packet: &[u8],
            destination: Option<NetworkInterface>,
        ) -> Option<std::io::Result<()>> {
            if self.1.packets.is_empty() && self.0.recv_timeout(Duration::from_secs(2)).is_err() {
                return Some(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
            }
            self.1.send_to(packet, destination)
        }
    }
    struct CoordinatedReceiver(Option<mpsc::Sender<()>>, Receiver);
    impl DataLinkReceiver for CoordinatedReceiver {
        fn next(&mut self) -> std::io::Result<&[u8]> {
            if let Some(ready) = self.0.take() {
                ready
                    .send(())
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            }
            self.1.next()
        }
    }
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut sender = CoordinatedSender(ready_rx, Sender::default());
    let mut receiver = CoordinatedReceiver(
        Some(ready_tx),
        Receiver {
            pending: [reply()].into(),
            current: vec![],
            fail: false,
            notify_read: None,
        },
    );
    let hosts = scan_channel(
        &mut sender,
        &mut receiver,
        LOCAL_IP,
        LOCAL_MAC,
        &[PEER_IP, Ipv4Addr::new(192, 168, 1, 21)],
        Duration::from_millis(5),
    )
    .unwrap();
    assert_eq!(sender.1.packets.len(), 2);
    assert_eq!(
        hosts,
        vec![DiscoveredHost {
            ip: PEER_IP,
            mac: PEER_MAC
        }]
    );
}
