use super::*;

const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);

/// Builds a response the way a DNS server lays it out: the question is
/// repeated and the answer's owner name is a pointer back to it.
fn response(id: u16, rcode: u8, target: Option<&[u8]>) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x81, 0x80 | rcode]); // response, recursion available
    packet.extend_from_slice(&[0, 1, 0, u8::from(target.is_some()), 0, 0, 0, 0]);
    packet.extend_from_slice(
        &build_query(id, &reverse_name(IP), TYPE_PTR, true).unwrap()[HEADER_LEN..],
    );
    if let Some(target) = target {
        packet.extend_from_slice(&[0xc0, 0x0c]); // owner name: pointer to the question
        packet.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x0e, 0x10]); // PTR, IN, ttl 3600
        packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
        packet.extend_from_slice(target);
    }
    packet
}

/// `annas-iphone.local` as labels.
const LABELS: &[u8] = b"\x0cannas-iphone\x05local\x00";

#[test]
fn reverse_names_list_the_octets_backwards() {
    assert_eq!(reverse_name(IP), "5.1.168.192.in-addr.arpa");
}

#[test]
fn a_ptr_query_has_the_exact_wire_layout() {
    let query = build_query(0x1234, "5.1.168.192.in-addr.arpa", TYPE_PTR, true).unwrap();

    let expected: Vec<u8> = [
        &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..], // header, RD set, one question
        b"\x015\x011\x03168\x03192\x07in-addr\x04arpa\x00",
        &[0, 12, 0, 1], // PTR, IN
    ]
    .concat();
    assert_eq!(query, expected);
}

#[test]
fn multicast_style_queries_do_not_ask_for_recursion() {
    let query = build_query(7, "x.local", TYPE_PTR, false).unwrap();

    assert_eq!(&query[2..4], &[0, 0]);
}

#[test]
fn invalid_labels_are_refused() {
    assert_eq!(
        build_query(1, "a..b", TYPE_PTR, true),
        Err(DnsError::InvalidLabel)
    );
    assert_eq!(
        build_query(1, &"x".repeat(64), TYPE_PTR, true),
        Err(DnsError::InvalidLabel)
    );
}

#[test]
fn a_ptr_answer_is_read() {
    let names = parse_ptr_response(&response(9, 0, Some(LABELS)), 9).unwrap();

    assert_eq!(names, ["annas-iphone.local"]);
}

#[test]
fn a_target_that_points_back_into_the_packet_is_followed() {
    // The answer's target is "host" plus a pointer to the question's
    // "in-addr.arpa" tail, as real servers compress.
    let mut packet = response(3, 0, None);
    packet[7] = 1; // one answer
    let tail = packet.windows(8).position(|w| w == b"\x07in-addr").unwrap();
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]);
    let target = [b"\x04host".as_slice(), &[0xc0, tail as u8]].concat();
    packet.extend_from_slice(&(target.len() as u16).to_be_bytes());
    packet.extend_from_slice(&target);

    assert_eq!(
        parse_ptr_response(&packet, 3).unwrap(),
        ["host.in-addr.arpa"]
    );
}

#[test]
fn no_such_name_is_an_empty_answer_not_an_error() {
    assert_eq!(parse_ptr_response(&response(4, 3, None), 4), Ok(Vec::new()));
}

#[test]
fn a_response_without_answers_yields_nothing() {
    assert_eq!(parse_ptr_response(&response(4, 0, None), 4), Ok(Vec::new()));
}

#[test]
fn server_failures_are_reported() {
    assert_eq!(
        parse_ptr_response(&response(4, 2, None), 4),
        Err(DnsError::ServerFailure(2))
    );
    assert_eq!(
        parse_ptr_response(&response(4, 5, None), 4),
        Err(DnsError::ServerFailure(5))
    );
}

#[test]
fn answers_to_a_different_query_are_rejected() {
    let packet = response(9, 0, Some(LABELS));

    assert_eq!(parse_ptr_response(&packet, 10), Err(DnsError::IdMismatch));
    assert!(is_response_to(&packet, 9));
    assert!(!is_response_to(&packet, 10));
}

#[test]
fn a_query_is_not_mistaken_for_a_response() {
    let query = build_query(9, "x.local", TYPE_PTR, true).unwrap();

    assert_eq!(parse_ptr_response(&query, 9), Err(DnsError::NotAResponse));
    assert!(!is_response_to(&query, 9));
}

#[test]
fn truncated_packets_never_panic() {
    let packet = response(9, 0, Some(LABELS));
    for cut in 0..packet.len() {
        let _ = parse_ptr_response(&packet[..cut], 9);
    }
    assert_eq!(parse_ptr_response(&[], 1), Err(DnsError::Truncated));
}

#[test]
fn a_pointer_loop_is_cut_off() {
    let mut packet = response(9, 0, None);
    packet[7] = 1;
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]);
    let loop_at = packet.len() + 2;
    packet.extend_from_slice(&2u16.to_be_bytes());
    packet.extend_from_slice(&[0xc0, loop_at as u8]); // points at itself

    assert_eq!(parse_ptr_response(&packet, 9), Err(DnsError::BadPointer));
}

#[test]
fn a_pointer_outside_the_packet_is_refused() {
    let mut packet = response(9, 0, None);
    packet[7] = 1;
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0xff]);

    assert_eq!(parse_ptr_response(&packet, 9), Err(DnsError::BadPointer));
}

#[test]
fn an_over_long_name_is_refused() {
    let label = [&[63u8][..], &[b'a'; 63]].concat();
    let target = [label.repeat(5), vec![0]].concat();

    assert_eq!(
        parse_ptr_response(&response(9, 0, Some(&target)), 9),
        Err(DnsError::NameTooLong)
    );
}

#[test]
fn a_record_length_that_runs_past_the_packet_is_refused() {
    let mut packet = response(9, 0, Some(LABELS));
    let len_at = packet.len() - LABELS.len() - 2;
    packet[len_at] = 0xff;

    assert_eq!(parse_ptr_response(&packet, 9), Err(DnsError::Truncated));
}
