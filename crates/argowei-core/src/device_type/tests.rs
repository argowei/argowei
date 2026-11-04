use super::rules::{HOSTNAMES, MDNS, PORTS, VENDORS};
use super::*;

fn classify_vendor(vendor: &str) -> Classification {
    classify(&Signals {
        vendor: Some(vendor),
        ..Signals::default()
    })
}

fn classify_hostname(hostname: &str) -> Classification {
    classify(&Signals {
        hostname: Some(hostname),
        ..Signals::default()
    })
}

/// (input, expected type, expected confidence)
#[test]
fn vendors_name_a_type_in_proportion_to_how_telling_they_are() {
    let cases = [
        ("Brother industries, LTD.", DeviceType::Printer, 70),
        (
            "AVM Audiovisuelles Marketing und Computersysteme GmbH",
            DeviceType::Router,
            70,
        ),
        ("Synology Incorporated", DeviceType::Server, 80),
        ("Espressif Inc.", DeviceType::Iot, 75),
        ("Raspberry Pi Foundation", DeviceType::Server, 40),
        ("Lenovo Mobile Communication", DeviceType::Laptop, 55),
        // Weak, ambiguous vendors still count when they reach the threshold ...
        ("Apple, Inc.", DeviceType::Smartphone, 30),
        ("Hewlett Packard", DeviceType::Printer, 30),
        // ... and fall to Unknown when they do not.
        ("Samsung Electronics Co.,Ltd", DeviceType::Unknown, 0),
        ("Some Unlisted Vendor Ltd", DeviceType::Unknown, 0),
    ];

    for (vendor, expected_type, expected_confidence) in cases {
        let result = classify_vendor(vendor);
        assert_eq!(
            (result.device_type, result.confidence),
            (expected_type, expected_confidence),
            "{vendor}"
        );
    }
}

#[test]
fn vendor_matching_ignores_case() {
    assert_eq!(
        classify_vendor("BROTHER INDUSTRIES").device_type,
        DeviceType::Printer
    );
}

#[test]
fn hostnames_match_whole_tokens_or_prefixes() {
    let cases = [
        ("iPhone-von-Anna", DeviceType::Smartphone, 80),
        ("DESKTOP-AB12CD", DeviceType::Laptop, 60),
        ("Brother-MFC-L2750DW", DeviceType::Printer, 85),
        ("fritz.box", DeviceType::Router, 85),
        ("esp32-living-room", DeviceType::Iot, 85),
        ("living-room-tv", DeviceType::Iot, 55),
        ("backup-nas", DeviceType::Server, 55),
        ("raspberrypi", DeviceType::Server, 60),
        // "nas" must be a whole token: this is just a name.
        ("kenas", DeviceType::Unknown, 0),
        ("annas-room", DeviceType::Unknown, 0),
        ("", DeviceType::Unknown, 0),
    ];

    for (hostname, expected_type, expected_confidence) in cases {
        let result = classify_hostname(hostname);
        assert_eq!(
            (result.device_type, result.confidence),
            (expected_type, expected_confidence),
            "{hostname:?}"
        );
    }
}

#[test]
fn open_ports_hint_at_a_type() {
    let cases: [(&[u16], DeviceType, u8); 6] = [
        (&[9100], DeviceType::Printer, 80),
        (&[62078], DeviceType::Smartphone, 80),
        (&[8291], DeviceType::Router, 80),
        (&[22], DeviceType::Server, 30),
        // Everyone has a web server; that says nothing.
        (&[80, 443], DeviceType::Unknown, 0),
        // Several printer ports are one kind of evidence, not three.
        (&[631, 9100, 515], DeviceType::Printer, 80),
    ];

    for (ports, expected_type, expected_confidence) in cases {
        let result = classify(&Signals {
            open_ports: ports,
            ..Signals::default()
        });
        assert_eq!(
            (result.device_type, result.confidence),
            (expected_type, expected_confidence),
            "{ports:?}"
        );
    }
}

#[test]
fn mdns_service_types_are_normalized_and_matched() {
    let result = classify(&Signals {
        mdns_services: &["_IPP._tcp.local", "_unknown-thing._tcp.local"],
        ..Signals::default()
    });

    assert_eq!(
        (result.device_type, result.confidence),
        (DeviceType::Printer, 90)
    );
    assert_eq!(
        result.evidence.len(),
        1,
        "an unknown service is not evidence"
    );

    let casts = classify(&Signals {
        mdns_services: &["_googlecast._tcp.local", "_airplay._tcp.local"],
        ..Signals::default()
    });
    // Same kind of evidence for the same type: the strongest counts once.
    assert_eq!((casts.device_type, casts.confidence), (DeviceType::Iot, 80));
}

#[test]
fn agreeing_evidence_combines_but_never_reaches_certainty() {
    let printer = classify(&Signals {
        vendor: Some("Brother industries, LTD."),
        mdns_services: &["_ipp._tcp.local"],
        ..Signals::default()
    });
    // 1 - 0.30 * 0.10 = 97, capped.
    assert_eq!(
        (printer.device_type, printer.confidence),
        (DeviceType::Printer, MAX_CONFIDENCE)
    );

    let phone = classify(&Signals {
        vendor: Some("Apple, Inc."),
        hostname: Some("iPhone-von-Anna"),
        ..Signals::default()
    });
    // 1 - 0.70 * 0.20 = 86.
    assert_eq!(
        (phone.device_type, phone.confidence),
        (DeviceType::Smartphone, 86)
    );
}

#[test]
fn a_private_mac_alone_is_too_weak_to_name_a_type() {
    let result = classify(&Signals {
        locally_administered_mac: true,
        ..Signals::default()
    });

    assert_eq!(
        (result.device_type, result.confidence),
        (DeviceType::Unknown, 0)
    );
    // The evidence is still reported, so the UI can say what little there was.
    assert!(result
        .evidence
        .iter()
        .all(|e| e.kind == EvidenceKind::PrivateMac));
    assert_eq!(result.evidence.len(), 2);
}

#[test]
fn a_private_mac_tips_weak_evidence_over_the_threshold() {
    let result = classify(&Signals {
        vendor: Some("Apple, Inc."),
        locally_administered_mac: true,
        ..Signals::default()
    });

    // Smartphone: 1 - 0.70 * 0.75 = 48.
    assert_eq!(
        (result.device_type, result.confidence),
        (DeviceType::Smartphone, 48)
    );
}

#[test]
fn the_better_supported_type_wins_a_conflict() {
    let result = classify(&Signals {
        vendor: Some("Dell Inc."),
        open_ports: &[22],
        ..Signals::default()
    });

    assert_eq!(
        (result.device_type, result.confidence),
        (DeviceType::Laptop, 35)
    );
    assert_eq!(result.evidence.len(), 2, "both signals are reported");
}

#[test]
fn exact_ties_resolve_by_a_fixed_priority_not_by_input_order() {
    // Port 53 (router, 50) and port 2049 (server, 50) tie.
    for ports in [[53u16, 2049], [2049, 53]] {
        let result = classify(&Signals {
            open_ports: &ports,
            ..Signals::default()
        });
        assert_eq!(
            (result.device_type, result.confidence),
            (DeviceType::Router, 50),
            "{ports:?}"
        );
    }
}

#[test]
fn the_result_does_not_depend_on_input_order() {
    let a = classify(&Signals {
        vendor: Some("Brother industries, LTD."),
        hostname: Some("BRN001122"),
        open_ports: &[9100, 631, 80, 22],
        mdns_services: &["_ipp._tcp.local", "_printer._tcp.local"],
        ..Signals::default()
    });
    let b = classify(&Signals {
        vendor: Some("Brother industries, LTD."),
        hostname: Some("BRN001122"),
        open_ports: &[22, 80, 631, 9100],
        mdns_services: &["_printer._tcp.local", "_ipp._tcp.local"],
        ..Signals::default()
    });

    assert_eq!(a, b);
    assert_eq!(
        a,
        classify(&Signals {
            vendor: Some("Brother industries, LTD."),
            hostname: Some("BRN001122"),
            open_ports: &[9100, 631, 80, 22],
            mdns_services: &["_ipp._tcp.local", "_printer._tcp.local"],
            ..Signals::default()
        })
    );
}

#[test]
fn evidence_lists_only_fired_rules_strongest_first() {
    let result = classify(&Signals {
        vendor: Some("Dell Inc."),
        hostname: Some("thinkpad-x1"),
        open_ports: &[22, 80],
        ..Signals::default()
    });

    let weights: Vec<u8> = result.evidence.iter().map(|e| e.weight).collect();
    assert_eq!(weights, vec![85, 35, 30]);
    assert_eq!(result.evidence[0].kind, EvidenceKind::Hostname);
    assert_eq!(result.evidence[2].detail, "port 22 open");
}

#[test]
fn nothing_known_means_unknown_with_no_confidence() {
    assert_eq!(classify(&Signals::default()), Classification::default());
}

#[test]
fn confidence_is_zero_exactly_when_the_type_is_unknown() {
    let samples = [
        Signals::default(),
        Signals {
            vendor: Some("Samsung"),
            ..Signals::default()
        },
        Signals {
            vendor: Some("Brother"),
            ..Signals::default()
        },
        Signals {
            open_ports: &[22],
            ..Signals::default()
        },
    ];
    for signals in samples {
        let result = classify(&signals);
        assert_eq!(
            result.device_type == DeviceType::Unknown,
            result.confidence == 0,
            "{signals:?}"
        );
        assert!(result.confidence <= MAX_CONFIDENCE);
    }
}

#[test]
fn device_types_round_trip_through_text_and_json() {
    for device_type in DeviceType::ALL {
        assert_eq!(DeviceType::parse(device_type.as_str()), Some(device_type));
        assert_eq!(
            serde_json::to_string(&device_type).unwrap(),
            format!("\"{}\"", device_type.as_str())
        );
    }
    assert_eq!(DeviceType::parse("Printer"), None);
    assert_eq!(DeviceType::parse("toaster"), None);
}

#[test]
fn a_classification_survives_a_json_round_trip() {
    let original = classify(&Signals {
        vendor: Some("Brother industries, LTD."),
        open_ports: &[9100],
        ..Signals::default()
    });

    let json = serde_json::to_value(&original).unwrap();
    assert_eq!(json["evidence"][0]["kind"], "port");
    assert_eq!(json["evidence"][0]["type"], "printer");
    assert_eq!(
        serde_json::from_value::<Classification>(json).unwrap(),
        original
    );
}

/// The tables must not contain two rules that can never be told apart,
/// or a typo that would silently shadow a rule.
#[test]
fn rule_tables_have_no_duplicates_and_sane_weights() {
    fn unique<T: Ord + Copy + std::fmt::Debug>(items: Vec<T>) {
        let mut sorted = items.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), items.len(), "duplicate rule in {items:?}");
    }

    unique(VENDORS.iter().map(|r| r.pattern).collect());
    unique(HOSTNAMES.iter().map(|r| r.pattern).collect());
    unique(PORTS.iter().map(|r| r.pattern).collect());
    unique(MDNS.iter().map(|r| r.pattern).collect());

    let weights = VENDORS
        .iter()
        .map(|r| r.weight)
        .chain(HOSTNAMES.iter().map(|r| r.weight))
        .chain(PORTS.iter().map(|r| r.weight))
        .chain(MDNS.iter().map(|r| r.weight));
    for weight in weights {
        assert!((1..=95).contains(&weight), "weight {weight} out of range");
    }
    assert!(VENDORS.iter().all(|r| r.device_type != DeviceType::Unknown));
}
