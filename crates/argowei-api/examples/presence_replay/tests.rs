//! Hand-calculated timelines and schema boundaries, independent of the CLI.

use serde_json::{json, Value};

use super::*;

fn input() -> Value {
    json!({
        "schema_version": 1,
        "dataset": {"id": "hand-calculated", "kind": "synthetic", "description": "Test timeline", "ground_truth_source": "Independent scenario labels"},
        "policy": {"offline_after_missed_scans": 3, "offline_after_secs": 15},
        "traces": [{
            "device_id": "device-a", "interface": "test0", "duration_ms": 30000,
            "observations": [
                {"at_ms": 0, "outcome": "reply"},
                {"at_ms": 10000, "outcome": "miss"},
                {"at_ms": 15000, "outcome": "miss"},
                {"at_ms": 18000, "outcome": "miss"},
                {"at_ms": 22000, "outcome": "reply"},
                {"at_ms": 25000, "outcome": "miss"},
                {"at_ms": 28000, "outcome": "miss"},
                {"at_ms": 29000, "outcome": "miss"}
            ],
            "ground_truth": [
                {"at_ms": 0, "state": "online"},
                {"at_ms": 5000, "state": "offline"},
                {"at_ms": 20000, "state": "online"},
                {"at_ms": 24000, "state": "offline"}
            ]
        }]
    })
}

fn run(value: &Value) -> Report {
    replay_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn irregular_intervals_weight_time_and_preserve_every_departure() {
    let report = run(&input());
    let result = &report.traces[0].methods[0];
    let confusion = &result.metrics.confusion;
    assert_eq!(confusion.truth_online.online_ms, 7000);
    assert_eq!(confusion.truth_online.offline_ms, 2000);
    assert_eq!(confusion.truth_offline.offline_ms, 2000);
    assert_eq!(confusion.truth_offline.online_ms, 19000);
    assert_eq!(result.metrics.false_online_episodes, 2);
    assert_eq!(result.metrics.false_offline_episodes, 1);
    assert_eq!(result.metrics.completed_scans, 8);
    assert_eq!(result.detection.departures, 2);
    assert_eq!(result.detection.detected, 1);
    assert_eq!(result.detection.censored, 1);
    assert_eq!(result.detection.detected_delay_p50_ms, Some(13000));
    assert!(matches!(
        result.departures[0].outcome,
        Detection::Detected {
            delay_ms: 13000,
            ..
        }
    ));
    assert!(matches!(
        result.departures[1].outcome,
        Detection::Censored {
            observed_for_ms: 6000,
            reason: "trace_end",
            ..
        }
    ));
}

#[test]
fn failed_scans_do_not_decide_even_when_the_time_threshold_has_passed() {
    let mut value = input();
    let trace = &mut value["traces"][0];
    trace["duration_ms"] = json!(50000);
    trace["observations"] = json!([
        {"at_ms":0,"outcome":"reply"},
        {"at_ms":5000,"outcome":"miss"},
        {"at_ms":20000,"outcome":"failed"},
        {"at_ms":25000,"outcome":"miss"}
    ]);
    trace["ground_truth"] = json!([{"at_ms":0,"state":"online"}]);
    value["policy"]["offline_after_missed_scans"] = json!(2);
    let report = run(&value);
    for result in &report.traces[0].methods[..3] {
        assert_eq!(result.metrics.confusion.truth_online.online_ms, 25000);
        assert_eq!(result.metrics.confusion.truth_online.offline_ms, 25000);
        assert_eq!(result.metrics.completed_scans, 3);
        assert_eq!(result.metrics.failed_scans, 1);
    }
    assert_eq!(
        report.traces[0].methods[3]
            .metrics
            .confusion
            .truth_online
            .offline_ms,
        45000
    );
}

#[test]
fn skipped_attempts_are_counted_without_changing_presence() {
    let mut value = input();
    value["schema_version"] = json!(2);
    let trace = &mut value["traces"][0];
    trace["duration_ms"] = json!(50000);
    trace["observations"] = json!([
        {"at_ms":0,"outcome":"reply"},
        {"at_ms":5000,"outcome":"miss"},
        {"at_ms":20000,"outcome":"skipped"},
        {"at_ms":25000,"outcome":"miss"}
    ]);
    trace["ground_truth"] = json!([{"at_ms":0,"state":"online"}]);
    value["policy"]["offline_after_missed_scans"] = json!(2);
    let report = run(&value);
    for result in &report.traces[0].methods[..3] {
        assert_eq!(result.metrics.confusion.truth_online.online_ms, 25000);
        assert_eq!(result.metrics.confusion.truth_online.offline_ms, 25000);
        assert_eq!(result.metrics.completed_scans, 3);
        assert_eq!(result.metrics.failed_scans, 0);
        assert_eq!(result.metrics.skipped_scans, 1);
    }
    assert_eq!(report.aggregate[0].metrics.skipped_scans, 1);
}

#[test]
fn unknown_predictions_and_labels_are_not_counted_as_online_or_offline() {
    let mut value = input();
    let trace = &mut value["traces"][0];
    trace["duration_ms"] = json!(20000);
    trace["observations"] = json!([
        {"at_ms":2000,"outcome":"failed"},
        {"at_ms":5000,"outcome":"miss"},
        {"at_ms":10000,"outcome":"reply"},
        {"at_ms":15000,"outcome":"miss"}
    ]);
    trace["ground_truth"] = json!([
        {"at_ms":0,"state":"online"},
        {"at_ms":8000,"state":"unknown"},
        {"at_ms":12000,"state":"offline"}
    ]);
    let report = run(&value);
    let result = &report.traces[0].methods[3];
    assert_eq!(result.metrics.confusion.unlabeled_ms, 4000);
    assert_eq!(result.metrics.confusion.truth_online.unknown_ms, 8000);
    assert_eq!(result.metrics.confusion.truth_offline.online_ms, 3000);
    assert_eq!(result.metrics.confusion.truth_offline.offline_ms, 5000);
    assert_eq!(result.detection.departures, 0);
    assert_eq!(result.detection.detected_delay_p95_ms, None);
}

#[test]
fn ties_apply_both_streams_and_preexisting_offline_predictions_detect_at_zero_delay() {
    let mut value = input();
    let trace = &mut value["traces"][0];
    trace["observations"] = json!([
        {"at_ms":0,"outcome":"reply"},
        {"at_ms":10000,"outcome":"miss"}
    ]);
    trace["ground_truth"] = json!([
        {"at_ms":0,"state":"online"},
        {"at_ms":10000,"state":"offline"}
    ]);
    let report = run(&value);
    let result = &report.traces[0].methods[3];
    assert_eq!(result.metrics.confusion.truth_offline.online_ms, 0);
    assert!(matches!(
        result.departures[0].outcome,
        Detection::Detected { delay_ms: 0, .. }
    ));
    value["traces"][0]["ground_truth"][1]["at_ms"] = json!(12000);
    let report = run(&value);
    let result = &report.traces[0].methods[3];
    assert_eq!(result.metrics.confusion.truth_online.offline_ms, 2000);
    assert!(matches!(
        result.departures[0].outcome,
        Detection::Detected { delay_ms: 0, .. }
    ));
}

#[test]
fn returns_are_undetected_and_unknown_labels_censor_departures() {
    let mut value = input();
    let trace = &mut value["traces"][0];
    trace["observations"] = json!([{"at_ms":0,"outcome":"reply"}]);
    trace["ground_truth"] = json!([
        {"at_ms":0,"state":"online"},
        {"at_ms":5000,"state":"offline"},
        {"at_ms":10000,"state":"online"},
        {"at_ms":12000,"state":"offline"},
        {"at_ms":15000,"state":"unknown"},
        {"at_ms":18000,"state":"offline"},
        {"at_ms":20000,"state":"online"},
        {"at_ms":25000,"state":"offline"}
    ]);
    let report = run(&value);
    let result = &report.traces[0].methods[0];
    assert_eq!(result.detection.departures, 3);
    assert_eq!(result.detection.undetected, 1);
    assert_eq!(result.detection.censored, 2);
    assert!(matches!(
        result.departures[0].outcome,
        Detection::Undetected {
            observed_for_ms: 5000,
            ..
        }
    ));
    assert!(matches!(
        result.departures[1].outcome,
        Detection::Censored {
            observed_for_ms: 3000,
            reason: "ground_truth_unknown",
            ..
        }
    ));
    assert!(matches!(
        result.departures[2].outcome,
        Detection::Censored {
            observed_for_ms: 5000,
            reason: "trace_end",
            ..
        }
    ));
}

#[test]
fn aggregates_sum_durations_and_keep_deterministic_order() {
    let mut value = input();
    let mut second = value["traces"][0].clone();
    second["device_id"] = json!("device-b");
    value["traces"].as_array_mut().unwrap().push(second);
    let first = run(&value);
    let second = run(&value);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(first.aggregate[0].trace_count, 2);
    assert_eq!(first.aggregate[0].metrics.duration_ms, 60000);
    assert_eq!(
        first.aggregate[0].metrics.confusion.truth_offline.online_ms,
        38000
    );
    assert_eq!(first.aggregate[0].detection.departures, 4);
    assert_eq!(first.aggregate[0].detection.censored, 2);
}

#[test]
fn rejects_ambiguous_unknown_and_out_of_range_inputs() {
    let mut cases = Vec::new();
    let mut change = |path: &[&str], invalid: Value| {
        let mut value = input();
        let mut target = &mut value;
        for key in path {
            target = &mut target[*key];
        }
        *target = invalid;
        cases.push(value);
    };
    change(&["schema_version"], json!(3));
    change(&["extra"], json!(true));
    change(&["dataset", "kind"], json!("real"));
    change(&["dataset", "ground_truth_source"], json!("  "));
    change(&["dataset", "extra"], json!(true));
    change(&["policy", "offline_after_secs"], json!(u64::MAX));
    change(&["policy", "offline_after_missed_scans"], json!(0));
    change(&["traces"], json!([]));
    for value in cases {
        assert!(replay_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut old_schema_with_skip = input();
    old_schema_with_skip["traces"][0]["observations"][1]["outcome"] = json!("skipped");
    assert!(
        replay_json(&serde_json::to_vec(&old_schema_with_skip).unwrap())
            .err()
            .expect("v1 must reject skipped")
            .contains("schema_version 2")
    );
    let invalid_traces = [
        ("duration_ms", json!(0)),
        ("duration_ms", json!(u64::MAX)),
        ("device_id", json!(" ")),
        ("interface", json!("")),
        ("extra", json!(true)),
        ("observations", json!([])),
        ("ground_truth", json!([])),
        (
            "observations",
            json!([{"at_ms":0,"outcome":"reply"},{"at_ms":0,"outcome":"miss"}]),
        ),
        (
            "ground_truth",
            json!([{"at_ms":100,"state":"online"},{"at_ms":99,"state":"offline"}]),
        ),
        ("observations", json!([{"at_ms":30000,"outcome":"miss"}])),
        (
            "observations",
            json!([{"at_ms":0,"outcome":"reply","extra":true}]),
        ),
        (
            "ground_truth",
            json!([{"at_ms":0,"state":"online","extra":true}]),
        ),
    ];
    for (key, invalid) in invalid_traces {
        let mut value = input();
        value["traces"][0][key] = invalid;
        assert!(
            replay_json(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted invalid {key}"
        );
    }
    let mut value = input();
    let duplicate = value["traces"][0].clone();
    value["traces"].as_array_mut().unwrap().push(duplicate);
    assert!(replay_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut lab = input();
    lab["dataset"]["kind"] = json!("lab");
    lab["dataset"]["ground_truth_source"] = json!(" ");
    assert!(replay_json(&serde_json::to_vec(&lab).unwrap()).is_err());
}

#[test]
fn omitted_policy_uses_production_defaults_and_zero_time_is_supported() {
    let mut value = input();
    value.as_object_mut().unwrap().remove("policy");
    let report = run(&value);
    assert_eq!(report.schema_version, 2);
    assert_eq!(report.traces[0].methods[0].metrics.skipped_scans, 0);
    let production = PresencePolicy::default();
    assert_eq!(
        report.policy.offline_after_secs,
        production.offline_after.as_secs()
    );
    assert_eq!(
        report.policy.offline_after_missed_scans,
        production.offline_after_missed_scans
    );
    value["policy"] = json!({"offline_after_missed_scans":3,"offline_after_secs":0});
    let report = run(&value);
    assert_eq!(
        report.traces[0].methods[0]
            .metrics
            .confusion
            .truth_offline
            .offline_ms,
        3000
    );
}
