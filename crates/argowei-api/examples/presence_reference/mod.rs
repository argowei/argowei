use chrono::{DateTime, TimeDelta, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    schema_version: u8,
    kind: String,
    device_id: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    source: Source,
    clock: Clock,
    events: Vec<Event>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Source {
    description: String,
    raw_log_sha256: String,
    state_definition: String,
    completeness: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Clock {
    offset_ms: i64,
    uncertainty_ms: u64,
    evidence: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    id: String,
    recorded_at: DateTime<Utc>,
    uncertainty_ms: u64,
    state: State,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Online,
    Offline,
    Unknown,
}

#[derive(Serialize)]
struct Label {
    at: DateTime<Utc>,
    state: State,
}

#[derive(Serialize)]
pub struct Artifact {
    artifact_version: u8,
    input_sha256: String,
    reference: Reference,
    ground_truth: Vec<Label>,
}

fn timestamp(at: DateTime<Utc>) -> Result<(), String> {
    if !at.nanosecond().is_multiple_of(1_000_000) || at.nanosecond() >= 1_000_000_000 {
        return Err("timestamps must be whole milliseconds without leap seconds".into());
    }
    Ok(())
}

fn shift(at: DateTime<Utc>, ms: i64) -> Result<DateTime<Utc>, String> {
    let delta = TimeDelta::try_milliseconds(ms)
        .ok_or("clock adjustment exceeds supported duration range")?;
    at.checked_add_signed(delta)
        .ok_or_else(|| "clock adjustment exceeds supported timestamp range".into())
}

pub fn convert_json(bytes: &[u8]) -> Result<Artifact, String> {
    let reference: Reference = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if reference.schema_version != 1 || !matches!(reference.kind.as_str(), "lab" | "synthetic") {
        return Err("expected schema_version 1 and kind lab or synthetic".into());
    }
    for text in [
        &reference.device_id,
        &reference.source.description,
        &reference.source.state_definition,
        &reference.source.completeness,
        &reference.clock.evidence,
    ] {
        if text.trim().is_empty() {
            return Err("reference identity and provenance must not be blank".into());
        }
    }
    let hash = &reference.source.raw_log_sha256;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("raw_log_sha256 must contain 64 hexadecimal characters".into());
    }
    timestamp(reference.start)?;
    timestamp(reference.end)?;
    if reference.end <= reference.start || reference.events.is_empty() {
        return Err("expected a positive window and nonempty reference events".into());
    }
    let mut boundaries = Vec::new();
    let mut previous_recorded = None;
    let mut previous_latest = None;
    let mut ids = std::collections::HashSet::new();
    for event in &reference.events {
        timestamp(event.recorded_at)?;
        if event.id.trim().is_empty() || !ids.insert(&event.id) {
            return Err("event IDs must be nonblank and unique".into());
        }
        if previous_recorded.is_some_and(|at| at >= event.recorded_at) {
            return Err("recorded event timestamps must strictly increase".into());
        }
        let radius = reference
            .clock
            .uncertainty_ms
            .checked_add(event.uncertainty_ms)
            .and_then(|ms| i64::try_from(ms).ok())
            .ok_or("combined uncertainty exceeds supported range")?;
        let center = shift(event.recorded_at, reference.clock.offset_ms)?;
        let earliest = shift(center, -radius)?;
        let latest = shift(center, radius)?;
        if previous_latest.is_some_and(|at| at >= earliest) {
            return Err("reference uncertainty bounds overlap or touch; resolve event order or split the study".into());
        }
        if earliest < latest {
            boundaries.push((earliest, State::Unknown));
        }
        boundaries.push((latest, event.state));
        previous_recorded = Some(event.recorded_at);
        previous_latest = Some(latest);
    }
    let mut state = State::Unknown;
    let mut ground_truth = Vec::new();
    for (at, next) in boundaries {
        if at <= reference.start {
            state = next;
            continue;
        }
        if ground_truth.is_empty() {
            ground_truth.push(Label {
                at: reference.start,
                state,
            });
        }
        if at >= reference.end {
            break;
        }
        if next != state {
            ground_truth.push(Label { at, state: next });
            state = next;
        }
    }
    if ground_truth.is_empty() {
        ground_truth.push(Label {
            at: reference.start,
            state,
        });
    }
    Ok(Artifact {
        artifact_version: 1,
        input_sha256: format!("{:x}", Sha256::digest(bytes)),
        reference,
        ground_truth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn input() -> Value {
        json!({
            "schema_version": 1, "kind": "synthetic", "device_id": "device-01",
            "start": "2026-11-08T12:00:00Z", "end": "2026-11-08T12:00:10Z",
            "source": {
                "description": "Hand-authored regression events, not measurements",
                "raw_log_sha256": "0".repeat(64), "state_definition": "Test LAN membership",
                "completeness": "All synthetic state changes included through trace end"
            },
            "clock": { "offset_ms": 100, "uncertainty_ms": 50, "evidence": "Synthetic bound" },
            "events": [
                { "id": "initial", "recorded_at": "2026-11-08T11:59:59Z", "uncertainty_ms": 0, "state": "online" },
                { "id": "disconnect", "recorded_at": "2026-11-08T12:00:05Z", "uncertainty_ms": 150, "state": "offline" }
            ]
        })
    }

    fn convert(value: &Value) -> Result<Artifact, String> {
        convert_json(&serde_json::to_vec(value).unwrap())
    }

    fn timeline(value: &Value) -> Vec<(i64, State)> {
        let artifact = convert(value).unwrap();
        artifact
            .ground_truth
            .iter()
            .map(|label| {
                (
                    (label.at - artifact.reference.start).num_milliseconds(),
                    label.state,
                )
            })
            .collect()
    }

    #[test]
    fn sums_clock_and_event_uncertainty_with_signed_offset() {
        let mut value = input();
        assert_eq!(
            timeline(&value),
            vec![
                (0, State::Online),
                (4900, State::Unknown),
                (5300, State::Offline)
            ]
        );
        value["clock"]["offset_ms"] = json!(-100);
        assert_eq!(
            timeline(&value),
            vec![
                (0, State::Online),
                (4700, State::Unknown),
                (5100, State::Offline)
            ]
        );
    }

    #[test]
    fn clips_start_and_end_without_inventing_initial_state() {
        let mut value = input();
        value["events"].as_array_mut().unwrap().remove(0);
        assert_eq!(
            timeline(&value),
            vec![(0, State::Unknown), (5300, State::Offline)]
        );
        value["start"] = json!("2026-11-08T12:00:05Z");
        assert_eq!(
            timeline(&value),
            vec![(0, State::Unknown), (300, State::Offline)]
        );
        value["start"] = json!("2026-11-08T12:00:05.300Z");
        assert_eq!(timeline(&value), vec![(0, State::Offline)]);
        value["start"] = json!("2026-11-08T12:00:00Z");
        value["end"] = json!("2026-11-08T12:00:05.300Z");
        assert_eq!(timeline(&value), vec![(0, State::Unknown)]);
    }

    #[test]
    fn exact_events_and_explicit_unknown_periods() {
        let mut value = input();
        value["clock"]["uncertainty_ms"] = json!(0);
        value["events"][1]["uncertainty_ms"] = json!(0);
        assert_eq!(
            timeline(&value),
            vec![(0, State::Online), (5100, State::Offline)]
        );
        value["events"][1]["state"] = json!("unknown");
        assert_eq!(
            timeline(&value),
            vec![(0, State::Online), (5100, State::Unknown)]
        );
    }

    #[test]
    fn rejects_ambiguous_order_precision_and_invalid_provenance() {
        for (path, replacement) in [
            ("/schema_version", json!(2)),
            ("/kind", json!("measured")),
            ("/device_id", json!(" ")),
            ("/source/completeness", json!("")),
            ("/source/raw_log_sha256", json!("invalid")),
            ("/events/1/id", json!("initial")),
            ("/events/1/recorded_at", json!("2026-11-08T11:59:59Z")),
            (
                "/events/1/recorded_at",
                json!("2026-11-08T12:00:05.000001Z"),
            ),
            ("/events/1/recorded_at", json!("2026-11-08T12:00:60Z")),
            ("/events/1/uncertainty_ms", json!(u64::MAX)),
            ("/clock/offset_ms", json!(i64::MAX)),
            ("/clock/offset_ms", json!(i64::MIN)),
            ("/end", json!("2026-11-08T12:00:00Z")),
            ("/events", json!([])),
        ] {
            let mut value = input();
            *value.pointer_mut(path).unwrap() = replacement;
            assert!(convert(&value).is_err(), "accepted {path}");
        }
        let mut value = input();
        value["events"][1]["recorded_at"] = json!("2026-11-08T11:59:59.250Z");
        assert!(convert(&value).err().unwrap().contains("overlap or touch"));
    }

    #[test]
    fn deterministic_artifact_preserves_input_and_exact_byte_hash() {
        let value = input();
        let bytes = serde_json::to_vec(&value).unwrap();
        let first = serde_json::to_value(convert_json(&bytes).unwrap()).unwrap();
        assert_eq!(
            first,
            serde_json::to_value(convert_json(&bytes).unwrap()).unwrap()
        );
        assert_eq!(first["reference"], value);
        let mut spaced = bytes;
        spaced.push(b'\n');
        let second = serde_json::to_value(convert_json(&spaced).unwrap()).unwrap();
        assert_ne!(first["input_sha256"], second["input_sha256"]);
        assert_eq!(first["ground_truth"], second["ground_truth"]);
        let mut invalid = value;
        invalid["unrecognized"] = json!(true);
        assert!(convert(&invalid).is_err());
    }
}
