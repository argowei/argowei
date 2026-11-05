//! Versioned input and deterministic replay results.

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub schema_version: u32,
    pub dataset: Dataset,
    #[serde(default)]
    pub policy: Policy,
    pub traces: Vec<Trace>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dataset {
    pub id: String,
    pub kind: DatasetKind,
    pub description: String,
    pub ground_truth_source: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DatasetKind {
    Synthetic,
    Lab,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub offline_after_missed_scans: u32,
    pub offline_after_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        let production = argowei_api::presence::PresencePolicy::default();
        Self {
            offline_after_missed_scans: production.offline_after_missed_scans,
            offline_after_secs: production.offline_after.as_secs(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Trace {
    pub device_id: String,
    pub interface: String,
    pub duration_ms: u64,
    pub observations: Vec<Observation>,
    pub ground_truth: Vec<Label>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub at_ms: u64,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Reply,
    Miss,
    Failed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Label {
    pub at_ms: u64,
    pub state: State,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Online,
    Offline,
    Unknown,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Method {
    ProductionAnd,
    TimeOnly,
    MissesOnly,
    OneMiss,
}

pub(super) const METHODS: [Method; 4] = [
    Method::ProductionAnd,
    Method::TimeOnly,
    Method::MissesOnly,
    Method::OneMiss,
];

/// A deterministic result: no wall clock, host names, or generated identifiers.
#[derive(Serialize)]
pub struct Report {
    pub(super) schema_version: u32,
    pub(super) dataset: Dataset,
    pub(super) policy: Policy,
    pub(super) methodology: &'static str,
    pub(super) traces: Vec<TraceReport>,
    pub(super) aggregate: Vec<AggregateReport>,
}

#[derive(Serialize)]
pub(super) struct TraceReport {
    pub device_id: String,
    pub interface: String,
    pub duration_ms: u64,
    pub methods: Vec<MethodReport>,
}

#[derive(Serialize)]
pub(super) struct MethodReport {
    pub method: Method,
    pub metrics: Metrics,
    pub departures: Vec<Departure>,
    pub detection: DetectionSummary,
}

#[derive(Serialize)]
pub(super) struct AggregateReport {
    pub method: Method,
    pub trace_count: usize,
    pub metrics: Metrics,
    pub detection: DetectionSummary,
}

#[derive(Default, Serialize)]
pub(super) struct Metrics {
    pub duration_ms: u64,
    pub confusion: Confusion,
    pub false_offline_episodes: u64,
    pub false_online_episodes: u64,
    pub completed_scans: u64,
    pub failed_scans: u64,
}

#[derive(Default, Serialize)]
pub(super) struct Confusion {
    pub truth_online: PredictionDurations,
    pub truth_offline: PredictionDurations,
    pub unlabeled_ms: u64,
}

#[derive(Default, Serialize)]
pub(super) struct PredictionDurations {
    pub online_ms: u64,
    pub offline_ms: u64,
    pub unknown_ms: u64,
}

#[derive(Serialize)]
pub(super) struct Departure {
    pub at_ms: u64,
    #[serde(flatten)]
    pub outcome: Detection,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum Detection {
    Detected {
        detected_at_ms: u64,
        delay_ms: u64,
    },
    Undetected {
        returned_at_ms: u64,
        observed_for_ms: u64,
    },
    Censored {
        censored_at_ms: u64,
        observed_for_ms: u64,
        reason: &'static str,
    },
}

#[derive(Default, Serialize)]
pub(super) struct DetectionSummary {
    pub departures: usize,
    pub detected: usize,
    pub undetected: usize,
    pub censored: usize,
    pub detected_delay_p50_ms: Option<u64>,
    pub detected_delay_p95_ms: Option<u64>,
}
