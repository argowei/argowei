//! Replay scan evidence against separately recorded presence labels.

mod model;
#[cfg(test)]
mod tests;

use std::{collections::HashSet, time::Duration};

use argowei_api::presence::PresencePolicy;
use chrono::{DateTime, Utc};
pub use model::Report;
use model::*;

const METHODOLOGY: &str = "Intervals are [at_ms, next_event_ms), ending at duration_ms. Labels and observations at the same timestamp apply together. Prediction starts unknown until a reply; failed and skipped attempts preserve state and miss count; only completed scans change predictions. An online-to-offline label transition starts a departure; an already-offline prediction detects it with zero delay. A return before detection is undetected; loss of labels or the trace ending before detection is censored. Delay p50/p95 use nearest-rank quantiles of detected departures only; undetected and censored counts are reported separately. Lab provenance is supplied by the recorder, not verified by this tool.";

/// Parse and validate v1 or v2 JSON, then replay all four methods without I/O.
pub fn replay_json(input: &[u8]) -> Result<Report, String> {
    let input: Input = serde_json::from_slice(input).map_err(|error| error.to_string())?;
    validate(&input)?;
    let traces: Vec<_> = input
        .traces
        .iter()
        .map(|trace| TraceReport {
            device_id: trace.device_id.clone(),
            interface: trace.interface.clone(),
            duration_ms: trace.duration_ms,
            methods: METHODS
                .iter()
                .map(|method| replay(trace, input.policy, *method))
                .collect(),
        })
        .collect();
    let aggregate = METHODS
        .iter()
        .enumerate()
        .map(|(index, method)| {
            let mut metrics = Metrics::default();
            let mut departures = Vec::new();
            for trace in &traces {
                metrics.add(&trace.methods[index].metrics);
                departures.extend(trace.methods[index].departures.iter());
            }
            AggregateReport {
                method: *method,
                trace_count: traces.len(),
                metrics,
                detection: summarize(departures),
            }
        })
        .collect();
    Ok(Report {
        schema_version: 2,
        dataset: input.dataset,
        policy: input.policy,
        methodology: METHODOLOGY,
        traces,
        aggregate,
    })
}

fn validate(input: &Input) -> Result<(), String> {
    if !matches!(input.schema_version, 1 | 2) {
        return Err("schema_version must be 1 or 2".into());
    }
    for (name, value) in [
        ("dataset.id", &input.dataset.id),
        ("dataset.description", &input.dataset.description),
        (
            "dataset.ground_truth_source",
            &input.dataset.ground_truth_source,
        ),
    ] {
        nonempty(name, value)?;
    }
    if input.policy.offline_after_missed_scans == 0 {
        return Err("offline_after_missed_scans must be positive".into());
    }
    chrono::Duration::from_std(Duration::from_secs(input.policy.offline_after_secs))
        .map_err(|_| "offline_after_secs exceeds the supported time range")?;
    if input.traces.is_empty() {
        return Err("traces must not be empty".into());
    }
    let mut ids = HashSet::new();
    let mut total = 0_u64;
    for trace in &input.traces {
        nonempty("device_id", &trace.device_id)?;
        nonempty("interface", &trace.interface)?;
        if !ids.insert(&trace.device_id) {
            return Err(format!("duplicate device_id: {}", trace.device_id));
        }
        if trace.duration_ms == 0 {
            return Err("duration_ms must be positive".into());
        }
        timestamp(trace.duration_ms).ok_or("duration_ms exceeds the supported time range")?;
        total = total
            .checked_add(trace.duration_ms)
            .ok_or("total trace duration overflows u64")?;
        validate_times(
            "observations",
            trace.duration_ms,
            trace.observations.iter().map(|event| event.at_ms),
        )?;
        if input.schema_version == 1
            && trace
                .observations
                .iter()
                .any(|event| matches!(event.outcome, Outcome::Skipped))
        {
            return Err("skipped observations require schema_version 2".into());
        }
        validate_times(
            "ground_truth",
            trace.duration_ms,
            trace.ground_truth.iter().map(|event| event.at_ms),
        )?;
    }
    Ok(())
}

fn nonempty(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be blank"))
    } else {
        Ok(())
    }
}

fn validate_times(
    name: &str,
    duration: u64,
    times: impl Iterator<Item = u64>,
) -> Result<(), String> {
    let mut previous = None;
    for at in times {
        if at >= duration {
            return Err(format!("{name} timestamps must be less than duration_ms"));
        }
        if previous.is_some_and(|previous| at <= previous) {
            return Err(format!("{name} timestamps must strictly increase"));
        }
        previous = Some(at);
    }
    if previous.is_none() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn timestamp(ms: u64) -> Option<DateTime<Utc>> {
    DateTime::UNIX_EPOCH
        .checked_add_signed(chrono::Duration::try_milliseconds(ms.try_into().ok()?)?)
}

fn replay(trace: &Trace, config: Policy, method: Method) -> MethodReport {
    let policy = PresencePolicy {
        offline_after_missed_scans: config.offline_after_missed_scans,
        offline_after: Duration::from_secs(config.offline_after_secs),
    };
    let mut metrics = Metrics::default();
    let mut departures = Vec::new();
    let (mut evidence, mut labels, mut previous) = (0, 0, 0);
    let (mut truth, mut prediction) = (State::Unknown, State::Unknown);
    let (mut last_seen, mut pending) = (None, None);
    let mut misses = 0_i64;
    let mut last_error = None;
    while evidence < trace.observations.len() || labels < trace.ground_truth.len() {
        let at = trace
            .observations
            .get(evidence)
            .map(|event| event.at_ms)
            .unwrap_or(trace.duration_ms)
            .min(
                trace
                    .ground_truth
                    .get(labels)
                    .map(|event| event.at_ms)
                    .unwrap_or(trace.duration_ms),
            );
        metrics.interval(truth, prediction, at - previous, &mut last_error);
        if let Some(label) = trace
            .ground_truth
            .get(labels)
            .filter(|label| label.at_ms == at)
        {
            if truth == State::Offline && label.state != State::Offline {
                finish_departure(
                    &mut departures,
                    &mut pending,
                    at,
                    label.state == State::Unknown,
                    "ground_truth_unknown",
                );
            }
            if truth == State::Online && label.state == State::Offline {
                pending = Some(at);
            }
            truth = label.state;
            labels += 1;
        }
        if let Some(observation) = trace
            .observations
            .get(evidence)
            .filter(|event| event.at_ms == at)
        {
            match observation.outcome {
                Outcome::Failed => metrics.failed_scans += 1,
                Outcome::Skipped => metrics.skipped_scans += 1,
                Outcome::Reply => {
                    metrics.completed_scans += 1;
                    last_seen = Some(at);
                    misses = 0;
                    prediction = State::Online;
                }
                Outcome::Miss => {
                    metrics.completed_scans += 1;
                    misses = misses.saturating_add(1);
                    if let Some(seen) = last_seen {
                        let offline = match method {
                            Method::ProductionAnd => policy.is_offline(
                                misses,
                                timestamp(seen).expect("validated timestamp"),
                                timestamp(at).expect("validated timestamp"),
                            ),
                            Method::TimeOnly => {
                                Duration::from_millis(at - seen) >= policy.offline_after
                            }
                            Method::MissesOnly => {
                                misses >= i64::from(config.offline_after_missed_scans)
                            }
                            Method::OneMiss => true,
                        };
                        prediction = if offline {
                            State::Offline
                        } else {
                            State::Online
                        };
                    }
                }
            }
            evidence += 1;
        }
        if truth == State::Offline && prediction == State::Offline {
            if let Some(departed) = pending.take() {
                departures.push(Departure {
                    at_ms: departed,
                    outcome: Detection::Detected {
                        detected_at_ms: at,
                        delay_ms: at - departed,
                    },
                });
            }
        }
        previous = at;
    }
    metrics.interval(
        truth,
        prediction,
        trace.duration_ms - previous,
        &mut last_error,
    );
    finish_departure(
        &mut departures,
        &mut pending,
        trace.duration_ms,
        true,
        "trace_end",
    );
    let detection = summarize(departures.iter());
    MethodReport {
        method,
        metrics,
        departures,
        detection,
    }
}

fn finish_departure(
    departures: &mut Vec<Departure>,
    pending: &mut Option<u64>,
    at: u64,
    censored: bool,
    reason: &'static str,
) {
    if let Some(departed) = pending.take() {
        let outcome = if censored {
            Detection::Censored {
                censored_at_ms: at,
                observed_for_ms: at - departed,
                reason,
            }
        } else {
            Detection::Undetected {
                returned_at_ms: at,
                observed_for_ms: at - departed,
            }
        };
        departures.push(Departure {
            at_ms: departed,
            outcome,
        });
    }
}

fn summarize<'a>(departures: impl IntoIterator<Item = &'a Departure>) -> DetectionSummary {
    let mut summary = DetectionSummary::default();
    let mut delays = Vec::new();
    for departure in departures {
        summary.departures += 1;
        match departure.outcome {
            Detection::Detected { delay_ms, .. } => {
                summary.detected += 1;
                delays.push(delay_ms);
            }
            Detection::Undetected { .. } => summary.undetected += 1,
            Detection::Censored { .. } => summary.censored += 1,
        }
    }
    delays.sort_unstable();
    if !delays.is_empty() {
        summary.detected_delay_p50_ms = Some(delays[delays.len().div_ceil(2) - 1]);
        // ceil(n * 95 / 100), without overflowing the multiplication.
        let rank = delays.len() / 100 * 95 + (delays.len() % 100 * 95).div_ceil(100);
        summary.detected_delay_p95_ms = Some(delays[rank - 1]);
    }
    summary
}

impl Metrics {
    fn interval(
        &mut self,
        truth: State,
        prediction: State,
        ms: u64,
        last_error: &mut Option<State>,
    ) {
        if ms == 0 {
            return;
        }
        self.duration_ms += ms;
        let durations = match truth {
            State::Online => Some(&mut self.confusion.truth_online),
            State::Offline => Some(&mut self.confusion.truth_offline),
            State::Unknown => {
                self.confusion.unlabeled_ms += ms;
                None
            }
        };
        if let Some(durations) = durations {
            match prediction {
                State::Online => durations.online_ms += ms,
                State::Offline => durations.offline_ms += ms,
                State::Unknown => durations.unknown_ms += ms,
            }
        }
        let error = match (truth, prediction) {
            (State::Online, State::Offline) => Some(State::Offline),
            (State::Offline, State::Online) => Some(State::Online),
            _ => None,
        };
        if error != *last_error {
            match error {
                Some(State::Offline) => self.false_offline_episodes += 1,
                Some(State::Online) => self.false_online_episodes += 1,
                _ => {}
            }
        }
        *last_error = error;
    }

    fn add(&mut self, other: &Self) {
        self.duration_ms += other.duration_ms;
        self.confusion
            .truth_online
            .add(&other.confusion.truth_online);
        self.confusion
            .truth_offline
            .add(&other.confusion.truth_offline);
        self.confusion.unlabeled_ms += other.confusion.unlabeled_ms;
        self.false_offline_episodes += other.false_offline_episodes;
        self.false_online_episodes += other.false_online_episodes;
        self.completed_scans += other.completed_scans;
        self.failed_scans += other.failed_scans;
        self.skipped_scans += other.skipped_scans;
    }
}

impl PredictionDurations {
    fn add(&mut self, other: &Self) {
        self.online_ms += other.online_ms;
        self.offline_ms += other.offline_ms;
        self.unknown_ms += other.unknown_ms;
    }
}
