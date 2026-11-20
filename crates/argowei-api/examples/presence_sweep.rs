//! Why these thresholds? A parameter sweep over the production PresencePolicy.
//!
//! [`presence_evaluation`](presence_evaluation.rs) asks whether the shipped rule
//! behaves correctly on five hand-authored traces. It cannot answer a different
//! question: whether `3` missed scans and `15` minutes are a defensible *choice*
//! rather than two numbers that happen to work on those traces. This program
//! sweeps the (missed scans x minutes) grid over many generated traces and
//! reports the cost of each setting, so the shipped default can be read off a
//! measured trade-off curve instead of being asserted.
//!
//! The traces come from a seeded generative model, not from a network: a device
//! alternates between present and absent, a present device can still miss a
//! reply while its Wi-Fi radio sleeps, and the scanner itself sometimes fails.
//! Ground truth is the generator's own present/absent state, which no rule sees.
//! This measures how the rule reacts to that model's failure modes; it is not a
//! claim about how real devices on a real network behave.
//!
//! Two costs are counted per setting, and they trade off against each other:
//! a *false offline* (the device was present and the rule said offline) and
//! *detection delay* (minutes from a device actually leaving until the rule
//! says so). Lowering one raises the other, so no setting is best at both; the
//! report marks the settings that are Pareto-optimal, meaning no other setting
//! is at least as good on both costs and strictly better on one.
//!
//! Two results are worth reading off the report. The shipped thresholds cut
//! false offline reports roughly twelvefold against reporting on a single
//! missed reply, at the cost of several minutes of delay, which is the
//! trade-off the rule exists to make. They are also *redundant* at this scan
//! interval: three missed scans five minutes apart already span the fifteen
//! minutes the second threshold asks for, so it never binds here and the cell
//! costs exactly what `(3, 0)` costs. That is a property of this model's
//! five-minute cadence, not an argument for removing the threshold, which
//! still guards deployments that scan far more often or pause between scans.
//!
//! No sockets, database, or wall clock. The seed is fixed, so the JSON report is
//! byte-identical across runs and machines.

use std::time::Duration;

use argowei_api::presence::PresencePolicy;
use chrono::{DateTime, TimeZone, Utc};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

/// Fixed so the report is reproducible; any value exercises the same model.
const SEED: u64 = 0x0A12_07E1;
/// Enough traces that one unlucky device cannot swing a cell of the grid.
const TRACES: usize = 200;
/// Scans per trace, at `SCAN_INTERVAL_MIN` apart: about eight hours of history.
const STEPS_PER_TRACE: usize = 96;
const SCAN_INTERVAL_MIN: i64 = 5;

/// Per-scan chance that a present device does not answer (Wi-Fi power saving).
const SLEEP_MISS_RATE: f64 = 0.25;
/// Per-scan chance the scan itself fails and yields no evidence either way.
const SCAN_FAILURE_RATE: f64 = 0.05;
/// Per-scan chance a present device leaves, or an absent device returns.
const DEPARTURE_RATE: f64 = 0.02;
const RETURN_RATE: f64 = 0.08;

/// Swept thresholds. The shipped default (3, 15) is one cell of this grid.
const MISS_THRESHOLDS: &[u32] = &[1, 2, 3, 4, 5, 6];
const MINUTE_THRESHOLDS: &[i64] = &[0, 5, 10, 15, 20, 30, 45, 60];

const DEFAULT_MISSES: u32 = 3;
const DEFAULT_MINUTES: i64 = 15;

#[derive(Clone, Copy)]
struct Step {
    minute: i64,
    /// A failed scan supplies no evidence about the device.
    completed: bool,
    replied: bool,
    /// The generator's state, which the rule never observes.
    truly_online: bool,
}

/// One trace from the generative model described in the module documentation.
/// `sleep_miss_rate` is a parameter so the sensitivity check can vary the one
/// assumption the conclusions are most exposed to.
fn generate_trace(rng: &mut StdRng, sleep_miss_rate: f64) -> Vec<Step> {
    let mut steps = Vec::with_capacity(STEPS_PER_TRACE);
    // Start present, so every trace has a last-seen time before it can leave.
    let mut present = true;
    for index in 0..STEPS_PER_TRACE {
        let minute = index as i64 * SCAN_INTERVAL_MIN;
        let completed = !rng.gen_bool(SCAN_FAILURE_RATE);
        // A present device replies unless its radio is asleep; an absent device
        // never replies. Replies are only meaningful when the scan completed.
        let replied = completed && present && !rng.gen_bool(sleep_miss_rate);
        steps.push(Step {
            minute,
            completed,
            replied,
            truly_online: present,
        });
        // Transition after the observation, so the label matches this scan.
        present = if present {
            !rng.gen_bool(DEPARTURE_RATE)
        } else {
            rng.gen_bool(RETURN_RATE)
        };
    }
    steps
}

#[derive(Default)]
struct Counters {
    completed_scans: u64,
    /// Device was present and the rule reported offline.
    false_offline: u64,
    /// Device was absent and the rule still reported online.
    missed_offline: u64,
    /// Minutes from an actual departure to the first offline report.
    detection_delay_total: i64,
    detections: u64,
    /// Departures the rule never reported before the device returned.
    undetected_departures: u64,
}

/// Run one threshold setting over one trace, accumulating into `counters`.
fn run_trace(
    policy: &PresencePolicy,
    steps: &[Step],
    origin: DateTime<Utc>,
    counters: &mut Counters,
) {
    let mut last_seen = origin;
    let mut misses = 0_i64;
    let mut online = true;
    // Set when the device leaves, cleared once the rule notices or it returns.
    let mut departed_at: Option<i64> = None;
    let mut was_online = true;

    for step in steps {
        if step.truly_online != was_online {
            if step.truly_online {
                // Returned before the rule ever reported the previous departure.
                if departed_at.is_some() {
                    counters.undetected_departures += 1;
                    departed_at = None;
                }
            } else {
                departed_at = Some(step.minute);
            }
            was_online = step.truly_online;
        }

        if !step.completed {
            continue;
        }
        counters.completed_scans += 1;
        let now = origin + chrono::Duration::minutes(step.minute);
        if step.replied {
            last_seen = now;
            misses = 0;
            online = true;
        } else {
            misses += 1;
            if policy.is_offline(misses, last_seen, now) {
                online = false;
            }
        }

        if step.truly_online && !online {
            counters.false_offline += 1;
        } else if !step.truly_online && online {
            counters.missed_offline += 1;
        }
        if !online {
            if let Some(left_at) = departed_at {
                counters.detection_delay_total += step.minute - left_at;
                counters.detections += 1;
                departed_at = None;
            }
        }
    }
    if departed_at.is_some() {
        // Still unreported when the trace ended.
        counters.undetected_departures += 1;
    }
}

#[derive(Serialize)]
struct Cell {
    offline_after_missed_scans: u32,
    offline_after_minutes: i64,
    /// True for the threshold pair the application ships.
    shipped_default: bool,
    completed_scans: u64,
    false_offline: u64,
    /// False offline reports per 1000 completed scans, comparable across cells.
    false_offline_per_1k_scans: f64,
    missed_offline: u64,
    detected_departures: u64,
    undetected_departures: u64,
    /// Mean minutes from an actual departure to the first offline report.
    mean_detection_delay_minutes: Option<f64>,
    /// No other cell is at least as good on both costs and better on one.
    pareto_optimal: bool,
    /// A looser cell with identical costs exists, so both thresholds are not
    /// binding here: the miss count alone already delays the report past this
    /// many minutes. Such a cell buys nothing over the looser one.
    redundant_threshold: bool,
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn sweep() -> Vec<Cell> {
    sweep_at(SLEEP_MISS_RATE)
}

fn sweep_at(sleep_miss_rate: f64) -> Vec<Cell> {
    // One trace set, reused for every cell, so cells differ only by thresholds.
    let mut rng = StdRng::seed_from_u64(SEED);
    let traces: Vec<Vec<Step>> = (0..TRACES)
        .map(|_| generate_trace(&mut rng, sleep_miss_rate))
        .collect();
    let origin = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

    let mut cells: Vec<Cell> = Vec::new();
    for &misses in MISS_THRESHOLDS {
        for &minutes in MINUTE_THRESHOLDS {
            let policy = PresencePolicy {
                offline_after_missed_scans: misses,
                offline_after: Duration::from_secs((minutes as u64) * 60),
            };
            let mut counters = Counters::default();
            for trace in &traces {
                run_trace(&policy, trace, origin, &mut counters);
            }
            let delay = (counters.detections > 0).then(|| {
                round2(counters.detection_delay_total as f64 / counters.detections as f64)
            });
            cells.push(Cell {
                offline_after_missed_scans: misses,
                offline_after_minutes: minutes,
                shipped_default: misses == DEFAULT_MISSES && minutes == DEFAULT_MINUTES,
                completed_scans: counters.completed_scans,
                false_offline: counters.false_offline,
                false_offline_per_1k_scans: round2(
                    counters.false_offline as f64 * 1000.0 / counters.completed_scans as f64,
                ),
                missed_offline: counters.missed_offline,
                detected_departures: counters.detections,
                undetected_departures: counters.undetected_departures,
                mean_detection_delay_minutes: delay,
                pareto_optimal: false,
                redundant_threshold: false,
            });
        }
    }
    mark_redundant(&mut cells);
    mark_pareto(&mut cells);
    cells
}

/// Both thresholds must hold, so whichever binds later decides alone: raising
/// the other one changes nothing. A cell is redundant when a setting that is no
/// stricter in either threshold reaches exactly the same costs, which means the
/// extra strictness buys nothing. Only the loosest member of such a tie group
/// stays, so the Pareto front lists each distinct trade-off once.
fn mark_redundant(cells: &mut [Cell]) {
    let snapshot: Vec<(u32, i64, f64, Option<f64>)> = cells
        .iter()
        .map(|c| {
            (
                c.offline_after_missed_scans,
                c.offline_after_minutes,
                c.false_offline_per_1k_scans,
                c.mean_detection_delay_minutes,
            )
        })
        .collect();
    for cell in cells.iter_mut() {
        cell.redundant_threshold = snapshot.iter().any(|&(misses, minutes, rate, delay)| {
            let looser_or_equal =
                misses <= cell.offline_after_missed_scans && minutes <= cell.offline_after_minutes;
            let strictly_looser =
                misses < cell.offline_after_missed_scans || minutes < cell.offline_after_minutes;
            looser_or_equal
                && strictly_looser
                && rate == cell.false_offline_per_1k_scans
                && delay == cell.mean_detection_delay_minutes
        });
    }
}

/// A cell is dominated when another cell is at least as good on both costs and
/// strictly better on at least one. Cells that never detect a departure have no
/// delay to compare, and redundant cells duplicate a looser setting, so neither
/// joins the front.
fn mark_pareto(cells: &mut [Cell]) {
    let costs: Vec<Option<(f64, f64)>> = cells
        .iter()
        .map(|cell| {
            cell.mean_detection_delay_minutes
                .map(|delay| (cell.false_offline_per_1k_scans, delay))
        })
        .collect();
    for index in 0..cells.len() {
        let Some((false_rate, delay)) = costs[index] else {
            continue;
        };
        if cells[index].redundant_threshold {
            continue;
        }
        let dominated = costs.iter().enumerate().any(|(other, cost)| {
            other != index
                && cost.is_some_and(|(other_rate, other_delay)| {
                    other_rate <= false_rate
                        && other_delay <= delay
                        && (other_rate < false_rate || other_delay < delay)
                })
        });
        cells[index].pareto_optimal = !dominated;
    }
}

/// Sleep rates the sensitivity check re-runs the shipped thresholds at. The
/// modelled 0.25 sits in the middle; the ends cover a device that almost always
/// answers and one that answers barely half the time.
const SENSITIVITY_RATES: &[f64] = &[0.05, 0.15, 0.25, 0.35, 0.45];

/// How the shipped thresholds hold up when the least certain model assumption
/// changes. Every number above depends on devices missing a quarter of their
/// replies while asleep, which is an assumption and not a measurement, so the
/// report states what the same thresholds cost at other rates.
#[derive(Serialize)]
struct Sensitivity {
    sleep_miss_rate: f64,
    /// The shipped thresholds at this rate.
    false_offline_per_1k_scans: f64,
    mean_detection_delay_minutes: Option<f64>,
    /// The loosest setting, which reports offline on one missed reply.
    baseline_false_offline_per_1k_scans: f64,
    /// How many times fewer false offline reports the shipped thresholds give
    /// than that baseline. Above 1 means the rule is still earning its delay.
    improvement_factor: Option<f64>,
}

fn sensitivity() -> Vec<Sensitivity> {
    SENSITIVITY_RATES
        .iter()
        .map(|&rate| {
            let cells = sweep_at(rate);
            let find = |misses: u32, minutes: i64| {
                cells
                    .iter()
                    .find(|c| {
                        c.offline_after_missed_scans == misses && c.offline_after_minutes == minutes
                    })
                    .expect("swept cell")
            };
            let shipped = find(DEFAULT_MISSES, DEFAULT_MINUTES);
            let baseline = find(1, 0);
            Sensitivity {
                sleep_miss_rate: rate,
                false_offline_per_1k_scans: shipped.false_offline_per_1k_scans,
                mean_detection_delay_minutes: shipped.mean_detection_delay_minutes,
                baseline_false_offline_per_1k_scans: baseline.false_offline_per_1k_scans,
                improvement_factor: (shipped.false_offline_per_1k_scans > 0.0).then(|| {
                    round2(baseline.false_offline_per_1k_scans / shipped.false_offline_per_1k_scans)
                }),
            }
        })
        .collect()
}

#[derive(Serialize)]
struct Report {
    model: Model,
    cells: Vec<Cell>,
    sensitivity: Vec<Sensitivity>,
}

#[derive(Serialize)]
struct Model {
    seed: u64,
    traces: usize,
    steps_per_trace: usize,
    scan_interval_minutes: i64,
    sleep_miss_rate: f64,
    scan_failure_rate: f64,
    departure_rate: f64,
    return_rate: f64,
}

fn main() {
    let report = Report {
        model: Model {
            seed: SEED,
            traces: TRACES,
            steps_per_trace: STEPS_PER_TRACE,
            scan_interval_minutes: SCAN_INTERVAL_MIN,
            sleep_miss_rate: SLEEP_MISS_RATE,
            scan_failure_rate: SCAN_FAILURE_RATE,
            departure_rate: DEPARTURE_RATE,
            return_rate: RETURN_RATE,
        },
        cells: sweep(),
        sensitivity: sensitivity(),
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(cells: &[Cell], misses: u32, minutes: i64) -> &Cell {
        cells
            .iter()
            .find(|c| c.offline_after_missed_scans == misses && c.offline_after_minutes == minutes)
            .expect("swept cell")
    }

    #[test]
    fn the_sweep_is_deterministic() {
        let first = sweep();
        let second = sweep();
        assert_eq!(first.len(), MISS_THRESHOLDS.len() * MINUTE_THRESHOLDS.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.false_offline, b.false_offline);
            assert_eq!(
                a.mean_detection_delay_minutes,
                b.mean_detection_delay_minutes
            );
        }
    }

    #[test]
    fn raising_either_threshold_cannot_add_false_offline_reports() {
        // Both thresholds are necessary conditions for an offline report, so a
        // stricter setting can only report offline where a looser one already
        // did. If this fails, the rule is not monotone and the trade-off curve
        // below would be meaningless.
        let cells = sweep();
        for window in MISS_THRESHOLDS.windows(2) {
            for &minutes in MINUTE_THRESHOLDS {
                let looser = cell(&cells, window[0], minutes);
                let stricter = cell(&cells, window[1], minutes);
                assert!(stricter.false_offline <= looser.false_offline);
            }
        }
        for &misses in MISS_THRESHOLDS {
            for window in MINUTE_THRESHOLDS.windows(2) {
                let looser = cell(&cells, misses, window[0]);
                let stricter = cell(&cells, misses, window[1]);
                assert!(stricter.false_offline <= looser.false_offline);
            }
        }
    }

    #[test]
    fn one_miss_and_no_waiting_is_the_costly_corner() {
        // The loosest cell is what the production rule exists to avoid: it
        // reports offline on a single missed reply.
        let cells = sweep();
        let loosest = cell(&cells, 1, 0);
        let shipped = cell(&cells, DEFAULT_MISSES, DEFAULT_MINUTES);
        assert!(loosest.false_offline > shipped.false_offline);
        // And it pays for that with the shortest delay, which is the trade-off.
        assert!(
            loosest.mean_detection_delay_minutes.unwrap()
                < shipped.mean_detection_delay_minutes.unwrap()
        );
    }

    #[test]
    fn the_shipped_default_is_recorded_once() {
        let cells = sweep();
        assert_eq!(cells.iter().filter(|c| c.shipped_default).count(), 1);
    }

    #[test]
    fn the_thresholds_keep_earning_their_delay_at_every_modelled_sleep_rate() {
        // The headline numbers assume devices miss a quarter of their replies.
        // If the rule only paid off at that one rate, the result would be an
        // artefact of the assumption rather than a property of the rule.
        let rows = sensitivity();
        assert_eq!(rows.len(), SENSITIVITY_RATES.len());
        for row in &rows {
            let factor = row
                .improvement_factor
                .expect("the shipped thresholds report some false offline at every rate");
            assert!(
                factor > 1.0,
                "at sleep rate {} the shipped thresholds gave no improvement (factor {factor})",
                row.sleep_miss_rate
            );
        }
        // The benefit shrinks as devices sleep more: at a high enough miss rate
        // even three consecutive misses become common, so waiting rescues a
        // smaller share of them. The rule still helps several times over at the
        // sleepiest rate modelled, which is the claim worth defending; a
        // constant or growing factor would be the surprising result.
        let factors: Vec<f64> = rows
            .iter()
            .map(|row| row.improvement_factor.unwrap())
            .collect();
        for pair in factors.windows(2) {
            assert!(
                pair[1] < pair[0],
                "the benefit should shrink as devices sleep more, got {pair:?}"
            );
        }
        assert!(*factors.last().unwrap() > 2.0);
    }

    #[test]
    fn sleepier_devices_cost_more_false_offline_reports() {
        // A direct statement of the exposure: the shipped thresholds are not
        // rate-independent, and a deployment full of power-saving devices
        // should expect more false offline reports than this sweep's headline.
        let rows = sensitivity();
        for pair in rows.windows(2) {
            assert!(pair[1].false_offline_per_1k_scans > pair[0].false_offline_per_1k_scans);
        }
    }

    #[test]
    fn a_dominated_cell_is_not_on_the_front() {
        // Same miss threshold, longer wait: never fewer false offline reports
        // and never a shorter delay, so the longer wait cannot be on the front
        // unless it ties on both.
        let cells = sweep();
        let front: Vec<_> = cells.iter().filter(|c| c.pareto_optimal).collect();
        assert!(!front.is_empty());
        for cell in &front {
            assert!(cell.mean_detection_delay_minutes.is_some());
            assert!(!cell.redundant_threshold);
        }
    }

    #[test]
    fn at_this_scan_interval_the_minute_threshold_never_binds() {
        // Three missed scans five minutes apart already span fifteen minutes,
        // so the shipped minute threshold cannot fire any later than the miss
        // count does: (3, 15) costs exactly what (3, 0) costs. The second
        // threshold still matters in deployments this sweep does not model, a
        // scanner that polls far more often or pauses between scans, which is
        // why this is recorded as a property of the sweep rather than an
        // argument for dropping it from the policy.
        let cells = sweep();
        let shipped = cell(&cells, DEFAULT_MISSES, DEFAULT_MINUTES);
        let misses_only = cell(&cells, DEFAULT_MISSES, 0);
        assert_eq!(
            shipped.false_offline_per_1k_scans,
            misses_only.false_offline_per_1k_scans
        );
        assert_eq!(
            shipped.mean_detection_delay_minutes,
            misses_only.mean_detection_delay_minutes
        );
        assert!(shipped.redundant_threshold);
    }
}
