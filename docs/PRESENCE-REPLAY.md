# Presence trace replay

Replay recorded observations and independently labeled device states against
the production presence policy and three baselines. Unlike the small
[synthetic evaluation](PRESENCE-EVALUATION.md), this benchmark accepts external
datasets and measures durations across irregular scan intervals.

The committed [input](evidence/presence-replay.synthetic.json) and
[report](evidence/presence-replay.synthetic-report.json) are **synthetic
regression fixtures**, not field measurements or evidence of superiority.

## Run

From the repository root, with the Rust toolchain installed:

```sh
cargo run --locked -q -p argowei-api --example presence_replay -- \
  docs/evidence/presence-replay.synthetic.json > /tmp/presence-report.json
diff -u docs/evidence/presence-replay.synthetic-report.json /tmp/presence-report.json
cargo test --locked -p argowei-api --example presence_replay
```

Pass a JSON path or `-` to read stdin; `--help` prints usage. A validated,
deterministic JSON artifact is written to stdout. Invalid input produces a
diagnostic on stderr and exit status 1. No database, sockets, privileges, or
wall clock are involved. `input_sha256` identifies the exact input bytes,
including whitespace; it establishes reproducibility, not authenticity.

## Input contract (version 2)

```json
{
  "schema_version": 2,
  "dataset": {
    "id": "example-only",
    "kind": "synthetic",
    "description": "A hand-authored example, not a field observation.",
    "ground_truth_source": "Separately specified synthetic state transitions."
  },
  "policy": { "offline_after_missed_scans": 3, "offline_after_secs": 900 },
  "traces": [{
    "device_id": "anonymous-device-1",
    "interface": "lab-interface-1",
    "duration_ms": 1200000,
    "observations": [
      { "at_ms": 0, "outcome": "reply" },
      { "at_ms": 300000, "outcome": "miss" },
      { "at_ms": 600000, "outcome": "failed" },
      { "at_ms": 750000, "outcome": "skipped" },
      { "at_ms": 900000, "outcome": "miss" }
    ],
    "ground_truth": [
      { "at_ms": 0, "state": "online" },
      { "at_ms": 420000, "state": "offline" }
    ]
  }]
}
```

- `dataset.kind` is `synthetic` or `lab`. The ID, description, and
  `ground_truth_source` are required nonempty provenance declarations. The
  tool cannot verify that labels were actually measured independently.
- Version 1 inputs remain readable with their original `reply`, `miss`, and
  `failed` outcomes. `skipped` requires version 2. Reports use schema version
  2, including when replaying a version 1 input.
- `policy` is optional; its defaults are 3 missed scans and 900 seconds. When
  present, both fields are required. The miss threshold must be positive;
  a zero time threshold is allowed.
- Each trace describes one device on one fixed interface, over the half-open
  interval `[0, duration_ms)`. IDs must be unique across traces. Split interface
  changes into separate, independently identified experimental windows.
- Both arrays must be nonempty, with strictly increasing `at_ms` values in
  each array. Offsets are milliseconds relative to the same trace origin;
  every offset must be less than the positive `duration_ms`. Unsupported
  schema versions, unknown fields, invalid enum values, duplicate identities,
  out-of-order events, and unrepresentable time ranges are rejected.
- `reply` means a completed scan observed the device; `miss` means a completed
  scan of that interface did not. `failed` means the attempt produced no usable
  scan result. `skipped` means no scan ran because the interface was
  already busy. Both remain visible as separate counts and never become misses.
- Ground truth is `online`, `offline`, or explicitly `unknown`. Before its
  first label it is unknown. A label applies until the next change or trace
  end. An observation and label at the same offset take effect together.

## Replay semantics

All methods begin with an **unknown prediction**, until the first reply.
A reply sets online, resets consecutive misses, and updates last seen.
Failed and skipped attempts leave the prediction and miss count unchanged. Completed scans
without a reply update the miss count and evaluate the method. Once offline,
the prediction stays offline until a reply. Elapsed time alone never causes
a state change between scan events; this matches production evaluation at
completed scans rather than adding a background timer.

| Method | Offline condition at a completed scan without a reply |
| --- | --- |
| `production_and` | Configured miss count **and** elapsed time; calls `PresencePolicy::is_offline` |
| `time_only` | Configured elapsed time |
| `misses_only` | Configured miss count |
| `one_miss` | One miss |

The replay isolates decision logic. It does not emulate SQL transactions,
discovery scheduling, multi-interface reconciliation, or device identity.

## Metrics

Each trace has a report for each method; `aggregate` pools the same methods
across traces. Duration totals are **device-milliseconds**, so overlapping
device traces contribute separately. Aggregates are not network wall time
and are not an unweighted average of per-device rates.

States are held over `[event, next_event)`, including scanner gaps and the
final interval to `duration_ms`. For a fixed prediction timeline, adding
evaluation points does not inflate an error's duration. Additional actual
scans can change the miss count and therefore the predictions.

| Report field | Meaning |
| --- | --- |
| `metrics.confusion.truth_online` | Time truly online, partitioned into predicted `online_ms`, `offline_ms`, and `unknown_ms` |
| `metrics.confusion.truth_offline` | Time truly offline, partitioned the same way |
| `metrics.confusion.unlabeled_ms` | Time with unknown reference state, excluded from correctness claims |
| `metrics.false_offline_episodes` | Distinct intervals where the device is labeled online but predicted offline |
| `metrics.false_online_episodes` | Distinct intervals where the device is labeled offline but predicted online |
| `metrics.completed_scans`, `failed_scans`, `skipped_scans` | Counts of usable scans, failed scans, and skipped attempts |
| `departures` | Every observed `online` → `offline` label transition and its outcome |

The six confusion cells plus `unlabeled_ms` partition the complete trace
duration. Unknown predictions on known labels remain visible; they are
neither counted correct nor silently discarded. Unknown labels interrupt
error episodes. Attempt counts are per device trace; aggregate counts sum those
trace counts. A single interface-level skip included for two devices therefore
contributes two to the aggregate `skipped_scans`, not two separate scheduler
events.

A departure is detected at the first offline prediction during that offline
episode. An already offline prediction has delay zero; any preceding false
offline duration is still counted. Returning online before detection gives
`status: undetected`. Trace end or loss of the reference label before
detection gives `status: censored` with the reason and observation duration.
An initial offline label or `unknown` → `offline` transition is not an
observed departure, because the departure time is not known.

`detection` reports detected, undetected, and censored counts separately.
Its p50/p95 delays use nearest rank over **detected departures only** (null
when there are none). Always read these quantiles with the outcome counts:
detecting only the easiest departures must not look like good overall
latency. No population-level accuracy, confidence intervals, probe overhead,
or CPU measurements are inferred by this replay.

## Collect a first lab dataset

For a database-backed workflow, see the [presence lab protocol](PRESENCE-LAB.md).

1. Define what online means for the experiment: for example, membership in a
   controlled LAN. Physical presence, a running OS, Wi-Fi association, and an
   ARP answer are different claims. Record sleep separately in the collection
   notes even if the selected label remains online.
2. Use a separate reference signal: controlled power/link changes, device
   logs, or a serial log from an ESP32. Do not label presence from the same
   ARP replies being evaluated. Record clock alignment and its uncertainty;
   mark uncertain label windows as unknown.
3. Capture successful scans, absent replies, scanner failures, and skipped
   attempts separately. Include sleep, actual disconnection, reconnection,
   and scanner outage; retain failure cases. Keep raw observation and reference logs so the
   conversion to this format can be audited.
4. Use pseudonymous IDs and document device classes, scan interval, collector
   version, experiment dates, labeling method, and trace exclusions alongside
   the dataset. Set `kind: lab` only for actual measurements.
5. Choose parameters using separate devices or recording periods from those
   used for final evaluation. Preserve dataset and parameter versions; report
   error duration, error episodes, all departure outcomes, and limitations.

One small homelab dataset supports conclusions about that setup. Extending
the dataset and validating reference labels comes before claims about a
general device population or an improved algorithm.
