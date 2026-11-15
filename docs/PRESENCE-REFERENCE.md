# Independent reference label conversion

`presence_reference` converts separately recorded state events into the
`ground_truth` array used by a [lab study](PRESENCE-LAB.md). It is offline,
deterministic, and requires no database, network access, or system clock.
This is implemented tooling with synthetic regression tests; no independent
lab measurements or field accuracy are established by it.

## Question and method

How can an operator avoid treating uncertain reference transition times as
exact? Manually inserting `unknown` labels is possible but error-prone.
Using only a central timestamp understates uncertainty. This converter uses
explicit bounds and rejects ambiguous ordering instead of guessing an order.
It does not estimate clock error or authenticate reference logs.

For each event, the aligned center is `recorded_at + clock.offset_ms`.
The radius is `clock.uncertainty_ms + event.uncertainty_ms`. Positive offset
adds time to the reference clock to align it to the collector's UTC timestamp
axis; negative offset subtracts time. The event may occur between
`center - radius` and `center + radius`. Labels are `unknown` over the half-open
interval between these bounds, then take the event's state at the upper bound.
Zero-radius events change state exactly at the center. Successive event bounds
must be strictly separated; overlapping or touching bounds are rejected.
This conservative restriction avoids imposing an unproved order.

The initial state is unknown until the first event's upper bound. An event
before study start can establish its initial state. Conversion clips to
`[start, end)`, emits a label at start, and coalesces identical adjacent labels.
Explicit `unknown` events represent reference-source loss or excluded periods;
a later known event is required to resume labeling. Known states are held
until the next event or study end, so the source must account for all changes
throughout that period. A single observation cannot establish continued presence.

## Input contract (version 1)

One input describes one pseudonymous device and one fixed clock alignment.
All fields below are required; unknown fields are rejected. This example is
synthetic, including its placeholder raw-log hash.

```json
{
  "schema_version": 1,
  "kind": "synthetic",
  "device_id": "device-01",
  "start": "2026-11-08T12:00:00Z",
  "end": "2026-11-08T12:00:10Z",
  "source": {
    "description": "Hand-authored transitions, not measured events",
    "raw_log_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "state_definition": "Membership in a controlled test LAN",
    "completeness": "All synthetic changes included through window end"
  },
  "clock": {
    "offset_ms": 100,
    "uncertainty_ms": 50,
    "evidence": "Synthetic alignment; not a measured clock bound"
  },
  "events": [
    { "id": "initial", "recorded_at": "2026-11-08T11:59:59Z", "uncertainty_ms": 0, "state": "online" },
    { "id": "disconnect", "recorded_at": "2026-11-08T12:00:05Z", "uncertainty_ms": 150, "state": "offline" }
  ]
}
```

`kind` is `synthetic` or `lab`; choose `lab` only for actual independent
measurements. Neither the declaration nor a hash establishes authenticity.
Provenance strings and event IDs must be nonblank; IDs must be unique.
`raw_log_sha256` identifies exact original log bytes and must be 64 hex
characters. Keep those bytes separately; the converter does not read that log.
Events must be nonempty and strictly increasing in recorded time, including
events outside the study window. State is `online`, `offline`, or `unknown`.
Times require an explicit timezone and whole-millisecond precision. Leap
seconds, sub-millisecond times, nonpositive windows, negative uncertainties,
overflow, and unsupported versions are rejected. Normalize finer-resolution
logs conservatively first, accounting for rounding in event uncertainty.

The global clock uncertainty must bound alignment error over the **entire**
window, including drift and the collector clock's error. Event uncertainty
covers reference sensing, timestamp resolution and logging delay. Use justified
bounds, not RMS offsets or assumed zero error. Split studies at clock steps,
alignment changes or unbounded drift. Never infer reference labels from ARP.

## Reproduce and use

```sh
cargo run --locked -q -p argowei-api --example presence_reference -- \
  reference.json > reference-labels.json
cargo test --locked -p argowei-api --example presence_reference
```

Use `-` for stdin or `--help` for usage. Invalid input exits 1 with diagnostics
on stderr. The artifact contains `artifact_version: 1`, SHA-256 of exact input
bytes, the parsed reference with all provenance and events, and `ground_truth`.
The example produces online at start, unknown at `12:00:04.900Z`, and offline
at `12:00:05.300Z`.

Copy only `ground_truth` into the study trace with matching `device_id`, `start`
and `end`. Retain the full artifact, original input, raw log, alignment evidence,
study, export and replay report. Record its input hash in the study's
`dataset.ground_truth_source`. Run the existing export and replay commands in
the lab protocol. Synthetic labels cannot establish a lab study.
Unknown windows exclude correctness claims and break observed departures;
the existing replay does not estimate latency bounds for uncertain departures.
Report unlabeled duration alongside errors and censored outcomes.

## Timing sources and limits

Primary documentation read for this contract (2026-11-14):

- [RFC 5905, section 4](https://www.rfc-editor.org/rfc/rfc5905.html#section-4)
  distinguishes offset, dispersion and RMS jitter, and describes growing
  uncertainty with drift. These concepts are not measured bounds for this study.
- [chronyc tracking documentation](https://chrony-project.org/doc/4.8/chronyc.html#tracking)
  distinguishes system-clock correction from NTP-clock offsets and gives
  `|system_time_offset| + root_dispersion + 0.5 * root_delay` as an accuracy
  bound assuming the stratum-1 source is correct. A tracking snapshot alone
  does not bound an entire experiment or reference logging delay.

Real independent logs, completeness evidence and justified alignment bounds
remain necessary. The tool checks consistency of declarations, not their truth.
