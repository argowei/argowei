# Presence inference: a reproducible synthetic evaluation

## Question and scope

Does requiring both three missed completed scans and 15 minutes since the last
reply reduce false offline transitions compared with one-threshold rules? What
latency and failure modes remain? This evaluates Argowei's current
[`PresencePolicy`](../crates/argowei-api/src/presence.rs), not whether an ARP
reply proves a physical device is present.

Behavioral expectations for these hand-authored traces: the combined rule should avoid
the time-only false offline state after a scanner gap and the misses-only false
offline state after three rapid scans. It should still mark a device offline
when that device sleeps through both thresholds. A contrary result in any of
those traces would reject the corresponding expectation for this implementation.

[Nmap's host-discovery documentation](https://nmap.org/book/man-host-discovery.html)
describes ARP discovery on local Ethernet and notes that proxy ARP can make
nonexistent targets appear present. [arp-scan](https://github.com/royhills/arp-scan)
focuses on discovering and fingerprinting IPv4 hosts through ARP. Argowei's
research question here is narrower: how to interpret a *sequence* of completed
scans without turning one missing reply or a scanner outage into a confident
offline claim. This comparison concerns documented capabilities, not a measured
benchmark against either tool.

## Protocol

The [evaluation program](../crates/argowei-api/examples/presence_evaluation.rs)
uses the production policy function with a fixed clock and five hand-authored
traces. Each step specifies the minute, whether the scan completed, whether the
device replied, and independent ground truth. Failed scans are excluded from
miss counts and evaluation points. A reply resets the count and restores the
reported online state. No network, database, root permission or random seed is
needed.

Four rules see identical traces:

| Rule | Offline condition after a completed scan without reply |
|---|---|
| `production_and` | At least 3 misses **and** at least 15 minutes since last reply |
| `time_only_15m` | At least 15 minutes since last reply |
| `misses_only_3` | At least 3 misses |
| `one_miss` | Any single miss |

The primary metrics count completed scans where the reported state is offline
while ground truth is online (`false_offline`) or the reverse (`missed_offline`).
`first_detection_minute` is the first completed scan at which a truly departed
device is reported offline. Counts are per scan, so consecutive wrong states
each count; they are not counts of distinct devices or incident rates.

The traces exercise intermittent replies, a genuine departure, an hour-long
scanner gap, a device that sleeps through four scans, and three rapid misses
inside the time grace period. The scenarios were chosen to expose boundary
behavior, not sampled from a real network or a population distribution.

## Observations

The committed [machine-readable result](evidence/presence-evaluation.json)
has one row per trace and rule. Key outcomes:

| Trace | Production rule | Comparator | Interpretation |
|---|---|---|---|
| Intermittent replies | 0 false offline | One miss: 3 | A reply resets evidence of absence. |
| Genuine departure | First detected at minute 25; 2 missed offline scan points | One miss: minute 15; 0 missed points | Waiting for stronger evidence delays detection. |
| Scanner gap | 0 false offline | Time only: 1 | Elapsed time alone misclassifies the first scan after an outage. |
| Sleeping device | 2 false offline | One miss: 4 | The combined rule still misclassifies sufficiently long nonresponse. |
| Rapid misses | 0 false offline | Misses only: 1 | Scan count alone misclassifies a short burst. |

This is a deterministic characterization of the current decision rule. It does
not establish field accuracy, statistical superiority, or novelty of the rule.
ARP replies are unauthenticated; proxy ARP and address changes can confuse
identity. Real scan frequency, host sleep behavior, interface changes and
ground-truth labeling must be measured before making deployment claims.

## Reproduce and extend

From the repository root:

```bash
cargo test --locked -p argowei-api --example presence_evaluation
cargo run --locked -q -p argowei-api --example presence_evaluation \
  | diff - docs/evidence/presence-evaluation.json
```

The CI runs both commands. Next, collect consented lab traces with an
independent ground-truth signal, record scanner failures separately from empty
scans, and report false offline duration and departure-detection latency across
device types and scan intervals. Keep synthetic and field results separate.

The [trace replay benchmark](PRESENCE-REPLAY.md) accepts external observation
and ground-truth timelines, measures duration-weighted errors, and records
multiple departures with explicit undetected and censored outcomes.
