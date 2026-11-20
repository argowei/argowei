# Presence thresholds: why three missed scans and fifteen minutes?

## Question and scope

The [synthetic evaluation](PRESENCE-EVALUATION.md) asks whether the shipped rule
behaves correctly on five hand-authored traces. It cannot answer a different
question: whether `offline_after_missed_scans = 3` and `offline_after = 15min`
are a defensible *choice* rather than two numbers that happen to work on those
traces. This sweep measures the cost of every setting on a grid, so the default
can be read off a trade-off curve instead of being asserted.

This measures how [`PresencePolicy`](../crates/argowei-api/src/presence.rs)
reacts to one generative model. It is not a field measurement, and it does not
claim that real devices miss replies at the modelled rate. An ARP reply still
does not prove a physical device is present.

## Protocol

The [sweep program](../crates/argowei-api/examples/presence_sweep.rs) generates
200 traces of 96 scans each from a seeded model, then runs all 48 threshold
combinations over the same trace set, so cells differ only by thresholds. Each
cell evaluates 18,203 completed scans. No network, database, or wall clock is
used; the seed is fixed, so the report is byte-identical across runs.

In the model a device alternates between present and absent (2% chance of
leaving, 8% of returning per scan), a present device still misses a reply 25% of
the time while its radio sleeps, and 5% of scans fail and supply no evidence
either way. Ground truth is the generator's own state, which no rule observes.
The sleep rate is then varied separately in the [sensitivity
check](#sensitivity-to-the-sleep-rate) below.

Two costs are counted, and they oppose each other:

| Cost | Definition |
|---|---|
| False offline | Scan points where the device was present and the rule reported offline, normalised per 1000 completed scans. |
| Detection delay | Mean minutes from an actual departure to the first offline report. |

A cell is **Pareto-optimal** when no other cell is at least as good on both
costs and strictly better on one. A cell is **redundant** when a setting that is
no stricter in either threshold reaches exactly the same costs, so the extra
strictness buys nothing; those are excluded from the front, leaving 16 distinct
trade-offs out of 48 cells.

## Observations

| Thresholds | False offline / 1k scans | Mean delay (min) | Note |
|---|---|---|---|
| 1 miss, 0 min | 210.08 | 0.27 | Reports offline on a single missed reply. |
| 2 misses, 15 min | 20.33 | 8.42 | |
| **3 misses, 15 min** | **16.92** | **9.13** | **Shipped default.** |
| 3 misses, 20 min | 8.90 | 13.44 | |
| 4 misses, 0 min | 7.64 | 14.35 | |
| 6 misses, 60 min | 1.87 | 53.22 | Nearly silent, and nearly blind. |

Two results stand out.

**The shipped thresholds buy a twelvefold reduction in false offline reports.**
Against reporting on a single missed reply, 210.08 drops to 16.92 per 1000
scans, paid for with about nine minutes of delay instead of a quarter of a
minute. That is the trade-off the combined rule exists to make, and the sweep
puts a number on it rather than asserting it.

**At this scan interval the minute threshold never binds.** Three missed scans
five minutes apart already span the fifteen minutes the second threshold asks
for, so `(3, 15)` costs exactly what `(3, 0)` costs and is marked redundant.
This is a property of the modelled five-minute cadence, not an argument for
removing the threshold: it still guards deployments that scan far more often, or
that pause between scans, which is precisely the scanner-outage failure mode the
[evaluation](PRESENCE-EVALUATION.md) shows a time-only rule getting wrong. A
deployment that shortens the scan interval should expect the minute threshold to
start binding, and should re-run this sweep with its own cadence.

The sweep also records departures the rule never reported before the device
returned (`undetected_departures`), which rises with stricter thresholds: 1 at
one miss, 49 at the shipped default, 217 at the strictest cell. Delay alone
understates what strictness costs, because the departures that are never
detected at all contribute no delay to the mean.

## Sensitivity to the sleep rate

Every number above assumes a present device misses 25% of its replies while its
radio sleeps. That is an assumption, not a measurement, and it is the one the
conclusions are most exposed to, so the report re-runs the shipped thresholds
across a range of rates.

| Sleep miss rate | False offline / 1k scans | Mean delay (min) | One-miss baseline | Improvement |
|---|---|---|---|---|
| 0.05 | 0.93 | 10.64 | 43.29 | 46.55x |
| 0.15 | 5.05 | 9.92 | 125.58 | 24.87x |
| 0.25 | 16.92 | 9.13 | 210.08 | 12.42x |
| 0.35 | 44.17 | 8.00 | 295.34 | 6.69x |
| 0.45 | 81.85 | 6.92 | 376.53 | 4.60x |

Two things follow, and the second is the uncomfortable one.

The rule is not an artefact of the chosen rate: it beats the one-miss baseline
by at least 4.6 times everywhere in this range, so the decision to wait survives the
assumption being wrong in either direction.

But the benefit *shrinks* as devices sleep more, and the absolute cost grows
sharply: 0.93 false offline reports per 1000 scans at a 5% miss rate against
81.85 at 45%. Once missed replies are common enough, three consecutive misses
stop being rare, and waiting rescues a smaller share of them. A network full of
power-saving devices should therefore expect noticeably more false offline
reports than the headline figure, and is the case where raising
`offline_after_missed_scans` is worth considering. This is the opposite of a
reassuring result, and it is why the rate is reported rather than buried in a
constant.

This is a characterisation of one decision rule under one model. It does not
establish field accuracy or statistical superiority. Real scan frequency, host
sleep behaviour and ground-truth labelling must be measured before making
deployment claims, and the modelled rates are assumptions, not observations.

## Reproduce and extend

From the repository root:

```bash
cargo test --locked -p argowei-api --example presence_sweep
cargo run --locked -q -p argowei-api --example presence_sweep \
  | diff - docs/evidence/presence-sweep.json
```

The CI runs both commands. To sweep a different cadence or model, change the
constants at the top of the program and regenerate the evidence file; the tests
assert monotonicity and determinism rather than specific numbers, so they
survive a re-parameterisation.

Field data belongs in the [trace replay benchmark](PRESENCE-REPLAY.md), which
accepts recorded observations with independent ground truth. Keep synthetic and
field results separate.
