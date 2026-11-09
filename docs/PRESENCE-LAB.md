# Presence lab protocol

This protocol converts persisted scan attempts into the existing
[presence replay](PRESENCE-REPLAY.md) format. It does not itself create
independent ground truth or establish field accuracy.

## Before recording

1. Define the reference state in writing. A useful first experiment defines
   `online` as a controlled device being connected to the test LAN, regardless
   of whether it answers ARP. Record sleep and power state separately.
2. Use a separate reference source, such as controlled link changes plus
   device or switch logs. Never derive labels from Argowei's ARP sightings.
3. Synchronize clocks and record maximum clock error. Label uncertain periods
   `unknown`, including transitions whose exact time cannot be established.
4. Fix the scan interval, policy parameters, device classes, and exclusion
   rules before comparing methods. Use separate devices or periods for any
   parameter tuning and final evaluation. Enter the policy parameters actually
   configured during collection in the study file; the exporter verifies them
   against the values stored with every completed scan. Use a separate study
   and export if they change.
5. Choose a window entirely after migration `0012`. Earlier scans have no
   recorded policy snapshot and cannot pass this provenance check. Failed scans
   are retained. Skipped scheduler ticks are recorded but omitted from replay
   because no scan ran. Database outages cannot be captured in the database;
   document them as exclusions or explicitly uncertain windows. Export after
   the run has stopped, before deleting inventory records. Completed scan
   timestamps mark when results were stored, not when the ARP probe began.

## Export

Write a local `study.json` with the following shape. Times are UTC ISO 8601
timestamps. The `end` boundary is exclusive. The MAC is used only for the
local database lookup and is omitted from the generated replay file.

```json
{
  "schema_version": 1,
  "dataset": {
    "id": "lab-2026-11-08-v1",
    "kind": "lab",
    "description": "Controlled LAN experiment; document device classes and scan interval separately.",
    "ground_truth_source": "Switch link log and device serial log, aligned to UTC"
  },
  "policy": { "offline_after_missed_scans": 3, "offline_after_secs": 900 },
  "traces": [{
    "device_id": "device-01",
    "mac_address": "aa:bb:cc:00:00:01",
    "interface": "eth0",
    "start": "2026-11-08T12:00:00Z",
    "end": "2026-11-08T13:00:00Z",
    "ground_truth": [
      { "at": "2026-11-08T12:00:00Z", "state": "online" },
      { "at": "2026-11-08T12:30:00Z", "state": "offline" }
    ]
  }]
}
```

The example addresses and labels above are illustrative, not a measured
dataset. Use a private study file for real MAC addresses and sensitive network
metadata. The exporter rejects missing labels, empty observation windows,
duplicate pseudonyms, unjournaled or inconsistently linked completed scans,
and events that collapse to the same millisecond. It reads inventory, attempts,
and sightings from one read-only database snapshot, so concurrent scans cannot
produce a mixed export. A database outage that left no record still requires an
operator-documented exclusion or `unknown` label. A policy mismatch or missing
policy snapshot also stops the export; editing the study file cannot
retroactively establish which thresholds were used.

```sh
DATABASE_URL=postgres://... cargo run --locked -q -p argowei-api \
  --example presence_export -- study.json > presence-lab.json
cargo run --locked -q -p argowei-api --example presence_replay -- \
  presence-lab.json > presence-lab-report.json
```

Keep the original logs, study file, exported input, report, collector commit,
scan configuration and clock-alignment notes together. Publish only after
reviewing identifiers and network details. Report false-offline and
false-online duration, all departure outcomes, and detected-only latency
quantiles together. A single homelab dataset supports claims about that
setup, not a general device population.
