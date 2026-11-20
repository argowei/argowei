# Architecture

Argowei is four Rust crates, a PostgreSQL database and an Angular dashboard. The
split follows one rule: **measuring the network, deciding what a measurement
means, and storing the result are separate layers**, and only the innermost one
touches the network while only the outermost one touches the database.

```
                     ┌───────────────┐
   LAN ──ARP/nmap──▶ │   collector   │  measures, returns values
                     └───────┬───────┘
                             │ (no database access)
   ┌─────────┐       ┌───────▼───────┐       ┌────────────┐
   │   cli   │──────▶│     core      │◀──────│    api     │
   └─────────┘       │ models, rules │       │ HTTP, auth │
                     └───────────────┘       └─────┬──────┘
                                                   │ sqlx
                                            ┌──────▼──────┐     ┌───────────┐
                                            │ PostgreSQL  │     │  Angular  │
                                            └─────────────┘◀────│ dashboard │
                                                      /api      └───────────┘
```

## Crates

| Crate | Depends on | Responsibility |
|---|---|---|
| `argowei-core` | nothing in-tree | Domain models and pure rules: devices, names, device types, events, the IEEE OUI registry, scan profiles, targets, schedules and scan diffing. |
| `argowei-collector` | `core`, `pnet` | Measurement only: sends ARP requests, resolves names (DHCP, mDNS, NetBIOS, rDNS) and runs nmap port scans. Returns values; stores nothing. |
| `argowei-api` | `core`, `collector`, `axum`, `sqlx` | The only crate that reads or writes the database. Serves the authenticated HTTP API, schedules discovery and scans, and persists devices, scans, presence and events. |
| `argowei-cli` | `core`, `collector`, `clap` | Interface discovery and manual scans from a terminal, without a database. |

`core` has no in-tree dependencies, so a rule can be unit-tested without a
socket or a database. `collector` holds no state: a scan is a function from a
target to observations, which is what makes the presence work
([evaluation](PRESENCE-EVALUATION.md), [sweep](PRESENCE-SWEEP.md),
[replay](PRESENCE-REPLAY.md)) reproducible without hardware.

## Why the collector cannot write

Discovery runs with raw-socket permission. Keeping persistence out of that crate
means the privileged code path has no reason to reach the database, and a bug in
packet handling cannot corrupt the inventory. The API is the single writer, so
every stored fact passes through one place that can validate it, record an event
and write the audit log.

This is also the separation the project's planned enforcement work depends on:
deciding that a device should be blocked and actually blocking it must stay
different steps, each separately auditable.

## Data flow

1. The API's scheduler decides a scan is due (`discovery`, `scans`) and asks the
   collector to run it against configured interfaces or targets.
2. The collector performs the measurement and returns observations. A scan that
   fails is reported as failed rather than as an empty result, because the two
   mean different things to presence.
3. The API persists the observations, derives presence
   ([`presence.rs`](../crates/argowei-api/src/presence.rs)), diffs the scan
   against the previous one, and records typed events ([events](EVENTS.md)).
4. The dashboard polls `/api/...` and renders the inventory, alerts, timeline
   and schedules. All filtering and sorting of the device list happens in the
   browser over the polled snapshot.

A completed scan with no reply is evidence; a failed scan is not. That
distinction is carried end to end, and it is why presence requires both a miss
count and elapsed time before reporting a device offline.

## State and migrations

PostgreSQL holds the inventory, scan and event history. Migrations live in
[`migrations/`](../migrations) and the API applies pending ones at startup, so a
deployment never needs a separate migration step. Schema changes are additive
migrations; see the [technical reference](TECHNICAL-REFERENCE.md#database-migrations).

## Frontend

The Angular dashboard is a standalone-component application under
[`frontend/src/app`](../frontend/src/app):

- `core/` — typed API clients, models, auth interceptor and polling helper.
- `features/` — one folder per page: devices, alerts, events, schedules, login,
  setup.
- `shared/` — small presentational pieces reused across pages.

Components are small and own their template and styles inline. Global design
tokens and shared classes live in [`src/styles.css`](../frontend/src/styles.css);
a component only adds styles for its own layout.

## What this architecture does not give you

The collector observes the interfaces you configure, and a normal LAN host
cannot see traffic between other devices. ARP replies and hostnames are
unauthenticated, so the inventory records what the network claimed, not proven
identity. See the [threat model](THREAT-MODEL.md) for what that means for the
conclusions you can draw from the data.
