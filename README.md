# Argowei

Argowei is a self-hosted network intelligence and device management platform
for homelabs and private infrastructure.

## Research and evidence

The [presence evaluation](docs/PRESENCE-EVALUATION.md) runs the production
decision rule on deterministic traces and compares it with three simpler
rules. It records both avoided false offline states and the remaining sleep
failure case, with [machine-readable results](docs/evidence/presence-evaluation.json)
checked in CI. This is a synthetic experiment; field accuracy remains open.

## Development

Start the application with Docker Compose:

```bash
docker compose up --build
```

The dashboard is available at <http://localhost:4200> and the API at
<http://localhost:8000/api>.

The backend runs on the host network so it can see your real LAN; see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the three supported setups
(development, systemd service, Docker Compose) and why.

Copy `.env.example` to `.env` first to set the Postgres/Redis credentials used
by Compose (sensible defaults are provided).

To run the services locally instead, start Postgres and Redis (e.g. via
`docker compose up db redis`), then the backend:

```bash
cargo install sqlx-cli --no-default-features --features postgres,rustls  # one-time setup
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
cargo run -p argowei-api
```

Then start the frontend in a separate terminal:

```bash
cd frontend
npm install
npm start
```

The dashboard lists devices at `/devices` (search, filter by status, trust and
group, sortable columns, refreshed every 10 seconds) and shows a device's
profile at `/devices/<id>`, where label, notes, group and trust level can be
edited. Frontend tests run with Vitest:

```bash
cd frontend
npm test -- --watch=false
```

Run the CLI:

```bash
cargo run -p argowei-cli -- about
cargo run -p argowei-cli -- interfaces
```

## Repository Layout

```text
crates/
  argowei-api/    Axum API used by the web application
  argowei-cli/    command-line interface
  argowei-collector/ bounded local-network discovery
  argowei-core/   shared domain types and pure logic
frontend/         Angular dashboard
migrations/       database schema migrations
```

### ARP discovery

```bash
cargo run -p argowei-cli -- interfaces
cargo build -p argowei-cli
sudo ./target/debug/argowei scan eth0
```

Requires root or `CAP_NET_RAW` on Linux. Scans the interface's first IPv4
network, limited to /22 through /32. Requests are paced at up to 100 per
second, followed by a three-second response window. Transport errors fail
the scan. Results currently go to the terminal only.

ARP replies are unauthenticated; a missing reply does not prove a device is
offline.

### Scheduled discovery

The API can scan interfaces on an interval and store the results in
`devices` / `device_addresses`. It is off until interfaces are configured:

```bash
ARGOWEI_DISCOVERY_INTERFACES=eth0,wlan0   # comma-separated; empty = disabled
ARGOWEI_DISCOVERY_INTERVAL_SECS=300       # 30-86400
ARGOWEI_DISCOVERY_TIMEOUT_SECS=3          # response window, 1-60
```

The API process needs raw-socket rights (`CAP_NET_RAW`, e.g.
`sudo setcap cap_net_raw+ep target/debug/argowei-api` for local development;
in Docker the backend needs host networking plus `cap_add: [NET_RAW]`). Without
them each scan logs an error naming the missing capability and is retried at
the next interval; the API keeps running.

### Presence and analysis

A device is marked offline only after it missed `ARGOWEI_OFFLINE_AFTER_MISSED_SCANS`
(default 3) consecutive scans of the interface that last saw it **and**
`ARGOWEI_OFFLINE_AFTER_SECS` (default 900) have passed since it was last seen.
Both are required so a scanning gap (API down) cannot mark everything offline
after one miss. Failed scans are not scans and never count as misses.

A failed scan is still visible: `GET /api/discovery/status` (authenticated)
lists, per configured interface, the last attempt, last success and summary,
the last error, and the number of consecutive failures. This status lives in
memory only: nothing is written to the database and it resets on restart.

`is_online` is only the current view. The evidence is kept for analysis:

| Table | Content |
|---|---|
| `discovery_scans` | every completed scan: interface, method, time, hosts seen |
| `device_sightings` | which device answered in which scan, from which IP |
| `events` | `device.discovered`, `device.online`, `device.offline` with the evidence in `payload` (missed scans, silence, policy) |

A device that did not answer is the absence of a sighting for a scan that ran.
Examples:

```sql
-- Share of scans in the last 7 days in which each device answered.
SELECT d.mac_address,
       round(100.0 * count(sg.scan_id) / NULLIF(max(t.total), 0), 1) AS answered_pct
FROM devices d
CROSS JOIN (SELECT count(*) AS total FROM discovery_scans
            WHERE interface = 'eth0' AND scanned_at > now() - interval '7 days') t
LEFT JOIN device_sightings sg ON sg.device_id = d.id
     AND sg.scan_id IN (SELECT id FROM discovery_scans
                        WHERE interface = 'eth0' AND scanned_at > now() - interval '7 days')
WHERE d.last_seen_interface = 'eth0'
GROUP BY d.mac_address ORDER BY answered_pct;

-- Online/offline transitions per device, oldest first.
SELECT d.mac_address, e.occurred_at, e.type, e.payload
FROM events e JOIN devices d ON d.id = e.device_id
WHERE e.type LIKE 'device.%' ORDER BY d.mac_address, e.occurred_at;
```

`device.discovered` is the first online period's start. Devices recorded
before presence tracking existed are not marked offline until seen again.
No new probes are sent for any of this: presence is derived from the scans
already running.

Re-scans only move `last_seen` forward. A device that changes IP keeps its
old address row, and when an IP moves to a different device both rows are
kept; the newest `last_seen` is the current holder. Devices that do not answer
are left unchanged (online/offline tracking is a separate feature).

### Authentication

All `/api` routes except `/api`, `/api/health`, `/api/auth/status`,
`/api/auth/setup` and `/api/auth/login` require a session cookie.

On first start, with no admin account, the API logs a one-time setup token:

```text
WARN no admin account yet; first-run setup token: <token>
```

Create the admin once with it (password: 12-128 bytes):

```bash
curl -X POST http://localhost:8000/api/auth/setup \
  -H 'Content-Type: application/json' \
  -d '{"setup_token":"<token>","username":"admin","password":"<password>"}'
```

Sessions last `ARGOWEI_SESSION_TTL_HOURS` (default 24). Set
`ARGOWEI_COOKIE_SECURE=true` when serving over HTTPS. Repeated failed logins
are delayed with exponential backoff (capped at 5 minutes).

The dashboard redirects to `/setup` on a fresh install (paste the token from
the server log) and to `/login` otherwise. An expired session sends you back
to the login page and returns you to where you were afterwards.

### Device labels and notes

`PATCH /api/devices/{id}` sets a user label and free-text notes:

```bash
curl -X PATCH http://localhost:8000/api/devices/1 -b cookies.txt \
  -H 'Content-Type: application/json' \
  -d '{"label":"Wohnzimmer TV","notes":"Samsung, hinter dem Schrank"}'
```

Labels are trimmed, single-line and at most 64 characters; notes are trimmed
and at most 2000 characters. A missing field is left unchanged; `null` or a
blank value clears it. `name` keeps what discovery derived and is never
changed by a user; `display_name` is the label if set, otherwise `name`.
Discovery never overwrites a label or notes. Changes are audit-logged with the
before/after values.

### Groups and trust levels

Devices can be classified, nothing is enforced yet (that is the policy
engine's job). Eight system groups are seeded: Unassigned, Trusted, Servers,
Guest, IoT, Kids, Quarantine and Blocked. Each stores its default behavior as data in
`defaults` (for example `{"internet": "allow", "lan": "block"}`) for the
policy engine to consume later. System groups cannot be renamed or deleted,
but their description and defaults can be tuned; custom groups can be
created, renamed and deleted (a group that still has devices cannot be
deleted).

```bash
curl http://localhost:8000/api/groups -b cookies.txt
curl -X POST http://localhost:8000/api/groups -b cookies.txt \
  -H 'Content-Type: application/json' -d '{"name":"Labor","defaults":{"internet":"allow"}}'
curl -X PATCH http://localhost:8000/api/devices/1 -b cookies.txt \
  -H 'Content-Type: application/json' -d '{"group_id":4,"trust_level":"restricted"}'
```

Every device is in exactly one group; new devices start in **Unassigned** (a
device can be moved back there by its id, `group_id: null` is rejected). It
also has one trust level: `trusted`, `normal`, `restricted`, `unknown`
(default for new devices) or `suspicious`. Discovery never changes either.
Changes are audit-logged, group changes with the group names.

### Device type

Each device gets a type (`smartphone`, `laptop`, `server`, `iot`, `printer`,
`router` or `unknown`) inferred by a rule-based classifier in
`argowei-core::device_type`. It is a pure function: the same signals always give
the same answer, and it returns every rule that fired with its weight, so the
dashboard can show *why* a device was called a printer. Signals are the
manufacturer (from the MAC), a private MAC address, the hostname, open ports and
mDNS service types. Evidence for one type combines like independent witnesses
(`1 - Π(1 - w)`), never reaches certainty (capped at 95 %) and is ignored below
30 %, which yields `unknown`. A signal kind counts once per type.

Today only the manufacturer and the MAC kind are known; hostnames, open ports
and mDNS feed in as those sources arrive. Devices recorded earlier start as
`unknown` and are classified the next time a scan sees them.

The inference and the user's decision are stored separately, so re-classifying
on every scan never overwrites a manual choice:

```bash
# set a manual type; null goes back to the automatic guess
curl -X PATCH http://localhost:8000/api/devices/1 -b cookies.txt \
  -H 'Content-Type: application/json' -d '{"type_override":"printer"}'
```

`GET /api/devices` returns `device_type` (the type to show), `type_source`
(`manual` or `inferred`), `type_override` and `inferred` (`device_type`,
`confidence`, `evidence`). The classifier is a heuristic; MAC addresses and
hostnames can be wrong or spoofed.

### Alerts for new devices

When a device appears that Argowei has never seen, it raises exactly one alert
(`device.new`, severity `warning`); the database enforces the "exactly one".
Alerts have a life cycle, `open` → `acknowledged` → `resolved` (an open alert
can also be resolved directly), and every step is audit-logged.

A fresh install would otherwise alert for every device already on the network,
so each interface has a **baseline**: devices found in its first scan are
learned silently, and so are devices found within the next
`ARGOWEI_BASELINE_WINDOW_SECS` (default `0`, meaning only the first scan; e.g.
`86400` keeps learning for a day so devices that were asleep during the first
scan do not alert). A newly added interface gets its own baseline. The
dashboard shows a banner while the baseline is pending or still learning, and a
badge with the open alerts in the navigation.

```bash
curl 'http://localhost:8000/api/alerts?status=active' -b cookies.txt   # active (default) | open | acknowledged | resolved | all
curl http://localhost:8000/api/alerts/status -b cookies.txt            # counts + baseline state
curl -X POST http://localhost:8000/api/alerts/1/acknowledge -b cookies.txt
curl -X POST http://localhost:8000/api/alerts/1/resolve -b cookies.txt
```

Each alert carries `suggested_actions`. *Trust* and *Restrict* only classify
the device (trust level) and then resolve the alert. *Block* and *Quarantine*
are listed but disabled until enforcement (gateway or router integration)
exists. Alerts are not pushed over a WebSocket yet; the dashboard polls every
15 seconds.

### Audit log

Logins, logouts, setup and every other state-changing request are recorded in
the append-only `audit_log` table (enforced by database triggers). Read it
with `GET /api/audit-log` (filters: `actor`, `action`, `from`, `to`; cursor
pagination via `before` and `limit`).

### Backend checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Collector tests use fake channels and require no network access or root.
API integration tests need Postgres and a `DATABASE_URL` (each test creates
its own database), e.g. `DATABASE_URL=postgres://argowei:argowei@localhost:5432/argowei`
with `docker compose up db`.

### Database migrations

Schema changes are plain SQL files in `migrations/`, applied with
`sqlx-cli`. After adding a new migration file:

```bash
sqlx migrate add describe_the_change
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
```

## License

[MIT](LICENSE)
