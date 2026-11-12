# Technical reference

Implementation details, configuration, and development commands for Argowei. For choosing a deployment, see [Deployment](DEPLOYMENT.md).

## Local development

Follow [Deployment](DEPLOYMENT.md) to choose a setup. The API applies pending
database migrations at startup. The dashboard is available at
<http://localhost:4200> and the API at <http://localhost:8000/api>.

To run the API locally, start Postgres and then the backend:

```bash
docker compose up -d db
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

## ARP discovery

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

## Scheduled discovery

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

## Presence and analysis

A device is marked offline only after it missed `ARGOWEI_OFFLINE_AFTER_MISSED_SCANS`
(default 3) consecutive scans of the interface that last saw it **and**
`ARGOWEI_OFFLINE_AFTER_SECS` (default 900) have passed since it was last seen.
Both are required so a scanning gap (API down) cannot mark everything offline
after one miss. Failed scans are not scans and never count as misses.

A failed scan is still visible: `GET /api/discovery/status` (authenticated)
lists, per configured interface, the last attempt, last success and summary,
the last error, and the number of consecutive failures. This API snapshot
resets on restart; the attempt history is persisted in `scan_attempts`.

`is_online` is only the current view. The evidence is kept for analysis:

| Table | Content |
|---|---|
| `discovery_scans` | every completed scan: interface, method, time, hosts seen |
| `scan_attempts` | completed, failed and skipped attempts; completed rows link to `discovery_scans` |
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

Attempt journaling begins with migration `0011`; earlier completed scans have
no matching attempt row. A database outage cannot be persisted to that same
database and is reported only through logs and the transient status endpoint.
The [lab export protocol](PRESENCE-LAB.md) describes how to turn recorded
attempts into replay input with independent labels.

Re-scans only move `last_seen` forward. A device that changes IP keeps its
old address row, and when an IP moves to a different device both rows are
kept; the newest `last_seen` is the current holder. Devices that do not answer
are left unchanged (online/offline tracking is a separate feature).

## Authentication

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

## Device labels and notes

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

## Groups and trust levels

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

## Device type

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

## Alerts for new devices

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

## Device names

A device is called by its MAC address until a source names it. Four sources are
asked, each on its own and each answer is kept:

| Source | How | Typically answers |
|---|---|---|
| `dhcp` | a dnsmasq lease file (`ARGOWEI_DHCP_LEASES_FILE`), by MAC | every device that sent a hostname |
| `mdns` | a unicast PTR query to the device's port 5353 | Apple devices, Linux with Avahi, printers, TVs |
| `netbios` | a node status request to the device's port 137 | Windows and Samba hosts |
| `rdns` | a PTR query to your router's DNS server | whatever the router learned from DHCP |

When sources disagree the order is **DHCP, mDNS, NetBIOS, reverse DNS**; the
chosen name is the device's `name` and `name_source`, and `names` lists every
source's answer. A **label you set always wins** and is never touched by
discovery. The router's own domain is dropped (`iPhone.fritz.box` is `iPhone`),
and names that say nothing (`localhost`, an address spelled out) or contain
control characters are discarded. A changed name is recorded as a
`device.named` event.

Lookups are cheap by design: a device is asked once it is new, then again after
`ARGOWEI_HOSTNAME_REFRESH_SECS` (default 3600), and sooner (a sixth of that)
while it has no name. They run after the scan has been stored, in a step of
their own, on at most `ARGOWEI_HOSTNAME_CONCURRENCY` threads with a
`ARGOWEI_HOSTNAME_TIMEOUT_MS` limit per query, so a resolver that fails, times
out or crashes can never fail a discovery run. A device without mDNS refuses at
once, so it costs one round trip.

```bash
ARGOWEI_HOSTNAME_SOURCES=dhcp,mdns,netbios,rdns   # any subset; empty turns lookups off
ARGOWEI_DNS_SERVER=192.168.178.1                  # router; default: local servers in /etc/resolv.conf
ARGOWEI_DHCP_LEASES_FILE=/var/lib/misc/dnsmasq.leases
```

To see what your own devices answer, without a scan:

```bash
cargo run -p argowei-cli -- resolve 192.168.178.1 192.168.178.37 --dns-server 192.168.178.1
```

Queries only go to private, link-local or loopback addresses. A reverse lookup
reveals which addresses exist, so DNS servers taken from `resolv.conf` are used
only if they are on the local network; a public resolver is used only if you set
it explicitly. Names come from the network and any device can claim any name:
treat them as labels, not identity. IPv6 is not covered yet.

## Event timeline

What Argowei observed (devices discovered, online, offline, named) is recorded
as typed, versioned events and shown on the dashboard's **Timeline**, with
filters by device, type, severity and time. Read them with `GET /api/events`
(cursor pagination that stays complete while events are written). Types,
payload schemas and the API are described in [EVENTS.md](EVENTS.md).

## Audit log

Logins, logouts, setup and every other state-changing request are recorded in
the append-only `audit_log` table (enforced by database triggers). Read it
with `GET /api/audit-log` (filters: `actor`, `action`, `from`, `to`; cursor
pagination via `before` and `limit`).

## Backend checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Collector tests use fake channels and require no network access or root.
API integration tests need Postgres and a `DATABASE_URL` (each test creates
its own database), e.g. `DATABASE_URL=postgres://argowei:argowei@localhost:5432/argowei`
with `docker compose up db`.

## Database migrations

Schema changes are plain SQL files in `migrations/`, embedded in the API
binary and applied before it serves requests. To add a new migration file,
install `sqlx-cli` and run:

```bash
sqlx migrate add describe_the_change
```

Cargo rebuilds the API when `migrations/` changes. For manual inspection or repair, run
`sqlx migrate info` or `sqlx migrate run` against the intended database.

