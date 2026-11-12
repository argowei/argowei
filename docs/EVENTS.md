# Events

Events are timestamped facts about the network: a device appeared, went
offline, got a name. They are stored in the `events` table and shown on the
dashboard's **Timeline**. Unlike the audit log, which records what *users* did,
events record what Argowei *observed*.

The types and payloads below are defined in code
(`crates/argowei-core/src/events.rs`), so a payload can only be recorded with
the type it belongs to. This page is the reference for anyone reading the API
or the table directly.

## Versioning

Every event stores the `schema_version` of its type's payload. Adding an
optional field keeps the version. Renaming or removing a field, or changing
what a field means, bumps it, and older events keep their old version and
shape. Check `(type, schema_version)` before interpreting a payload.

## Types

| Type | Version | Severity | When |
|---|---|---|---|
| `device.discovered` | 1 | info | A MAC address is seen for the first time. |
| `device.online` | 1 | info | A device answers again after being marked offline. |
| `device.offline` | 1 | info | A device missed enough scans, for long enough (see presence). |
| `device.named` | 1 | info | The name shown for a device changed. |

### `device.discovered` (v1)

| Field | Type | Meaning |
|---|---|---|
| `interface` | string | Interface the scan ran on. |
| `scan_id` | integer | The ARP scan (`discovery_scans.id`) that saw the device. |
| `ip` | string | IPv4 address it answered from. |
| `baseline` | boolean | Learned silently during the interface's baseline (no alert). |

### `device.online` (v1)

| Field | Type | Meaning |
|---|---|---|
| `interface` | string | Interface the scan ran on. |
| `scan_id` | integer | The ARP scan that saw it again. |
| `ip` | string | IPv4 address it answered from. |
| `last_seen_before` | RFC 3339 timestamp | When it was last seen before going offline. |

### `device.offline` (v1)

| Field | Type | Meaning |
|---|---|---|
| `interface` | string | Interface the device was last seen on. |
| `last_seen` | RFC 3339 timestamp | Its last sighting. |
| `missed_scans` | integer | Scans of that interface that ran since `last_seen`. |
| `silent_for_secs` | integer | Seconds between `last_seen` and the decision. |
| `policy.offline_after_missed_scans` | integer | Policy in force: scans to miss. |
| `policy.offline_after_secs` | integer | Policy in force: minimum silence in seconds. |

### `device.named` (v1)

| Field | Type | Meaning |
|---|---|---|
| `from` | string | The previous name (the MAC address before any source named it). |
| `to` | string | The new name. |
| `source` | `dhcp` \| `mdns` \| `netbios` \| `rdns` | Where the new name comes from. |
| `answers` | array of `{source, name}` | Every source's current answer. |

## Reading the timeline

```bash
curl 'http://localhost:8000/api/events?limit=50' -b cookies.txt
curl 'http://localhost:8000/api/events?device=7&type=device.offline' -b cookies.txt
curl 'http://localhost:8000/api/events?from=2026-01-01T00:00:00Z&severity=warning' -b cookies.txt
curl  http://localhost:8000/api/events/types -b cookies.txt
```

Filters: `device` (id), `type`, `severity`, `from` and `to` (RFC 3339,
inclusive, on `occurred_at`), `limit` (1-200, default 50). The response is
`{ items, next_before, truncated }`, newest first. Every item has an opaque
`cursor`:

- **Older events:** pass `next_before` as `before`.
- **Newer events** (polling): pass the newest item's `cursor` as `after`. If
  `truncated` is true, more new events exist than `limit`; reload from the top
  instead of prepending.

Paging is stable while events are being written: an event can never appear
behind a cursor a client already holds. Rows are ordered by the transaction
that wrote them, and an event only becomes visible once every transaction that
started before it has ended. In practice events show up a few milliseconds
after they are committed.
