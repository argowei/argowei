# Threat model (early development)

This document describes the current network inventory and port scanning, not
the planned DNS, vulnerability-analysis or enforcement features. Argowei is intended for an
operator-controlled homelab or private infrastructure. It is not a network
intrusion-prevention system.

## Assets and trust boundaries

- The PostgreSQL database contains device MAC and IP addresses, discovered
  names, presence history, user labels, audit entries and session-token hashes.
  Treat it as sensitive network metadata.
- The admin password and browser session grant control over the inventory.
  The one-time setup token appears in the API log until the first admin is
  created; access to those logs is therefore privileged.
- The API reaches a selected LAN interface with `CAP_NET_RAW`. The web client
  reaches the API through the frontend web server. Both HTTP ports are exposed by
  the example Compose setup unless a host firewall restricts them.
- ARP replies, DHCP lease files and name-resolution responses cross a trust
  boundary: other devices or infrastructure can influence them. They are
  observations, not authenticated identity claims.
- Port scans are started by a signed-in user and run nmap as a child process
  of the API, without capabilities (`--unprivileged` TCP connect scans) and
  with an empty environment apart from `PATH`. Service banners and versions in
  nmap's output come from the scanned devices and are untrusted data.

## Covered controls

The API requires a server-side session for inventory, configuration and audit
routes. Session tokens are random, stored only as hashes in PostgreSQL and
sent in `HttpOnly`, `SameSite=Strict` cookies. State-changing requests with an
`Origin` header must match the request host. Setup requires a random token
read from the server log, and repeated failed logins are delayed. Database
queries use parameters. Port scans only target private and link-local
addresses (optionally narrowed by `ARGOWEI_SCAN_ALLOWED_RANGES`), checked on the
server; the client chooses a fixed profile, never nmap arguments, and nmap is
started without a shell. Scans are limited in number and run time, can be
cancelled, and starting or cancelling one is audit-logged. The container runs as a non-root user with only
`NET_RAW` in its capability bounding set; PostgreSQL publishes on loopback.
These controls reduce common web and deployment risks but do not make the
example deployment safe for arbitrary networks.

## Important limits and attacks

| Scenario | Current behavior and operator action |
| --- | --- |
| A hostile LAN device forges ARP replies or names | It can corrupt the inventory or presence inference. Verify identity through an independent signal before taking action. |
| A device sleeps, changes address or misses replies | Presence can be wrong. Failed scans are excluded from miss counts, but a completed scan with no reply is still uncertain evidence. See [Presence evaluation](PRESENCE-EVALUATION.md). |
| An attacker can observe or alter HTTP traffic | The example has no TLS and `ARGOWEI_COOKIE_SECURE=false`. Use a TLS reverse proxy and set that variable to `true` before using Argowei across an untrusted network. |
| The host exposes ports 8000 or 4200 beyond the intended LAN | The API and the static frontend become reachable. Restrict access with a host firewall or private interface; never forward these ports to the internet. |
| A reader obtains API logs before setup | The setup token can be used to create the first admin. Restrict log access and complete setup promptly. |
| A signed-in user (or a stolen session) starts port scans | Scans stay on the local network and are bounded, but they still send traffic that devices and intrusion detection can notice, and a full scan of many devices takes time. Scans are audit-logged; narrow `ARGOWEI_SCAN_ALLOWED_RANGES` if only some subnets may be scanned. |
| Scan results are taken as complete | Firewalls, rate limiting and sleeping devices hide ports; a missing open port is not proof that a service is gone. |
| A database or host is compromised | Network metadata, password hashes and session hashes can be disclosed. Restrict database access, backups and host administration. |

The Compose frontend serves a production Angular build with an unprivileged
Nginx container. There is no formal release or security support window. No
claim is made that Argowei detects every device, verifies device identity,
finds vulnerabilities or enforces a policy.

