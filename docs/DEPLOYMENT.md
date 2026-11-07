# Deployment

Argowei looks at your local network, so *where* it runs matters. On Docker's
default bridge network a container only sees its own virtual subnet, never
your LAN: ARP scans would find nothing. Pick the setup that fits your use.

| Use | Setup |
|---|---|
| Development and experiments | Postgres in Docker, API and CLI via `cargo run` ([1](#1-development)) |
| Always-on at home | `argowei-api` as a systemd service ([2](#2-systemd-service-recommended-for-always-on)) |
| Docker for everything | Compose with host networking ([3](#3-docker-compose-host-network)) |

For experiments, run Argowei on a Raspberry Pi or a VM with a bridged network
interface rather than on your main machine. Gateway/enforcement features
(v0.9) should be tried in dry-run mode or inside a VM first.

> The API listens on `0.0.0.0:8000` by default. All routes except health,
> login and first-run setup require authentication. These defaults are for a
> trusted lab network, not an internet-facing deployment. Restrict ports
> 8000 and 4200 with a host firewall; use a TLS reverse proxy before entering
> credentials across an untrusted network. See the [threat model](THREAT-MODEL.md).

## 1. Development

Start the database and API. The API applies pending SQL migrations on startup
and fails to start if the database or a migration is unavailable:

```bash
docker compose up -d db
cargo run -p argowei-api
```

Scanning needs raw sockets. Give the CLI binary the capability once instead of
running it with `sudo`:

```bash
cargo build -p argowei-cli
sudo setcap cap_net_raw+ep target/debug/argowei
./target/debug/argowei scan eth0
```

`setcap` applies to that file only and has to be repeated after each rebuild.

## 2. systemd service (recommended for always-on)

```bash
cargo build --release -p argowei-api
sudo install -m 0755 target/release/argowei-api /usr/local/bin/argowei-api

sudo useradd --system --home-dir /var/lib/argowei --shell /usr/sbin/nologin argowei
sudo install -d -o argowei -g argowei /var/lib/argowei
sudo install -d -m 0750 -g argowei /etc/argowei
sudo install -m 0640 -g argowei .env.example /etc/argowei/argowei.env   # then edit

sudo install -m 0644 deploy/argowei-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now argowei-api
journalctl -u argowei-api -f      # shows the first-run setup token
```

Edit `/etc/argowei/argowei.env`: set a unique `POSTGRES_PASSWORD`, and
`POSTGRES_HOST` if the database is not on this machine.
The unit grants only `CAP_NET_RAW` (ambient, so no `setcap` is needed) and
sandboxes the process. Postgres can run in Docker (`docker compose up -d db`,
bound to loopback) or natively.

The API applies pending migrations before serving requests.

## 3. Docker Compose (host network)

Set a unique PostgreSQL password in `.env` before a persistent deployment.
For a local, disposable lab setup:

```bash
cp .env.example .env
docker compose up --build
```

Compose passes the `ARGOWEI_*` discovery and hostname settings from `.env` to
the backend. Set `ARGOWEI_DISCOVERY_INTERFACES` to an interface visible on the
Linux host; discovery otherwise stays disabled. The container runs as the
unprivileged `argowei` user with `CAP_NET_RAW` on its executable and
`no-new-privileges` enabled; the capability bounding set contains only
`NET_RAW`.
Verify an actual scan on your chosen interface before relying on the inventory.
If you use a DHCP lease file, mount it read-only in the backend and set
`ARGOWEI_DHCP_LEASES_FILE` to its **container** path.

The `backend` service uses `network_mode: host` so it sees the real LAN, and
runs with all capabilities dropped except `NET_RAW`. Consequences:

- The API is on port 8000 of the host itself (there is no port mapping).
- It reaches Postgres through its loopback-published port.
- `network_mode: host` works on Linux only (not Docker Desktop on macOS/Windows).
- `db` publishes to `127.0.0.1` only.

Add `NET_ADMIN` to the backend's `cap_add` only when you enable firewall
enforcement.
