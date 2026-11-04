# Deployment

Argowei looks at your local network, so *where* it runs matters. On Docker's
default bridge network a container only sees its own virtual subnet, never
your LAN: ARP scans would find nothing. Pick the setup that fits your use.

| Use | Setup |
|---|---|
| Development and experiments | Postgres/Redis in Docker, API and CLI via `cargo run` ([1](#1-development)) |
| Always-on at home | `argowei-api` as a systemd service ([2](#2-systemd-service-recommended-for-always-on)) |
| Docker for everything | Compose with host networking ([3](#3-docker-compose-host-network)) |

For experiments, run Argowei on a Raspberry Pi or a VM with a bridged network
interface rather than on your main machine. Gateway/enforcement features
(v0.9) should be tried in dry-run mode or inside a VM first.

> The API listens on `0.0.0.0:8000`. All routes except health, login and
> first-run setup require authentication, but do not expose port 8000 to the
> internet.

## 1. Development

Install `sqlx-cli` once with
`cargo install sqlx-cli --no-default-features --features postgres,rustls`,
then start the database and API:

```bash
docker compose up -d db redis
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
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

Edit `/etc/argowei/argowei.env`: set a real `POSTGRES_PASSWORD`, and
`POSTGRES_HOST`/`REDIS_HOST` if the databases are not on this machine.
The unit grants only `CAP_NET_RAW` (ambient, so no `setcap` is needed) and
sandboxes the process. Postgres and Redis can run in Docker
(`docker compose up -d db redis`, bound to loopback) or natively.

Apply migrations before the first start and after each upgrade (see
[Database migrations](TECHNICAL-REFERENCE.md#database-migrations)).

## 3. Docker Compose (host network)

The API does not apply schema migrations automatically. With the default
credentials from `.env.example`, initialize the database before starting all
services:

```bash
cp .env.example .env
docker compose up -d db redis
cargo install sqlx-cli --no-default-features --features postgres,rustls  # once
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
docker compose up --build
```

If you change the PostgreSQL credentials in `.env`, use the matching database
URL for the migration command.

The `backend` service uses `network_mode: host` so it sees the real LAN, and
runs with all capabilities dropped except `NET_RAW`. Consequences:

- The API is on port 8000 of the host itself (there is no port mapping).
- It reaches Postgres/Redis through their loopback-published ports.
- `network_mode: host` works on Linux only (not Docker Desktop on macOS/Windows).
- `db` and `redis` publish to `127.0.0.1` only.

Add `NET_ADMIN` to the backend's `cap_add` only when you enable firewall
enforcement.
