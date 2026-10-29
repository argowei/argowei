# Argowei

Argowei is a self-hosted network intelligence and device management platform
for homelabs and private infrastructure.

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

### Backend checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Collector tests use fake channels and require no network access or root.

### Database migrations

Schema changes are plain SQL files in `migrations/`, applied with
`sqlx-cli`. After adding a new migration file:

```bash
sqlx migrate add describe_the_change
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
```

## License

[MIT](LICENSE)
