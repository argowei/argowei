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

Copy `.env.example` to `.env` first to set the Postgres/Redis credentials used
by Compose (sensible defaults are provided).

To run the services locally instead, start Postgres and Redis (e.g. via
`docker compose up db redis`), then the backend:

```bash
cd backend
cargo install sqlx-cli --no-default-features --features postgres,rustls  # one-time setup
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
cargo run
```

Then start the frontend in a separate terminal:

```bash
cd frontend
npm install
npm start
```

### Database migrations

Schema changes are plain SQL files in `backend/migrations/`, applied with
`sqlx-cli`. After adding a new migration file:

```bash
cd backend
sqlx migrate add describe_the_change
sqlx migrate run --database-url postgres://argowei:argowei@localhost:5432/argowei
```

## License

[MIT](LICENSE)
