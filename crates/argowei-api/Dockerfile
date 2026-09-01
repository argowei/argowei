FROM rust:1.90-slim AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked -p argowei-api

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd --system argowei && useradd --system --gid argowei argowei

COPY --from=builder /app/target/release/argowei-api ./argowei-api
COPY migrations ./migrations

USER argowei

EXPOSE 8000

CMD ["./argowei-api"]
