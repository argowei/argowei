FROM rust:1.90-slim AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations

RUN cargo build --release --locked -p argowei-api

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd --system argowei && useradd --system --gid argowei argowei

COPY --from=builder /app/target/release/argowei-api ./argowei-api
# Only the API binary gets NET_RAW (for ARP). nmap runs unprivileged
# (`--unprivileged`, TCP connect scans): it inherits no capabilities.
RUN setcap cap_net_raw=ep ./argowei-api

USER argowei

EXPOSE 8000

CMD ["./argowei-api"]
