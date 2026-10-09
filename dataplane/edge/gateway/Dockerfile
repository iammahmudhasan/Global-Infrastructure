# Build Stage
FROM rust:1.85-bullseye AS builder

WORKDIR /usr/src/nexusedge

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
# Create dummy lib and main to cache dependencies
RUN mkdir src && echo "pub fn dummy() {}" > src/lib.rs && echo "fn main() {}" > src/main.rs && cargo build --release
RUN rm -rf src target/release/deps/nexusedge* target/release/.fingerprint/nexusedge* target/release/nexusedge*

COPY src ./src
RUN cargo build --release

# Runtime Stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl1.1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/nexusedge/target/release/nexusedge-gateway /app/nexusedge-gateway
COPY gateway.yaml /app/gateway.yaml

EXPOSE 8080

ENTRYPOINT ["/app/nexusedge-gateway"]
