# Build Stage
FROM rust:1.85-bullseye AS builder

WORKDIR /usr/src/nexusedge
COPY Cargo.toml Cargo.lock ./
# Create dummy main to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release || true
COPY src ./src
RUN cargo build --release

# Runtime Stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/nexusedge/target/release/nexusedge-gateway /app/nexusedge-gateway
COPY gateway.yaml /app/gateway.yaml

EXPOSE 8080

ENTRYPOINT ["/app/nexusedge-gateway"]
