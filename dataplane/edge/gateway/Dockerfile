# Build Stage
ARG RUST_IMAGE=public.ecr.aws/docker/library/rust:1-bookworm
ARG RUNTIME_IMAGE=public.ecr.aws/docker/library/debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder

WORKDIR /usr/src/nexusedge

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
# Create dummy lib and main to cache dependencies
RUN mkdir src && echo "pub fn dummy() {}" > src/lib.rs && echo "fn main() {}" > src/main.rs && cargo build --release
RUN rm -rf src target/release/deps/nexusedge* target/release/.fingerprint/nexusedge* target/release/nexusedge*

COPY src ./src
RUN cargo build --release

# Runtime Stage
FROM ${RUNTIME_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 nexusedge && \
    useradd -u 10001 -g nexusedge -m -s /bin/bash nexusedge

WORKDIR /app
COPY --from=builder /usr/src/nexusedge/target/release/nexusedge-gateway /app/nexusedge-gateway
COPY gateway.yaml /app/gateway.yaml

RUN chown -R 10001:10001 /app

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/app/nexusedge-gateway"]
