# ADR 0001: Adopt Polyglot Monorepo & 3-Plane Master Architecture

## Status
Accepted

## Context
NexusEdge requires tight coupling across low-latency network data planes, distributed cloud control planes, AI inference optimization schedulers, and customer-facing interfaces. Fragmenting these systems into 20+ separate Git repositories at this stage would create immense friction in cross-system contract changes, breaking change detection, and end-to-end integration testing.

## Decision
We organize the entire platform as a single polyglot monorepo partitioned into three operational planes:
1. **Data Plane (`dataplane/`)**: Written in Rust and C/eBPF. Optimized for line-rate packet latency and deterministic memory safety.
2. **Control Plane (`services/`)**: Written in Go. Optimized for concurrency, Raft consensus, and cloud-native API orchestration.
3. **Intelligence Plane (`intelligence/`)**: Written in Python. Optimized for mathematical multi-objective placement, PyTorch models, and capacity forecasting.

## Consequences
- Single commit atomic contract updates across proto, control plane, and data plane.
- Strict boundaries enforced via `internal/` packages, Buf linting, and Bazel/Cargo workspaces.
- Services communicate strictly via gRPC, REST, and NATS JetStream events.
