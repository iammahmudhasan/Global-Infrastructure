# CLAUDE.md — NexusEdge Engineering & Development Operating Manual

This document provides definitive guidance for all AI assistants, engineers, and contributors operating on **NexusEdge**.

---

## ⚡ The First-Principles Development Protocol

> **"Whenever we build anything, we test it in the real world immediately. No hypothetical code. No assumptions."**

1. **Reason from Physical & Economic Truths:**
   - We do not build yesterday's Cloudflare (legacy static CDN).
   - We build the **Infrastructure-Neutral Global Fabric** answering the core question:
     *"Where should every application, AI inference request, and compute workload run right now?"*
2. **Mandatory Real-World Verification:**
   - Every single component, route, or scheduler algorithm written MUST be executed and verified immediately.
   - Run `cargo check`, `cargo test`, `go test ./...`, or execute Python placement models. Never commit unverified code.
3. **Continuous Cryptographic Git Push:**
   - Commit with descriptive commit messages and push to `origin/main` after completing tasks.

---

## 🛠️ Build, Test, & Execution Commands

### 1. Data Plane (Rust + C/eBPF)
```bash
# Check and compile root Rust workspace
cargo check
cargo build --release

# Run Edge Gateway locally (port 8080)
cd dataplane/edge/gateway
cargo run

# Run unit tests
cargo test
```

### 2. Control Plane (Go)
```bash
# Run Global Router & Workload Dispatcher (port 9090)
cd services/network/global-router
go run cmd/global-router/main.go

# Run official CLI
cd apps/cli
go run cmd/main.go status
```

### 3. Intelligence Plane (Python 3.14)
```bash
# Execute mathematical placement optimizer
python intelligence/scheduling/workload-scheduler/optimizer.py
```

### 4. Protobuf & API Governance
```bash
# Lint all proto contracts
buf lint

# Detect breaking changes against main branch
buf breaking --against ".git#branch=main"
```

---

## 🏛️ The 3-Plane Master Architecture

| Plane | Stack & Primary Language | Invariant & Operational Responsibility |
|---|---|---|
| **Data Plane** | **Rust + C/eBPF** (`dataplane/`) | Latency matters. Line-rate packet processing, zero GC pauses, memory safety. |
| **Control Plane**| **Go + gRPC** (`services/`) | Correctness matters. Raft consensus, K8s operators, NATS JetStream, Postgres 18. |
| **Intelligence** | **Python 3.14** (`intelligence/`) | Optimization matters. PyTorch, vLLM, ClickHouse telemetry, placement math. |
| **Product / UI** | **TypeScript / Next.js** (`apps/`) | Developer experience. Tailwind, shadcn/ui, real-time 3D telemetry. |

---

## 📁 The 14 Monorepo Pillars

```text
apps/         → Next.js Dashboard, Go CLI (nexusedge), Public Docs, Console
services/     → Go Control Plane domain services (Network, Compute, Storage, Billing)
dataplane/    → Rust L7 Edge Proxy, C/eBPF XDP filter, L4 LB, Wasmtime
intelligence/ → Python Workload Scheduler, GPU Capacity, Carbon optimization
proto/        → Protobuf contracts with Buf governance (proto/compute/v1/workload.proto)
schemas/      → Event & data contracts (NATS JetStream)
infra/        → Datacenter topology, regions (Dhaka, Singapore, Frankfurt, Virginia), BGP
deploy/       → Envoy proxy configs, Kubernetes manifests, Helm, Argo CD
tests/        → Integration, e2e, network emulation, security, chaos tests
benchmarks/   → Line-rate Mpps, proxy latency, DNS throughput, GPU saturation
rfcs/         → Formal architectural proposals (RFC 0001)
adr/          → Permanent architectural decision records (ADR 0001, ADR 0002)
security/     → Threat models, compliance, SBOM, cryptographic signing
docs/         → Master architecture, network runbooks, operator guides
```

---

## 🚀 10–15 Year Execution Roadmap

- **Phase 0 (0–12 Months):** Global AI & Compute Traffic Controller (Multi-cloud, Multi-GPU, Latency/Cost routing, Sovereign data residency).
- **Phase 1 (1–3 Years):** First Regional PoPs (Dhaka, Singapore, Frankfurt, Virginia, Mumbai) via WireGuard overlay.
- **Phase 2 (3–5 Years):** Own ASN, BGP Anycast, direct IXP peering (BDIX, Equinix, DE-CIX).
- **Phase 3 (5–8 Years):** Distributed Edge GPU inference, Ceph sovereign storage, Firecracker microVMs.
- **Phase 4 (8–15 Years):** Unified Global Infrastructure Fabric (Energy & grid-aware compute migration).
