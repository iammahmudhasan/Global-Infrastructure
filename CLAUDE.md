# CLAUDE.md — NexusEdge Engineering & Development Operating Manual

This document provides definitive guidance for all AI assistants, engineers, and contributors operating on **NexusEdge**.

> **Constitutional Rulebook:** [docs/AI_ENGINEERING_RULES.md](docs/AI_ENGINEERING_RULES.md) (126 Mandatory Platform Rules)  
> **Workspace Rule:** [.agents/rules/ai-engineering-rules.md](.agents/rules/ai-engineering-rules.md)  
> **Platform Mission:** Build the world's most intelligent global infrastructure network for applications and AI.  
> **Priority Hierarchy (Rule 1):**  
> $$\mathbf{Correctness} > \mathbf{Security} > \mathbf{Reliability} > \mathbf{Maintainability} > \mathbf{Performance} > \mathbf{Speed}$$

---

## ⚡ 1. The First-Principles Development Protocol

> **"Whenever we build anything, we test it in the real world immediately. No hypothetical code. No assumptions."**

1. **Reason from Physical & Economic Truths (Rule 2):**
   - We do not build yesterday's Cloudflare (legacy static CDN).
   - We build the **Infrastructure-Neutral Global Fabric** answering the core question:
     *"Where should every application, AI inference request, and compute workload run right now?"*
2. **Mandatory Real-World Verification (Rules 2, 81):**
   - Every single component, route, or scheduler algorithm written MUST be executed and verified immediately in the shell.
   - Run `cargo check`, `cargo test`, `go test ./...`, or execute Python placement models. Never commit unverified code.
3. **Continuous Cryptographic Git Push (Rules 3, 96):**
   - Commit with descriptive commit messages and push to `origin/main` after completing tasks.
4. **Visual Architecture Graph Anchor Mandate (Rule 124):**
   - Before writing or deleting code for any milestone or subsystem, construct a complete Mermaid architecture/relationship graph. Visually anchor component boundaries, line-rate data plane paths, control plane state loops, and failure transitions.
5. **The 4-Question Code Justification Mandate (Rule 125):**
   - Before adding or removing ANY code, explicitly answer:
     1. **WHERE:** Exact file path, package, and plane.
     2. **WHY:** Technical and business requirement driving the change.
     3. **IMPACT:** Operational behavior and state transitions when written.
     4. **RISK OF OMISSION:** What breaks, what fails, or what security/reliability hole opens up if omitted.
6. **Cleanliness & Industrial Discipline Mandate (Rule 126):**
   - Zero unused code (no dead functions, unused structs, orphaned files, or dangling imports).
   - Zero zombie comments (no commented-out dead code).
   - No gratuitous emoji clutter in production code, comments, or error messages. Clean, industrial-grade engineering only.

---

## 🛠️ 2. Build, Test, & Execution Commands

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

### 3. Intelligence Plane (Python 3.12+)
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

## 🏛️ 3. The 3-Plane Master Architecture

| Plane | Stack & Primary Language | Invariant & Operational Responsibility |
|---|---|---|
| **Data Plane** | **Rust + C/eBPF** (`dataplane/`) | Latency matters. Line-rate packet processing, zero GC pauses, memory safety. Never calls control plane for ordinary forwarding (Rule 5). |
| **Control Plane**| **Go + gRPC** (`services/`) | Correctness matters. Raft consensus, K8s operators, NATS JetStream, Postgres 18. Domain owns its data (Rule 8). |
| **Intelligence** | **Python 3.12+** (`intelligence/`) | Optimization matters. PyTorch, vLLM, ClickHouse telemetry, placement math. Bounded by deterministic fallbacks (Rules 28–30). |
| **Product / UI** | **TypeScript / Next.js** (`apps/`) | Developer experience. Tailwind, shadcn/ui, real-time 3D telemetry. |

---

## 📁 4. The 14 Monorepo Pillars & Domain Invariants (Rules 4–8)

```text
apps/         → Next.js Dashboard, Go CLI (nexusedge), Public Docs, Console. No core daemons.
services/     → Go Control Plane domain services (Network, Compute, Storage, Billing).
dataplane/    → Rust L7 Edge Proxy, C/eBPF XDP filter, L4 LB, Wasmtime. Line-rate execution.
intelligence/ → Python Workload Scheduler, GPU Capacity, Carbon optimization.
proto/        → Protobuf contracts with Buf governance (proto/compute/v1/workload.proto).
schemas/      → Event & data contracts (NATS JetStream Avro/JSON schemas).
infra/        → Datacenter topology, regions (Dhaka, Singapore, Frankfurt, Virginia), BGP.
deploy/       → Envoy proxy configs, Kubernetes manifests, Helm, Argo CD.
tests/        → Integration, e2e, network emulation, security, chaos tests.
benchmarks/   → Line-rate Mpps, proxy latency, DNS throughput, GPU saturation.
rfcs/         → Formal architectural proposals (RFC 0001).
adr/          → Permanent architectural decision records (ADR 0001, ADR 0002).
security/     → Threat models, compliance, SBOM, cryptographic signing.
docs/         → Master architecture, network runbooks, operator guides.
```

### Invariant Rules:
1. **No God Services (Rule 59):** Do not create `services/core` or `libs/utils`.
2. **Private Service Isolation (Rule 7):** Do not import another service's `internal/` packages.
3. **Database Ownership (Rule 8):** Services communicate via gRPC/events, never cross-domain SQL queries.
4. **Adopt Commodity, Build Moat (Rules 33, 34):** Leverage Linux, Postgres, K8s, Envoy, PowerDNS, Ceph; engineer our 5 proprietary engines.

---

## ⚙️ 5. Practical Guidelines from the 123 Rules

- **Understand First (Rule 2):** Read the nearest `README.md`, relevant RFCs/ADRs, and contracts before changing code.
- **API Contracts Are Sacred (Rule 9):** `proto/` and `schemas/` changes must be additive and versioned (`v1`, `v2`).
- **Resilience by Default (Rules 14–16):** Plan for server, fiber, and regional partitions. Make all mutating APIs idempotent with idempotency keys.
- **Zero Secrets (Rules 18–19):** Never hardcode secrets. Redact tokens and headers in all logs.
- **Untrusted Input (Rule 23):** Validate lengths, ranges, headers, and protobuf messages. Fail closed (Rule 88).
- **Safe Concurrency (Rules 39–41):** Tasks must have clear lifecycles, timeouts, and cancellation paths. Graceful shutdown on `SIGTERM`.
- **Tenant Isolation (Rules 54–55):** Verify identity, organization, and permissions on every resource access. Never trust raw entity IDs.
- **Truthful Telemetry (Rules 81–84):** No fabricated metrics. Provide actual shell execution output or explicitly label theoretical estimates.

---

## 🛡️ 6. Rule 122: Absolute Non-Negotiables

### NEVER:
* Commit secrets into source code or test fixtures.
* Invent test results or fabricate benchmark metrics.
* Disable security (TLS, auth, isolation) to make tests pass.
* Cross service private boundaries (`services/<A>/internal` -> `<B>`).
* Put packet-path logic behind unnecessary control-plane calls.
* Make AI the sole authority for critical infrastructure decisions without deterministic fallback.
* Hide errors or return fake success responses.
* Claim completion without actual shell validation.
* Rewrite mature infrastructure without a strong reason.
* Write or delete code without answering Where, Why, Impact, and Risk of Omission.
* Leave unused functions, orphaned files, or commented-out zombie code in the repository.
* Clutter source code or logs with excessive emojis.
* Write code without first constructing a complete architectural graph.

### ALWAYS:
* Follow the 14-pillar directory structure.
* Construct a complete visual architecture graph (Mermaid) before writing code.
* Explicitly define Where, Why, What happens, and What breaks before adding or removing code.
* Validate all external input.
* Use least privilege.
* Expose OpenTelemetry metrics, structured logs, and distributed traces.
* Treat public and internal APIs as compatibility contracts.
* Plan for failure modes (partitions, node crashes, hardware degradation).
* Keep infrastructure state reconciled via declarative controllers.
* Measure performance via actual benchmarks rather than guessing.
* Ensure 100% dead-code elimination, zero orphaned files, and clean industrial code.

---

## 📋 7. Rule 121: Final Completion Checklist

```text
[ ] Architectural graph anchored before coding?
[ ] 4-Question justification answered (Where, Why, Impact, Risk)?
[ ] Correct domain?
[ ] Correct architectural boundary?
[ ] Existing code inspected?
[ ] Existing behavior preserved?
[ ] API contracts preserved?
[ ] Database ownership preserved?
[ ] Security reviewed?
[ ] Tenant isolation reviewed?
[ ] Failure modes considered?
[ ] Timeouts considered?
[ ] Retries safe?
[ ] Idempotency considered?
[ ] Observability added?
[ ] Tests added/updated?
[ ] Performance measured when relevant?
[ ] Zero unused code or orphaned files remaining?
[ ] Zero commented-out zombie code?
[ ] Clean industrial code without emoji clutter?
[ ] No secrets added?
[ ] No unnecessary dependencies?
[ ] No unrelated refactor?
[ ] Documentation updated?
[ ] Migration considered?
[ ] Rollback considered?
[ ] Actual validation performed?
[ ] No fabricated test/benchmark claims?
```

---

## 🚀 8. 10–15 Year Execution Roadmap

- **Phase 0 (0–12 Months):** Global AI & Compute Traffic Controller (Multi-cloud, Multi-GPU, Latency/Cost routing, Sovereign data residency).
- **Phase 1 (1–3 Years):** First Regional PoPs (Dhaka, Singapore, Frankfurt, Virginia, Mumbai) via WireGuard overlay.
- **Phase 2 (3–5 Years):** Own ASN, BGP Anycast, direct IXP peering (BDIX, Equinix, DE-CIX).
- **Phase 3 (5–8 Years):** Distributed Edge GPU inference, Ceph sovereign storage, Firecracker microVMs.
- **Phase 4 (8–15 Years):** Unified Global Infrastructure Fabric (Energy & grid-aware compute migration).

---

## 🇧🇩 9. Strategic Geo-Anchor (Bangladesh Advantage)

- **BDIX Peering:** 167 members, 2.27 Tbps cumulative port capacity.
- **SMW6 Submarine Cable:** 30,000 Gbps planned capacity (Cox's Bazar to Singapore/Mumbai/France).
- **National Data Management Act 2026:** Mandates synchronized real-time copy within Bangladesh for Critical Information Infrastructure (CII). NexusEdge provides **Global-Grade Infrastructure + Local Cryptographic Sovereignty**.

---

## 🧠 10. Rule 123: Engineering Philosophy

> **"The goal is not to produce the most code. The goal is to produce the smallest amount of correct, secure, observable, maintainable code that can become part of a globally distributed infrastructure system."**  
>  
> *Every implementation must ask:*  
> **"Will this still make sense when this system operates across hundreds of PoPs, thousands of nodes, millions of workloads, multiple continents, and thousands of engineers?"**  
> *If the answer is no, redesign it before merging.*
