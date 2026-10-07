# AGENTS.md — NexusEdge Autonomous Agent Operating Manual

> **Mission:** Build the world's most intelligent global infrastructure network for applications and AI.  
> **Core Intellectual Question:** *"Where should every application, AI inference request, and compute workload run right now?"*  
> **Constitutional Rulebook:** [docs/AI_ENGINEERING_RULES.md](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/docs/AI_ENGINEERING_RULES.md) (123 Mandatory Platform Rules)

---

## ⚡ The First-Principles Development Protocol

All AI coding assistants and autonomous engineering agents operating on this codebase MUST follow these **non-negotiable first principles**:

1. **Constitutional Hierarchy:**
   **Correctness > Security > Reliability > Maintainability > Performance > Development Speed**
   Never reverse this order merely to ship faster. All 123 rules in [docs/AI_ENGINEERING_RULES.md](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/docs/AI_ENGINEERING_RULES.md) apply repository-wide.
2. **First-Principles Thinking Over Analogies:**
   - Never copy legacy architectures blindly (e.g. Cloudflare is 15 years old, designed for static web caching).
   - Reason upward from physical truths: subsea fiber latency (speed of light in glass ~200 km/ms), transformer power density (100–200 kW/rack), and GPU memory bandwidth.
3. **Mandatory Real-World Verification:**
   - **Never write unverified code.** When a feature, proxy route, or scheduler algorithm is implemented, it MUST be executed and tested immediately in the shell.
   - Run `cargo check`, `cargo test`, `go test ./...`, or execute Python placement models. Never assume code works without execution proof.
4. **Continuous Cryptographic Git Push:**
   - Every completed task, bugfix, or architectural addition MUST be committed cleanly and pushed immediately to `origin/main` with verified commits.

---

## 🏛️ The 3-Plane Master Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │ 1. INTELLIGENCE PLANE (Optimization Matters) │
                  │ Python 3.14 + PyTorch / vLLM + ClickHouse    │
                  └──────────────────────┬───────────────────────┘
                                         │ (Calculated Placement & Routing Graphs)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │   2. CONTROL PLANE (Correctness Matters)     │
                  │   Go + gRPC (Buf) + NATS JetStream + Postgres│
                  └──────────────────────┬───────────────────────┘
                                         │ (Sub-100ms Declarative Reconciliation)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │      3. DATA PLANE (Latency Matters)         │
                  │   Rust Fast-Path + Envoy L7 + Linux C/eBPF   │
                  └──────────────────────────────────────────────┘
```

---

## 📁 The 14 Monorepo Pillars & Strict Invariants

The monorepo is strictly structured into 14 domain directories. **Never place files outside their designated pillar:**

| Pillar | Operational Plane | Strict Invariants & Responsibilities |
|---|---|---|
| **`apps/`** | Customer Products | Next.js Dashboard, Go CLI (`nexusedge`), Docs, Status, Console. No core daemons. |
| **`services/`** | Control Plane (Go) | Business domains: `api-gateway`, `network/global-router`, `compute`, `storage`, `billing`. |
| **`dataplane/`** | Data Plane (Rust/C) | Line-rate packet path: `edge/gateway`, `network/ebpf/programs/xdp`, `runtime/wasm`. |
| **`intelligence/`** | Intelligence Plane (Python)| Multi-objective schedulers, capacity predictors, PyTorch models, GPU optimizers. |
| **`proto/`** | API Contracts | Protocol Buffers governed by `buf.yaml`. Source of truth for all gRPC communication. |
| **`schemas/`** | Event / Data Contracts | NATS JetStream event schemas (Avro/JSON), Telemetry, Analytics schemas. |
| **`infra/`** | Physical / Cloud Substrate| Datacenter topology, regions (`dhaka`, `singapore`, `frankfurt`, `virginia`), BGP, SONiC. |
| **`deploy/`** | Deployment Manifests | Envoy configs, Kubernetes base & overlays (dev/prod), Helm charts, Argo CD. |
| **`tests/`** | Multi-Tier Verification| Integration, e2e, network emulation, security fuzzing, chaos injection. |
| **`benchmarks/`** | Performance Benchmarks | Line-rate Mpps, L7 proxy latency (p99), DNS throughput, GPU memory saturation. |
| **`rfcs/`** | Architectural Proposals | Proposed architecture changes before code is written (`rfcs/0001-...`). |
| **`adr/`** | Architecture Decisions | Permanent architectural decision records (`adr/0001-...`). |
| **`security/`** | Security Foundations | Threat models, compliance rules, SBOM, signing keys, zero-trust policies. |
| **`docs/`** | Documentation & Runbooks | Master system architecture, operational runbooks, disaster recovery procedures. |

### 5 Non-Negotiable Invariants:
1. **Data Plane ≠ Control Plane:** Performance-critical code is Rust/C; control/reconciliation is Go. Packets never depend on slow control-plane round trips.
2. **Private Internal Packages:** `services/<A>` must NEVER import `services/<B>/internal`. Communicate strictly via gRPC/events.
3. **No God Services:** Do not create `services/core` or `libs/utils`. Keep packages domain-specific.
4. **Domain Owns Its Data:** No monolithic database. Network service owns network tables; Billing owns billing tables.
5. **Adopt Commodity, Build Moat:** Adopt Postgres, K8s, Envoy, PowerDNS, Ceph, NATS. Build our 5 IP engines.

---

## 🎯 The 5 Proprietary IP Engines (Our Moat)

1. **Global Traffic Director (`dataplane/`, `services/network`):** Routes users to nearest PoP via Anycast & live RTT probes.
2. **Universal Workload Scheduler (`intelligence/`, `services/orchestration`):** Places jobs based on Latency, Cost, Power, and Sovereignty.
3. **Capacity Engine (`services/compute`, `intelligence/capacity`):** Tracks live GPU VRAM, grid power, and transit capacity.
4. **Policy Engine (`services/network`, OPA):** Sub-millisecond data residency enforcement (Bangladesh NDMA 2026, EU GDPR).
5. **Global Control Plane (`services/`):** Raft/NATS declarative state replication in under 100ms globally.

---

## 🛡️ Rule 122: Absolute Non-Negotiable Invariants

### NEVER:
- Commit secrets (API keys, private keys, tokens, production certificates).
- Invent test results or fabricate benchmark metrics.
- Disable security (TLS, auth, isolation) to make tests pass.
- Bypass authorization or trust unverified IDs.
- Cross service private boundaries (`internal/`).
- Directly access another domain's database.
- Introduce dependencies without justification.
- Make destructive production changes without authorization.
- Put packet-path logic behind unnecessary control-plane calls.
- Make AI the sole authority for critical infrastructure decisions.
- Hide errors or return fake success responses.
- Claim completion without real validation.
- Rewrite mature infrastructure without a strong reason.

### ALWAYS:
- Preserve architecture and 14-pillar directory boundaries.
- Validate all external input.
- Enforce least privilege and defense in depth.
- Add OpenTelemetry metrics, traces, and structured logs.
- Test meaningful changes across unit, integration, and security tiers.
- Consider failure, partition, timeout, and rollback.
- Prefer idempotent operations and reconciliation loops.
- Keep APIs versioned and backward compatible.
- Document major architecture decisions in RFCs and ADRs.
- Measure performance via actual benchmarks rather than guessing.
- Bounded AI decisions by deterministic policy fallbacks.
- Optimize for correctness and long-term maintainability.

---

## 📋 Rule 121: Final Completion Checklist

Before considering any engineering task complete, verify:

```text
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

## 🛠️ CLI & Build Verification Cheatsheet

```bash
# 1. Rust Data Plane (Gateway)
cd dataplane/edge/gateway
cargo check
cargo test

# 2. Go Control Plane (Global Router)
cd services/network/global-router
go run cmd/global-router/main.go

# 3. Intelligence Plane (Optimizer)
python intelligence/scheduling/workload-scheduler/optimizer.py

# 4. Official CLI
cd apps/cli
go run cmd/main.go status

# 5. Protobuf Governance
buf lint
buf breaking --against ".git#branch=main"
```

---

## 🇧🇩 Strategic Geo-Anchor (Bangladesh Advantage)
- **BDIX Peering:** 167 members, 2.27 Tbps cumulative port capacity.
- **SMW6 Submarine Cable:** 30,000 Gbps planned capacity (Cox's Bazar to Singapore/Mumbai/France).
- **National Data Management Act 2026:** Mandates synchronized real-time copy within Bangladesh for Critical Information Infrastructure (CII). NexusEdge provides **Global-Grade Infrastructure + Local Cryptographic Sovereignty**.

---

## 🧠 Rule 123: Engineering Philosophy

The goal is not to produce the most code.  
The goal is to produce the smallest amount of correct, secure, observable, maintainable code that can become part of a globally distributed infrastructure system.

Every implementation must ask:  
> **"Will this still make sense when this system operates across hundreds of PoPs, thousands of nodes, millions of workloads, multiple continents, and thousands of engineers?"**  
If the answer is no, redesign it before merging.
