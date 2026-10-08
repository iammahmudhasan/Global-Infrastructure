# AGENTS.md — NexusEdge Autonomous Agent Operating Manual

> **Platform Mission:** Build the world's most intelligent global infrastructure network for applications and AI.  
> **Core Intellectual Question:** *"Where should every application, AI inference request, and compute workload run right now?"*  
> **Constitutional Rulebook:** [docs/AI_ENGINEERING_RULES.md](docs/AI_ENGINEERING_RULES.md) (127 Mandatory Platform Rules)  
> **Workspace Rule:** [.agents/rules/ai-engineering-rules.md](.agents/rules/ai-engineering-rules.md)

---

## ⚡ 1. The First-Principles Development Protocol

All AI coding agents operating on this codebase MUST follow these non-negotiable first principles:

1. **Constitutional Priority Hierarchy (Rule 1):**  
   $$\mathbf{Correctness} > \mathbf{Security} > \mathbf{Reliability} > \mathbf{Maintainability} > \mathbf{Performance} > \mathbf{Speed}$$  
   *Never reverse this order merely to ship faster.*
2. **First-Principles Over Analogies (Rule 2):**  
   Do not copy legacy architectures blindly (e.g. Cloudflare is 15 years old, designed for static web caching). Reason upward from physical truths: speed of light in fiber (~200 km/ms), rack power density (100–200 kW/rack), and GPU memory bandwidth.
3. **Mandatory Real-World Verification (Rules 2, 81):**  
   **Never write unverified code.** Every feature, route, or scheduler algorithm MUST be executed and verified immediately in the shell (`cargo check`, `cargo test`, `go test ./...`, `python optimizer.py`). Never assume code works without execution proof.
4. **Continuous Cryptographic Git Push (Rule 3, 96):**  
   Every completed task, bugfix, or architectural addition MUST be committed cleanly and pushed immediately to `origin/main` with verified commits.
5. **Architectural Graph Anchor Mandate (Rule 124):**  
   Before generating, modifying, or deleting code for any milestone or subsystem, the agent MUST construct and output a complete architectural relationship graph (Mermaid diagram). The graph must explicitly illustrate component boundaries, data-plane vs. control-plane paths, data stores, external dependencies, and failure transitions. This visually anchors the system topology and prevents architectural drift or blind patching.
6. **The 4-Question Code Justification Mandate (Rule 125):**  
   Before writing OR deleting any code, the agent MUST explicitly define and document:
   - **WHERE:** The exact file path, package, and layer (Data Plane / Control Plane / Intelligence).
   - **WHY:** The concrete technical and business requirement driving this addition/deletion.
   - **IMPACT:** What happens when this code is written (operational behavior, state transitions, outputs).
   - **RISK OF OMISSION:** What breaks, what fails, or what security/reliability hole opens up if this code is NOT written.
7. **Cleanliness & Industrial Discipline Mandate (Rule 126):**  
   - **Zero Unused Code:** No dead functions, unused struct fields, orphaned files, or dangling imports.
   - **Zero Zombie Comments:** No commented-out dead code blocks.
   - **No Gratuitous Emojis:** Keep production code, type definitions, log messages, and comments strictly industrial, professional, and free of emoji clutter.
8. **Pre-Push CI Parity Mandate (Rule 127):**  
   **Zero Remote CI Failures.** Never commit or push to `origin/main` without first executing and passing the complete local CI parity verification suite mirroring `.github/workflows/ci.yml`. Functional compilation alone is strictly insufficient; all formatting gates (`gofmt -l`, `cargo fmt --check`), linting gates (`cargo clippy -D warnings`), and test suites must be verified 100% clean locally before push.


---

## 🏛️ 2. The 3-Plane Master Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │      1. INTELLIGENCE PLANE (Optimization Matters)      │
                  │      Python 3.12+ + PyTorch / vLLM + ClickHouse        │
                  │      Multi-objective scheduling: Latency, Cost, Carbon │
                  └──────────────────────────┬─────────────────────────────┘
                                             │ (Calculated Placement Graphs & Intent)
                                             ▼
                  ┌────────────────────────────────────────────────────────┐
                  │        2. CONTROL PLANE (Correctness Matters)          │
                  │        Go + gRPC (Buf) + NATS JetStream + Postgres 18  │
                  │        Sub-100ms declarative reconciliation loops       │
                  └──────────────────────────┬─────────────────────────────┘
                                             │ (Pushed Local State & Fast-Path Policy)
                                             ▼
                  ┌────────────────────────────────────────────────────────┐
                  │           3. DATA PLANE (Latency Matters)              │
                  │        Rust Fast-Path + Envoy L7 + Linux C/eBPF / XDP  │
                  │        Line-rate packet path, zero GC, lock-free       │
                  └────────────────────────────────────────────────────────┘
```

---

## 📁 3. The 14 Monorepo Pillars & Strict Invariants (Rules 4–8)

The monorepo is strictly structured into 14 domain directories. **Never place files outside their designated pillar:**

| Pillar | Operational Plane | Strict Invariants & Responsibilities |
|---|---|---|
| **`apps/`** | Product / Customer | Next.js Dashboard, Go CLI (`nexusedge`), Docs, Status, Console. No core daemons. |
| **`services/`** | Control Plane (Go) | Business domains: `api-gateway`, `network/global-router`, `compute`, `storage`, `billing`. |
| **`dataplane/`** | Data Plane (Rust/C) | Line-rate packet path: `edge/gateway`, `network/ebpf/programs/xdp`, `runtime/wasm`. |
| **`intelligence/`** | Intelligence (Python)| Multi-objective schedulers, capacity predictors, PyTorch models, GPU optimizers. |
| **`proto/`** | API Contracts | Protocol Buffers governed by `buf.yaml`. Source of truth for all gRPC communication. |
| **`schemas/`** | Event / Data Contracts | NATS JetStream event schemas (Avro/JSON), Telemetry, Analytics schemas. |
| **`infra/`** | Physical Substrate | Datacenter topology, regions (`dhaka`, `singapore`, `frankfurt`, `virginia`), BGP, SONiC. |
| **`deploy/`** | Deployment Manifests | Envoy configs, Kubernetes base & overlays (dev/prod), Helm charts, Argo CD. |
| **`tests/`** | Multi-Tier Verification| Integration, e2e, network emulation, security fuzzing, chaos injection. |
| **`benchmarks/`** | Performance Benchmarks | Line-rate Mpps, L7 proxy latency (p99), DNS throughput, GPU memory saturation. |
| **`rfcs/`** | Architectural Proposals| Proposed architecture changes before code is written (`rfcs/0001-...`). |
| **`adr/`** | Architectural Decisions| Permanent architectural decision records (`adr/0001-...`). |
| **`security/`** | Security Foundations | Threat models, compliance rules, SBOM, signing keys, zero-trust policies. |
| **`docs/`** | Master Documentation | System architecture, network runbooks, operational disaster recovery procedures. |

### 5 Non-Negotiable Invariants:
1. **Data Plane ≠ Control Plane (Rule 5):** High-performance packet processing lives in Rust/C. Packets must NEVER wait on slow control plane or DB round trips.
2. **Private Service Boundaries (Rule 7):** `services/<A>` must NEVER import `services/<B>/internal`. Communicate strictly via gRPC/events.
3. **No God Services (Rule 59):** Do not create `services/core` or `libs/utils`. Keep libraries domain-specific (`libs/go/telemetry`).
4. **Domain Owns Its Data (Rule 8):** Network service owns network tables; Billing owns billing tables. Never execute cross-domain SQL queries.
5. **Adopt Commodity, Build Moat (Rules 33, 34):** Adopt Postgres, K8s, Envoy, PowerDNS, Ceph, NATS. Focus proprietary IP on our 5 engines.

---

## 🎯 4. The 5 Proprietary IP Engines (Our Moat)

1. **Global Traffic Director (`dataplane/`, `services/network`):** Routes requests to optimal PoPs via Anycast & live RTT telemetry.
2. **Universal Workload Scheduler (`intelligence/`, `services/orchestration`):** Places jobs based on Latency, Cost, Power, and Sovereignty.
3. **Capacity Engine (`services/compute`, `intelligence/capacity`):** Tracks live GPU VRAM, grid power, and transit capacity.
4. **Policy Engine (`services/network`, OPA):** Sub-millisecond data residency enforcement (Bangladesh NDMA 2026, EU GDPR).
5. **Global Control Plane (`services/`):** Raft/NATS declarative state replication in under 100ms globally.

---

## ⚙️ 5. Operationalizing Key Rules for AI Agents

- **Rule 2 (Understand Before Editing):** Inspect existing domain code, tests, and nearest README before modifying anything.
- **Rule 9–11 (API & Event Contracts):** `proto/` and `schemas/` are sacred contracts. Never make breaking changes silently; use semantic versioning (`v1`, `v2`). Run `buf lint`.
- **Rule 12 (Desired State Architecture):** Implement idempotent declarative reconciliation loops over imperative scripts.
- **Rule 14–16 (Failure & Idempotency):** Assume networks partition, nodes fail, and requests duplicate. Design all mutating APIs with `request_id` / `idempotency_key`.
- **Rule 18–19 (Zero Secrets in Code/Logs):** Never commit API keys, private keys, or passwords. Redact authorization headers and tokens in logs.
- **Rule 23 (Untrusted Input):** Validate lengths, types, ranges, IPs, headers, and protobuf payloads. Fail closed.
- **Rule 24 (Unsafe Rust):** Rust `unsafe` is forbidden unless strictly necessary with an explicit `// SAFETY:` invariant block.
- **Rule 28–30 (AI / Intelligence Bounds):** ML predictions must NEVER bypass deterministic safety checks. Always provide a deterministic fallback when models are offline.
- **Rule 35–37 (Error Handling & Timeouts):** No swallowed errors (`_ = ...`). Every external network call MUST have explicit timeouts and bounded backoff.
- **Rule 42–43 (Observability):** Expose OpenTelemetry traces, structured metrics, and pass `request_id` / `trace_id` across service hops.
- **Rule 54–55 (Tenant Isolation):** Multi-tenancy is mandatory. Never trust an entity ID (`GET /instances/{id}`) without organizational authorization.
- **Rule 83–84 (No Fabricated Metrics):** Never fabricate latency, throughput, benchmark claims, or test passes. Measurements must be empirically verified.

---

## 🛡️ 6. Rule 122: Absolute Non-Negotiables

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
- Write or delete code without explicitly answering Where, Why, Impact, and Risk of Omission.
- Leave unused functions, orphaned files, or commented-out zombie code in the repository.
- Clutter source code or internal logs with gratuitous emojis.
- Write code without first anchoring the full system graph.
- Push to remote origin without running and passing the full local Pre-Push CI Parity verification suite (Rule 127).

### ALWAYS:
- Preserve architecture and 14-pillar directory boundaries.
- Construct a complete visual architecture graph (Mermaid) before writing code.
- Explicitly define Where, Why, What happens, and What breaks before adding or removing code.
- Validate all external input.
- Enforce least privilege and defense in depth.
- Add OpenTelemetry metrics, traces, and structured logs.
- Test meaningful changes across unit, integration, and security tiers.
- Consider failure, partition, timeout, and rollback.
- Prefer idempotent operations and reconciliation loops.
- Keep APIs versioned and backward compatible.
- Document major architecture decisions in RFCs and ADRs.
- Measure performance via actual benchmarks rather than guessing.
- Bound AI decisions by deterministic policy fallbacks.
- Optimize for correctness and long-term maintainability.
- Ensure 100% dead-code elimination, zero orphaned files, and clean industrial code.
- Run the 100% Pre-Push CI Parity suite (`tools/ci/verify-ci.ps1`, `tools/ci/verify-ci.sh`, or `make verify-ci`) before any `git push`.

---

## 📋 7. Rule 121: Final Completion Checklist

Before considering ANY engineering task complete, verify:

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
[ ] 100% Pre-Push CI Parity verified (gofmt, cargo fmt --check, cargo clippy -D warnings, go vet, all test suites)?
```

---

## 🛠️ 8. Execution & Verification Cheatsheet

```bash
# 0. One-Shot Pre-Push CI Parity Suite (MANDATORY BEFORE EVERY GIT PUSH)
powershell -ExecutionPolicy Bypass -File tools/ci/verify-ci.ps1   # Windows
bash tools/ci/verify-ci.sh                                        # Linux / macOS / CI
make verify-ci                                                    # Makefile

# 1. Rust Data Plane (Gateway)
cd dataplane/edge/gateway
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check
cargo test

# 2. Go Control Plane (Format, Vet, and Test)
cd services/edge/config-controller && gofmt -l . && go vet ./... && go test ./...
cd services/network/global-router && gofmt -l . && go vet ./... && go test ./...

# 3. Intelligence Plane (Optimizer)
python intelligence/scheduling/workload-scheduler/optimizer.py

# 4. Monorepo Formatting (Automated Fix)
make fmt-all

# 5. Official CLI
cd apps/cli
go run cmd/main.go status

# 6. Protobuf Governance
buf lint
buf breaking --against ".git#branch=main"
```

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
