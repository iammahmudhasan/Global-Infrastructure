# Contributing to NexusEdge

Welcome to the **NexusEdge** engineering monorepo. We maintain world-class engineering discipline across our Data Plane, Control Plane, and Intelligence Plane.

---

## 🏛️ Monorepo Invariants (The 5 Golden Rules)

1. **Strict Dependency Direction:**
   - `Product (apps/)` -> `Control Plane (services/)` -> `Data Plane (dataplane/)` -> `Physical Infra`.
   - Never import internal packages directly across service boundaries (e.g., `services/compute` must NOT import `services/network/internal`). Use gRPC, events, or proto contracts.
2. **Data Plane vs. Control Plane Isolation:**
   - Performance/latency-critical paths live in `dataplane/` (Rust, C/eBPF).
   - Business correctness, policy, and reconciliation live in `services/` (Go).
3. **No God Services or Garbage Dumps:**
   - Avoid creating `services/core` or `libs/utils`. Keep libraries domain-specific (e.g. `libs/rust/http`, `libs/go/telemetry`).
4. **API Contracts are Immutable:**
   - Any API or proto change must pass `buf breaking` validation before merging.
5. **Architectural Decisions Require RFCs:**
   - Propose major changes in `rfcs/`, document permanent architectural decisions in `adr/`.
