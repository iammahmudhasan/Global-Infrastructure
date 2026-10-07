# NexusEdge: The Intelligent Global Infrastructure Fabric

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Data Plane: Rust + C/eBPF](https://img.shields.io/badge/Data%20Plane-Rust%20%2B%20eBPF-orange.svg)](docs/TECH_STACK.md)
[![Control Plane: Go + gRPC](https://img.shields.io/badge/Control%20Plane-Go%20%2B%20gRPC-00ADD8.svg)](docs/TECH_STACK.md)
[![Intelligence Plane: Python](https://img.shields.io/badge/Intelligence-Python%203.14%20%2B%20vLLM-3776AB.svg)](docs/TECH_STACK.md)

> **"Do not build yesterday's Cloudflare. Do not build an undifferentiated AI Gateway or a capital-burning GPU cloud. Build the Infrastructure-Neutral Global Fabric whose core intellectual question is: 'Where should every application, AI inference request, and compute workload run right now?'"**

---

## 🏛️ The 3-Plane Master Architecture

Every subsystem in NexusEdge is strictly partitioned into three decoupled operational planes:

```mermaid
graph TD
    subgraph IntelligencePlane [1. INTELLIGENCE PLANE (Optimization Matters)]
        PythonML[Python 3.14 + PyTorch / vLLM / NVIDIA Dynamo]
        Analytics[ClickHouse Columnar Telemetry Engine]
        OptEngine[Global Multi-Objective Workload Optimizer]
    end

    subgraph ControlPlane [2. CONTROL PLANE (Correctness Matters)]
        GoCP[Go Orchestrator + gRPC + Buf]
        EventBus[NATS + JetStream Event Mesh]
        ConfigDB[(PostgreSQL 18 - System of Record)]
        AuthEngine[SPIFFE/SPIRE + OpenBao + OPA/Rego]
    end

    subgraph DataPlane [3. DATA PLANE (Latency Matters)]
        Anycast[Anycast BGP + PowerDNS / dnsdist]
        XDP[Linux Kernel eBPF / XDP L4 Drop]
        EnvoyProxy[Envoy L7 Edge Gateway]
        RustFastPath[Rust Custom High-Throughput Engine - Tokio/Hyper]
        EdgeWasm[Wasmtime WebAssembly Micro-Sandboxes]
    end

    IntelligencePlane -->|Calculated Routing Graphs & Schedules| ControlPlane
    ControlPlane -->|Sub-100ms Declarative Propagation| DataPlane
```

---

## 🎯 The Core Primitive: The Universal `Workload`

The fundamental primitive of the entire platform is the **`Workload`** (defined in [`proto/nexusedge/v1/workload.proto`](proto/nexusedge/v1/workload.proto)):
- **Web & Static Content** (Edge cached, zero origin overhead)
- **API Gateway** (Proxied via Envoy + Rust fast-path)
- **Container / Pod** (Kubernetes + Cilium eBPF CNI + containerd)
- **MicroVM** (Isolated inside Firecracker for untrusted tenant execution)
- **GPU Inference Job** (Routed to optimal vLLM / SGLang / Dynamo clusters)
- **Persistent Agentic Loop** (Multi-turn reasoning with KV-cache affinity)
- **Database / Volume** (Mounted via Ceph RBD or S3)

---

## ⚡ The 5 Proprietary Moat Engines (What We Build Ourselves)

We explicitly **do not** rewrite mature open-source infrastructure (Postgres, K8s, Linux, Envoy, PowerDNS, FRR, Ceph, NATS, OTel, Firecracker). We build the proprietary brain:

1. **Global Traffic Director:** Maps users to the optimal edge PoP using real-time Anycast, BGP telemetry, and RTT probes.
2. **Global Workload Scheduler:** Dispatches workloads across bare-metal, K8s, MicroVMs, and multi-cloud providers.
3. **Capacity Engine:** Tracks real-time availability of GPU VRAM, CPU cores, subsea transit bandwidth, and data center grid power.
4. **Policy Engine:** Enforces sub-millisecond data residency (Bangladesh NDMA 2026, EU GDPR), security posture, and SLA budgets.
5. **Global Control Plane:** Distributes declarative state globally with strict consistency and zero downtime.

---

## 📁 Monorepo Directory Contract (The 14 Pillars)

| Directory | Plane / Function | Stack & Role |
|---|---|---|
| **`apps/`** | Customer-Facing Products | Next.js Dashboard, `nexusedge` Go CLI, Docs, Status, Console |
| **`services/`** | Control Plane | Go domain services (Global Router, IAM, DNS, Compute, Storage, Billing) |
| **`dataplane/`** | Data Plane (Hot Path) | Rust + C/eBPF (L7 Edge Proxy, WAF, XDP filter, L4 LB, Wasm) |
| **`intelligence/`**| Intelligence Plane | Python 3.14 (Mathematical Workload Placement, Capacity Forecast) |
| **`proto/`** | API Contracts | Protocol Buffers + Buf Governance (`proto/compute/v1/workload.proto`) |
| **`schemas/`** | Data Contracts | NATS JetStream Event Schemas, Telemetry, and Analytics Contracts |
| **`infra/`** | Physical & Cloud Substrate| Regions (Dhaka, Singapore, Frankfurt, Virginia), BGP, Hardware |
| **`deploy/`** | Deployment Manifests | Envoy configs, Kubernetes manifests, Helm, Argo CD, Firecracker |
| **`tests/`** | Multi-Tier Verification | Integration, e2e, network emulation, security, chaos tests |
| **`benchmarks/`**| Performance Benchmarks | Packet rate (Mpps), L7 proxy latency, DNS throughput, GPU saturation |
| **`rfcs/`** | Architecture Proposals | Formal proposals before major decisions (`rfcs/0001-...`) |
| **`adr/`** | Architecture Decisions | Permanent architectural decision records (`adr/0001-...`) |
| **`security/`** | Security Foundations | Threat models, compliance, SBOM, cryptographic signing policies |
| **`docs/`** | Documentation & Runbooks | Master system architecture, network runbooks, operator guides |

---

## 🚀 Running the Subsystems Locally

### 1. Data Plane (Rust Gateway)
```bash
cd dataplane/edge/gateway
cargo run
```

### 2. Control Plane (Go Global Router & Workload Dispatcher)
```bash
cd services/network/global-router
go run cmd/global-router/main.go
```

### 3. Intelligence Plane (Python Optimizer)
```bash
python intelligence/scheduling/workload-scheduler/optimizer.py
```

### 4. Official CLI
```bash
cd apps/cli
go run cmd/main.go status
```

---

## 📜 Strategic Reading
- **[Master Architecture](docs/MASTER_ARCHITECTURE.md)**: Deep dive into the 3 planes and 5 IP engines.
- **[Technology Stack Matrix](docs/TECH_STACK.md)**: Rationale behind Rust, Go, C, Python, Envoy, FRR, and Ceph.
- **[10–15 Year Thesis](docs/THESIS.md)**: The mathematical roadmap from $0 to hyper-scale.

## 📄 License
Licensed under the [MIT License](LICENSE).
