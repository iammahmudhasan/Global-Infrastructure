# North-Star Technology Stack Matrix

> **"Rust (Data Plane) + Go (Control Plane) + C/eBPF (Kernel Path) + Python (AI/Intelligence) + TypeScript (UI/Product)"**

---

## 1. Programming Languages: Strict Division of Responsibilities

```
                                      THE LANGUAGE TRINITY
                                               │
             ┌─────────────────────────────────┼─────────────────────────────────┐
             ↓                                 ↓                                 ↓
        #1 RUST                            #2 GO                             #3 C / eBPF
      [Data Plane]                      [Control Plane]                     [Kernel Path]
 • Edge Proxy & Fast-Path          • API Servers & REST/gRPC         • eBPF / XDP Bytecode
 • High-Performance Networking     • Schedulers & Orchestration      • libbpf & TC Filters
 • L4 Load Balancer                • K8s Operators & Controllers     • Hardware Driver Hooks
 • Packet Processing               • Billing & IAM Services          • DPDK Integrations
 • In-Memory Cache Engine          • Fleet Management Daemon         
 • WebAssembly (Wasmtime)          • Cloud-Native Infrastructure CLI 
                                               │
             ┌─────────────────────────────────┴─────────────────────────────────┐
             ↓                                                                   ↓
        #4 PYTHON                                                          #5 TYPESCRIPT
   [Intelligence Plane]                                                 [Customer Frontend]
 • AI Research & Models                                            • Next.js / React
 • Scheduling Optimization Math                                    • Tailwind CSS + shadcn/ui
 • Capacity & Grid Power Forecasts                                 • Real-Time Mission Control
 • PyTorch, vLLM & NVIDIA Dynamo                                   • Official Client SDKs
```

### Detailed Language Stacks
- **Rust:** `tokio`, `hyper`, `tonic` (gRPC), `rustls`, `serde`, `axum`, `quiche` (HTTP/3), `criterion`.
- **Go:** `gRPC`, `protobuf`, `connect-go`, `k8s.io/client-go`, `cobra` (CLI), `opentelemetry-go`, `pgx` (Postgres driver).
- **C:** Linux kernel eBPF headers, `libbpf`, XDP network device drivers.
- **Python:** `uv` (package manager), `PyTorch`, `NumPy`, `Polars`, `scikit-learn`, `Ruff` (linter), `pytest`.
- **TypeScript:** Node 24+, Next.js App Router, Tailwind CSS, shadcn/ui, Radix UI, TanStack Query.

---

## 2. Infrastructure & Networking Subsystems

| Domain | Selected Technology | Architectural Rationale |
|---|---|---|
| **Global DNS** | PowerDNS Authoritative + dnsdist | High-throughput Anycast DNS, DNSSEC, DoS/abuse mitigation, and dynamic HTTP API record management. |
| **Border Routing** | FRRouting (FRR) | Full Internet routing table BGP-4, internal eBGP data-center fabrics, EVPN/VXLAN overlay, RPKI/ROA validation, BGP FlowSpec, and RTBH. |
| **Switch Layer** | SONiC (Software for Open Networking in the Cloud) | Open-source network OS running on white-box merchant-silicon spine-leaf switches. |
| **L7 Edge Proxy** | Envoy Proxy + Custom Rust Fast-Path | Envoy provides battle-tested HTTP/1/2/3, TLS termination, and service discovery; Rust provides specialized fast-paths where profiling dictates. |
| **DDoS Protection** | 3-Layer Defense | **L3/L4:** XDP/eBPF + nftables + BGP FlowSpec; **L4 LB:** XDP + Rust; **L7:** Envoy + WAF + Token-Bucket. |
| **WAF** | Coraza / ModSecurity + ML Anomaly Engine | Rule-based OWASP core ruleset with behavioral anomaly risk scoring. |
| **Compute Orchestration** | Kubernetes + Cilium CNI + containerd | Cilium eBPF datapath eliminates kube-proxy iptables bottlenecks; containerd ensures lean OCI execution. |
| **Virtualization & Isolation**| KVM + Firecracker MicroVMs + KubeVirt | Firecracker runs untrusted tenant code in isolated microVMs with sub-second boot times. |
| **Edge Compute** | WebAssembly (Wasmtime) | Language-neutral sandboxed functions executing in microseconds. |
| **Distributed Storage** | Ceph (RBD, RGW/S3, CephFS) | Regional storage clusters (Asia, Europe, US) with S3-compatible APIs; control-plane handles cross-region replication. |
| **Primary Database** | PostgreSQL 18 | Rock-solid relational storage for users, orgs, billing, and infrastructure state with regional read replicas. |
| **Ephemeral Cache** | Valkey | Redis OSS continuation for rate limits, session tokens, and distributed locking. Never used as system-of-record. |
| **Event Bus** | NATS + JetStream | High-speed, persistent event mesh for control plane commands; Kafka/Redpanda reserved for massive data plane telemetry. |
| **OLAP / Analytics** | ClickHouse | Extreme columnar compression and SQL analysis for trillions of request logs, security events, and billing metrics. |
| **Observability** | OpenTelemetry + Prometheus + Mimir + Loki + Tempo + Grafana | Standardized OTel collection with horizontally scalable metrics (Mimir), logs (Loki), and traces (Tempo). |
| **AI Inference Serving** | vLLM + SGLang + NVIDIA Dynamo | High-throughput distributed inference, KV-cache-aware routing, disaggregated serving, and multi-GPU tensor parallelism. |
| **IaC & GitOps** | OpenTofu + Helm + Argo CD + Harbor | Declarative infrastructure as code without BSL license lock-in, automated by Argo CD GitOps pipelines. |
| **Identity & Secrets** | SPIFFE/SPIRE + OpenBao + OPA/Rego + OpenFGA | Cryptographic mTLS workload identity (SPIFFE), secret management (OpenBao), and fine-grained authorization (OPA + OpenFGA). |
| **API Governance** | Protocol Buffers + Buf | Automated linting, breaking change detection, and multi-language gRPC client generation. |
| **Chaos & Resilience** | Chaos Mesh + Litmus | Continuous automated failure injection (server kill, rack kill, transit drop, PoP partition). |

---

## 3. What We Build Ourselves vs. What We Adopt

```
                     DO NOT REINVENT (Battle-Tested)
  PostgreSQL • Kubernetes • Linux • Envoy • PowerDNS • FRR • Ceph • NATS
  Prometheus • OpenTelemetry • KVM • Firecracker • Cilium • Valkey • ClickHouse
                                   ▲
                                   │ Powered By
                                   │
                     OUR PROPRIETARY MOAT (The IP)
  ┌────────────────────────────────────────────────────────────────────────┐
  │ 1. Global Traffic Director (Latency & BGP Multi-Path Router)           │
  │ 2. Universal Workload Scheduler (Calculates WHERE to run each job)     │
  │ 3. Capacity Engine (Live GPU VRAM, CPU, Transit, & Grid Power Tracker) │
  │ 4. Policy Engine (Sub-ms Data Residency & Cost Arbitrage)              │
  │ 5. Global Control Plane (Declarative Sub-100ms Distribution)           │
  └────────────────────────────────────────────────────────────────────────┘
```
