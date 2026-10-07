# NexusEdge Master Architecture: The North-Star Blueprint

> **"Do not reinvent commodity and battle-tested infrastructure. Invent the proprietary Moat: The Global Traffic Director, Workload Scheduler, Capacity Engine, Policy Engine, and Control Plane Orchestrator."**

---

## 1. The 3-Plane Master Architecture

Every subsystem in NexusEdge is strictly partitioned into three decoupled operational planes:

```mermaid
graph TD
    subgraph IntelligencePlane [INTELLIGENCE PLANE (Optimization Matters)]
        PythonML[Python 3.14 + PyTorch / vLLM / NVIDIA Dynamo]
        Analytics[ClickHouse Columnar Telemetry Engine]
        OptEngine[Global Multi-Objective Workload Optimizer]
        CapacityAI[Real-Time Power, Grid & Capacity Predictor]
    end

    subgraph ControlPlane [CONTROL PLANE (Correctness Matters)]
        GoCP[Go Orchestrator + gRPC + Buf]
        EventBus[NATS + JetStream Event Mesh]
        ConfigDB[(PostgreSQL 18 - System of Record)]
        StateCache[(Valkey - Ephemeral State & Distributed Locks)]
        AuthEngine[SPIFFE/SPIRE + OpenBao + OPA/Rego]
    end

    subgraph DataPlane [DATA PLANE (Latency Matters)]
        Anycast[Anycast BGP + PowerDNS / dnsdist]
        XDP[Linux Kernel eBPF / XDP L4 Drop & L4 LB]
        EnvoyProxy[Envoy L7 Edge Gateway]
        RustFastPath[Rust Custom High-Throughput Engine - Tokio/Hyper]
        EdgeWasm[Wasmtime WebAssembly Micro-Sandboxes]
    end

    subgraph PhysicalCompute [PHYSICAL & CLUSTER SUBSTRATE]
        K8s[Kubernetes + Cilium eBPF CNI + containerd]
        Virtualization[KVM + Firecracker MicroVMs + KubeVirt]
        Storage[Ceph: RBD Block + RGW S3 Object + CephFS File]
        NetworkFabric[Spine-Leaf Whitebox Switches + SONiC + EVPN/VXLAN]
    end

    IntelligencePlane -->|Calculated Routing Graph & Schedules| ControlPlane
    ControlPlane -->|Sub-100ms Declarative Propagation| DataPlane
    ControlPlane -->|Cluster & Node Lifecycle| PhysicalCompute
    DataPlane -->|Line-Rate User Ingress| PhysicalCompute
    DataPlane -.->|OpenTelemetry Ingestion| IntelligencePlane
```

---

## 2. Core Abstraction: The Universal `Workload`

The platform does not identify as a "Kubernetes company", "CDN company", or "GPU cloud". The fundamental primitive of the entire platform is the **`Workload`**.

A `Workload` can be:
- **Web / Static Asset** (Cached at edge, zero origin latency)
- **API Endpoint** (Proxied via Envoy + Rust fast-path)
- **Container / Pod** (Scheduled onto K8s + Cilium)
- **MicroVM** (Isolated inside Firecracker for untrusted code execution)
- **GPU Inference / Reasoning Job** (Routed to optimal vLLM / SGLang instance)
- **Agentic Autonomous Loop** (Persistent state with KV-cache affinity)
- **Database / Storage Volume** (Mounted via Ceph RBD or S3)

The platform's proprietary engine continuously answers:
$$\text{WHERE?} \quad \text{WHICH HARDWARE?} \quad \text{WHICH NETWORK?} \quad \text{WHICH REGION?} \quad \text{WHICH GPU?} \quad \text{WHAT COST?} \quad \text{WHAT LATENCY?} \quad \text{WHAT POLICY?}$$

---

## 3. The 5 Proprietary Moat Engines (What We Build Ourselves)

We explicitly **do not** rewrite mature open-source systems. We build the proprietary orchestration brain that commands them:

| Engine | Primary Language | Function & Intellectual Property |
|---|---|---|
| **1. Global Traffic Director** | Rust + Go | Maps users to the optimal edge PoP using real-time Anycast, BGP telemetry, and RTT probes. |
| **2. Global Workload Scheduler** | Go + Python | Dispatches workloads to the optimal node across bare-metal, K8s, MicroVMs, and multi-cloud providers. |
| **3. Capacity Engine** | Go + ClickHouse | Tracks real-time availability of GPU VRAM, CPU cores, memory, subsea transit bandwidth, and data center grid power. |
| **4. Policy Engine** | Go + OPA / Rego | Enforces sub-millisecond data residency (BD, EU, US), security posture, SLA budgets, and compliance. |
| **5. Global Control Plane** | Go + NATS | Distributes declarative state globally with strict consistency and zero downtime. |

---

## 4. Subsystem Inventory: Battle-Tested Commodity vs. Proprietary Moat

```
┌──────────────────────────────────────┬────────────────────────────────────────────────────────┐
│ SUBSYSTEM DOMAIN                     │ CHOSEN BATTLE-TESTED TECHNOLOGIES                      │
├──────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ Primary Database (System of Record)  │ PostgreSQL 18 + Regional Replicas + Logical Rep        │
│ Ephemeral Cache & Distributed Locks  │ Valkey (Redis OSS continuation)                        │
│ Analytics & Observability OLAP       │ ClickHouse (Columnar logs, telemetry, traces)          │
│ Event Bus & Async Control Plane      │ NATS + JetStream (Later Kafka/Redpanda for Data Plane) │
│ Global DNS & Anycast                 │ PowerDNS Authoritative + dnsdist                       │
│ Edge L7 Proxy & Ingress              │ Envoy + Custom Rust Fast-Path                          │
│ Container Orchestration & CNI        │ Kubernetes + Cilium (eBPF datapath) + containerd       │
│ Serverless MicroVMs & Isolation      │ Firecracker (KVM) + WebAssembly (Wasmtime)             │
│ Distributed Storage Fabric           │ Ceph (RBD Block, RGW S3 Object, CephFS File)           │
│ AI Serving & Distributed Inference   │ vLLM, SGLang, TensorRT-LLM, Triton, NVIDIA Dynamo      │
│ Border Routing & Switching           │ FRRouting (FRR - BGP, EVPN/VXLAN), SONiC Whitebox      │
│ Observability Suite                  │ OpenTelemetry + Prometheus + Mimir + Loki + Tempo      │
│ Infrastructure as Code & GitOps      │ OpenTofu + Helm + Argo CD + Harbor                     │
│ Workload & Machine Identity          │ SPIFFE / SPIRE + OpenBao (Vault continuation) + OIDC   │
│ API Governance & RPC                 │ Protocol Buffers + Buf + gRPC                          │
│ Customer Dashboard                   │ React + Next.js + TypeScript + Tailwind + shadcn/ui    │
└──────────────────────────────────────┴────────────────────────────────────────────────────────┘
```
