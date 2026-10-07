# Technology Stack Matrix & Systems Architecture

This document defines the official engineering stack for the **NexusEdge Global Infrastructure Fabric**. It outlines the exact separation of concerns across Networking, Bare-Metal Infrastructure, Distributed Storage, and Systems Programming.

---

## 1. Stack Overview & Division of Responsibilities

```mermaid
graph TB
    subgraph DataPlane [High-Throughput Data Plane (Kernel & Edge)]
        eBPF[eBPF / XDP / DPDK<br/>C & Rust] --> L4[L4 Packet Filtering & Anti-DDoS]
        L4 --> Proxy[L7 Edge Proxy, WAF & Cache<br/>Rust - Pingora/Hyper Architecture]
    end

    subgraph ControlPlane [Global Control Plane & Orchestration]
        GoCP[Control Plane Orchestrator<br/>Go + gRPC + Raft Consensus] --> ConfigSync[Config Propagation << 100ms]
        ConfigSync -.->|Zero-Lock Shared State| Proxy
        DNS[Anycast GeoDNS & Route Controller<br/>Go + CoreDNS / BIRD BGP] --> GoCP
    end

    subgraph ComputeStorage [Virtualization & Distributed Storage]
        KVM[KVM / Proxmox / Firecracker MicroVMs]
        Ceph[Ceph / MinIO Distributed Object Storage]
        Containers[Docker / Containerd / Kubernetes]
    end

    subgraph Presentation [Developer Experience & Mission Control]
        UI[Mission Control Dashboard<br/>TypeScript / React / WebSockets]
        CLI[Global Operator CLI<br/>Go]
    end
```

---

## 2. Layer-by-Layer Technical Specification

### A. Networking & Kernel Subsystems

| Domain | Technology / Protocol | Purpose in NexusEdge |
|---|---|---|
| **L3/L4 Routing** | BGP (Border Gateway Protocol), Anycast | Multi-PoP IP advertisement across transit providers and IXPs (Internet Exchange Points) for automatic nearest-node routing. |
| **BGP Routing Deamons** | BIRD, FRRouting (FRR) | Software-defined BGP session management, community tagging, and route filtering. |
| **Kernel Packet Processing** | **eBPF (Extended BPF) & XDP** | Line-rate packet processing inside Linux kernel network driver. Drops volumetric DDoS packets (SYN floods, UDP amplification) before socket allocation. |
| **Advanced Data Plane** | DPDK (Data Plane Development Kit) | Kernel-bypass userspace packet processing for ultra-high throughput 100G/400G PoP uplinks (Stage 3+). |
| **Transport & Application** | TCP/IP, QUIC, HTTP/1.1, HTTP/2, HTTP/3 | Multiplexed client-to-edge communication with zero-roundtrip TLS 1.3 session resumption. |
| **Encrypted Overlay Mesh** | WireGuard | Private, high-speed, kernel-level mesh network connecting all global edge nodes and origin backbones. |

---

### B. Systems Programming Languages (The Core Trinity)

The platform rejects "one language for everything" and pairs each workload with its optimal runtime:

#### 1. **Rust (The Data Plane & Edge Runtime)**
- **Role:** L7 Reverse Proxy, WAF, Memory-Safe Zero-Copy Caching, WebAssembly (Wasm) Isolation.
- **Why Rust:** Zero-cost abstractions, deterministic memory management without garbage collection (GC) pauses, thread-safety at compile time, and peak memory efficiency. Matches Cloudflare's *Pingora* and Fastly's *Compute@Edge*.

#### 2. **Go (The Control Plane & Orchestration Engine)**
- **Role:** Global Control Plane, Raft consensus nodes, DNS server, Multi-cluster orchestration, Operator CLI, and internal APIs.
- **Why Go:** Superb concurrent networking (`goroutines`), fast compilation, vast cloud-native ecosystem (Kubernetes, Docker, etcd, Prometheus, Terraform), and unmatched developer velocity for distributed systems.

#### 3. **C / C++ (Kernel Hooks & Hardware Abstraction)**
- **Role:** eBPF bytecode programs (`xdp_drop`, TC egress filters), DPDK hardware drivers, and raw Linux socket optimizations (`io_uring`, `AF_XDP`).

#### 4. **TypeScript (Mission Control & Edge SDKs)**
- **Role:** Developer Portal, Real-time 3D telemetry dashboard, and public JavaScript/TypeScript client SDKs.

#### 5. **Python (AI Workload & Telemetry Intelligence)**
- **Role:** KV-cache routing optimization simulations, predictive carbon/energy cost models, and telemetry anomaly detection.

---

### C. Infrastructure, Virtualization & Bare-Metal

- **Host Operating System:** Linux (Debian / Rocky Linux / Alpine with custom kernel tunings for `sysctl` network buffers, TCP BBR congestion control, and hugepages).
- **Virtualization & MicroVMs:**
  - **Proxmox VE & KVM:** Hardware-assisted virtualization for multi-tenant dedicated servers and PoP bare-metal provisioning.
  - **Firecracker / containerd:** MicroVMs for sub-second, hardware-isolated edge compute environments.
- **Reverse Proxies & Ingress Reference Models:**
  - **Envoy, HAProxy, NGINX:** Benchmarks, ingress gateways, and edge fallbacks.
- **Orchestration:** Docker, Containerd, Kubernetes (K3s / Talos Linux for lightweight edge clusters).

---

### D. Distributed Storage Hierarchy

| Tier | Technology | Purpose |
|---|---|---|
| **L1: In-Memory Edge Cache** | Lock-Free In-Memory LRU (Rust) | Sub-millisecond response time for hot static and dynamic API responses. |
| **L2: Local Persistent NVMe** | RocksDB / LMDB / SQLite | High-speed local state, edge KV storage, and local rate-limit windows. |
| **L3: Global Object Storage** | Ceph / MinIO / S3-Compatible Layer | Distributed object storage for static assets, models, and durable customer uploads. |
| **Data Protection** | Snapshotting, Multi-region Replication | Cryptographic data replication adhering strictly to local sovereignty laws. |

---

## 3. Engineering Standard & Invariants

1. **Zero-Garbage Collection on Hot Paths:** No request passing through the L4/L7 ingress path may encounter runtime garbage collection pauses.
2. **Sovereignty by Design:** Network routing and data storage policies must natively support geo-fencing (e.g., `de-only`, `eu-only`, `ap-only`).
3. **Graceful Degrade:** If the Go Control Plane becomes unreachable, Edge Data Plane nodes (Rust) must continue serving cached traffic and filtering attacks autonomously without interruption.
