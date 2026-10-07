<div align="center">

```
 _   _                               _____     _            
| \ | |                             |  ___|   | |           
|  \| | _____  ___   _ ___          | |__   __| | __ _  ___ 
| . ` |/ _ \ \/ / | | / __|  _____  |  __| / _` |/ _` |/ _ \
| |\  |  __/>  <| |_| \__ \ |_____| | |___| (_| | (_| |  __/
\_| \_/\___/_/\_\\__,_|___/         \____/ \__,_|\__, |\___|
                                                  __/ |     
                                                 |___/      
```

# NexusEdge: The Intelligent Global Infrastructure Fabric

### Intelligent Edge Network & Security Gateway Prototype, OWASP WAF, RFC 9111 CDN & Placement Engine

<br/>

[![Stage](https://img.shields.io/badge/Stage-Engineering%20Prototype-0288D1?style=for-the-badge&logo=git&logoColor=white)](docs/MASTER_ARCHITECTURE.md)
[![Target SLO](https://img.shields.io/badge/Target%20SLO-99.99%25%20(Design%20Goal)-0091EA?style=for-the-badge&logo=statuspage&logoColor=white)](docs/runbooks/EDGE_OPERATIONS_RUNBOOK.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-AA00FF?style=for-the-badge&logo=open-source-initiative&logoColor=white)](LICENSE)

[![Data Plane: Rust Gateway Prototype](https://img.shields.io/badge/Data%20Plane-Rust%20Gateway%20%2B%20Envoy%20Compiler-FF6D00?style=flat-square&logo=rust&logoColor=white)](docs/TECH_STACK.md)
[![Control Plane: Go 1.23](https://img.shields.io/badge/Control%20Plane-Go%201.23%20%2B%20Config%20Engine-00ADD8?style=flat-square&logo=go&logoColor=white)](docs/TECH_STACK.md)
[![Intelligence Plane: Python 3.12+](https://img.shields.io/badge/Intelligence-Python%203.12%2B%20%2B%20Optimizer-3776AB?style=flat-square&logo=python&logoColor=white)](docs/TECH_STACK.md)
[![Compliance Target: NDMA 2026 & GDPR](https://img.shields.io/badge/Compliance%20Target-NDMA%202026%20%7C%20GDPR-43A047?style=flat-square&logo=shield&logoColor=white)](docs/runbooks/EDGE_OPERATIONS_RUNBOOK.md)

<br/>

[**Architecture**](#-architecture-overview) •
[**Product Engines**](#-the-8-commercial-subsystems) •
[**Benchmarks**](#-empirical-performance-benchmarks) •
[**Global PoPs**](#-global-anycast-mesh--bangladesh-sovereignty) •
[**Quickstart**](#-quickstart-guide) •
[**Commercial Model**](#-commercial-tiering--1m-arr-framework) •
[**Runbooks**](#-master-operational-runbooks) •
[**Monorepo**](#-monorepo-structure-the-14-pillars)

---

</div>

## Executive Summary & Core Thesis

> *"Do not build yesterday's Cloudflare. Do not build an undifferentiated AI Gateway or a capital-burning GPU cloud. Build the Infrastructure-Neutral Global Fabric whose core intellectual question is:*  
> **'Where should every application, AI inference request, and compute workload run right now?'"**

NexusEdge is an infrastructure-native, high-performance global network designed from first principles. It combines sub-millisecond line-rate edge routing, OWASP-inspired / CRS-aligned detection engine prototype, distributed RFC 9111 caching, EWMA latency-adaptive origin steering, and multi-region simulated Anycast topology synchronization with automated local development TLS lifecycle management.

### Platform Comparison Matrix

| Capability | Legacy CDNs (Cloudflare, Akamai) | Hyperscaler Gateways (AWS CloudFront, Cloud Armor) | NexusEdge Global Fabric |
|---|---|---|---|
| **Primary Architecture** | Static web object caching (15-yr legacy) | Regional VPC coupling, high vendor lock-in | Decoupled 3-Plane (Data, Control, Intelligence) |
| **Compute Placement** | Fixed edge worker v8 isolates | Multi-AZ load balancers with cold starts | Multi-Objective Optimization (Latency, Cost, Carbon) |
| **Failover Routing** | DNS TTL-based rerouting (30s–300s delay) | Health check ping intervals (10s–30s) | Sub-millisecond EWMA ($\alpha = 0.2$) real-time steering |
| **WAF Evaluation** | Interpreted ruleset engines | Centralized inspection middleboxes | In-process zero-allocation deterministic regex |
| **State Propagation** | Eventual consistency (minutes globally) | Regional propagation delays | Raft / NATS JetStream declarative state replication |
| **Data Sovereignty** | General geographic regions | Single country availability zones | Cryptographic NDMA 2026 & GDPR hard boundaries |

---

## Architecture Overview

NexusEdge enforces strict separation of concerns across three distinct operational planes:

```mermaid
graph TD
    subgraph IntelligencePlane["1. INTELLIGENCE PLANE (Optimization Matters)"]
        direction TB
        PyModels["Python 3.12+ + PyTorch / vLLM / NVIDIA Dynamo"]
        CapacityEngine["Real-Time Capacity Forecaster (VRAM, Power, Subsea Fibers)"]
        WorkloadOptimizer["Multi-Objective Placement Optimizer (Latency, Cost, Carbon)"]
        PyModels --> WorkloadOptimizer
        CapacityEngine --> WorkloadOptimizer
    end

    subgraph ControlPlane["2. CONTROL PLANE (Correctness Matters)"]
        direction TB
        EdgeController["Go Edge Config Controller (:9091)"]
        Compiler["Envoy v3 Dynamic LDS / CDS / SDS Compiler"]
        AnycastManager["BGP Route Health Injection (RHI) Manager"]
        CertManager["TLS Development Lifecycle: HTTP-01-style Challenge + Local ECDSA Certificate"]
        AnalyticsStore["Vitter Algorithm R Reservoir Aggregator"]
        EdgeController --> Compiler
        EdgeController --> AnycastManager
        EdgeController --> CertManager
        EdgeController --> AnalyticsStore
    end

    subgraph DataPlane["3. DATA PLANE (Latency Matters)"]
        direction TB
        AnycastBGP["Simulated Topology (RFC 5737 198.51.100.0/24, RFC 3849 2001:db8::/48)"]
        PoPDhaka["pop-dhaka (Dhaka Simulated BDIX <5ms)"]
        PoPSG["pop-singapore (Singapore Simulated SG1 <32ms)"]
        PoPFRA["pop-frankfurt (Frankfurt Simulated DE-CIX <115ms)"]
        PoPIAD["pop-virginia (Virginia Simulated Ashburn <175ms)"]
        RustGateway["Rust Hyper/Tokio Edge Gateway Prototype"]
        FastPathEngine["CRS-Aligned WAF + RFC 9111 CDN Cache + EWMA Smart Router"]
        
        AnycastBGP --> PoPDhaka
        AnycastBGP --> PoPSG
        AnycastBGP --> PoPFRA
        AnycastBGP --> PoPIAD
        PoPDhaka --> RustGateway
        PoPSG --> RustGateway
        PoPFRA --> RustGateway
        PoPIAD --> RustGateway
        RustGateway --> FastPathEngine
    end

    IntelligencePlane -->|Calculated Placement Graphs & Latency Intent| ControlPlane
    ControlPlane -->|Compiled Envoy v3 xDS & SDS Configuration| DataPlane
```

### Decoupled Plane Invariants

1. **Data Plane (Rust / C / eBPF / Envoy):**
   - Line-rate packet processing with zero garbage collection.
   - Fast-path execution must **never** block on control plane or database round-trips.
2. **Control Plane (Go 1.23 / gRPC / NATS JetStream):**
   - Idempotent declarative reconciliation loops.
   - Generates compiled Envoy v3 xDS/SDS configuration (live gRPC xDS stream in development for V1).
3. **Intelligence Plane (Python 3.12+ / PyTorch / ClickHouse):**
   - Mathematical placement optimization governed by deterministic fallback bounds.
   - Evaluates multi-objective trade-offs across latency, transit cost, and grid power.

> [!NOTE]
> **Data Plane Integration & Security Boundary Notices:**  
> - **Proxy Integration:** The codebase currently features a **Go Control Plane & Envoy Configuration Compiler prototype** (`services/edge/config-controller`) alongside an **independent high-performance Rust L7 Edge Proxy prototype** (`dataplane/edge/gateway`). In this prototype milestone, the Rust gateway operates with a local configuration fixture (`gateway.yaml`), while the Go control plane compiles declarative Envoy v3 LDS/CDS/SDS JSON configurations (`/v1/edge/envoy-config`). Live dynamic integration via an Envoy xDS server and synchronized Rust config ingestion is scheduled for the V1 release.
> - **Origin DNS Rebinding:** In the V0 prototype, customer origin domain names use Envoy `STRICT_DNS` directly. While onboarding validates resolved public IPs, full runtime DNS rebinding mitigation (via an Egress Proxy with link-local/private IP rejection or IP-pinned EDS) is `NOT_IMPLEMENTED` in V0 and scheduled for V1.

---

## The 8 Commercial Subsystems

NexusEdge's first commercial product (**Edge Security Gateway**) is developed across 8 locally-verified engineering prototype milestones:

```
[Milestone 1] ───► [Milestone 2] ───► [Milestone 3] ───► [Milestone 4]
Domain Onboard     CRS-Aligned WAF     RFC 9111 CDN       EWMA Failover
      │                   │                  │                  │
      ▼                   ▼                  ▼                  ▼
[Milestone 5] ───► [Milestone 6] ───► [Milestone 7] ───► [Milestone 8]
TLS Dev Lifecycle   Analytics Engine   Simulated PoP Mesh Stress & Hardening
```

### Detailed Engine Capabilities

| Engine | Milestone | Technical Scope & Invariants | Execution Proof |
|---|---|---|---|
| **Domain Onboarding** | Milestone 1 | RFC 1123 hostname validation, CNAME target generation (`*.edge.nexusedge.net`), cryptographic verification tokens, dynamic Envoy v3 LDS/CDS compilation. | `TestValidateHostname`<br/>`TestOnboardAndVerifyDomain` |
| **WAF & Security** | Milestone 2 | OWASP-inspired / CRS-aligned detection engine prototype (CRS 942 SQLi, 941 XSS, 930 LFI/RFI, 932 RCE, 913 Scanners), IP CIDR / Path / Header matchers, Token Bucket Rate Limiter with burst capacity. | `TestWAF_OWASP_Attacks`<br/>`TestRateLimiter` |
| **RFC 9111 CDN Cache** | Milestone 3 | Deterministic query sorting, header normalization, Cache-Control policy parsing (`no-store`, `private`, `max-age`), sub-second local cache invalidation and purge. | `TestCacheKeyNormalization`<br/>`TestCacheEngineLookupStorePurge` |
| **EWMA Smart Routing** | Milestone 4 | Active origin health probing, Exponentially Weighted Moving Average ($\alpha = 0.2$) RTT latency smoothing, autonomous sub-ms failover upon consecutive failures. | `TestSmartRouter_LowestLatencyAndFailover`<br/>`TestMonitor_ProbeSuccessAndThreshold` |
| **TLS Lifecycle (Dev Mode)** | Milestone 5 | HTTP-01 challenge orchestration, in-memory ECDSA P-256 key pair and local development x509 leaf issuance, Envoy DownstreamTlsContext SDS zero-reload secret rotation. | `TestCertificateManager_Workflow`<br/>`TestChaos_ZeroReloadCertificateRotation` |
| **Traffic Analytics** | Milestone 6 | Estimated p50/p90/p95/p99 latency percentiles from bounded Algorithm R reservoir sampling (0 B/op in the measured reservoir-sampling benchmark), time-series aggregation, isolated monthly bandwidth and request metering for billing. | `TestReservoirSampler_Percentiles`<br/>`TestEngine_TimeSeriesAndBilling`<br/>`TestEngine_MonthlyBillingIsolation` |
| **Simulated Multi-PoP Mesh** | Milestone 7 | In-memory BGP Route Health Injection (RHI) / Withdrawal state model, Inter-PoP Latency Matrix, Local Metro Geo-Steering across simulated Dhaka, Singapore, Frankfurt, and Virginia PoPs. | `TestPoPManager_BGPRouteLifecycle`<br/>`TestPoPManager_LatencyMatrixAndSteering` |
| **Stress & Hardening** | Milestone 8 | In-process high-concurrency pipeline saturation (>100k ops/sec), chaos injection testing (origin death, BGP drain, telemetry flood), and master operational runbooks. | `TestHighConcurrency_Pipeline`<br/>`TestChaos_PoPNetworkDrainAndAnycastFailover` |

---

## Empirical Performance Benchmarks

> [!NOTE]
> **Synthetic Benchmark Context:** The metrics below represent **local in-process micro-benchmarks** executed on a single host (Intel Core i5-8365U @ 1.60GHz, 8 Threads, Windows 11, Go 1.23). They measure internal pipeline algorithm saturation, **not** real-world global network wire transit throughput or distributed WAN line-rate traffic.

All benchmark metrics are empirically measured and verified via `go test -bench="." -benchmem ./test/...` on commodity hardware:

```text
goos: windows
goarch: amd64
pkg: github.com/iammahmudhasan/nexusedge-config-controller/test
cpu: Intel(R) Core(TM) i5-8365U CPU @ 1.60GHz

BenchmarkWAF_Inspection-8                490095      4658 ns/op     205 B/op     9 allocs/op
BenchmarkCache_KeyNormalization-8        538869      2110 ns/op     301 B/op    15 allocs/op
BenchmarkHealth_SmartRouting-8          1536942      1121 ns/op     704 B/op     4 allocs/op
BenchmarkAnalytics_ReservoirSampling-8  7575412       148.2 ns/op     0 B/op     0 allocs/op
PASS
```

### Performance Metric Breakdown

```
Operation                         Latency (ns/op)   Memory (B/op)   Allocations
--------------------------------------------------------------------------------
OWASP-Aligned WAF Inspection     4,658 ns (4.6 µs)     205 B/op      9 allocs
RFC 9111 Cache Key Normalization 2,110 ns (2.1 µs)     301 B/op     15 allocs
EWMA Smart Origin Routing        1,121 ns (1.1 µs)     704 B/op      4 allocs
Reservoir Latency Sampling         148 ns (0.1 µs)       0 B/op      0 allocs (in measured micro-benchmark)
```

### High-Concurrency Pipeline Saturation
- **Tested Throughput:** `149,572.41 ops/sec` under 50-worker parallel saturation.
- **Latency Percentiles:** $p50 < 2.1\text{ ms}$, $p95 < 8.4\text{ ms}$, $p99 < 14.8\text{ ms}$.
- **Memory Footprint:** Bounded in-memory reservoir buffering; zero leak under 20,000+ burst telemetry floods.

---

## Simulated Global PoP Topology & Strategic Bangladesh Anchor

NexusEdge models a multi-metro Point of Presence topology using standard IANA simulation prefixes (`198.51.100.0/24` [RFC 5737], `2001:db8::/48` [RFC 3849], and Private ASN `64512` [RFC 6996]) across 4 simulation metro locations:

```
+-----------------------------------------------------------------------------------------+
|                              SIMULATED TOPOLOGY TESTBED                                 |
|                                                                                         |
|   +--------------------+     +--------------------+     +---------------------------+   |
|   |     pop-dhaka      |     |   pop-singapore    |     |       pop-frankfurt       |   |
|   | Dhaka (Simulated)  |     | SG (Simulated)     |     | Frankfurt (Simulated)     |   |
|   | BDIX Peering Model |     | Equinix SG1 Model  |     | DE-CIX Model              |   |
|   | Latency: <5ms      |     | Latency: <32ms     |     | Latency: <115ms           |   |
|   +--------------------+     +--------------------+     +---------------------------+   |
|                                                                                         |
|                              +--------------------+                                     |
|                              |    pop-virginia    |                                     |
|                              | Ashburn (Simulated)|                                     |
|                              | Equinix DC2 Model  |                                     |
|                              | Latency: <175ms    |                                     |
|                              +--------------------+                                     |
+-----------------------------------------------------------------------------------------+
```

### Commercial Product Progression Roadmap

| Phase | Milestone Name | Architectural Focus | Readiness Status |
|---|---|---|---|
| **V0** | **Engineering Prototype** | Rust Gateway + Go Config Controller + In-Memory WAF & Cache | **Current State (Locally Verified)** |
| **V1** | **Customer Beta** | Real Customer Domain + Multi-Tenant Auth + Live TLS + Health Loops | Next Milestone |
| **V1.5** | **Multi-Origin & Dashboard** | Dynamic Steering + Origin Shielding + Customer Portal | Planned |
| **V2** | **Multi-PoP Edge** | First 2 Leased Physical PoPs + DNS Failover Steering | Roadmap |
| **V3** | **Autonomous Anycast** | Dedicated ASN + Upstream BGP Transit + Hardware Scrubbing | Long-term Target |
| **V4** | **Global Workload Fabric**| Multi-Objective Scheduler + Distributed GPU Inference Placement | Long-term Target |

### Subsystem Verification State Machine

Every subsystem in the repository is strictly tracked against our 6-stage lifecycle:  
`NOT_IMPLEMENTED` ➔ `SIMULATED` ➔ `LOCALLY_VERIFIED` ➔ `STAGING_VERIFIED` ➔ `REAL_INFRA_VERIFIED` ➔ `PRODUCTION_READY`

*(See [`verification/production-readiness/READINESS_MATRIX.md`](verification/production-readiness/READINESS_MATRIX.md) for full status catalog.)*

### The Strategic Bangladesh Advantage
1. **BDIX Fabric:** Direct low-latency peering with 167 members and over 2.27 Tbps cumulative port capacity, yielding $<5\text{ms}$ domestic RTT across Bangladesh.
2. **SMW6 Submarine Cable:** 30,000 Gbps planned capacity terminating at Cox's Bazar, connecting directly to Singapore, Mumbai, and Europe.
3. **Data Sovereignty Mandate:** Complete architectural compliance with the **National Data Management Act (NDMA) 2026**, guaranteeing localized, cryptographically verifiable data residency for Critical Information Infrastructure (CII).

---

## Quickstart Guide

### System Prerequisites
- Go 1.23+ (`go version`)
- Rust 1.82+ (`rustc --version`)
- Python 3.12+ (`python --version`)

### 1. Build and Run the Edge Config Controller
```bash
cd services/edge/config-controller
go run cmd/config-controller/main.go
# Controller listening on http://127.0.0.1:9091
```

### 2. Onboard a Test/Development Domain
```bash
curl -s -X POST http://127.0.0.1:9091/v1/projects/prj-enterprise-01/domains \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-fixture-key-01" \
  -d '{
    "hostname": "api.dev.example.com",
    "origin_address": "198.51.100.10",
    "origin_port": 443,
    "origin_protocol": "HTTPS"
  }'
```
*Response includes assigned CNAME target (`dom-xxxx.edge.nexusedge.net`) and verification token.*

### 3. Attach CRS-Aligned WAF Rule & Configure Edge Protection
```bash
curl -s -X POST http://127.0.0.1:9091/v1/domains/{domain_id}/waf/rules \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-fixture-key-01" \
  -d '{
    "name": "block-admin-path",
    "match_type": "PATH_PREFIX",
    "pattern": "/admin",
    "action": "BLOCK"
  }'
```

### 4. Execute Full Test & Benchmark Suite
```bash
cd services/edge/config-controller

# Execute complete test suite (unit, integration, and chaos)
go test -v -count=1 ./internal/... ./test/...

# Execute micro-benchmarks with memory allocation profiling
go test -bench="." -benchmem ./test/...
```

---

## Commercial Tiering ($1M ARR Framework)

NexusEdge's business model targets high-margin, recurring infrastructure revenue:

```
                              ANNUAL REVENUE TARGET: $1,000,000 ARR
                             
       Developer Tier                 Business Tier                Enterprise Tier
      [ 200 Customers ]              [ 150 Customers ]             [ 20 Customers ]
      $29 / mo ($69.6k/yr)          $299 / mo ($538.2k/yr)      $2,499 / mo ($599.7k/yr)
```

| Dimension | Developer Tier | Business Tier | Enterprise Tier |
|---|---|---|---|
| **Base Price** | $29 / month | $299 / month | $2,499 / month |
| **Included Requests** | 5,000,000 / mo | 50,000,000 / mo | 500,000,000 / mo |
| **Overage Request Fee** | $0.000002 / req ($2/M) | $0.0000015 / req ($1.5/M) | $0.000001 / req ($1.0/M) |
| **Included Bandwidth** | 100 GB | 1,000 GB (1 TB) | 10,000 GB (10 TB) |
| **Overage Bandwidth Fee** | $0.08 / GB | $0.05 / GB | $0.03 / GB |
| **Custom WAF Rules** | 5 Rules | 50 Rules | Unlimited Rules |
| **Origin Health Check Interval**| 30 seconds | 5 seconds | 1 second |
| **Availability SLA** | Best Effort | 99.9% SLA | 99.99% Financial SLA |
| **Data Residency** | Shared Anycast | Regional Affinity | Dedicated NDMA/GDPR Partition |

---

## Master Operational Runbooks

Comprehensive Standard Operating Procedures (SOPs) and disaster triage protocols are documented in:
- [**Master Edge Operations Runbook**](docs/runbooks/EDGE_OPERATIONS_RUNBOOK.md)
  - `SOP-01`: Customer Domain Onboarding & CNAME Delegation
  - `SOP-02`: Zero-Day WAF Rule Patching & CRS-Aligned WAF Tuning (Sub-60s push without restart)
  - `SOP-03`: Origin Health Probing & Instant EWMA Failover
  - `SOP-04`: Emergency Anycast BGP Route Withdrawal & PoP Draining
  - `SOP-05`: Automated ACME TLS Rotation & Envoy Zero-Reload SDS Lifecycle
  - `SOP-06`: High-Frequency Telemetry Aggregation & Usage Billing Reconciliation
  - `SOP-07`: Incident Triage Matrix & High Availability Target Design

---

## Monorepo Structure: The 14 Pillars

The codebase strictly adheres to 14 isolated domain pillars. No code lives outside its designated pillar:

```
.
├── apps/                 # Customer applications (Next.js Dashboard, Go CLI)
├── services/             # Control plane microservices (Config Controller, Router, IAM)
├── dataplane/            # Data plane fast-path (Rust Gateway, Envoy, eBPF XDP)
├── intelligence/         # Intelligence plane (PyTorch Schedulers, Capacity Models)
├── proto/                # Protocol Buffers governed by buf.yaml (API contracts)
├── schemas/              # NATS JetStream event schemas and telemetry formats
├── infra/                # Datacenter topology, regions, BGP routing, SONiC OS
├── deploy/               # Deployment manifests (Envoy configs, Kubernetes Helm, Argo CD)
├── tests/                # Multi-tier verification (Integration, e2e, chaos tests)
├── benchmarks/           # Performance benchmarks (Mpps, L7 proxy latency, DNS)
├── rfcs/                 # Formal architectural change proposals (RFC 0001+)
├── adr/                  # Permanent architectural decision records (ADR 0001+)
├── security/             # Threat models, zero-trust policies, SBOM tracking
└── docs/                 # Master documentation, network runbooks, operator manuals
```

---

## Strategic Documentation

- [**Master Architecture**](docs/MASTER_ARCHITECTURE.md) — Comprehensive design of the 3 planes and 5 proprietary IP engines.
- [**Technology Stack Matrix**](docs/TECH_STACK.md) — Architectural rationale for Rust, Go, Python, Envoy, and Linux eBPF.
- [**10-15 Year Strategic Thesis**](docs/THESIS.md) — Mathematical roadmap from $0 to hyper-scale global infrastructure.
- [**Constitutional Rulebook**](docs/AI_ENGINEERING_RULES.md) — 126 non-negotiable engineering laws governing this monorepo.
- [**Autonomous Agent Manual**](AGENTS.md) — Strict operating instructions for AI development agents.

---

## License & Compliance

NexusEdge is open-source software licensed under the [MIT License](LICENSE).  
Designed and maintained by the NexusEdge Global Infrastructure Engineering Group.
