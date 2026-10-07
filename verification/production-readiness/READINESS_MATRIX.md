# NexusEdge Subsystem Readiness Matrix

This document is the single source of truth for the production readiness of all NexusEdge architectural subsystems.

## The 6-Stage Subsystem Verification Lifecycle

All components and capabilities transition strictly through the following six verification gates:

```
[ NOT_IMPLEMENTED ]
         │
         ▼
  [ SIMULATED ]             -> In-memory models, synthetic testbeds, RFC test prefixes
         │
         ▼
[ LOCALLY_VERIFIED ]        -> Pass unit, integration, and micro-benchmarks on local machine
         │
         ▼
[ STAGING_VERIFIED ]        -> Tested on dedicated multi-node staging cluster with external traffic
         │
         ▼
[ REAL_INFRA_VERIFIED ]     -> Tested with real customer domains, leased hardware, live transit
         │
         ▼
[ PRODUCTION_READY ]        -> Hardened with SLA/SLO metrics, automated failover, 24/7 on-call
```

---

## Active Subsystem Readiness Inventory

| Domain / Subsystem | Current State | Evidence & Test Suite | Target Milestone | Notes |
|---|---|---|---|---|
| **Data Plane: Rust Gateway** | `LOCALLY_VERIFIED` | `cargo test` in `dataplane/edge/gateway` | V0 / V1 | Hyper/Tokio HTTP reverse proxy with local WAF & cache integration. |
| **Data Plane: Envoy xDS Engine** | `SIMULATED` | `compiler_test.go` | V1.5 / V2 | Compiles Envoy v3 LDS/CDS/SDS JSON; live xDS control stream planned. |
| **Data Plane: eBPF XDP Filter** | `SIMULATED` | `infra/network/` | V3 | Architecture planned; line-rate XDP C programs in development. |
| **Control Plane: Domain Service** | `LOCALLY_VERIFIED` | `onboarding_test.go`, `TestOnboardAndVerifyDomain` | V0 / V1 | RFC 1123 hostname validation & CNAME target assignment verified. |
| **Control Plane: CRS-Aligned WAF Prototype**| `LOCALLY_VERIFIED` | `waf_test.go`, `TestWAF_OWASP_Attacks` | V0 / V1 | OWASP-inspired regex attack patterns (SQLi, XSS, RCE, Path Traversal); Coraza/CRS engine planned. |
| **Control Plane: RFC 9111 Cache** | `LOCALLY_VERIFIED` | `cache_test.go`, `TestCacheEngineLookupStorePurge` | V0 / V1 | In-memory key normalization & Cache-Control parser passes locally. |
| **Control Plane: EWMA Health Router**| `LOCALLY_VERIFIED` | `router_test.go`, `TestSmartRouter_LowestLatencyAndFailover` | V0 / V1 | In-memory EWMA smoothing & autonomous failover passes locally. |
| **Control Plane: TLS Dev Lifecycle** | `LOCALLY_VERIFIED` | `manager_test.go`, `TestCertificateManager_Workflow` | V0 | Generates local ECDSA P-256 self-signed leaf certificates for testing. |
| **Control Plane: Production ACME (RFC 8555)** | `NOT_IMPLEMENTED` | - | V1 | Real Let's Encrypt / external WebPKI integration scheduled for V1. |
| **Control Plane: SDS Secret Distribution** | `SIMULATED_DECLARATIVE / NOT_IMPLEMENTED` | `compiler_test.go` | V1 | Envoy v3 SDS gRPC cluster declared with HTTP/2; live secret serving daemon scheduled for V1. |
| **Control Plane: Traffic Analytics** | `LOCALLY_VERIFIED` | `engine_test.go`, `TestReservoirSampler_Percentiles` | V0 / V1 | Estimated p50/p95/p99 from bounded Algorithm R reservoir sampling with isolated monthly billing. |
| **Persistence Layer (PostgreSQL)** | `NOT_IMPLEMENTED` | - | V1 | In-memory sync.RWMutex store in V0; PostgreSQL repository layer planned for V1 Customer Beta. |
| **Network: Multi-PoP Topology** | `SIMULATED` | `manager_test.go` with RFC 5737/6996 test prefixes | V0 / V1 | In-memory 4-metro topology model (Dhaka, SG, Frankfurt, Virginia). |
| **Network: BGP Route Health Injection** | `SIMULATED` | `TestPoPManager_BGPRouteLifecycle` | V3 | In-memory state machine. Hardware BGP speaker planned for V3. |
| **Network: Global Anycast Fabric** | `SIMULATED` | - | V3 | Simulated via RFC 5737 (198.51.100.0/24) & RFC 3849 (2001:db8::/48). |
| **Intelligence: Workload Scheduler** | `LOCALLY_VERIFIED` | `optimizer.py`, `scheduler_test.go` | V0 / V4 | Multi-objective placement optimization prototype in Python/Go. |
| **Intelligence: Capacity Forecaster**| `SIMULATED` | `fixtures/simulation/capacity/` | V4 | Mathematical models run on simulated provider inventories. |
| **Tenant Isolation & Auth Middleware** | `LOCALLY_VERIFIED` | `auth_test.go`, `TestControlPlane_AuthenticationAndTenantIsolation` | V0 / V1 | Control plane middleware, tenant spoofing rejection, and IDOR resource-level authorization verified. |
| **Automated CI/CD Pipeline** | `LOCALLY_VERIFIED` | `.github/workflows/ci.yml` | V0 / V1 | GitHub Actions workflow configured for Go tests/vet, Rust check/test, Python optimizer, and Compose validation. |
| **99.99% Guaranteed Availability** | `NOT_IMPLEMENTED` | - | V2 / V3 | Target design SLO. Real SLA requires multi-PoP live production traffic. |

---

## Architectural Honesty Guidelines

1. **Never claim `PRODUCTION_READY`** for any subsystem that has not passed through all 5 preceding gates with verifiable log artifacts.
2. **Never commit real public ASNs or IP prefixes** belonging to external network operators to model our infrastructure. Always use IANA simulation ranges (RFC 5737, RFC 3849, RFC 6996) until official allocation.
3. **Never label local self-signed certificates** as external ACME CA certificates.
4. **Never label single-node in-memory micro-benchmarks** as global network throughput.
