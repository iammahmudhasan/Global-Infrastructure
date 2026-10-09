# RFC 0002: Single-PoP Edge Security Gateway — Architecture, Traffic Flow, and Acceptance Gates

- **Author:** NexusEdge Architecture Team
- **Status:** Approved / Active Implementation
- **Date:** 2026-10-09
- **Target Release:** v0.2.0 (Single-PoP Pilot Milestone)

---

## 1. Executive Summary & Problem Statement

Prior to this RFC, the edge deployment manifests suffered from a critical architectural inversion: Envoy routed general customer ingress (`/`) directly to the Go Control Plane (`config-controller:9091`), while only the `/edge/` prefix was routed to the Rust Data Plane (`nexusedge-gateway:8080`). Furthermore, Envoy lacked standard public ingress ports (80/443) and TLS termination.

This RFC formalizes the **Single-PoP Edge Security Gateway** product milestone: a hardened, single-region edge gateway fronting customer origins with line-rate packet processing, strict tenant isolation, zero ambient DNS fallback, and cryptographically verified control plane configuration sync.

---

## 2. System Topology & Traffic Separation

The architecture strictly separates the **Data Plane** (latency-critical packet path) from the **Control Plane** (correctness-critical policy distribution):

```
[ Public Internet Client ]
          │
          │ HTTP (Port 80/10000) / HTTPS (Port 443/10443)
          ▼
┌────────────────────────────────────────────────────────┐
│ Envoy L7 Edge Ingress                                  │
│ - Downstream TLS Termination (SNI / Certificates)      │
│ - ACME HTTP-01 Routing: /.well-known/acme-challenge/   │
│ - Customer Traffic Default: /*                         │
└──────────────┬───────────────────────────┬─────────────┘
               │                           │
  /.well-known/acme-challenge/*            │ All Customer Traffic (/*)
               │                           ▼
               │                ┌────────────────────────────────────────┐
               │                │ NexusEdge Rust Data Plane (Port 8080)  │
               │                │ - WAF Inspection (SQLi, XSS, Path Trav)│
               │                │ - Rate Limiting (Token Bucket)         │
               │                │ - Edge Response Cache                  │
               │                │ - Longest-Prefix Path Routing          │
               │                │ - Strict Pinned DNS (Zero Rebinding)   │
               │                └───────────────────┬────────────────────┘
               │                                    │
               ▼                                    ▼
┌───────────────────────────────┐     ┌──────────────────────────────────┐
│ Go Control Plane (Port 9091)  │     │ Customer Origins                 │
│ - Domain Onboarding & ACM     │     │ - API Origin (/api/)             │
│ - Snapshot Compiler (SHA-256) │     │ - Admin Origin (/admin/)         │
│ - Management APIs (Private)   │     │ - Main Origin (/*)               │
└───────────────────────────────┘     └──────────────────────────────────┘
```

---

## 3. The Four Core Implementation Pillars

### Pillar A: Public Ingress Traffic Flow
- **Default Route Invariant:** 100% of customer web and API requests entering Envoy route to `rust_fast_path_cluster` (`nexusedge-gateway:8080`).
- **Management API Isolation:** Control Plane management APIs (`/v1/projects/`, `/v1/edge/`, `/v1/domains/`) are strictly internal and inaccessible via public ingress.
- **ACME Challenge Exception:** Only `/.well-known/acme-challenge/` routes to `control_plane_cluster` (`config-controller:9091`) for automated domain validation.
- **TLS Termination:** Envoy terminates client TLS on port 10443 (mapped to 443 in production) using staging or automated ACME certificates.

### Pillar B: Control Plane Delivery & Zero-Downtime DNS Updates
- **Snapshot Fetch & Verification:** The Rust Gateway periodically polls `/v1/edge/pops/{pop_id}/config`. Snapshots are validated against mandatory `X-Snapshot-Checksum` SHA-256 headers before route replacement.
- **Fail-Closed Fallback:** If a snapshot is corrupted, tampered, or exceeds the 16 MiB memory-bomb ceiling, the gateway rejects the update and preserves the Last-Known-Good (LKG) routing table.
- **Epoch Versioning & Staged DNS Pruning:** DNS pin updates use an atomic epoch counter. Candidate pins are merged before the route swap lock. In asynchronous runtimes, retired pins are retained for a 5-second grace period before eviction, preventing transient resolution errors for in-flight requests.

### Pillar C: Customer Routing & Security Invariants
- **Multi-Origin Path Routing:** Evaluates longest-prefix matches (`/api/` -> API origin, `/admin/` -> Admin origin). Unmatched paths fail closed.
- **SSRF Hardening:** Private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`), link-local addresses, and cloud metadata (`169.254.169.254`) are rejected in route definitions and upstream redirects.
- **Strict DNS Pinning:** Upstream connections resolve exclusively via pre-pinned IP addresses; ambient DNS fallback is forbidden.
- **WAF & Rate Limiting:** Malicious payloads trigger immediate HTTP 403 blocks; requests exceeding burst thresholds trigger HTTP 429 Too Many Requests.

### Pillar D: Startup Readiness & Operational Verification
- **Readiness Gate:** `/ready` returns HTTP 503 Service Unavailable if either `control_plane.enabled` or `control_plane.snapshot_file` is active until the first valid configuration snapshot is successfully verified and applied.
- **Liveness Gate:** `/healthz` independently verifies gateway process health.
- **Graceful Rollback:** Corrupted updates never mutate live proxy state; rolling back control plane revisions triggers atomic gateway reconfiguration without restart.

---

## 4. Acceptance Gates (Production Readiness)

| Gate | Acceptance Criteria | Verification Method |
|---|---|---|
| **Gate 1: Real Traffic Path** | Client -> Envoy -> Rust Gateway -> Controlled Origin succeeds. Zero customer requests reach Control Plane. | Integration test verifying upstream response headers and Envoy access logs. |
| **Gate 2: HTTPS & TLS** | Valid TLS handshake on port 443/10443 with correct SNI and certificate chain. | OpenSSL client handshake validation and curl TLS test. |
| **Gate 3: Routing Isolation** | `/api/` and `/admin/` route to distinct origins; unmatched paths fail closed. | Integration test verifying target origin segregation. |
| **Gate 4: Config Sync & Integrity** | Valid snapshots apply atomically; tampered checksums or payloads > 16 MiB fail closed. | Unit and integration test injecting invalid checksums. |
| **Gate 5: SSRF Hardening** | Private, loopback, and metadata destinations rejected; redirect-following SSRF blocked. | Unit tests across IPv4/IPv6 private ranges. |
| **Gate 6: Security Enforcement** | SQL injection/XSS payloads return 403; rate limit bursts return 429; cache returns HIT. | Automated test suite exercising WAF, token bucket, and cache headers. |
| **Gate 7: Zero-Downtime DNS** | DNS pinning updates do not drop active in-flight requests to retiring origins. | Epoch versioning and deferred grace period validation. |
| **Gate 8: Recovery & Rollback** | Gateway and Control Plane restart cleanly; gateway preserves valid state during CP outages. | Service kill and restart chaos simulation. |
| **Gate 9: CI Parity** | 100% pass on formatting, vetting, Clippy (`-D warnings`), and Compose runtime tests. | Local and remote CI parity verification scripts. |

---

## 5. Security & Threat Modeling

1. **Snapshot Memory-Bomb:** Mitigated by 16 MiB maximum payload budget and bounded streaming chunks.
2. **DNS Rebinding & Ambient Leakage:** Mitigated by `PinnedDnsResolver` returning `PermissionDenied` on unpinned lookups.
3. **Control Plane Ingress Exposure:** Mitigated by Envoy routing rules preventing external access to `/v1/` endpoints.
4. **Credential Leakage:** Redacted authorization headers in logs; zero hardcoded secrets.
