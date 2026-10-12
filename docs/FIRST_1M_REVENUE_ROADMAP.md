# The $1M ARR Roadmap: Global Edge Network + Security Gateway

> **Strategic Directive:** Focus on **ONE PRODUCT ONLY**. Achieve $1,000,000 ARR in recurring software-first infrastructure revenue before deploying capital into physical data centers.  
> **The Product:** **NexusEdge Global Edge Network + Security Gateway**  
> **Customer Value Proposition:** *"Put our network in front of your application in 2 minutes. We manage line-rate DDoS, WAF, SSL, origin failover, and local latency—with zero code changes and zero server migrations."*

---

## 1. The $1,000,000 ARR Math (Unit Economics)

To reach **$1,000,000 ARR** ($\approx \$83,333\text{ MRR}$), we do not need millions of free users. We need **~115 paying commercial organizations**:

```
┌─────────────────────────┬──────────────┬──────────────────┬─────────────────┐
│ Plan Tier               │ Monthly Fee  │ Target Customers │ Monthly Revenue │
├─────────────────────────┼──────────────┼──────────────────┼─────────────────┤
│ Tier 1: Startup / Pro   │ $29 / mo     │ 150 customers    │ $4,350 / mo     │
│ Tier 2: Business        │ $249 / mo    │ 90 customers     │ $22,410 / mo    │
│ Tier 3: Enterprise / CII│ $2,499 / mo  │ 23 customers     │ $57,477 / mo    │
├─────────────────────────┼──────────────┼──────────────────┼─────────────────┤
│ TOTAL                   │              │ 263 Customers    │ $84,237 / mo    │
│ ANNUAL RUN RATE (ARR)   │              │                  │ $1,010,844 / yr │
└─────────────────────────┴─────────────────────────────────┴─────────────────┘
```

### Why Customers Pay:
- **Tier 2 ($249/mo):** Mid-market e-commerce, fintech, and SaaS companies suffering from credential stuffing, bot scraping, and origin downtime. Paying $249/mo for automated origin failover and sub-150µs WAF is an immediate no-brainer compared to hiring a DevOps engineer.
- **Tier 3 ($2,499/mo):** Banks, financial institutions, and critical infrastructure in Bangladesh and South Asia requiring **strict National Data Management Act (NDMA 2026) compliance**, sub-4ms BDIX peering, and dedicated Anycast VIPs.

---

## 2. Customer Request Flow (The Single Product Engine)

```
                            CUSTOMER REQUEST
                                   │
                                   ▼
                         1. Managed Anycast DNS
                         (BDIX & Global RTT Steering)
                                   │
                                   ▼
                       2. NexusEdge Edge Gateway
                    ┌─────────────────────────────┐
                    │ • L3/L4/L7 DDoS Scrubbing   │
                    │ • Automated TLS 1.3 / mTLS  │
                    │ • Line-Rate OWASP WAF       │
                    │ • Token-Bucket Rate Limiter │
                    │ • RFC 9111 Response Cache   │
                    └──────────────┬──────────────┘
                                   │ (Clean Traffic)
                                   ▼
                    3. Intelligent Origin Dispatch
                    ┌─────────────────────────────┐
                    │ Primary: AWS / GCP Instance │
                    │ Backup:  Local Bare-Metal   │
                    │ (Sub-100ms Health Failover) │
                    └─────────────────────────────┘
```

---

## 3. Current Codebase Inventory: What is Already Built?

Our monorepo already contains the operational foundation for this exact product:

| Subsystem | Existing File / Package | Current Capabilities |
|---|---|---|
| **Data Plane (Rust)** | [`dataplane/edge/gateway/src/proxy.rs`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/dataplane/edge/gateway/src/proxy.rs) | High-performance reverse proxy with non-blocking connection pooling and path routing. |
| **WAF Engine (Rust)** | [`dataplane/edge/gateway/src/waf.rs`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/dataplane/edge/gateway/src/waf.rs) | Line-rate SQLi, XSS, Path Traversal, Scanners, and Cloud Metadata SSRF protection. |
| **Rate Limiter (Rust)**| [`dataplane/edge/gateway/src/rate_limit.rs`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/dataplane/edge/gateway/src/rate_limit.rs) | Lock-free sliding window token bucket per client IP and API key. |
| **Edge Cache (Rust)** | [`dataplane/edge/gateway/src/cache.rs`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/dataplane/edge/gateway/src/cache.rs) | In-memory bounded cache adhering to RFC 9111 TTL and `Vary` headers. |
| **Customer Onboarding**| [`services/edge/config-controller/internal/onboarding/service.go`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/services/edge/config-controller/internal/onboarding/service.go) | 2-minute domain onboarding API with CNAME target provisioning. |
| **Origin Health & Failover** | [`services/edge/config-controller/internal/health/monitor.go`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/services/edge/config-controller/internal/health/monitor.go) | Smart router with latency tracking and autonomous origin failover. |
| **Automated SSL/TLS** | [`services/edge/config-controller/internal/certificate/manager.go`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/services/edge/config-controller/internal/certificate/manager.go) | Automated ACME HTTP-01 and DNS-01 challenge management. |
| **Secret Vault** | [`services/edge/config-controller/internal/security/vault_cipher.go`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/services/edge/config-controller/internal/security/vault_cipher.go) | AES-256-GCM envelope encryption (`enc:v1:...`). |
| **Audit Logging** | [`services/edge/config-controller/internal/security/audit.go`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/services/edge/config-controller/internal/security/audit.go) | HMAC-SHA256 hash-chained tamper-proof audit trail. |
| **Customer Console** | [`apps/dashboard/public/index.html`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/apps/dashboard/public/index.html) | Interactive 10-pillar Control Plane console. |
| **Local Verification** | [`tests/e2e/test_single_pop_gateway.ps1`](file:///c:/Users/mah54/Desktop/Infrastructure%20Business/tests/e2e/test_single_pop_gateway.ps1) | 7 Acceptance integration test gates. |

---

## 4. The 3 Scaling Milestones to Reach $1M ARR

### Milestone 1: Production Colocation & Anycast Ingress ($0 to $50K ARR)
- **Deployment:** Spin up our Docker / Envoy / Rust Edge Gateway stack on 3 low-cost third-party transit nodes:
  - **Dhaka:** Local BDIX-connected virtual machine / dedicated server.
  - **Singapore:** Equinix / DigitalOcean transit node (Asia hub).
  - **Frankfurt / Virginia:** Hetzner / AWS transit node (EU/US hub).
- **Onboarding Flow:** Launch automated self-serve domain registration where customers enter their domain + backend server IP, add a CNAME, and go live in 2 minutes.

### Milestone 2: Enterprise Smart Origin Failover & WAF Upsell ($50K to $300K ARR)
- **The Core Differentiator:** Offer **Autonomous Multi-Cloud Origin Failover**. If a customer's primary AWS origin returns 502/503 or latency spikes, NexusEdge immediately routes traffic to their standby server with sub-100ms detection.
- **Enterprise WAF:** Target fintechs, banks, and e-commerce platforms facing cyber threats.

### Milestone 3: National Data Sovereignty Moat ($300K to $1,000,000 ARR)
- **Sovereign Gateway (BD NDMA 2026):** Bangladesh's National Data Management Act mandates real-time local data retention for Critical Information Infrastructure (CII).
- **The Contract:** Sign 20–30 financial institutions and enterprise customers at $2,000–$3,000/month for guaranteed in-country sovereign routing and BDIX peering.
- **Target Achieved:** $1,000,000+ ARR.

---

## 5. The Physical Data Center Milestone Trigger

$$\text{Trigger Condition:} \quad \mathbf{ARR} \ge \mathbf{\$1,000,000} \quad \text{AND} \quad \mathbf{Net\ Margin} \ge \mathbf{40\%}$$

Only once we have:
1. Proven customer demand and hundreds of paying organizations,
2. An active traffic stream flowing through our proxy nodes,
3. Established cash flow and bankability,

**Then and only then** do we begin leasing dedicated colocation suites, purchasing dark fiber, and building our proprietary high-density physical data centers.
